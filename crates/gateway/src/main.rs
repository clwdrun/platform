//! The gateway binary: a pingora service that terminates TLS and routes by
//! host to the edge application ([`gateway::edge::Edge`]).
//!
//! Sync `main`, not `#[tokio::main]`: pingora's [`Server`] owns and manages its
//! own runtimes, so it must run on a plain thread. Configuration comes from the
//! environment. TLS uses a per-org certificate chosen at handshake time by SNI
//! ([`gateway::tls::DynamicCert`]) — one wildcard cert per org — so a host that
//! is not `{app}.{org}.<apps domain>`, or an org with no issued certificate, fails the
//! handshake rather than being served a wrong certificate. This is binary-edge
//! glue, so `anyhow`; the library crates use `thiserror`.

use std::env;
use std::sync::Arc;

use anyhow::Context as _;
use gateway::cert::CertResolver;
use gateway::edge::{Edge, Serving};
use gateway::lookup::RouteLookup;
use gateway::signin::SigninClient;
use gateway::tls::DynamicCert;
use gateway::worker::WorkerUpstream;
use pingora::apps::http_app::HttpServer;
use pingora::listeners::tls::TlsSettings;
use pingora::server::Server;
use pingora::services::listening::Service;
use shared::cert::DirCertStore;
use shared::domains::{AppsDomain, ControlPlaneDomain};

fn main() -> anyhow::Result<()> {
    shared::telemetry::init();

    let listen = env::var("CLWD_GATEWAY_LISTEN").unwrap_or_else(|_| "0.0.0.0:8443".to_owned());
    // Two domains, both required, no default: apps are served from a
    // registrable domain of their own, never the control plane's (#62). One
    // variable for both is how that would quietly be undone.
    let apps = AppsDomain::parse(
        &env::var("CLWD_APPS_DOMAIN").context("CLWD_APPS_DOMAIN must name the apps domain")?,
    )?;
    let control_plane_domain = ControlPlaneDomain::parse(
        &env::var("CLWD_CONTROL_PLANE_DOMAIN")
            .context("CLWD_CONTROL_PLANE_DOMAIN must name the control plane's public host")?,
    )?;
    apps.separate_from(&control_plane_domain)?;
    let control_plane = env::var("CLWD_CONTROL_PLANE")
        .context("CLWD_CONTROL_PLANE must be the internal control-plane base URL")?;
    let internal_secret =
        env::var("CLWD_INTERNAL_SECRET").context("CLWD_INTERNAL_SECRET must be set")?;
    // One `{org}/cert.pem` + `{org}/key.pem` per org under this directory. #22's
    // secret broker replaces this file store behind the CertStore trait.
    let cert_dir = env::var("CLWD_CERT_DIR")
        .context("CLWD_CERT_DIR must name the per-org certificate directory")?;

    tracing::info!(%listen, %apps, control_plane = control_plane_domain.as_str(), %cert_dir, "gateway serving");

    let lookup = Arc::new(RouteLookup::new(
        control_plane.clone(),
        internal_secret.clone(),
    )?);
    let mut edge = Edge::new(lookup, apps.clone());
    // Apps are served when a worker is configured; without one a live app
    // answers `gateway.not_ready`, as before #11. The worker is a separate
    // process and user: app code never runs in this one, which holds every
    // org's TLS key and the internal credential.
    match env::var("CLWD_WORKER_SOCKET") {
        Ok(socket) => {
            let worker_uid: u32 = env::var("CLWD_WORKER_UID")
                .context("CLWD_WORKER_UID must name the worker's user id")?
                .parse()
                .context("CLWD_WORKER_UID must be a number")?;
            let signin = Arc::new(SigninClient::new(
                control_plane.clone(),
                internal_secret.clone(),
            )?);
            tracing::info!(%socket, worker_uid, "serving apps through the worker");
            // App log lines (#78): queued without waiting by each request,
            // shipped in batches by a thread and runtime of their own.
            let (ship, receiver) = gateway::logship::LogShip::new(gateway::logship::CHANNEL);
            let sink = gateway::logship::Sink {
                client: reqwest::Client::builder()
                    .timeout(std::time::Duration::from_secs(5))
                    .build()
                    .context("building the log shipping client")?,
                url: reqwest::Url::parse(&format!(
                    "{}/internal/logs",
                    control_plane.trim_end_matches('/')
                ))
                .context("CLWD_CONTROL_PLANE must be a URL")?,
                secret: Arc::<str>::from(internal_secret.as_str()),
            };
            let shipping = ship.clone();
            std::thread::Builder::new()
                .name("log-ship".to_owned())
                .spawn(move || {
                    match tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                    {
                        Ok(runtime) => {
                            runtime.block_on(gateway::logship::ship(receiver, shipping, sink));
                        }
                        Err(error) => tracing::error!(
                            %error,
                            "no runtime for log shipping; app log lines are dropped"
                        ),
                    }
                })
                .context("starting the log shipping thread")?;
            let serving = Serving::new(
                signin,
                control_plane_domain.clone(),
                Arc::new(WorkerUpstream::new(socket, worker_uid)),
            )
            .with_logs(ship);
            // The authorization cache's invalidation stream (#12), on a thread
            // and runtime of its own: pingora owns the others. Until it has
            // connected and been granted a lease, every request takes the
            // uncached check.
            let (authz, gateway_id) = (serving.authz(), uuid::Uuid::now_v7());
            let (base, secret) = (
                control_plane.clone(),
                Arc::<str>::from(internal_secret.as_str()),
            );
            std::thread::Builder::new()
                .name("authz-stream".to_owned())
                .spawn(move || {
                    match tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                    {
                        Ok(runtime) => runtime
                            .block_on(gateway::authz::follow(authz, base, secret, gateway_id)),
                        Err(error) => tracing::error!(
                            %error,
                            "no runtime for the invalidation stream; the cache stays bypassed"
                        ),
                    }
                })
                .context("starting the invalidation stream thread")?;
            edge = edge.serving(serving);
        }
        Err(_) => tracing::warn!("CLWD_WORKER_SOCKET is unset; live apps answer gateway.not_ready"),
    }

    let store = Arc::new(DirCertStore::new(&cert_dir));
    let resolver = CertResolver::new(store, apps);
    let tls = TlsSettings::with_callbacks(DynamicCert::callbacks(resolver))
        .map_err(|e| anyhow::anyhow!("TLS settings: {e}"))?;

    let mut server = Server::new(None).map_err(|e| anyhow::anyhow!("pingora server: {e}"))?;
    server.bootstrap();

    let mut service = Service::new("gateway-edge".to_owned(), HttpServer::new_app(edge));
    service.add_tls_with_settings(&listen, None, tls);
    server.add_service(service);

    server.run_forever();
}
