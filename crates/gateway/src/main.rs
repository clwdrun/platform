//! The gateway binary: a pingora service that terminates TLS and routes by
//! host to the edge application ([`gateway::edge::Edge`]).
//!
//! Sync `main`, not `#[tokio::main]`: pingora's [`Server`] owns and manages its
//! own runtimes, so it must run on a plain thread. Configuration comes from the
//! environment. TLS uses a per-org certificate chosen at handshake time by SNI
//! ([`gateway::tls::DynamicCert`]) — one wildcard cert per org — so a host that
//! is not `{app}.{org}.<apex>`, or an org with no issued certificate, fails the
//! handshake rather than being served a wrong certificate. This is binary-edge
//! glue, so `anyhow`; the library crates use `thiserror`.

use std::env;
use std::sync::Arc;

use anyhow::Context as _;
use gateway::cert::CertResolver;
use gateway::edge::Edge;
use gateway::lookup::RouteLookup;
use gateway::tls::DynamicCert;
use pingora::apps::http_app::HttpServer;
use pingora::listeners::tls::TlsSettings;
use pingora::server::Server;
use pingora::services::listening::Service;
use shared::cert::DirCertStore;

fn main() -> anyhow::Result<()> {
    shared::telemetry::init();

    let listen = env::var("CLWD_GATEWAY_LISTEN").unwrap_or_else(|_| "0.0.0.0:8443".to_owned());
    let apex = env::var("CLWD_APEX").unwrap_or_else(|_| "clwd.run".to_owned());
    let control_plane = env::var("CLWD_CONTROL_PLANE")
        .context("CLWD_CONTROL_PLANE must be the internal control-plane base URL")?;
    let internal_secret =
        env::var("CLWD_INTERNAL_SECRET").context("CLWD_INTERNAL_SECRET must be set")?;
    // One `{org}/cert.pem` + `{org}/key.pem` per org under this directory. #22's
    // secret broker replaces this file store behind the CertStore trait.
    let cert_dir = env::var("CLWD_CERT_DIR")
        .context("CLWD_CERT_DIR must name the per-org certificate directory")?;

    tracing::info!(%listen, %apex, %cert_dir, "gateway serving");

    let lookup = Arc::new(RouteLookup::new(control_plane, internal_secret)?);
    let edge = Edge::new(lookup, apex.clone());

    let store = Arc::new(DirCertStore::new(&cert_dir));
    let resolver = CertResolver::new(store, apex);
    let tls = TlsSettings::with_callbacks(DynamicCert::callbacks(resolver))
        .map_err(|e| anyhow::anyhow!("TLS settings: {e}"))?;

    let mut server = Server::new(None).map_err(|e| anyhow::anyhow!("pingora server: {e}"))?;
    server.bootstrap();

    let mut service = Service::new("gateway-edge".to_owned(), HttpServer::new_app(edge));
    service.add_tls_with_settings(&listen, None, tls);
    server.add_service(service);

    server.run_forever();
}
