//! Apps, orgs, versions, share grants.
//! `runtime: Wasm | MicroVM` is stored as a single field here and never
//! branched on above clwd-runtime.
//!
//! # `bootstrap-token`
//!
//! ```text
//! control-plane bootstrap-token --org <slug> --name <name> --scopes admin \
//!     --direct-database-write
//! ```
//!
//! Until OIDC lands (#9) nothing can call the issuance route without a token,
//! so the first one is written straight into the database. This grants nothing
//! new — whoever holds `DATABASE_URL` already has full control — but it is an
//! operator's tool, and it refuses to run without a flag that says what it
//! does, so nobody reaches it by accident.
//!
//! The token goes to stdout and nothing else does, so `$(...)` captures exactly
//! the token. It is shown once.
//!
//! # `openapi`
//!
//! Prints the OpenAPI document built from the route table, and nothing else.
//! `just openapi` writes it to `crates/control-plane/openapi.json`, which is the
//! file the service serves and CI checks.
//!
//! # `migrate`
//!
//! Applies the migrations embedded in this binary to `DATABASE_URL`, over a
//! connection without the serving pool's statement timeout. The server never
//! migrates on its own: it refuses to start against a database that is behind
//! it (#48).
//!
//! # No subcommand: serve
//!
//! Configuration is in [`control_plane::config`]; the startup order, readiness
//! and the shutdown sequence are below, in [`serve`].

use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context as _, bail, ensure};
use control_plane::config::{Config, Reconciler};
use control_plane::reconcile::{ReconcilerState, StateCell};
use control_plane::serve::{self as serving, Health};
use control_plane::{auth, db, pool, token::Scopes};
use sqlx::ConnectOptions as _;
use tokio::net::TcpListener;
use tokio::signal::unix::{Signal, SignalKind, signal};
use tokio::sync::watch;

const SUBCOMMAND: &str = "bootstrap-token";
const OPENAPI: &str = "openapi";
const MIGRATE: &str = "migrate";

/// How long a stopping reconciler gets to finish the row it is on, after the
/// drain, before it is abandoned (its row is reclaimed once stale).
const BACKGROUND_STOP: Duration = Duration::from_secs(5);
const CONFIRM: &str = "--direct-database-write";
const USAGE: &str = "usage: control-plane bootstrap-token --org <slug> --name <name> \
                     --scopes <scope,...> --direct-database-write";

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut args = std::env::args().skip(1);
    let first = args.next();

    // Before telemetry, so stdout is the document and nothing else.
    if first.as_deref() == Some(OPENAPI) {
        print!("{}", control_plane::openapi::json()?);
        return Ok(());
    }

    shared::telemetry::init();

    match first.as_deref() {
        Some(SUBCOMMAND) => bootstrap(parse(args)?).await,
        Some(MIGRATE) => migrate().await,
        None => serve().await,
        Some(other) => bail!(
            "unknown subcommand {other:?}: expected none (serve), `{MIGRATE}`, `{OPENAPI}` or `{SUBCOMMAND}`"
        ),
    }
}

async fn migrate() -> anyhow::Result<()> {
    let url = std::env::var("DATABASE_URL")
        .context("DATABASE_URL must name the control plane's database")?;
    pool::migrate(&url, &pool::MIGRATOR)
        .await
        .context("applying migrations")?;
    tracing::info!("migrations applied");
    Ok(())
}

/// SIGTERM (what an orchestrator sends) or SIGINT (a terminal).
struct Signals {
    term: Signal,
    int: Signal,
}

impl Signals {
    fn install() -> anyhow::Result<Self> {
        Ok(Self {
            term: signal(SignalKind::terminate()).context("installing the SIGTERM handler")?,
            int: signal(SignalKind::interrupt()).context("installing the SIGINT handler")?,
        })
    }

    async fn next(&mut self) {
        tokio::select! {
            _ = self.term.recv() => {}
            _ = self.int.recv() => {}
        }
    }
}

async fn bind(var: &str, addr: std::net::SocketAddr) -> anyhow::Result<TcpListener> {
    TcpListener::bind(addr)
        .await
        .with_context(|| format!("binding {var} ({addr})"))
}

/// Serve until signalled, then stop in order.
///
/// Startup: configuration (every setting validated, or exit naming it);
/// bind all three listeners (a port conflict fails here); serve the ops
/// listener, not ready; reach the database, retrying while it is unreachable
/// and exiting if it refuses the credentials; refuse a schema behind this
/// build; open every pooled connection; start the relay, sign-in discovery and
/// the reconciler, none of which can stop the instance serving; serve the
/// public and internal listeners; ready.
///
/// Stopping, on SIGTERM or SIGINT: not ready at once; wait the pre-stop delay
/// so the load balancer stops sending; close both listeners and end every
/// authorization stream; drain for up to [`serving::DRAIN`]; stop the
/// reconciler between rows; close the pools; exit 0. A second signal at any
/// point exits 1 at once.
async fn serve() -> anyhow::Result<()> {
    let started = Instant::now();
    let config = Config::from_env().context("invalid configuration")?;
    let reconciler_on = matches!(config.reconciler, Reconciler::On(_));
    tracing::info!(
        public = %config.public.0,
        internal = %config.internal.0,
        ops = %config.ops.0,
        issuer = %config.oidc.issuer,
        control_plane = config.control_plane_domain.as_str(),
        apps = config.apps_domain.as_str(),
        pool = config.pool.max_connections,
        acquire_timeout_ms = config.pool.acquire_timeout.as_millis() as u64,
        pre_stop_s = config.pre_stop.as_secs(),
        reconciler = if reconciler_on { "on" } else { "off" },
        "control-plane starting"
    );
    if !config.oidc.issuer.starts_with("https://") {
        tracing::warn!(issuer = %config.oidc.issuer, "CLWD_ALLOW_INSECURE_ISSUER is set: sign-in trusts a plain-HTTP issuer");
    }

    let mut signals = Signals::install()?;
    let health = Health::new();
    let (ops_stop, ops_stopped) = watch::channel(false);
    let (stop, stopped) = watch::channel(false);
    let (background_stop, background_stopped) = watch::channel(false);

    let ops = bind("CLWD_OPS_LISTEN", config.ops.0).await?;
    let public = bind("CLWD_PUBLIC_LISTEN", config.public.0).await?;
    let internal = bind("CLWD_INTERNAL_LISTEN", config.internal.0).await?;
    let ops_task = tokio::spawn(serving::serve_ops(ops, health.clone(), ops_stopped));

    let reconciler_state = Arc::new(StateCell::new(ReconcilerState::Off));
    health.reconciler(reconciler_state.clone());

    let startup = start(config, &health, reconciler_state, &background_stopped);
    let running = tokio::select! {
        running = startup => running?,
        () = signals.next() => {
            tracing::info!("signalled during startup; exiting");
            return Ok(());
        }
    };

    let public_task = tokio::spawn(serving::serve_router(
        "public",
        public,
        control_plane::http::router(running.state.clone()),
        serving::MAX_CONNECTIONS,
        stopped.clone(),
        serving::DRAIN,
    ));
    let internal_task = tokio::spawn(serving::serve_router(
        "internal",
        internal,
        control_plane::http::internal_router(running.state.clone()),
        serving::MAX_CONNECTIONS,
        stopped,
        serving::DRAIN,
    ));
    drop(running.state);
    health.pools_open(running.serving.clone(), running.probe.clone());
    let log_task = tokio::spawn(serving::log_changes(health.clone(), background_stopped));
    tracing::info!(
        cold_start_ms = started.elapsed().as_millis() as u64,
        "ready"
    );

    signals.next().await;
    let stopping = Instant::now();
    health.stop();
    let _ = background_stop.send(true);
    tracing::info!(
        pre_stop_s = running.pre_stop.as_secs(),
        "stopping: not ready; waiting out the pre-stop delay"
    );

    let second = async {
        signals.next().await;
        tracing::warn!("second signal: exiting without draining");
        std::process::exit(1);
    };
    tokio::pin!(second);

    tokio::select! {
        () = tokio::time::sleep(running.pre_stop) => {}
        () = &mut second => {}
    }
    let _ = stop.send(true);
    if let Some(relay) = &running.relay {
        relay.shut();
    }
    let (public, internal) = tokio::select! {
        drained = async { tokio::join!(public_task, internal_task) } => drained,
        () = &mut second => unreachable_exit(),
    };
    for (name, drained) in [("public", public), ("internal", internal)] {
        match drained {
            Ok(drained) => tracing::info!(
                listener = name,
                open = drained.open,
                complete = drained.complete,
                "listener stopped"
            ),
            Err(error) => tracing::error!(listener = name, %error, "listener task failed"),
        }
    }

    running.discovery.abort();
    if let Some(mut reconciler) = running.reconciler {
        tokio::select! {
            finished = tokio::time::timeout(BACKGROUND_STOP, &mut reconciler) => {
                if finished.is_err() {
                    tracing::warn!("the reconciler did not stop between rows in time; abandoning its row, which is reclaimed once stale");
                    reconciler.abort();
                }
            }
            () = &mut second => unreachable_exit(),
        }
    }
    let _ = log_task.await;
    drop(running.relay);
    running.serving.close().await;
    running.probe.close().await;
    let _ = ops_stop.send(true);
    let _ = ops_task.await;
    tracing::info!(
        stopping_ms = stopping.elapsed().as_millis() as u64,
        "stopped"
    );
    Ok(())
}

/// The second-signal branch exits the process, so this is never reached; it
/// exists to give that branch a type.
fn unreachable_exit() -> ! {
    std::process::exit(1)
}

/// What startup hands to the serving phase.
struct Running {
    state: control_plane::http::AppState,
    serving: sqlx::PgPool,
    probe: sqlx::PgPool,
    relay: Option<Arc<control_plane::relay::Relay>>,
    discovery: tokio::task::JoinHandle<()>,
    reconciler: Option<tokio::task::JoinHandle<()>>,
    pre_stop: Duration,
}

/// Is a connect failure one that retrying can fix (the database is down or
/// starting), rather than one that it cannot (wrong credentials, no such
/// database)?
fn worth_retrying(error: &sqlx::Error) -> bool {
    match error {
        sqlx::Error::Io(_) | sqlx::Error::PoolTimedOut => true,
        // cannot_connect_now: the server is starting up or shutting down.
        sqlx::Error::Database(e) => e.code().as_deref() == Some("57P03"),
        _ => false,
    }
}

async fn start(
    config: Config,
    health: &Arc<Health>,
    reconciler_state: Arc<StateCell>,
    background_stopped: &watch::Receiver<bool>,
) -> anyhow::Result<Running> {
    let options = pool::serving_options(config.database_url.expose())
        .context("DATABASE_URL is not a usable Postgres URL")?;

    // Reach the database, waiting while it is unreachable: readiness says
    // so meanwhile, and the orchestrator decides how long that is allowed.
    let mut wait = Duration::from_millis(250);
    let mut failures = 0u32;
    let mut gate = loop {
        match options.connect().await {
            Ok(connection) => break connection,
            Err(error) if worth_retrying(&error) => {
                failures += 1;
                if failures == 1 {
                    tracing::warn!(%error, "the database is unreachable; not ready until it answers");
                }
                tokio::time::sleep(wait).await;
                wait = (wait * 2).min(Duration::from_secs(5));
            }
            Err(error) => return Err(error).context("connecting with DATABASE_URL"),
        }
    };
    pool::check_schema(&mut gate, &pool::MIGRATOR)
        .await
        .context("refusing to serve")?;
    sqlx::Connection::close(gate)
        .await
        .context("closing the schema check's connection")?;

    let serving = pool::open(options.clone(), config.pool)
        .await
        .context("opening the serving pool (CLWD_DB_MAX_CONNECTIONS)")?;
    let probe = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .min_connections(1)
        .idle_timeout(None)
        .max_lifetime(None)
        .acquire_timeout(serving::READY_DB_CHECK)
        .connect_lazy_with(options);

    let relay = match control_plane::relay::Relay::start(&serving).await {
        Ok(relay) => {
            health.relay_started(relay.clone());
            Some(relay)
        }
        Err(error) => {
            // Degraded, not down: with no relay every gateway takes the
            // uncached path, which is correct (#12).
            tracing::error!(%error, "the authorization relay did not start; gateways will bypass their caches");
            None
        }
    };

    let signin = Arc::new(
        control_plane::signin::SignIn::new(config.oidc.to_identity(), config.session_key)
            .context("CLWD_GOOGLE_REDIRECT_URI")?,
    );
    health.signin_configured(signin.clone());
    let discovery = {
        let signin = signin.clone();
        tokio::spawn(async move { signin.discover_until_ready().await })
    };

    let txt = control_plane::orgs::SystemTxtLookup::new()
        .map_err(anyhow::Error::msg)
        .context("reading the system resolver configuration, for domain verification")?;
    let operator = opendal::Operator::new(
        opendal::services::Fs::default().root(
            config
                .artifact_root
                .to_str()
                .context("CLWD_ARTIFACT_ROOT is not valid UTF-8")?,
        ),
    )
    .context("CLWD_ARTIFACT_ROOT")?;

    let reconciler = match config.reconciler {
        Reconciler::Off => None,
        Reconciler::On(acme) => Some(start_reconciler(
            acme,
            serving.clone(),
            config.apps_domain.clone(),
            reconciler_state,
            background_stopped.clone(),
        )?),
    };

    let mut state =
        control_plane::http::AppState::new(serving.clone(), builder::ArtifactStore::new(operator))
            .with_internal_secret(config.internal_secret.expose())
            .with_signin(signin)
            .with_apps_domain(config.apps_domain)
            .with_txt_lookup(Arc::new(txt));
    if let Some(relay) = &relay {
        state = state.with_relay(relay.clone());
    }

    Ok(Running {
        state,
        serving,
        probe,
        relay,
        discovery,
        reconciler,
        pre_stop: config.pre_stop,
    })
}

fn start_reconciler(
    acme: control_plane::config::Acme,
    pool: sqlx::PgPool,
    apps: shared::domains::AppsDomain,
    state: Arc<StateCell>,
    stop: watch::Receiver<bool>,
) -> anyhow::Result<tokio::task::JoinHandle<()>> {
    control_plane::acme::install_crypto_provider();
    // Read and parse now, so a missing or malformed file fails startup; the
    // account itself is restored in the background, since that reaches the CA.
    let credentials = std::fs::read_to_string(&acme.account_file).with_context(|| {
        format!(
            "reading CLWD_ACME_ACCOUNT_FILE ({})",
            acme.account_file.display()
        )
    })?;
    let _parsed: instant_acme::AccountCredentials = serde_json::from_str(&credentials)
        .context("CLWD_ACME_ACCOUNT_FILE is not ACME account credentials")?;
    let dns: Arc<dyn control_plane::acme::DnsProvider> = Arc::new(
        control_plane::cloudflare::CloudflareDns::new(
            acme.cloudflare_token.expose(),
            acme.cloudflare_zone_id,
            acme.cloudflare_nameservers,
        )
        .context("CLWD_CLOUDFLARE_TOKEN")?,
    );
    let store: Arc<dyn shared::cert::CertStore> =
        Arc::new(shared::cert::DirCertStore::new(acme.cert_dir));
    let ca_root = acme.ca_root;
    let connect = {
        let pool = pool.clone();
        move || {
            let (credentials, ca_root, dns, store, pool, apps) = (
                credentials.clone(),
                ca_root.clone(),
                dns.clone(),
                store.clone(),
                pool.clone(),
                apps.clone(),
            );
            async move {
                let credentials =
                    serde_json::from_str::<instant_acme::AccountCredentials>(&credentials)
                        .map_err(|e| e.to_string())?;
                let builder = match &ca_root {
                    Some(root) => instant_acme::Account::builder_with_root(root),
                    None => instant_acme::Account::builder(),
                }
                .map_err(|e| e.to_string())?;
                let account = builder
                    .from_credentials(credentials)
                    .await
                    .map_err(|e| e.to_string())?;
                Ok(control_plane::acme::CertIssuer::new(
                    account, dns, store, pool, apps,
                ))
            }
        }
    };
    Ok(tokio::spawn(control_plane::reconcile::run(
        pool, connect, state, stop,
    )))
}

#[derive(Debug)]
struct Bootstrap {
    org: String,
    name: String,
    scopes: Scopes,
}

fn parse(mut args: impl Iterator<Item = String>) -> anyhow::Result<Bootstrap> {
    let (mut org, mut name, mut scopes, mut confirmed) = (None, None, None, false);

    while let Some(flag) = args.next() {
        let mut value = || {
            args.next()
                .with_context(|| format!("{flag} needs a value\n{USAGE}"))
        };
        match flag.as_str() {
            "--org" => org = Some(value()?),
            "--name" => name = Some(value()?),
            "--scopes" => scopes = Some(Scopes::parse_all(value()?.split(','))?),
            CONFIRM => confirmed = true,
            _ => bail!("unexpected argument {flag:?}\n{USAGE}"),
        }
    }

    ensure!(
        confirmed,
        "refusing to run without {CONFIRM}: this writes a credential straight into the \
         database, bypassing the API\n{USAGE}"
    );

    Ok(Bootstrap {
        org: org.with_context(|| format!("--org is required\n{USAGE}"))?,
        name: name.with_context(|| format!("--name is required\n{USAGE}"))?,
        scopes: scopes.with_context(|| format!("--scopes is required\n{USAGE}"))?,
    })
}

async fn bootstrap(args: Bootstrap) -> anyhow::Result<()> {
    let url = std::env::var("DATABASE_URL")
        .context("DATABASE_URL must name the control plane's database")?;
    let pool = sqlx::PgPool::connect(&url)
        .await
        .context("connecting to the database")?;

    let org = db::org_by_slug(&pool, &args.org)
        .await?
        .with_context(|| format!("no live org has the slug {:?}", args.org))?;
    let issued = auth::issue(&pool, org.id, None, &args.name, args.scopes).await?;

    eprintln!(
        "issued token {} for org {} with scopes: {}. It is shown once and cannot be recovered.",
        issued.id, org.slug, args.scopes
    );
    println!("{}", issued.secret.expose());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> impl Iterator<Item = String> {
        list.iter()
            .map(|s| (*s).to_owned())
            .collect::<Vec<_>>()
            .into_iter()
    }

    #[test]
    fn a_complete_invocation_parses() {
        let parsed = parse(args(&[
            "--org",
            "acme",
            "--name",
            "ci",
            "--scopes",
            "admin,publish",
            CONFIRM,
        ]))
        .expect("complete");
        assert_eq!(parsed.org, "acme");
        assert_eq!(parsed.name, "ci");
        assert_eq!(parsed.scopes.to_names(), ["publish", "admin"]);
    }

    /// The flag is the guard against running this by accident.
    #[test]
    fn it_refuses_without_the_confirmation_flag() {
        let err = parse(args(&[
            "--org", "acme", "--name", "ci", "--scopes", "admin",
        ]))
        .expect_err("unconfirmed");
        assert!(err.to_string().contains(CONFIRM), "{err}");
    }

    #[test]
    fn unknown_arguments_and_scopes_are_rejected() {
        assert!(parse(args(&["--org", "acme", "--verbose", CONFIRM])).is_err());
        assert!(parse(args(&["--scopes", "root", CONFIRM])).is_err());
        assert!(parse(args(&["--org"])).is_err(), "a flag with no value");
    }
}
