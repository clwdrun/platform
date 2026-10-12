//! Serving over sockets: the accept loop, readiness, and the ops listener
//! (#48).
//!
//! # Three listeners
//!
//! - **public** ([`crate::http::router`]): sign-in, tokens, publish, the
//!   OpenAPI document. Reached through whatever forwards the platform's own
//!   hosts (#95).
//! - **internal** ([`crate::http::internal_router`]): the gateways' session
//!   checks, the handshake exchange, route resolution and the authorization
//!   stream. Private by policy ([`crate::config::private_only`]).
//! - **ops** ([`ops_service`]): `/livez` and `/readyz`, for the orchestrator.
//!   Private by the same policy, with no credential, and nothing else on it.
//!
//! # Connection-level protection
//!
//! axum's own `serve` builds hyper's connection builder without a timer, which
//! silently disables hyper's header read timeout: a client that sends a header
//! a byte at a time holds a connection forever (slowloris). So connections are
//! served here, with hyper directly: HTTP/1.1 only, a [`TokioTimer`], a
//! [`HEADER_READ_TIMEOUT`], and at most [`MAX_CONNECTIONS`] open per listener
//! (accepting pauses at the cap, so the kernel's backlog absorbs a burst
//! rather than the process running out of descriptors).
//!
//! # Draining
//!
//! Each listener's connections are watched by a [`GracefulShutdown`]: one
//! watch receiver per *connection*, nothing per request, so draining costs a
//! request nothing. On stop, the listener closes, every connection is told to
//! finish its in-flight request and close, and the drain waits up to
//! [`DRAIN`]: the request timeout, so every admitted request has either
//! finished or already timed out by then.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::http::{Method, Request, Response, StatusCode, header};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper_util::rt::{TokioIo, TokioTimer};
use hyper_util::server::graceful::GracefulShutdown;
use hyper_util::service::TowerToHyperService;
use tokio::net::TcpListener;
use tokio::sync::{Semaphore, watch};

use crate::reconcile::StateCell;
use crate::relay::Relay;
use crate::signin::SignIn;

/// How long a client may take to send a request's headers.
pub const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(10);

/// How long stopping waits for in-flight requests: the request timeout.
pub const DRAIN: Duration = crate::http::REQUEST_TIMEOUT;

/// Connections open at once on the public or internal listener.
pub const MAX_CONNECTIONS: usize = 512;

/// Connections open at once on the ops listener: an orchestrator's probes.
pub const MAX_OPS_CONNECTIONS: usize = 16;

/// How long `/readyz` gives the database to answer.
pub const READY_DB_CHECK: Duration = Duration::from_millis(500);

/// What readiness and the startup log read: set as startup progresses, and
/// by the shutdown sequence.
#[derive(Default)]
pub struct Health {
    stopping: AtomicBool,
    /// The serving pool, set once every connection is open.
    serving: OnceLock<sqlx::PgPool>,
    /// A connection of readiness's own, so a busy serving pool does not read
    /// as an unreachable database and take every instance out together.
    probe: OnceLock<sqlx::PgPool>,
    relay: OnceLock<Arc<Relay>>,
    signin: OnceLock<Arc<SignIn>>,
    reconciler: OnceLock<Arc<StateCell>>,
}

impl Health {
    #[must_use]
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// The serving pool is full and the readiness probe has its connection.
    pub fn pools_open(&self, serving: sqlx::PgPool, probe: sqlx::PgPool) {
        let _ = self.serving.set(serving);
        let _ = self.probe.set(probe);
    }

    pub fn relay_started(&self, relay: Arc<Relay>) {
        let _ = self.relay.set(relay);
    }

    pub fn signin_configured(&self, signin: Arc<SignIn>) {
        let _ = self.signin.set(signin);
    }

    pub fn reconciler(&self, state: Arc<StateCell>) {
        let _ = self.reconciler.set(state);
    }

    /// From here on, readiness is false: the first step of stopping.
    pub fn stop(&self) {
        self.stopping.store(true, Ordering::SeqCst);
    }

    /// Readiness, with every check's state.
    ///
    /// Ready means this instance can serve requests correctly: the pool is
    /// open, the database answers, and it is not stopping. The relay, sign-in
    /// discovery and the reconciler are **reported, never failed on**: each has
    /// a correct degraded mode (gateways bypass their caches, sign-in answers
    /// `identity.provider_unavailable`, certificates renew weeks ahead), and
    /// failing readiness on a shared dependency would take every instance out
    /// of the load balancer at once.
    pub async fn readiness(&self) -> Readiness {
        let stopping = self.stopping.load(Ordering::SeqCst);
        let pool = if self.serving.get().is_some() {
            "open"
        } else {
            "opening"
        };
        let database = match self.probe.get() {
            None => "not checked",
            Some(probe) => {
                match tokio::time::timeout(
                    READY_DB_CHECK,
                    sqlx::query_scalar::<_, i32>("select 1").fetch_one(probe),
                )
                .await
                {
                    Ok(Ok(_)) => "ok",
                    Ok(Err(_)) => "error",
                    Err(_) => "timeout",
                }
            }
        };
        let relay = match self.relay.get() {
            None => "not started",
            Some(relay) if relay.healthy() => "healthy",
            Some(_) => "degraded",
        };
        let oidc = match self.signin.get() {
            None => "not configured",
            Some(signin) if signin.discovered() => "discovered",
            Some(_) => "degraded",
        };
        let reconciler = self
            .reconciler
            .get()
            .map_or("not started", |state| state.get().as_str());
        Readiness {
            ready: !stopping && pool == "open" && database == "ok",
            stopping,
            pool,
            database,
            relay,
            oidc,
            reconciler,
        }
    }
}

/// One `/readyz` answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub struct Readiness {
    pub ready: bool,
    pub stopping: bool,
    pub pool: &'static str,
    pub database: &'static str,
    pub relay: &'static str,
    pub oidc: &'static str,
    pub reconciler: &'static str,
}

/// Log each change in the degraded checks once, every second, until `stop`.
pub async fn log_changes(health: Arc<Health>, mut stop: watch::Receiver<bool>) {
    let mut last: Option<Readiness> = None;
    loop {
        let now = health.readiness().await;
        if let Some(before) = last {
            for (check, was, is) in [
                ("relay", before.relay, now.relay),
                ("oidc", before.oidc, now.oidc),
                ("database", before.database, now.database),
            ] {
                if was != is {
                    // ponytail: a log line is the signal until #89's alerting
                    // exists; emit there too once it does.
                    tracing::warn!(check, was, is, "readiness check changed");
                }
            }
        }
        last = Some(now);
        tokio::select! {
            () = tokio::time::sleep(Duration::from_secs(1)) => {}
            () = stopped(&mut stop) => return,
        }
    }
}

/// The ops listener's whole surface: `GET /livez` and `GET /readyz`.
///
/// Plain hyper rather than an axum router: the route table in
/// [`crate::http`] is the only way into the router, and these two are not
/// part of the API.
pub async fn ops_service(
    health: Arc<Health>,
    request: Request<Incoming>,
) -> Result<Response<Body>, Infallible> {
    let response = match (request.method(), request.uri().path()) {
        (&Method::GET, "/livez") => plain(StatusCode::OK, "ok"),
        (&Method::GET, "/readyz") => {
            let readiness = health.readiness().await;
            let status = if readiness.ready {
                StatusCode::OK
            } else {
                StatusCode::SERVICE_UNAVAILABLE
            };
            match serde_json::to_string(&readiness) {
                Ok(json) => Response::builder()
                    .status(status)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(json))
                    .unwrap_or_else(|_| plain(StatusCode::INTERNAL_SERVER_ERROR, "")),
                Err(_) => plain(StatusCode::INTERNAL_SERVER_ERROR, ""),
            }
        }
        _ => plain(StatusCode::NOT_FOUND, "not found"),
    };
    Ok(response)
}

/// Resolve once `stop` is set (or its sender is gone). The guard
/// `wait_for` returns is dropped here, before anything else awaits: it is not
/// `Send`, and held across a `select!` it would make the task not `Send`.
pub async fn stopped(stop: &mut watch::Receiver<bool>) {
    let _ = stop.wait_for(|stop| *stop).await;
}

fn plain(status: StatusCode, text: &'static str) -> Response<Body> {
    let mut response = Response::new(Body::from(text));
    *response.status_mut() = status;
    response
}

/// How a listener's drain ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Drained {
    /// Connections open when the drain began.
    pub open: usize,
    /// Whether every one closed inside the deadline.
    pub complete: bool,
}

/// Serve `router` on `listener` until `stop` is set, then drain for up to
/// `drain`.
pub async fn serve_router(
    name: &'static str,
    listener: TcpListener,
    router: Router,
    limit: usize,
    stop: watch::Receiver<bool>,
    drain: Duration,
) -> Drained {
    serve(
        name,
        listener,
        TowerToHyperService::new(router),
        limit,
        stop,
        drain,
    )
    .await
}

/// Serve the ops endpoints on `listener` until `stop` is set.
pub async fn serve_ops(
    listener: TcpListener,
    health: Arc<Health>,
    stop: watch::Receiver<bool>,
) -> Drained {
    let service = hyper::service::service_fn(move |request| ops_service(health.clone(), request));
    serve(
        "ops",
        listener,
        service,
        MAX_OPS_CONNECTIONS,
        stop,
        Duration::from_secs(1),
    )
    .await
}

async fn serve<S>(
    name: &'static str,
    listener: TcpListener,
    service: S,
    limit: usize,
    mut stop: watch::Receiver<bool>,
    drain: Duration,
) -> Drained
where
    S: hyper::service::Service<Request<Incoming>, Response = Response<Body>>
        + Clone
        + Send
        + 'static,
    S::Future: Send + 'static,
    S::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    let graceful = GracefulShutdown::new();
    let permits = Arc::new(Semaphore::new(limit));
    let mut builder = http1::Builder::new();
    builder
        .timer(TokioTimer::new())
        .header_read_timeout(HEADER_READ_TIMEOUT)
        .keep_alive(true);

    loop {
        // A permit first, so at the cap nothing is accepted at all.
        let permit = tokio::select! {
            permit = permits.clone().acquire_owned() => match permit {
                Ok(permit) => permit,
                Err(_) => break,
            },
            () = stopped(&mut stop) => break,
        };
        let (stream, _peer): (_, SocketAddr) = tokio::select! {
            accepted = listener.accept() => match accepted {
                Ok(accepted) => accepted,
                Err(error) => {
                    // Out of descriptors, or a connection reset before
                    // accept: not fatal, and not worth a hot loop.
                    tracing::warn!(listener = name, %error, "accept failed");
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    continue;
                }
            },
            () = stopped(&mut stop) => break,
        };
        let connection = builder.serve_connection(TokioIo::new(stream), service.clone());
        let watched = graceful.watch(connection);
        tokio::spawn(async move {
            if let Err(error) = watched.await {
                tracing::debug!(%error, "connection ended with an error");
            }
            drop(permit);
        });
    }
    drop(listener);

    let open = graceful.count();
    tracing::info!(
        listener = name,
        open,
        deadline_s = drain.as_secs(),
        "draining"
    );
    let complete = tokio::time::timeout(drain, graceful.shutdown())
        .await
        .is_ok();
    if complete {
        tracing::info!(listener = name, "drained");
    } else {
        tracing::warn!(
            listener = name,
            "drain deadline passed with connections still open; closing them"
        );
    }
    Drained { open, complete }
}
