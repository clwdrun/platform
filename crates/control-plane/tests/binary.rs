//! The serving binary, started as a child process with real configuration
//! (#48).
//!
//! Every other test drives the router in-process, which is how a missing
//! layer in `main` would go unnoticed. These spawn the built binary, talk to
//! it over sockets, and signal it. Numbered as in #48.
//!
//! Timing: nothing here sleeps to synchronise. Each wait is a poll for a
//! named condition with a deadline, and the deadline's panic prints the
//! binary's output.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::{ExitStatus, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::routing::get;
use control_plane::http::{Access, production_routes};
use sqlx::PgPool;
use tokio::io::{AsyncBufReadExt as _, AsyncReadExt as _, AsyncWriteExt as _, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::process::{Child, Command};

const SECRET: &str = "binary-test-internal-secret-0123456789";
const SESSION_KEY: &str = "binary-test-session-key-0123456789abcdef";
const CLIENT_SECRET: &str = "binary-test-google-client-secret";
const DB_PASSWORD_MARKER: &str = "binary-test-never-printed";

// ------------------------------------------------------------- harness ----

fn free_addr() -> SocketAddr {
    std::net::TcpListener::bind("127.0.0.1:0")
        .and_then(|l| l.local_addr())
        .expect("a free port")
}

fn database_url(pool: &PgPool) -> String {
    use sqlx::ConnectOptions as _;
    pool.connect_options().to_url_lossy().to_string()
}

fn scratch_dir(label: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "clwd-binary-{label}-{}-{}",
        std::process::id(),
        uuid::Uuid::now_v7()
    ));
    std::fs::create_dir_all(&dir).expect("scratch dir");
    dir
}

/// A complete, valid configuration on three fresh ports.
#[derive(Clone)]
struct Env {
    vars: BTreeMap<&'static str, String>,
    public: SocketAddr,
    internal: SocketAddr,
    ops: SocketAddr,
}

impl Env {
    fn new(database_url: &str, issuer: &str) -> Self {
        let (public, internal, ops) = (free_addr(), free_addr(), free_addr());
        let vars = [
            ("DATABASE_URL", database_url.to_owned()),
            ("CLWD_PUBLIC_LISTEN", public.to_string()),
            ("CLWD_INTERNAL_LISTEN", internal.to_string()),
            ("CLWD_OPS_LISTEN", ops.to_string()),
            ("CLWD_INTERNAL_SECRET", SECRET.to_owned()),
            ("CLWD_SESSION_KEY", SESSION_KEY.to_owned()),
            ("CLWD_GOOGLE_CLIENT_ID", "client".to_owned()),
            ("CLWD_GOOGLE_CLIENT_SECRET", CLIENT_SECRET.to_owned()),
            (
                "CLWD_GOOGLE_REDIRECT_URI",
                format!("http://{public}/auth/google/callback"),
            ),
            ("CLWD_OIDC_ISSUER", issuer.to_owned()),
            ("CLWD_ALLOW_INSECURE_ISSUER", "1".to_owned()),
            ("CLWD_CONTROL_PLANE_DOMAIN", "api.clwd.test".to_owned()),
            ("CLWD_APPS_DOMAIN", "clwd.app".to_owned()),
            (
                "CLWD_ARTIFACT_ROOT",
                scratch_dir("artifacts").to_string_lossy().into_owned(),
            ),
            ("CLWD_CERT_RECONCILER", "off".to_owned()),
            ("CLWD_PRE_STOP_DELAY", "0s".to_owned()),
            ("RUST_LOG", "info".to_owned()),
            ("NO_COLOR", "1".to_owned()),
        ]
        .into_iter()
        .collect();
        Self {
            vars,
            public,
            internal,
            ops,
        }
    }

    fn set(mut self, var: &'static str, value: impl Into<String>) -> Self {
        self.vars.insert(var, value.into());
        self
    }

    fn without(mut self, var: &str) -> Self {
        self.vars.remove(var);
        self
    }
}

/// A running binary. Killed on drop.
struct Cp {
    child: Child,
    public: SocketAddr,
    internal: SocketAddr,
    ops: SocketAddr,
    output: Arc<Mutex<String>>,
}

fn collect(
    output: &Arc<Mutex<String>>,
    stream: impl tokio::io::AsyncRead + Unpin + Send + 'static,
) {
    let output = output.clone();
    tokio::spawn(async move {
        let mut lines = BufReader::new(stream).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            let mut out = output.lock().expect("lock");
            out.push_str(&line);
            out.push('\n');
        }
    });
}

impl Cp {
    fn start(env: &Env) -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_control-plane"))
            .env_clear()
            .envs(&env.vars)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .expect("spawn the control-plane binary");
        let output = Arc::new(Mutex::new(String::new()));
        collect(&output, child.stdout.take().expect("stdout"));
        collect(&output, child.stderr.take().expect("stderr"));
        Self {
            child,
            public: env.public,
            internal: env.internal,
            ops: env.ops,
            output,
        }
    }

    fn output(&self) -> String {
        self.output.lock().expect("lock").clone()
    }

    async fn readyz(&self) -> Option<(u16, serde_json::Value)> {
        let response = client()
            .get(format!("http://{}/readyz", self.ops))
            .send()
            .await
            .ok()?;
        let status = response.status().as_u16();
        Some((status, response.json().await.ok()?))
    }

    /// Poll `/readyz` until `until` holds for its answer.
    async fn wait_readyz(
        &self,
        what: &str,
        until: impl Fn(u16, &serde_json::Value) -> bool,
    ) -> serde_json::Value {
        let deadline = Instant::now() + Duration::from_secs(90);
        loop {
            if let Some((status, body)) = self.readyz().await
                && until(status, &body)
            {
                return body;
            }
            assert!(
                Instant::now() < deadline,
                "waited 90 s for readiness to be {what}; output:\n{}",
                self.output()
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    async fn ready(&self) -> serde_json::Value {
        self.wait_readyz("ready", |status, _| status == 200).await
    }

    fn signal(&self, signal: libc::c_int) {
        let pid = self.child.id().expect("running") as libc::pid_t;
        // SAFETY: `kill` on a child we spawned and still own.
        let sent = unsafe { libc::kill(pid, signal) };
        assert_eq!(sent, 0, "signal {signal} to {pid}");
    }

    async fn exit(&mut self, within: Duration) -> ExitStatus {
        match tokio::time::timeout(within, self.child.wait()).await {
            Ok(status) => status.expect("wait"),
            Err(_) => panic!("did not exit within {within:?}; output:\n{}", self.output()),
        }
    }
}

/// Start the binary with `env` and wait for it to exit on its own.
async fn exits(env: &Env, within: Duration) -> (ExitStatus, String) {
    let mut cp = Cp::start(env);
    let status = cp.exit(within).await;
    // The output readers finish once the pipes close.
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline && !cp.output().contains("Error") {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    (status, cp.output())
}

fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(40))
        .build()
        .expect("client")
}

/// A discovery-only OIDC issuer: enough for sign-in to start. Serves on
/// `listener`, which the caller may bind late to model an outage.
fn start_issuer(listener: TcpListener) -> tokio::task::JoinHandle<()> {
    let issuer = format!("http://{}", listener.local_addr().expect("addr"));
    #[expect(
        clippy::disallowed_methods,
        reason = "a mock OIDC issuer, not the guarded control-plane router"
    )]
    let app = axum::Router::new()
        .route(
            "/.well-known/openid-configuration",
            get(move || {
                let issuer = issuer.clone();
                async move {
                    axum::Json(serde_json::json!({
                        "issuer": issuer,
                        "authorization_endpoint": format!("{issuer}/authorize"),
                        "token_endpoint": format!("{issuer}/token"),
                        "jwks_uri": format!("{issuer}/jwks"),
                        "response_types_supported": ["code"],
                        "subject_types_supported": ["public"],
                        "id_token_signing_alg_values_supported": ["RS256"],
                    }))
                }
            }),
        )
        .route(
            "/jwks",
            get(|| async { axum::Json(serde_json::json!({ "keys": [] })) }),
        );
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    })
}

async fn issuer() -> (String, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind issuer");
    let url = format!("http://{}", listener.local_addr().expect("addr"));
    (url, start_issuer(listener))
}

/// The session check with a well-formed session that matches nothing.
async fn check(internal: SocketAddr) -> reqwest::Response {
    client()
        .post(format!("http://{internal}/internal/app-sessions/check"))
        .bearer_auth(SECRET)
        .json(&serde_json::json!({
            "session": "5e".repeat(32),
            "app_id": uuid::Uuid::now_v7(),
        }))
        .send()
        .await
        .expect("the check answers")
}

async fn envelope(response: reqwest::Response) -> (u16, String) {
    let status = response.status().as_u16();
    let json: serde_json::Value = response.json().await.expect("an envelope");
    (status, json["code"].as_str().unwrap_or_default().to_owned())
}

/// Wait until a statement from another connection is blocked on a lock.
async fn wait_for_lock_waiters(pool: &PgPool, at_least: i64) {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let waiting: i64 = sqlx::query_scalar(
            "select count(*) from pg_stat_activity
              where datname = current_database() and wait_event_type = 'Lock'",
        )
        .fetch_one(pool)
        .await
        .expect("pg_stat_activity");
        if waiting >= at_least {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "{waiting} of {at_least} lock waiters after 10 s"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

// --------------------------------------------------------------- tests ----

/// 1. It serves: readiness turns ready once the database and the relay are
/// up, and the public and internal routes answer over sockets.
#[sqlx::test(migrations = "../../migrations")]
async fn it_serves(pool: PgPool) {
    let (issuer, _issuer) = issuer().await;
    let cp = Cp::start(&Env::new(&database_url(&pool), &issuer));
    let ready = cp
        .wait_readyz("ready with the relay healthy", |status, body| {
            status == 200 && body["relay"] == "healthy"
        })
        .await;
    assert_eq!(ready["pool"], "open");
    assert_eq!(ready["database"], "ok");

    let live = client()
        .get(format!("http://{}/livez", cp.ops))
        .send()
        .await
        .expect("livez");
    assert_eq!(live.status(), 200);

    let openapi = client()
        .get(format!("http://{}/openapi.json", cp.public))
        .send()
        .await
        .expect("openapi");
    assert_eq!(openapi.status(), 200);
    let doc: serde_json::Value = openapi.json().await.expect("json");
    assert!(
        doc["paths"].get("/healthz").is_none(),
        "public /healthz is gone"
    );

    let (status, code) = envelope(check(cp.internal).await).await;
    assert_eq!((status, code.as_str()), (401, "identity.unauthenticated"));
}

/// The issue's acceptance criterion: not ready before the database is
/// reachable, ready after, with no restart.
#[sqlx::test(migrations = "../../migrations")]
async fn readiness_waits_for_the_database(pool: PgPool) {
    use sqlx::ConnectOptions as _;
    let real = pool.connect_options();
    let upstream = format!("{}:{}", real.get_host(), real.get_port());
    let proxy = free_addr();
    let mut url = real.to_url_lossy();
    url.set_port(Some(proxy.port())).expect("port");
    url.set_host(Some("127.0.0.1")).expect("host");

    let (issuer, _issuer) = issuer().await;
    let cp = Cp::start(&Env::new(url.as_str(), &issuer));
    // Nothing listens on the proxy's port yet: the database is unreachable.
    let before = cp
        .wait_readyz("answering, not ready", |status, _| status == 503)
        .await;
    assert_eq!(before["pool"], "opening", "{before}");
    let deadline = Instant::now() + Duration::from_secs(5);
    while !cp.output().contains("the database is unreachable") {
        assert!(
            Instant::now() < deadline,
            "no unreachable log:\n{}",
            cp.output()
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    let listener = TcpListener::bind(proxy).await.expect("bind the proxy");
    tokio::spawn(async move {
        while let Ok((mut inbound, _)) = listener.accept().await {
            let upstream = upstream.clone();
            tokio::spawn(async move {
                if let Ok(mut outbound) = TcpStream::connect(upstream).await {
                    let _ = tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await;
                }
            });
        }
    });
    let after = cp.ready().await;
    assert_eq!(after["database"], "ok");
}

/// 2. No internal path is served on the public listener, and no public path
/// on the internal one. The path list is the route table, so a new route is
/// covered without editing this test.
#[sqlx::test(migrations = "../../migrations")]
async fn the_internal_router_is_not_on_the_public_port(pool: PgPool) {
    let (issuer, _issuer) = issuer().await;
    let cp = Cp::start(&Env::new(&database_url(&pool), &issuer));
    cp.ready().await;

    let mut checked = 0;
    for route in production_routes() {
        let path = route
            .path
            .replace("{org}", "acme")
            .replace("{app}", "notes")
            .replace("{app_id}", &uuid::Uuid::now_v7().to_string())
            .replace("{org_id}", &uuid::Uuid::now_v7().to_string())
            .replace("{token_id}", &uuid::Uuid::now_v7().to_string())
            .replace("{claim_id}", &uuid::Uuid::now_v7().to_string());
        assert!(!path.contains('{'), "an unfilled parameter in {path}");
        let wrong = if route.access == Access::Internal {
            cp.public
        } else {
            cp.internal
        };
        let response = client()
            .request(route.verb.method(), format!("http://{wrong}{path}"))
            .bearer_auth(SECRET)
            .header("content-type", "application/json")
            .body("{}")
            .send()
            .await
            .expect("an answer");
        let (status, code) = envelope(response).await;
        assert_eq!(
            (status, code.as_str()),
            (404, "control-plane.not_found"),
            "{} {path} on the wrong listener ({wrong})",
            route.verb.method()
        );
        checked += 1;
    }
    let internal = production_routes()
        .iter()
        .filter(|r| r.access == Access::Internal)
        .count();
    assert!(
        internal >= 6 && checked > internal,
        "checked {checked}, {internal} internal"
    );
}

/// 3. Each required variable, missing: the binary exits non-zero, names it,
/// and never prints a secret.
#[sqlx::test(migrations = "../../migrations")]
async fn config_failures_are_legible(pool: PgPool) {
    let url = database_url(&pool).replacen("://", &format!("://{DB_PASSWORD_MARKER}@"), 1);
    // The marker rides in the URL's user part, so a printed URL would show it.
    let base = Env::new(&url, "http://127.0.0.1:9");
    for var in [
        "DATABASE_URL",
        "CLWD_PUBLIC_LISTEN",
        "CLWD_INTERNAL_LISTEN",
        "CLWD_OPS_LISTEN",
        "CLWD_INTERNAL_SECRET",
        "CLWD_SESSION_KEY",
        "CLWD_GOOGLE_CLIENT_ID",
        "CLWD_GOOGLE_CLIENT_SECRET",
        "CLWD_GOOGLE_REDIRECT_URI",
        "CLWD_CONTROL_PLANE_DOMAIN",
        "CLWD_APPS_DOMAIN",
        "CLWD_ARTIFACT_ROOT",
        "CLWD_CERT_RECONCILER",
    ] {
        let started = Instant::now();
        let (status, output) = exits(&base.clone().without(var), Duration::from_secs(10)).await;
        assert!(!status.success(), "started without {var}:\n{output}");
        assert!(
            output.contains(&format!("{var} is required")),
            "the error does not name {var}:\n{output}"
        );
        assert!(started.elapsed() < Duration::from_secs(10));
        for secret in [SECRET, SESSION_KEY, CLIENT_SECRET, DB_PASSWORD_MARKER] {
            assert!(
                !output.contains(secret),
                "a secret was printed without {var}:\n{output}"
            );
        }
    }
}

/// 4. The internal and ops listeners refuse a public or unspecified address
/// without the override, and the unspecified one even with it.
#[sqlx::test(migrations = "../../migrations")]
async fn no_unspecified_or_public_bind_by_accident(pool: PgPool) {
    let base = Env::new(&database_url(&pool), "http://127.0.0.1:9");
    for (var, allow) in [
        ("CLWD_INTERNAL_LISTEN", "CLWD_INTERNAL_LISTEN_ALLOW_PUBLIC"),
        ("CLWD_OPS_LISTEN", "CLWD_OPS_LISTEN_ALLOW_PUBLIC"),
    ] {
        let port = free_addr().port();
        for (address, override_, expect) in [
            (format!("0.0.0.0:{port}"), false, "every interface"),
            (format!("0.0.0.0:{port}"), true, "every interface"),
            (format!("[::]:{port}"), true, "every interface"),
            (format!("203.0.113.9:{port}"), false, "_ALLOW_PUBLIC=1"),
        ] {
            let mut env = base.clone().set(var, address.clone());
            if override_ {
                env = env.set(allow, "1");
            }
            let (status, output) = exits(&env, Duration::from_secs(10)).await;
            assert!(!status.success(), "{var}={address} started:\n{output}");
            assert!(
                output.contains(var) && output.contains(expect),
                "{var}={address}: expected {expect:?}:\n{output}"
            );
        }
    }
}

/// 5. Pool exhaustion is named: with every connection held, a request gets
/// `control-plane.timeout` within the acquire timeout, well inside the
/// gateway's 5 s.
#[sqlx::test(migrations = "../../migrations")]
async fn pool_exhaustion_is_named(pool: PgPool) {
    let (issuer, _issuer) = issuer().await;
    let env = Env::new(&database_url(&pool), &issuer)
        .set("CLWD_DB_MAX_CONNECTIONS", "2")
        .set("CLWD_DB_ACQUIRE_TIMEOUT", "500ms");
    let cp = Cp::start(&env);
    cp.ready().await;

    // Hold both pooled connections: two checks blocked on a lock this test
    // holds, each inside the 2 s statement timeout.
    let mut lock = pool.begin().await.expect("begin");
    sqlx::query("lock table app_sessions in access exclusive mode")
        .execute(&mut *lock)
        .await
        .expect("lock");
    let holders: Vec<_> = (0..2).map(|_| tokio::spawn(check(cp.internal))).collect();
    wait_for_lock_waiters(&pool, 2).await;

    let started = Instant::now();
    let (status, code) = envelope(check(cp.internal).await).await;
    let waited = started.elapsed();
    assert_eq!((status, code.as_str()), (504, "control-plane.timeout"));
    assert!(
        waited < Duration::from_millis(1500),
        "answered after {waited:?}: the acquire timeout is 500 ms and a held connection frees at 2 s"
    );
    lock.rollback().await.expect("release");
    for holder in holders {
        let _ = holder.await;
    }
}

/// 6. `statement_timeout` bites: a statement stuck past 2 s is cancelled,
/// answered as `control-plane.timeout`, and its connection goes back to the
/// pool (a pool of one, so the next request proves it).
#[sqlx::test(migrations = "../../migrations")]
async fn statement_timeout_bites(pool: PgPool) {
    let (issuer, _issuer) = issuer().await;
    let env = Env::new(&database_url(&pool), &issuer).set("CLWD_DB_MAX_CONNECTIONS", "1");
    let cp = Cp::start(&env);
    cp.ready().await;

    let mut lock = pool.begin().await.expect("begin");
    sqlx::query("lock table app_sessions in access exclusive mode")
        .execute(&mut *lock)
        .await
        .expect("lock");
    let started = Instant::now();
    let (status, code) = envelope(check(cp.internal).await).await;
    let waited = started.elapsed();
    assert_eq!((status, code.as_str()), (504, "control-plane.timeout"));
    assert!(
        waited >= Duration::from_secs(2) && waited < Duration::from_secs(4),
        "answered after {waited:?}; the statement timeout is 2 s"
    );
    lock.rollback().await.expect("release");

    let (status, code) = envelope(check(cp.internal).await).await;
    assert_eq!(
        (status, code.as_str()),
        (401, "identity.unauthenticated"),
        "the one connection is back in the pool"
    );
}

/// 7. The schema gate: one migration behind, the binary refuses to start and
/// says what to run.
#[sqlx::test(migrations = "../../migrations")]
async fn a_database_behind_the_build_is_refused(pool: PgPool) {
    sqlx::query(
        "delete from _sqlx_migrations where version = (select max(version) from _sqlx_migrations)",
    )
    .execute(&pool)
    .await
    .expect("forget the latest migration");
    let env = Env::new(&database_url(&pool), "http://127.0.0.1:9");
    let (status, output) = exits(&env, Duration::from_secs(30)).await;
    assert!(
        !status.success(),
        "started against a database behind it:\n{output}"
    );
    assert!(
        output.contains("the database is behind this build")
            && output.contains("control-plane migrate"),
        "{output}"
    );
}

/// 8. The drain, in order: readiness goes false while connections are still
/// accepted; then the listener closes and an open authorization stream ends
/// at once; a request in flight completes; the process exits 0 well inside
/// the deadline.
#[sqlx::test(migrations = "../../migrations")]
async fn sigterm_drains_in_order(pool: PgPool) {
    let (issuer, _issuer) = issuer().await;
    let env = Env::new(&database_url(&pool), &issuer).set("CLWD_PRE_STOP_DELAY", "2s");
    let mut cp = Cp::start(&env);
    cp.wait_readyz("ready with the relay healthy", |status, body| {
        status == 200 && body["relay"] == "healthy"
    })
    .await;

    // An open authorization stream, past its hello.
    let mut stream = client()
        .get(format!("http://{}/internal/authz/stream", cp.internal))
        .bearer_auth(SECRET)
        .send()
        .await
        .expect("stream");
    assert_eq!(stream.status(), 200);
    let hello = stream.chunk().await.expect("read").expect("a hello");
    assert!(
        String::from_utf8_lossy(&hello).contains("hello"),
        "{hello:?}"
    );

    // A request in flight: headers sent, body not yet.
    let body = serde_json::json!({ "session": "5e".repeat(32), "app_id": uuid::Uuid::now_v7() })
        .to_string();
    let mut in_flight = TcpStream::connect(cp.internal).await.expect("connect");
    in_flight
        .write_all(
            format!(
                "POST /internal/app-sessions/check HTTP/1.1\r\nhost: cp\r\nauthorization: Bearer {SECRET}\r\n\
                 content-type: application/json\r\ncontent-length: {}\r\n\r\n",
                body.len()
            )
            .as_bytes(),
        )
        .await
        .expect("headers");

    cp.signal(libc::SIGTERM);
    let signalled = Instant::now();

    // Readiness flips first, while the public listener still accepts.
    cp.wait_readyz("not ready", |status, body| {
        status == 503 && body["stopping"] == true
    })
    .await;
    let not_ready_at = Instant::now();
    assert!(
        TcpStream::connect(cp.public).await.is_ok(),
        "the listener closed before readiness went false"
    );

    // Then the listener closes.
    let deadline = Instant::now() + Duration::from_secs(10);
    while TcpStream::connect(cp.public).await.is_ok() {
        assert!(
            Instant::now() < deadline,
            "still accepting 10 s after SIGTERM"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let closed_at = Instant::now();
    // Readiness went false a whole pre-stop delay (2 s) before the listener
    // closed: the load balancer's window to stop sending. Flipping it at the
    // moment of closing would leave no such window.
    let window = closed_at - not_ready_at;
    assert!(
        window >= Duration::from_millis(1500),
        "readiness went false only {window:?} before the listener closed; the pre-stop delay is 2 s"
    );

    // The stream ends promptly, not at the 30 s drain deadline.
    let ended = tokio::time::timeout(Duration::from_secs(3), async {
        while let Ok(Some(_)) = stream.chunk().await {}
    })
    .await;
    assert!(
        ended.is_ok(),
        "the authorization stream was still open 3 s after the listener closed"
    );

    // The request in flight completes after the listener closed.
    in_flight.write_all(body.as_bytes()).await.expect("body");
    let mut answer = String::new();
    tokio::time::timeout(
        Duration::from_secs(10),
        in_flight.read_to_string(&mut answer),
    )
    .await
    .expect("an answer within 10 s")
    .expect("read");
    assert!(answer.starts_with("HTTP/1.1 401"), "{answer}");

    let status = cp.exit(Duration::from_secs(30)).await;
    assert!(status.success(), "exit {status}:\n{}", cp.output());
    assert!(
        signalled.elapsed() < Duration::from_secs(10),
        "took {:?} to stop",
        signalled.elapsed()
    );
}

/// A live app session for `app`, as the sign-in handshake would leave one.
async fn live_session(pool: &PgPool) -> (String, uuid::Uuid) {
    use control_plane::db;
    let org = db::create_org(pool, "acme").await.expect("org");
    let app = db::create_app(pool, org.id, "notes", "wasm")
        .await
        .expect("app");
    let user = db::create_user(pool, "v@example.com").await.expect("user");
    db::add_org_member(
        pool,
        org.id,
        user.id,
        control_plane::orgs::JoinedVia::Claimant,
    )
    .await
    .expect("member");
    let key =
        control_plane::signin::CookieKey::from_secret(SESSION_KEY.as_bytes()).expect("long enough");
    let parent = control_plane::session::issue(pool, &key, user.id)
        .await
        .expect("issue")
        .expect("a session")
        .id;
    let raw = "6f".repeat(32);
    sqlx::query("insert into app_subjects (app_id, user_id) values ($1, $2)")
        .bind(app.id.as_uuid())
        .bind(user.id.as_uuid())
        .execute(pool)
        .await
        .expect("subject");
    sqlx::query(
        "insert into app_sessions (id, parent_session_id, app_id, secret_sha256, expires_at)
         values (gen_random_uuid(), $1, $2, $3, now() + interval '1 hour')",
    )
    .bind(parent.as_uuid())
    .bind(app.id.as_uuid())
    .bind({
        use sha2::Digest as _;
        sha2::Sha256::digest(raw.as_bytes()).to_vec()
    })
    .execute(pool)
    .await
    .expect("app session");
    (raw, app.id.as_uuid())
}

struct Gateway {
    authz: Arc<gateway::authz::Authz>,
    follower: tokio::task::JoinHandle<()>,
}

impl Gateway {
    fn follow(internal: SocketAddr) -> Self {
        let base = format!("http://{internal}");
        let client = gateway::signin::SigninClient::new(base.clone(), SECRET).expect("client");
        let authz = Arc::new(gateway::authz::Authz::new(Arc::new(client)));
        let follower = tokio::spawn(gateway::authz::follow(
            authz.clone(),
            base,
            Arc::from(SECRET),
            uuid::Uuid::now_v7(),
        ));
        Self { authz, follower }
    }

    async fn wait(&self, what: &str, until: impl Fn(&gateway::authz::Authz) -> bool) {
        self.wait_within(what, Duration::from_secs(30), until).await;
    }

    async fn wait_within(
        &self,
        what: &str,
        within: Duration,
        until: impl Fn(&gateway::authz::Authz) -> bool,
    ) {
        let deadline = Instant::now() + within;
        while !until(&self.authz) {
            assert!(
                Instant::now() < deadline,
                "gateway not {what} after {within:?}: {}",
                self.authz.describe()
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    async fn allows(&self, session: &str, app: uuid::Uuid) -> Result<bool, String> {
        self.authz
            .authorize(&gateway::signin::AppSession::new(session), &app.to_string())
            .await
            .map(|checked| {
                checked.is_some_and(|c| matches!(c.decision, shared::authz::Decision::Allow(_)))
            })
            .map_err(|e| format!("{e:?}"))
    }
}

impl Drop for Gateway {
    fn drop(&mut self) {
        self.follower.abort();
    }
}

/// 9. A gateway follows a control-plane restart: bypass while it is down,
/// fail closed while nothing answers, never a stale allow, and caching again
/// once a new instance is up. #12's contract across a real restart.
#[sqlx::test(migrations = "../../migrations")]
async fn a_gateway_follows_a_control_plane_restart(pool: PgPool) {
    let (session, app) = live_session(&pool).await;
    let (issuer, _issuer) = issuer().await;
    let env = Env::new(&database_url(&pool), &issuer);
    let mut first = Cp::start(&env);
    first.ready().await;

    let gw = Gateway::follow(first.internal);
    gw.wait("caching", gateway::authz::Authz::is_caching).await;
    assert_eq!(
        gw.allows(&session, app).await,
        Ok(true),
        "allowed, and now cached"
    );

    // The stream ends with the listener (no pre-stop delay here), and the
    // gateway bypasses at once: well inside its 3 s lease, which would
    // otherwise be what ended the cache (mutation 9).
    first.signal(libc::SIGTERM);
    gw.wait_within("in bypass", Duration::from_secs(1), |a| !a.is_caching())
        .await;
    let status = first.exit(Duration::from_secs(30)).await;
    assert!(status.success());

    // Revoked while no control plane runs: the cache must not answer.
    sqlx::query("update sessions set revoked_at = now()")
        .execute(&pool)
        .await
        .expect("revoke");
    assert!(
        gw.allows(&session, app).await.is_err(),
        "with no control plane up the gateway must fail closed: {}",
        gw.authz.describe()
    );

    let second = Cp::start(&env);
    second.ready().await;
    gw.wait("caching again", gateway::authz::Authz::is_caching)
        .await;
    assert_eq!(
        gw.allows(&session, app).await,
        Ok(false),
        "the revoked session must not be served from the old cache"
    );
}

/// 10. A second signal during the drain exits at once, non-zero.
#[sqlx::test(migrations = "../../migrations")]
async fn a_second_signal_exits_at_once(pool: PgPool) {
    let (issuer, _issuer) = issuer().await;
    let env = Env::new(&database_url(&pool), &issuer).set("CLWD_PRE_STOP_DELAY", "10s");
    let mut cp = Cp::start(&env);
    cp.ready().await;
    cp.signal(libc::SIGTERM);
    cp.wait_readyz("stopping", |_, body| body["stopping"] == true)
        .await;
    let second = Instant::now();
    cp.signal(libc::SIGTERM);
    let status = cp.exit(Duration::from_secs(3)).await;
    assert_eq!(status.code(), Some(1), "{}", cp.output());
    assert!(second.elapsed() < Duration::from_secs(2));
}

/// 11. Slowloris: headers trickled a byte a second are cut off at the 10 s
/// header read timeout, and an idle keep-alive connection is closed on the
/// same clock.
#[sqlx::test(migrations = "../../migrations")]
async fn slow_headers_and_idle_keep_alives_are_cut_off(pool: PgPool) {
    let (issuer, _issuer) = issuer().await;
    let cp = Cp::start(&Env::new(&database_url(&pool), &issuer));
    cp.ready().await;

    let trickle = async {
        let mut slow = TcpStream::connect(cp.public).await.expect("connect");
        let started = Instant::now();
        slow.write_all(b"GET /openapi.json HTTP/1.1\r\n")
            .await
            .expect("request line");
        let mut byte = 0u8;
        loop {
            tokio::time::sleep(Duration::from_secs(1)).await;
            byte = byte.wrapping_add(1);
            let header = format!("x-{byte}: 1\r\n");
            if slow.write_all(header.as_bytes()).await.is_err() {
                break;
            }
            let mut probe = [0u8; 1];
            if let Ok(Ok(0) | Err(_)) =
                tokio::time::timeout(Duration::from_millis(1), slow.peek(&mut probe)).await
            {
                break;
            }
            assert!(
                started.elapsed() < Duration::from_secs(20),
                "still open after 20 s of trickling"
            );
        }
        started.elapsed()
    };

    let idle = async {
        let mut kept = TcpStream::connect(cp.public).await.expect("connect");
        kept.write_all(b"GET /openapi.json HTTP/1.1\r\nhost: cp\r\n\r\n")
            .await
            .expect("request");
        // Read the whole response, then sit idle.
        let mut buf = vec![0u8; 256 * 1024];
        let mut read = 0;
        let mut length = None;
        loop {
            let n = kept.read(&mut buf[read..]).await.expect("read");
            assert!(n > 0, "closed before the response ended");
            read += n;
            let text = String::from_utf8_lossy(&buf[..read]);
            if let Some(end) = text.find("\r\n\r\n") {
                let len = length.get_or_insert_with(|| {
                    text[..end]
                        .lines()
                        .find_map(|l| l.strip_prefix("content-length: "))
                        .and_then(|v| v.trim().parse::<usize>().ok())
                        .expect("a content-length")
                });
                if read >= end + 4 + *len {
                    break;
                }
            }
        }
        let started = Instant::now();
        let mut rest = [0u8; 1];
        let closed = tokio::time::timeout(Duration::from_secs(20), kept.read(&mut rest)).await;
        assert!(
            matches!(closed, Ok(Ok(0)) | Ok(Err(_))),
            "an idle keep-alive connection was still open after 20 s"
        );
        started.elapsed()
    };

    let (trickled, idled) = tokio::join!(trickle, idle);
    for (what, took) in [
        ("trickled headers", trickled),
        ("an idle keep-alive", idled),
    ] {
        assert!(
            took >= Duration::from_secs(9) && took < Duration::from_secs(13),
            "{what} was cut off after {took:?}; the header read timeout is 10 s"
        );
    }
}

/// Sign-in with the identity provider down: the instance is ready, session
/// checks work, sign-in is `identity.provider_unavailable`; once the provider
/// answers, sign-in works with no restart.
#[sqlx::test(migrations = "../../migrations")]
async fn sign_in_waits_for_the_provider_without_a_restart(pool: PgPool) {
    let issuer_addr = free_addr();
    let issuer_url = format!("http://{issuer_addr}");
    let cp = Cp::start(&Env::new(&database_url(&pool), &issuer_url));
    let ready = cp.ready().await;
    assert_eq!(ready["oidc"], "degraded", "{ready}");

    let (status, code) = envelope(check(cp.internal).await).await;
    assert_eq!(
        (status, code.as_str()),
        (401, "identity.unauthenticated"),
        "session checks work"
    );
    let response = client()
        .get(format!("http://{}/auth/google", cp.public))
        .send()
        .await
        .expect("sign-in");
    let (status, code) = envelope(response).await;
    assert_eq!(
        (status, code.as_str()),
        (503, "identity.provider_unavailable")
    );

    let _issuer = start_issuer(
        TcpListener::bind(issuer_addr)
            .await
            .expect("bind the issuer"),
    );
    cp.wait_readyz("discovered", |_, body| body["oidc"] == "discovered")
        .await;
    let response = client()
        .get(format!("http://{}/auth/google", cp.public))
        .send()
        .await
        .expect("sign-in");
    assert_eq!(response.status(), 303);
    let location = response
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    assert!(
        location.starts_with(&format!("{issuer_url}/authorize")),
        "{location}"
    );
}

/// A disabled decision-input trigger degrades the relay, not readiness: the
/// instance stays ready, `/readyz` names the relay as degraded, the gateway
/// bypasses its cache, and app requests still succeed uncached.
#[sqlx::test(migrations = "../../migrations")]
async fn a_dead_relay_degrades_without_failing_readiness(pool: PgPool) {
    let (session, app) = live_session(&pool).await;
    let (issuer, _issuer) = issuer().await;
    let cp = Cp::start(&Env::new(&database_url(&pool), &issuer));
    cp.wait_readyz("ready with the relay healthy", |status, body| {
        status == 200 && body["relay"] == "healthy"
    })
    .await;
    let gw = Gateway::follow(cp.internal);
    gw.wait("caching", gateway::authz::Authz::is_caching).await;

    let input = control_plane::authz::INPUTS[0].table;
    let trigger = control_plane::authz::TRIGGERS[0];
    // Both names are this crate's own constants, not input.
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "alter table {input} disable trigger {trigger}"
    )))
    .execute(&pool)
    .await
    .expect("disable a trigger");

    let degraded = cp
        .wait_readyz("relay degraded", |_, body| body["relay"] == "degraded")
        .await;
    let (status, _) = cp.readyz().await.expect("readyz");
    assert_eq!(status, 200, "still ready: {degraded}");
    assert_eq!(degraded["ready"], true);
    gw.wait("in bypass", |a| !a.is_caching()).await;
    assert_eq!(
        gw.allows(&session, app).await,
        Ok(true),
        "the uncached path serves"
    );
}
