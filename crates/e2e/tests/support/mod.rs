//! The browser harness: every real server, one real Chrome (#62).
//!
//! In one process, on loopback:
//!
//! - the control plane's **public** router over TLS at `api.clwd.test`, and its
//!   **internal** router over plain HTTP on a port only the gateway is told;
//! - the gateway (pingora, TLS, per-org certificates) serving
//!   `*.clwd-apps.test`, with the **test upstream** as its app hop;
//! - a mock OIDC issuer, so sign-in runs end to end in the browser;
//! - `evil.clwd.test`, a sibling host *of the control plane*, for the negative
//!   control: it is what an app served under the control plane's own domain —
//!   the model #62 replaced — could do.
//!
//! Chrome resolves every name to these ports with `--host-resolver-rules`, and
//! trusts the one test certificate by pinning its key
//! (`--ignore-certificate-errors-spki-list`). A pinned key, not
//! `--ignore-certificate-errors`: and [`no_bypass_browser`] proves the pin is
//! doing the work — without it the same harness loads nothing — so a TLS
//! mistake can never become a page that quietly fails to set `__Host-`
//! cookies and makes every test pass for the wrong reason.

use std::collections::HashMap;
use std::io::Write as _;
use std::net::{SocketAddr, TcpListener as StdListener};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use axum::extract::{Query, State};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Form, Json, Router};
use base64::Engine as _;
use bytes::Bytes;
use chromiumoxide::browser::{Browser, BrowserConfig};
use chromiumoxide::cdp::browser_protocol::network::GetCookiesParams;
use chromiumoxide::page::Page;
use futures::StreamExt as _;
use gateway::upstream::{AppTarget, AppUpstream, UpstreamError, UpstreamRequest, UpstreamResponse};
use http::{HeaderMap, HeaderValue, StatusCode};
use sha2::Digest as _;
use sqlx::PgPool;

pub const CONTROL_PLANE: &str = "api.clwd.test";
pub const EVIL: &str = "evil.clwd.test";
pub const APPS: &str = "clwd-apps.test";
pub const NOTES: &str = "notes.acme.clwd-apps.test";
pub const WIKI: &str = "wiki.acme.clwd-apps.test";
pub const ATTACKER_APP: &str = "page.other.clwd-apps.test";
pub const INTERNAL_SECRET: &str = "e2e-internal-secret";
/// A string only the test upstream writes. The release gateway must not
/// contain it (`just release-has-no-test-upstream`).
pub const TEST_UPSTREAM_MARKER: &str = "clwd-test-upstream-v1";
const CLIENT_ID: &str = "e2e-client.apps.googleusercontent.com";
const CLIENT_SECRET: &str = "e2e-client-secret";
pub const SUBJECT: &str = "e2e-google-subject";
pub const EMAIL: &str = "visitor@example.com";
/// The visitor's Workspace domain, verified by `acme` with auto-join on, so
/// the visitor is a member of `acme` and of nothing else — in particular not
/// of `other`, whose app is the non-member case.
pub const VISITOR_DOMAIN: &str = "example.com";

/// The key the control plane signs its cookies with in this harness.
pub fn cookie_key() -> control_plane::signin::CookieKey {
    control_plane::signin::CookieKey::from_secret(b"e2e-cookie-key-of-some-length-0123")
        .expect("a long enough test secret")
}

fn free_port() -> u16 {
    StdListener::bind("127.0.0.1:0")
        .and_then(|l| l.local_addr())
        .map(|a| a.port())
        .expect("a free loopback port")
}

// ---------------------------------------------------------------- certs ----

/// One key, one certificate for every TLS name, signed by a throwaway CA.
pub struct Certs {
    pub cert_pem: String,
    pub key_pem: String,
    /// base64(SHA-256(SubjectPublicKeyInfo)) — Chrome's pin format.
    pub spki_pin: String,
}

fn certs() -> &'static Certs {
    static CERTS: OnceLock<Certs> = OnceLock::new();
    CERTS.get_or_init(|| {
        let ca_key = rcgen::KeyPair::generate().expect("CA key");
        let mut ca = rcgen::CertificateParams::new(Vec::<String>::new()).expect("CA params");
        ca.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca.distinguished_name
            .push(rcgen::DnType::CommonName, "e2e test CA");
        let ca_cert = ca.self_signed(&ca_key).expect("CA cert");
        let issuer = rcgen::Issuer::new(ca, ca_key);

        let key = rcgen::KeyPair::generate().expect("leaf key");
        let leaf = rcgen::CertificateParams::new(vec![
            CONTROL_PLANE.to_owned(),
            EVIL.to_owned(),
            format!("*.acme.{APPS}"),
            format!("*.other.{APPS}"),
        ])
        .expect("leaf params")
        .signed_by(&key, &issuer)
        .expect("leaf cert");
        let spki = sha2::Sha256::digest(rcgen::PublicKeyData::subject_public_key_info(&key));
        Certs {
            cert_pem: format!("{}{}", leaf.pem(), ca_cert.pem()),
            key_pem: key.serialize_pem(),
            spki_pin: base64::engine::general_purpose::STANDARD.encode(spki),
        }
    })
}

fn rustls_config() -> Arc<rustls::ServerConfig> {
    control_plane::acme::install_crypto_provider();
    let c = certs();
    let chain: Vec<_> = rustls_pemfile::certs(&mut c.cert_pem.as_bytes())
        .collect::<Result<_, _>>()
        .expect("cert chain");
    let key = rustls_pemfile::private_key(&mut c.key_pem.as_bytes())
        .expect("key")
        .expect("a key");
    Arc::new(
        rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(chain, key)
            .expect("rustls config"),
    )
}

/// Serve `router` over TLS on `port`.
/// Serve `router` over TLS on a fresh loopback port, returning the port.
///
/// The listener is bound once and kept: picking a free port, releasing it and
/// binding again is a race between thirteen parallel harnesses, and losing it
/// silently points a test at another test's server.
async fn serve_tls(router: Router) -> u16 {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind a TLS port");
    let port = listener.local_addr().expect("addr").port();
    let acceptor = tokio_rustls::TlsAcceptor::from(rustls_config());
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                continue;
            };
            let acceptor = acceptor.clone();
            let router = router.clone();
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(stream).await else {
                    return;
                };
                let service = hyper_util::service::TowerToHyperService::new(router);
                let _ = hyper_util::server::conn::auto::Builder::new(
                    hyper_util::rt::TokioExecutor::new(),
                )
                .serve_connection(hyper_util::rt::TokioIo::new(tls), service)
                .await;
            });
        }
    });
    port
}

// ----------------------------------------------------------- mock issuer ----

struct Grant {
    nonce: String,
    challenge: String,
}

struct Issuer {
    url: String,
    key: openidconnect::core::CoreRsaPrivateSigningKey,
    codes: Mutex<HashMap<String, Grant>>,
}

fn rsa_pem() -> &'static String {
    static PEM: OnceLock<String> = OnceLock::new();
    PEM.get_or_init(|| {
        use rsa::pkcs1::EncodeRsaPrivateKey as _;
        rsa::RsaPrivateKey::new(&mut rand::thread_rng(), 2048)
            .expect("RSA key")
            .to_pkcs1_pem(rsa::pkcs1::LineEnding::LF)
            .expect("PEM")
            .to_string()
    })
}

async fn issuer_discovery(State(issuer): State<Arc<Issuer>>) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "issuer": issuer.url,
        "authorization_endpoint": format!("{}/authorize", issuer.url),
        "token_endpoint": format!("{}/token", issuer.url),
        "jwks_uri": format!("{}/jwks", issuer.url),
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
    }))
}

async fn issuer_jwks(
    State(issuer): State<Arc<Issuer>>,
) -> Json<openidconnect::core::CoreJsonWebKeySet> {
    use openidconnect::PrivateSigningKey as _;
    Json(openidconnect::core::CoreJsonWebKeySet::new(vec![
        issuer.key.as_verification_key(),
    ]))
}

/// Consent, instantly: what Google's authorization endpoint does once the
/// visitor agrees.
async fn issuer_authorize(
    State(issuer): State<Arc<Issuer>>,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    let code = format!("code-{}", uuid::Uuid::now_v7());
    issuer.codes.lock().expect("lock").insert(
        code.clone(),
        Grant {
            nonce: q.get("nonce").cloned().unwrap_or_default(),
            challenge: q.get("code_challenge").cloned().unwrap_or_default(),
        },
    );
    let redirect = q.get("redirect_uri").cloned().unwrap_or_default();
    let state = q.get("state").cloned().unwrap_or_default();
    Redirect::to(&format!("{redirect}?code={code}&state={state}")).into_response()
}

async fn issuer_token(
    State(issuer): State<Arc<Issuer>>,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use openidconnect::core::{CoreGenderClaim, CoreJwsSigningAlgorithm};
    use openidconnect::{
        Audience, EndUserEmail, IdTokenClaims, IssuerUrl, Nonce, StandardClaims, SubjectIdentifier,
    };

    let Some(grant) = form
        .get("code")
        .and_then(|c| issuer.codes.lock().expect("lock").remove(c))
    else {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "invalid_grant"})),
        )
            .into_response();
    };
    let verifier = form.get("code_verifier").cloned().unwrap_or_default();
    if URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(verifier.as_bytes())) != grant.challenge {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "invalid_grant"})),
        )
            .into_response();
    }
    let now = chrono::Utc::now();
    let claims: IdTokenClaims<identity::GoogleClaims, CoreGenderClaim> = IdTokenClaims::new(
        IssuerUrl::new(issuer.url.clone()).expect("issuer"),
        vec![Audience::new(CLIENT_ID.to_owned())],
        now + chrono::Duration::hours(1),
        now,
        StandardClaims::new(SubjectIdentifier::new(SUBJECT.to_owned()))
            .set_email(Some(EndUserEmail::new(EMAIL.to_owned())))
            .set_email_verified(Some(true)),
        // A Workspace account, so sign-in joins the visitor to `acme` through
        // the org's verified domain — the product's own path to membership.
        identity::GoogleClaims {
            hd: Some(VISITOR_DOMAIN.to_owned()),
        },
    )
    .set_nonce(Some(Nonce::new(grant.nonce)));
    let token = identity::GoogleIdToken::new(
        claims,
        &issuer.key,
        CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256,
        None,
        None,
    )
    .expect("sign");
    Json(serde_json::json!({
        "access_token": "unused",
        "token_type": "Bearer",
        "expires_in": 3600,
        "id_token": token.to_string(),
    }))
    .into_response()
}

async fn start_issuer() -> String {
    let pem = tokio::task::spawn_blocking(rsa_pem)
        .await
        .expect("keygen")
        .clone();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind issuer");
    let url = format!("http://{}", listener.local_addr().expect("addr"));
    let issuer = Arc::new(Issuer {
        url: url.clone(),
        key: openidconnect::core::CoreRsaPrivateSigningKey::from_pem(&pem, None).expect("key"),
        codes: Mutex::default(),
    });
    #[expect(
        clippy::disallowed_methods,
        reason = "a mock OIDC issuer, not the control-plane router"
    )]
    let app = Router::new()
        .route("/.well-known/openid-configuration", get(issuer_discovery))
        .route("/jwks", get(issuer_jwks))
        .route("/authorize", get(issuer_authorize))
        .route("/token", post(issuer_token))
        .with_state(issuer);
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    url
}

// ---------------------------------------------------------- evil sibling ----

/// `evil.clwd.test`: a host on the control plane's own registrable domain.
/// Its pages run the same attacks an app could, before #62 moved apps off it.
async fn start_evil() -> u16 {
    #[expect(
        clippy::disallowed_methods,
        reason = "the harness's attacker site, not the control-plane router"
    )]
    let app = Router::new()
        .route(
            "/plant",
            get(|Query(q): Query<HashMap<String, String>>| async move {
                // `cookie` is the full document.cookie assignment to try.
                let cookie = q.get("cookie").cloned().unwrap_or_default();
                Html(format!(
                    "<script>document.cookie = {}; document.title = 'planted';</script>",
                    serde_json::to_string(&cookie).unwrap_or_default()
                ))
            }),
        )
        .route(
            "/link",
            get(|Query(q): Query<HashMap<String, String>>| async move {
                let to = q.get("to").cloned().unwrap_or_default();
                Html(format!(
                    "<a id=\"go\" href={}>open</a>",
                    serde_json::to_string(&to).unwrap_or_default()
                ))
            }),
        );
    serve_tls(app).await
}

// ---------------------------------------------------------- test upstream ----

/// The test upstream: the only HTTP implementation of the gateway's app hop,
/// test-only. It answers per app *as resolved by the gateway* — the
/// [`AppTarget`] — and counts every request that reaches it.
pub struct TestUpstream {
    names: HashMap<String, &'static str>,
    /// Every `(app, path and query)` that reached the hop, in order.
    pub seen_paths: Mutex<Vec<(&'static str, String)>>,
    pub seen_cookies: Mutex<Vec<(&'static str, String)>>,
}

impl TestUpstream {
    /// Whether a request for exactly `path_and_query` reached `app`. Tests use
    /// a unique probe path, so the browser's own background requests (a
    /// favicon) cannot move the answer.
    pub fn saw(&self, app: &str, path_and_query: &str) -> bool {
        self.seen_paths
            .lock()
            .expect("lock")
            .iter()
            .any(|(a, p)| *a == app && p == path_and_query)
    }

    /// Whether `path_and_query` reached any app at all.
    pub fn saw_anywhere(&self, path_and_query: &str) -> bool {
        self.seen_paths
            .lock()
            .expect("lock")
            .iter()
            .any(|(_, p)| p == path_and_query)
    }
}

#[async_trait::async_trait]
impl AppUpstream for TestUpstream {
    async fn forward(
        &self,
        target: &AppTarget,
        request: UpstreamRequest,
    ) -> Result<UpstreamResponse, UpstreamError> {
        let name = *self
            .names
            .get(target.app_id())
            .ok_or_else(|| UpstreamError(format!("no such app {}", target.app_id())))?;
        let cookie = request
            .headers
            .get(http::header::COOKIE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_owned();
        self.seen_cookies
            .lock()
            .expect("lock")
            .push((name, cookie.clone()));
        self.seen_paths
            .lock()
            .expect("lock")
            .push((name, request.path_and_query.clone()));

        let mut headers = HeaderMap::new();
        headers.insert(
            "x-clwd-test-upstream",
            HeaderValue::from_static(TEST_UPSTREAM_MARKER),
        );
        headers.insert(
            http::header::CONTENT_TYPE,
            HeaderValue::from_static("text/html"),
        );
        let path = request.path_and_query.clone();
        let body = if path.starts_with("/echo") {
            // What reached the app: its cookie header, nothing else.
            format!("<pre id=\"echo\">{}</pre>", html_escape(&cookie))
        } else if path.starts_with("/set-reserved") {
            for value in [
                "__Host-clwd_app_session=planted-by-app; Path=/; Secure; HttpOnly",
                "__Host-clwd_state=planted-by-app; Path=/; Secure",
                "app_theme=dark; Path=/; Secure",
            ] {
                headers.append(http::header::SET_COOKIE, HeaderValue::from_static(value));
            }
            "<p id=\"set\">set</p>".to_owned()
        } else if let Some(cookie) = path.strip_prefix("/plant?cookie=") {
            let cookie = percent_decode(cookie);
            format!(
                "<script>document.cookie = {}; document.title = 'planted';</script>",
                serde_json::to_string(&cookie).unwrap_or_default()
            )
        } else {
            format!("<p id=\"app\">{name}</p>")
        };
        Ok(UpstreamResponse::new(
            StatusCode::OK,
            headers,
            Bytes::from(body),
        ))
    }
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let hex = bytes
            .get(i + 1..i + 3)
            .and_then(|h| std::str::from_utf8(h).ok())
            .and_then(|h| u8::from_str_radix(h, 16).ok());
        match (bytes[i], hex) {
            (b'%', Some(b)) => {
                out.push(b);
                i += 3;
            }
            (b, _) => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

// ------------------------------------------------------------- logs ----

/// Every log line any server in this process writes, for the redaction test.
#[derive(Clone, Default)]
pub struct Logs(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for Logs {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0
            .lock()
            .map_err(|_| std::io::Error::other("poisoned"))?
            .extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Logs {
    type Writer = Logs;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

impl Logs {
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.0.lock().expect("lock")).into_owned()
    }
}

/// The process-wide log capture, at TRACE, with every span event.
pub fn logs() -> &'static Logs {
    static LOGS: OnceLock<Logs> = OnceLock::new();
    LOGS.get_or_init(|| {
        let logs = Logs::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(logs.clone())
            .with_max_level(tracing::Level::TRACE)
            .with_span_events(tracing_subscriber::fmt::format::FmtSpan::FULL)
            .with_ansi(false)
            .finish();
        let _ = tracing::subscriber::set_global_default(subscriber);
        logs
    })
}

// ------------------------------------------------------------- harness ----

pub struct Harness {
    pub upstream: Arc<TestUpstream>,
    /// The real worker, when started [`Harness::with_worker`].
    pub worker: Option<Arc<worker::Worker>>,
    /// Where artifacts are stored, shared with the worker.
    pub artifacts: builder::ArtifactStore,
    /// The store's raw backend, for tampering with an artifact.
    pub operator: opendal::Operator,
    pub pool: PgPool,
    pub control_plane_port: u16,
    pub gateway_port: u16,
    pub evil_port: u16,
    /// The gateway's authorization cache (#12).
    pub authz: Arc<gateway::authz::Authz>,
    /// The control plane's invalidation relay.
    pub relay: Arc<control_plane::relay::Relay>,
    /// The control plane's internal listener, for a second gateway's stream.
    pub internal_base: String,
    /// Between the harness gateway and the relay.
    pub stream_proxy: Arc<StreamProxy>,
    /// Every server thread this harness started: stopped when it drops.
    servers: Servers,
    /// The control plane's own pool: closed when this drops.
    control_plane_pool: PgPool,
    /// Files and directories this harness made: removed when it drops,
    /// after the servers that use them have stopped.
    _scratch: Vec<Scratch>,
}

impl Drop for Harness {
    /// Stop every server this test started, whether it passed or panicked:
    /// a server left running keeps threads, sockets and retries going for the
    /// rest of the binary, under every test that runs after it (#90).
    fn drop(&mut self) {
        self.servers.stop_all();
        // Closed here, at the test's end: `#[sqlx::test]` drops the test's
        // database next, and cannot while connections to it are open. Spawned
        // because closing awaits; sqlx's own teardown awaits its pool's close
        // before the drop, which runs this too. The exit check proves it.
        let pool = self.control_plane_pool.clone();
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn(async move { pool.close().await });
        }
    }
}

/// The whoami fixture (`crates/e2e/fixtures/whoami`), built for wasm32-wasip2
/// by `just fixture`. A missing build is a compile error, never a skip.
pub const WHOAMI: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../target/fixtures/wasm32-wasip2/release/whoami.wasm"
));

/// Which hop the gateway uses.
#[derive(Clone)]
enum Hop {
    /// The HTTP test upstream: what the session-isolation tests drive.
    Test,
    /// The real worker, in this process, running the whoami fixture.
    Worker,
    /// Any hop a test supplies: a misbehaving worker, say.
    Given(Arc<dyn AppUpstream>),
}

/// A bundle of `wasm` granting `egress`, as `clwd build` makes one.
pub fn bundle_of(wasm: &[u8], egress: &[&str]) -> bytes::Bytes {
    let encoded = clwd_bundle::build(
        clwd_bundle::Runtime::Wasm,
        "app.wasm",
        clwd_bundle::Capabilities {
            version: 1,
            egress: egress.iter().map(|h| (*h).to_owned()).collect(),
            secrets: vec![],
            storage_namespaces: vec![],
            limits: clwd_bundle::Limits {
                cpu_ms: 5_000,
                memory_mb: 128,
            },
        },
        vec![clwd_bundle::File {
            path: "app.wasm".into(),
            data: wasm.to_vec(),
            executable: false,
        }],
    )
    .expect("a well-formed bundle encodes");
    bytes::Bytes::from(encoded.bytes)
}

/// This process's user id: the gateway and the worker share it in tests.
pub fn my_uid() -> u32 {
    use std::os::unix::fs::MetadataExt as _;
    std::fs::metadata("/proc/self").expect("/proc/self").uid()
}

/// A socket path short enough for `SUN_LEN` (108 bytes).
pub fn socket_path() -> std::path::PathBuf {
    std::path::PathBuf::from(format!(
        "/tmp/clwd-e2e-{}.sock",
        &uuid::Uuid::now_v7().simple().to_string()[20..]
    ))
}

impl Harness {
    /// Start everything against `pool`, with the HTTP test upstream as the hop.
    pub async fn start(pool: PgPool) -> Self {
        Self::start_with(pool, Hop::Test).await
    }

    /// Start everything against `pool`, with the real worker as the hop and
    /// the whoami fixture published as every app. One artifact, three apps:
    /// the same digest under different app ids.
    pub async fn with_worker(pool: PgPool) -> Self {
        Self::start_with(pool, Hop::Worker).await
    }

    /// Start everything against `pool`, with `hop` as the gateway's hop.
    pub async fn with_hop(pool: PgPool, hop: Arc<dyn AppUpstream>) -> Self {
        Self::start_with(pool, Hop::Given(hop)).await
    }

    async fn start_with(pool: PgPool, kind: Hop) -> Self {
        logs();
        no_server_outlives_its_test();
        watch_for_stalls();
        control_plane::acme::install_crypto_provider();

        // Apps: two in `acme`, one in `other`.
        let acme = control_plane::db::create_org(&pool, "acme")
            .await
            .expect("org");
        let other = control_plane::db::create_org(&pool, "other")
            .await
            .expect("org");
        // `acme` holds the visitor's domain, verified, with auto-join on. The
        // claimant is someone else, so the visitor's membership comes from
        // sign-in alone.
        let claimant: uuid::Uuid = sqlx::query_scalar(
            "insert into users (id, email) values ($1, 'owner@example.net') returning id",
        )
        .bind(uuid::Uuid::now_v7())
        .fetch_one(&pool)
        .await
        .expect("claimant");
        sqlx::query(
            "insert into org_domains (domain, org_id, claimant_id, auto_join) values ($1, $2, $3, true)",
        )
        .bind(VISITOR_DOMAIN)
        .bind(acme.id.as_uuid())
        .bind(claimant)
        .execute(&pool)
        .await
        .expect("acme verifies the visitor's domain");
        // One store, shared by the control plane and the worker, as publish
        // and the worker share one in production.
        let operator =
            opendal::Operator::new(opendal::services::Memory::default()).expect("operator");
        let artifacts = builder::ArtifactStore::new(operator.clone());
        let mut names = HashMap::new();
        for (org, name, label) in [
            (acme.id, "notes", "notes"),
            (acme.id, "wiki", "wiki"),
            (other.id, "page", "page"),
        ] {
            let app = control_plane::db::create_app(&pool, org, name, "wasm")
                .await
                .expect("app");
            // A published version, so the app has something to run: the
            // fixture, stored where publish stores it.
            let validated =
                builder::validate(bundle_of(WHOAMI, &[])).expect("the fixture validates");
            artifacts.put(&validated).await.expect("stored");
            sqlx::query(
                "insert into app_versions (id, app_id, digest, state) values ($1, $2, $3, 'ready')",
            )
            .bind(uuid::Uuid::now_v7())
            .bind(app.id.as_uuid())
            .bind(validated.digest().to_string())
            .execute(&pool)
            .await
            .expect("a ready version");
            names.insert(app.id.to_string(), label);
        }

        let issuer = start_issuer().await;

        // The control plane.
        let signin = control_plane::signin::SignIn::discover(
            identity::OidcConfig::new(
                CLIENT_ID,
                CLIENT_SECRET,
                format!("https://{CONTROL_PLANE}/auth/google/callback"),
                issuer,
            ),
            cookie_key(),
        )
        .await
        .expect("discovery against the mock issuer");
        let relay = control_plane::relay::Relay::start(&pool)
            .await
            .expect("the invalidation relay starts");
        let control_plane_pool = control_plane_pool(&pool).await;
        let state =
            control_plane::http::AppState::new(control_plane_pool.clone(), artifacts.clone())
                .with_relay(relay.clone())
                .with_signin(signin)
                .with_internal_secret(INTERNAL_SECRET)
                .with_apps_domain(shared::domains::AppsDomain::parse(APPS).expect("apps domain"));
        let control_plane_port = serve_tls(control_plane::http::router(state.clone())).await;
        let internal = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind internal");
        let internal_port = internal.local_addr().expect("addr").port();
        let internal_router = control_plane::http::internal_router(state);
        tokio::spawn(async move {
            let _ = axum::serve(internal, internal_router).await;
        });

        let evil_port = start_evil().await;

        // The gateway, with the test upstream as its hop.
        let upstream = Arc::new(TestUpstream {
            names,
            seen_cookies: Mutex::default(),
            seen_paths: Mutex::default(),
        });
        let cert_dir = Scratch::dir("certs");
        for org in ["acme", "other"] {
            let dir = cert_dir.path().join(org);
            std::fs::create_dir_all(&dir).expect("cert dir");
            std::fs::File::create(dir.join("cert.pem"))
                .and_then(|mut f| f.write_all(certs().cert_pem.as_bytes()))
                .expect("cert.pem");
            std::fs::File::create(dir.join("key.pem"))
                .and_then(|mut f| f.write_all(certs().key_pem.as_bytes()))
                .expect("key.pem");
        }
        let internal_base = format!("http://127.0.0.1:{internal_port}");
        let servers = Servers::default();
        let mut scratch = vec![cert_dir];
        let (hop, worker): (Arc<dyn AppUpstream>, _) = match kind {
            Hop::Test => (upstream.clone(), None),
            Hop::Given(hop) => (hop, None),
            Hop::Worker => {
                let worker = Arc::new(
                    worker::Worker::new(artifacts.clone(), my_uid()).expect("the worker starts"),
                );
                let socket = Scratch::socket();
                // Its own runtime on its own threads, as its own process has in
                // production. On the test's single-threaded runtime, running
                // app code would starve the control plane beside it.
                let (serving, path) = (Arc::clone(&worker), socket.path().to_path_buf());
                let (ready, bound) = tokio::sync::oneshot::channel();
                servers.spawn("worker", move |mut stop| {
                    let runtime = tokio::runtime::Builder::new_multi_thread()
                        .enable_all()
                        .build()
                        .expect("worker runtime");
                    runtime.block_on(async move {
                        let listener =
                            tokio::net::UnixListener::bind(&path).expect("bind the worker");
                        let _ = ready.send(());
                        tokio::select! {
                            () = serving.serve(listener) => {}
                            _ = stop.wait_for(|stop| *stop) => {}
                        }
                    });
                });
                bound.await.expect("the worker is listening");
                let upstream = gateway::worker::WorkerUpstream::new(socket.path(), my_uid());
                scratch.push(socket);
                (Arc::new(upstream), Some(worker))
            }
        };
        let (gateway_port, authz) = start_gateway(
            &pool,
            &internal_base,
            &hop,
            scratch[0].path(),
            control_plane_port,
            &servers,
        )
        .await;
        for port in [control_plane_port, evil_port] {
            wait_for_port(port).await;
        }
        // The gateway reaches the relay through a proxy a test can cut, so a
        // dropped stream stays dropped instead of reconnecting at once.
        let stream_proxy = StreamProxy::start(internal_port).await;
        follow(
            &servers,
            authz.clone(),
            &stream_proxy.base(),
            uuid::Uuid::now_v7(),
        );
        // Every test runs with the cache live, as production does once its
        // stream is up: the bypass path is the exception tests choose.
        wait_until("the gateway's cache is live", || authz.is_caching()).await;

        Self {
            upstream,
            worker,
            artifacts,
            operator,
            pool,
            control_plane_port,
            gateway_port,
            evil_port,
            authz,
            relay,
            internal_base,
            stream_proxy,
            servers,
            control_plane_pool,
            _scratch: scratch,
        }
    }

    /// Make the signed-in visitor a member of `org` as well, the way a grant
    /// (#15/#16) will let them reach another org's app. The visitor must have
    /// signed in once, so their user exists.
    pub async fn join(&self, org: &str) {
        let added = sqlx::query(
            "insert into org_members (org_id, user_id, joined_via)
             select o.id, u.id, 'claimant' from orgs o, users u
              where o.slug = $1 and u.email = $2",
        )
        .bind(org)
        .bind(EMAIL)
        .execute(&self.pool)
        .await
        .expect("join");
        assert_eq!(added.rows_affected(), 1, "the visitor has signed in");
    }

    /// Follow a stream into another gateway's cache, stopped with this
    /// harness.
    pub fn follow(&self, authz: Arc<gateway::authz::Authz>, internal_base: &str) {
        follow(&self.servers, authz, internal_base, uuid::Uuid::now_v7());
    }

    fn resolver_rules(&self) -> String {
        format!(
            "MAP {CONTROL_PLANE} 127.0.0.1:{}, MAP {EVIL} 127.0.0.1:{}, MAP *.{APPS} 127.0.0.1:{}",
            self.control_plane_port, self.evil_port, self.gateway_port
        )
    }

    /// Chrome, trusting the test certificate by its pinned key.
    pub async fn browser(&self) -> Chrome {
        launch(&self.resolver_rules(), Some(&certs().spki_pin)).await
    }

    /// Chrome with the same name mapping and **no** certificate bypass: the
    /// negative control that makes a TLS mistake loud.
    pub async fn no_bypass_browser(&self) -> Chrome {
        launch(&self.resolver_rules(), None).await
    }

    /// A raw HTTPS client that resolves the test names here and trusts the
    /// test certificate — for requests a browser would never send.
    pub fn http(&self) -> reqwest::Client {
        let root = reqwest::Certificate::from_pem(certs().cert_pem.as_bytes()).expect("cert");
        let mut builder = reqwest::Client::builder()
            .add_root_certificate(root)
            .redirect(reqwest::redirect::Policy::none());
        for (host, port) in [
            (CONTROL_PLANE, self.control_plane_port),
            (NOTES, self.gateway_port),
            (WIKI, self.gateway_port),
            (ATTACKER_APP, self.gateway_port),
        ] {
            builder = builder.resolve(host, SocketAddr::from(([127, 0, 0, 1], port)));
        }
        builder.build().expect("client")
    }
}

/// Start the gateway — pingora, which binds its own address — on a port it
/// actually owns.
///
/// pingora takes an address, not a bound socket, so the port is picked first
/// and can be lost to a parallel harness in between. That loss is silent: the
/// thread whose bind failed dies, and the port answers anyway — with another
/// test's gateway and database. So ownership is proved, not assumed: a probe
/// request must create a handshake row in **this** harness's database. If it
/// does not, the port belongs to someone else and a new one is tried.
async fn start_gateway(
    pool: &PgPool,
    internal_base: &str,
    hop: &Arc<dyn AppUpstream>,
    cert_dir: &std::path::Path,
    control_plane_port: u16,
    servers: &Servers,
) -> (u16, Arc<gateway::authz::Authz>) {
    for attempt in 1..=5 {
        let (sent, received) = std::sync::mpsc::channel();
        let gateway_port = free_port();
        let (internal_base, hop, cert_dir) = (
            internal_base.to_owned(),
            hop.clone(),
            cert_dir.to_path_buf(),
        );
        let server = servers.spawn("gateway", move |stop| {
            use pingora::apps::http_app::HttpServer;
            use pingora::listeners::tls::TlsSettings;
            use pingora::server::Server;
            use pingora::services::listening::Service;

            let apps = shared::domains::AppsDomain::parse(APPS).expect("apps domain");
            let lookup = Arc::new(
                gateway::lookup::RouteLookup::new(internal_base.clone(), INTERNAL_SECRET)
                    .expect("lookup"),
            );
            let signin = Arc::new(
                gateway::signin::SigninClient::new(internal_base, INTERNAL_SECRET).expect("client"),
            );
            let serving = gateway::edge::Serving::new(
                signin,
                shared::domains::ControlPlaneDomain::parse(CONTROL_PLANE).expect("cp domain"),
                hop,
            );
            let _ = sent.send(serving.authz());
            let edge = gateway::edge::Edge::new(lookup, apps.clone()).serving(serving);
            let store = Arc::new(shared::cert::DirCertStore::new(&cert_dir));
            let resolver = gateway::cert::CertResolver::new(store, apps);
            let tls = TlsSettings::with_callbacks(gateway::tls::DynamicCert::callbacks(resolver))
                .expect("tls");
            let mut server = Server::new(None).expect("pingora");
            server.bootstrap();
            let mut service = Service::new("e2e-gateway".to_owned(), HttpServer::new_app(edge));
            service.add_tls_with_settings(&format!("127.0.0.1:{gateway_port}"), None, tls);
            server.add_service(service);
            // `run`, not `run_forever`: it returns once told to stop, and
            // installs no process-wide signal handlers in a test binary.
            server.run(pingora::server::RunArgs {
                shutdown_signal: Box::new(StopSignal(stop)),
            });
        });
        wait_for_port(gateway_port).await;
        let before: i64 = sqlx::query_scalar("select count(*) from handshakes")
            .fetch_one(pool)
            .await
            .expect("count");
        let probe = probe_client(gateway_port, control_plane_port)
            .get(format!("https://{NOTES}/__probe"))
            .send()
            .await;
        let after: i64 = sqlx::query_scalar("select count(*) from handshakes")
            .fetch_one(pool)
            .await
            .expect("count");
        if probe.is_ok() && after > before {
            return (gateway_port, received.recv().expect("the gateway's cache"));
        }
        // This attempt's server answered for nobody: stop it now.
        servers.stop(server);
        eprintln!(
            "e2e: gateway port {gateway_port} answered for another harness (attempt {attempt}); retrying"
        );
    }
    panic!("could not start a gateway on a port this harness owns");
}

fn probe_client(gateway_port: u16, control_plane_port: u16) -> reqwest::Client {
    let root = reqwest::Certificate::from_pem(certs().cert_pem.as_bytes()).expect("cert");
    reqwest::Client::builder()
        .add_root_certificate(root)
        .redirect(reqwest::redirect::Policy::none())
        .resolve(NOTES, SocketAddr::from(([127, 0, 0, 1], gateway_port)))
        .resolve(
            CONTROL_PLANE,
            SocketAddr::from(([127, 0, 0, 1], control_plane_port)),
        )
        .build()
        .expect("client")
}

async fn wait_for_port(port: u16) {
    for _ in 0..200 {
        if tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .is_ok()
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("nothing listening on {port}");
}

// -------------------------------------------------------------- chrome ----

/// The Chrome binary: `$CLWD_CHROME`, else the first of `google-chrome`,
/// `google-chrome-stable`, `chromium` on `PATH`. Never skipped: with no
/// browser, the test fails and says so.
fn chrome_binary() -> String {
    if let Ok(path) = std::env::var("CLWD_CHROME") {
        return path;
    }
    let path = std::env::var_os("PATH").unwrap_or_default();
    for name in ["google-chrome", "google-chrome-stable", "chromium"] {
        for dir in std::env::split_paths(&path) {
            let candidate = dir.join(name);
            if candidate.is_file() {
                return candidate.to_string_lossy().into_owned();
            }
        }
    }
    "google-chrome".to_owned()
}

/// The longest a navigation, redirects included, may take.
const NAVIGATION_DEADLINE: Duration = Duration::from_secs(30);

pub struct Chrome {
    pub browser: Browser,
    _handler: tokio::task::JoinHandle<()>,
    /// The profile directory: removed after the browser above is dropped.
    _profile: Scratch,
}

async fn launch(rules: &str, spki_pin: Option<&str>) -> Chrome {
    let profile = Scratch::dir("chrome");
    let mut builder = BrowserConfig::builder()
        .chrome_executable(chrome_binary())
        .new_headless_mode()
        .no_sandbox()
        // chromiumoxide ignores every certificate error by default, over the
        // DevTools protocol. Off: the only trust is the pinned key below, and
        // the no-bypass control proves it (it caught this default).
        .respect_https_errors()
        .user_data_dir(profile.path())
        .arg(("host-resolver-rules", rules));
    if let Some(pin) = spki_pin {
        builder = builder.arg(("ignore-certificate-errors-spki-list", pin));
    }
    let config = builder.build().expect("browser config");
    let (browser, mut handler) = Browser::launch(config).await.unwrap_or_else(|e| {
        panic!(
            "Chrome did not start ({}): {e}. The browser tests need Chrome; set CLWD_CHROME to its path",
            chrome_binary()
        )
    });
    let handle = tokio::spawn(async move { while handler.next().await.is_some() {} });
    Chrome {
        browser,
        _handler: handle,
        _profile: profile,
    }
}

impl Chrome {
    /// A new tab at `url`, after its redirects.
    ///
    /// Bounded: chromiumoxide's navigation has no deadline of its own, and a
    /// navigation that never completes once stalled the whole gate for half
    /// an hour. Now it fails in seconds and says where it was.
    pub async fn open(&self, url: &str) -> Page {
        let page = self.browser.new_page("about:blank").await.expect("a tab");
        match tokio::time::timeout(NAVIGATION_DEADLINE, page.goto(url)).await {
            Ok(navigated) => {
                navigated.unwrap_or_else(|e| panic!("navigating to {url}: {e}"));
            }
            Err(_) => panic!(
                "navigating to {url} did not finish in {NAVIGATION_DEADLINE:?}; the tab was at {:?}",
                page.url().await.ok().flatten()
            ),
        }
        page
    }

    /// The cookies this browser would send to `url`, as `(name, value, domain)`.
    pub async fn cookies_for(&self, page: &Page, url: &str) -> Vec<(String, String, String)> {
        let reply = page
            .execute(
                GetCookiesParams::builder()
                    .urls(vec![url.to_owned()])
                    .build(),
            )
            .await
            .expect("Network.getCookies");
        reply
            .result
            .cookies
            .iter()
            .map(|c| (c.name.clone(), c.value.clone(), c.domain.clone()))
            .collect()
    }
}

/// The page's text content.
pub async fn text(page: &Page) -> String {
    page.evaluate("document.body ? document.body.innerText : ''")
        .await
        .ok()
        .and_then(|v| v.into_value::<String>().ok())
        .unwrap_or_default()
}

/// The app a page shows, from the test upstream's `#app` element — empty for
/// anything else, an error page included.
pub async fn app_name(page: &Page) -> String {
    page.evaluate("(document.getElementById('app') || {innerText: ''}).innerText")
        .await
        .ok()
        .and_then(|v| v.into_value::<String>().ok())
        .unwrap_or_default()
}

/// Wait until the page's URL is no longer `from`, for up to five seconds.
pub async fn wait_to_leave(page: &Page, from: &str) {
    for _ in 0..100 {
        if url(page).await != from {
            let _ = page.wait_for_navigation().await;
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// The page's URL.
pub async fn url(page: &Page) -> String {
    page.url().await.ok().flatten().unwrap_or_default()
}

// ------------------------------------------------------------ servers ----

/// Server threads alive right now, across every test in this binary.
static LIVE_SERVERS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// Held by a server thread for its whole life.
struct Alive;

impl Alive {
    fn new() -> Self {
        LIVE_SERVERS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Self
    }
}

impl Drop for Alive {
    fn drop(&mut self) {
        LIVE_SERVERS.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
    }
}

/// One server thread and the signal that stops it. Dropping the signal's
/// sender stops the server too, so a forgotten harness still cleans up.
pub struct ServerThread {
    name: &'static str,
    stop: tokio::sync::watch::Sender<bool>,
    thread: std::thread::JoinHandle<()>,
}

/// Every server thread a harness started.
#[derive(Default)]
pub struct Servers(Mutex<Vec<Option<ServerThread>>>);

impl Servers {
    /// Start `serve` on a thread of its own, handing it the stop signal. The
    /// thread is counted live until it returns.
    fn spawn(
        &self,
        name: &'static str,
        serve: impl FnOnce(tokio::sync::watch::Receiver<bool>) + Send + 'static,
    ) -> usize {
        let (stop, stopped) = tokio::sync::watch::channel(false);
        let alive = Alive::new();
        let thread = std::thread::spawn(move || {
            let _alive = alive;
            serve(stopped);
        });
        let mut threads = self.0.lock().expect("servers");
        threads.push(Some(ServerThread { name, stop, thread }));
        threads.len() - 1
    }

    /// Stop one server, by the index `spawn` returned.
    fn stop(&self, index: usize) {
        let server = self.0.lock().expect("servers")[index].take();
        if let Some(server) = server {
            let _ = server.stop.send(true);
            join(server);
        }
    }

    /// Stop every server this harness started, and wait for each to exit.
    fn stop_all(&self) {
        let servers: Vec<ServerThread> = std::mem::take(&mut *self.0.lock().expect("servers"))
            .into_iter()
            .flatten()
            .collect();
        for server in &servers {
            let _ = server.stop.send(true);
        }
        for server in servers {
            join(server);
        }
    }
}

/// Wait up to ten seconds for a stopped server's thread to exit. One that
/// does not is left counted live, and the exit check fails the binary.
fn join(server: ServerThread) {
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while !server.thread.is_finished() {
        if std::time::Instant::now() > deadline {
            eprintln!("e2e: the {} server did not stop within 10 s", server.name);
            return;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let _ = server.thread.join();
}

/// pingora's shutdown signal, from the harness rather than from Unix signals.
/// A closed channel (the harness dropped without stopping) also stops it.
struct StopSignal(tokio::sync::watch::Receiver<bool>);

#[async_trait::async_trait]
impl pingora::server::ShutdownSignalWatch for StopSignal {
    async fn recv(&self) -> pingora::server::ShutdownSignal {
        let mut stop = self.0.clone();
        let _ = stop.wait_for(|stop| *stop).await;
        pingora::server::ShutdownSignal::FastShutdown
    }
}

/// The end-of-suite check: when this test binary exits, no server any test
/// started may still be alive. Registered once; it turns a leak into a failed
/// binary rather than a slower, noisier one.
fn no_server_outlives_its_test() {
    static REGISTERED: OnceLock<()> = OnceLock::new();
    REGISTERED.get_or_init(|| {
        extern "C" fn check() {
            let connections = connections_left_to_test_databases().unwrap_or_default();
            if !connections.is_empty() {
                eprintln!(
                    "e2e: {} connection(s) to test databases still open after the suite: {connections:?}",
                    connections.len()
                );
            }
            let live = LIVE_SERVERS.load(std::sync::atomic::Ordering::SeqCst);
            let left = LIVE_SCRATCH.load(std::sync::atomic::Ordering::SeqCst);
            let recreated = std::fs::read_dir(scratch_root()).map_or(0, Iterator::count);
            let _ = std::fs::remove_dir_all(scratch_root());
            if recreated > 0 {
                eprintln!(
                    "e2e: {recreated} scratch path(s) recreated after removal, in {}",
                    scratch_root().display()
                );
            }
            if live > 0 || left > 0 || !connections.is_empty() {
                eprintln!(
                    "e2e: {live} test server(s) still alive and {left} scratch path(s) left when the binary exited"
                );
                // SAFETY: `_exit` ends the process at once, which is all this
                // handler is for; it runs no further handlers.
                unsafe { libc::_exit(1) };
            }
        }
        // SAFETY: `check` is a plain `extern "C" fn` with no captures.
        unsafe {
            libc::atexit(check);
        }
    });
}

/// When a request under load was refused, say why before the assertion fails:
/// the gateway's warning for whichever control-plane call failed (the route
/// lookup or the session check, with its error), the control plane's pool
/// state for any slow or failed acquire, and Postgres's connections against
/// its limit (#90).
pub async fn explain_refusals(pool: &PgPool) {
    let text = logs().text();
    let causes: Vec<&str> = text
        .lines()
        .filter(|l| {
            l.contains("cold lookup")
                || l.contains("app session check failed")
                || l.contains("slow in its handler")
                || l.contains("waited to be handled")
                || l.contains("slow inside Postgres")
                || l.contains("runtime stalled")
                || l.contains("waited for a database connection")
                || l.contains("time to acquire exceeded")
                || l.contains("too many clients")
        })
        .collect();
    eprintln!("REFUSALS {} cause lines", causes.len());
    for line in causes.iter().take(200) {
        eprintln!("REFUSALS {}", &line[..line.len().min(500)]);
    }
    let connections: Result<(i64, String), _> = sqlx::query_as(
        "select (select count(*) from pg_stat_activity), current_setting('max_connections')",
    )
    .fetch_one(pool)
    .await;
    eprintln!(
        "REFUSALS postgres connections (all databases), max: {connections:?}; this test's pool size {} idle {}",
        pool.size(),
        pool.num_idle()
    );
}

/// Scratch paths that exist right now, across every test in this binary.
static LIVE_SCRATCH: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// A file or directory a test made, removed when this is dropped (on a pass
/// or a panic). Left behind, Chrome profiles filled `/tmp`'s quota after a
/// few hundred runs (#90). Sockets get short paths of their own, because a
/// Unix socket path must fit in 108 bytes.
pub struct Scratch(std::path::PathBuf);

impl Scratch {
    /// A fresh directory, `<scratch root>/<kind>-<id>`.
    fn dir(kind: &str) -> Self {
        let path = scratch_root().join(format!("{kind}-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir_all(&path).expect("a scratch directory");
        LIVE_SCRATCH.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Self(path)
    }

    /// A socket path short enough for `SUN_LEN`; the socket is made by
    /// whatever binds it.
    pub fn socket() -> Self {
        LIVE_SCRATCH.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Self(socket_path())
    }

    pub fn path(&self) -> &std::path::Path {
        &self.0
    }
}

impl Drop for Scratch {
    /// Releasing the guard is what the exit check counts: a path whose guard
    /// was never dropped is a leak. Physical removal can lag the release:
    /// Chrome is killed asynchronously, and its helper processes write into
    /// the profile while they exit, so a profile is removed again until it
    /// stays gone, and whatever remains is removed with the scratch root at
    /// exit.
    fn drop(&mut self) {
        LIVE_SCRATCH.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
        if self.0.starts_with(scratch_root()) {
            let path = self.0.clone();
            let _ = std::fs::remove_dir_all(&path);
            std::thread::spawn(move || {
                for _ in 0..25 {
                    std::thread::sleep(Duration::from_millis(200));
                    let _ = std::fs::remove_dir_all(&path);
                }
            });
        } else if let Err(e) = std::fs::remove_file(&self.0)
            && e.kind() != std::io::ErrorKind::NotFound
        {
            eprintln!("e2e: could not remove {}: {e}", self.0.display());
        }
    }
}

/// Where scratch directories go: one directory per test binary run, under
/// the system temp directory (in RAM here). Not under `target/`: Chrome
/// writes its profile constantly, and on disk that I/O slowed every browser
/// test running beside it.
fn scratch_root() -> std::path::PathBuf {
    static ROOT: OnceLock<std::path::PathBuf> = OnceLock::new();
    ROOT.get_or_init(|| std::env::temp_dir().join(format!("clwd-e2e-{}", std::process::id())))
        .clone()
}

/// Log whenever this test's runtime falls behind. `#[sqlx::test]` runs each
/// test on a current-thread runtime, and the harness serves the control plane
/// on it beside the test's own client: a request the control plane cannot get
/// to is a stall here, not a slow handler (#90). Ends with the runtime.
fn watch_for_stalls() {
    tokio::spawn(async {
        let tick = Duration::from_millis(50);
        loop {
            let asleep = std::time::Instant::now();
            tokio::time::sleep(tick).await;
            let late_ms = asleep.elapsed().saturating_sub(tick).as_millis();
            if late_ms > 250 {
                tracing::warn!(late_ms, "e2e: the test's runtime stalled");
            }
        }
    });
}

/// The control plane's pool, as production should size one (#48), not
/// `#[sqlx::test]`'s: that closes connections idle for a second, so each burst
/// reopened them, and under the suite's load opening a Postgres connection
/// took 0.5 to 4.5 s, past the gateway's 5 s budget (#90). All five are opened
/// here, none times out idle, and a shortage fails after 3 s as its own error
/// (`control-plane.timeout`), never as the gateway's timeout.
///
/// Opening is not a request, so it gets its own budget. Through `acquire`, an
/// open is cancelled at the 3 s deadline: under load, where opens take longer,
/// every retry was cancelled too. With no idle timeout and no max lifetime,
/// sqlx's own maintenance task opens `min_connections` at creation with a
/// 300 s deadline, so the pool is ready once all five are idle.
async fn control_plane_pool(test_pool: &PgPool) -> PgPool {
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(5)
        .min_connections(5)
        .idle_timeout(None)
        .max_lifetime(None)
        .acquire_timeout(Duration::from_secs(3))
        .connect_lazy_with((*test_pool.connect_options()).clone());
    let started = std::time::Instant::now();
    while pool.num_idle() < 5 {
        assert!(
            started.elapsed() < Duration::from_secs(120),
            "the control plane's pool, opened at start: {} of 5 open after 120 s",
            pool.num_idle()
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    if started.elapsed() > Duration::from_secs(3) {
        tracing::warn!(
            opened_ms = started.elapsed().as_millis(),
            "e2e: opening the control plane's pool took over 3 s"
        );
    }
    pool
}

/// After the suite: no connection to any test database is left open. Polls
/// for up to ten seconds, since a closed connection's backend takes a moment
/// to exit. `None` when there is no database to ask.
fn connections_left_to_test_databases() -> Option<Vec<String>> {
    let url = std::env::var("DATABASE_URL").ok()?;
    std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .ok()?;
        runtime.block_on(async move {
            use sqlx::Connection as _;
            let mut connection = sqlx::PgConnection::connect(&url).await.ok()?;
            let deadline = std::time::Instant::now() + Duration::from_secs(10);
            loop {
                let left: Vec<String> = sqlx::query_scalar(
                    "select datname::text from pg_stat_activity
                      where datname like '\\_sqlx\\_test%' and pid <> pg_backend_pid()",
                )
                .fetch_all(&mut connection)
                .await
                .ok()?;
                if left.is_empty() || std::time::Instant::now() > deadline {
                    return Some(left);
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        })
    })
    .join()
    .ok()
    .flatten()
}

/// Follow the invalidation stream at `internal_base` into `authz`, as the
/// gateway binary does: on a thread and runtime of its own, stopped with the
/// harness's other servers.
fn follow(
    servers: &Servers,
    authz: Arc<gateway::authz::Authz>,
    internal_base: &str,
    gateway: uuid::Uuid,
) {
    let base = internal_base.to_owned();
    servers.spawn("stream", move |mut stop| {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("stream runtime")
            .block_on(async move {
                tokio::select! {
                    () = gateway::authz::follow(authz, base, Arc::from(INTERNAL_SECRET), gateway) => {}
                    _ = stop.wait_for(|stop| *stop) => {}
                }
            });
    });
}

/// Wait for `condition`, polling, failing after ten seconds. For conditions
/// the product reaches on its own (a stream connecting, a lease lapsing), not
/// for ordering a test's own steps, which use barriers.
pub async fn wait_until(what: &str, mut condition: impl FnMut() -> bool) {
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while !condition() {
        assert!(
            std::time::Instant::now() < deadline,
            "timed out waiting: {what}"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

/// A TCP proxy in front of the control plane's internal listener, for the
/// invalidation stream. A test can cut it (close every connection and refuse
/// new ones, as a partition would) or hold acks (connections whose request is
/// an ack wait at a gate), without touching the product.
pub struct StreamProxy {
    port: u16,
    cut: std::sync::atomic::AtomicBool,
    /// Acks take a read lock; holding acks is holding the write lock.
    gate: Arc<tokio::sync::RwLock<()>>,
    held: Mutex<Option<tokio::sync::OwnedRwLockWriteGuard<()>>>,
    /// Each connection, and whether its first request was an ack.
    open: Mutex<Vec<(Arc<std::sync::atomic::AtomicBool>, tokio::task::AbortHandle)>>,
}

impl StreamProxy {
    pub async fn start(internal_port: u16) -> Arc<Self> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind the proxy");
        let proxy = Arc::new(Self {
            port: listener.local_addr().expect("addr").port(),
            cut: std::sync::atomic::AtomicBool::new(false),
            gate: Arc::default(),
            held: Mutex::default(),
            open: Mutex::default(),
        });
        let serving = proxy.clone();
        tokio::spawn(async move {
            while let Ok((mut inbound, _)) = listener.accept().await {
                if serving.cut.load(std::sync::atomic::Ordering::SeqCst) {
                    continue; // dropped: refused
                }
                let proxy = serving.clone();
                let is_ack = Arc::new(std::sync::atomic::AtomicBool::new(false));
                let marked = is_ack.clone();
                let task = tokio::spawn(async move {
                    let mut head = [0u8; 32];
                    let Ok(n) = inbound.peek(&mut head).await else {
                        return;
                    };
                    if head[..n].starts_with(b"POST /internal/authz/ack") {
                        marked.store(true, std::sync::atomic::Ordering::SeqCst);
                        let _ = proxy.gate.read().await;
                    }
                    let Ok(mut outbound) =
                        tokio::net::TcpStream::connect(("127.0.0.1", internal_port)).await
                    else {
                        return;
                    };
                    let _ = tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await;
                });
                serving
                    .open
                    .lock()
                    .expect("open")
                    .push((is_ack, task.abort_handle()));
            }
        });
        proxy
    }

    pub fn base(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }

    /// Close every connection and refuse new ones.
    pub fn cut(&self) {
        self.cut.store(true, std::sync::atomic::Ordering::SeqCst);
        for (_, task) in self.open.lock().expect("open").drain(..) {
            task.abort();
        }
    }

    /// Hold every ack from now on, until [`Self::release`].
    pub async fn hold_acks(&self) {
        let guard = self.gate.clone().write_owned().await;
        *self.held.lock().expect("held") = Some(guard);
        // A kept-alive ack connection already past the gate would carry the
        // next ack unheld: close it, so the next ack opens one at the gate.
        for (is_ack, task) in self.open.lock().expect("open").iter() {
            if is_ack.load(std::sync::atomic::Ordering::SeqCst) {
                task.abort();
            }
        }
    }

    /// Let held acks through, and stop holding.
    pub fn release(&self) {
        self.held.lock().expect("held").take();
    }
}
