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
    pub pool: PgPool,
    pub control_plane_port: u16,
    pub gateway_port: u16,
    pub evil_port: u16,
}

impl Harness {
    /// Start everything against `pool`.
    pub async fn start(pool: PgPool) -> Self {
        logs();
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
        let mut names = HashMap::new();
        for (org, name, label) in [
            (acme.id, "notes", "notes"),
            (acme.id, "wiki", "wiki"),
            (other.id, "page", "page"),
        ] {
            let app = control_plane::db::create_app(&pool, org, name, "wasm")
                .await
                .expect("app");
            // A published version, so the app has something to run. The test
            // upstream does not read the digest; its shape only has to parse.
            sqlx::query(
                "insert into app_versions (id, app_id, digest, state) values ($1, $2, $3, 'ready')",
            )
            .bind(uuid::Uuid::now_v7())
            .bind(app.id.as_uuid())
            .bind(format!("blake3:{}", "ab".repeat(32)))
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
        let operator =
            opendal::Operator::new(opendal::services::Memory::default()).expect("operator");
        let state =
            control_plane::http::AppState::new(pool.clone(), builder::ArtifactStore::new(operator))
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
        let cert_dir = std::env::temp_dir().join(format!("e2e-certs-{}", uuid::Uuid::now_v7()));
        for org in ["acme", "other"] {
            let dir = cert_dir.join(org);
            std::fs::create_dir_all(&dir).expect("cert dir");
            std::fs::File::create(dir.join("cert.pem"))
                .and_then(|mut f| f.write_all(certs().cert_pem.as_bytes()))
                .expect("cert.pem");
            std::fs::File::create(dir.join("key.pem"))
                .and_then(|mut f| f.write_all(certs().key_pem.as_bytes()))
                .expect("key.pem");
        }
        let internal_base = format!("http://127.0.0.1:{internal_port}");
        let hop: Arc<dyn AppUpstream> = upstream.clone();
        let gateway_port =
            start_gateway(&pool, &internal_base, &hop, &cert_dir, control_plane_port).await;
        for port in [control_plane_port, evil_port] {
            wait_for_port(port).await;
        }

        Self {
            upstream,
            pool,
            control_plane_port,
            gateway_port,
            evil_port,
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
) -> u16 {
    for attempt in 1..=5 {
        let gateway_port = free_port();
        let (internal_base, hop, cert_dir) = (
            internal_base.to_owned(),
            hop.clone(),
            cert_dir.to_path_buf(),
        );
        std::thread::spawn(move || {
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
            let edge = gateway::edge::Edge::new(lookup, apps.clone()).serving(
                gateway::edge::Serving::new(
                    signin,
                    shared::domains::ControlPlaneDomain::parse(CONTROL_PLANE).expect("cp domain"),
                    hop,
                ),
            );
            let store = Arc::new(shared::cert::DirCertStore::new(&cert_dir));
            let resolver = gateway::cert::CertResolver::new(store, apps);
            let tls = TlsSettings::with_callbacks(gateway::tls::DynamicCert::callbacks(resolver))
                .expect("tls");
            let mut server = Server::new(None).expect("pingora");
            server.bootstrap();
            let mut service = Service::new("e2e-gateway".to_owned(), HttpServer::new_app(edge));
            service.add_tls_with_settings(&format!("127.0.0.1:{gateway_port}"), None, tls);
            server.add_service(service);
            server.run_forever();
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
            return gateway_port;
        }
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
}

async fn launch(rules: &str, spki_pin: Option<&str>) -> Chrome {
    let dir = std::env::temp_dir().join(format!("e2e-chrome-{}", uuid::Uuid::now_v7()));
    let mut builder = BrowserConfig::builder()
        .chrome_executable(chrome_binary())
        .new_headless_mode()
        .no_sandbox()
        // chromiumoxide ignores every certificate error by default, over the
        // DevTools protocol. Off: the only trust is the pinned key below, and
        // the no-bypass control proves it (it caught this default).
        .respect_https_errors()
        .user_data_dir(dir)
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
