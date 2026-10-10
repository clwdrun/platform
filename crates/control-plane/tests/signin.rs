//! Google sign-in through the real router, against a mock OIDC issuer and a
//! real Postgres.
//!
//! The mock is an in-process HTTP server on an ephemeral port, so discovery
//! and the code exchange run over real TCP through the control plane's own
//! `reqwest` client. It behaves like Google where the security argument leans
//! on Google:
//!
//! - **An authorization code is single-use.** The token endpoint removes a
//!   code from its table on the first exchange, success or failure. The
//!   replay test is only meaningful because of this: against a mock that
//!   accepts a code twice it would pass with no replay protection at all.
//! - PKCE S256 is checked: the verifier must hash to the stored challenge.
//! - The client must authenticate with its secret (HTTP Basic).
//!
//! Every test asserts at the boundary — the status and code the browser gets,
//! and whether a session that `session::authenticate` accepts came out of it.
//! The mock starts with `expect`, never a skip: if it cannot bind, these fail.

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use axum::body::Body;
use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, Request, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Form, Json, Router};
use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use control_plane::http::AppState;
use control_plane::orgs::TxtLookup;
use control_plane::session;
use control_plane::signin::{CookieKey, FLOW_COOKIE, SignIn};
use identity::oidc::GoogleIdTokenClaims;
use identity::{GoogleClaims, GoogleIdToken, OidcConfig};
use openidconnect::core::{CoreJsonWebKeySet, CoreJwsSigningAlgorithm, CoreRsaPrivateSigningKey};
use openidconnect::{
    Audience, EndUserEmail, IssuerUrl, Nonce, PrivateSigningKey as _, StandardClaims,
    SubjectIdentifier,
};
use sha2::{Digest as _, Sha256};
use sqlx::PgPool;
use tower::ServiceExt as _;

const CLIENT_ID: &str = "test-client.apps.googleusercontent.com";
const CLIENT_SECRET: &str = "test-client-secret";
const REDIRECT: &str = "https://api.clwd.run/auth/google/callback";
const APEX: &str = "clwd.run";
const SUBJECT: &str = "google-subject-1";
const EMAIL: &str = "person@example.com";

// ------------------------------------------------------------ mock issuer ----

/// One deviation per ID-token check, so each negative perturbs exactly one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Tamper {
    None,
    WrongIssuer,
    WrongAudience,
    Expired,
    WrongNonce,
    UntrustedKey,
}

struct Grant {
    nonce: String,
    challenge: String,
}

struct Mock {
    issuer: String,
    codes: Mutex<HashMap<String, Grant>>,
    tamper: Mutex<Tamper>,
    subject: Mutex<String>,
    email: Mutex<String>,
    /// The `hd` claim. `None` is a consumer Google account.
    hd: Mutex<Option<String>>,
    token_calls: AtomicUsize,
    issued: AtomicUsize,
}

fn pem() -> &'static (String, String) {
    static PEMS: OnceLock<(String, String)> = OnceLock::new();
    PEMS.get_or_init(|| {
        use rsa::pkcs1::EncodeRsaPrivateKey as _;
        let mut rng = rand::thread_rng();
        let mut generate = || {
            rsa::RsaPrivateKey::new(&mut rng, 2048)
                .expect("generate a test RSA key")
                .to_pkcs1_pem(rsa::pkcs1::LineEnding::LF)
                .expect("encode PKCS#1 PEM")
                .to_string()
        };
        (generate(), generate())
    })
}

fn trusted_key() -> CoreRsaPrivateSigningKey {
    CoreRsaPrivateSigningKey::from_pem(&pem().0, None).expect("trusted key")
}

fn untrusted_key() -> CoreRsaPrivateSigningKey {
    CoreRsaPrivateSigningKey::from_pem(&pem().1, None).expect("untrusted key")
}

fn utc(secs: i64) -> chrono::DateTime<chrono::Utc> {
    chrono::DateTime::from_timestamp(secs, 0).expect("valid timestamp")
}

impl Mock {
    /// What Google's authorization endpoint does after the user consents:
    /// mint a code bound to this request's nonce and PKCE challenge, and
    /// return the callback query the browser is redirected with.
    fn consent(&self, authorize_url: &str) -> String {
        let url = openidconnect::url::Url::parse(authorize_url).expect("authorize url");
        let q: HashMap<_, _> = url.query_pairs().into_owned().collect();
        assert_eq!(q["code_challenge_method"], "S256");
        let code = format!("code-{}", uuid::Uuid::now_v7());
        self.codes.lock().expect("lock").insert(
            code.clone(),
            Grant {
                nonce: q["nonce"].clone(),
                challenge: q["code_challenge"].clone(),
            },
        );
        format!("code={code}&state={}", q["state"])
    }

    fn id_token(&self, nonce: &str) -> String {
        let tamper = *self.tamper.lock().expect("lock");
        let now = chrono::Utc::now().timestamp();
        let (iat, exp) = if tamper == Tamper::Expired {
            (now - 7200, now - 3600)
        } else {
            (now, now + 3600)
        };
        let issuer = if tamper == Tamper::WrongIssuer {
            "https://accounts.evil.example".to_owned()
        } else {
            self.issuer.clone()
        };
        let audience = if tamper == Tamper::WrongAudience {
            "another-client.apps.googleusercontent.com"
        } else {
            CLIENT_ID
        };
        let nonce = if tamper == Tamper::WrongNonce {
            "not-the-nonce".to_owned()
        } else {
            nonce.to_owned()
        };
        let key = if tamper == Tamper::UntrustedKey {
            untrusted_key()
        } else {
            trusted_key()
        };

        let standard = StandardClaims::new(SubjectIdentifier::new(
            self.subject.lock().expect("lock").clone(),
        ))
        .set_email(Some(EndUserEmail::new(
            self.email.lock().expect("lock").clone(),
        )))
        .set_email_verified(Some(true));
        let claims = GoogleIdTokenClaims::new(
            IssuerUrl::new(issuer).expect("issuer"),
            vec![Audience::new(audience.to_owned())],
            utc(exp),
            utc(iat),
            standard,
            GoogleClaims {
                hd: self.hd.lock().expect("lock").clone(),
            },
        )
        .set_nonce(Some(Nonce::new(nonce)));
        GoogleIdToken::new(
            claims,
            &key,
            CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256,
            None,
            None,
        )
        .expect("sign")
        .to_string()
    }
}

async fn discovery(State(mock): State<Arc<Mock>>) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "issuer": mock.issuer,
        "authorization_endpoint": format!("{}/authorize", mock.issuer),
        "token_endpoint": format!("{}/token", mock.issuer),
        "jwks_uri": format!("{}/jwks", mock.issuer),
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
    }))
}

async fn jwks() -> Json<CoreJsonWebKeySet> {
    Json(CoreJsonWebKeySet::new(vec![
        trusted_key().as_verification_key(),
    ]))
}

fn invalid_grant() -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(serde_json::json!({ "error": "invalid_grant" })),
    )
        .into_response()
}

async fn token(
    State(mock): State<Arc<Mock>>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    mock.token_calls.fetch_add(1, Ordering::SeqCst);

    let basic = format!(
        "Basic {}",
        STANDARD.encode(format!("{CLIENT_ID}:{CLIENT_SECRET}"))
    );
    if headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        != Some(&basic)
    {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "error": "invalid_client" })),
        )
            .into_response();
    }
    if form.get("grant_type").map(String::as_str) != Some("authorization_code")
        || form.get("redirect_uri").map(String::as_str) != Some(REDIRECT)
    {
        return invalid_grant();
    }

    // Burned on first use, whatever happens next — as Google does.
    let Some(grant) = form
        .get("code")
        .and_then(|code| mock.codes.lock().expect("lock").remove(code))
    else {
        return invalid_grant();
    };
    let Some(verifier) = form.get("code_verifier") else {
        return invalid_grant();
    };
    if URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes())) != grant.challenge {
        return invalid_grant();
    }

    mock.issued.fetch_add(1, Ordering::SeqCst);
    Json(serde_json::json!({
        "access_token": "unused-access-token",
        "token_type": "Bearer",
        "expires_in": 3600,
        "id_token": mock.id_token(&grant.nonce),
    }))
    .into_response()
}

struct Issuer {
    mock: Arc<Mock>,
    server: tokio::task::JoinHandle<()>,
    dns: Arc<MockTxt>,
}

async fn start_issuer() -> Issuer {
    // Generate the keys before serving, on a blocking thread: RSA keygen in a
    // debug build takes seconds, and doing it inside the first `/jwks` request
    // outruns the client's timeout.
    tokio::task::spawn_blocking(pem).await.expect("keygen");
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect(
        "the mock issuer must bind — a sign-in test that cannot reach it fails, it is not skipped",
    );
    let issuer = format!("http://{}", listener.local_addr().expect("addr"));
    let mock = Arc::new(Mock {
        issuer,
        codes: Mutex::default(),
        tamper: Mutex::new(Tamper::None),
        subject: Mutex::new(SUBJECT.to_owned()),
        email: Mutex::new(EMAIL.to_owned()),
        hd: Mutex::new(Some("example.com".to_owned())),
        token_calls: AtomicUsize::new(0),
        issued: AtomicUsize::new(0),
    });
    // The workspace lint forbids `Router::route` so the control plane's route
    // table stays the only way into *its* router. This is the mock issuer's
    // own server, not that router; `#[expect]` fails if it stops applying.
    #[expect(
        clippy::disallowed_methods,
        reason = "mock OIDC issuer, not the guarded control-plane router"
    )]
    let app = Router::new()
        .route("/.well-known/openid-configuration", get(discovery))
        .route("/jwks", get(jwks))
        .route("/token", post(token))
        .with_state(mock.clone());
    let server = tokio::spawn(async move {
        axum::serve(listener, app)
            .await
            .expect("mock issuer serves");
    });
    Issuer {
        mock,
        server,
        dns: Arc::default(),
    }
}

// ------------------------------------------------------------- the client ----

fn key() -> CookieKey {
    CookieKey::from_secret(b"a-test-signing-secret-of-some-length")
}

async fn state(pool: &PgPool, issuer: &Issuer) -> AppState {
    let operator =
        opendal::Operator::new(opendal::services::Memory::default()).expect("in-memory operator");
    let signin = SignIn::discover(
        OidcConfig::new(
            CLIENT_ID,
            CLIENT_SECRET,
            REDIRECT,
            issuer.mock.issuer.clone(),
        ),
        key(),
        APEX,
    )
    .await
    .expect("discovery against the mock issuer");
    AppState::new(pool.clone(), builder::ArtifactStore::new(operator))
        .with_signin(signin)
        .with_txt_lookup(issuer.dns.clone())
}

/// TXT records the domain-verification lookup sees, set per test.
#[derive(Default)]
struct MockTxt(Mutex<HashMap<String, Vec<String>>>);

impl MockTxt {
    fn publish(&self, name: &str, value: &str) {
        self.0
            .lock()
            .expect("lock")
            .entry(name.to_owned())
            .or_default()
            .push(value.to_owned());
    }
}

#[async_trait::async_trait]
impl TxtLookup for MockTxt {
    async fn txt(&self, name: &str) -> Result<Vec<String>, String> {
        Ok(self
            .0
            .lock()
            .map_err(|_| "poisoned".to_owned())?
            .get(name)
            .cloned()
            .unwrap_or_default())
    }
}

struct Reply {
    status: StatusCode,
    headers: HeaderMap,
    json: serde_json::Value,
}

impl Reply {
    fn code(&self) -> &str {
        self.json["code"].as_str().unwrap_or("")
    }

    fn set_cookies(&self) -> Vec<String> {
        self.headers
            .get_all(header::SET_COOKIE)
            .iter()
            .map(|v| v.to_str().expect("ascii").to_owned())
            .collect()
    }

    /// The `name=value` pair of the cookie this reply sets under `name`, if
    /// it sets a non-empty one.
    fn cookie(&self, name: &str) -> Option<String> {
        self.set_cookies().into_iter().find_map(|c| {
            let pair = c.split(';').next()?.to_owned();
            let (n, v) = pair.split_once('=')?;
            (n == name && !v.is_empty()).then_some(pair)
        })
    }
}

async fn get_(state: &AppState, uri: &str, cookie: Option<&str>) -> Reply {
    send(state, "GET", uri, cookie).await
}

/// The control plane's own origin, as a browser on its pages sends it.
const ORIGIN: &str = "https://api.clwd.run";
/// What a browser sends on a request from the control plane's own pages.
const SAME_ORIGIN: [(&str, &str); 1] = [("sec-fetch-site", "same-origin")];

/// A request from the control plane's own pages.
async fn send(state: &AppState, method: &str, uri: &str, cookie: Option<&str>) -> Reply {
    send_with(state, method, uri, cookie, &SAME_ORIGIN, "").await
}

async fn send_with(
    state: &AppState,
    method: &str,
    uri: &str,
    cookie: Option<&str>,
    headers: &[(&str, &str)],
    body: &str,
) -> Reply {
    let mut request = Request::builder().method(method).uri(uri);
    if let Some(cookie) = cookie {
        request = request.header(header::COOKIE, cookie);
    }
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    let response = control_plane::http::router(state.clone())
        .oneshot(
            request
                .body(Body::from(body.to_owned()))
                .expect("a valid request"),
        )
        .await
        .expect("the router answers");
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .expect("body");
    Reply {
        status,
        headers,
        json: serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
    }
}

/// Start sign-in: the flow cookie and the authorize URL.
async fn begin(state: &AppState) -> (String, String) {
    let reply = get_(state, "/auth/google", None).await;
    assert_eq!(reply.status, StatusCode::SEE_OTHER);
    let flow = reply.cookie(FLOW_COOKIE).expect("a flow cookie");
    let location = reply.headers[header::LOCATION]
        .to_str()
        .expect("ascii")
        .to_owned();
    (flow, location)
}

/// Whether this reply's session cookie authenticates.
async fn authenticates(pool: &PgPool, reply: &Reply) -> Option<db_user::Id> {
    let pair = reply.cookie(session::COOKIE_NAME)?;
    let mut headers = HeaderMap::new();
    headers.insert(header::COOKIE, HeaderValue::from_str(&pair).expect("ascii"));
    session::authenticate(pool, &key(), &headers)
        .await
        .ok()
        .map(|s| s.user_id)
}

mod db_user {
    pub type Id = control_plane::ids::UserId;
}

async fn user_count(pool: &PgPool) -> i64 {
    sqlx::query_scalar!(r#"select count(*) as "n!" from users"#)
        .fetch_one(pool)
        .await
        .expect("count")
}

// ------------------------------------------------------------------ tests ----

#[sqlx::test(migrations = "../../migrations")]
async fn a_full_sign_in_ends_in_a_session_that_authenticates(pool: PgPool) {
    let issuer = start_issuer().await;
    let state = state(&pool, &issuer).await;

    let (flow, authorize) = begin(&state).await;
    let query = issuer.mock.consent(&authorize);
    let reply = get_(
        &state,
        &format!("/auth/google/callback?{query}"),
        Some(&flow),
    )
    .await;

    assert_eq!(reply.status, StatusCode::SEE_OTHER, "{:?}", reply.json);
    assert_eq!(reply.headers[header::LOCATION], "https://clwd.run/");
    let user = authenticates(&pool, &reply)
        .await
        .expect("the session the callback issued authenticates");

    let row = sqlx::query!(
        "select email, google_subject from users where id = $1",
        user.as_uuid()
    )
    .fetch_one(&pool)
    .await
    .expect("the user row");
    assert_eq!(row.google_subject.as_deref(), Some(SUBJECT));
    assert_eq!(row.email, EMAIL);

    // The flow cookie is consumed.
    assert!(
        reply
            .set_cookies()
            .iter()
            .any(|c| c.starts_with(&format!("{FLOW_COOKIE}=;")) && c.contains("Max-Age=0")),
        "the flow cookie is cleared: {:?}",
        reply.set_cookies()
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_mismatched_state_is_rejected_before_any_exchange(pool: PgPool) {
    let issuer = start_issuer().await;
    let state = state(&pool, &issuer).await;

    let (flow, authorize) = begin(&state).await;
    let query = issuer.mock.consent(&authorize);
    let code = query.split('&').next().expect("code=...");
    let reply = get_(
        &state,
        &format!("/auth/google/callback?{code}&state=forged"),
        Some(&flow),
    )
    .await;

    assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
    assert_eq!(reply.code(), "identity.unauthenticated");
    assert_eq!(reply.cookie(session::COOKIE_NAME), None);
    assert_eq!(
        issuer.mock.token_calls.load(Ordering::SeqCst),
        0,
        "a forged state must not reach the token endpoint"
    );
    assert_eq!(
        issuer.mock.codes.lock().expect("lock").len(),
        1,
        "the code is not burned"
    );
}

/// The hostile replay: the captured callback URL with its flow cookie intact.
/// The cookie still opens and the state still matches, so the only thing that
/// can stop it is the exchange — and the token-call count proves that is where
/// it was stopped.
#[sqlx::test(migrations = "../../migrations")]
async fn a_replayed_callback_is_rejected_at_the_exchange(pool: PgPool) {
    let issuer = start_issuer().await;
    let state = state(&pool, &issuer).await;

    let (flow, authorize) = begin(&state).await;
    let uri = format!("/auth/google/callback?{}", issuer.mock.consent(&authorize));

    let first = get_(&state, &uri, Some(&flow)).await;
    assert_eq!(first.status, StatusCode::SEE_OTHER, "{:?}", first.json);

    let replay = get_(&state, &uri, Some(&flow)).await;
    assert_eq!(replay.status, StatusCode::UNAUTHORIZED);
    assert_eq!(replay.code(), "identity.unauthenticated");
    assert_eq!(replay.cookie(session::COOKIE_NAME), None);
    assert_eq!(
        issuer.mock.token_calls.load(Ordering::SeqCst),
        2,
        "the replay reached the exchange — the cookie did not stop it"
    );
    assert_eq!(
        issuer.mock.issued.load(Ordering::SeqCst),
        1,
        "the burned code issued nothing the second time"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_missing_or_tampered_flow_cookie_is_rejected(pool: PgPool) {
    let issuer = start_issuer().await;
    let state = state(&pool, &issuer).await;

    let (flow, authorize) = begin(&state).await;
    let uri = format!("/auth/google/callback?{}", issuer.mock.consent(&authorize));

    // Flip a payload character, not the signature's last one: that last
    // base64 character carries padding bits, so flipping it can leave the
    // signature bytes unchanged and test the decoder rather than the key.
    let (name_and_head, rest) = flow.split_once('.').expect("a JWT has segments");
    let mut payload = rest.as_bytes().to_vec();
    payload[0] = if payload[0] == b'A' { b'B' } else { b'A' };
    let tampered = format!(
        "{name_and_head}.{}",
        String::from_utf8(payload).expect("ascii")
    );

    for cookie in [None, Some(tampered.as_str())] {
        let reply = get_(&state, &uri, cookie).await;
        assert_eq!(reply.status, StatusCode::UNAUTHORIZED, "{cookie:?}");
        assert_eq!(reply.code(), "identity.unauthenticated");
        assert_eq!(reply.cookie(session::COOKIE_NAME), None);
    }
    assert_eq!(issuer.mock.token_calls.load(Ordering::SeqCst), 0);
}

/// Every ID-token check, through the whole route: the exchange succeeds at
/// the mock, the token it returns is wrong in exactly one way, and no session
/// and no user come out of it.
#[sqlx::test(migrations = "../../migrations")]
async fn each_bad_id_token_is_rejected_through_the_route(pool: PgPool) {
    let issuer = start_issuer().await;
    let state = state(&pool, &issuer).await;

    for tamper in [
        Tamper::WrongIssuer,
        Tamper::WrongAudience,
        Tamper::Expired,
        Tamper::WrongNonce,
        Tamper::UntrustedKey,
    ] {
        *issuer.mock.tamper.lock().expect("lock") = tamper;
        let issued_before = issuer.mock.issued.load(Ordering::SeqCst);

        let (flow, authorize) = begin(&state).await;
        let query = issuer.mock.consent(&authorize);
        let reply = get_(
            &state,
            &format!("/auth/google/callback?{query}"),
            Some(&flow),
        )
        .await;

        assert_eq!(
            issuer.mock.issued.load(Ordering::SeqCst),
            issued_before + 1,
            "{tamper:?}: the mock issued a token, so the rejection is the verifier's"
        );
        assert_eq!(reply.status, StatusCode::UNAUTHORIZED, "{tamper:?}");
        assert_eq!(reply.code(), "identity.unauthenticated", "{tamper:?}");
        assert_eq!(reply.cookie(session::COOKIE_NAME), None, "{tamper:?}");
    }
    assert_eq!(user_count(&pool).await, 0, "no bad token created a user");

    // Teeth: the same harness with no tamper signs in, so the five rejections
    // above are the tampering, not a broken harness.
    *issuer.mock.tamper.lock().expect("lock") = Tamper::None;
    let (flow, authorize) = begin(&state).await;
    let query = issuer.mock.consent(&authorize);
    let reply = get_(
        &state,
        &format!("/auth/google/callback?{query}"),
        Some(&flow),
    )
    .await;
    assert!(
        authenticates(&pool, &reply).await.is_some(),
        "{:?}",
        reply.json
    );
}

/// Sign-in mints a new session whatever session cookie arrived with it.
#[sqlx::test(migrations = "../../migrations")]
async fn every_sign_in_issues_a_fresh_session(pool: PgPool) {
    let issuer = start_issuer().await;
    let state = state(&pool, &issuer).await;

    let (flow, authorize) = begin(&state).await;
    let query = issuer.mock.consent(&authorize);
    let first = get_(
        &state,
        &format!("/auth/google/callback?{query}"),
        Some(&flow),
    )
    .await;
    let old = first.cookie(session::COOKIE_NAME).expect("a session");

    let (flow, authorize) = begin(&state).await;
    let query = issuer.mock.consent(&authorize);
    let second = get_(
        &state,
        &format!("/auth/google/callback?{query}"),
        Some(&format!("{flow}; {old}")),
    )
    .await;
    let new = second.cookie(session::COOKIE_NAME).expect("a session");

    assert_ne!(old, new, "the arriving session is never reused");
    let sessions: i64 = sqlx::query_scalar!(r#"select count(*) as "n!" from sessions"#)
        .fetch_one(&pool)
        .await
        .expect("count");
    assert_eq!(sessions, 2);
}

/// The user is found by Google subject: a changed email is the same user,
/// and a different subject claiming a taken email is refused, not linked.
#[sqlx::test(migrations = "../../migrations")]
async fn users_are_keyed_on_subject_never_email(pool: PgPool) {
    let issuer = start_issuer().await;
    let state = state(&pool, &issuer).await;
    let sign_in = || async {
        let (flow, authorize) = begin(&state).await;
        let query = issuer.mock.consent(&authorize);
        get_(
            &state,
            &format!("/auth/google/callback?{query}"),
            Some(&flow),
        )
        .await
    };

    let first = authenticates(&pool, &sign_in().await)
        .await
        .expect("signed in");

    *issuer.mock.email.lock().expect("lock") = "renamed@example.com".to_owned();
    let renamed = authenticates(&pool, &sign_in().await)
        .await
        .expect("signed in");
    assert_eq!(first, renamed, "same subject, same user");

    // A different Google account now presents the address the first user
    // holds — what a reassigned address looks like.
    *issuer.mock.subject.lock().expect("lock") = "google-subject-2".to_owned();
    let takeover = sign_in().await;
    assert_eq!(takeover.status, StatusCode::CONFLICT);
    assert_eq!(takeover.code(), "control-plane.conflict");
    assert_eq!(takeover.cookie(session::COOKIE_NAME), None);
    assert_eq!(user_count(&pool).await, 1);
}

/// Negative control: with the issuer gone, sign-in is a retryable timeout —
/// not a session, and not a pass.
#[sqlx::test(migrations = "../../migrations")]
async fn with_the_issuer_down_sign_in_fails_closed(pool: PgPool) {
    let issuer = start_issuer().await;
    let state = state(&pool, &issuer).await;
    let (flow, authorize) = begin(&state).await;
    let query = issuer.mock.consent(&authorize);

    issuer.server.abort();
    let _ = issuer.server.await;

    let reply = get_(
        &state,
        &format!("/auth/google/callback?{query}"),
        Some(&flow),
    )
    .await;
    assert_eq!(
        reply.status,
        StatusCode::GATEWAY_TIMEOUT,
        "{:?}",
        reply.json
    );
    assert_eq!(reply.code(), "control-plane.timeout");
    assert_eq!(reply.cookie(session::COOKIE_NAME), None);
}

#[tokio::test]
async fn discovery_against_a_down_issuer_fails() {
    let issuer = start_issuer().await;
    let url = issuer.mock.issuer.clone();
    issuer.server.abort();
    let _ = issuer.server.await;

    let result = SignIn::discover(
        OidcConfig::new(CLIENT_ID, CLIENT_SECRET, REDIRECT, url),
        key(),
        APEX,
    )
    .await;
    assert!(
        matches!(result, Err(identity::FlowError::Unavailable(_))),
        "discovery with no issuer must fail as unavailable"
    );
}

// ----------------------------------------------------------------- logout ----

async fn signed_in(state: &AppState, issuer: &Issuer) -> String {
    let (flow, authorize) = begin(state).await;
    let query = issuer.mock.consent(&authorize);
    let reply = get_(
        state,
        &format!("/auth/google/callback?{query}"),
        Some(&flow),
    )
    .await;
    reply.cookie(session::COOKIE_NAME).expect("signed in")
}

async fn verdict(pool: &PgPool, cookie: &str) -> Result<(), String> {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::COOKIE,
        HeaderValue::from_str(cookie).expect("ascii"),
    );
    session::authenticate(pool, &key(), &headers)
        .await
        .map(|_| ())
        .map_err(|e| e.code().to_owned())
}

/// Logout is a server-side revoke: the old cookie, byte for byte, no longer
/// authenticates — asserted on the reuse, not on the column.
#[sqlx::test(migrations = "../../migrations")]
async fn logging_out_revokes_the_session_server_side(pool: PgPool) {
    let issuer = start_issuer().await;
    let state = state(&pool, &issuer).await;
    let cookie = signed_in(&state, &issuer).await;
    assert_eq!(verdict(&pool, &cookie).await, Ok(()));

    let reply = send(&state, "POST", "/auth/logout", Some(&cookie)).await;
    assert_eq!(reply.status, StatusCode::NO_CONTENT, "{:?}", reply.json);
    assert!(
        reply.set_cookies().iter().any(|c| {
            c.starts_with(&format!("{}=;", session::COOKIE_NAME))
                && c.contains("Domain=clwd.run")
                && c.contains("Max-Age=0")
        }),
        "the session cookie is cleared: {:?}",
        reply.set_cookies()
    );

    assert_eq!(
        verdict(&pool, &cookie).await,
        Err("identity.unauthenticated".to_owned()),
        "the old cookie must not authenticate after logout"
    );
}

/// No session, a forged one, an already-revoked one: the same `204` and the
/// same headers, so the reply says nothing about what the cookie was.
#[sqlx::test(migrations = "../../migrations")]
async fn logout_is_idempotent_and_reveals_nothing(pool: PgPool) {
    let issuer = start_issuer().await;
    let state = state(&pool, &issuer).await;
    let cookie = signed_in(&state, &issuer).await;
    let first = send(&state, "POST", "/auth/logout", Some(&cookie)).await;
    assert_eq!(first.status, StatusCode::NO_CONTENT);

    let forged = format!("{}=not.a.jwt", session::COOKIE_NAME);
    for presented in [None, Some(forged.as_str()), Some(cookie.as_str())] {
        let reply = send(&state, "POST", "/auth/logout", presented).await;
        assert_eq!(reply.status, StatusCode::NO_CONTENT, "{presented:?}");
        assert_eq!(reply.json, serde_json::Value::Null, "{presented:?}");
        assert_eq!(reply.set_cookies(), first.set_cookies(), "{presented:?}");
    }
}

/// A GET cannot sign anyone out: an `<img src>` on any page could fire one.
#[sqlx::test(migrations = "../../migrations")]
async fn logout_by_get_is_refused_and_revokes_nothing(pool: PgPool) {
    let issuer = start_issuer().await;
    let state = state(&pool, &issuer).await;
    let cookie = signed_in(&state, &issuer).await;

    let reply = get_(&state, "/auth/logout", Some(&cookie)).await;
    assert_eq!(
        reply.status,
        StatusCode::METHOD_NOT_ALLOWED,
        "{:?}",
        reply.json
    );
    assert_eq!(reply.cookie(session::COOKIE_NAME), None);
    assert_eq!(verdict(&pool, &cookie).await, Ok(()));
}

// ------------------------------------------------------------------- orgs ----
//
// Every assertion about who belongs where reads `org_members` itself — never a
// value the code returned. A function that answers "personal org" while also
// inserting a row for the shared one passes a return-value test and fails the
// property these tests exist for.

const CLAIMANT: &str = "google-subject-claimant";

/// Sign in as one Google account, with `hd` as given (`None`: a consumer
/// account). Returns the session cookie and the user id.
async fn sign_in_as(
    state: &AppState,
    issuer: &Issuer,
    subject: &str,
    email: &str,
    hd: Option<&str>,
) -> (String, uuid::Uuid) {
    *issuer.mock.subject.lock().expect("lock") = subject.to_owned();
    *issuer.mock.email.lock().expect("lock") = email.to_owned();
    *issuer.mock.hd.lock().expect("lock") = hd.map(str::to_owned);
    let (flow, authorize) = begin(state).await;
    let query = issuer.mock.consent(&authorize);
    let reply = get_(
        state,
        &format!("/auth/google/callback?{query}"),
        Some(&flow),
    )
    .await;
    assert_eq!(reply.status, StatusCode::SEE_OTHER, "{:?}", reply.json);
    let cookie = reply.cookie(session::COOKIE_NAME).expect("signed in");
    let user = verdict_user(state, &cookie).await;
    (cookie, user)
}

async fn verdict_user(state: &AppState, cookie: &str) -> uuid::Uuid {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::COOKIE,
        HeaderValue::from_str(cookie).expect("ascii"),
    );
    session::authenticate(&state.pool, &key(), &headers)
        .await
        .expect("a live session")
        .user_id
        .as_uuid()
}

#[derive(Debug, PartialEq, Eq)]
struct Membership {
    org: uuid::Uuid,
    slug: String,
    joined_via: String,
}

/// Every membership row for `user`, read from the database.
async fn memberships(pool: &PgPool, user: uuid::Uuid) -> Vec<Membership> {
    sqlx::query_as!(
        Membership,
        r#"select o.id as org, o.slug, m.joined_via
             from org_members m join orgs o on o.id = m.org_id
            where m.user_id = $1
            order by o.slug"#,
        user
    )
    .fetch_all(pool)
    .await
    .expect("memberships")
}

async fn members_of(pool: &PgPool, org: uuid::Uuid) -> i64 {
    sqlx::query_scalar!(
        r#"select count(*) as "n!" from org_members where org_id = $1"#,
        org
    )
    .fetch_one(pool)
    .await
    .expect("count")
}

async fn claim(state: &AppState, cookie: &str, body: &serde_json::Value) -> Reply {
    send_with(
        state,
        "POST",
        "/v1/domain-claims",
        Some(cookie),
        &SAME_ORIGIN,
        &body.to_string(),
    )
    .await
}

/// Publish a claim's TXT record and verify it.
async fn verify(state: &AppState, issuer: &Issuer, cookie: &str, claim: &Reply) -> Reply {
    issuer.dns.publish(
        claim.json["txt_name"].as_str().expect("txt_name"),
        claim.json["txt_value"].as_str().expect("txt_value"),
    );
    let id = claim.json["id"].as_str().expect("id");
    send(
        state,
        "POST",
        &format!("/v1/domain-claims/{id}/verify"),
        Some(cookie),
    )
    .await
}

/// Claim and verify `domain` as `cookie`'s user. Returns the new org's id.
async fn domain_org(
    state: &AppState,
    issuer: &Issuer,
    cookie: &str,
    domain: &str,
    slug: &str,
    auto_join: bool,
) -> uuid::Uuid {
    let started = claim(
        state,
        cookie,
        &serde_json::json!({ "domain": domain, "slug": slug, "auto_join": auto_join }),
    )
    .await;
    assert_eq!(started.status, StatusCode::CREATED, "{:?}", started.json);
    let verified = verify(state, issuer, cookie, &started).await;
    assert_eq!(verified.status, StatusCode::CREATED, "{:?}", verified.json);
    verified.json["id"]
        .as_str()
        .and_then(|id| id.parse().ok())
        .expect("an org id")
}

/// The free-mail rule, with something to fall into: an org has verified
/// `example.com` with auto-join on, and a consumer account (no `hd`) whose
/// email is at `example.com` signs in. It gets a personal org and nothing
/// else — the email's domain is evidence of nothing.
#[sqlx::test(migrations = "../../migrations")]
async fn a_consumer_account_never_joins_an_existing_org(pool: PgPool) {
    let issuer = start_issuer().await;
    let state = state(&pool, &issuer).await;
    let (claimant, _) = sign_in_as(
        &state,
        &issuer,
        CLAIMANT,
        "admin@example.com",
        Some("example.com"),
    )
    .await;
    let shared = domain_org(&state, &issuer, &claimant, "example.com", "example", true).await;

    let (_, bob) = sign_in_as(&state, &issuer, "consumer-bob", "bob@example.com", None).await;

    let rows = memberships(&pool, bob).await;
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0].joined_via, "personal");
    assert!(rows[0].slug.starts_with("p-"), "{rows:?}");
    assert_ne!(rows[0].org, shared);
    assert_eq!(members_of(&pool, shared).await, 1, "only the claimant");
}

#[sqlx::test(migrations = "../../migrations")]
async fn two_consumer_accounts_never_share_an_org(pool: PgPool) {
    let issuer = start_issuer().await;
    let state = state(&pool, &issuer).await;
    let (_, a) = sign_in_as(&state, &issuer, "consumer-a", "a@gmail.com", None).await;
    let (_, b) = sign_in_as(&state, &issuer, "consumer-b", "b@gmail.com", None).await;

    let (a, b) = (memberships(&pool, a).await, memberships(&pool, b).await);
    assert_eq!((a.len(), b.len()), (1, 1), "{a:?} {b:?}");
    assert_ne!(a[0].org, b[0].org);
    assert_eq!(members_of(&pool, a[0].org).await, 1);
    assert_eq!(members_of(&pool, b[0].org).await, 1);
}

/// `hd` present, but no org holds the domain: a personal org, not an org bound
/// to the domain — the first account to arrive does not get to own it.
#[sqlx::test(migrations = "../../migrations")]
async fn a_workspace_account_with_no_org_for_its_domain_gets_a_personal_org(pool: PgPool) {
    let issuer = start_issuer().await;
    let state = state(&pool, &issuer).await;
    let (_, user) = sign_in_as(&state, &issuer, "ws-1", "a@acme.test", Some("acme.test")).await;

    let rows = memberships(&pool, user).await;
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0].joined_via, "personal");
    let bound: i64 = sqlx::query_scalar!(r#"select count(*) as "n!" from org_domains"#)
        .fetch_one(&pool)
        .await
        .expect("count");
    assert_eq!(bound, 0, "no domain is bound by signing in");
}

/// Auto-join on: the account joins the domain org and gets no personal org.
#[sqlx::test(migrations = "../../migrations")]
async fn auto_join_puts_a_workspace_account_in_one_org_only(pool: PgPool) {
    let issuer = start_issuer().await;
    let state = state(&pool, &issuer).await;
    let (claimant, _) = sign_in_as(
        &state,
        &issuer,
        CLAIMANT,
        "admin@example.com",
        Some("example.com"),
    )
    .await;
    let org = domain_org(&state, &issuer, &claimant, "example.com", "example", true).await;

    let (_, user) = sign_in_as(
        &state,
        &issuer,
        "ws-2",
        "b@example.com",
        Some("example.com"),
    )
    .await;

    assert_eq!(
        memberships(&pool, user).await,
        vec![Membership {
            org,
            slug: "example".to_owned(),
            joined_via: "domain".to_owned(),
        }]
    );
}

/// Auto-join is off unless asked for: a claim that does not mention it leaves
/// the domain's other accounts out — proven by the membership being absent.
#[sqlx::test(migrations = "../../migrations")]
async fn auto_join_is_off_by_default(pool: PgPool) {
    let issuer = start_issuer().await;
    let state = state(&pool, &issuer).await;
    let (claimant, _) = sign_in_as(
        &state,
        &issuer,
        CLAIMANT,
        "admin@example.com",
        Some("example.com"),
    )
    .await;
    let started = claim(
        &state,
        &claimant,
        &serde_json::json!({ "domain": "example.com", "slug": "example" }),
    )
    .await;
    assert_eq!(started.json["auto_join"], false, "{:?}", started.json);
    let verified = verify(&state, &issuer, &claimant, &started).await;
    assert_eq!(verified.status, StatusCode::CREATED, "{:?}", verified.json);
    let org: uuid::Uuid = verified.json["id"]
        .as_str()
        .and_then(|id| id.parse().ok())
        .expect("org id");

    let (_, user) = sign_in_as(
        &state,
        &issuer,
        "ws-3",
        "c@example.com",
        Some("example.com"),
    )
    .await;

    let rows = memberships(&pool, user).await;
    assert!(rows.iter().all(|m| m.org != org), "{rows:?}");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].joined_via, "personal");
}

/// `hd` is trusted and the email's domain ignored, in both directions.
#[sqlx::test(migrations = "../../migrations")]
async fn hd_decides_when_it_differs_from_the_email_domain(pool: PgPool) {
    let issuer = start_issuer().await;
    let state = state(&pool, &issuer).await;
    let (claimant, _) = sign_in_as(
        &state,
        &issuer,
        CLAIMANT,
        "admin@example.com",
        Some("example.com"),
    )
    .await;
    let org = domain_org(&state, &issuer, &claimant, "example.com", "example", true).await;

    // hd is the org's domain, the email is elsewhere: joins.
    let (_, inside) = sign_in_as(
        &state,
        &issuer,
        "ws-4",
        "d@alias.example.net",
        Some("example.com"),
    )
    .await;
    assert!(
        memberships(&pool, inside)
            .await
            .iter()
            .any(|m| m.org == org)
    );

    // The email is at the org's domain, hd is elsewhere: does not.
    let (_, outside) =
        sign_in_as(&state, &issuer, "ws-5", "e@example.com", Some("other.test")).await;
    assert!(
        memberships(&pool, outside)
            .await
            .iter()
            .all(|m| m.org != org)
    );
}

/// Someone who signed in before the domain was claimed joins on their next
/// sign-in, and keeps their personal org.
#[sqlx::test(migrations = "../../migrations")]
async fn an_earlier_user_joins_on_next_sign_in_and_keeps_their_personal_org(pool: PgPool) {
    let issuer = start_issuer().await;
    let state = state(&pool, &issuer).await;
    let (_, early) = sign_in_as(
        &state,
        &issuer,
        "ws-6",
        "f@example.com",
        Some("example.com"),
    )
    .await;
    let personal = memberships(&pool, early).await;
    assert_eq!(personal.len(), 1);

    let (claimant, _) = sign_in_as(
        &state,
        &issuer,
        CLAIMANT,
        "admin@example.com",
        Some("example.com"),
    )
    .await;
    let org = domain_org(&state, &issuer, &claimant, "example.com", "example", true).await;

    sign_in_as(
        &state,
        &issuer,
        "ws-6",
        "f@example.com",
        Some("example.com"),
    )
    .await;
    let rows = memberships(&pool, early).await;
    assert_eq!(rows.len(), 2, "{rows:?}");
    assert!(rows.contains(&personal[0]));
    assert!(
        rows.iter()
            .any(|m| m.org == org && m.joined_via == "domain")
    );
}

/// Every event the sign-in path emitted, by name, with its fields.
#[derive(Clone, Default)]
struct Events(Arc<Mutex<Vec<Event>>>);

/// An event's name and its fields, rendered.
type Event = (String, HashMap<String, String>);

struct Fields(HashMap<String, String>);

impl tracing::field::Visit for Fields {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        self.0.insert(
            field.name().to_owned(),
            format!("{value:?}").trim_matches('"').to_owned(),
        );
    }
}

impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for Events {
    fn on_event(&self, event: &tracing::Event<'_>, _: tracing_subscriber::layer::Context<'_, S>) {
        let mut fields = Fields(HashMap::new());
        event.record(&mut fields);
        if let Ok(mut events) = self.0.lock() {
            events.push((event.metadata().name().to_owned(), fields.0));
        }
    }
}

/// An account that left the domain's tenant loses its domain membership on its
/// next sign-in — a hard delete, recorded as the audit event — while its
/// personal org, which did not come through the domain, survives.
#[sqlx::test(migrations = "../../migrations")]
async fn sync_removes_only_domain_memberships_and_records_each(pool: PgPool) {
    use tracing_subscriber::layer::SubscriberExt as _;

    let issuer = start_issuer().await;
    let state = state(&pool, &issuer).await;
    let (_, user) = sign_in_as(
        &state,
        &issuer,
        "ws-7",
        "g@example.com",
        Some("example.com"),
    )
    .await;
    let (claimant, _) = sign_in_as(
        &state,
        &issuer,
        CLAIMANT,
        "admin@example.com",
        Some("example.com"),
    )
    .await;
    let org = domain_org(&state, &issuer, &claimant, "example.com", "example", true).await;
    sign_in_as(
        &state,
        &issuer,
        "ws-7",
        "g@example.com",
        Some("example.com"),
    )
    .await;
    let before = memberships(&pool, user).await;
    assert_eq!(before.len(), 2, "{before:?}");

    let events = Events::default();
    let _guard =
        tracing::subscriber::set_default(tracing_subscriber::registry().with(events.clone()));
    // The account is now outside the tenant: same Google subject, no `hd`.
    sign_in_as(&state, &issuer, "ws-7", "g@example.com", None).await;

    let after = memberships(&pool, user).await;
    assert_eq!(after.len(), 1, "{after:?}");
    assert_eq!(after[0].joined_via, "personal", "the personal org survives");
    let rows: i64 = sqlx::query_scalar!(
        r#"select count(*) as "n!" from org_members where org_id = $1 and user_id = $2"#,
        org,
        user
    )
    .fetch_one(&pool)
    .await
    .expect("count");
    assert_eq!(rows, 0, "removal is a hard delete");

    let events = events.0.lock().expect("lock");
    let removed: Vec<_> = events
        .iter()
        .filter(|(name, _)| name == control_plane::orgs::MEMBERSHIP_REMOVED)
        .collect();
    assert_eq!(removed.len(), 1, "{events:?}");
    let fields = &removed[0].1;
    assert_eq!(fields["org_id"], org.to_string());
    assert_eq!(fields["user_id"], user.to_string());
    assert_eq!(fields["reason"], "hd_mismatch");
    assert_eq!(fields["actor"], "system");
}

/// Two first sign-ins create one personal org, not two.
#[sqlx::test(migrations = "../../migrations")]
async fn signing_in_again_creates_no_second_personal_org(pool: PgPool) {
    let issuer = start_issuer().await;
    let state = state(&pool, &issuer).await;
    let (_, user) = sign_in_as(&state, &issuer, "consumer-c", "c@gmail.com", None).await;
    sign_in_as(&state, &issuer, "consumer-c", "c@gmail.com", None).await;
    assert_eq!(memberships(&pool, user).await.len(), 1);
}

// ----------------------------------------------------------- domain claims ----

async fn claim_rows(pool: &PgPool) -> i64 {
    sqlx::query_scalar!(r#"select count(*) as "n!" from domain_claims"#)
        .fetch_one(pool)
        .await
        .expect("count")
}

/// Reserved, taken and personal-shaped slugs are refused with a message that
/// says why, and nothing is written.
#[sqlx::test(migrations = "../../migrations")]
async fn reserved_taken_and_personal_slugs_are_refused_legibly(pool: PgPool) {
    let issuer = start_issuer().await;
    let state = state(&pool, &issuer).await;
    control_plane::db::create_org(&pool, "taken")
        .await
        .expect("org");
    let (cookie, _) = sign_in_as(
        &state,
        &issuer,
        CLAIMANT,
        "admin@example.com",
        Some("example.com"),
    )
    .await;

    for (slug, status, code, says) in [
        (
            "admin",
            StatusCode::BAD_REQUEST,
            "control-plane.invalid_request",
            "reserved",
        ),
        (
            "taken",
            StatusCode::CONFLICT,
            "control-plane.conflict",
            "taken",
        ),
        (
            "p-abc",
            StatusCode::BAD_REQUEST,
            "control-plane.invalid_request",
            "personal",
        ),
        (
            "Not A Slug",
            StatusCode::BAD_REQUEST,
            "control-plane.invalid_request",
            "slug",
        ),
    ] {
        let reply = claim(
            &state,
            &cookie,
            &serde_json::json!({ "domain": "example.com", "slug": slug }),
        )
        .await;
        assert_eq!(reply.status, status, "{slug}: {:?}", reply.json);
        assert_eq!(reply.code(), code, "{slug}");
        assert!(
            reply.json["message"]
                .as_str()
                .is_some_and(|m| m.contains(says)),
            "{slug}: {:?}",
            reply.json
        );
    }
    assert_eq!(claim_rows(&pool).await, 0);
}

/// A slug taken between claim and verification is refused at verification,
/// and nothing is bound.
#[sqlx::test(migrations = "../../migrations")]
async fn a_slug_taken_before_verification_is_refused_then(pool: PgPool) {
    let issuer = start_issuer().await;
    let state = state(&pool, &issuer).await;
    let (cookie, _) = sign_in_as(
        &state,
        &issuer,
        CLAIMANT,
        "admin@example.com",
        Some("example.com"),
    )
    .await;
    let started = claim(
        &state,
        &cookie,
        &serde_json::json!({ "domain": "example.com", "slug": "example" }),
    )
    .await;
    control_plane::db::create_org(&pool, "example")
        .await
        .expect("org");
    let reply = verify(&state, &issuer, &cookie, &started).await;
    assert_eq!(reply.status, StatusCode::CONFLICT, "{:?}", reply.json);
    let bound: i64 = sqlx::query_scalar!(r#"select count(*) as "n!" from org_domains"#)
        .fetch_one(&pool)
        .await
        .expect("count");
    assert_eq!(bound, 0);
}

/// `hd` is what lets a person *start* a claim, and only for their own domain.
#[sqlx::test(migrations = "../../migrations")]
async fn a_claim_needs_the_claimants_own_hosted_domain(pool: PgPool) {
    let issuer = start_issuer().await;
    let state = state(&pool, &issuer).await;
    let (consumer, _) = sign_in_as(&state, &issuer, "consumer-d", "d@example.com", None).await;
    let (other, _) = sign_in_as(&state, &issuer, "ws-8", "h@other.test", Some("other.test")).await;

    for cookie in [&consumer, &other] {
        let reply = claim(
            &state,
            cookie,
            &serde_json::json!({ "domain": "example.com", "slug": "example" }),
        )
        .await;
        assert_eq!(reply.status, StatusCode::FORBIDDEN, "{:?}", reply.json);
        assert_eq!(reply.code(), "identity.forbidden");
    }
    assert_eq!(claim_rows(&pool).await, 0);
}

/// Spelling does not make a second verified domain: `Example.COM.` is
/// `example.com`, and once that is verified a second claim of it is refused.
#[sqlx::test(migrations = "../../migrations")]
async fn domain_spellings_normalise_to_one_verified_domain(pool: PgPool) {
    let issuer = start_issuer().await;
    let state = state(&pool, &issuer).await;
    // Google's `hd` in a different case is the same domain too.
    let (first, _) = sign_in_as(
        &state,
        &issuer,
        CLAIMANT,
        "admin@example.com",
        Some("EXAMPLE.com"),
    )
    .await;
    let started = claim(
        &state,
        &first,
        &serde_json::json!({ "domain": "Example.COM.", "slug": "example" }),
    )
    .await;
    assert_eq!(started.status, StatusCode::CREATED, "{:?}", started.json);
    assert_eq!(started.json["domain"], "example.com");
    assert_eq!(started.json["txt_name"], "_clwd-verify.example.com");
    assert_eq!(
        verify(&state, &issuer, &first, &started).await.status,
        StatusCode::CREATED
    );

    let (second, _) = sign_in_as(
        &state,
        &issuer,
        "ws-9",
        "i@example.com",
        Some("example.com."),
    )
    .await;
    let again = claim(
        &state,
        &second,
        &serde_json::json!({ "domain": "example.com", "slug": "example-two" }),
    )
    .await;
    assert_eq!(again.status, StatusCode::CONFLICT, "{:?}", again.json);
    let stored: Vec<String> = sqlx::query_scalar!("select domain from org_domains")
        .fetch_all(&pool)
        .await
        .expect("domains");
    assert_eq!(stored, vec!["example.com".to_owned()]);
}

/// Without the TXT record there is no org. With it, verification creates the
/// org, the claimant's membership, and a `pending` certificate row — and calls
/// no certificate authority, so none can fail it.
#[sqlx::test(migrations = "../../migrations")]
async fn verification_needs_the_txt_record_and_queues_the_certificate(pool: PgPool) {
    let issuer = start_issuer().await;
    let state = state(&pool, &issuer).await;
    let (cookie, claimant) = sign_in_as(
        &state,
        &issuer,
        CLAIMANT,
        "admin@example.com",
        Some("example.com"),
    )
    .await;
    let started = claim(
        &state,
        &cookie,
        &serde_json::json!({ "domain": "example.com", "slug": "example" }),
    )
    .await;
    let id = started.json["id"].as_str().expect("id");

    issuer
        .dns
        .publish("_clwd-verify.example.com", "a-different-value");
    let early = send(
        &state,
        "POST",
        &format!("/v1/domain-claims/{id}/verify"),
        Some(&cookie),
    )
    .await;
    assert_eq!(early.status, StatusCode::BAD_REQUEST, "{:?}", early.json);
    assert!(
        control_plane::db::org_by_slug(&pool, "example")
            .await
            .expect("read")
            .is_none()
    );

    let reply = verify(&state, &issuer, &cookie, &started).await;
    assert_eq!(reply.status, StatusCode::CREATED, "{:?}", reply.json);
    assert_eq!(reply.json["certificate"]["status"], "pending");
    let org: uuid::Uuid = reply.json["id"]
        .as_str()
        .and_then(|i| i.parse().ok())
        .expect("id");
    assert!(
        memberships(&pool, claimant)
            .await
            .iter()
            .any(|m| m.org == org && m.joined_via == "claimant")
    );
    let cert = sqlx::query_scalar!("select state from certificates where org_id = $1", org)
        .fetch_one(&pool)
        .await
        .expect("a certificate row");
    assert_eq!(cert, "pending");
    assert_eq!(claim_rows(&pool).await, 0, "a verified claim is consumed");
}

/// An expired claim cannot be verified and holds nothing back: another
/// claimant from the tenant verifies the domain.
#[sqlx::test(migrations = "../../migrations")]
async fn an_expired_claim_is_inert(pool: PgPool) {
    let issuer = start_issuer().await;
    let state = state(&pool, &issuer).await;
    let (first, _) = sign_in_as(
        &state,
        &issuer,
        CLAIMANT,
        "admin@example.com",
        Some("example.com"),
    )
    .await;
    let stale = claim(
        &state,
        &first,
        &serde_json::json!({ "domain": "example.com", "slug": "example" }),
    )
    .await;
    sqlx::query!("update domain_claims set expires_at = now() - interval '1 second'")
        .execute(&pool)
        .await
        .expect("expire");
    let reply = verify(&state, &issuer, &first, &stale).await;
    assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{:?}", reply.json);
    assert!(
        reply.json["message"]
            .as_str()
            .is_some_and(|m| m.contains("expired"))
    );

    let (second, _) = sign_in_as(
        &state,
        &issuer,
        "ws-10",
        "j@example.com",
        Some("example.com"),
    )
    .await;
    domain_org(&state, &issuer, &second, "example.com", "example", false).await;
}

/// Someone else's claim is not found, not forbidden: its existence is not
/// confirmed.
#[sqlx::test(migrations = "../../migrations")]
async fn another_users_claim_cannot_be_verified(pool: PgPool) {
    let issuer = start_issuer().await;
    let state = state(&pool, &issuer).await;
    let (owner, _) = sign_in_as(
        &state,
        &issuer,
        CLAIMANT,
        "admin@example.com",
        Some("example.com"),
    )
    .await;
    let started = claim(
        &state,
        &owner,
        &serde_json::json!({ "domain": "example.com", "slug": "example" }),
    )
    .await;
    let (thief, _) = sign_in_as(
        &state,
        &issuer,
        "ws-11",
        "k@example.com",
        Some("example.com"),
    )
    .await;
    let reply = verify(&state, &issuer, &thief, &started).await;
    assert_eq!(reply.status, StatusCode::NOT_FOUND, "{:?}", reply.json);
    assert!(
        control_plane::db::org_by_slug(&pool, "example")
            .await
            .expect("read")
            .is_none()
    );
}

/// Until roles exist only the claimant may change auto-join: a member who is
/// not the claimant is refused and the flag is unchanged in the database.
#[sqlx::test(migrations = "../../migrations")]
async fn only_the_claimant_can_change_auto_join(pool: PgPool) {
    let issuer = start_issuer().await;
    let state = state(&pool, &issuer).await;
    let (claimant, _) = sign_in_as(
        &state,
        &issuer,
        CLAIMANT,
        "admin@example.com",
        Some("example.com"),
    )
    .await;
    let org = domain_org(&state, &issuer, &claimant, "example.com", "example", true).await;
    let (member, member_id) = sign_in_as(
        &state,
        &issuer,
        "ws-12",
        "l@example.com",
        Some("example.com"),
    )
    .await;
    assert!(
        memberships(&pool, member_id)
            .await
            .iter()
            .any(|m| m.org == org)
    );

    let flag = || async {
        sqlx::query_scalar!("select auto_join from org_domains where domain = 'example.com'")
            .fetch_one(&pool)
            .await
            .expect("flag")
    };
    let body = serde_json::json!({ "domain": "example.com", "auto_join": false }).to_string();
    let uri = format!("/v1/orgs/{org}/domains");

    let refused = send_with(&state, "PATCH", &uri, Some(&member), &SAME_ORIGIN, &body).await;
    assert_eq!(refused.status, StatusCode::FORBIDDEN, "{:?}", refused.json);
    assert_eq!(refused.code(), "identity.forbidden");
    assert!(flag().await, "the flag is unchanged");

    let changed = send_with(&state, "PATCH", &uri, Some(&claimant), &SAME_ORIGIN, &body).await;
    assert_eq!(changed.status, StatusCode::OK, "{:?}", changed.json);
    assert!(!flag().await);
}

// ------------------------------------------------------- same-origin (CSRF) ----

/// A cookie-authenticated state change from anywhere but the control plane's
/// own origin is refused — including from an app under the apex, which is the
/// same *site*, so `SameSite=Lax` sends the cookie. Each case asserts that
/// nothing was written, not just the status.
#[sqlx::test(migrations = "../../migrations")]
async fn cross_origin_state_changes_are_refused(pool: PgPool) {
    let issuer = start_issuer().await;
    let state = state(&pool, &issuer).await;
    let (cookie, _) = sign_in_as(
        &state,
        &issuer,
        CLAIMANT,
        "admin@example.com",
        Some("example.com"),
    )
    .await;
    let body = serde_json::json!({ "domain": "example.com", "slug": "example" }).to_string();

    for headers in [
        &[("sec-fetch-site", "same-site")][..],
        &[("sec-fetch-site", "cross-site"), ("origin", ORIGIN)][..],
        &[("origin", "https://evil.acme.clwd.run")][..],
        &[("origin", "null")][..],
        &[][..],
    ] {
        let reply = send_with(
            &state,
            "POST",
            "/v1/domain-claims",
            Some(&cookie),
            headers,
            &body,
        )
        .await;
        assert_eq!(
            reply.status,
            StatusCode::FORBIDDEN,
            "{headers:?}: {:?}",
            reply.json
        );
        assert_eq!(reply.code(), "identity.forbidden", "{headers:?}");
        assert_eq!(claim_rows(&pool).await, 0, "{headers:?} wrote a claim");
    }

    // Logout is cookie-authenticated and state-changing too.
    let reply = send_with(
        &state,
        "POST",
        "/auth/logout",
        Some(&cookie),
        &[("sec-fetch-site", "same-site")],
        "",
    )
    .await;
    assert_eq!(reply.status, StatusCode::FORBIDDEN);
    assert_eq!(
        verdict(&pool, &cookie).await,
        Ok(()),
        "the session survives"
    );

    // The control plane's own origin, by either header, is accepted.
    for headers in [&[("origin", ORIGIN)][..], &SAME_ORIGIN[..]] {
        sqlx::query!("delete from domain_claims")
            .execute(&pool)
            .await
            .expect("reset");
        let reply = send_with(
            &state,
            "POST",
            "/v1/domain-claims",
            Some(&cookie),
            headers,
            &body,
        )
        .await;
        assert_eq!(
            reply.status,
            StatusCode::CREATED,
            "{headers:?}: {:?}",
            reply.json
        );
    }
}

/// The claimant's membership came through the domain too: signing in from
/// outside the tenant removes it, and with it the right to change auto-join.
#[sqlx::test(migrations = "../../migrations")]
async fn a_claimant_who_leaves_the_tenant_loses_the_org(pool: PgPool) {
    let issuer = start_issuer().await;
    let state = state(&pool, &issuer).await;
    let (cookie, claimant) = sign_in_as(
        &state,
        &issuer,
        CLAIMANT,
        "admin@example.com",
        Some("example.com"),
    )
    .await;
    let org = domain_org(&state, &issuer, &cookie, "example.com", "example", true).await;

    let (cookie, _) = sign_in_as(&state, &issuer, CLAIMANT, "admin@example.com", None).await;
    assert!(
        memberships(&pool, claimant)
            .await
            .iter()
            .all(|m| m.org != org)
    );
    let body = serde_json::json!({ "domain": "example.com", "auto_join": false }).to_string();
    let reply = send_with(
        &state,
        "PATCH",
        &format!("/v1/orgs/{org}/domains"),
        Some(&cookie),
        &SAME_ORIGIN,
        &body,
    )
    .await;
    assert_eq!(reply.status, StatusCode::NOT_FOUND, "{:?}", reply.json);
}
