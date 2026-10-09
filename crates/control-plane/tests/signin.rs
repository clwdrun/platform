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
                hd: Some("example.com".to_owned()),
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
    Issuer { mock, server }
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
    AppState::new(pool.clone(), builder::ArtifactStore::new(operator)).with_signin(signin)
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

async fn send(state: &AppState, method: &str, uri: &str, cookie: Option<&str>) -> Reply {
    let mut request = Request::builder().method(method).uri(uri);
    if let Some(cookie) = cookie {
        request = request.header(header::COOKIE, cookie);
    }
    let response = control_plane::http::router(state.clone())
        .oneshot(request.body(Body::empty()).expect("a valid request"))
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
