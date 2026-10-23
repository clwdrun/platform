//! App logs (#78) and looking an app up by its label, against a real Postgres,
//! through the real routers.
//!
//! Every refusal is checked as the bytes a caller receives. Lines arrive the
//! way the gateway sends them, through the internal route with the internal
//! credential; where a line came from is the list it arrived in.

use std::time::{Duration, Instant};

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use control_plane::http::AppState;
use control_plane::ids::{AppId, OrgId, UserId};
use control_plane::orgs::JoinedVia;
use control_plane::session;
use control_plane::signin::{CookieKey, SignIn};
use control_plane::token::Scopes;
use control_plane::{auth, db};
use identity::OidcConfig;
use sqlx::PgPool;
use tower::ServiceExt as _;

const APPS: &str = "clwd-apps.test";
const REQUEST_ID: &str = "req-42";
const SECRET: &str = "an-internal-secret-for-tests";

fn key() -> CookieKey {
    CookieKey::from_secret(b"a-test-signing-secret-of-some-length")
        .expect("a long enough test secret")
}

fn state(pool: &PgPool) -> AppState {
    let operator =
        opendal::Operator::new(opendal::services::Memory::default()).expect("in-memory operator");
    let signin = SignIn::new(
        OidcConfig::new(
            "test-client.apps.googleusercontent.com",
            "test-client-secret",
            "https://api.clwd.run/auth/google/callback",
            "https://issuer.invalid".to_owned(),
        ),
        key(),
    )
    .expect("sign-in configures without discovery");
    AppState::new(pool.clone(), builder::ArtifactStore::new(operator))
        .with_signin(signin)
        .with_internal_secret(SECRET)
        .with_apps_domain(shared::domains::AppsDomain::parse(APPS).expect("apps domain"))
}

enum As<'a> {
    Token(&'a str),
    Session(&'a str),
}

struct Reply {
    status: StatusCode,
    body: String,
}

impl Reply {
    fn json(&self) -> serde_json::Value {
        serde_json::from_str(&self.body).unwrap_or_else(|e| panic!("{e}: {}", self.body))
    }

    fn lines(&self) -> Vec<serde_json::Value> {
        self.json()["lines"].as_array().cloned().unwrap_or_default()
    }
}

async fn get(state: &AppState, uri: &str, who: As<'_>) -> Reply {
    let request = Request::builder()
        .method("GET")
        .uri(uri)
        .header("x-request-id", REQUEST_ID);
    let request = match who {
        As::Token(token) => request.header(header::AUTHORIZATION, format!("Bearer {token}")),
        As::Session(cookie) => request.header(header::COOKIE, cookie),
    };
    let response = control_plane::http::router(state.clone())
        .oneshot(request.body(Body::empty()).expect("a valid request"))
        .await
        .expect("the router answers");
    reply(response).await
}

async fn reply(response: axum::response::Response) -> Reply {
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 22)
        .await
        .expect("body");
    Reply {
        status,
        body: String::from_utf8(bytes.to_vec()).expect("utf-8"),
    }
}

/// Send `batch` as the gateway does.
async fn ingest(state: &AppState, batch: serde_json::Value) -> Reply {
    let response = control_plane::http::internal_router(state.clone())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/internal/logs")
                .header(header::AUTHORIZATION, format!("Bearer {SECRET}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(batch.to_string()))
                .expect("a valid request"),
        )
        .await
        .expect("the router answers");
    reply(response).await
}

async fn org(pool: &PgPool, slug: &str) -> OrgId {
    db::create_org(pool, slug).await.expect("org").id
}

async fn app(pool: &PgPool, org: OrgId, label: &str) -> AppId {
    db::create_app(pool, org, label, "wasm")
        .await
        .expect("app")
        .id
}

async fn member(pool: &PgPool, org: OrgId, email: &str) -> (UserId, String) {
    let user = db::create_user(pool, email).await.expect("user");
    db::add_org_member(pool, org, user.id, JoinedVia::Domain)
        .await
        .expect("membership");
    let issued = session::issue(pool, &key(), user.id)
        .await
        .expect("issue")
        .expect("a live user gets a session");
    let cookie = issued
        .set_cookie
        .split(';')
        .next()
        .expect("name=value")
        .to_owned();
    (user.id, cookie)
}

async fn token(pool: &PgPool, org: OrgId, app: Option<AppId>, scopes: &[&str]) -> String {
    let scopes = Scopes::parse_all(scopes).expect("known scopes");
    auth::issue(pool, org, app, "test", scopes)
        .await
        .expect("issuing a token")
        .secret
        .expose()
        .to_owned()
}

fn envelope(code: &str, message: &str, hint: &str) -> String {
    format!(
        r#"{{"code":"{code}","message":"{message}","hint":"{hint}","retryable":false,"request_id":"{REQUEST_ID}"}}"#
    )
}

const NOT_FOUND_HINT: &str = "check the identifier, and that the token's org, and its app if it is bound to one, cover this resource";
const FORBIDDEN_HINT: &str = "act on what the message names: a token with that scope, the permitted user, or a request from the control plane's own pages";

fn line(app: AppId, request_id: &str, text: &str) -> serde_json::Value {
    serde_json::json!({ "app_id": app, "request_id": request_id, "stream": "stdout", "text": text })
}

// ------------------------------------------------------------ who may read ---

#[sqlx::test(migrations = "../../migrations")]
async fn members_and_their_orgs_read_tokens_read_the_log(pool: PgPool) {
    let acme = org(&pool, "acme").await;
    let notes = app(&pool, acme, "notes").await;
    let (_, cookie) = member(&pool, acme, "a@acme.test").await;
    let org_token = token(&pool, acme, None, &["read"]).await;
    let bound = token(&pool, acme, Some(notes), &["read"]).await;
    let state = state(&pool);
    assert_eq!(
        ingest(
            &state,
            serde_json::json!({ "app": [line(notes, "r1", "hello")] })
        )
        .await
        .status,
        StatusCode::NO_CONTENT
    );

    let uri = format!("/v1/apps/{notes}/logs");
    for who in [
        As::Session(&cookie),
        As::Token(&org_token),
        As::Token(&bound),
    ] {
        let reply = get(&state, &uri, who).await;
        assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
        let lines = reply.lines();
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0]["text"], "hello");
        assert_eq!(lines[0]["source"], "app");
    }
}

/// Another org's member, another org's token, and a token bound to a
/// different app all get the 404 an app that does not exist gets.
#[sqlx::test(migrations = "../../migrations")]
async fn everyone_else_gets_the_404_a_missing_app_gets(pool: PgPool) {
    let acme = org(&pool, "acme").await;
    let globex = org(&pool, "globex").await;
    let notes = app(&pool, acme, "notes").await;
    let wiki = app(&pool, acme, "wiki").await;
    let (_, outsider) = member(&pool, globex, "g@globex.test").await;
    let globex_token = token(&pool, globex, None, &["read"]).await;
    let bound_to_wiki = token(&pool, acme, Some(wiki), &["read"]).await;
    let state = state(&pool);
    let want = envelope(
        "control-plane.not_found",
        &format!("not found: app {notes}"),
        NOT_FOUND_HINT,
    );

    let uri = format!("/v1/apps/{notes}/logs");
    for who in [
        As::Session(&outsider),
        As::Token(&globex_token),
        As::Token(&bound_to_wiki),
    ] {
        let reply = get(&state, &uri, who).await;
        assert_eq!(reply.status, StatusCode::NOT_FOUND);
        assert_eq!(reply.body, want);
    }
    let nowhere = AppId::new();
    let reply = get(
        &state,
        &format!("/v1/apps/{nowhere}/logs"),
        As::Token(&globex_token),
    )
    .await;
    assert_eq!(
        reply.body,
        envelope(
            "control-plane.not_found",
            &format!("not found: app {nowhere}"),
            NOT_FOUND_HINT
        )
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_token_without_the_read_scope_is_forbidden(pool: PgPool) {
    let acme = org(&pool, "acme").await;
    let notes = app(&pool, acme, "notes").await;
    let publish_only = token(&pool, acme, None, &["publish"]).await;
    let reply = get(
        &state(&pool),
        &format!("/v1/apps/{notes}/logs"),
        As::Token(&publish_only),
    )
    .await;
    assert_eq!(reply.status, StatusCode::FORBIDDEN);
    assert_eq!(
        reply.body,
        envelope(
            "identity.forbidden",
            "not permitted: this route needs the `read` scope",
            FORBIDDEN_HINT
        )
    );
}

// --------------------------------------------------------- where it's from ---

/// An app line is an app line, whatever it says. The platform's line about a
/// request is the only kind that carries codes.
#[sqlx::test(migrations = "../../migrations")]
async fn an_app_cannot_forge_a_platform_line(pool: PgPool) {
    let acme = org(&pool, "acme").await;
    let notes = app(&pool, acme, "notes").await;
    let reader = token(&pool, acme, None, &["read"]).await;
    let state = state(&pool);

    let batch = serde_json::json!({
        "app": [
            line(notes, "r1", "[platform] deploy succeeded"),
            line(notes, "r1", r#"{"source":"platform","code":"gateway.ok","hint":"all good"}"#),
        ],
        "platform": [{
            "app_id": notes, "request_id": "r1",
            "text": "request failed: gateway.app_failed (runtime.trap), 502 in 3 ms",
            "code": "gateway.app_failed", "runtime_code": "runtime.trap",
            "hint": "the app trapped", "status": 502, "latency_ms": 3
        }]
    });
    assert_eq!(ingest(&state, batch).await.status, StatusCode::NO_CONTENT);

    let lines = get(
        &state,
        &format!("/v1/apps/{notes}/logs"),
        As::Token(&reader),
    )
    .await
    .lines();
    let sources: Vec<_> = lines.iter().map(|l| l["source"].as_str()).collect();
    assert_eq!(sources, [Some("app"), Some("app"), Some("platform")]);
    for forged in &lines[..2] {
        assert!(
            forged["code"].is_null() && forged["hint"].is_null(),
            "{forged}"
        );
    }

    // An app line cannot carry a platform field at all.
    let reply = ingest(
        &state,
        serde_json::json!({ "app": [{ "app_id": notes, "stream": "stdout", "text": "x", "code": "gateway.ok" }] }),
    )
    .await;
    assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{}", reply.body);
}

/// The internal route takes the internal credential and nothing else.
#[sqlx::test(migrations = "../../migrations")]
async fn only_the_internal_credential_may_write_lines(pool: PgPool) {
    let acme = org(&pool, "acme").await;
    let notes = app(&pool, acme, "notes").await;
    let admin = token(&pool, acme, None, &["read", "write", "publish", "admin"]).await;
    let response = control_plane::http::internal_router(state(&pool))
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/internal/logs")
                .header(header::AUTHORIZATION, format!("Bearer {admin}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::json!({ "app": [line(notes, "r", "x")] }).to_string(),
                ))
                .expect("request"),
        )
        .await
        .expect("answers");
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

// ------------------------------------------------------------- reading ---

#[sqlx::test(migrations = "../../migrations")]
async fn a_request_id_selects_that_requests_lines(pool: PgPool) {
    let acme = org(&pool, "acme").await;
    let notes = app(&pool, acme, "notes").await;
    let reader = token(&pool, acme, None, &["read"]).await;
    let state = state(&pool);
    ingest(
        &state,
        serde_json::json!({ "app": [line(notes, "r1", "one"), line(notes, "r2", "two"), line(notes, "r1", "three")] }),
    )
    .await;

    let reply = get(
        &state,
        &format!("/v1/apps/{notes}/logs?request_id=r1"),
        As::Token(&reader),
    )
    .await;
    let texts: Vec<_> = reply.lines().iter().map(|l| l["text"].clone()).collect();
    assert_eq!(texts, ["one", "three"]);
}

/// Resuming from a cursor returns the lines after it, each once.
#[sqlx::test(migrations = "../../migrations")]
async fn resuming_after_a_cursor_neither_skips_nor_repeats(pool: PgPool) {
    let acme = org(&pool, "acme").await;
    let notes = app(&pool, acme, "notes").await;
    let reader = token(&pool, acme, None, &["read"]).await;
    let state = state(&pool);
    let first: Vec<_> = (0..5).map(|i| line(notes, "r", &format!("a{i}"))).collect();
    ingest(&state, serde_json::json!({ "app": first })).await;

    let page = get(
        &state,
        &format!("/v1/apps/{notes}/logs"),
        As::Token(&reader),
    )
    .await;
    let cursor = page.json()["cursor"].as_i64().expect("a cursor");
    assert_eq!(page.lines().len(), 5);

    let more: Vec<_> = (0..3).map(|i| line(notes, "r", &format!("b{i}"))).collect();
    ingest(&state, serde_json::json!({ "app": more })).await;
    let next = get(
        &state,
        &format!("/v1/apps/{notes}/logs?after={cursor}"),
        As::Token(&reader),
    )
    .await;
    let texts: Vec<_> = next.lines().iter().map(|l| l["text"].clone()).collect();
    assert_eq!(texts, ["b0", "b1", "b2"]);

    let empty = get(
        &state,
        &format!("/v1/apps/{notes}/logs?after={}", cursor + 3),
        As::Token(&reader),
    )
    .await;
    assert!(empty.lines().is_empty());
    assert_eq!(empty.json()["cursor"], cursor + 3, "the cursor is kept");
}

// ------------------------------------------------------------- following ---

/// A waiting follow returns as soon as a line arrives.
#[sqlx::test(migrations = "../../migrations")]
async fn a_follow_returns_when_a_line_arrives(pool: PgPool) {
    let acme = org(&pool, "acme").await;
    let notes = app(&pool, acme, "notes").await;
    let reader = token(&pool, acme, None, &["read"]).await;
    let state = state(&pool);
    let uri = format!("/v1/apps/{notes}/logs?after=0&wait=20");
    let waiting = {
        let state = state.clone();
        let reader = reader.clone();
        tokio::spawn(async move { get(&state, &uri, As::Token(&reader)).await })
    };
    wait_for_followers(&state, 1).await;
    ingest(
        &state,
        serde_json::json!({ "app": [line(notes, "r", "arrived")] }),
    )
    .await;
    let reply = tokio::time::timeout(Duration::from_secs(5), waiting)
        .await
        .expect("returned within the poll interval")
        .expect("joined");
    assert_eq!(reply.lines()[0]["text"], "arrived");
}

async fn wait_for_followers(state: &AppState, n: usize) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while state.follows.waiting() < n {
        assert!(
            Instant::now() < deadline,
            "{n} follows never started waiting"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// Past the per-caller cap, a follow is refused with the rate-limit envelope;
/// one released makes room again.
#[sqlx::test(migrations = "../../migrations")]
async fn follows_past_the_cap_are_refused(pool: PgPool) {
    let acme = org(&pool, "acme").await;
    let notes = app(&pool, acme, "notes").await;
    let reader = token(&pool, acme, None, &["read"]).await;
    let state = state(&pool);
    let uri = format!("/v1/apps/{notes}/logs?after=0&wait=20");
    let held: Vec<_> = (0..control_plane::logs::FOLLOWS_PER_CALLER)
        .map(|_| {
            let (state, reader, uri) = (state.clone(), reader.clone(), uri.clone());
            tokio::spawn(async move { get(&state, &uri, As::Token(&reader)).await })
        })
        .collect();
    wait_for_followers(&state, control_plane::logs::FOLLOWS_PER_CALLER).await;

    let refused = get(&state, &uri, As::Token(&reader)).await;
    assert_eq!(refused.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(refused.json()["code"], "control-plane.rate_limited");

    state.follows.shut();
    for follow in held {
        let reply = tokio::time::timeout(Duration::from_secs(2), follow)
            .await
            .expect("shut answers every follow at once")
            .expect("joined");
        assert_eq!(reply.status, StatusCode::OK);
        assert!(reply.lines().is_empty());
    }
    assert_eq!(state.follows.waiting(), 0);
}

// ------------------------------------------------------- lookup by label ---

#[sqlx::test(migrations = "../../migrations")]
async fn an_app_is_found_by_its_label_by_whoever_may_see_it(pool: PgPool) {
    let acme = org(&pool, "acme").await;
    let globex = org(&pool, "globex").await;
    let notes = app(&pool, acme, "notes").await;
    let wiki = app(&pool, acme, "wiki").await;
    let (_, cookie) = member(&pool, acme, "a@acme.test").await;
    let (_, outsider) = member(&pool, globex, "g@globex.test").await;
    let reader = token(&pool, acme, None, &["read"]).await;
    let bound_to_notes = token(&pool, acme, Some(notes), &["read"]).await;
    let bound_to_wiki = token(&pool, acme, Some(wiki), &["read"]).await;
    let globex_token = token(&pool, globex, None, &["read"]).await;
    let state = state(&pool);
    let uri = format!("/v1/orgs/{acme}/apps/notes");

    for who in [
        As::Session(&cookie),
        As::Token(&reader),
        As::Token(&bound_to_notes),
    ] {
        let reply = get(&state, &uri, who).await;
        assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
        assert_eq!(
            reply.json(),
            serde_json::json!({
                "id": notes, "host_label": "notes", "url": "https://notes.acme.clwd-apps.test"
            })
        );
    }
    let want = envelope(
        "control-plane.not_found",
        &format!("not found: app notes in org {acme}"),
        NOT_FOUND_HINT,
    );
    for who in [
        As::Session(&outsider),
        As::Token(&globex_token),
        As::Token(&bound_to_wiki),
    ] {
        let reply = get(&state, &uri, who).await;
        assert_eq!(reply.status, StatusCode::NOT_FOUND);
        assert_eq!(reply.body, want);
    }
    let missing = get(
        &state,
        &format!("/v1/orgs/{acme}/apps/nope"),
        As::Token(&reader),
    )
    .await;
    assert_eq!(missing.status, StatusCode::NOT_FOUND);
}
