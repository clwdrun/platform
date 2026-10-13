//! Creating an app (#108), against a real Postgres, through the real router.
//!
//! Both callers — a browser session and an API token — and every refusal, with
//! the envelope a caller actually receives. The host-label guarantees are held
//! to the database itself: an `UPDATE` run by hand is refused the same as one
//! from the application, which is the point of putting them in a trigger.

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

fn key() -> CookieKey {
    CookieKey::from_secret(b"a-test-signing-secret-of-some-length")
        .expect("a long enough test secret")
}

fn state(pool: &PgPool) -> AppState {
    let operator =
        opendal::Operator::new(opendal::services::Memory::default()).expect("in-memory operator");
    // Never discovered: the cookie path needs only the key and the origin
    // the redirect URI names.
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
        .with_apps_domain(shared::domains::AppsDomain::parse(APPS).expect("apps domain"))
}

/// How a request authenticates.
enum As<'a> {
    Token(&'a str),
    /// A session cookie, from the control plane's own pages.
    Session(&'a str),
    /// A session cookie, from another page on the same site.
    SameSite(&'a str),
}

struct Reply {
    status: StatusCode,
    body: String,
}

impl Reply {
    fn json(&self) -> serde_json::Value {
        serde_json::from_str(&self.body).expect("a JSON body")
    }
}

async fn create(state: &AppState, org: OrgId, who: As<'_>, body: &str) -> Reply {
    let mut request = Request::builder()
        .method("POST")
        .uri(format!("/v1/orgs/{org}/apps"))
        .header("x-request-id", REQUEST_ID)
        .header(header::CONTENT_TYPE, "application/json");
    request = match who {
        As::Token(token) => request.header(header::AUTHORIZATION, format!("Bearer {token}")),
        As::Session(cookie) => request
            .header(header::COOKIE, cookie)
            .header("sec-fetch-site", "same-origin"),
        As::SameSite(cookie) => request
            .header(header::COOKIE, cookie)
            .header("sec-fetch-site", "same-site"),
    };
    let response = control_plane::http::router(state.clone())
        .oneshot(
            request
                .body(Body::from(body.to_owned()))
                .expect("a valid request"),
        )
        .await
        .expect("the router answers");
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .expect("body");
    Reply {
        status,
        body: String::from_utf8(bytes.to_vec()).expect("utf-8"),
    }
}

async fn org(pool: &PgPool, slug: &str) -> OrgId {
    db::create_org(pool, slug).await.expect("org").id
}

/// A signed-in member of `org`, and the cookie their browser sends.
async fn member(pool: &PgPool, org: OrgId, email: &str) -> (UserId, String) {
    let user = db::create_user(pool, email).await.expect("user");
    db::add_org_member(pool, org, user.id, JoinedVia::Domain)
        .await
        .expect("membership");
    (user.id, cookie(pool, user.id).await)
}

async fn cookie(pool: &PgPool, user: UserId) -> String {
    let issued = session::issue(pool, &key(), user)
        .await
        .expect("issue")
        .expect("a live user gets a session");
    issued
        .set_cookie
        .split(';')
        .next()
        .expect("name=value")
        .to_owned()
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

/// The envelope for `code`, as a caller receives it, byte for byte.
fn envelope(code: &str, message: &str, hint: &str) -> String {
    format!(
        r#"{{"code":"{code}","message":"{message}","hint":"{hint}","retryable":false,"request_id":"{REQUEST_ID}"}}"#
    )
}

const NOT_FOUND_HINT: &str = "check the identifier, and that the token's org, and its app if it is bound to one, cover this resource";
const FORBIDDEN_HINT: &str = "act on what the message names: a token with that scope, the permitted user, or a request from the control plane's own pages";
const INVALID_HINT: &str = "check the request against the OpenAPI schema at /openapi.json";
const CONFLICT_HINT: &str = "re-read the resource and retry with the current state";

// ------------------------------------------------------------- creating ----

#[sqlx::test(migrations = "../../migrations")]
async fn a_member_creates_an_app_and_a_retry_returns_the_same_one(pool: PgPool) {
    let acme = org(&pool, "acme").await;
    let (_, cookie) = member(&pool, acme, "a@acme.test").await;
    let state = state(&pool);

    let first = create(
        &state,
        acme,
        As::Session(&cookie),
        r#"{"host_label":"notes"}"#,
    )
    .await;
    assert_eq!(first.status, StatusCode::CREATED, "{}", first.body);
    let app = first.json();
    assert_eq!(app["created"], true);
    assert_eq!(app["host_label"], "notes");
    assert_eq!(app["name"], "notes");
    assert_eq!(app["org_id"], acme.to_string());
    assert_eq!(app["url"], "https://notes.acme.clwd-apps.test");

    let again = create(
        &state,
        acme,
        As::Session(&cookie),
        r#"{"host_label":"notes"}"#,
    )
    .await;
    assert_eq!(again.status, StatusCode::OK, "{}", again.body);
    let existing = again.json();
    assert_eq!(existing["created"], false);
    assert_eq!(
        existing["id"], app["id"],
        "a retry returns the app it created"
    );
}

/// The agent's path: a token, no cookie, no origin header.
#[sqlx::test(migrations = "../../migrations")]
async fn a_write_token_of_the_org_creates_an_app(pool: PgPool) {
    let acme = org(&pool, "acme").await;
    let token = token(&pool, acme, None, &["write", "publish"]).await;

    let reply = create(
        &state(&pool),
        acme,
        As::Token(&token),
        r#"{"host_label":"notes"}"#,
    )
    .await;
    assert_eq!(reply.status, StatusCode::CREATED, "{}", reply.body);
    assert_eq!(reply.json()["url"], "https://notes.acme.clwd-apps.test");
}

// ------------------------------------------------------------- refusing ----

/// Another org is indistinguishable from one that does not exist, for both
/// kinds of caller.
#[sqlx::test(migrations = "../../migrations")]
async fn another_orgs_caller_gets_the_same_404_as_no_org(pool: PgPool) {
    let acme = org(&pool, "acme").await;
    let globex = org(&pool, "globex").await;
    let (_, outsider) = member(&pool, globex, "g@globex.test").await;
    let globex_token = token(&pool, globex, None, &["write"]).await;
    let state = state(&pool);
    let want = envelope(
        "control-plane.not_found",
        &format!("not found: org {acme}"),
        NOT_FOUND_HINT,
    );

    for who in [As::Session(&outsider), As::Token(&globex_token)] {
        let reply = create(&state, acme, who, r#"{"host_label":"notes"}"#).await;
        assert_eq!(reply.status, StatusCode::NOT_FOUND);
        assert_eq!(reply.body, want);
    }
    let nowhere = OrgId::new();
    let reply = create(
        &state,
        nowhere,
        As::Token(&globex_token),
        r#"{"host_label":"notes"}"#,
    )
    .await;
    assert_eq!(reply.status, StatusCode::NOT_FOUND);
    assert_eq!(
        reply.body,
        envelope(
            "control-plane.not_found",
            &format!("not found: org {nowhere}"),
            NOT_FOUND_HINT
        )
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_token_bound_to_one_app_cannot_create_apps(pool: PgPool) {
    let acme = org(&pool, "acme").await;
    let bound_to = db::create_app(&pool, acme, "first", "wasm")
        .await
        .expect("app")
        .id;
    let bound = token(&pool, acme, Some(bound_to), &["write"]).await;

    let reply = create(
        &state(&pool),
        acme,
        As::Token(&bound),
        r#"{"host_label":"second"}"#,
    )
    .await;
    assert_eq!(reply.status, StatusCode::FORBIDDEN);
    assert_eq!(
        reply.body,
        envelope(
            "identity.forbidden",
            "not permitted: a token bound to one app cannot create apps",
            FORBIDDEN_HINT
        )
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_token_without_write_is_refused(pool: PgPool) {
    let acme = org(&pool, "acme").await;
    let publish_only = token(&pool, acme, None, &["publish"]).await;

    let reply = create(
        &state(&pool),
        acme,
        As::Token(&publish_only),
        r#"{"host_label":"notes"}"#,
    )
    .await;
    assert_eq!(reply.status, StatusCode::FORBIDDEN, "{}", reply.body);
    assert_eq!(reply.json()["code"], "identity.forbidden");
    assert!(
        reply.json()["message"]
            .as_str()
            .unwrap_or("")
            .contains("write"),
        "the refusal names the missing scope: {}",
        reply.body
    );
}

/// A member's cookie sent from an app page on the same site is the forgery the
/// origin check exists for. A token is never subject to it.
#[sqlx::test(migrations = "../../migrations")]
async fn a_cookie_from_another_page_on_the_site_is_refused(pool: PgPool) {
    let acme = org(&pool, "acme").await;
    let (_, cookie) = member(&pool, acme, "a@acme.test").await;

    let reply = create(
        &state(&pool),
        acme,
        As::SameSite(&cookie),
        r#"{"host_label":"notes"}"#,
    )
    .await;
    assert_eq!(reply.status, StatusCode::FORBIDDEN);
    assert_eq!(
        reply.body,
        envelope(
            "identity.forbidden",
            "not permitted: a cross-origin request; this operation must come from the control plane's own pages",
            FORBIDDEN_HINT
        )
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn an_invalid_label_or_runtime_is_a_400_that_says_why(pool: PgPool) {
    let acme = org(&pool, "acme").await;
    let token = token(&pool, acme, None, &["write"]).await;
    let state = state(&pool);

    let reply = create(&state, acme, As::Token(&token), r#"{"host_label":"Notes"}"#).await;
    assert_eq!(reply.status, StatusCode::BAD_REQUEST);
    assert_eq!(
        reply.body,
        envelope(
            "control-plane.invalid_request",
            r#"invalid request: host_label \"Notes\": use 1-63 lowercase letters, digits and hyphens, not starting or ending with a hyphen"#,
            INVALID_HINT
        )
    );

    for bad in ["-notes", "notes-", "", "no_tes", &"a".repeat(64)] {
        let reply = create(
            &state,
            acme,
            As::Token(&token),
            &format!(r#"{{"host_label":"{bad}"}}"#),
        )
        .await;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{bad:?}");
    }

    let reply = create(
        &state,
        acme,
        As::Token(&token),
        r#"{"host_label":"notes","runtime":"microvm"}"#,
    )
    .await;
    assert_eq!(reply.status, StatusCode::BAD_REQUEST);
    assert_eq!(
        reply.body,
        envelope(
            "control-plane.invalid_request",
            r#"invalid request: runtime \"microvm\": only `wasm` is available"#,
            INVALID_HINT
        )
    );
}

// ---------------------------------------------------- the host label ----

/// A deleted app's label is retired with it: never a new app under the URL
/// someone shared for the old one.
#[sqlx::test(migrations = "../../migrations")]
async fn a_deleted_apps_label_cannot_be_created_again(pool: PgPool) {
    let acme = org(&pool, "acme").await;
    let token = token(&pool, acme, None, &["write"]).await;
    let state = state(&pool);

    let first = create(&state, acme, As::Token(&token), r#"{"host_label":"notes"}"#).await;
    let id: uuid::Uuid = first.json()["id"]
        .as_str()
        .expect("id")
        .parse()
        .expect("uuid");
    sqlx::query!("update apps set deleted_at = now() where id = $1", id)
        .execute(&pool)
        .await
        .expect("soft delete");

    let reply = create(&state, acme, As::Token(&token), r#"{"host_label":"notes"}"#).await;
    assert_eq!(reply.status, StatusCode::CONFLICT);
    assert_eq!(
        reply.body,
        envelope(
            "control-plane.conflict",
            r#"conflict: host_label \"notes\" belonged to a deleted app in this org, and labels are never reused; choose another"#,
            CONFLICT_HINT
        )
    );

    // Not even by hand: the unique key has no `deleted_at` condition.
    let err = db::create_app(&pool, acme, "notes", "wasm")
        .await
        .expect_err("a retired label cannot be inserted");
    assert!(err.to_string().contains("unique"), "{err}");
}

/// The database refuses to change a host label, whoever asks.
#[sqlx::test(migrations = "../../migrations")]
async fn the_database_refuses_to_change_a_host_label(pool: PgPool) {
    let acme = org(&pool, "acme").await;
    let app = db::create_app(&pool, acme, "notes", "wasm")
        .await
        .expect("app");

    let err = sqlx::query!(
        "update apps set host_label = 'other' where id = $1",
        app.id.as_uuid()
    )
    .execute(&pool)
    .await
    .expect_err("a host label is immutable");
    assert!(
        err.to_string().contains("app host label is immutable"),
        "{err}"
    );
    let db_code = err
        .as_database_error()
        .and_then(|e| e.code())
        .map(|c| c.to_string());
    assert_eq!(db_code.as_deref(), Some("23001"), "restrict_violation");
}

/// Renaming the display name moves nothing: the URL, the gateway's routing and
/// the label all stay where they were.
#[sqlx::test(migrations = "../../migrations")]
async fn renaming_an_app_never_changes_its_url(pool: PgPool) {
    let acme = org(&pool, "acme").await;
    let token = token(&pool, acme, None, &["write"]).await;
    let state = state(&pool);
    let first = create(&state, acme, As::Token(&token), r#"{"host_label":"notes"}"#).await;
    let id: uuid::Uuid = first.json()["id"]
        .as_str()
        .expect("id")
        .parse()
        .expect("uuid");

    sqlx::query!("update apps set name = 'journal' where id = $1", id)
        .execute(&pool)
        .await
        .expect("a display name can change");

    let again = create(&state, acme, As::Token(&token), r#"{"host_label":"notes"}"#).await;
    let app = again.json();
    assert_eq!(app["name"], "journal");
    assert_eq!(app["host_label"], "notes");
    assert_eq!(app["url"], "https://notes.acme.clwd-apps.test");

    // The gateway's resolve routes by the label, and not by the new name.
    let by_label = db::resolve_live_app(&pool, "acme", "notes")
        .await
        .expect("resolve");
    assert_eq!(by_label.map(|a| a.id.as_uuid()), Some(id));
    let by_name = db::resolve_live_app(&pool, "acme", "journal")
        .await
        .expect("resolve");
    assert!(by_name.is_none(), "a display name must never route");
}
