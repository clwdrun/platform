//! The internal host-resolution route: mapping `{app}.{org}` to a live app for
//! the gateway, and who is allowed to ask.
//!
//! Coverage is both halves: the query (`db::resolve_live_app`) resolves only live
//! apps, and the route (`GET /internal/orgs/{org}/apps/{app}`) serves only the
//! holder of the platform-internal credential — no customer token, and nothing
//! at all when the credential is unconfigured.

use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode, header};
use control_plane::db;
use control_plane::http::{AppState, internal_router as router};
use sqlx::PgPool;
use tower::ServiceExt as _;

const SECRET: &str = "test-internal-secret";

fn state_with_secret(pool: PgPool) -> AppState {
    let operator =
        opendal::Operator::new(opendal::services::Memory::default()).expect("in-memory operator");
    AppState::new(pool, builder::ArtifactStore::new(operator)).with_internal_secret(SECRET)
}

async fn get(
    state: &AppState,
    uri: &str,
    credential: Option<&str>,
) -> (StatusCode, serde_json::Value) {
    let mut builder = Request::builder().uri(uri);
    if let Some(secret) = credential {
        builder = builder.header(header::AUTHORIZATION, format!("Bearer {secret}"));
    }
    let response = router(state.clone())
        .oneshot(builder.body(Body::empty()).expect("a valid request"))
        .await
        .expect("router responds");
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 64 * 1024)
        .await
        .expect("body reads");
    let json = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, json)
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_query_resolves_only_live_apps(pool: PgPool) {
    let org = db::create_org(&pool, "acme").await.expect("org");
    db::create_app(&pool, org.id, "dashboard", "wasm")
        .await
        .expect("app");

    assert!(
        db::resolve_live_app(&pool, "acme", "dashboard")
            .await
            .expect("query")
            .is_some(),
        "a live app resolves"
    );
    assert!(
        db::resolve_live_app(&pool, "acme", "ghost")
            .await
            .expect("query")
            .is_none(),
        "an unknown app in a known org does not resolve"
    );
    assert!(
        db::resolve_live_app(&pool, "ghost", "dashboard")
            .await
            .expect("query")
            .is_none(),
        "an app under an unknown org does not resolve"
    );
}

/// The version to run is the newest `ready` one: none before a publish
/// completes, and never a `pending` or `failed` one.
#[sqlx::test(migrations = "../../migrations")]
async fn the_digest_is_the_newest_ready_version(pool: PgPool) {
    let org = db::create_org(&pool, "acme").await.expect("org");
    let app = db::create_app(&pool, org.id, "dashboard", "wasm")
        .await
        .expect("app");
    let digest = |n: u8| format!("blake3:{}", format!("{n:02x}").repeat(32));
    let live = || async {
        db::resolve_live_app(&pool, "acme", "dashboard")
            .await
            .expect("query")
            .expect("resolves")
            .digest
    };
    assert_eq!(live().await, None, "nothing published yet");

    for (n, state) in [(1, "ready"), (2, "ready"), (3, "pending"), (4, "failed")] {
        sqlx::query("insert into app_versions (id, app_id, digest, state) values ($1, $2, $3, $4)")
            .bind(uuid::Uuid::now_v7())
            .bind(app.id.as_uuid())
            .bind(digest(n))
            .bind(state)
            .execute(&pool)
            .await
            .expect("version");
    }
    assert_eq!(live().await, Some(digest(2)));
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_route_serves_the_holder_of_the_secret(pool: PgPool) {
    let state = state_with_secret(pool.clone());
    let org = db::create_org(&pool, "acme").await.expect("org");
    db::create_app(&pool, org.id, "dashboard", "wasm")
        .await
        .expect("app");

    let (status, body) = get(&state, "/internal/orgs/acme/apps/dashboard", Some(SECRET)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(
        body["app_id"].is_string(),
        "the resolution carries the app id: {body}"
    );
    assert_eq!(
        body["org_id"].as_str(),
        Some(org.id.to_string().as_str()),
        "and the org id: {body}"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn an_unknown_host_is_a_not_found_envelope(pool: PgPool) {
    let state = state_with_secret(pool.clone());
    db::create_org(&pool, "acme").await.expect("org");

    let (status, body) = get(&state, "/internal/orgs/acme/apps/ghost", Some(SECRET)).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    assert_eq!(body["code"], "control-plane.not_found");
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_wrong_or_missing_credential_is_denied(pool: PgPool) {
    let state = state_with_secret(pool.clone());
    let org = db::create_org(&pool, "acme").await.expect("org");
    db::create_app(&pool, org.id, "dashboard", "wasm")
        .await
        .expect("app");

    // The right host with the wrong secret: unauthenticated, not a resolution.
    let (status, body) = get(&state, "/internal/orgs/acme/apps/dashboard", Some("wrong")).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert_eq!(body["code"], "identity.unauthenticated");

    // The right host with no credential at all: also denied.
    let (status, _) = get(&state, "/internal/orgs/acme/apps/dashboard", None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[sqlx::test(migrations = "../../migrations")]
async fn an_unconfigured_secret_fails_closed(pool: PgPool) {
    // No `with_internal_secret`: an unset internal credential must deny every
    // request, never read as "open". A live app and a plausible secret, so the
    // only thing that can deny is the missing configuration.
    let operator =
        opendal::Operator::new(opendal::services::Memory::default()).expect("in-memory operator");
    let state = AppState::new(pool.clone(), builder::ArtifactStore::new(operator));
    let org = db::create_org(&pool, "acme").await.expect("org");
    db::create_app(&pool, org.id, "dashboard", "wasm")
        .await
        .expect("app");

    let (status, _) = get(&state, "/internal/orgs/acme/apps/dashboard", Some(SECRET)).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "an unconfigured internal secret must fail closed"
    );
}
