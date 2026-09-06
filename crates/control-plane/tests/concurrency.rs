//! Ten concurrent publishes of the same digest produce one row.
//!
//! # Why this file does not use `#[sqlx::test]`
//!
//! Every other database test here does, and this one deliberately does not.
//! `#[sqlx::test]` expands to `sqlx::test_block_on`, which builds a
//! **`new_current_thread`** Tokio runtime — hardcoded in `sqlx-core`, with no
//! flavour argument on the attribute:
//!
//! ```text
//! tokio::runtime::Builder::new_current_thread()
//! ```
//!
//! Ten `tokio::spawn`s on that runtime are cooperative on one thread. They do
//! interleave at await points, so Postgres would still see concurrent
//! connections — but the test would pass identically if they serialised
//! completely, because "exactly one row" holds under full serialisation too.
//! That is a test that proves the index works and nothing about racing.
//!
//! So this file sets up its own database and uses a multi-threaded runtime.
//! **Do not "fix" the inconsistency by moving it back to `#[sqlx::test]`** —
//! the inconsistency is the point, and the reason is above.
//!
//! # What makes it genuinely concurrent
//!
//! A [`Barrier`] released only once all ten tasks have reached it. Without one,
//! `tokio::spawn` ordering lets the first task finish its whole round trip
//! before the last has started, and the contention never happens.

use std::sync::Arc;

use control_plane::db::{self, Claim};
use control_plane::ids::AppId;
use sqlx::AssertSqlSafe;
use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;
use tokio::sync::Barrier;
use uuid::Uuid;

const DIGEST_A: &str = "blake3:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const DIGEST_B: &str = "blake3:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

/// How many publishers race. The acceptance criterion names ten.
const RACERS: usize = 10;

/// A throwaway database with the migrations applied.
///
/// `#[sqlx::test]` normally does this; doing it by hand is the cost of the
/// multi-threaded runtime explained above. The database is named per run so
/// concurrent test binaries do not collide, and dropped on the way out.
struct Scratch {
    admin: PgPool,
    pool: PgPool,
    name: String,
}

impl Scratch {
    async fn new() -> Self {
        let base = std::env::var("DATABASE_URL")
            .expect("DATABASE_URL must be set — this test needs a real database, and skipping it when absent would be a test that passes by not running");
        let name = format!("clwd_concurrency_{}", Uuid::now_v7().simple());

        let (prefix, _) = base
            .rsplit_once('/')
            .expect("DATABASE_URL ends with a database name");
        let admin = PgPoolOptions::new()
            .max_connections(2)
            .connect(&base)
            .await
            .expect("connecting to the configured database");
        // `create database` takes no bind parameters, so the name has to be
        // interpolated. sqlx 0.9 gates that behind `raw_sql` rather than
        // letting it look like an ordinary query. `AssertSqlSafe` is the right
        // shape for a lint: the escape hatch exists, and it is named after the
        // claim you are making rather than after suppressing the warning.
        //
        // Safe here because `name` is `clwd_concurrency_` plus a UUIDv7 in
        // simple form — hex digits only, no operator input, no quote to break
        // out of. It is not safe as a pattern; anything reaching this from a
        // request needs a different design, not this comment.
        let create = format!(r#"create database "{name}""#);
        sqlx::raw_sql(AssertSqlSafe(create))
            .execute(&admin)
            .await
            .expect("creating the scratch database");

        let pool = PgPoolOptions::new()
            // Every racer needs its own connection, or the pool serialises them
            // and the race this test exists for cannot happen.
            .max_connections(RACERS as u32 + 2)
            .connect(&format!("{prefix}/{name}"))
            .await
            .expect("connecting to the scratch database");
        sqlx::migrate!("../../migrations")
            .run(&pool)
            .await
            .expect("running migrations");

        Self { admin, pool, name }
    }

    async fn drop_it(self) {
        let Self { admin, pool, name } = self;
        pool.close().await;
        // Same reasoning as the create above.
        let drop = format!(r#"drop database if exists "{name}" with (force)"#);
        let _ = sqlx::raw_sql(AssertSqlSafe(drop)).execute(&admin).await;
        admin.close().await;
    }
}

/// Publishes `digest` to `app`, resolving the ambiguous empty result the way
/// the route does.
async fn publish(pool: &PgPool, app: AppId, digest: &'static str) -> Claim {
    match db::claim_app_version(pool, app, digest)
        .await
        .expect("the claim query runs")
    {
        Some(row) => Claim::Won(row),
        None => Claim::Held(
            db::app_version_by_digest(pool, app, digest)
                .await
                .expect("the disambiguating read runs")
                .expect("a conflict means a row exists"),
        ),
    }
}

async fn an_app(pool: &PgPool) -> AppId {
    let org = db::create_org(pool, "acme").await.expect("org");
    db::create_app(pool, org.id, "one", "wasm")
        .await
        .expect("app")
        .id
}

/// A real bundle, built the way `clwd build` builds one.
fn a_bundle(body: &[u8]) -> bytes::Bytes {
    const PREAMBLE: [u8; 8] = [0x00, 0x61, 0x73, 0x6d, 0x0d, 0x00, 0x01, 0x00];
    let mut data = PREAMBLE.to_vec();
    data.extend_from_slice(body);
    let encoded = clwd_bundle::build(
        clwd_bundle::Runtime::Wasm,
        "app.wasm",
        clwd_bundle::Capabilities {
            version: 1,
            egress: vec![],
            secrets: vec![],
            storage_namespaces: vec![],
            limits: clwd_bundle::Limits {
                cpu_ms: 1_000,
                memory_mb: 64,
            },
        },
        vec![clwd_bundle::File {
            path: "app.wasm".into(),
            data,
            executable: false,
        }],
    )
    .expect("a well-formed bundle encodes");
    bytes::Bytes::from(encoded.bytes)
}

fn state_for(pool: &PgPool) -> control_plane::http::AppState {
    let operator =
        opendal::Operator::new(opendal::services::Memory::default()).expect("in-memory operator");
    control_plane::http::AppState::new(pool.clone(), builder::ArtifactStore::new(operator))
}

async fn post_bundle(
    state: &control_plane::http::AppState,
    app: AppId,
    body: bytes::Bytes,
) -> (axum::http::StatusCode, serde_json::Value) {
    use tower::ServiceExt;
    let request = axum::http::Request::builder()
        .method("POST")
        .uri(format!("/v1/apps/{app}/versions"))
        .body(axum::body::Body::from(body))
        .expect("valid request");
    let response = control_plane::http::router(state.clone())
        .oneshot(request)
        .await
        .expect("router responds");
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .expect("body");
    let json = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, json)
}

/// The route end to end: a real bundle, a real database, a real store.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn publishing_twice_reports_created_then_already_existed() {
    let scratch = Scratch::new().await;
    let app = an_app(&scratch.pool).await;
    let state = state_for(&scratch.pool);
    let bundle = a_bundle(b"body");

    let (first, body) = post_bundle(&state, app, bundle.clone()).await;
    assert_eq!(first, axum::http::StatusCode::CREATED, "body: {body}");
    assert_eq!(body["state"], "ready");

    let (second, body2) = post_bundle(&state, app, bundle).await;
    assert_eq!(
        second,
        axum::http::StatusCode::OK,
        "a retry is not a conflict"
    );
    assert_eq!(
        body2["id"], body["id"],
        "a retry must return the version it found, not a new one"
    );

    scratch.drop_it().await;
}

/// The other half of the ambiguous empty result. A conflict is 200; an app
/// that is absent or deleted is 404. Both returning 200 would be a publish
/// that succeeded into nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn publishing_to_a_deleted_app_is_404_not_200() {
    let scratch = Scratch::new().await;
    let app = an_app(&scratch.pool).await;
    let state = state_for(&scratch.pool);

    sqlx::query!(
        "update apps set deleted_at = now() where id = $1",
        app.as_uuid()
    )
    .execute(&scratch.pool)
    .await
    .expect("soft delete");

    let (status, body) = post_bundle(&state, app, a_bundle(b"body")).await;
    assert_eq!(status, axum::http::StatusCode::NOT_FOUND);
    assert_eq!(body["code"], "control-plane.not_found");

    scratch.drop_it().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn publishing_to_an_unknown_app_is_404() {
    let scratch = Scratch::new().await;
    let state = state_for(&scratch.pool);
    let (status, body) = post_bundle(&state, AppId::new(), a_bundle(b"body")).await;
    assert_eq!(status, axum::http::StatusCode::NOT_FOUND);
    assert_eq!(body["code"], "control-plane.not_found");
    scratch.drop_it().await;
}

/// An invalid bundle is rejected before the claim, so it leaves no row.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_invalid_bundle_produces_no_row() {
    let scratch = Scratch::new().await;
    let app = an_app(&scratch.pool).await;
    let state = state_for(&scratch.pool);

    let (status, body) =
        post_bundle(&state, app, bytes::Bytes::from_static(b"not a tar stream")).await;
    assert_eq!(status, axum::http::StatusCode::BAD_REQUEST);
    assert!(
        body["code"]
            .as_str()
            .is_some_and(|c| c.starts_with("bundle.")),
        "the caller's bundle is wrong and the code must say how: {body}"
    );

    let rows: Option<i64> = sqlx::query_scalar!(
        "select count(*) from app_versions where app_id = $1",
        app.as_uuid()
    )
    .fetch_one(&scratch.pool)
    .await
    .expect("counting");
    assert_eq!(rows, Some(0), "validation failed before the claim");

    scratch.drop_it().await;
}

/// The acceptance criterion, against a real database on a real thread pool.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ten_concurrent_identical_publishes_produce_one_row() {
    let scratch = Scratch::new().await;
    let app = an_app(&scratch.pool).await;

    // Released only once all ten have arrived, so they start together rather
    // than in spawn order.
    let gate = Arc::new(Barrier::new(RACERS));
    let mut racers = Vec::with_capacity(RACERS);
    for _ in 0..RACERS {
        let pool = scratch.pool.clone();
        let gate = Arc::clone(&gate);
        racers.push(tokio::spawn(async move {
            gate.wait().await;
            publish(&pool, app, DIGEST_A).await
        }));
    }

    let mut created = 0usize;
    let mut existed = 0usize;
    for racer in racers {
        match racer.await.expect("no racer panicked") {
            Claim::Won(_) => created += 1,
            Claim::Held(_) => existed += 1,
        }
    }

    let rows: Option<i64> = sqlx::query_scalar!(
        "select count(*) from app_versions where app_id = $1 and digest = $2",
        app.as_uuid(),
        DIGEST_A
    )
    .fetch_one(&scratch.pool)
    .await
    .expect("counting rows");

    // Reported as counts rather than a bare pass: if this test ever stops
    // racing, these are the numbers that say so.
    assert_eq!(rows, Some(1), "the unique index must leave exactly one row");
    assert_eq!(created, 1, "exactly one publisher may win the digest");
    assert_eq!(
        existed,
        RACERS - 1,
        "every other publisher must be told it already existed"
    );

    scratch.drop_it().await;
}

/// Without this, an implementation that deduplicated *everything* would pass
/// the test above.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_different_digests_concurrently_produce_two_rows() {
    let scratch = Scratch::new().await;
    let app = an_app(&scratch.pool).await;

    let gate = Arc::new(Barrier::new(2));
    let mut racers = Vec::with_capacity(2);
    for digest in [DIGEST_A, DIGEST_B] {
        let pool = scratch.pool.clone();
        let gate = Arc::clone(&gate);
        racers.push(tokio::spawn(async move {
            gate.wait().await;
            publish(&pool, app, digest).await
        }));
    }

    let mut created = 0usize;
    for racer in racers {
        if racer.await.expect("no racer panicked").was_created() {
            created += 1;
        }
    }

    let rows: Option<i64> = sqlx::query_scalar!(
        "select count(*) from app_versions where app_id = $1",
        app.as_uuid()
    )
    .fetch_one(&scratch.pool)
    .await
    .expect("counting rows");

    assert_eq!(created, 2, "different bytes are different versions");
    assert_eq!(rows, Some(2), "and each gets its own row");

    scratch.drop_it().await;
}
