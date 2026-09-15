//! Constraint tests against a real Postgres.
//!
//! `#[sqlx::test(migrations = "../../migrations")]` creates a fresh database per test and runs `migrations/`
//! into it, so every one of these also exercises the migration from empty to
//! head. They need a reachable database — `DATABASE_URL`, or `just check`,
//! which brings one up.

use control_plane::db;
use sqlx::PgPool;

/// The SQLSTATE a failed query reported, so a test can assert *which*
/// constraint rejected the row rather than merely that something did.
fn sqlstate(err: sqlx::Error) -> String {
    match err {
        sqlx::Error::Database(e) => e.code().expect("postgres reports a code").into_owned(),
        other => panic!("expected a database error, got {other:?}"),
    }
}

const UNIQUE_VIOLATION: &str = "23505";
const CHECK_VIOLATION: &str = "23514";
const RESTRICT_VIOLATION: &str = "23001";
const FK_VIOLATION: &str = "23503";

const DIGEST_A: &str = "blake3:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const DIGEST_B: &str = "blake3:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

#[sqlx::test(migrations = "../../migrations")]
async fn duplicate_org_slug_is_rejected(pool: PgPool) {
    db::create_org(&pool, "acme").await.expect("first insert");
    let err = db::create_org(&pool, "acme")
        .await
        .expect_err("second insert");
    assert_eq!(sqlstate(err), UNIQUE_VIOLATION);
}

#[sqlx::test(migrations = "../../migrations")]
async fn reserved_org_slug_is_rejected(pool: PgPool) {
    let err = db::create_org(&pool, "www")
        .await
        .expect_err("reserved slug");
    assert_eq!(sqlstate(err), RESTRICT_VIOLATION);
}

/// A slug that was mutable for a month is a subdomain that was reassignable,
/// and a reassigned subdomain is handed a browser's still-live cookie. The
/// guard is a trigger so it also holds against a hand-run UPDATE.
#[sqlx::test(migrations = "../../migrations")]
async fn org_slug_is_immutable(pool: PgPool) {
    let org = db::create_org(&pool, "acme").await.expect("insert");
    let err = sqlx::query!(
        "update orgs set slug = 'acme2' where id = $1",
        org.id.as_uuid()
    )
    .execute(&pool)
    .await
    .expect_err("slug update");
    assert_eq!(sqlstate(err), RESTRICT_VIOLATION);
}

#[sqlx::test(migrations = "../../migrations")]
async fn org_slug_must_be_a_dns_label(pool: PgPool) {
    for bad in ["-leading", "trailing-", "Upper", "under_score", ""] {
        let result = db::create_org(&pool, bad).await;
        assert!(result.is_err(), "{bad:?} was accepted");
        assert_eq!(sqlstate(result.unwrap_err()), CHECK_VIOLATION, "{bad:?}");
    }
}

/// #18's acceptance criterion: two orgs can both own an app named
/// `dashboard`, and neither can own two.
#[sqlx::test(migrations = "../../migrations")]
async fn app_names_are_unique_within_an_org_only(pool: PgPool) {
    let acme = db::create_org(&pool, "acme").await.expect("acme");
    let globex = db::create_org(&pool, "globex").await.expect("globex");

    db::create_app(&pool, acme.id, "dashboard", "wasm")
        .await
        .expect("acme/dashboard");
    db::create_app(&pool, globex.id, "dashboard", "wasm")
        .await
        .expect("globex/dashboard — a different org, so no collision");

    let err = db::create_app(&pool, acme.id, "dashboard", "microvm")
        .await
        .expect_err("acme/dashboard twice");
    assert_eq!(sqlstate(err), UNIQUE_VIOLATION);
}

/// A deleted app keeps its name, so a new app cannot inherit its identity,
/// its subdomain, or its links. The unique index is unconditional for this.
#[sqlx::test(migrations = "../../migrations")]
async fn a_deleted_app_does_not_free_its_name(pool: PgPool) {
    let org = db::create_org(&pool, "acme").await.expect("org");
    let app = db::create_app(&pool, org.id, "dashboard", "wasm")
        .await
        .expect("app");
    sqlx::query!(
        "update apps set deleted_at = now() where id = $1",
        app.id.as_uuid()
    )
    .execute(&pool)
    .await
    .expect("soft delete");

    let err = db::create_app(&pool, org.id, "dashboard", "wasm")
        .await
        .expect_err("name is still taken");
    assert_eq!(sqlstate(err), UNIQUE_VIOLATION);
}

/// The column stores `clwd_bundle::Runtime::as_str()` and nothing else. It is
/// never matched on above clwd-runtime, but it is still a closed set.
#[sqlx::test(migrations = "../../migrations")]
async fn runtime_accepts_only_the_two_spellings(pool: PgPool) {
    let org = db::create_org(&pool, "acme").await.expect("org");
    for good in ["wasm", "microvm"] {
        db::create_app(&pool, org.id, good, good)
            .await
            .unwrap_or_else(|e| panic!("{good} rejected: {e}"));
    }
    let err = db::create_app(&pool, org.id, "third", "firecracker")
        .await
        .expect_err("unknown runtime");
    assert_eq!(sqlstate(err), CHECK_VIOLATION);
}

/// The key #7 builds idempotent publish on.
#[sqlx::test(migrations = "../../migrations")]
async fn app_id_and_digest_are_unique_together(pool: PgPool) {
    let org = db::create_org(&pool, "acme").await.expect("org");
    let one = db::create_app(&pool, org.id, "one", "wasm")
        .await
        .expect("one");
    let two = db::create_app(&pool, org.id, "two", "wasm")
        .await
        .expect("two");

    assert!(
        db::claim_app_version(&pool, org.id, one.id, DIGEST_A)
            .await
            .expect("first publish")
            .is_some(),
        "the first claim on a digest wins it"
    );
    assert!(
        db::claim_app_version(&pool, org.id, one.id, DIGEST_B)
            .await
            .expect("a different digest for the same app")
            .is_some()
    );
    assert!(
        db::claim_app_version(&pool, org.id, two.id, DIGEST_A)
            .await
            .expect("the same digest for a different app")
            .is_some()
    );

    // The behaviour #7 changed. This used to be a unique violation; the index
    // is the same, but `on conflict do nothing` turns the rejection into the
    // answer — no row back, no error, and the caller reads the existing one.
    assert!(
        db::claim_app_version(&pool, org.id, one.id, DIGEST_A)
            .await
            .expect("a repeat claim is not an error")
            .is_none(),
        "the second claim on a digest must not win it"
    );

    // And exactly one row exists for it, which is what the index is for.
    let rows = sqlx::query_scalar!(
        "select count(*) from app_versions where app_id = $1 and digest = $2",
        one.id.as_uuid(),
        DIGEST_A
    )
    .fetch_one(&pool)
    .await
    .expect("counting");
    assert_eq!(rows, Some(1));
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_version_digest_must_be_a_blake3_content_address(pool: PgPool) {
    let org = db::create_org(&pool, "acme").await.expect("org");
    let app = db::create_app(&pool, org.id, "one", "wasm")
        .await
        .expect("app");

    for bad in [
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "blake3:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "blake3:tooshort",
        "artifacts/dashboard/latest.tar",
    ] {
        let result = db::claim_app_version(&pool, org.id, app.id, bad).await;
        assert!(result.is_err(), "{bad:?} was accepted");
        assert_eq!(sqlstate(result.unwrap_err()), CHECK_VIOLATION, "{bad:?}");
    }
}

/// A version row exists before its artifact does, so a crash mid-publish
/// leaves a visible `pending` row rather than an orphan artifact.
#[sqlx::test(migrations = "../../migrations")]
async fn a_version_starts_pending_and_is_marked_ready(pool: PgPool) {
    let org = db::create_org(&pool, "acme").await.expect("org");
    let app = db::create_app(&pool, org.id, "one", "wasm")
        .await
        .expect("app");

    let version = db::claim_app_version(&pool, org.id, app.id, DIGEST_A)
        .await
        .expect("publish")
        .expect("the first claim wins");
    assert_eq!(version.state, "pending");

    let ready = db::mark_app_version_ready(&pool, version.id)
        .await
        .expect("store succeeded");
    assert_eq!(ready.state, "ready");
    assert_eq!(ready.id, version.id);
}

/// The foreign key cannot see `deleted_at`, so a plain insert would publish
/// happily into a deleted app. The claim folds the predicate into its source
/// query, which is what makes this a no-op rather than a silent success.
#[sqlx::test(migrations = "../../migrations")]
async fn a_deleted_app_cannot_be_published_to(pool: PgPool) {
    let org = db::create_org(&pool, "acme").await.expect("org");
    let app = db::create_app(&pool, org.id, "one", "wasm")
        .await
        .expect("app");
    sqlx::query!(
        "update apps set deleted_at = now() where id = $1",
        app.id.as_uuid()
    )
    .execute(&pool)
    .await
    .expect("soft delete");

    assert!(
        db::claim_app_version(&pool, org.id, app.id, DIGEST_A)
            .await
            .expect("a deleted app is not a driver error")
            .is_none(),
        "publishing into a deleted app must claim nothing"
    );

    // And no row was written, so this is genuinely absent rather than held.
    assert!(
        db::app_version_by_digest(&pool, org.id, app.id, DIGEST_A)
            .await
            .expect("lookup")
            .is_none(),
        "an unclaimed digest must leave no row behind"
    );
}

/// An app that never existed is the other half of the ambiguous empty result.
#[sqlx::test(migrations = "../../migrations")]
async fn an_unknown_app_cannot_be_published_to(pool: PgPool) {
    let absent = control_plane::ids::AppId::new();
    assert!(
        db::claim_app_version(&pool, control_plane::ids::OrgId::new(), absent, DIGEST_A)
            .await
            .expect("an unknown app is not a driver error")
            .is_none(),
        "the select yields no row, so the foreign key is never offered one"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_user_can_join_an_org(pool: PgPool) {
    let org = db::create_org(&pool, "acme").await.expect("org");
    let user = db::create_user(&pool, "someone@example.com")
        .await
        .expect("user");
    db::add_org_member(&pool, org.id, user.id)
        .await
        .expect("membership");

    let err = db::add_org_member(&pool, org.id, user.id)
        .await
        .expect_err("joining twice");
    assert_eq!(sqlstate(err), UNIQUE_VIOLATION);
}

#[sqlx::test(migrations = "../../migrations")]
async fn an_email_is_stored_lowercased(pool: PgPool) {
    db::create_user(&pool, "someone@example.com")
        .await
        .expect("lowercase");
    let err = db::create_user(&pool, "Someone@Example.com")
        .await
        .expect_err("mixed case");
    assert_eq!(sqlstate(err), CHECK_VIOLATION);
}

/// The certificates table (#5): one row per org, a bounded state, and a real
/// org behind every row. State only — no key material is stored here.
#[sqlx::test(migrations = "../../migrations")]
async fn certificate_rows_are_one_per_org_with_a_bounded_state(pool: PgPool) {
    let org = db::create_org(&pool, "acme").await.expect("org");

    // A valid row inserts.
    sqlx::query("insert into certificates (org_id, state) values ($1, 'pending')")
        .bind(org.id.as_uuid())
        .execute(&pool)
        .await
        .expect("a valid certificate row");

    // One row per org: the primary key is org_id.
    let dup = sqlx::query("insert into certificates (org_id, state) values ($1, 'issued')")
        .bind(org.id.as_uuid())
        .execute(&pool)
        .await
        .expect_err("a second row for the same org");
    assert_eq!(sqlstate(dup), UNIQUE_VIOLATION);

    // An unknown state is rejected (real org, so only the CHECK can fire).
    let beta = db::create_org(&pool, "beta").await.expect("org2");
    let bad_state = sqlx::query("insert into certificates (org_id, state) values ($1, 'bogus')")
        .bind(beta.id.as_uuid())
        .execute(&pool)
        .await
        .expect_err("an out-of-range state");
    assert_eq!(sqlstate(bad_state), CHECK_VIOLATION);

    // A certificate for a nonexistent org is rejected.
    let orphan = sqlx::query("insert into certificates (org_id, state) values ($1, 'pending')")
        .bind(uuid::Uuid::now_v7())
        .execute(&pool)
        .await
        .expect_err("a certificate with no org");
    assert_eq!(sqlstate(orphan), FK_VIOLATION);
}
