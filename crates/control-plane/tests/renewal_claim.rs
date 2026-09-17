//! The renewal reconciler's claim (`db::claim_due_for_renewal`): which rows a
//! pass takes, what state it leaves, and what it never blocks on.
//!
//! Database-only — no Pebble, no ACME. The rows are built with the same helpers
//! issuance uses (`cert_mark_pending` / `cert_mark_issued` / `cert_mark_failed`),
//! so what is claimed here is what issuance leaves behind.

use chrono::{Duration, Utc};
use control_plane::db;
use control_plane::ids::OrgId;
use sqlx::PgPool;

const STALE_AFTER_SECS: i64 = 900;
const RETRY_AFTER_SECS: i64 = 3600;

/// An org whose certificate was issued with `renew_after` as its ARI schedule.
async fn issued(pool: &PgPool, slug: &str, renew_after: chrono::DateTime<Utc>) -> OrgId {
    let org = db::create_org(pool, slug).await.expect("org");
    db::cert_mark_pending(pool, org.id, "https://ca.invalid/order/1")
        .await
        .expect("pending");
    db::cert_mark_issued(pool, org.id, renew_after + Duration::days(30), renew_after)
        .await
        .expect("issued");
    org.id
}

async fn state_of(pool: &PgPool, org: OrgId) -> String {
    db::cert_record(pool, org)
        .await
        .expect("read")
        .expect("row")
        .state
}

/// Move `last_renewal_attempt` back by `secs`, to simulate a claim or failure
/// that happened a while ago.
async fn backdate_attempt(pool: &PgPool, org: OrgId, secs: i64) {
    sqlx::query!(
        "update certificates \
          set last_renewal_attempt = now() - ($1::bigint * interval '1 second') \
          where org_id = $2",
        secs,
        org.as_uuid(),
    )
    .execute(pool)
    .await
    .expect("backdate");
}

async fn claim(pool: &PgPool) -> Vec<db::DueCert> {
    db::claim_due_for_renewal(pool, 10, STALE_AFTER_SECS, RETRY_AFTER_SECS)
        .await
        .expect("claim runs")
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_due_certificate_is_claimed_and_marked_renewing(pool: PgPool) {
    let org = issued(&pool, "acme", Utc::now() - Duration::hours(1)).await;

    let claimed = claim(&pool).await;
    assert_eq!(claimed.len(), 1, "the due row is claimed");
    assert_eq!(claimed[0].org_id, org);
    assert_eq!(claimed[0].slug, "acme");
    assert_eq!(
        state_of(&pool, org).await,
        "renewing",
        "the claim marks the row in the same statement"
    );

    // A second pass finds nothing: the row is renewing and fresh, not due.
    assert!(
        claim(&pool).await.is_empty(),
        "a fresh renewing row must not be reclaimed"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_certificate_whose_window_has_not_passed_is_not_claimed(pool: PgPool) {
    issued(&pool, "acme", Utc::now() + Duration::days(30)).await;
    assert!(
        claim(&pool).await.is_empty(),
        "nothing due means nothing claimed"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_stale_renewing_row_is_reclaimed(pool: PgPool) {
    let org = issued(&pool, "acme", Utc::now() - Duration::hours(1)).await;
    assert_eq!(claim(&pool).await.len(), 1, "first claim takes it");

    // The worker died between the mark and `cert_mark_issued`: an hour later a
    // pass must take it back rather than strand it.
    backdate_attempt(&pool, org, 3600).await;
    let reclaimed = claim(&pool).await;
    assert_eq!(reclaimed.len(), 1, "the stale row re-enters rotation");
    assert_eq!(reclaimed[0].org_id, org);
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_failed_certificate_retries_only_after_backoff(pool: PgPool) {
    let org = db::create_org(&pool, "acme").await.expect("org");
    db::cert_mark_failed(&pool, org.id, "simulated outage")
        .await
        .expect("failed");

    assert!(
        claim(&pool).await.is_empty(),
        "a fresh failure must back off, not retry at once"
    );

    backdate_attempt(&pool, org.id, RETRY_AFTER_SECS + 60).await;
    let retried = claim(&pool).await;
    assert_eq!(retried.len(), 1, "the backoff elapsed, so it is due again");
    assert_eq!(retried[0].org_id, org.id);
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_row_locked_elsewhere_is_skipped_not_waited_on(pool: PgPool) {
    let first = issued(&pool, "first", Utc::now() - Duration::hours(1)).await;
    issued(&pool, "second", Utc::now() - Duration::hours(1)).await;

    // Another worker holds the first row's lock and is slow to commit. The
    // claim must take the second row and return, not queue behind the first —
    // that non-blocking is what `SKIP LOCKED` is, and an advisory lock would
    // serialise here instead.
    let mut held = pool.begin().await.expect("txn");
    sqlx::query!(
        "select org_id from certificates where org_id = $1 for update",
        first.as_uuid(),
    )
    .fetch_one(&mut *held)
    .await
    .expect("holding the row lock");

    let claimed = tokio::time::timeout(std::time::Duration::from_secs(5), claim(&pool))
        .await
        .expect("the claim must not block on a locked row");
    assert_eq!(
        claimed.iter().map(|c| c.slug.as_str()).collect::<Vec<_>>(),
        vec!["second"],
        "the locked row is skipped, the free one taken"
    );
    // `held` drops here and rolls back, releasing the lock.
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_deleted_org_is_never_claimed(pool: PgPool) {
    let org = issued(&pool, "acme", Utc::now() - Duration::hours(1)).await;
    sqlx::query!(
        "update orgs set deleted_at = now() where id = $1",
        org.as_uuid()
    )
    .execute(&pool)
    .await
    .expect("soft delete");

    assert!(
        claim(&pool).await.is_empty(),
        "there is nothing left to serve under a deleted org's names"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn marking_pending_preserves_an_existing_renewing_claim(pool: PgPool) {
    // The reconciler claims (renewing) BEFORE issuance starts its order; when
    // `issue_inner` then persists the order URL it must not clobber the claim
    // back to `pending` — the stale-reclaim arm looks for `renewing`, and a
    // crash after the order persist would otherwise leave a `pending` row no
    // pass reclaims.
    let org = issued(&pool, "acme", Utc::now() - Duration::hours(1)).await;
    assert_eq!(claim(&pool).await.len(), 1, "claimed as renewing");

    db::cert_mark_pending(&pool, org, "https://ca.invalid/order/2")
        .await
        .expect("order persist");
    assert_eq!(
        state_of(&pool, org).await,
        "renewing",
        "persisting the order URL keeps the claim"
    );

    // And a first issuance (no prior claim) still lands in `pending`.
    let fresh = db::create_org(&pool, "fresh").await.expect("org");
    db::cert_mark_pending(&pool, fresh.id, "https://ca.invalid/order/3")
        .await
        .expect("pending");
    assert_eq!(state_of(&pool, fresh.id).await, "pending");
}
