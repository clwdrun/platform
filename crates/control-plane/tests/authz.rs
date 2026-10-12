//! The database side of authorization invalidation (#12), against a real
//! Postgres: triggers, the outbox's numbering, the relay, leases.
//!
//! None of this can run against the offline query cache. Triggers,
//! `pg_notify` and constraint-trigger deferral exist only in a database.

use std::collections::BTreeSet;
use std::time::{Duration, Instant};

use axum::body::Body;
use axum::http::{Request, StatusCode};
use control_plane::authz::{INPUTS, TRIGGERS};
use control_plane::relay::{self, Relay};
use control_plane::{db, http::AppState};
use shared::authz::{Ack, Seq};
use sqlx::PgPool;
use tower::ServiceExt as _;

const INTERNAL: &str = "test-internal-secret";

async fn latest(pool: &PgPool) -> u64 {
    relay::latest(pool).await.expect("latest").get()
}

/// `(seq, kind)` for every outbox row after `from`.
async fn outbox_after(pool: &PgPool, from: u64) -> Vec<(i64, String)> {
    sqlx::query_as("select seq, kind from authz_outbox where seq > $1 order by seq, kind")
        .bind(i64::try_from(from).expect("small"))
        .fetch_all(pool)
        .await
        .expect("outbox")
}

async fn outbox_rows(pool: &PgPool) -> i64 {
    sqlx::query_scalar("select count(*) from authz_outbox")
        .fetch_one(pool)
        .await
        .expect("count")
}

/// Every relation the decision statement reads is in `INPUTS`, and every
/// input carries every trigger, enabled. Read from the statement's plan, so
/// a join added to the decision without its triggers fails here.
#[sqlx::test(migrations = "../../migrations")]
async fn the_decision_reads_exactly_the_inputs_and_each_is_watched(pool: PgPool) {
    let statement = include_str!("../queries/authz_check.sql");
    let plan: serde_json::Value = sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
        "explain (format json) {statement}"
    )))
    .bind(vec![0u8; 32])
    .bind(uuid::Uuid::nil())
    .fetch_one(&pool)
    .await
    .expect("explain");
    fn relations(node: &serde_json::Value, out: &mut BTreeSet<String>) {
        match node {
            serde_json::Value::Object(map) => {
                if let Some(serde_json::Value::String(name)) = map.get("Relation Name") {
                    out.insert(name.clone());
                }
                map.values().for_each(|v| relations(v, out));
            }
            serde_json::Value::Array(items) => items.iter().for_each(|v| relations(v, out)),
            _ => {}
        }
    }
    let mut read = BTreeSet::new();
    relations(&plan, &mut read);
    // The one relation that is not a decision input: the counter, read for
    // the snapshot position the answer reflects. A change to it is a change
    // in numbering, never in who may do what.
    assert!(
        read.remove("authz_seq"),
        "the decision no longer reads as_of"
    );
    let inputs: BTreeSet<String> = INPUTS.iter().map(|i| i.table.to_owned()).collect();
    assert_eq!(read, inputs, "the decision and authz::INPUTS disagree");

    assert!(relay::triggers_ok(&pool).await.expect("query"));
    let watched: i64 = sqlx::query_scalar(
        "select count(*) from pg_trigger t join pg_class c on c.oid = t.tgrelid
          where t.tgname = any($1) and t.tgenabled = 'O'",
    )
    .bind(TRIGGERS.iter().map(|t| (*t).to_owned()).collect::<Vec<_>>())
    .fetch_one(&pool)
    .await
    .expect("count");
    assert_eq!(
        watched,
        i64::try_from(INPUTS.len() * TRIGGERS.len()).expect("small"),
        "a trigger exists on a table that is not a decision input, or is missing"
    );

    // Negative control: disabling one trigger is seen.
    sqlx::query("alter table sessions disable trigger authz_upd")
        .execute(&pool)
        .await
        .expect("disable");
    assert!(!relay::triggers_ok(&pool).await.expect("query"));
}

/// One transaction, several writes: one sequence number, every entity named.
#[sqlx::test(migrations = "../../migrations")]
async fn a_transaction_gets_one_number_and_names_what_it_touched(pool: PgPool) {
    let from = latest(&pool).await;
    let mut tx = pool.begin().await.expect("begin");
    let user = db::create_user(&mut *tx, "a@example.com")
        .await
        .expect("user");
    let org = db::create_org(&mut *tx, "acme").await.expect("org");
    db::add_org_member(
        &mut *tx,
        org.id,
        user.id,
        control_plane::orgs::JoinedVia::Claimant,
    )
    .await
    .expect("member");
    // Nothing is numbered before commit: the counter is taken at commit.
    assert_eq!(latest(&pool).await, from);
    tx.commit().await.expect("commit");

    assert_eq!(latest(&pool).await, from + 1);
    let rows = outbox_after(&pool, from).await;
    assert!(
        rows.iter()
            .all(|(seq, _)| *seq == i64::try_from(from + 1).expect("small"))
    );
    let kinds: BTreeSet<&str> = rows.iter().map(|(_, k)| k.as_str()).collect();
    assert_eq!(kinds, BTreeSet::from(["org", "user"]));
}

/// A rolled-back transaction leaves no hole: the counter is a row, not a
/// sequence, so the next commit is the next number.
#[sqlx::test(migrations = "../../migrations")]
async fn a_rollback_leaves_no_gap(pool: PgPool) {
    let from = latest(&pool).await;
    let mut tx = pool.begin().await.expect("begin");
    sqlx::query("set constraints all immediate")
        .execute(&mut *tx)
        .await
        .expect("immediate");
    db::create_user(&mut *tx, "gone@example.com")
        .await
        .expect("user");
    tx.rollback().await.expect("rollback");
    db::create_user(&pool, "kept@example.com")
        .await
        .expect("user");
    assert_eq!(latest(&pool).await, from + 1);
}

/// Concurrent committers get distinct, contiguous numbers.
#[sqlx::test(migrations = "../../migrations")]
async fn concurrent_commits_number_without_gaps(pool: PgPool) {
    let from = latest(&pool).await;
    let writers = (0..16).map(|i| {
        let pool = pool.clone();
        tokio::spawn(async move {
            db::create_user(&pool, &format!("u{i}@example.com"))
                .await
                .expect("user");
        })
    });
    for writer in writers {
        writer.await.expect("joined");
    }
    let seqs: BTreeSet<i64> = outbox_after(&pool, from)
        .await
        .into_iter()
        .map(|(seq, _)| seq)
        .collect();
    let expected: BTreeSet<i64> = (1..=16)
        .map(|n| i64::try_from(from).expect("small") + n)
        .collect();
    assert_eq!(seqs, expected);
}

/// Mutation 9's test: a sign-in that rewrites the same email emits nothing;
/// a changed email emits.
#[sqlx::test(migrations = "../../migrations")]
async fn an_unchanged_sign_in_emits_nothing(pool: PgPool) {
    db::upsert_google_user(&pool, "google-1", "a@example.com", None)
        .await
        .expect("first sign-in");
    let from = latest(&pool).await;
    db::upsert_google_user(&pool, "google-1", "a@example.com", None)
        .await
        .expect("same again");
    assert_eq!(latest(&pool).await, from, "an unchanged row emitted");
    db::upsert_google_user(&pool, "google-1", "b@example.com", None)
        .await
        .expect("renamed");
    assert_eq!(latest(&pool).await, from + 1);
    assert_eq!(outbox_after(&pool, from).await[0].1, "user");
}

/// Mutation 10's test: row triggers do not fire on TRUNCATE; the statement
/// trigger turns it into a flush.
#[sqlx::test(migrations = "../../migrations")]
async fn truncate_flushes_every_cache(pool: PgPool) {
    let from = latest(&pool).await;
    sqlx::query("truncate app_subjects")
        .execute(&pool)
        .await
        .expect("truncate");
    assert_eq!(
        outbox_after(&pool, from).await,
        vec![(i64::try_from(from + 1).expect("small"), "all".to_owned())]
    );
}

async fn with_relay(pool: &PgPool) -> (AppState, std::sync::Arc<Relay>) {
    let relay = Relay::start(pool).await.expect("relay");
    let state = AppState::new(
        pool.clone(),
        builder::ArtifactStore::new(
            opendal::Operator::new(opendal::services::Memory::default()).expect("memory"),
        ),
    )
    .with_internal_secret(INTERNAL)
    .with_relay(relay.clone());
    let deadline = Instant::now() + Duration::from_secs(10);
    while !relay.healthy() {
        assert!(Instant::now() < deadline, "the relay never became healthy");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    (state, relay)
}

async fn ack(state: &AppState, gateway: uuid::Uuid, applied: Seq) -> StatusCode {
    let body = serde_json::to_vec(&Ack { gateway, applied }).expect("json");
    control_plane::http::internal_router(state.clone())
        .oneshot(
            Request::post("/internal/authz/ack")
                .header("authorization", format!("Bearer {INTERNAL}"))
                .header("content-type", "application/json")
                .body(Body::from(body))
                .expect("request"),
        )
        .await
        .expect("answered")
        .status()
}

/// Mutation 13's test: a lease write is not a decision input. Heartbeats
/// renew leases every second; if they emitted, every cache would flush.
#[sqlx::test(migrations = "../../migrations")]
async fn an_ack_leaves_the_outbox_unchanged(pool: PgPool) {
    let (state, _relay) = with_relay(&pool).await;
    let before = (outbox_rows(&pool).await, latest(&pool).await);
    for _ in 0..3 {
        assert_eq!(
            ack(&state, uuid::Uuid::now_v7(), Seq::ZERO).await,
            StatusCode::NO_CONTENT
        );
    }
    assert_eq!((outbox_rows(&pool).await, latest(&pool).await), before);
}

/// The relay broadcasts each committed transaction once, in order.
#[sqlx::test(migrations = "../../migrations")]
async fn the_relay_relays_each_commit_in_order(pool: PgPool) {
    let (_state, relay) = with_relay(&pool).await;
    let from = relay.current();
    for i in 0..5 {
        db::create_user(&pool, &format!("u{i}@example.com"))
            .await
            .expect("user");
    }
    let deadline = Instant::now() + Duration::from_secs(10);
    while relay.current() < Seq::new(from.get() + 5) {
        assert!(
            Instant::now() < deadline,
            "not relayed: {:?}",
            relay.current()
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert_eq!(relay.current(), Seq::new(from.get() + 5));
}

/// Whether `gateway`'s lease is live, by the database's clock.
async fn lease_live(pool: &PgPool, gateway: uuid::Uuid) -> bool {
    sqlx::query_scalar("select lease_until > now() from gateway_leases where gateway_id = $1")
        .bind(gateway)
        .fetch_one(pool)
        .await
        .expect("lease")
}

/// A revoke waits for a gateway that has not applied it until the gateway
/// acks or its lease lapses; it never returns early.
///
/// Judged by the database's own record at the moment `converged` returns, not
/// by a stopwatch: the lease runs from the ack, on the database's clock, so a
/// test's timer started later measures load, not the wait. (It did: under a
/// loaded suite, setup between the ack and the timer took up to 3 s, and the
/// stopwatch version failed 6 runs in 40 while the product was right.)
#[sqlx::test(migrations = "../../migrations")]
async fn converged_waits_out_a_lagging_lease(pool: PgPool) {
    let (state, _relay) = with_relay(&pool).await;
    let gateway = uuid::Uuid::now_v7();
    // The gateway has applied nothing; the revocation is at 1.
    assert_eq!(
        ack(&state, gateway, Seq::ZERO).await,
        StatusCode::NO_CONTENT
    );
    relay::converged(&pool, Seq::new(1))
        .await
        .expect("converges");
    assert!(
        !lease_live(&pool, gateway).await,
        "returned while the lagging gateway's lease was still live"
    );

    // Acked: returns without waiting the lease out. The lease is made an
    // hour long, as a gateway that keeps renewing would hold it, so a
    // `converged` that waited for it to lapse would hit its own deadline and
    // fail instead of returning. (A 3-second lease made this a stopwatch
    // again: under load more than 3 s could pass, and it failed for nothing.)
    let acked = uuid::Uuid::now_v7();
    assert_eq!(
        ack(&state, acked, Seq::new(1)).await,
        StatusCode::NO_CONTENT
    );
    sqlx::query(
        "update gateway_leases set lease_until = now() + interval '1 hour' where gateway_id = $1",
    )
    .bind(acked)
    .execute(&pool)
    .await
    .expect("a long lease");
    relay::converged(&pool, Seq::new(1))
        .await
        .expect("an acknowledged gateway is not waited for");
    assert!(lease_live(&pool, acked).await);
}

/// Test 6's database half (mutation 15): the sequence an answer reports is
/// read in the same snapshot as the decision. Deterministic, with the
/// database as the barrier: a transaction holds `authz_seq` locked, revokes
/// the session, and commits only once the check is waiting on that lock. A
/// check that read its decision first and the sequence afterwards would come
/// back with the old allow and the new number; the one statement comes back
/// with an answer and a number that agree.
#[sqlx::test(migrations = "../../migrations")]
async fn the_sequence_is_read_in_the_decisions_snapshot(pool: PgPool) {
    use control_plane::handshake::{self, AppSessionSecret};
    let org = db::create_org(&pool, "acme").await.expect("org");
    let app = db::create_app(&pool, org.id, "notes", "wasm")
        .await
        .expect("app");
    let user = db::create_user(&pool, "v@example.com").await.expect("user");
    db::add_org_member(
        &pool,
        org.id,
        user.id,
        control_plane::orgs::JoinedVia::Claimant,
    )
    .await
    .expect("member");
    let parent = control_plane::session::issue(
        &pool,
        &control_plane::signin::CookieKey::from_secret(b"a-test-signing-secret-of-some-length")
            .expect("a long enough test secret"),
        user.id,
    )
    .await
    .expect("issue")
    .expect("a session")
    .id;
    let raw = "5e".repeat(32);
    let secret = AppSessionSecret::parse(&raw).expect("our shape");
    sqlx::query("insert into app_subjects (app_id, user_id) values ($1, $2)")
        .bind(app.id.as_uuid())
        .bind(user.id.as_uuid())
        .execute(&pool)
        .await
        .expect("subject");
    sqlx::query(
        "insert into app_sessions (id, parent_session_id, app_id, secret_sha256, expires_at)
         values (gen_random_uuid(), $1, $2, $3, now() + interval '1 hour')",
    )
    .bind(parent.as_uuid())
    .bind(app.id.as_uuid())
    .bind({
        use sha2::Digest as _;
        sha2::Sha256::digest(raw.as_bytes()).to_vec()
    })
    .execute(&pool)
    .await
    .expect("app session");
    assert!(
        handshake::check(&pool, &secret, app.id)
            .await
            .expect("check")
            .is_some(),
        "positive control: the session is live"
    );

    let mut revoke = pool.begin().await.expect("begin");
    sqlx::query("lock table authz_seq in access exclusive mode")
        .execute(&mut *revoke)
        .await
        .expect("lock");
    let checking = {
        let pool = pool.clone();
        let secret = secret.clone();
        tokio::spawn(async move { handshake::check(&pool, &secret, app.id).await })
    };
    // The barrier: the check is blocked on the lock.
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let waiting: i64 = sqlx::query_scalar(
            "select count(*) from pg_stat_activity
              where datname = current_database() and wait_event_type = 'Lock'",
        )
        .fetch_one(&pool)
        .await
        .expect("activity");
        if waiting > 0 {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the check never waited on the lock"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    sqlx::query("update sessions set revoked_at = now() where id = $1")
        .bind(parent.as_uuid())
        .execute(&mut *revoke)
        .await
        .expect("revoke");
    revoke.commit().await.expect("commit");
    let revocation = latest(&pool).await;

    match checking.await.expect("joined").expect("check") {
        None => {} // the revocation and its number, both seen
        Some(checked) => assert!(
            checked.as_of.get() < revocation,
            "an allow made before the revocation reports the revocation's number \
             ({} >= {revocation}): the gateway would serve it as fresh",
            checked.as_of
        ),
    }
}
