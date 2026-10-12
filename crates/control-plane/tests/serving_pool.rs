//! The serving pool's timeouts, the schema gate, and migrations (#48),
//! against live Postgres.

use std::time::Duration;

use control_plane::pool::{self, MIGRATOR, SchemaError};
use sqlx::migrate::Migrator;
use sqlx::{ConnectOptions as _, Connection as _, PgConnection, PgPool};

async fn connection(pool: &PgPool) -> PgConnection {
    pool.connect_options()
        .connect()
        .await
        .expect("a connection to the test database")
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_migrated_database_passes_the_schema_gate(pool: PgPool) {
    pool::check_schema(&mut connection(&pool).await, &MIGRATOR)
        .await
        .expect("fully migrated");
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_database_behind_this_build_is_refused(pool: PgPool) {
    let latest = MIGRATOR
        .iter()
        .map(|m| m.version)
        .max()
        .expect("migrations");
    sqlx::query("delete from _sqlx_migrations where version = $1")
        .bind(latest)
        .execute(&pool)
        .await
        .expect("forget the latest migration");
    let err = pool::check_schema(&mut connection(&pool).await, &MIGRATOR)
        .await
        .expect_err("behind");
    assert!(
        matches!(err, SchemaError::Behind { version, .. } if version == latest),
        "{err}"
    );
    assert!(err.to_string().contains("control-plane migrate"), "{err}");
}

#[sqlx::test(migrations = false)]
async fn an_empty_database_is_behind(pool: PgPool) {
    let err = pool::check_schema(&mut connection(&pool).await, &MIGRATOR)
        .await
        .expect_err("nothing applied");
    assert!(matches!(err, SchemaError::Behind { .. }), "{err}");
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_failed_or_edited_migration_is_refused(pool: PgPool) {
    let first = MIGRATOR
        .iter()
        .map(|m| m.version)
        .min()
        .expect("migrations");
    sqlx::query("update _sqlx_migrations set checksum = '\\x00' where version = $1")
        .bind(first)
        .execute(&pool)
        .await
        .expect("edit");
    let err = pool::check_schema(&mut connection(&pool).await, &MIGRATOR)
        .await
        .expect_err("changed");
    assert!(
        matches!(err, SchemaError::Changed { version } if version == first),
        "{err}"
    );

    sqlx::query("update _sqlx_migrations set success = false where version = $1")
        .bind(first)
        .execute(&pool)
        .await
        .expect("fail");
    let err = pool::check_schema(&mut connection(&pool).await, &MIGRATOR)
        .await
        .expect_err("failed");
    assert!(
        matches!(err, SchemaError::Failed { version } if version == first),
        "{err}"
    );
}

/// Ahead is a rollout in progress: the next build's migrations ran first.
#[sqlx::test(migrations = "../../migrations")]
async fn a_database_ahead_of_this_build_is_allowed(pool: PgPool) {
    sqlx::query(
        "insert into _sqlx_migrations (version, description, success, checksum, execution_time) \
         values (99991231235959, 'from the future', true, '\\x00', 0)",
    )
    .execute(&pool)
    .await
    .expect("a future migration");
    pool::check_schema(&mut connection(&pool).await, &MIGRATOR)
        .await
        .expect("ahead is allowed");
}

/// The serving timeout is real: a statement longer than it is cancelled with
/// SQLSTATE 57014, and an idle transaction is ended by the server.
#[sqlx::test(migrations = false)]
async fn serving_connections_carry_both_timeouts(pool: PgPool) {
    let url = pool.connect_options().to_url_lossy().to_string();
    let mut serving = pool::serving_options(&url)
        .expect("options")
        .connect()
        .await
        .expect("a serving connection");
    let (statement, idle): (String, String) = sqlx::query_as(
        "select current_setting('statement_timeout'), current_setting('idle_in_transaction_session_timeout')",
    )
    .fetch_one(&mut serving)
    .await
    .expect("settings");
    assert_eq!((statement.as_str(), idle.as_str()), ("2s", "5s"));

    let err = sqlx::query("select pg_sleep(3)")
        .execute(&mut serving)
        .await
        .expect_err("cancelled at 2 s");
    let code = err
        .as_database_error()
        .and_then(|e| e.code().map(|c| c.into_owned()));
    assert_eq!(code.as_deref(), Some("57014"), "{err}");
}

/// Mutation 13: giving `migrate` the serving timeouts turns this red. A real
/// migration (an index build, a backfill) runs longer than any request.
#[sqlx::test(migrations = false)]
async fn a_slow_migration_succeeds_under_migrate(pool: PgPool) {
    let dir = std::env::temp_dir().join(format!(
        "clwd-slow-migration-{}-{}",
        std::process::id(),
        uuid::Uuid::now_v7()
    ));
    std::fs::create_dir_all(&dir).expect("migrations dir");
    std::fs::write(
        dir.join("20000101000000_slow.sql"),
        "select pg_sleep(3);\ncreate table slow_marker (id int);\n",
    )
    .expect("write the slow migration");
    let slow = Migrator::new(dir.as_path()).await.expect("load");

    let url = pool.connect_options().to_url_lossy().to_string();
    let started = std::time::Instant::now();
    let result = pool::migrate(&url, &slow).await;
    let _ = std::fs::remove_dir_all(&dir);
    result.expect("a 3 s migration completes under `migrate`");
    assert!(started.elapsed() >= Duration::from_secs(3));

    let mut check = connection(&pool).await;
    sqlx::query("select 1 from slow_marker")
        .execute(&mut check)
        .await
        .expect("the migration ran to the end");
    check.close().await.expect("close");
}
