//! The serving pool, the schema gate, and migrations (#48).
//!
//! # The pool's shape, and why
//!
//! - **Every connection is opened before the instance is ready**
//!   (`min_connections` = `max_connections`). Opening a connection under load
//!   took 0.5–4.5 s in #90's measurements; a pool that opens on demand opens
//!   exactly when that is slowest.
//! - **No idle timeout and no `max_lifetime`.** An idle timeout closes
//!   connections that the next burst reopens. sqlx 0.9's `max_lifetime` has no
//!   jitter, so every connection opened together expires together: #90's
//!   reopen storm on a timer. Jittered recycling is #98.
//! - **`test_before_acquire` stays on**, so a connection broken by a database
//!   failover is detected rather than handed to a request.
//! - **Acquire timeout from configuration, below the gateway's 5 s**, so a
//!   pool shortage is `control-plane.timeout` and never a gateway timeout.
//! - **`statement_timeout` [`STATEMENT_TIMEOUT`] and
//!   `idle_in_transaction_session_timeout` [`IDLE_IN_TRANSACTION_TIMEOUT`]**,
//!   set as startup parameters on every serving connection. A statement
//!   stuck behind a lock ends as `control-plane.timeout` in 2 s rather than
//!   holding a connection for the request's 30 s; a transaction left open by a
//!   bug is closed by the server rather than pinning its locks.
//!
//! Neither timeout reaches migrations: [`migrate`] connects with plain options
//! from the URL, because an index build or a backfill legitimately runs for
//! longer than any request should.

use std::time::Duration;

use sqlx::migrate::Migrator;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::{ConnectOptions as _, Connection as _, PgConnection, PgPool};

/// Every migration in `migrations/`, embedded at compile time.
pub static MIGRATOR: Migrator = sqlx::migrate!("../../migrations");

/// The serving pool's per-statement ceiling.
pub const STATEMENT_TIMEOUT: Duration = Duration::from_secs(2);

/// How long a serving connection may sit idle inside a transaction.
pub const IDLE_IN_TRANSACTION_TIMEOUT: Duration = Duration::from_secs(5);

/// How long startup waits for every pooled connection to open before it gives
/// up and exits, so the orchestrator restarts it rather than it sitting
/// not-ready forever.
pub const FILL_DEADLINE: Duration = Duration::from_secs(60);

/// The connect options every serving connection uses: the URL's, plus the two
/// timeouts.
///
/// # Errors
///
/// The URL does not parse.
pub fn serving_options(url: &str) -> Result<PgConnectOptions, sqlx::Error> {
    let options: PgConnectOptions = url.parse()?;
    Ok(options.options([
        (
            "statement_timeout",
            format!("{}ms", STATEMENT_TIMEOUT.as_millis()),
        ),
        (
            "idle_in_transaction_session_timeout",
            format!("{}ms", IDLE_IN_TRANSACTION_TIMEOUT.as_millis()),
        ),
    ]))
}

/// Open the serving pool and wait until every connection is open.
///
/// The pool fills itself: with no idle timeout and no lifetime, sqlx's
/// maintenance task opens `min_connections` at creation. Waiting for that,
/// rather than acquiring connections to force them open, avoids sqlx
/// cancelling an open at its acquire deadline, which livelocks under load
/// (#90).
///
/// # Errors
///
/// [`sqlx::Error::PoolTimedOut`] if the pool is not full within
/// [`FILL_DEADLINE`].
pub async fn open(
    options: PgConnectOptions,
    settings: crate::config::PoolSettings,
) -> Result<PgPool, sqlx::Error> {
    let size = settings.max_connections;
    let pool = PgPoolOptions::new()
        .max_connections(size)
        .min_connections(size)
        .idle_timeout(None)
        .max_lifetime(None)
        .test_before_acquire(true)
        .acquire_timeout(settings.acquire_timeout)
        .connect_lazy_with(options);
    let started = tokio::time::Instant::now();
    while pool.size() < size {
        if started.elapsed() > FILL_DEADLINE {
            tracing::error!(open = pool.size(), size, "the serving pool did not fill");
            return Err(sqlx::Error::PoolTimedOut);
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    tracing::info!(
        size,
        opened_ms = started.elapsed().as_millis() as u64,
        "serving pool open"
    );
    Ok(pool)
}

/// Why the database's schema does not match this build.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SchemaError {
    /// A migration this build embeds has not been applied.
    #[error(
        "the database is behind this build: migration {version} ({description}) is not applied; \
         run `control-plane migrate` first"
    )]
    Behind { version: i64, description: String },
    /// A migration was recorded as failed.
    #[error("migration {version} is recorded as failed; repair the database before starting")]
    Failed { version: i64 },
    /// An applied migration's checksum differs from the embedded one: the
    /// file was edited after it ran.
    #[error("migration {version} was applied with different contents than this build embeds")]
    Changed { version: i64 },
    /// The migrations table could not be read.
    #[error("reading the applied migrations: {0}")]
    Db(#[from] sqlx::Error),
}

/// Refuse a database that is behind this build, and allow one that is ahead.
///
/// Behind means a query this build runs may name a column that does not exist
/// yet, so the instance must not start. Ahead is the normal state during a
/// rollout, when migrations ran for the next build before this one stopped:
/// migrations here are additive, so the old build keeps working. That is
/// logged, once.
///
/// # Errors
///
/// [`SchemaError`], naming the first migration that disagrees.
pub async fn check_schema(
    connection: &mut PgConnection,
    migrator: &Migrator,
) -> Result<(), SchemaError> {
    let applied: Vec<(i64, bool, Vec<u8>)> = match sqlx::query_as(
        "select version, success, checksum from _sqlx_migrations order by version",
    )
    .fetch_all(&mut *connection)
    .await
    {
        Ok(rows) => rows,
        // No migrations table at all: nothing is applied.
        Err(sqlx::Error::Database(e)) if e.code().as_deref() == Some("42P01") => Vec::new(),
        Err(e) => return Err(e.into()),
    };
    if let Some((version, ..)) = applied.iter().find(|(_, success, _)| !success) {
        return Err(SchemaError::Failed { version: *version });
    }
    let embedded: Vec<_> = migrator
        .iter()
        .filter(|m| !m.migration_type.is_down_migration())
        .collect();
    for migration in &embedded {
        match applied.iter().find(|(v, ..)| *v == migration.version) {
            None => {
                return Err(SchemaError::Behind {
                    version: migration.version,
                    description: migration.description.to_string(),
                });
            }
            Some((_, _, checksum)) if *checksum != *migration.checksum => {
                return Err(SchemaError::Changed {
                    version: migration.version,
                });
            }
            Some(_) => {}
        }
    }
    let ahead: Vec<i64> = applied
        .iter()
        .map(|(v, ..)| *v)
        .filter(|v| embedded.iter().all(|m| m.version != *v))
        .collect();
    if !ahead.is_empty() {
        tracing::warn!(
            ?ahead,
            "the database has migrations this build does not know; continuing, since migrations are additive"
        );
    }
    Ok(())
}

/// Apply every pending migration in `migrator`, over a connection without the
/// serving pool's timeouts.
///
/// # Errors
///
/// Connecting or migrating failed.
pub async fn migrate(url: &str, migrator: &Migrator) -> Result<(), sqlx::migrate::MigrateError> {
    // Plain options from the URL: the serving timeouts would end a long
    // migration halfway (#48).
    let options: PgConnectOptions = url.parse()?;
    let mut connection = options.connect().await?;
    migrator.run(&mut connection).await?;
    connection.close().await?;
    Ok(())
}
