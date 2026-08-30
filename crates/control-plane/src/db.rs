//! Row types for the core schema, and the queries that produce them.
//!
//! Identifiers are UUIDv7 minted here rather than by the database: the caller
//! needs the id before the INSERT so that idempotent publish (#7) can claim a
//! digest and reference the row it is claiming in one round trip.
//!
//! Timestamps come from the database. `now()` is transaction-start time, so an
//! app row and its first version row written in one transaction share one, and
//! a control plane running on several nodes has one clock its writers already
//! agree on rather than several that drift.

use chrono::{DateTime, Utc};
use sqlx::PgExecutor;
use uuid::Uuid;

/// An organisation. `slug` is the org half of `{app}.{org}.clwd.run` and is
/// immutable once set — the database enforces that with a trigger, because a
/// reassignable subdomain is handed a browser's still-live cookie.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Org {
    pub id: Uuid,
    pub slug: String,
    pub created_at: DateTime<Utc>,
    pub deleted_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct User {
    pub id: Uuid,
    pub email: String,
    pub created_at: DateTime<Utc>,
    pub deleted_at: Option<DateTime<Utc>>,
}

/// An app.
///
/// `runtime` is a `String`, not an enum, and that is deliberate. The value is
/// `"wasm"` or `"microvm"` — exactly `clwd_bundle::Runtime::as_str()` — and it
/// exists to be stored, passed and displayed. Nothing above `clwd-runtime`
/// matches on it to choose a code path; a `Sandbox` implementation does. An
/// enum here would make that match one keystroke away instead of a decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct App {
    pub id: Uuid,
    pub org_id: Uuid,
    pub name: String,
    pub runtime: String,
    pub created_at: DateTime<Utc>,
    pub deleted_at: Option<DateTime<Utc>>,
}

/// A published version of an app, addressed by the digest of its bundle.
///
/// The row is written `pending` before the artifact is stored and marked
/// `ready` after — see the migration for why that ordering is the one that
/// makes a crash mid-publish visible instead of leaving an orphan artifact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppVersion {
    pub id: Uuid,
    pub app_id: Uuid,
    pub digest: String,
    pub state: String,
    pub created_at: DateTime<Utc>,
}

pub async fn create_org(ex: impl PgExecutor<'_>, slug: &str) -> sqlx::Result<Org> {
    sqlx::query_as!(
        Org,
        r#"insert into orgs (id, slug) values ($1, $2)
           returning id, slug, created_at, deleted_at"#,
        Uuid::now_v7(),
        slug,
    )
    .fetch_one(ex)
    .await
}

pub async fn org_by_slug(ex: impl PgExecutor<'_>, slug: &str) -> sqlx::Result<Option<Org>> {
    sqlx::query_as!(
        Org,
        r#"select id, slug, created_at, deleted_at from orgs
           where slug = $1 and deleted_at is null"#,
        slug,
    )
    .fetch_optional(ex)
    .await
}

pub async fn create_user(ex: impl PgExecutor<'_>, email: &str) -> sqlx::Result<User> {
    sqlx::query_as!(
        User,
        r#"insert into users (id, email) values ($1, $2)
           returning id, email, created_at, deleted_at"#,
        Uuid::now_v7(),
        email,
    )
    .fetch_one(ex)
    .await
}

/// Records that a user belongs to an org. Membership only: what a member may
/// do is a Cedar policy (#14), not a column here.
pub async fn add_org_member(
    ex: impl PgExecutor<'_>,
    org_id: Uuid,
    user_id: Uuid,
) -> sqlx::Result<()> {
    sqlx::query!(
        "insert into org_members (org_id, user_id) values ($1, $2)",
        org_id,
        user_id,
    )
    .execute(ex)
    .await
    .map(|_| ())
}

pub async fn create_app(
    ex: impl PgExecutor<'_>,
    org_id: Uuid,
    name: &str,
    runtime: &str,
) -> sqlx::Result<App> {
    sqlx::query_as!(
        App,
        r#"insert into apps (id, org_id, name, runtime) values ($1, $2, $3, $4)
           returning id, org_id, name, runtime, created_at, deleted_at"#,
        Uuid::now_v7(),
        org_id,
        name,
        runtime,
    )
    .fetch_one(ex)
    .await
}

/// Inserts a `pending` version row for a digest.
///
/// Rejects a second row for the same `(app_id, digest)` on the unique index.
/// Converting that rejection into "this digest was already published, here is
/// the existing version" is idempotent publish, and belongs to #7 — this is
/// only the row the index is built on.
pub async fn create_app_version(
    ex: impl PgExecutor<'_>,
    app_id: Uuid,
    digest: &str,
) -> sqlx::Result<AppVersion> {
    sqlx::query_as!(
        AppVersion,
        r#"insert into app_versions (id, app_id, digest) values ($1, $2, $3)
           returning id, app_id, digest, state, created_at"#,
        Uuid::now_v7(),
        app_id,
        digest,
    )
    .fetch_one(ex)
    .await
}

/// Marks a version `ready`, which is what the caller does once the artifact is
/// stored under its digest.
pub async fn mark_app_version_ready(ex: impl PgExecutor<'_>, id: Uuid) -> sqlx::Result<AppVersion> {
    sqlx::query_as!(
        AppVersion,
        r#"update app_versions set state = 'ready' where id = $1
           returning id, app_id, digest, state, created_at"#,
        id,
    )
    .fetch_one(ex)
    .await
}
