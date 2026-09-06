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

use crate::ids::{AppId, OrgId, UserId, VersionId};
use chrono::{DateTime, Utc};
use sqlx::PgExecutor;

/// An organisation. `slug` is the org half of `{app}.{org}.clwd.run` and is
/// immutable once set — the database enforces that with a trigger, because a
/// reassignable subdomain is handed a browser's still-live cookie.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Org {
    pub id: OrgId,
    pub slug: String,
    pub created_at: DateTime<Utc>,
    pub deleted_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct User {
    pub id: UserId,
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
    pub id: AppId,
    pub org_id: OrgId,
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
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct AppVersion {
    pub id: VersionId,
    pub app_id: AppId,
    pub digest: String,
    pub state: String,
    pub created_at: DateTime<Utc>,
}

pub async fn create_org(ex: impl PgExecutor<'_>, slug: &str) -> sqlx::Result<Org> {
    sqlx::query_as!(
        Org,
        r#"insert into orgs (id, slug) values ($1, $2)
           returning id, slug, created_at, deleted_at"#,
        OrgId::new().as_uuid(),
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
        UserId::new().as_uuid(),
        email,
    )
    .fetch_one(ex)
    .await
}

/// Records that a user belongs to an org. Membership only: what a member may
/// do is a Cedar policy (#14), not a column here.
pub async fn add_org_member(
    ex: impl PgExecutor<'_>,
    org_id: OrgId,
    user_id: UserId,
) -> sqlx::Result<()> {
    sqlx::query!(
        "insert into org_members (org_id, user_id) values ($1, $2)",
        org_id.as_uuid(),
        user_id.as_uuid(),
    )
    .execute(ex)
    .await
    .map(|_| ())
}

pub async fn create_app(
    ex: impl PgExecutor<'_>,
    org_id: OrgId,
    name: &str,
    runtime: &str,
) -> sqlx::Result<App> {
    sqlx::query_as!(
        App,
        r#"insert into apps (id, org_id, name, runtime) values ($1, $2, $3, $4)
           returning id, org_id, name, runtime, created_at, deleted_at"#,
        AppId::new().as_uuid(),
        org_id.as_uuid(),
        name,
        runtime,
    )
    .fetch_one(ex)
    .await
}

/// The outcome of claiming `(app_id, digest)`.
///
/// Which arm you get is decided by whether the `INSERT` returned a row, not by
/// a prior `SELECT`. A read-then-write would be a race wearing an
/// optimisation's clothes: two requests could both read "absent" and both
/// proceed. The insert *is* the atomic answer, and this type carries it out of
/// the query so a caller cannot re-derive it wrongly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Claim {
    /// This request won the digest and owes the artifact write.
    Won(AppVersion),
    /// Someone already holds it — this request, earlier, or another one now.
    ///
    /// Not an error. With a content address, the same bytes are the same
    /// version by construction, so this is what a retry looks like.
    Held(AppVersion),
}

impl Claim {
    /// The version row, whichever way the claim went.
    #[must_use]
    pub fn version(&self) -> &AppVersion {
        match self {
            Self::Won(v) | Self::Held(v) => v,
        }
    }

    /// Whether this request created the row.
    #[must_use]
    pub fn was_created(&self) -> bool {
        matches!(self, Self::Won(_))
    }
}

/// Claims `(app_id, digest)` for a live app, or reports who already holds it.
///
/// # The four lines that make the index a concurrency primitive
///
/// `#1` shipped the unique index on `(app_id, digest)`; until now the query
/// was a plain `INSERT`, so a duplicate was a unique-violation *error* rather
/// than the answer. `ON CONFLICT DO NOTHING ... RETURNING` turns the same
/// index into the thing that decides a race: exactly one concurrent inserter
/// gets a row back, every other gets none, and no lock is involved.
///
/// # The app check rides along in the same statement
///
/// `insert ... select ... from apps where id = $2 and deleted_at is null`
/// rather than a `SELECT` first. The foreign key already rejects an app that
/// does not exist, but it cannot see `deleted_at` — so a plain insert would
/// happily publish into a deleted app. Folding the predicate into the source
/// query keeps that check atomic with the claim.
///
/// # Why zero rows is ambiguous, and why that is fine
///
/// An empty result means *either* the conflict fired *or* no live app matched.
/// Those need different answers — a conflict is a success, a missing app is a
/// 404 — so the caller disambiguates with [`app_version_by_digest`]. That
/// second query is a read, but it is not a race: it runs only on the path
/// where this request is not the one making progress, and both possible
/// answers are stable by the time it runs.
///
/// # Errors
///
/// Propagates whatever the driver reports. A foreign-key violation cannot
/// occur here — the `select` yields no row for an unknown app rather than
/// offering one the constraint would reject.
pub async fn claim_app_version(
    ex: impl PgExecutor<'_>,
    app_id: AppId,
    digest: &str,
) -> sqlx::Result<Option<AppVersion>> {
    sqlx::query_as!(
        AppVersion,
        r#"insert into app_versions (id, app_id, digest)
           select $1, id, $3 from apps where id = $2 and deleted_at is null
           on conflict (app_id, digest) do nothing
           returning id, app_id, digest, state, created_at"#,
        VersionId::new().as_uuid(),
        app_id.as_uuid(),
        digest,
    )
    .fetch_optional(ex)
    .await
}

/// The existing version for `(app_id, digest)`, if there is one.
///
/// Only called after [`claim_app_version`] returns nothing, to tell a conflict
/// apart from an app that does not exist or has been deleted.
///
/// # Errors
///
/// Propagates whatever the driver reports.
pub async fn app_version_by_digest(
    ex: impl PgExecutor<'_>,
    app_id: AppId,
    digest: &str,
) -> sqlx::Result<Option<AppVersion>> {
    sqlx::query_as!(
        AppVersion,
        r#"select id, app_id, digest, state, created_at from app_versions
           where app_id = $1 and digest = $2"#,
        app_id.as_uuid(),
        digest,
    )
    .fetch_optional(ex)
    .await
}

/// Marks a version `ready`, which is what the caller does once the artifact is
/// stored under its digest.
pub async fn mark_app_version_ready(
    ex: impl PgExecutor<'_>,
    id: VersionId,
) -> sqlx::Result<AppVersion> {
    sqlx::query_as!(
        AppVersion,
        r#"update app_versions set state = 'ready' where id = $1
           returning id, app_id, digest, state, created_at"#,
        id.as_uuid(),
    )
    .fetch_one(ex)
    .await
}
