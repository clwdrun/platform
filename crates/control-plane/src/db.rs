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

use crate::ids::{AppId, OrgId, TokenId, UserId, VersionId};
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
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, utoipa::ToSchema)]
pub struct AppVersion {
    /// The version's id.
    #[schema(value_type = String, format = Uuid)]
    pub id: VersionId,
    /// The app it is a version of.
    #[schema(value_type = String, format = Uuid)]
    pub app_id: AppId,
    /// The bundle's content address: `blake3:` and 64 lowercase hex characters.
    /// The same bytes always have the same digest, which is what makes
    /// publishing idempotent.
    #[schema(pattern = "^blake3:[0-9a-f]{64}$")]
    pub digest: String,
    /// `pending` while the artifact is being stored, `ready` once it is. A
    /// successful publish always returns `ready`.
    pub state: String,
    /// When the version was first published.
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

/// Resolve `{app}.{org}` to the live app it names, for the gateway's host
/// router. `None` when the org or the app does not exist, is soft-deleted, or
/// the app is not that org's — the three cases the gateway answers with a 404,
/// deliberately indistinguishable to a caller.
pub async fn resolve_app(
    ex: impl PgExecutor<'_>,
    org_slug: &str,
    app_name: &str,
) -> sqlx::Result<Option<App>> {
    sqlx::query_as!(
        App,
        r#"select a.id, a.org_id, a.name, a.runtime, a.created_at, a.deleted_at
           from apps a
           join orgs o on o.id = a.org_id
           where o.slug = $1 and o.deleted_at is null
             and a.name = $2 and a.deleted_at is null"#,
        org_slug,
        app_name,
    )
    .fetch_optional(ex)
    .await
}

/// The certificate lifecycle row for an org: its state and, when issuing, the
/// in-flight ACME order URL. Holds no key material — the certificate and key
/// live in the [`shared::cert::CertStore`]. See `migrations/*_certificates.sql`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertRecord {
    pub state: String,
    pub order_url: Option<String>,
}

/// The certificate row for `org`, or `None` if issuance has never begun. The
/// issuer reads this to decide whether to RESUME an in-flight order
/// (`order_url` present) or start a fresh one — resuming is what keeps a retry
/// during an outage from burning the new-certificate rate limit.
pub async fn cert_record(
    ex: impl PgExecutor<'_>,
    org_id: OrgId,
) -> sqlx::Result<Option<CertRecord>> {
    sqlx::query_as!(
        CertRecord,
        r#"select state, order_url from certificates where org_id = $1"#,
        org_id.as_uuid(),
    )
    .fetch_optional(ex)
    .await
}

/// Record that issuance is in flight for `org`, persisting the ACME order URL so
/// a later attempt resumes it. Idempotent: repeated calls (a retry) update the
/// URL in place rather than failing on the primary key.
///
/// A row the reconciler already claimed (`renewing`) keeps that state: the
/// claim is what the stale-reclaim arm of [`claim_due_for_renewal`] looks for,
/// so clobbering it back to `pending` here would hide an in-flight renewal
/// from the very query that recovers it after a crash.
pub async fn cert_mark_pending(
    ex: impl PgExecutor<'_>,
    org_id: OrgId,
    order_url: &str,
) -> sqlx::Result<()> {
    sqlx::query!(
        r#"insert into certificates (org_id, state, order_url)
           values ($1, 'pending', $2)
           on conflict (org_id) do update
             set order_url = $2, last_renewal_error = null,
                 state = case when certificates.state = 'renewing'
                              then 'renewing' else 'pending' end"#,
        org_id.as_uuid(),
        order_url,
    )
    .execute(ex)
    .await
    .map(|_| ())
}

/// Mark `org`'s certificate issued and clear the in-flight order: the
/// certificate itself is already in the store, this records the lifecycle state
/// the renewal reconciler reads.
pub async fn cert_mark_issued(
    ex: impl PgExecutor<'_>,
    org_id: OrgId,
    not_after: DateTime<Utc>,
    ari_renewal_after: DateTime<Utc>,
) -> sqlx::Result<()> {
    sqlx::query!(
        r#"update certificates
             set state = 'issued', order_url = null,
                 not_after = $2, ari_renewal_after = $3,
                 last_renewal_attempt = now(), last_renewal_error = null
           where org_id = $1"#,
        org_id.as_uuid(),
        not_after,
        ari_renewal_after,
    )
    .execute(ex)
    .await
    .map(|_| ())
}

/// An org the renewal reconciler claimed: due for renewal and marked
/// `renewing` in the same statement (see [`claim_due_for_renewal`]). The slug
/// is what the driver needs to find the stored certificate and to build the
/// `_acme-challenge` name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DueCert {
    pub org_id: OrgId,
    pub slug: String,
}

/// Claim up to `limit` certificates due for renewal, marking each `renewing`.
///
/// Due means one of three things: `issued` with `ari_renewal_after` passed
/// (its time has come); `renewing` with no attempt since `stale_after` (a
/// worker died between the claim commit and `cert_mark_issued`, and the row
/// must re-enter rotation rather than strand — the next pass resumes it via
/// `order_url`, the same shape as #7's pending rows being finished by a later
/// attempt); or `failed` with no attempt since `retry_after` (a transient
/// failure gets another try, with a backoff that respects the
/// 5-failed-validations-per-identifier-per-hour budget).
///
/// Orgs that are soft-deleted are never claimed: there is nothing left to serve
/// under their names.
///
/// `pending` rows are NOT claimed: they belong to the creation path's direct
/// `issue()` call, which drives them synchronously. No production caller mints
/// `pending` today; when issuance is wired into org creation, extend this
/// claim (or that path's retry) to resume them — until then, a crashed direct
/// issuance would strand `pending`, which is why new callers must go through
/// this claim rather than calling `issue`/`renew` directly.
///
/// # Why `FOR UPDATE SKIP LOCKED`, not an advisory lock
///
/// An advisory lock serialises the whole reconciler — every worker queues
/// behind one global lock and renewals proceed one cert at a time. `SKIP
/// LOCKED` locks only the rows this claim takes, so workers on several nodes
/// proceed in parallel over disjoint sets. The failed-validation budget is per
/// identifier (per cert), so per-row is exactly the granularity the guarantee
/// needs: two workers can never drive the same cert concurrently, and neither
/// blocks the other.
///
/// # Why the transaction is short
///
/// Selection, locking and marking happen in a single statement, which commits
/// before issuance runs — so the row locks release with it and the slow work
/// (DNS writes, ACME polling) never holds a database transaction open. A crash
/// after the mark leaves a `renewing` row with no worker, reclaimed by the
/// stale arm above rather than stranded.
pub async fn claim_due_for_renewal(
    pool: &sqlx::PgPool,
    limit: i64,
    stale_after_secs: i64,
    retry_after_secs: i64,
) -> sqlx::Result<Vec<DueCert>> {
    let ids = sqlx::query_scalar!(
        r#"with due as (
               select c.org_id as org_id
               from certificates as c
               join orgs as o on o.id = c.org_id and o.deleted_at is null
               where (c.state = 'issued'
                      and c.ari_renewal_after <= now())
                  or (c.state = 'renewing'
                      and c.last_renewal_attempt
                          < now() - ($2::bigint * interval '1 second'))
                  or (c.state = 'failed'
                      and c.last_renewal_attempt
                          < now() - ($3::bigint * interval '1 second'))
               order by c.ari_renewal_after nulls last
               limit $1
               for update of c skip locked
           )
           update certificates as c
              set state = 'renewing',
                  last_renewal_attempt = now(),
                  last_renewal_error = null
             from due
            where c.org_id = due.org_id
        returning c.org_id as "org_id: OrgId""#,
        limit,
        stale_after_secs,
        retry_after_secs,
    )
    .fetch_all(pool)
    .await?;

    // The slugs the driver needs. A second read, not the same statement: the
    // rows are already marked, so no lock is needed — and an org deleted
    // between the claim and this read simply yields no slug, which the driver
    // retires visibly rather than driving blind.
    let uuids: Vec<uuid::Uuid> = ids.iter().map(|id| id.as_uuid()).collect();
    let slugs = sqlx::query!(
        r#"select id as "id: OrgId", slug from orgs
            where id = any($1) and deleted_at is null"#,
        &uuids,
    )
    .fetch_all(pool)
    .await?;

    Ok(slugs
        .into_iter()
        .map(|row| DueCert {
            org_id: row.id,
            slug: row.slug,
        })
        .collect())
}

/// Record that issuance or renewal failed, visibly. A silent failure is an
/// outage with no deploy behind it, so the error is stored for the reconciler
/// and an operator to see. The order URL is kept so the failure can be resumed.
pub async fn cert_mark_failed(
    ex: impl PgExecutor<'_>,
    org_id: OrgId,
    error: &str,
) -> sqlx::Result<()> {
    sqlx::query!(
        r#"insert into certificates (org_id, state, last_renewal_attempt, last_renewal_error)
           values ($1, 'failed', now(), $2)
           on conflict (org_id) do update
             set state = 'failed', last_renewal_attempt = now(), last_renewal_error = $2"#,
        org_id.as_uuid(),
        error,
    )
    .execute(ex)
    .await
    .map(|_| ())
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
///
/// # The org rides along too
///
/// `org_id` is the caller's org, from their token. An app in another org
/// yields no row exactly as an app that does not exist does, so a token cannot
/// learn that another org's app is real — and the check costs no extra query.
pub async fn claim_app_version(
    ex: impl PgExecutor<'_>,
    org_id: OrgId,
    app_id: AppId,
    digest: &str,
) -> sqlx::Result<Option<AppVersion>> {
    sqlx::query_as!(
        AppVersion,
        r#"insert into app_versions (id, app_id, digest)
           select $1, id, $3 from apps
           where id = $2 and org_id = $4 and deleted_at is null
           on conflict (app_id, digest) do nothing
           returning id, app_id, digest, state, created_at"#,
        VersionId::new().as_uuid(),
        app_id.as_uuid(),
        digest,
        org_id.as_uuid(),
    )
    .fetch_optional(ex)
    .await
}

/// The existing version for `(app_id, digest)`, if there is one and the app
/// is live and in `org_id`.
///
/// Only called after [`claim_app_version`] returns nothing, to tell a conflict
/// apart from an app that does not exist, has been deleted, or belongs to
/// another org.
///
/// **Scoped by the same predicate as the claim, deliberately.** Without it an
/// org mismatch fails the claim and then succeeds here, and the caller is
/// handed another org's version row — the claim's check undone by the read
/// that follows it.
///
/// # Errors
///
/// Propagates whatever the driver reports.
pub async fn app_version_by_digest(
    ex: impl PgExecutor<'_>,
    org_id: OrgId,
    app_id: AppId,
    digest: &str,
) -> sqlx::Result<Option<AppVersion>> {
    sqlx::query_as!(
        AppVersion,
        r#"select v.id, v.app_id, v.digest, v.state, v.created_at
           from app_versions v
           join apps a on a.id = v.app_id
           where v.app_id = $1 and v.digest = $2
             and a.org_id = $3 and a.deleted_at is null"#,
        app_id.as_uuid(),
        digest,
        org_id.as_uuid(),
    )
    .fetch_optional(ex)
    .await
}

/// A live token, as verification sees it.
///
/// `scopes` is the column's names; [`crate::auth`] parses them. The secret is
/// not here and never is: the row is found *by* its digest, so there is
/// nothing to compare afterwards.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenGrant {
    pub id: TokenId,
    pub org_id: OrgId,
    pub app_id: Option<AppId>,
    pub scopes: Vec<String>,
}

/// Records a token under its digest, if the org is live and any app binding
/// names a live app in that org. `None` otherwise.
///
/// The liveness checks are folded into the insert, as the claim above does,
/// rather than read first: a separate read would be a race with a delete.
///
/// # Errors
///
/// Propagates whatever the driver reports, including the `api_tokens`
/// constraints if a caller skipped validating the name or the scopes.
pub async fn insert_token(
    ex: impl PgExecutor<'_>,
    org_id: OrgId,
    app_id: Option<AppId>,
    name: &str,
    digest: &[u8; 32],
    scopes: &[String],
) -> sqlx::Result<Option<TokenId>> {
    sqlx::query_scalar!(
        r#"insert into api_tokens (id, org_id, app_id, name, secret_sha256, scopes)
           select $1, $2, $3, $4, $5, $6
           where exists (select 1 from orgs where id = $2 and deleted_at is null)
             and ($3::uuid is null or exists (
                   select 1 from apps where id = $3 and org_id = $2 and deleted_at is null))
           returning id as "id: TokenId""#,
        TokenId::new().as_uuid(),
        org_id.as_uuid(),
        app_id.map(|app| app.as_uuid()),
        name,
        &digest[..],
        scopes,
    )
    .fetch_optional(ex)
    .await
}

/// The live token with this digest.
///
/// # One outcome for every failure
///
/// Unknown, revoked, belonging to a deleted org, bound to a deleted app: all
/// `None`, from one query with one shape. There is no "found, but wrong" path
/// to take a different amount of time or return a different error — the
/// absent-not-denied property of `clwdrun/clwd#56`, applied to credentials.
///
/// # Errors
///
/// Propagates whatever the driver reports. The caller must treat an error as
/// a denial, never as a pass.
pub async fn token_by_digest(
    ex: impl PgExecutor<'_>,
    digest: &[u8; 32],
) -> sqlx::Result<Option<TokenGrant>> {
    sqlx::query_as!(
        TokenGrant,
        r#"select t.id, t.org_id, t.app_id as "app_id: AppId", t.scopes
           from api_tokens t
           where t.secret_sha256 = $1
             and t.revoked_at is null
             and exists (select 1 from orgs o where o.id = t.org_id and o.deleted_at is null)
             and (t.app_id is null or exists (
                   select 1 from apps a where a.id = t.app_id and a.deleted_at is null))"#,
        &digest[..],
    )
    .fetch_optional(ex)
    .await
}

/// Revokes a token in `org_id`, and within `app_id` when the revoker is bound
/// to one. `true` if the token exists within that reach.
///
/// Revoking twice is revoking once: `coalesce` keeps the first timestamp,
/// which is the one #30 needs, and the second call still reports success.
///
/// # Errors
///
/// Propagates whatever the driver reports.
pub async fn revoke_token(
    ex: impl PgExecutor<'_>,
    id: TokenId,
    org_id: OrgId,
    app_id: Option<AppId>,
) -> sqlx::Result<bool> {
    sqlx::query_scalar!(
        r#"update api_tokens set revoked_at = coalesce(revoked_at, now())
           where id = $1 and org_id = $2 and ($3::uuid is null or app_id = $3)
           returning id"#,
        id.as_uuid(),
        org_id.as_uuid(),
        app_id.map(|app| app.as_uuid()),
    )
    .fetch_optional(ex)
    .await
    .map(|row| row.is_some())
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
