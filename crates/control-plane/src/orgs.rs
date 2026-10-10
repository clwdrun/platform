//! Which org a signed-in person belongs to (#10).
//!
//! Every later authorization decision — per-request authz (#12), Cedar
//! entities (#14), grants (#15), revocation (#17) — hangs off `org_members`.
//! So the rule for writing a row there is narrow, and every ambiguous case
//! resolves toward **not** joining: a join can be granted later, an unwanted
//! one cannot be un-seen.
//!
//! # The rule, evaluated at every sign-in ([`resolve_at_sign_in`])
//!
//! Orgs are matched on Google's hosted-domain claim (`hd`) **only**, never on
//! the email's domain.
//!
//! - **No `hd`** — a consumer Google account, gmail or otherwise. Joins
//!   nothing; gets a personal org. This includes a consumer account registered
//!   as `bob@acme.com`: Google verified that address once, when the account
//!   was made, and the address's ownership may since have changed. The email
//!   domain is not evidence of anything.
//! - **`hd` present, no org holds that domain** — a personal org. The person
//!   may *claim* the domain ([`start_claim`]), which takes DNS proof. Binding
//!   the domain on first sign-in would make the first `acme.com` account to
//!   arrive — a contractor, a temp — the founder and owner of Acme's org and
//!   its slug.
//! - **`hd` matches a DNS-verified domain with auto-join on** — joins that org,
//!   and gets no personal org. Auto-join is off unless the person who proved
//!   control turned it on.
//! - **`hd` matches a verified domain with auto-join off** — a personal org;
//!   joining is by invitation (#16).
//! - **`hd` differs from the email's domain** — `hd` is trusted and the email
//!   domain ignored. (What `hd` carries for a Workspace *secondary* domain is
//!   not documented by Google; if it is the primary domain, an org that
//!   verified only the secondary domain matches nobody, which fails safe.)
//!
//! # Why `hd` presence and not a free-mail blocklist
//!
//! The free-mail rule ("a gmail user never auto-joins anything") is enforced
//! by `hd` being absent, not by a list of free-mail domains. Google sets `hd`
//! only for accounts in a managed Workspace tenant, so its absence identifies
//! every consumer account without enumerating providers. A blocklist is
//! incomplete on day one, misses every regional provider, and could never
//! catch `bob@acme.com` on a consumer account at all — a missed entry is a
//! breach. **Do not "simplify" this into a blocklist.** The one list here,
//! [`CLAIM_REFUSED_DOMAINS`], is an extra layer on *claims* only.
//!
//! # Sync and removal
//!
//! At each sign-in, `domain` and `claimant` memberships in orgs whose verified
//! domains do not include the person's current `hd` are hard-deleted (#1 made
//! `org_members` a hard delete: a tombstone is a row a buggy query can
//! resurrect into access). Each removal is a [`MEMBERSHIP_REMOVED`] tracing
//! event — the record #30's audit log will take over. Personal and (later,
//! #16) invited memberships are never touched by sync.
//!
//! The claimant is removed too: "whoever proved DNS control" does not outlast
//! leaving the tenant, and an org whose claimant is gone has its auto-join
//! flag changed by an operator — the same as when they leave outright.
//!
//! An offboarded Workspace account cannot sign in at all, so sync never fires
//! for it: its live session lasts up to the session lifetime (24 hours), and
//! org API tokens it created live until revoked. Group sync through the
//! Directory API, which would close that, is its own issue.

use std::sync::Arc;

use async_trait::async_trait;
use identity::{DomainError, HostedDomain};
use serde::Serialize;
use shared::Error;
use shared::cert::OrgSlug;
use sqlx::PgPool;

use crate::auth::unavailable;
use crate::ids::{OrgId, UserId};

/// The name of the tracing event emitted for every membership removal, with
/// fields `org_id`, `user_id`, `reason` (`hd_mismatch` | `manual`) and `actor`
/// (a user id, or `system`). Fixed, because the audit log (#30) will read it.
pub const MEMBERSHIP_REMOVED: &str = "org_membership_removed";

/// Domains whose claim is refused outright: consumer mail domains no single
/// org can own.
///
/// **Not** what enforces the free-mail rule — `hd` absence does that (see the
/// module docs), and these domains never appear in `hd` anyway. This is a
/// second layer on the claim path only, against a DNS mistake on our side.
pub const CLAIM_REFUSED_DOMAINS: [&str; 2] = ["gmail.com", "googlemail.com"];

/// Personal-org slugs are `p-` and this many lowercase base32 characters.
const PERSONAL_SLUG_CHARS: usize = 10;
/// The prefix that marks a personal org's slug. A domain org may not use it,
/// so the two kinds of slug never overlap.
pub const PERSONAL_SLUG_PREFIX: &str = "p-";
/// How many random personal slugs are tried before giving up. 32^10 values
/// make even one collision implausible; the bound only keeps a defect finite.
const PERSONAL_SLUG_ATTEMPTS: usize = 5;
/// How long a domain claim stays verifiable. Long enough for a DNS change to
/// go through a customer's change control; an expired claim is inert.
pub const CLAIM_TTL: chrono::Duration = chrono::Duration::hours(72);
/// The label the verification TXT record sits under.
pub const VERIFY_LABEL: &str = "_clwd-verify";

/// How a membership came about. Stored as `org_members.joined_via`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum JoinedVia {
    /// The sole member of a personal org.
    Personal,
    /// Auto-joined through a verified domain.
    Domain,
    /// The person who verified the org's domain.
    Claimant,
}

impl JoinedVia {
    /// The column value.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Personal => "personal",
            Self::Domain => "domain",
            Self::Claimant => "claimant",
        }
    }
}

/// A domain someone asks to claim for a new org, normalised.
///
/// Its own type, not a [`HostedDomain`]: a claimed domain is caller input that
/// has proven nothing, `hd` is a Google assertion. [`ClaimedDomain::is_hosted_by`]
/// is the only comparison between them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimedDomain(String);

impl ClaimedDomain {
    /// Normalise `raw` and refuse the domains in [`CLAIM_REFUSED_DOMAINS`].
    ///
    /// # Errors
    ///
    /// `control-plane.invalid_request` for a malformed or refused domain.
    pub fn parse(raw: &str) -> Result<Self, Error> {
        let domain =
            identity::domain::normalize(raw).map_err(|e: DomainError| Error::InvalidRequest {
                what: format!("`{raw}` is not a usable domain: {e}"),
            })?;
        if CLAIM_REFUSED_DOMAINS.contains(&domain.as_str()) {
            return Err(Error::InvalidRequest {
                what: format!("`{domain}` is a consumer mail domain and cannot be claimed"),
            });
        }
        Ok(Self(domain))
    }

    /// The normalised domain.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Whether `hd` is this domain.
    #[must_use]
    pub fn is_hosted_by(&self, hd: &HostedDomain) -> bool {
        self.0 == hd.as_str()
    }
}

// ------------------------------------------------------------- sign-in ----

/// A membership sign-in sync removed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct Removal {
    pub org_id: OrgId,
    pub user_id: UserId,
}

/// What [`resolve_at_sign_in`] did. The database is the truth; this is for
/// logging.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Resolution {
    /// Orgs auto-joined through a verified domain.
    pub joined: Vec<OrgId>,
    /// Memberships removed because `hd` no longer matches.
    pub removed: Vec<Removal>,
    /// The personal org created, if one was.
    pub personal: Option<OrgId>,
}

/// Apply the org rule for `user` signing in with hosted domain `hd`.
///
/// In one transaction, holding the user row's lock so two concurrent sign-ins
/// of one person cannot race: remove `domain`/`claimant` memberships `hd` no
/// longer supports, auto-join any org that verified `hd` with auto-join on,
/// and create a personal org if the person then belongs to nothing at all.
/// Emits one [`MEMBERSHIP_REMOVED`] event per removal, after commit.
///
/// # Errors
///
/// [`unavailable`]'s mapping for a database failure;
/// `control-plane.internal` if no personal slug could be allocated.
pub async fn resolve_at_sign_in(
    pool: &PgPool,
    user: UserId,
    hd: Option<&HostedDomain>,
) -> Result<Resolution, Error> {
    let hd = hd.map(HostedDomain::as_str);
    let mut tx = pool.begin().await.map_err(unavailable)?;

    sqlx::query!(
        "select id from users where id = $1 for update",
        user.as_uuid()
    )
    .fetch_one(&mut *tx)
    .await
    .map_err(unavailable)?;

    // `d.domain = $2` with a null `$2` is never true, so a consumer sign-in
    // removes every membership that came through a domain.
    let removed = sqlx::query_scalar!(
        r#"delete from org_members m
            where m.user_id = $1
              and m.joined_via in ('domain', 'claimant')
              and not exists (select 1 from org_domains d
                               where d.org_id = m.org_id and d.domain = $2)
        returning m.org_id as "org_id: OrgId""#,
        user.as_uuid(),
        hd,
    )
    .fetch_all(&mut *tx)
    .await
    .map_err(unavailable)?;

    // The hd check: only a hosted domain joins anything. A consumer account
    // (`hd` absent) never reaches this insert.
    let joined = match hd {
        Some(hd) => sqlx::query_scalar!(
            r#"insert into org_members (org_id, user_id, joined_via)
               select d.org_id, $1, 'domain'
                 from org_domains d
                 join orgs o on o.id = d.org_id and o.deleted_at is null
                where d.domain = $2 and d.auto_join
               on conflict (org_id, user_id) do nothing
               returning org_id as "org_id: OrgId""#,
            user.as_uuid(),
            hd,
        )
        .fetch_all(&mut *tx)
        .await
        .map_err(unavailable)?,
        None => Vec::new(),
    };

    let belongs = sqlx::query_scalar!(
        r#"select exists (select 1 from org_members where user_id = $1) as "belongs!""#,
        user.as_uuid()
    )
    .fetch_one(&mut *tx)
    .await
    .map_err(unavailable)?;

    let personal = if belongs {
        None
    } else {
        Some(create_personal_org(&mut tx, user, personal_slug).await?)
    };

    tx.commit().await.map_err(unavailable)?;

    let removed: Vec<Removal> = removed
        .into_iter()
        .map(|org_id| Removal {
            org_id,
            user_id: user,
        })
        .collect();
    for removal in &removed {
        tracing::info!(
            name: MEMBERSHIP_REMOVED,
            org_id = %removal.org_id,
            user_id = %removal.user_id,
            reason = "hd_mismatch",
            actor = "system",
            "org membership removed",
        );
    }

    Ok(Resolution {
        joined,
        removed,
        personal,
    })
}

/// A fresh personal-org slug: `p-` and ten characters of lowercase base32.
/// Never derived from the person — every slug is published in a certificate
/// transparency log once the org has a certificate.
fn personal_slug() -> Result<String, Error> {
    const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
    let mut bytes = [0u8; PERSONAL_SLUG_CHARS];
    getrandom::fill(&mut bytes).map_err(|e| Error::Internal { source: e.into() })?;
    // 256 is a multiple of 32, so masking is unbiased.
    let tail: String = bytes
        .iter()
        .map(|b| char::from(ALPHABET[usize::from(b & 31)]))
        .collect();
    Ok(format!("{PERSONAL_SLUG_PREFIX}{tail}"))
}

async fn create_personal_org(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    user: UserId,
    mut next_slug: impl FnMut() -> Result<String, Error>,
) -> Result<OrgId, Error> {
    for _ in 0..PERSONAL_SLUG_ATTEMPTS {
        let slug = next_slug()?;
        // `on conflict do nothing`, not a caught unique violation: a violation
        // would abort the transaction, and this one also holds the user lock.
        let created = sqlx::query_scalar!(
            r#"insert into orgs (id, slug) values ($1, $2)
               on conflict (slug) do nothing
               returning id as "id: OrgId""#,
            OrgId::new().as_uuid(),
            slug,
        )
        .fetch_optional(&mut **tx)
        .await
        .map_err(unavailable)?;
        if let Some(org) = created {
            add_member(&mut **tx, org, user, JoinedVia::Personal).await?;
            return Ok(org);
        }
    }
    Err(Error::Internal {
        source: anyhow::anyhow!(
            "no free personal-org slug after {PERSONAL_SLUG_ATTEMPTS} attempts"
        ),
    })
}

async fn add_member(
    ex: impl sqlx::PgExecutor<'_>,
    org: OrgId,
    user: UserId,
    via: JoinedVia,
) -> Result<(), Error> {
    crate::db::add_org_member(ex, org, user, via)
        .await
        .map_err(unavailable)
}

// -------------------------------------------------------------- claims ----

/// What a claimant must publish to prove control of a domain.
#[derive(Debug, Clone, Serialize, utoipa::ToSchema)]
#[non_exhaustive]
pub struct Claim {
    /// The claim's id, for the verify call.
    #[schema(value_type = String, format = Uuid)]
    pub id: uuid::Uuid,
    /// The domain being claimed, normalised.
    pub domain: String,
    /// The slug the org will get on verification.
    pub slug: String,
    /// Whether people whose Google hosted domain is this domain will join the
    /// org automatically. Off unless asked for.
    pub auto_join: bool,
    /// The TXT record name to create.
    pub txt_name: String,
    /// The TXT record value to publish.
    pub txt_value: String,
    /// After this the claim cannot be verified; start a new one.
    pub expires_at: chrono::DateTime<chrono::Utc>,
}

/// Refuse a slug a domain org may not take, legibly, before anything is
/// written: malformed, personal-shaped, reserved or taken. Verification
/// re-checks taken (the insert) and reserved (the trigger) atomically.
async fn check_domain_slug(pool: &PgPool, raw: &str) -> Result<OrgSlug, Error> {
    let slug = OrgSlug::parse(raw).map_err(|_| Error::InvalidRequest {
        what: format!(
            "`{raw}` is not a valid org slug: 1–63 lowercase letters, digits and hyphens, \
             not starting or ending with a hyphen"
        ),
    })?;
    if slug.as_str().starts_with(PERSONAL_SLUG_PREFIX) {
        return Err(Error::InvalidRequest {
            what: format!(
                "org slugs starting with `{PERSONAL_SLUG_PREFIX}` are reserved for personal orgs"
            ),
        });
    }
    let row = sqlx::query!(
        r#"select exists (select 1 from reserved_slugs where slug = $1) as "reserved!",
                  exists (select 1 from orgs where slug = $1) as "taken!""#,
        slug.as_str()
    )
    .fetch_one(pool)
    .await
    .map_err(unavailable)?;
    if row.reserved {
        return Err(reserved(&slug));
    }
    if row.taken {
        return Err(taken(&slug));
    }
    Ok(slug)
}

fn reserved(slug: &OrgSlug) -> Error {
    Error::InvalidRequest {
        what: format!("the org slug `{}` is reserved", slug.as_str()),
    }
}

fn taken(slug: &OrgSlug) -> Error {
    Error::Conflict {
        what: format!(
            "the org slug `{}` is taken; slugs are never reused, so choose another",
            slug.as_str()
        ),
    }
}

fn already_verified(domain: &ClaimedDomain) -> Error {
    Error::Conflict {
        what: format!(
            "`{}` is already verified by an org; a verified domain is never moved \
             automatically — contact support",
            domain.as_str()
        ),
    }
}

/// The hosted domain `user` last signed in with.
async fn current_hd(pool: &PgPool, user: UserId) -> Result<Option<HostedDomain>, Error> {
    let raw = sqlx::query_scalar!(
        "select hosted_domain from users where id = $1 and deleted_at is null",
        user.as_uuid()
    )
    .fetch_optional(pool)
    .await
    .map_err(unavailable)?
    .flatten();
    Ok(raw.and_then(|raw| HostedDomain::parse(&raw).ok()))
}

/// Start claiming `domain` for a new org with slug `slug`.
///
/// The claimant must be signed in from a Workspace tenant for exactly this
/// domain (`hd`): `hd` alone would let any account in the tenant — a
/// contractor's — bind the company domain, so DNS proof follows in
/// [`verify_claim`]. Nothing is reserved until then.
///
/// # Errors
///
/// `identity.forbidden` if the claimant's hosted domain is not `domain`;
/// `control-plane.invalid_request` for a malformed, refused, reserved or
/// personal-shaped slug; `control-plane.conflict` for a taken slug or an
/// already-verified domain.
pub async fn start_claim(
    pool: &PgPool,
    claimant: UserId,
    domain: &ClaimedDomain,
    slug: &str,
    auto_join: bool,
) -> Result<Claim, Error> {
    if !current_hd(pool, claimant)
        .await?
        .is_some_and(|hd| domain.is_hosted_by(&hd))
    {
        return Err(Error::Forbidden {
            what: format!(
                "claiming `{}` requires signing in with a Google Workspace account in that domain",
                domain.as_str()
            ),
        });
    }
    let slug = check_domain_slug(pool, slug).await?;
    if domain_is_verified(pool, domain).await? {
        return Err(already_verified(domain));
    }

    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).map_err(|e| Error::Internal { source: e.into() })?;
    let token: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    let id = uuid::Uuid::now_v7();
    let expires_at = sqlx::query_scalar!(
        r#"insert into domain_claims (id, domain, claimant_id, slug, auto_join, token, expires_at)
           values ($1, $2, $3, $4, $5, $6, now() + ($7::bigint * interval '1 second'))
           returning expires_at"#,
        id,
        domain.as_str(),
        claimant.as_uuid(),
        slug.as_str(),
        auto_join,
        token,
        CLAIM_TTL.num_seconds(),
    )
    .fetch_one(pool)
    .await
    .map_err(unavailable)?;

    Ok(Claim {
        id,
        domain: domain.as_str().to_owned(),
        slug: slug.as_str().to_owned(),
        auto_join,
        txt_name: format!("{VERIFY_LABEL}.{}", domain.as_str()),
        txt_value: token,
        expires_at,
    })
}

async fn domain_is_verified(pool: &PgPool, domain: &ClaimedDomain) -> Result<bool, Error> {
    sqlx::query_scalar!(
        r#"select exists (select 1 from org_domains where domain = $1) as "verified!""#,
        domain.as_str()
    )
    .fetch_one(pool)
    .await
    .map_err(unavailable)
}

/// Looks up TXT records, for domain verification.
///
/// A trait with one production implementation ([`SystemTxtLookup`]) so tests
/// can answer without DNS, like [`crate::acme::DnsProvider`].
#[async_trait]
pub trait TxtLookup: Send + Sync {
    /// Every TXT string at `name`; empty when the name or the records do not
    /// exist.
    ///
    /// # Errors
    ///
    /// A message for the log when the lookup itself could not be made.
    async fn txt(&self, name: &str) -> Result<Vec<String>, String>;
}

/// [`TxtLookup`] through the system resolver.
pub struct SystemTxtLookup(hickory_resolver::TokioResolver);

impl SystemTxtLookup {
    /// A lookup through the system's resolver configuration.
    ///
    /// # Errors
    ///
    /// A message if the system resolver configuration cannot be read.
    pub fn new() -> Result<Self, String> {
        hickory_resolver::Resolver::builder_tokio()
            .and_then(hickory_resolver::ResolverBuilder::build)
            .map(Self)
            .map_err(|e| e.to_string())
    }
}

#[async_trait]
impl TxtLookup for SystemTxtLookup {
    async fn txt(&self, name: &str) -> Result<Vec<String>, String> {
        use hickory_resolver::proto::rr::rdata::TXT;
        match self.0.txt_lookup(name).await {
            Ok(lookup) => Ok(lookup
                .answers()
                .iter()
                .filter_map(|record| record.try_borrow::<TXT>())
                .map(|txt| {
                    txt.data()
                        .txt_data
                        .iter()
                        .map(|chunk| String::from_utf8_lossy(chunk).into_owned())
                        .collect::<String>()
                })
                .collect()),
            Err(e) if e.is_no_records_found() || e.is_nx_domain() => Ok(Vec::new()),
            Err(e) => Err(e.to_string()),
        }
    }
}

/// A newly created domain org and its certificate's state.
#[derive(Debug, Clone, Serialize, utoipa::ToSchema)]
#[non_exhaustive]
pub struct CreatedOrg {
    /// The org's id.
    #[schema(value_type = String, format = Uuid)]
    pub id: OrgId,
    /// The org's slug: `{app}.{slug}.clwd.run`. Immutable.
    pub slug: String,
    /// The verified domain.
    pub domain: String,
    /// Whether people whose hosted domain is this domain join automatically.
    pub auto_join: bool,
    /// The org's wildcard certificate.
    pub certificate: CertificateStatus,
}

/// Verify claim `claim_id` by its TXT record and create the org.
///
/// In order: the claim must be the caller's and unexpired; the caller must
/// still be signed in from the domain's tenant; the TXT record must carry the
/// claim's token. Then, in one transaction: the org is created with the
/// claimed slug, the domain bound to it, the claimant made a member, and a
/// `pending` certificate row written for the reconciler. **No certificate
/// authority is called here**, so a CA outage or a full rate-limit bucket
/// cannot fail org creation; the certificate follows asynchronously.
///
/// # Errors
///
/// `control-plane.not_found` for a claim that is not the caller's;
/// `control-plane.invalid_request` for an expired claim, a TXT record not yet
/// visible, or a slug that became reserved; `identity.forbidden` if the
/// caller's hosted domain changed; `control-plane.conflict` if the domain was
/// verified by someone else first or the slug was taken; `control-plane.timeout`
/// if DNS could not be queried.
pub async fn verify_claim(
    pool: &PgPool,
    lookup: &dyn TxtLookup,
    claimant: UserId,
    claim_id: uuid::Uuid,
) -> Result<CreatedOrg, Error> {
    let not_found = || Error::NotFound {
        what: format!("domain claim {claim_id}"),
    };
    let claim = sqlx::query!(
        r#"select domain, slug, auto_join, token, expires_at > now() as "live!"
             from domain_claims where id = $1 and claimant_id = $2"#,
        claim_id,
        claimant.as_uuid(),
    )
    .fetch_optional(pool)
    .await
    .map_err(unavailable)?
    .ok_or_else(not_found)?;
    if !claim.live {
        return Err(Error::InvalidRequest {
            what: "this domain claim has expired; start a new one".to_owned(),
        });
    }
    let domain = ClaimedDomain(claim.domain);
    let slug = OrgSlug::parse(&claim.slug).map_err(|_| not_found())?;
    if !current_hd(pool, claimant)
        .await?
        .is_some_and(|hd| domain.is_hosted_by(&hd))
    {
        return Err(Error::Forbidden {
            what: format!(
                "verifying `{}` requires signing in with a Google Workspace account in that domain",
                domain.as_str()
            ),
        });
    }

    let name = format!("{VERIFY_LABEL}.{}", domain.as_str());
    let records = lookup.txt(&name).await.map_err(|reason| {
        tracing::warn!(%reason, name, "TXT lookup failed");
        Error::Timeout {
            dependency: "DNS".to_owned(),
        }
    })?;
    if !records.iter().any(|value| value == &claim.token) {
        return Err(Error::InvalidRequest {
            what: format!(
                "no TXT record at `{name}` carries this claim's value yet; DNS changes can take a \
                 while to appear — retry the verification"
            ),
        });
    }

    let mut tx = pool.begin().await.map_err(unavailable)?;
    // Still there and still live, under lock: a claim is verified once.
    let still_live = sqlx::query_scalar!(
        r#"delete from domain_claims where id = $1 and expires_at > now() returning id"#,
        claim_id
    )
    .fetch_optional(&mut *tx)
    .await
    .map_err(unavailable)?;
    if still_live.is_none() {
        return Err(not_found());
    }
    let org = sqlx::query_scalar!(
        r#"insert into orgs (id, slug) values ($1, $2)
           on conflict (slug) do nothing
           returning id as "id: OrgId""#,
        OrgId::new().as_uuid(),
        slug.as_str(),
    )
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| match &e {
        sqlx::Error::Database(db) if db.code().as_deref() == Some("23001") => reserved(&slug),
        _ => unavailable(e),
    })?
    .ok_or_else(|| taken(&slug))?;
    let bound = sqlx::query!(
        r#"insert into org_domains (domain, org_id, claimant_id, auto_join)
           values ($1, $2, $3, $4)
           on conflict (domain) do nothing"#,
        domain.as_str(),
        org.as_uuid(),
        claimant.as_uuid(),
        claim.auto_join,
    )
    .execute(&mut *tx)
    .await
    .map_err(unavailable)?;
    if bound.rows_affected() == 0 {
        return Err(already_verified(&domain));
    }
    add_member(&mut *tx, org, claimant, JoinedVia::Claimant).await?;
    ensure_certificate_row(&mut *tx, org).await?;
    tx.commit().await.map_err(unavailable)?;

    Ok(CreatedOrg {
        id: org,
        slug: slug.as_str().to_owned(),
        domain: domain.as_str().to_owned(),
        auto_join: claim.auto_join,
        certificate: CertificateStatus::from_state(Some("pending"), false),
    })
}

/// The result of changing an org domain's auto-join flag.
#[derive(Debug, Clone, Serialize, utoipa::ToSchema)]
#[non_exhaustive]
pub struct DomainSetting {
    /// The verified domain.
    pub domain: String,
    /// The new value.
    pub auto_join: bool,
}

/// Turn auto-join on or off for `org`'s verified `domain`.
///
/// **Only the user who verified the domain may**, and only while still a
/// member. Until #14 brings roles there is no "admin" to defer to, and letting
/// any member do it would let a contractor who is already in open the org to
/// every other account in the tenant. If the claimant leaves, an operator
/// changes the flag.
///
/// # Errors
///
/// `identity.forbidden` for a member who is not the claimant;
/// `control-plane.not_found` for anyone else, or an unknown org or domain.
pub async fn set_auto_join(
    pool: &PgPool,
    actor: UserId,
    org: OrgId,
    domain: &str,
    auto_join: bool,
) -> Result<DomainSetting, Error> {
    let not_found = || Error::NotFound {
        what: format!("domain {domain} on org {org}"),
    };
    let domain = identity::domain::normalize(domain).map_err(|_| not_found())?;
    let updated = sqlx::query_scalar!(
        r#"update org_domains d set auto_join = $4
            where d.org_id = $1 and d.domain = $2 and d.claimant_id = $3
              and exists (select 1 from org_members m where m.org_id = $1 and m.user_id = $3)
        returning auto_join"#,
        org.as_uuid(),
        domain,
        actor.as_uuid(),
        auto_join,
    )
    .fetch_optional(pool)
    .await
    .map_err(unavailable)?;
    if let Some(auto_join) = updated {
        return Ok(DomainSetting { domain, auto_join });
    }
    let member_of_domain_org = sqlx::query_scalar!(
        r#"select exists (
             select 1 from org_members m join org_domains d on d.org_id = m.org_id
              where m.org_id = $1 and m.user_id = $2 and d.domain = $3) as "member!""#,
        org.as_uuid(),
        actor.as_uuid(),
        domain,
    )
    .fetch_one(pool)
    .await
    .map_err(unavailable)?;
    if member_of_domain_org {
        Err(Error::Forbidden {
            what: "only the person who verified this domain can change auto-join".to_owned(),
        })
    } else {
        Err(not_found())
    }
}

// --------------------------------------------------------- certificates ----

/// Where an org's wildcard certificate stands, in the words a person sees.
///
/// The same field on the org-creation response and the publish response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, utoipa::ToSchema)]
#[non_exhaustive]
pub struct CertificateStatus {
    /// `pending`, `issued` or `failed`.
    pub status: CertState,
    /// What it means for reaching the org's apps.
    pub message: &'static str,
}

/// The three certificate states a person is told about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum CertState {
    /// Being issued; apps are not reachable over TLS yet.
    Pending,
    /// Issued; apps are reachable.
    Issued,
    /// Issuance failed and is being retried.
    Failed,
}

impl CertificateStatus {
    /// From a `certificates.state` value (`None` when there is no row) and
    /// whether a certificate has ever been issued. A row being renewed still
    /// serves its current certificate, so it reads as issued.
    #[must_use]
    pub fn from_state(state: Option<&str>, ever_issued: bool) -> Self {
        let status = match state {
            Some("failed") if !ever_issued => CertState::Failed,
            _ if ever_issued => CertState::Issued,
            _ => CertState::Pending,
        };
        let message = match status {
            CertState::Pending => {
                "This org's certificate is being issued, which usually takes a few minutes. \
                 Until it is, connections to its apps fail during the TLS handshake — browsers \
                 often show this as \"unexpected EOF\" or a dropped connection. That is not a \
                 network fault; retry shortly."
            }
            CertState::Issued => "This org's apps are served over HTTPS.",
            CertState::Failed => {
                "Issuing this org's certificate failed and is retried automatically. Until it \
                 succeeds, connections to its apps fail during the TLS handshake."
            }
        };
        Self { status, message }
    }
}

/// Insert `org`'s certificate row as `pending` if it has none — the hand-off
/// to the renewal reconciler, which claims `pending` rows. Idempotent.
///
/// # Errors
///
/// [`unavailable`]'s mapping for a database failure.
pub async fn ensure_certificate_row(
    ex: impl sqlx::PgExecutor<'_>,
    org: OrgId,
) -> Result<CertificateStatus, Error> {
    let row = sqlx::query!(
        r#"with inserted as (
               insert into certificates (org_id) values ($1)
               on conflict (org_id) do nothing
               returning state, not_after
           )
           select state as "state!", not_after is not null as "ever_issued!" from inserted
           union all
           select state, not_after is not null from certificates
            where org_id = $1 and not exists (select 1 from inserted)"#,
        org.as_uuid(),
    )
    .fetch_one(ex)
    .await
    .map_err(unavailable)?;
    Ok(CertificateStatus::from_state(
        Some(&row.state),
        row.ever_issued,
    ))
}

/// Shared handle to a [`TxtLookup`].
pub type SharedTxtLookup = Arc<dyn TxtLookup>;

// -------------------------------------------------------------- routes ----

use axum::Extension;
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use shared::RequestId;

use crate::db::ActiveSession;
use crate::http::{AppState, render};
use crate::openapi::{Body, Doc, Success};

/// `POST /v1/domain-claims`.
#[derive(serde::Deserialize, Serialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct ClaimRequest {
    /// The domain to claim: the hosted domain of the Google Workspace account
    /// making the request.
    domain: String,
    /// The new org's slug, `{app}.{slug}.clwd.run`. Permanent: it can never be
    /// changed or reused. May not start with `p-`.
    slug: String,
    /// Whether people signing in with a Google Workspace account in this domain
    /// join the org automatically. Defaults to off; only the person who verifies
    /// the domain can change it later.
    #[serde(default)]
    auto_join: bool,
}

/// `PATCH /v1/orgs/{org_id}/domains`.
#[derive(serde::Deserialize, Serialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct AutoJoinRequest {
    /// The verified domain to change.
    domain: String,
    /// The new value.
    auto_join: bool,
}

fn parse_body<T: serde::de::DeserializeOwned>(body: &[u8], what: &str) -> Result<T, Error> {
    // By hand rather than axum's `Json`, whose rejection is plain text, not an
    // envelope.
    serde_json::from_slice(body).map_err(|e| Error::InvalidRequest {
        what: format!("{what}: {e}"),
    })
}

fn json_response<T: Serialize>(status: StatusCode, value: &T) -> Response {
    (status, axum::Json(value)).into_response()
}

pub(crate) async fn claim_route(
    State(state): State<AppState>,
    Extension(session): Extension<ActiveSession>,
    Extension(request_id): Extension<RequestId>,
    body: Bytes,
) -> Response {
    let result = async {
        let request: ClaimRequest = parse_body(&body, "domain claim")?;
        let domain = ClaimedDomain::parse(&request.domain)?;
        start_claim(
            &state.pool,
            session.user_id,
            &domain,
            &request.slug,
            request.auto_join,
        )
        .await
    }
    .await;
    match result {
        Ok(claim) => json_response(StatusCode::CREATED, &claim),
        Err(error) => render(&error, &request_id),
    }
}

pub(crate) async fn verify_route(
    State(state): State<AppState>,
    Path(claim_id): Path<String>,
    Extension(session): Extension<ActiveSession>,
    Extension(request_id): Extension<RequestId>,
) -> Response {
    let result = async {
        let claim_id = claim_id
            .parse::<uuid::Uuid>()
            .map_err(|_| Error::NotFound {
                what: format!("domain claim {claim_id}"),
            })?;
        let lookup = state.txt_lookup.as_deref().ok_or_else(|| Error::Internal {
            source: anyhow::anyhow!("domain verification is not configured on this control plane"),
        })?;
        verify_claim(&state.pool, lookup, session.user_id, claim_id).await
    }
    .await;
    match result {
        Ok(org) => json_response(StatusCode::CREATED, &org),
        Err(error) => render(&error, &request_id),
    }
}

pub(crate) async fn auto_join_route(
    State(state): State<AppState>,
    Path(org): Path<String>,
    Extension(session): Extension<ActiveSession>,
    Extension(request_id): Extension<RequestId>,
    body: Bytes,
) -> Response {
    let result = async {
        let org_id = org.parse::<OrgId>().map_err(|_| Error::NotFound {
            what: format!("org {org}"),
        })?;
        let request: AutoJoinRequest = parse_body(&body, "auto-join setting")?;
        set_auto_join(
            &state.pool,
            session.user_id,
            org_id,
            &request.domain,
            request.auto_join,
        )
        .await
    }
    .await;
    match result {
        Ok(setting) => json_response(StatusCode::OK, &setting),
        Err(error) => render(&error, &request_id),
    }
}

fn claim_request_example() -> serde_json::Result<serde_json::Value> {
    serde_json::to_value(ClaimRequest {
        domain: "acme.com".to_owned(),
        slug: "acme".to_owned(),
        auto_join: false,
    })
}

fn claim_example() -> serde_json::Result<serde_json::Value> {
    serde_json::to_value(Claim {
        id: crate::openapi::EXAMPLE_CLAIM,
        domain: "acme.com".to_owned(),
        slug: "acme".to_owned(),
        auto_join: false,
        txt_name: format!("{VERIFY_LABEL}.acme.com"),
        txt_value: "0".repeat(64),
        expires_at: chrono::DateTime::UNIX_EPOCH,
    })
}

fn created_org_example() -> serde_json::Result<serde_json::Value> {
    serde_json::to_value(CreatedOrg {
        id: OrgId::from(crate::openapi::EXAMPLE_ORG),
        slug: "acme".to_owned(),
        domain: "acme.com".to_owned(),
        auto_join: false,
        certificate: CertificateStatus::from_state(Some("pending"), false),
    })
}

fn auto_join_request_example() -> serde_json::Result<serde_json::Value> {
    serde_json::to_value(AutoJoinRequest {
        domain: "acme.com".to_owned(),
        auto_join: true,
    })
}

fn domain_setting_example() -> serde_json::Result<serde_json::Value> {
    serde_json::to_value(DomainSetting {
        domain: "acme.com".to_owned(),
        auto_join: true,
    })
}

pub(crate) fn claim_doc() -> Doc {
    Doc {
        operation_id: "claimDomain",
        summary: "Start claiming a domain",
        description: "Starts claiming a domain for a new org. The caller must be signed in with a \
                      Google Workspace account whose hosted domain is the domain claimed. The \
                      response names a TXT record to publish; verifying it creates the org. \
                      Nothing is reserved until then, and the claim expires after 72 hours. \
                      `gmail.com` and `googlemail.com` cannot be claimed.",
        params: &[],
        request: Some(Body::json::<ClaimRequest>(
            "The domain, the new org's permanent slug, and whether the domain's accounts join automatically (default off).",
            claim_request_example,
        )),
        success: vec![Success {
            status: StatusCode::CREATED,
            description: "The claim was started. Publish `txt_value` at `txt_name`, then verify.",
            body: Some(Body::json::<Claim>("The claim.", claim_example)),
        }],
        errors: &["control-plane.invalid_request", "control-plane.conflict"],
    }
}

pub(crate) fn verify_doc() -> Doc {
    Doc {
        operation_id: "verifyDomainClaim",
        summary: "Verify a domain claim",
        description: "Checks the claim's TXT record and, if it carries the claim's value, creates \
                      the org with the claimed slug, binds the domain to it and makes the caller a \
                      member. The org's certificate is issued afterwards, asynchronously: the \
                      response's `certificate` says where that stands. A domain already verified \
                      by an org is never moved.",
        params: &[("claim_id", "The claim to verify.")],
        request: None,
        success: vec![Success {
            status: StatusCode::CREATED,
            description: "The org was created.",
            body: Some(Body::json::<CreatedOrg>(
                "The new org and its certificate status.",
                created_org_example,
            )),
        }],
        errors: &[
            "control-plane.invalid_request",
            "control-plane.not_found",
            "control-plane.conflict",
        ],
    }
}

pub(crate) fn auto_join_doc() -> Doc {
    Doc {
        operation_id: "setDomainAutoJoin",
        summary: "Turn a domain's auto-join on or off",
        description: "Sets whether people signing in with a Google Workspace account in this \
                      verified domain join the org automatically. Only the person who verified the \
                      domain may change it.",
        params: &[("org_id", "The org the domain is verified for.")],
        request: Some(Body::json::<AutoJoinRequest>(
            "The verified domain and its new setting.",
            auto_join_request_example,
        )),
        success: vec![Success {
            status: StatusCode::OK,
            description: "The setting was changed.",
            body: Some(Body::json::<DomainSetting>(
                "The domain and its setting.",
                domain_setting_example,
            )),
        }],
        errors: &["control-plane.invalid_request", "control-plane.not_found"],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_personal_slug_is_p_and_ten_lowercase_base32_characters() {
        for _ in 0..100 {
            let slug = personal_slug().expect("random");
            let tail = slug.strip_prefix(PERSONAL_SLUG_PREFIX).expect("p- prefix");
            assert_eq!(tail.len(), PERSONAL_SLUG_CHARS, "{slug}");
            assert!(
                tail.bytes()
                    .all(|b| b.is_ascii_lowercase() || (b'2'..=b'7').contains(&b)),
                "{slug}"
            );
            assert!(OrgSlug::parse(&slug).is_ok(), "{slug} is a valid org slug");
        }
    }

    #[test]
    fn a_claimed_domain_is_normalised_and_consumer_mail_refused() {
        let domain = ClaimedDomain::parse("Example.COM.").expect("a domain");
        assert_eq!(domain.as_str(), "example.com");
        assert!(domain.is_hosted_by(&HostedDomain::parse("EXAMPLE.com").expect("hd")));
        for refused in ["gmail.com", "GMail.com.", "googlemail.com", "not a domain"] {
            assert!(ClaimedDomain::parse(refused).is_err(), "{refused}");
        }
    }

    /// The retry bound is a bound: when every slug tried is taken, the answer
    /// is a clear error, not a loop and not a second org.
    #[sqlx::test(migrations = "../../migrations")]
    async fn personal_slug_allocation_gives_up_with_a_clear_error(pool: PgPool) {
        crate::db::create_org(&pool, "p-aaaaaaaaaa")
            .await
            .expect("org");
        let user = crate::db::create_user(&pool, "a@example.com")
            .await
            .expect("user");
        let mut tx = pool.begin().await.expect("tx");
        let mut tried = 0;
        let result = create_personal_org(&mut tx, user.id, || {
            tried += 1;
            Ok("p-aaaaaaaaaa".to_owned())
        })
        .await;
        let error = result.expect_err("every slug was taken");
        assert_eq!(tried, PERSONAL_SLUG_ATTEMPTS);
        assert_eq!(error.code(), "control-plane.internal");
        assert!(
            format!("{error:?}").contains("no free personal-org slug"),
            "{error:?}"
        );
    }
}
