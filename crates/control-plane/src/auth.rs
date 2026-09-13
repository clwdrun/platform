//! Who is calling, and what they may do.
//!
//! # The path a request takes
//!
//! ```text
//! assign_request_id   marks Authorization sensitive     (outermost, every route)
//! authenticate        format -> digest -> lookup -> rate limit
//! require_scope       the scope this route was registered with
//! handler             org and app binding, as part of its own query
//! ```
//!
//! # No cache, deliberately
//!
//! Every request looks its token up. Revocation is therefore effective on the
//! next request by construction, and there is nothing to invalidate. A request
//! already past this layer when a revoke lands finishes; the request timeout
//! bounds how long that can be.
//!
//! What `#12` inherits is `api_tokens.revoked_at` and [`db::token_by_digest`]
//! as the source of truth. If it caches token validity, it adds a per-org
//! epoch bumped in the revoke transaction — one column and one `UPDATE` — and
//! nothing here needs replacing. An epoch built now would have no grants to
//! key on and no consumer.
//!
//! # Failing closed
//!
//! A database error during lookup denies the request with
//! `control-plane.timeout` or `control-plane.internal`, **never** with
//! `identity.unauthenticated`. A 401 would tell the caller their token is bad
//! and send them off to rotate a credential that is fine.
//!
//! # Rate limiting is after authentication
//!
//! Keyed by [`TokenId`], so only tokens that exist create limiter entries and a
//! flood cannot grow the map. A flood of *well-formed* random tokens still
//! costs one indexed lookup each; limiting that by address needs forwarding
//! headers the gateway can vouch for, which is `#11`'s edge, not this layer.

use std::num::NonZeroU32;
use std::time::Duration;

use axum::body::Bytes;
use axum::extract::{Path, Request, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use governor::clock::Clock as _;
use governor::{DefaultKeyedRateLimiter, Quota};
use shared::{Error, RequestId};
use sqlx::PgPool;

use crate::db;
use crate::http::{AppState, render};
use crate::ids::{AppId, OrgId, TokenId};
use crate::token::{self, Scope, Scopes, TokenSecret};

/// The verified caller of one request.
///
/// Inserted by [`authenticate`]; a handler that needs it extracts it. A route
/// registered without authentication never has one, and extracting it there
/// is a 500 rather than a pass.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Principal {
    pub token_id: TokenId,
    pub org_id: OrgId,
    /// The one app this token is narrowed to, or `None` for the whole org.
    pub app_id: Option<AppId>,
    pub scopes: Scopes,
}

impl Principal {
    /// `identity.forbidden` naming `scope`, unless this token carries it.
    ///
    /// # Errors
    ///
    /// When the scope is missing.
    pub fn require(&self, scope: Scope) -> Result<(), Error> {
        if self.scopes.contains(scope) {
            Ok(())
        } else {
            Err(Error::Forbidden {
                what: format!("this route needs the `{}` scope", scope.as_str()),
            })
        }
    }

    /// Whether `app` is within this token's app binding.
    ///
    /// The org half of the binding is not checked here: it belongs in the
    /// query that reads the app, where it costs nothing and cannot be skipped
    /// by a handler that forgot to call this.
    #[must_use]
    pub fn may_reach_app(&self, app: AppId) -> bool {
        self.app_id.is_none_or(|bound| bound == app)
    }
}

/// The per-token limiter.
///
/// In memory, per process: behind N nodes a token gets N times this. That is
/// the ceiling of an in-process limiter, and the upgrade is a shared store once
/// there is more than one node to disagree.
pub type Limiter = DefaultKeyedRateLimiter<TokenId>;

const PER_SECOND: NonZeroU32 = match NonZeroU32::new(20) {
    Some(n) => n,
    None => panic!("the rate must be non-zero"),
};

const BURST: NonZeroU32 = match NonZeroU32::new(100) {
    Some(n) => n,
    None => panic!("the burst must be non-zero"),
};

/// 20 requests a second sustained, bursts of 100.
///
/// One quota for every route until a route gives a reason for its own.
#[must_use]
pub fn default_quota() -> Quota {
    Quota::per_second(PER_SECOND).allow_burst(BURST)
}

/// Authenticate the request, or answer it with the envelope.
///
/// Mounted with `route_layer` on the protected router, so it runs only for a
/// matched protected route and inside the request id, trace, panic and timeout
/// layers — the lookup is covered by the request's time budget.
pub async fn authenticate(
    State(state): State<AppState>,
    mut request: Request,
    next: Next,
) -> Response {
    // Read before the lookup's await, not during it: a `&Request` held across
    // an await makes this future `!Send`, because the body is not `Sync`.
    let presented = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(bearer)
        .and_then(token::digest_presented);

    match principal_for(&state, presented).await {
        Ok(principal) => {
            request.extensions_mut().insert(principal);
            next.run(request).await
        }
        Err(error) => render(&error, &request_id_of(&request)),
    }
}

async fn principal_for(
    state: &AppState,
    presented: Option<token::TokenDigest>,
) -> Result<Principal, Error> {
    let digest = presented.ok_or(Error::Unauthenticated {})?;

    let grant = db::token_by_digest(&state.pool, &digest)
        .await
        .map_err(unavailable)?
        .ok_or(Error::Unauthenticated {})?;

    // The column's CHECK makes an unknown name impossible, so one here is our
    // defect rather than the caller's problem — and a defect denies.
    let scopes =
        Scopes::parse_all(&grant.scopes).map_err(|e| Error::Internal { source: e.into() })?;

    // After the lookup, so a revoked token is 401 rather than 429, and only a
    // token that exists can create an entry.
    if let Err(not_until) = state.limiter.check_key(&grant.id) {
        return Err(Error::RateLimited {
            retry_after_secs: retry_after_secs(
                not_until.wait_time_from(state.limiter.clock().now()),
            ),
        });
    }

    Ok(Principal {
        token_id: grant.id,
        org_id: grant.org_id,
        app_id: grant.app_id,
        scopes,
    })
}

/// The token from `Bearer <token>`. The scheme is case-insensitive (RFC 7235);
/// the token is not touched, so stray whitespace makes it malformed.
fn bearer(value: &HeaderValue) -> Option<&str> {
    let (scheme, token) = value.to_str().ok()?.split_once(' ')?;
    scheme.eq_ignore_ascii_case("bearer").then_some(token)
}

/// Whole seconds a caller should wait, rounded up and never zero: a
/// `Retry-After: 0` invites the immediate retry the limit exists to prevent.
fn retry_after_secs(wait: Duration) -> u64 {
    (wait.as_secs() + u64::from(wait.subsec_nanos() > 0)).max(1)
}

/// A lookup that could not be made is a denial, reported as what it is.
fn unavailable(source: sqlx::Error) -> Error {
    match source {
        sqlx::Error::PoolTimedOut => Error::Timeout {
            dependency: "the database".to_owned(),
        },
        other => Error::Internal {
            source: other.into(),
        },
    }
}

fn request_id_of(request: &Request) -> RequestId {
    request
        .extensions()
        .get::<RequestId>()
        .cloned()
        .unwrap_or_else(RequestId::generate)
}

/// Deny unless the authenticated caller carries `scope`.
///
/// Attached per route by `http::protected`, which is the only way to add a
/// protected route and takes the scope as an argument — so a route cannot be
/// registered as protected and forget which scope it needs.
pub async fn require_scope(scope: Scope, request: Request, next: Next) -> Response {
    let outcome = match request.extensions().get::<Principal>() {
        Some(principal) => principal.require(scope),
        // Unreachable while the router is wired correctly, and if it is not,
        // this denies rather than letting a scoped route run unauthenticated.
        None => Err(Error::Internal {
            source: anyhow::anyhow!("a scoped route ran without authentication"),
        }),
    };
    match outcome {
        Ok(()) => next.run(request).await,
        Err(error) => render(&error, &request_id_of(&request)),
    }
}

/// The longest token name accepted, in characters. Matches the column's CHECK.
pub const NAME_MAX: usize = 100;

/// A token as issued: its row, and its secret for the one time it is shown.
#[derive(Debug)]
#[non_exhaustive]
pub struct Issued {
    pub id: TokenId,
    pub secret: TokenSecret,
}

/// Mint and store a token.
///
/// The one issuance path: the HTTP route and the bootstrap subcommand both
/// call this, so validation cannot differ between them. **It does not check
/// who is asking** — the route does that before calling, and the bootstrap
/// subcommand is gated by holding database credentials.
///
/// # Errors
///
/// `control-plane.invalid_request` for an empty scope set or a bad name;
/// `control-plane.not_found` if the org is not live or the app is not a live
/// app in it; `control-plane.internal` if randomness or the database fails.
pub async fn issue(
    pool: &PgPool,
    org_id: OrgId,
    app_id: Option<AppId>,
    name: &str,
    scopes: Scopes,
) -> Result<Issued, Error> {
    if scopes.is_empty() {
        return Err(Error::InvalidRequest {
            what: "a token needs at least one scope".to_owned(),
        });
    }
    if !(1..=NAME_MAX).contains(&name.chars().count()) {
        return Err(Error::InvalidRequest {
            what: format!("a token name is 1 to {NAME_MAX} characters"),
        });
    }

    let secret = TokenSecret::generate().map_err(|e| Error::Internal {
        source: anyhow::anyhow!("the system random source failed: {e}"),
    })?;

    let id = db::insert_token(
        pool,
        org_id,
        app_id,
        name,
        &secret.digest(),
        &scopes.to_names(),
    )
    .await
    .map_err(|e| Error::Internal { source: e.into() })?
    .ok_or_else(|| Error::NotFound {
        what: match app_id {
            Some(app) => format!("app {app}"),
            None => format!("org {org_id}"),
        },
    })?;

    Ok(Issued { id, secret })
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct IssueRequest {
    name: String,
    scopes: Vec<String>,
    #[serde(default)]
    app_id: Option<AppId>,
}

#[derive(serde::Serialize)]
struct IssueResponse<'a> {
    id: TokenId,
    /// The only time this value leaves the process.
    token: &'a str,
    name: &'a str,
    org_id: OrgId,
    app_id: Option<AppId>,
    scopes: Scopes,
}

/// `POST /v1/orgs/{org_id}/tokens` — requires `admin`.
///
/// The body is JSON: `{"name": "...", "scopes": ["publish"], "app_id": null}`.
/// The response is **201** with the token, and `Cache-Control: no-store` so no
/// intermediary keeps the one copy.
///
/// # A token can only issue a token no stronger than itself
///
/// Scopes must be a subset of the issuer's, and a token bound to an app can
/// only issue tokens bound to that same app. Otherwise `admin` on one app is
/// `admin` on the org one request later.
pub async fn issue_route(
    State(state): State<AppState>,
    Path(org): Path<String>,
    axum::Extension(principal): axum::Extension<Principal>,
    axum::Extension(request_id): axum::Extension<RequestId>,
    body: Bytes,
) -> Response {
    match issue_inner(&state, &org, &principal, &body).await {
        Ok(response) => response,
        Err(error) => render(&error, &request_id),
    }
}

async fn issue_inner(
    state: &AppState,
    org: &str,
    principal: &Principal,
    body: &[u8],
) -> Result<Response, Error> {
    // Another org, or a malformed id, is the same answer as an org that does
    // not exist: a 403 would confirm the org is real.
    let org_id = org
        .parse::<OrgId>()
        .ok()
        .filter(|id| *id == principal.org_id)
        .ok_or_else(|| Error::NotFound {
            what: format!("org {org}"),
        })?;

    // Parsed by hand rather than with axum's `Json` extractor, whose rejection
    // is a plain-text body and not an envelope.
    let request: IssueRequest =
        serde_json::from_slice(body).map_err(|e| Error::InvalidRequest {
            what: format!("token request: {e}"),
        })?;
    let scopes = Scopes::parse_all(&request.scopes).map_err(|e| Error::InvalidRequest {
        what: e.to_string(),
    })?;

    match (principal.app_id, request.app_id) {
        (Some(bound), Some(app)) if bound != app => {
            return Err(Error::NotFound {
                what: format!("app {app}"),
            });
        }
        (Some(_), None) => {
            return Err(Error::Forbidden {
                what: "a token bound to an app can only issue tokens bound to that app".to_owned(),
            });
        }
        _ => {}
    }

    let missing = scopes.missing_from(principal.scopes);
    if !missing.is_empty() {
        return Err(Error::Forbidden {
            what: format!("cannot grant scopes this token does not hold: {missing}"),
        });
    }

    let issued = issue(&state.pool, org_id, request.app_id, &request.name, scopes).await?;

    let mut response = (
        StatusCode::CREATED,
        axum::Json(IssueResponse {
            id: issued.id,
            token: issued.secret.expose(),
            name: &request.name,
            org_id,
            app_id: request.app_id,
            scopes,
        }),
    )
        .into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    Ok(response)
}

/// `DELETE /v1/tokens/{token_id}` — requires `admin`.
///
/// **204** once the token is revoked, including when it already was. **404**
/// for a token outside the caller's org or app binding, or a malformed id —
/// the same answer as a token that never existed.
pub async fn revoke_route(
    State(state): State<AppState>,
    Path(id): Path<String>,
    axum::Extension(principal): axum::Extension<Principal>,
    axum::Extension(request_id): axum::Extension<RequestId>,
) -> Response {
    let revoked = match id.parse::<TokenId>() {
        Ok(token_id) => {
            db::revoke_token(&state.pool, token_id, principal.org_id, principal.app_id).await
        }
        Err(_) => Ok(false),
    };
    match revoked {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => render(
            &Error::NotFound {
                what: format!("token {id}"),
            },
            &request_id,
        ),
        Err(e) => render(&Error::Internal { source: e.into() }, &request_id),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **Fail closed, on every arm.** Whatever the database reports, a lookup
    /// that could not be made is a 5xx that blames us — never a 401 that tells
    /// the caller to rotate a token that is fine.
    ///
    /// A unit test because the router-level outage test can only reach one arm:
    /// an unreachable pool retries until its acquire timeout, so it always
    /// surfaces as `PoolTimedOut`. A mutation that turned every *other* error
    /// into `identity.unauthenticated` passed that test.
    #[test]
    fn a_failed_lookup_never_blames_the_token() {
        for source in [
            sqlx::Error::PoolTimedOut,
            sqlx::Error::PoolClosed,
            sqlx::Error::Io(std::io::Error::from(std::io::ErrorKind::ConnectionRefused)),
            sqlx::Error::Protocol("unexpected message".to_owned()),
        ] {
            let label = format!("{source:?}");
            let error = unavailable(source);
            assert!(
                (500..=599).contains(&error.status()),
                "{label} became {} at {}",
                error.code(),
                error.status()
            );
            assert!(
                !error.code().starts_with("identity."),
                "{label} blamed the token: {}",
                error.code()
            );
        }
    }

    #[test]
    fn retry_after_rounds_up_and_is_never_zero() {
        assert_eq!(retry_after_secs(Duration::ZERO), 1);
        assert_eq!(retry_after_secs(Duration::from_millis(1)), 1);
        assert_eq!(retry_after_secs(Duration::from_secs(2)), 2);
        assert_eq!(retry_after_secs(Duration::from_millis(2_001)), 3);
    }

    #[test]
    fn bearer_parses_the_scheme_case_insensitively_and_nothing_else() {
        let token = HeaderValue::from_static("Bearer abc");
        assert_eq!(bearer(&token), Some("abc"));
        assert_eq!(bearer(&HeaderValue::from_static("bearer abc")), Some("abc"));
        assert_eq!(bearer(&HeaderValue::from_static("Basic abc")), None);
        assert_eq!(bearer(&HeaderValue::from_static("Bearer")), None);
        assert_eq!(
            bearer(&HeaderValue::from_static("Bearer  abc")),
            Some(" abc"),
            "not trimmed, so the format check rejects it"
        );
    }

    #[test]
    fn a_bound_token_reaches_only_its_app() {
        let mine = AppId::new();
        let bound = Principal {
            token_id: TokenId::new(),
            org_id: OrgId::new(),
            app_id: Some(mine),
            scopes: Scopes::default(),
        };
        assert!(bound.may_reach_app(mine));
        assert!(!bound.may_reach_app(AppId::new()));

        let unbound = Principal {
            app_id: None,
            ..bound
        };
        assert!(unbound.may_reach_app(AppId::new()));
    }
}
