//! Browser sessions: issuing the session cookie and authenticating by it.
//!
//! # The row is the session, the cookie is a pointer to it
//!
//! The cookie carries a 256-bit random secret, sealed as an HS256 JWT with the
//! same [`CookieKey`] the flow cookie uses. The signature lets a forged or
//! tampered cookie be refused before anything touches the database; it does
//! **not** make the cookie authoritative. Every request looks the secret's
//! digest up in `sessions` ([`db::lookup_active_session`]), so a revoke is
//! effective on the very next request whatever the browser still holds, and
//! the row's `expires_at` — judged by the database clock — is the end of the
//! session, not the JWT's `exp` or the cookie's `Max-Age`.
//!
//! # One outcome for every failure
//!
//! Absent, malformed, tampered, revoked, expired, unknown, duplicated: all
//! [`Error::Unauthenticated`], the same code and the same envelope. A database
//! error is a denial reported as what it is (timeout or internal), never as
//! unauthenticated — the failing-closed rule `auth` already holds.

use std::fmt;

use axum::http::{HeaderMap, header};
use chrono::{DateTime, Utc};
use jsonwebtoken::{Algorithm, Header, Validation};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use shared::Error;
use sqlx::PgPool;

use crate::auth::unavailable;
use crate::db::{self, ActiveSession};
use crate::ids::{SessionId, UserId};
use crate::signin::CookieKey;

/// The session cookie's name.
///
/// # This cookie rides to every app — `#11` must keep it identity-only
///
/// It is scoped to the apex (`Domain=<apex>`), which is what lets one sign-in
/// cover every `{app}.{org}.<apex>` — and is also why **every request to every
/// customer app carries it**. The gateway (`#11`) must therefore treat it as
/// identity-only:
///
/// - strip it from the request before proxying, resolving it to an identity
///   the gateway vouches for, so no app ever reads the raw cookie (an app that
///   could read it could replay it against the control plane as the user);
/// - strip any `Set-Cookie` naming it from app responses, so an app cannot
///   plant its own session on the apex (cookie tossing). [`authenticate`]
///   already refuses a request carrying two of these, but the gateway is where
///   the planting is stopped.
///
/// `__Secure-` makes the browser refuse to set it without `Secure`. `__Host-`
/// would be stronger but forbids `Domain`, which is the whole point here.
pub const COOKIE_NAME: &str = "__Secure-clwd_session";

/// How long a session lives from sign-in.
///
/// ponytail: one fixed lifetime, no sliding refresh. #9's "refresh" lands with
/// the callback; a sliding window is an `update ... set expires_at` there.
pub const TTL: chrono::Duration = chrono::Duration::hours(24);

const SECRET_BYTES: usize = 32;

/// A session's cookie secret, held only between minting it and sealing it.
/// Its `Debug` redacts, like [`crate::token::TokenSecret`].
struct SessionSecret(String);

impl SessionSecret {
    fn generate() -> Result<Self, getrandom::Error> {
        let mut bytes = [0u8; SECRET_BYTES];
        getrandom::fill(&mut bytes)?;
        Ok(Self(bytes.iter().map(|b| format!("{b:02x}")).collect()))
    }
}

impl fmt::Debug for SessionSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SessionSecret(<redacted>)")
    }
}

fn digest(secret: &str) -> [u8; 32] {
    Sha256::digest(secret.as_bytes()).into()
}

#[derive(Serialize, Deserialize)]
struct SessionClaims {
    /// Matches the row's `expires_at`, so a stale cookie is refused without a
    /// lookup. The row still decides.
    exp: i64,
    /// The secret whose digest names the row.
    sid: String,
}

/// A newly issued session.
#[derive(Debug)]
#[non_exhaustive]
pub struct Issued {
    pub id: SessionId,
    pub expires_at: DateTime<Utc>,
    /// The full `Set-Cookie` header value.
    pub set_cookie: String,
}

/// Issue a session for `user_id`, scoped to `apex`. `None` if the user does
/// not exist or is deleted.
///
/// # Errors
///
/// `control-plane.internal` if the random source or signing fails, and
/// whatever [`unavailable`] maps a database error to.
pub async fn issue(
    pool: &PgPool,
    key: &CookieKey,
    user_id: UserId,
    apex: &str,
) -> Result<Option<Issued>, Error> {
    let secret = SessionSecret::generate().map_err(|e| Error::Internal { source: e.into() })?;
    let expires_at = Utc::now() + TTL;

    let Some(id) = db::insert_session(pool, user_id, &digest(&secret.0), expires_at)
        .await
        .map_err(unavailable)?
    else {
        return Ok(None);
    };

    let claims = SessionClaims {
        exp: expires_at.timestamp(),
        sid: secret.0,
    };
    let value = jsonwebtoken::encode(&Header::new(Algorithm::HS256), &claims, &key.encoding)
        .map_err(|e| Error::Internal { source: e.into() })?;

    Ok(Some(Issued {
        id,
        expires_at,
        set_cookie: set_cookie(&value, apex, TTL.num_seconds()),
    }))
}

/// The `Set-Cookie` value for a session cookie. See [`COOKIE_NAME`] for why
/// it is apex-scoped and what that obliges the gateway to do.
fn set_cookie(value: &str, apex: &str, max_age_secs: i64) -> String {
    format!(
        "{COOKIE_NAME}={value}; Domain={apex}; Path=/; Max-Age={max_age_secs}; \
         HttpOnly; Secure; SameSite=Lax"
    )
}

/// The `Set-Cookie` value that tells a browser to drop the session cookie.
///
/// A courtesy, not the logout: logging out is [`db::revoke_session`]. A
/// browser that ignores this still holds a cookie that no longer authenticates.
#[must_use]
pub fn clear_cookie(apex: &str) -> String {
    set_cookie("", apex, 0)
}

/// The session this request's cookie names, if it is live.
///
/// # Errors
///
/// [`Error::Unauthenticated`] for every reason the cookie does not name a live
/// session; [`unavailable`]'s mapping if the lookup could not be made.
pub async fn authenticate(
    pool: &PgPool,
    key: &CookieKey,
    headers: &HeaderMap,
) -> Result<ActiveSession, Error> {
    let value = single_cookie(headers, COOKIE_NAME).ok_or(Error::Unauthenticated {})?;

    let mut validation = Validation::new(Algorithm::HS256);
    validation.set_required_spec_claims(&["exp"]);
    let claims = jsonwebtoken::decode::<SessionClaims>(value, &key.decoding, &validation)
        .map_err(|_| Error::Unauthenticated {})?
        .claims;

    db::lookup_active_session(pool, &digest(&claims.sid))
        .await
        .map_err(unavailable)?
        .ok_or(Error::Unauthenticated {})
}

/// The value of the cookie called `name`, if exactly one is present.
///
/// Two is refused rather than resolved: a second one is what a subdomain
/// planting its own cookie on the apex looks like, and picking either would
/// let the attacker choose which session the victim is in.
pub(crate) fn single_cookie<'h>(headers: &'h HeaderMap, name: &str) -> Option<&'h str> {
    let mut found = headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|pair| pair.trim().split_once('='))
        .filter(|(found, _)| *found == name)
        .map(|(_, value)| value);
    let first = found.next()?;
    found.next().is_none().then_some(first)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    fn headers(cookie: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(
            header::COOKIE,
            HeaderValue::from_str(cookie).expect("ascii"),
        );
        h
    }

    #[test]
    fn the_cookie_carries_every_flag() {
        let c = set_cookie("v", "clwd.run", 60);
        for flag in [
            "__Secure-clwd_session=v;",
            "Domain=clwd.run",
            "Path=/",
            "Max-Age=60",
            "HttpOnly",
            "Secure",
            "SameSite=Lax",
        ] {
            assert!(c.contains(flag), "{flag} missing from {c}");
        }
    }

    #[test]
    fn one_session_cookie_among_others_is_found() {
        let h = headers("a=1; __Secure-clwd_session=xyz; b=2");
        assert_eq!(single_cookie(&h, COOKIE_NAME), Some("xyz"));
    }

    #[test]
    fn two_session_cookies_are_refused() {
        let h = headers("__Secure-clwd_session=mine; __Secure-clwd_session=planted");
        assert_eq!(single_cookie(&h, COOKIE_NAME), None);
    }

    #[test]
    fn a_differently_named_cookie_is_not_the_session() {
        assert_eq!(
            single_cookie(&headers("clwd_session=xyz"), COOKIE_NAME),
            None
        );
    }

    #[test]
    fn the_secret_debug_is_redacted() {
        let s = SessionSecret::generate().expect("random");
        assert_eq!(s.0.len(), 64);
        assert_eq!(format!("{s:?}"), "SessionSecret(<redacted>)");
    }
}
