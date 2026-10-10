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
/// # Host-only, on the control plane's own host (#62)
///
/// `__Host-` makes the browser refuse the cookie unless it is `Secure`,
/// `Path=/`, and carries **no** `Domain` — so it exists on exactly the host that
/// set it, and no other host can set, overwrite or shadow one in its place.
/// That is the point: apps run untrusted code, and a session cookie any app
/// host could plant (`Domain=<apex>`) let an app fix a visitor into the
/// attacker's session. Apps get their own per-host sessions through the
/// handshake instead; this cookie never travels to them.
pub const COOKIE_NAME: &str = "__Host-clwd_session";

/// How long a session lives from sign-in.
///
/// ponytail: one fixed lifetime, no sliding refresh. A sliding window with an
/// absolute cap is #63; until then users sign in again daily.
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

/// Issue a session for `user_id`. `None` if the user does not exist or is
/// deleted.
///
/// # Errors
///
/// `control-plane.internal` if the random source or signing fails, and
/// whatever [`unavailable`] maps a database error to.
pub async fn issue(
    pool: &PgPool,
    key: &CookieKey,
    user_id: UserId,
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
        set_cookie: set_cookie(&value, TTL.num_seconds()),
    }))
}

/// The `Set-Cookie` value for the session cookie — the one place its
/// attributes are written. Each is there for a reason; do not add or drop one
/// to quiet a browser warning without reading this.
///
/// - **No `Domain`.** Required by `__Host-`, and the whole defence: a cookie
///   with no `Domain` is host-only, so no other host — no app — can set one the
///   control plane would read. Adding `Domain=` makes the browser reject the
///   cookie outright (the prefix forbids it), and renaming it to dodge that
///   reopens cookie tossing (#62).
/// - **`Path=/`.** Required by `__Host-`; the session covers the whole host.
/// - **`Secure`.** Required by `__Host-`; never sent over plain HTTP.
/// - **`HttpOnly`.** Script cannot read it, and cannot overwrite it either:
///   a cookie set from script never replaces an `HttpOnly` one.
/// - **`SameSite=Lax`.** Sent on a top-level navigation from another site (a
///   link into the control plane), withheld from cross-site subrequests and
///   form posts. CSRF on the same site is the origin check's job
///   (`http::require_same_origin`), not this attribute's.
/// - **`Max-Age`.** Matches the row's lifetime; the row still decides.
fn set_cookie(value: &str, max_age_secs: i64) -> String {
    format!("{COOKIE_NAME}={value}; Path=/; Max-Age={max_age_secs}; HttpOnly; Secure; SameSite=Lax")
}

/// The `Set-Cookie` value that tells a browser to drop the session cookie.
///
/// A courtesy, not the logout: logging out is [`db::revoke_session`]. A
/// browser that ignores this still holds a cookie that no longer authenticates.
#[must_use]
pub fn clear_cookie() -> String {
    set_cookie("", 0)
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

/// Middleware for [`crate::http::Access::Session`] routes: authenticate the
/// session cookie and hand the handler its [`ActiveSession`].
///
/// One lookup, the same as [`authenticate`]. Org membership is deliberately
/// **not** read here: this runs on every session request, and per-request
/// authorization is #12's, cached there.
pub(crate) async fn require(
    axum::extract::State(state): axum::extract::State<crate::http::AppState>,
    mut request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let request_id = request
        .extensions()
        .get::<shared::RequestId>()
        .cloned()
        .unwrap_or_else(shared::RequestId::generate);
    let Some(signin) = state.signin.as_deref() else {
        return crate::http::render(
            &Error::Internal {
                source: anyhow::anyhow!("sign-in is not configured on this control plane"),
            },
            &request_id,
        );
    };
    match authenticate(&state.pool, signin.key(), request.headers()).await {
        Ok(session) => {
            request.extensions_mut().insert(session);
            next.run(request).await
        }
        Err(error) => crate::http::render(&error, &request_id),
    }
}

/// The value of the cookie called exactly `name`, if exactly one is present.
///
/// Through [`shared::cookie::find`], the platform's one cookie parser: an
/// exact byte match on the name, never a repaired one, and two is refused
/// rather than resolved — a second one is what a planted cookie looks like,
/// and picking either would let the planter choose the session.
pub(crate) fn single_cookie<'h>(headers: &'h HeaderMap, name: &str) -> Option<&'h str> {
    match shared::cookie::find(
        headers
            .get_all(header::COOKIE)
            .iter()
            .map(axum::http::HeaderValue::as_bytes),
        name,
    ) {
        shared::cookie::Found::One(value) => Some(value),
        _ => None,
    }
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
    fn the_cookie_is_host_only_with_every_flag() {
        let c = set_cookie("v", 60);
        assert_eq!(
            c, "__Host-clwd_session=v; Path=/; Max-Age=60; HttpOnly; Secure; SameSite=Lax",
            "the literal header: no Domain attribute"
        );
        assert!(!c.to_ascii_lowercase().contains("domain"), "{c}");
        for flag in [
            "__Host-clwd_session=v;",
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
        let h = headers("a=1; __Host-clwd_session=xyz; b=2");
        assert_eq!(single_cookie(&h, COOKIE_NAME), Some("xyz"));
    }

    #[test]
    fn two_session_cookies_are_refused() {
        let h = headers("__Host-clwd_session=mine; __Host-clwd_session=planted");
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
