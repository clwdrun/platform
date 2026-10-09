//! OIDC sign-in: the flow cookie that carries the `state`, `nonce`, and PKCE
//! verifier between the redirect to Google and the callback.
//!
//! # What this cookie is
//!
//! Between the redirect and the callback the server holds nothing: the three
//! secrets ride in a signed cookie, bound to the one browser that has it. The
//! cookie is an HS256 JWT (via the already-vendored `jsonwebtoken`), so the
//! callback can verify it was issued here and has not expired without a
//! database round trip. The route sets it `HttpOnly`, `Secure`,
//! `SameSite=Lax`, with a short `Max-Age`, and clears it on use.
//!
//! # Where single-use is enforced — read this before trusting "delete on use"
//!
//! **The cookie is NOT the single-use guard.** It is stateless: a signed,
//! unexpired JWT stays valid until its `exp` whether or not the browser honours
//! the clearing `Set-Cookie`. Clearing it defends only the *cooperative*
//! browser — a replayed sign-in in the same session finds no cookie and is
//! rejected as if absent.
//!
//! The *hostile* replay — an attacker who captured the callback URL with its
//! cookie intact and replays it — is stopped one layer down, at the **code
//! exchange**: the authorization `code` is single-use at Google, and PKCE
//! binds the exchange to this flow's verifier. (`state` is not single-use at
//! Google — Google never sees it checked; it is our CSRF binding between the
//! callback and this cookie, nothing more.)
//! A replayed callback presents an already-burned `code`, and Google refuses
//! it. That is the single-use enforcement point; the cookie's `exp` and
//! clearing are a short leash and a cooperative-browser convenience, not the
//! security boundary. Do not add "the cookie is single-use" to this design —
//! it is not, by construction, and the code exchange is what makes replay safe.

use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};

/// The signing algorithm for the flow cookie.
const ALG: Algorithm = Algorithm::HS256;

/// The HS256 key the flow cookie is signed and verified with.
///
/// Holds key material, so its `Debug` redacts — a `{:?}` of the app state must
/// never print it. Built from a secret supplied by configuration (#22 will own
/// where that secret comes from and how it rotates).
pub struct CookieKey {
    encoding: EncodingKey,
    decoding: DecodingKey,
}

impl CookieKey {
    /// Build the key from raw secret bytes.
    #[must_use]
    pub fn from_secret(secret: &[u8]) -> Self {
        Self {
            encoding: EncodingKey::from_secret(secret),
            decoding: DecodingKey::from_secret(secret),
        }
    }
}

impl std::fmt::Debug for CookieKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CookieKey(<redacted>)")
    }
}

/// What the flow cookie carries, recovered at the callback.
///
/// All three are opaque strings here; the callback hands them back to
/// `identity` verbatim (`state` to compare, `nonce` and `pkce_verifier` for the
/// token exchange), so `control-plane` never depends on `openidconnect`'s types.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct FlowState {
    /// The CSRF token; the callback rejects a request whose `state` query
    /// parameter does not equal this.
    pub state: String,
    /// The nonce bound into the ID token at the authorization request.
    pub nonce: String,
    /// The PKCE verifier presented at the token exchange.
    pub pkce_verifier: String,
}

/// The JWT claims of a flow cookie.
#[derive(Serialize, Deserialize)]
struct FlowClaims {
    /// Expiry, seconds since the epoch. `jsonwebtoken` enforces it on decode.
    exp: u64,
    state: String,
    nonce: String,
    pkce: String,
}

/// Why a flow cookie was not accepted.
///
/// A tampered cookie, an expired one, and a malformed one collapse to a single
/// variant: to the caller they are one answer — start over — and distinguishing
/// them would only tell an attacker which part of a forged cookie to fix.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum FlowCookieError {
    /// The cookie was missing, malformed, tampered with, or expired.
    #[error("the sign-in flow cookie is missing, invalid, or expired")]
    Invalid,
}

/// Seal a flow cookie: an HS256 JWT expiring at `now_unix + ttl_secs`.
///
/// `now_unix` is seconds since the epoch; production passes the current time,
/// and a test passes a fixed value. Expiry is checked on [`open_flow`] against
/// the real clock.
///
/// # Errors
///
/// [`FlowCookieError::Invalid`] if encoding fails (it does not, for these
/// plain-string claims, but the fallible signature keeps the caller honest).
pub fn seal_flow(
    key: &CookieKey,
    state: &str,
    nonce: &str,
    pkce_verifier: &str,
    now_unix: u64,
    ttl_secs: u64,
) -> Result<String, FlowCookieError> {
    let claims = FlowClaims {
        exp: now_unix.saturating_add(ttl_secs),
        state: state.to_owned(),
        nonce: nonce.to_owned(),
        pkce: pkce_verifier.to_owned(),
    };
    jsonwebtoken::encode(&Header::new(ALG), &claims, &key.encoding)
        .map_err(|_| FlowCookieError::Invalid)
}

/// Open a flow cookie, verifying its signature and expiry.
///
/// # Errors
///
/// [`FlowCookieError::Invalid`] if the cookie is malformed, was not signed by
/// `key`, or has expired.
pub fn open_flow(key: &CookieKey, cookie: &str) -> Result<FlowState, FlowCookieError> {
    // Pin the algorithm: a token claiming any other `alg` is refused, so a
    // forged `alg: none` or an RS/HS confusion cannot get past the key check.
    let mut validation = Validation::new(ALG);
    validation.set_required_spec_claims(&["exp"]);
    let claims = jsonwebtoken::decode::<FlowClaims>(cookie, &key.decoding, &validation)
        .map_err(|_| FlowCookieError::Invalid)?
        .claims;
    Ok(FlowState {
        state: claims.state,
        nonce: claims.nonce,
        pkce_verifier: claims.pkce,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &[u8] = b"a-test-signing-secret-of-some-length";

    fn key() -> CookieKey {
        CookieKey::from_secret(SECRET)
    }

    /// A `now` comfortably in the past/future of the real clock, so expiry is
    /// unambiguous despite jsonwebtoken's default 60s leeway.
    fn now() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("after the epoch")
            .as_secs()
    }

    #[test]
    fn a_sealed_flow_cookie_round_trips() {
        let sealed = seal_flow(&key(), "the-state", "the-nonce", "the-verifier", now(), 600)
            .expect("sealing succeeds");

        let recovered = open_flow(&key(), &sealed).expect("a fresh cookie opens");

        assert_eq!(
            recovered,
            FlowState {
                state: "the-state".to_owned(),
                nonce: "the-nonce".to_owned(),
                pkce_verifier: "the-verifier".to_owned(),
            }
        );
    }

    #[test]
    fn a_tampered_cookie_is_rejected() {
        let sealed = seal_flow(&key(), "s", "n", "v", now(), 600).expect("sealing succeeds");
        // Flip one character of the payload segment; the signature no longer
        // matches.
        let (head, rest) = sealed.split_once('.').expect("a JWT has segments");
        let mut payload: Vec<u8> = rest.as_bytes().to_vec();
        payload[0] = if payload[0] == b'A' { b'B' } else { b'A' };
        let tampered = format!("{head}.{}", String::from_utf8(payload).expect("ascii"));

        assert!(matches!(
            open_flow(&key(), &tampered),
            Err(FlowCookieError::Invalid)
        ));
    }

    #[test]
    fn a_cookie_signed_with_another_key_is_rejected() {
        let other = CookieKey::from_secret(b"some-other-secret-entirely-different");
        let sealed = seal_flow(&other, "s", "n", "v", now(), 600).expect("sealing succeeds");

        assert!(matches!(
            open_flow(&key(), &sealed),
            Err(FlowCookieError::Invalid)
        ));
    }

    #[test]
    fn an_expired_cookie_is_rejected() {
        // Expired 400s ago: well past the 60s default leeway.
        let sealed = seal_flow(&key(), "s", "n", "v", now() - 1000, 600).expect("sealing succeeds");

        assert!(matches!(
            open_flow(&key(), &sealed),
            Err(FlowCookieError::Invalid)
        ));
    }

    #[test]
    fn a_malformed_cookie_is_rejected() {
        for junk in ["", "not-a-jwt", "a.b.c"] {
            assert!(matches!(
                open_flow(&key(), junk),
                Err(FlowCookieError::Invalid)
            ));
        }
    }

    #[test]
    fn the_key_debug_is_redacted() {
        assert_eq!(format!("{:?}", key()), "CookieKey(<redacted>)");
    }
}
