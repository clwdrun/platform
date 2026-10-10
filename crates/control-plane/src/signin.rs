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

use axum::Extension;
use axum::extract::{RawQuery, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use shared::{Error, RequestId};

use crate::auth::unavailable;
use crate::db;
use crate::http::{AppState, render};
use crate::openapi::{Doc, Success};
use crate::session;

/// The signing algorithm for the flow cookie.
const ALG: Algorithm = Algorithm::HS256;

/// The HS256 key the flow cookie is signed and verified with.
///
/// Holds key material, so its `Debug` redacts — a `{:?}` of the app state must
/// never print it. Built from a secret supplied by configuration (#22 will own
/// where that secret comes from and how it rotates).
pub struct CookieKey {
    pub(crate) encoding: EncodingKey,
    pub(crate) decoding: DecodingKey,
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
    /// An app-host handshake to resume after sign-in (its state), if sign-in
    /// was started by `/authorize`. Signed with the rest of the cookie, so it
    /// cannot be swapped in transit, and re-validated before use.
    pub resume: Option<String>,
}

/// The JWT claims of a flow cookie.
#[derive(Serialize, Deserialize)]
struct FlowClaims {
    /// Expiry, seconds since the epoch. `jsonwebtoken` enforces it on decode.
    exp: u64,
    state: String,
    nonce: String,
    pkce: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    resume: Option<String>,
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
    resume: Option<&crate::handshake::HandshakeState>,
) -> Result<String, FlowCookieError> {
    let claims = FlowClaims {
        exp: now_unix.saturating_add(ttl_secs),
        state: state.to_owned(),
        nonce: nonce.to_owned(),
        pkce: pkce_verifier.to_owned(),
        resume: resume.map(|r| r.expose().to_owned()),
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
        resume: claims.resume,
    })
}

// ---------------------------------------------------------------- routes ----

/// The flow cookie's name.
///
/// `__Host-`: host-only, `Path=/`, `Secure` — the browser refuses anything else,
/// so no subdomain can plant or read one. Unlike the session cookie it has no
/// reason to be seen anywhere but the control plane's own origin.
pub const FLOW_COOKIE: &str = "__Host-clwd_signin";

/// How long a sign-in may take between the redirect and the callback.
const FLOW_TTL_SECS: u64 = 600;

/// Everything the two sign-in routes need: the discovered flow, the HTTP
/// client it runs over, the cookie key, and the control plane's own origin.
pub struct SignIn {
    flow: identity::Flow,
    http: reqwest::Client,
    key: CookieKey,
    origin: String,
}

impl SignIn {
    /// The control plane's own origin (`https://api.<apex>`), taken from the
    /// configured redirect URI: the one origin a cookie-authenticated
    /// state-changing request is accepted from.
    #[must_use]
    pub fn origin(&self) -> &str {
        &self.origin
    }

    /// The key session and flow cookies are signed with.
    #[must_use]
    pub(crate) fn key(&self) -> &CookieKey {
        &self.key
    }

    /// Discover the issuer and assemble the sign-in configuration.
    ///
    /// # Errors
    ///
    /// Whatever [`identity::Flow::discover`] reports, and
    /// [`identity::FlowError::Unavailable`] if the HTTP client cannot be built.
    pub async fn discover(
        config: identity::OidcConfig,
        key: CookieKey,
    ) -> Result<Self, identity::FlowError> {
        crate::acme::install_crypto_provider();
        let origin = reqwest::Url::parse(&config.redirect_uri)
            .map(|url| url.origin().ascii_serialization())
            .map_err(|e| identity::FlowError::Rejected(format!("redirect uri: {e}")))?;
        // No redirects: the token endpoint is a credentialed POST, and a
        // followed redirect is how a client secret reaches a host nobody chose.
        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .map_err(|e| identity::FlowError::Unavailable(e.to_string()))?;
        let flow = identity::Flow::discover(config, &http).await?;
        Ok(Self {
            flow,
            http,
            key,
            origin,
        })
    }
}

fn flow_cookie(value: &str, max_age_secs: u64) -> String {
    format!("{FLOW_COOKIE}={value}; Path=/; Max-Age={max_age_secs}; HttpOnly; Secure; SameSite=Lax")
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn not_configured() -> Error {
    Error::Internal {
        source: anyhow::anyhow!("sign-in is not configured on this control plane"),
    }
}

/// `GET /auth/google`: set the flow cookie and send the browser to Google.
///
/// Takes no `return_to`/`next` parameter, deliberately: the callback always
/// lands on the control plane's own root, so there is no redirect target to validate and no
/// open redirect to get wrong.
pub(crate) async fn start(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    RawQuery(query): RawQuery,
) -> Response {
    // `resume` is the only parameter: an app-host handshake's state, which
    // brings the visitor back to `/authorize` on this host after sign-in. It
    // is a token in the shape this platform mints, not a URL, so there is
    // still no redirect target to validate.
    let resume = form_urlencoded::parse(query.as_deref().unwrap_or("").as_bytes())
        .find(|(name, _)| name == "resume")
        .and_then(|(_, value)| crate::handshake::HandshakeState::parse(&value));
    let Some(signin) = state.signin.as_deref() else {
        return render(&not_configured(), &request_id);
    };
    let auth = signin.flow.authorize();
    let sealed = match seal_flow(
        &signin.key,
        auth.state(),
        auth.nonce(),
        auth.pkce_verifier(),
        now_unix(),
        FLOW_TTL_SECS,
        resume.as_ref(),
    ) {
        Ok(sealed) => sealed,
        Err(e) => return render(&Error::Internal { source: e.into() }, &request_id),
    };
    (
        StatusCode::SEE_OTHER,
        [
            (header::LOCATION, auth.redirect_to().to_owned()),
            (header::SET_COOKIE, flow_cookie(&sealed, FLOW_TTL_SECS)),
        ],
    )
        .into_response()
}

/// `GET /auth/google/callback`: finish sign-in and issue a session.
///
/// In order, each a denial before the next runs: the flow cookie must open;
/// `state` must equal the cookie's (so a forged callback never reaches the
/// exchange); the code is exchanged under the cookie's PKCE verifier and the
/// ID token verified against its nonce; the user is found **by Google
/// subject**; a session is issued. The flow cookie is cleared on every
/// outcome, success or not.
///
/// # A fresh session, always
///
/// The session cookie the browser arrived with is never read here. Sign-in
/// mints a new session whatever came in, so a session planted before sign-in
/// (fixation) is not the one the user ends up authenticated as.
pub(crate) async fn callback(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    RawQuery(query): RawQuery,
    headers: HeaderMap,
) -> Response {
    let mut response = match finish(&state, query.as_deref().unwrap_or(""), &headers).await {
        Ok(response) => response,
        Err(error) => render(&error, &request_id),
    };
    if let Ok(clear) = HeaderValue::from_str(&flow_cookie("", 0)) {
        response.headers_mut().append(header::SET_COOKIE, clear);
    }
    response
}

async fn finish(state: &AppState, query: &str, headers: &HeaderMap) -> Result<Response, Error> {
    let signin = state.signin.as_deref().ok_or_else(not_configured)?;

    let cookie =
        crate::session::single_cookie(headers, FLOW_COOKIE).ok_or(Error::Unauthenticated {})?;
    let flow = open_flow(&signin.key, cookie).map_err(|_| Error::Unauthenticated {})?;

    let mut presented_state = None;
    let mut code = None;
    for (name, value) in form_urlencoded::parse(query.as_bytes()) {
        match &*name {
            "state" => presented_state = Some(value.into_owned()),
            "code" => code = Some(value.into_owned()),
            _ => {}
        }
    }

    // Before the exchange: a callback whose state is not this browser's is a
    // forgery, and must not cost a round trip to Google or burn a code.
    let presented_state = presented_state.ok_or(Error::Unauthenticated {})?;
    if !constant_time_eq(presented_state.as_bytes(), flow.state.as_bytes()) {
        return Err(Error::Unauthenticated {});
    }
    // An `error=access_denied` callback has no code: one more denial.
    let code = code.ok_or(Error::Unauthenticated {})?;

    let identity = signin
        .flow
        .exchange(&signin.http, &code, &flow.pkce_verifier, &flow.nonce)
        .await
        .map_err(|e| match e {
            identity::FlowError::Unavailable(reason) => {
                tracing::warn!(%reason, "the identity provider is unavailable");
                Error::Timeout {
                    dependency: "the identity provider".to_owned(),
                }
            }
            other => {
                tracing::info!(reason = %other, "sign-in rejected");
                Error::Unauthenticated {}
            }
        })?;

    // `users.email` is required, and only a verified address is carried at
    // all; an account without one cannot sign in.
    let email = identity
        .email
        .as_deref()
        .ok_or(Error::Unauthenticated {})?
        .to_lowercase();

    let hd = identity.hosted_domain.as_ref();
    let user =
        match db::upsert_google_user(&state.pool, identity.subject.as_str(), &email, hd).await {
            Ok(Some(user)) => user,
            Ok(None) => return Err(Error::Unauthenticated {}),
            Err(sqlx::Error::Database(e)) if e.constraint() == Some("users_email_key") => {
                return Err(Error::Conflict {
                    what: "another account already uses this email address".to_owned(),
                });
            }
            Err(e) => return Err(unavailable(e)),
        };

    // Which orgs this person belongs to, decided by `hd` and nothing else —
    // see `orgs` for the rule and why the email's domain plays no part.
    crate::orgs::resolve_at_sign_in(&state.pool, user, hd).await?;

    let issued = session::issue(&state.pool, &signin.key, user)
        .await?
        .ok_or(Error::Unauthenticated {})?;

    Ok((
        StatusCode::SEE_OTHER,
        [
            (
                header::LOCATION,
                match flow
                    .resume
                    .as_deref()
                    .and_then(crate::handshake::HandshakeState::parse)
                {
                    Some(resume) => {
                        format!("{}/authorize?state={}", signin.origin, resume.expose())
                    }
                    None => format!("{}/", signin.origin),
                },
            ),
            (header::SET_COOKIE, issued.set_cookie),
        ],
    )
        .into_response())
}

/// `POST /auth/logout`: revoke the session server-side and clear its cookie.
///
/// Always `204`, whatever the request carried: no cookie, a forged one, an
/// expired or already-revoked one. Distinguishing those would tell a caller
/// whether a cookie it holds was live. Only a database failure is reported,
/// as what it is.
///
/// `POST`, never `GET`: an `<img src>` on any page can fire a GET logout. A
/// cross-site POST does not carry the `SameSite=Lax` session cookie, so it
/// revokes nothing. A same-*site* one — script on an app subdomain — does;
/// that exposure is the shared-registrable-domain problem in #62.
pub(crate) async fn logout(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
) -> Response {
    let Some(signin) = state.signin.as_deref() else {
        return render(&not_configured(), &request_id);
    };
    match session::authenticate(&state.pool, &signin.key, &headers).await {
        Ok(live) => {
            if let Err(e) = db::revoke_session(&state.pool, live.id).await {
                return render(&unavailable(e), &request_id);
            }
        }
        Err(Error::Unauthenticated {}) => {}
        Err(other) => return render(&other, &request_id),
    }
    (
        StatusCode::NO_CONTENT,
        [(header::SET_COOKIE, session::clear_cookie())],
    )
        .into_response()
}

pub(crate) fn logout_doc() -> Doc {
    Doc {
        operation_id: "sign_out",
        summary: "Sign out",
        description: "Revokes the session the session cookie names, server-side, and clears the \
                      cookie. Idempotent and uninformative: a request with no session, or with an \
                      expired, revoked or forged one, gets the same `204`. A `POST` so that a \
                      cross-site image tag cannot sign anyone out.",
        params: &[],
        request: None,
        success: vec![Success {
            status: StatusCode::NO_CONTENT,
            description: "Signed out: any session the cookie named is revoked, and the cookie is cleared.",
            body: None,
        }],
        errors: &[],
    }
}

/// Compare without an early exit, so the time taken does not say how much of
/// a guessed `state` was right.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

pub(crate) fn start_doc() -> Doc {
    Doc {
        operation_id: "sign_in_start",
        summary: "Start Google sign-in",
        description: "Sets a short-lived, signed flow cookie carrying the OIDC `state`, `nonce` and \
                      PKCE verifier, and redirects the browser to Google. Takes no redirect-target \
                      parameter: the callback always lands on the control plane's own root.",
        params: &[],
        request: None,
        success: vec![Success {
            status: StatusCode::SEE_OTHER,
            description: "Redirect to Google's authorization endpoint.",
            body: None,
        }],
        errors: &[],
    }
}

pub(crate) fn callback_doc() -> Doc {
    Doc {
        operation_id: "sign_in_callback",
        summary: "Finish Google sign-in",
        description: "Google redirects here with `code` and `state`. Validates the flow cookie and \
                      `state`, exchanges the code under PKCE, verifies the ID token, finds the user \
                      by Google subject, and issues a fresh session cookie. Every rejection — a \
                      missing or tampered flow cookie, a mismatched `state`, a refused or replayed \
                      code, a failed ID token — is the same `identity.unauthenticated`.",
        params: &[],
        request: None,
        success: vec![Success {
            status: StatusCode::SEE_OTHER,
            description: "Signed in: a session cookie is set and the browser is sent to the control plane's own root.",
            body: None,
        }],
        errors: &["identity.unauthenticated", "control-plane.conflict"],
    }
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
        let sealed = seal_flow(
            &key(),
            "the-state",
            "the-nonce",
            "the-verifier",
            now(),
            600,
            None,
        )
        .expect("sealing succeeds");

        let recovered = open_flow(&key(), &sealed).expect("a fresh cookie opens");

        assert_eq!(
            recovered,
            FlowState {
                state: "the-state".to_owned(),
                nonce: "the-nonce".to_owned(),
                pkce_verifier: "the-verifier".to_owned(),
                resume: None,
            }
        );
    }

    #[test]
    fn a_tampered_cookie_is_rejected() {
        let sealed = seal_flow(&key(), "s", "n", "v", now(), 600, None).expect("sealing succeeds");
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
        let sealed = seal_flow(&other, "s", "n", "v", now(), 600, None).expect("sealing succeeds");

        assert!(matches!(
            open_flow(&key(), &sealed),
            Err(FlowCookieError::Invalid)
        ));
    }

    #[test]
    fn an_expired_cookie_is_rejected() {
        // Expired 400s ago: well past the 60s default leeway.
        let sealed =
            seal_flow(&key(), "s", "n", "v", now() - 1000, 600, None).expect("sealing succeeds");

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
