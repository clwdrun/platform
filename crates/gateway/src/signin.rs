//! The gateway's half of the app-host sign-in handshake (#62).
//!
//! The control plane's half, and the whole sequence, is documented on
//! `control_plane::handshake`. Here: the internal client the gateway uses to
//! begin a handshake, exchange its code and check a session on every request,
//! and the three cookies it sets on an app host.
//!
//! Every cookie here is `__Host-`: `Secure`, `Path=/`, no `Domain`. So it lives
//! on exactly one app host, and no other host — another app, or the control
//! plane — can set, overwrite or shadow it. What an app can still do is set
//! one *on its own host* from its own script; that reaches only itself.

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use reqwest::StatusCode;
use shared::hop::{AppSubject, Caller, OrgId};
use shared::return_path::ReturnPath;
use thiserror::Error;

/// The app-host session cookie.
pub const APP_SESSION_COOKIE: &str = "__Host-clwd_app_session";
/// The handshake state cookies, one per handshake in flight, binding a
/// callback to the browser that began it. Each is named
/// `__Host-clwd_state.<id>`, where `<id>` is the first [`STATE_ID_LEN`]
/// characters of the handshake's state, so the callback, which carries the
/// state, reads only its own cookie and clears only that one. One cookie per
/// host, overwritten by the second tab, made two concurrent sign-ins
/// invalidate each other until the loop guard stopped them (#83).
pub const STATE_COOKIE_PREFIX: &str = "__Host-clwd_state.";
/// How much of the state names its cookie: 64 bits, unique among a browser's
/// handful of handshakes in flight. The cookie's value still holds the whole
/// state, compared in constant time.
pub const STATE_ID_LEN: usize = 16;
/// How many handshakes one browser may have in flight for one host. A page
/// that opens many tabs must not grow the `Cookie` header without limit: a
/// handshake beyond this evicts the oldest, whose tab then restarts.
pub const MAX_IN_FLIGHT: usize = 4;
/// The handshake counter, for the loop guard.
pub const COUNTER_COOKIE: &str = "__Host-clwd_hs";
/// How many handshakes one browser may start for one app host inside
/// [`COUNTER_WINDOW_SECS`] before the gateway stops redirecting and shows an
/// error. Two concurrent tabs and one restart fit under it; a loop does not.
pub const MAX_HANDSHAKES: u8 = 4;
/// The loop guard's window.
pub const COUNTER_WINDOW_SECS: u64 = 60;
/// How long a begun handshake's state cookie lives.
const STATE_TTL_SECS: u64 = 600;

/// The `Set-Cookie` value for the app-host session — the one place its
/// attributes are written.
///
/// - **`__Host-`, no `Domain`, `Path=/`, `Secure`**: host-only, so it exists on
///   this app host alone. Adding `Domain=` makes a browser refuse it.
/// - **`HttpOnly`**: the app's script can neither read it nor overwrite it.
/// - **`SameSite=Lax`, not `Strict`**: a link to an app from email or another
///   site is a cross-site top-level navigation. Under `Strict` the cookie is
///   withheld on it — and on the redirects that follow, since a browser judges
///   the whole chain by where it began — so the gateway would start a
///   handshake, set the cookie, redirect, find it withheld again, and loop.
///   `Lax` sends it on top-level navigations and withholds it from cross-site
///   subrequests and form posts.
/// - **`Max-Age`**: no later than the parent control-plane session's end; the
///   control plane computes it.
#[must_use]
pub fn app_session_cookie(value: &str, max_age_secs: i64) -> String {
    format!(
        "{APP_SESSION_COOKIE}={value}; Path=/; Max-Age={max_age_secs}; HttpOnly; Secure; SameSite=Lax"
    )
}

/// The state cookie's name for `state`, or `None` if `state` is not the
/// control plane's shape (hex, at least [`STATE_ID_LEN`] long): the id goes
/// into a header name, so only hex ever does.
#[must_use]
pub fn state_cookie_name(state: &str) -> Option<String> {
    let id = state.get(..STATE_ID_LEN)?;
    id.bytes()
        .all(|b| b.is_ascii_hexdigit())
        .then(|| format!("{STATE_COOKIE_PREFIX}{id}"))
}

/// The `Set-Cookie` value for one handshake state cookie, named `name`. Same
/// attributes as the session for the same reasons; `Lax` in particular,
/// because the callback arrives as a top-level navigation from the control
/// plane, another site.
#[must_use]
pub fn state_cookie(name: &str, value: &str, max_age_secs: u64) -> String {
    format!("{name}={value}; Path=/; Max-Age={max_age_secs}; HttpOnly; Secure; SameSite=Lax")
}

/// A state cookie's value: when the handshake began (Unix microseconds, for
/// evicting the oldest) and the state itself.
#[must_use]
pub fn state_cookie_value(begun_us: u128, state: &str) -> String {
    format!("{begun_us}.{state}")
}

/// The `(begun_us, state)` a state cookie's value holds, if well formed.
#[must_use]
pub fn parse_state_cookie_value(value: &str) -> Option<(u128, &str)> {
    let (ms, state) = value.split_once('.')?;
    Some((ms.parse().ok()?, state))
}

/// The `Set-Cookie` value for the loop guard's counter.
#[must_use]
pub fn counter_cookie(count: u8, max_age_secs: u64) -> String {
    format!(
        "{COUNTER_COOKIE}={count}; Path=/; Max-Age={max_age_secs}; HttpOnly; Secure; SameSite=Lax"
    )
}

/// A fresh state cookie for a begun handshake begun at `begun_us`, or `None`
/// if `state` is not the control plane's shape.
#[must_use]
pub fn begun_state_cookie(state: &str, begun_us: u128) -> Option<String> {
    Some(state_cookie(
        &state_cookie_name(state)?,
        &state_cookie_value(begun_us, state),
        STATE_TTL_SECS,
    ))
}

/// An app-host session secret, as read from its cookie. Redacted `Debug`.
#[derive(Clone, PartialEq, Eq)]
pub struct AppSession(String);

impl AppSession {
    /// Wrap a cookie value.
    #[must_use]
    pub fn new(value: &str) -> Self {
        Self(value.to_owned())
    }
}

impl fmt::Debug for AppSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AppSession(<redacted>)")
    }
}

/// A completed exchange: the session to set and where to send the visitor.
#[derive(Debug)]
#[non_exhaustive]
pub struct Exchanged {
    pub session: AppSession,
    pub max_age_secs: i64,
    pub return_path: ReturnPath,
}

impl Exchanged {
    /// The session cookie to set for this exchange.
    #[must_use]
    pub fn set_cookie(&self) -> String {
        app_session_cookie(&self.session.0, self.max_age_secs)
    }
}

/// The control plane could not be asked.
#[derive(Debug, Error)]
#[error("the control plane could not be reached for sign-in: {0}")]
pub struct Unreachable(String);

/// An HTTP failure talking to the control plane, as [`Unreachable`]: the
/// URL left out (it can carry a code or a state), but what kind of failure it
/// was and its whole cause chain kept. reqwest's own message is only "error
/// sending request" for a timeout, a refused connection and a reset alike,
/// which could not tell a pool wait from a dead connection (#90).
fn unreachable(error: reqwest::Error) -> Unreachable {
    let kind = if error.is_timeout() {
        "timeout"
    } else if error.is_connect() {
        "connect"
    } else if error.is_body() || error.is_decode() {
        "body"
    } else if error.is_request() {
        "request"
    } else {
        "other"
    };
    let error = error.without_url();
    let mut message = format!("{kind}: {error}");
    let mut source = std::error::Error::source(&error);
    while let Some(cause) = source {
        message.push_str(": ");
        message.push_str(&cause.to_string());
        source = cause.source();
    }
    Unreachable(message)
}

/// The gateway's client for the control plane's internal sign-in routes.
pub struct SigninClient {
    client: reqwest::Client,
    base: String,
    secret: Arc<str>,
}

#[derive(serde::Deserialize)]
struct BeginResponse {
    state: String,
}

#[derive(serde::Deserialize)]
struct ExchangeResponse {
    session: String,
    max_age_secs: i64,
    return_path: String,
}

impl SigninClient {
    /// A client for the control plane's internal listener at `base`,
    /// presenting `secret`.
    ///
    /// # Errors
    ///
    /// [`Unreachable`] if the HTTP client cannot be built.
    pub fn new(base: impl Into<String>, secret: impl Into<Arc<str>>) -> Result<Self, Unreachable> {
        let client = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(2))
            .timeout(Duration::from_secs(5))
            // Never follow a redirect from the internal listener: the secret
            // rides on every request.
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| Unreachable(e.to_string()))?;
        Ok(Self {
            client,
            base: base.into(),
            secret: secret.into(),
        })
    }

    async fn post(
        &self,
        path: &str,
        body: serde_json::Value,
    ) -> Result<reqwest::Response, Unreachable> {
        self.client
            .post(format!("{}{path}", self.base))
            .bearer_auth(self.secret.as_ref())
            .json(&body)
            .send()
            .await
            .map_err(unreachable)
    }

    /// Begin a handshake for `app_id`, returning its state.
    ///
    /// # Errors
    ///
    /// [`Unreachable`] if the control plane could not be asked or refused.
    pub async fn begin(
        &self,
        app_id: &str,
        return_path: &ReturnPath,
    ) -> Result<String, Unreachable> {
        let response = self
            .post(
                "/internal/handshakes",
                serde_json::json!({ "app_id": app_id, "return_path": return_path.as_str() }),
            )
            .await?;
        if response.status() != StatusCode::CREATED {
            return Err(Unreachable(format!("begin answered {}", response.status())));
        }
        let body: BeginResponse = response.json().await.map_err(unreachable)?;
        Ok(body.state)
    }

    /// Exchange a callback's code and state. `Ok(None)` when the control
    /// plane refuses the pair — used, expired, or forged.
    ///
    /// # Errors
    ///
    /// [`Unreachable`] if the control plane could not be asked.
    pub async fn exchange(
        &self,
        code: &str,
        state: &str,
    ) -> Result<Option<Exchanged>, Unreachable> {
        let response = self
            .post(
                "/internal/handshakes/exchange",
                serde_json::json!({ "code": code, "state": state }),
            )
            .await?;
        match response.status() {
            StatusCode::OK => {
                let body: ExchangeResponse = response.json().await.map_err(unreachable)?;
                Ok(Some(Exchanged {
                    session: AppSession(body.session),
                    max_age_secs: body.max_age_secs,
                    return_path: ReturnPath::parse(&body.return_path)
                        .unwrap_or_else(|_| ReturnPath::root()),
                }))
            }
            StatusCode::UNAUTHORIZED | StatusCode::BAD_REQUEST => Ok(None),
            other => Err(Unreachable(format!("exchange answered {other}"))),
        }
    }

    /// Who `session` belongs to, if it is live for `app_id` — the per-request
    /// check. The identity comes from the control plane's one statement, never
    /// from anything in the request.
    ///
    /// # Errors
    ///
    /// [`Unreachable`] if the control plane could not be asked: the caller
    /// fails closed.
    pub async fn check(
        &self,
        session: &AppSession,
        app_id: &str,
    ) -> Result<Option<Checked>, Unreachable> {
        let response = self
            .post(
                "/internal/app-sessions/check",
                serde_json::json!({ "session": session.0, "app_id": app_id }),
            )
            .await?;
        match response.status() {
            StatusCode::OK => {
                let body: CheckResponse = response.json().await.map_err(unreachable)?;
                Ok(Some(Checked {
                    caller: Caller::new(
                        AppSubject::new(body.subject),
                        Some(body.email),
                        OrgId::new(body.org_id),
                    ),
                    member: body.member,
                }))
            }
            StatusCode::UNAUTHORIZED | StatusCode::BAD_REQUEST => Ok(None),
            other => Err(Unreachable(format!("check answered {other}"))),
        }
    }
}

#[derive(serde::Deserialize)]
struct CheckResponse {
    subject: String,
    email: String,
    org_id: String,
    member: bool,
}

/// A live app-host session's visitor.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Checked {
    /// Who the app is told is calling.
    pub caller: Caller,
    /// Whether the visitor is a member of the app's org. The interim access
    /// rule until #12: a non-member's request reaches no app code.
    pub member: bool,
}

#[must_use]
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_cookie_is_host_only_and_lax() {
        for c in [
            app_session_cookie("v", 60),
            begun_state_cookie(&"ab".repeat(32), 1).expect("hex state"),
            counter_cookie(1, 60),
        ] {
            assert!(c.starts_with("__Host-clwd_"), "{c}");
            assert!(c.contains("; Path=/;"), "{c}");
            assert!(c.contains("; HttpOnly; Secure; SameSite=Lax"), "{c}");
            assert!(!c.to_ascii_lowercase().contains("domain"), "{c}");
        }
        assert_eq!(
            app_session_cookie("v", 60),
            "__Host-clwd_app_session=v; Path=/; Max-Age=60; HttpOnly; Secure; SameSite=Lax"
        );
    }

    #[test]
    fn a_state_cookie_is_named_by_its_state_and_only_hex_names_one() {
        let state = "0123456789abcdef".repeat(4);
        assert_eq!(
            state_cookie_name(&state).as_deref(),
            Some("__Host-clwd_state.0123456789abcdef")
        );
        let set = begun_state_cookie(&state, 42).expect("hex state");
        assert!(set.starts_with(&format!("__Host-clwd_state.0123456789abcdef=42.{state};")));
        assert_eq!(
            parse_state_cookie_value(&format!("42.{state}")),
            Some((42, state.as_str()))
        );
        for bad in ["short", "0123456789abcdeg0000", "0123456789abcde;=x", ""] {
            assert_eq!(state_cookie_name(bad), None, "{bad}");
        }
    }

    #[test]
    fn a_session_debug_is_redacted() {
        assert_eq!(
            format!("{:?}", AppSession::new("secret")),
            "AppSession(<redacted>)"
        );
    }
}
