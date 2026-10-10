//! The hop from the gateway to an app (#62, ahead of #11).
//!
//! # What reaches this hop
//!
//! Only a request carrying a valid app-host session for the app it addresses
//! — the edge checks before calling [`AppUpstream::forward`] — and only after
//! the platform's own cookies are removed from it ([`shared::cookie`]). On the
//! way back, any `Set-Cookie` an app writes under a platform name is dropped
//! before the browser sees it.
//!
//! # Where it goes is never the request's to choose
//!
//! [`AppTarget`] names the app, and only the gateway can build one, from the
//! app row the control plane resolved for the requested host. No header, query
//! parameter or path chooses a destination: an implementation forwards to the
//! app the target names and nowhere else. A forwarding hop that took its
//! destination from the request would be an open proxy into the platform's
//! network.
//!
//! # No production implementation yet
//!
//! #11 adds the one that runs app code. Until then the edge has no upstream
//! and answers a live app with `gateway.not_ready`, exactly as before. The
//! only implementation that exists is the integration tests' HTTP upstream,
//! which lives under `tests/` and is never compiled into the gateway binary —
//! `just release-has-no-test-upstream` checks the release build for it.

use async_trait::async_trait;
use bytes::Bytes;
use http::{HeaderMap, Method, StatusCode};
use shared::hop::Caller;

/// The app a request is forwarded to, as the control plane resolved it.
/// Built only by the gateway; there is no public constructor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppTarget {
    app_id: String,
    org_id: String,
}

impl AppTarget {
    pub(crate) fn new(app_id: String, org_id: String) -> Self {
        Self { app_id, org_id }
    }

    /// The resolved app's id.
    #[must_use]
    pub fn app_id(&self) -> &str {
        &self.app_id
    }

    /// The resolved app's org id.
    #[must_use]
    pub fn org_id(&self) -> &str {
        &self.org_id
    }
}

/// A request on its way to an app, platform cookies already removed.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct UpstreamRequest {
    /// Who is calling, from the gateway's session check. Never a header.
    pub caller: Caller,
    pub method: Method,
    /// The path and query the visitor asked for, as received.
    pub path_and_query: String,
    pub headers: HeaderMap,
    pub body: Bytes,
}

impl UpstreamRequest {
    pub(crate) fn new(
        caller: Caller,
        method: Method,
        path_and_query: String,
        headers: HeaderMap,
        body: Bytes,
    ) -> Self {
        Self {
            caller,
            method,
            path_and_query,
            headers,
            body,
        }
    }
}

/// An app's answer, before the gateway filters its `Set-Cookie` headers.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct UpstreamResponse {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: Bytes,
}

impl UpstreamResponse {
    /// Assemble a response.
    #[must_use]
    pub fn new(status: StatusCode, headers: HeaderMap, body: Bytes) -> Self {
        Self {
            status,
            headers,
            body,
        }
    }
}

/// The app could not be reached.
#[derive(Debug, thiserror::Error)]
#[error("the app could not be reached: {0}")]
pub struct UpstreamError(pub String);

/// Delivers a request to the app named by an [`AppTarget`].
#[async_trait]
pub trait AppUpstream: Send + Sync {
    /// Forward `request` to `target`'s app and return its answer.
    ///
    /// # Errors
    ///
    /// [`UpstreamError`] when the app could not be reached.
    async fn forward(
        &self,
        target: &AppTarget,
        request: UpstreamRequest,
    ) -> Result<UpstreamResponse, UpstreamError>;
}

/// Headers a client could send to claim an identity or an origin, or that a
/// proxy in front of us would add. All of them are removed before the hop: the
/// app's caller comes from the session check alone, and it sees no forwarding
/// information at all (normalised client-address information can be added when
/// an app needs it).
const CLIENT_IDENTITY: &[&str] = &[
    "forwarded",
    "x-real-ip",
    "x-client-ip",
    "true-client-ip",
    "cf-connecting-ip",
];
/// Prefixes removed for the same reason: `x-clwd-*` is the platform's
/// namespace, and `x-forwarded-*` is a proxy's.
const CLIENT_IDENTITY_PREFIXES: &[&str] = &["x-clwd-", "x-forwarded-"];
/// Hop-by-hop headers (RFC 9110 §7.6.1): they describe one connection and
/// never cross a proxy, in either direction.
const HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-connection",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

/// Remove every header that could carry a client-chosen identity or origin,
/// and the hop-by-hop ones.
pub fn strip_client_identity(headers: &mut HeaderMap) {
    let names: Vec<http::HeaderName> = headers
        .keys()
        .filter(|name| {
            let name = name.as_str();
            CLIENT_IDENTITY.contains(&name)
                || CLIENT_IDENTITY_PREFIXES.iter().any(|p| name.starts_with(p))
        })
        .cloned()
        .collect();
    for name in names {
        headers.remove(name);
    }
    strip_hop_by_hop(headers);
}

/// Remove hop-by-hop headers, including any the `Connection` header names.
pub fn strip_hop_by_hop(headers: &mut HeaderMap) {
    let named: Vec<String> = headers
        .get_all(http::header::CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .map(|n| n.trim().to_ascii_lowercase())
        .filter(|n| !n.is_empty())
        .collect();
    for name in HOP_BY_HOP
        .iter()
        .copied()
        .chain(named.iter().map(String::as_str))
    {
        headers.remove(name);
    }
}

/// Remove `Set-Cookie` headers that would set a platform cookie, keeping the
/// app's own. Returns how many were removed.
pub fn drop_platform_set_cookies(headers: &mut HeaderMap) -> usize {
    let all: Vec<http::HeaderValue> = headers
        .get_all(http::header::SET_COOKIE)
        .iter()
        .cloned()
        .collect();
    let kept: Vec<http::HeaderValue> = all
        .iter()
        .filter(|v| !shared::cookie::sets_platform_cookie(v.as_bytes()))
        .cloned()
        .collect();
    let removed = all.len() - kept.len();
    headers.remove(http::header::SET_COOKIE);
    for value in kept {
        headers.append(http::header::SET_COOKIE, value);
    }
    removed
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::HeaderValue;

    #[test]
    fn client_identity_and_hop_by_hop_headers_are_stripped() {
        let mut headers = HeaderMap::new();
        for (name, value) in [
            ("x-clwd-caller", "someone-else"),
            ("X-Clwd-Subject", "forged"),
            ("forwarded", "for=1.2.3.4"),
            ("x-forwarded-for", "1.2.3.4"),
            ("x-forwarded-host", "evil.example"),
            ("x-real-ip", "1.2.3.4"),
            ("x-client-ip", "1.2.3.4"),
            ("true-client-ip", "1.2.3.4"),
            ("cf-connecting-ip", "1.2.3.4"),
            ("connection", "keep-alive, x-secret-hop"),
            ("x-secret-hop", "1"),
            ("upgrade", "websocket"),
            ("accept", "text/html"),
            ("x-app-header", "kept"),
        ] {
            headers.append(
                http::HeaderName::from_bytes(name.as_bytes()).expect("name"),
                HeaderValue::from_static(value),
            );
        }
        strip_client_identity(&mut headers);
        let mut left: Vec<&str> = headers.keys().map(http::HeaderName::as_str).collect();
        left.sort_unstable();
        assert_eq!(left, ["accept", "x-app-header"]);
    }

    #[test]
    fn platform_set_cookies_are_dropped_and_the_apps_kept() {
        let mut headers = HeaderMap::new();
        for value in [
            "theme=dark; Path=/",
            "__Host-clwd_app_session=planted; Path=/; Secure",
            "=__Host-clwd_state=planted",
            "__SECURE-clwd_session=planted; Domain=apps.test",
            "cart=3",
        ] {
            headers.append(http::header::SET_COOKIE, HeaderValue::from_static(value));
        }
        assert_eq!(drop_platform_set_cookies(&mut headers), 3);
        let left: Vec<&str> = headers
            .get_all(http::header::SET_COOKIE)
            .iter()
            .map(|v| v.to_str().expect("ascii"))
            .collect();
        assert_eq!(left, ["theme=dark; Path=/", "cart=3"]);
    }
}
