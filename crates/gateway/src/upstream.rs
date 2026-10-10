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
    pub method: Method,
    /// The path and query the visitor asked for, as received.
    pub path_and_query: String,
    pub headers: HeaderMap,
    pub body: Bytes,
}

impl UpstreamRequest {
    pub(crate) fn new(
        method: Method,
        path_and_query: String,
        headers: HeaderMap,
        body: Bytes,
    ) -> Self {
        Self {
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
