//! The hop from the gateway to the control plane's **public** listener (#95).
//!
//! The gateway is the only process with a public listener. Requests for the
//! control-plane domain (`CLWD_CONTROL_PLANE_DOMAIN`) — sign-in, the OIDC
//! callback, tokens, publish, the OpenAPI document — are forwarded here, to
//! the address in `CLWD_CONTROL_PLANE_PUBLIC`. Never to the internal or ops
//! listener: those are other addresses and other routers, and nothing in a
//! request chooses where it goes.
//!
//! # What the control plane sees
//!
//! The request as the client sent it, less its hop-by-hop headers, with the
//! gateway's own request id in `x-request-id` so the two logs share one id.
//! Cookies pass **unchanged**: on this host the platform's cookies
//! (`__Host-clwd_session`, the sign-in state) are the control plane's own, and
//! removing them is what the app hop does, not this one. Nothing is added:
//! no `X-Forwarded-*`, no client address. The control plane trusts no
//! forwarded header (#48), and supplying one would invite it to.
//!
//! # Buffered, on purpose
//!
//! The body is read whole (counted against the [`crate::budget`]) and the
//! answer is read whole, so this is plain request/response. Nothing on the
//! control plane streams: following logs is a long-poll of at most 20 s,
//! inside its 30 s request timeout.

use std::time::Duration;

use bytes::Bytes;
use http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use shared::RequestId;

use crate::upstream::strip_hop_by_hop;

/// How long the gateway waits for the control plane: just over its own 30 s
/// request timeout, so the control plane's timeout answers first and the
/// caller gets its envelope rather than the gateway's.
pub const TIMEOUT: Duration = Duration::from_secs(35);

/// The largest answer read back. The control plane's largest answers (a page
/// of logs, the OpenAPI document) are far smaller.
pub const MAX_RESPONSE: usize = 16 * 1024 * 1024;

/// Why the control plane gave no answer to pass on.
#[derive(Debug, thiserror::Error)]
pub enum HopError {
    /// No connection, no answer in time, or a broken one.
    #[error("the control plane could not be reached: {0}")]
    Unreachable(String),
    /// It answered with more than [`MAX_RESPONSE`].
    #[error("the control plane's answer exceeded {MAX_RESPONSE} bytes")]
    TooLarge,
}

/// The control plane's answer, hop-by-hop headers removed.
#[derive(Debug)]
pub struct Answer {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: Vec<u8>,
}

/// Forwards to the control plane's public listener.
pub struct ControlPlaneHop {
    client: reqwest::Client,
    base: reqwest::Url,
}

impl ControlPlaneHop {
    /// A hop to `base`, the public listener's URL (`CLWD_CONTROL_PLANE_PUBLIC`).
    ///
    /// # Errors
    ///
    /// When `base` is not an `http` or `https` URL, or the client cannot be
    /// built.
    pub fn new(base: &str) -> anyhow::Result<Self> {
        let base = reqwest::Url::parse(base)
            .map_err(|e| anyhow::anyhow!("CLWD_CONTROL_PLANE_PUBLIC is not a URL: {e}"))?;
        anyhow::ensure!(
            matches!(base.scheme(), "http" | "https") && base.host().is_some(),
            "CLWD_CONTROL_PLANE_PUBLIC must be an http(s) URL with a host, not {base}"
        );
        let client = reqwest::Client::builder()
            // A redirect is the control plane's answer to the caller, not an
            // instruction to the gateway.
            .redirect(reqwest::redirect::Policy::none())
            // `HTTP_PROXY` in the gateway's environment must not reroute this.
            .no_proxy()
            .timeout(TIMEOUT)
            .build()?;
        Ok(Self { client, base })
    }

    /// Forward one request and read its answer.
    ///
    /// # Errors
    ///
    /// [`HopError`] when there is no answer to pass on.
    pub async fn forward(
        &self,
        method: Method,
        path_and_query: &str,
        headers: &HeaderMap,
        body: Bytes,
        request_id: &RequestId,
    ) -> Result<Answer, HopError> {
        let mut url = self.base.clone();
        let (path, query) = path_and_query
            .split_once('?')
            .map_or((path_and_query, None), |(p, q)| (p, Some(q)));
        url.set_path(path);
        url.set_query(query);

        let mut response = self
            .client
            .request(method, url)
            .headers(request_headers(headers, request_id))
            .body(body)
            .send()
            .await
            .map_err(|e| HopError::Unreachable(e.to_string()))?;

        let status = response.status();
        let mut headers = std::mem::take(response.headers_mut());
        strip_hop_by_hop(&mut headers);
        let mut body = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|e| HopError::Unreachable(e.to_string()))?
        {
            if body.len() + chunk.len() > MAX_RESPONSE {
                return Err(HopError::TooLarge);
            }
            body.extend_from_slice(&chunk);
        }
        Ok(Answer {
            status,
            headers,
            body,
        })
    }
}

/// The headers sent on: the client's, less hop-by-hop ones and the two the
/// client library sets from the URL and body (`Host`, `Content-Length`), with
/// the gateway's request id in place of any the client sent.
///
/// Cookies, `Origin`, `Authorization` and the rest pass as they came. Nothing
/// is added.
#[must_use]
pub fn request_headers(client: &HeaderMap, request_id: &RequestId) -> HeaderMap {
    let mut headers = client.clone();
    strip_hop_by_hop(&mut headers);
    headers.remove(header::HOST);
    headers.remove(header::CONTENT_LENGTH);
    if let Ok(id) = HeaderValue::from_str(request_id.as_str()) {
        headers.insert("x-request-id", id);
    }
    headers
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(pairs: &[(&'static str, &'static str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in pairs {
            map.append(*name, HeaderValue::from_static(value));
        }
        map
    }

    #[test]
    fn platform_cookies_and_credentials_pass_unchanged() {
        let sent = headers(&[
            (
                "cookie",
                "__Host-clwd_session=s; __Host-clwd_state=t; theme=dark",
            ),
            ("authorization", "Bearer clwd_tok"),
            ("origin", "https://api.clwd.test"),
        ]);
        let on = request_headers(&sent, &RequestId::generate());
        for name in ["cookie", "authorization", "origin"] {
            assert_eq!(on.get(name), sent.get(name), "{name}");
        }
    }

    #[test]
    fn hop_by_hop_headers_and_the_ones_it_names_are_dropped() {
        let sent = headers(&[
            ("connection", "keep-alive, x-private"),
            ("x-private", "1"),
            ("keep-alive", "timeout=5"),
            ("transfer-encoding", "chunked"),
            ("upgrade", "websocket"),
            ("host", "api.clwd.test"),
            ("content-length", "3"),
            ("accept", "application/json"),
        ]);
        let on = request_headers(&sent, &RequestId::generate());
        for gone in [
            "connection",
            "x-private",
            "keep-alive",
            "transfer-encoding",
            "upgrade",
            "host",
            "content-length",
        ] {
            assert!(!on.contains_key(gone), "{gone} was forwarded");
        }
        assert_eq!(on.get("accept"), sent.get("accept"));
    }

    #[test]
    fn the_gateways_request_id_replaces_the_clients_and_nothing_is_added() {
        let id = RequestId::generate();
        let sent = headers(&[("x-request-id", "client-chose-this")]);
        let on = request_headers(&sent, &id);
        assert_eq!(
            on.get("x-request-id").and_then(|v| v.to_str().ok()),
            Some(id.as_str())
        );
        assert_eq!(on.len(), 1, "no header was added: {on:?}");
        assert!(
            !on.keys()
                .any(|k| k.as_str().starts_with("x-forwarded") || k == "forwarded"),
            "the gateway supplies no forwarded header"
        );
    }

    #[test]
    fn the_base_must_be_an_http_url_with_a_host() {
        assert!(ControlPlaneHop::new("http://127.0.0.1:8080").is_ok());
        for bad in ["127.0.0.1:8080", "ftp://cp", "file:///x", "not a url"] {
            assert!(ControlPlaneHop::new(bad).is_err(), "{bad}");
        }
    }
}
