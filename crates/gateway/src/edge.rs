//! The edge application: turns an inbound request into a response by its host.
//!
//! This is the pingora [`ServeHttp`] app. It parses the `Host` (via [`crate::host`]),
//! resolves it (via [`crate::lookup`]), and answers with the platform error
//! envelope. It does **not** proxy to an app: identity injection (#11) owns the
//! step where app code first runs, so until then a *known* host gets a 503
//! "not ready" rather than reaching anything. That is deliberate — no
//! unauthenticated request ever reaches an app.
//!
//! The routing decision ([`disposition`]) and its rendering ([`spec`]) are
//! separated from the pingora plumbing so both are unit-testable without a
//! socket or a handshake.

use std::sync::Arc;

use async_trait::async_trait;
use http::{HeaderValue, Response, StatusCode, header};
use pingora::apps::http_app::ServeHttp;
use pingora::protocols::http::ServerSession;
use shared::domains::AppsDomain;
use shared::{Envelope, RequestId};

use crate::host::parse_host;
use crate::lookup::{Route, RouteLookup};

/// A body to fall back to if serializing the envelope ever fails (it cannot —
/// every field is a plain string or bool — but a hand-written envelope beats an
/// empty body for a caller's parser).
const FALLBACK_BODY: &[u8] =
    br#"{"code":"gateway.internal","message":"internal error","hint":null,"retryable":false,"request_id":""}"#;

/// What the edge decided to do with a request, before it is rendered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Disposition {
    /// No app is served at this host: a 404.
    Unknown,
    /// A live app exists, but the gateway does not proxy yet (#11): a 503.
    NotReady,
    /// The host could not be resolved and nothing was cached: a 503.
    Unavailable,
}

/// The rendered form of a [`Disposition`]: status plus the envelope fields. The
/// codes are `gateway.*` — a distinct surface from the control plane's API
/// (`control-plane.*` / `identity.*`), because an unknown *host* or an app that
/// is not yet serving are gateway concerns, not API-resource ones.
struct EnvelopeSpec {
    status: StatusCode,
    code: &'static str,
    message: &'static str,
    hint: &'static str,
    retryable: bool,
}

/// Map a resolved route (or its absence) to a disposition. `None` means the
/// request had no usable host or a host that is not `{app}.{org}.<apex>` — both
/// unroutable, and both a 404. Pure, so it is tested directly.
fn disposition(route: Option<Route>) -> Disposition {
    match route {
        None | Some(Route::Unknown) => Disposition::Unknown,
        Some(Route::App { .. }) => Disposition::NotReady,
        Some(Route::Unavailable) => Disposition::Unavailable,
    }
}

/// The response spec for a disposition. Pure, so it is tested directly.
fn spec(disposition: Disposition) -> EnvelopeSpec {
    match disposition {
        Disposition::Unknown => EnvelopeSpec {
            status: StatusCode::NOT_FOUND,
            code: "gateway.unknown_host",
            message: "no application is served at this host",
            hint: "check the {app}.{org} host, and that the app is deployed",
            retryable: false,
        },
        Disposition::NotReady => EnvelopeSpec {
            status: StatusCode::SERVICE_UNAVAILABLE,
            code: "gateway.not_ready",
            message: "this application is not yet serving requests",
            hint: "the platform is bringing this app online; retry shortly",
            retryable: true,
        },
        Disposition::Unavailable => EnvelopeSpec {
            status: StatusCode::SERVICE_UNAVAILABLE,
            code: "gateway.unavailable",
            message: "the platform could not resolve this host right now",
            hint: "a platform dependency is unreachable; retry shortly",
            retryable: true,
        },
    }
}

/// Render an [`EnvelopeSpec`] into a full response carrying the platform error
/// envelope. Never panics: an infallible `Response::new` plus header inserts,
/// with a fallback body if serialization somehow fails.
fn render(spec: &EnvelopeSpec, request_id: &RequestId) -> Response<Vec<u8>> {
    let envelope = Envelope {
        code: spec.code,
        message: spec.message.to_owned(),
        hint: Some(spec.hint),
        retryable: spec.retryable,
        request_id: request_id.as_str(),
    };
    let body = serde_json::to_vec(&envelope).unwrap_or_else(|_| FALLBACK_BODY.to_vec());

    let mut response = Response::new(body);
    *response.status_mut() = spec.status;
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    headers.insert(
        "x-request-id",
        HeaderValue::from_str(request_id.as_str())
            .unwrap_or_else(|_| HeaderValue::from_static("invalid")),
    );
    response
}

/// Read the requested host: the `:authority` for HTTP/2, else the `Host`
/// header. The port, if any, is dropped — routing is by name. Takes pingora's
/// `RequestHeader`, which derefs to `http::request::Parts`.
fn requested_host(head: &pingora::http::RequestHeader) -> Option<String> {
    if let Some(authority) = head.uri.authority() {
        return Some(authority.host().to_owned());
    }
    head.headers
        .get(header::HOST)
        .and_then(|value| value.to_str().ok())
        .map(|value| value.split(':').next().unwrap_or(value).to_owned())
}

/// The pingora edge application.
pub struct Edge {
    lookup: Arc<RouteLookup>,
    apps: AppsDomain,
}

impl Edge {
    /// An edge that resolves hosts under the apps domain via `lookup`.
    #[must_use]
    pub fn new(lookup: Arc<RouteLookup>, apps: AppsDomain) -> Self {
        Self { lookup, apps }
    }

    /// Resolve a host string to a route, or `None` when it is not an app host.
    async fn route(&self, host: &str) -> Option<Route> {
        let app_host = parse_host(host, self.apps.as_str()).ok()?;
        Some(self.lookup.resolve(&app_host).await)
    }
}

#[async_trait]
impl ServeHttp for Edge {
    async fn response(&self, session: &mut ServerSession) -> Response<Vec<u8>> {
        let request_id = RequestId::generate();

        let route = match requested_host(session.req_header()) {
            Some(host) => self.route(&host).await,
            None => None,
        };
        let disposition = disposition(route);
        let spec = spec(disposition);

        // Every answer is observable: a request that reaches an app is #11's
        // concern, so today the interesting signal is which non-serving answer a
        // caller got and why.
        tracing::info!(
            code = spec.code,
            status = spec.status.as_u16(),
            request_id = request_id.as_str(),
            "edge response"
        );
        render(&spec, &request_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disposition_maps_every_route_and_the_no_host_case() {
        assert_eq!(disposition(None), Disposition::Unknown);
        assert_eq!(disposition(Some(Route::Unknown)), Disposition::Unknown);
        assert_eq!(
            disposition(Some(Route::App {
                app_id: "a".to_owned(),
                org_id: "o".to_owned(),
                stale: false,
            })),
            Disposition::NotReady
        );
        assert_eq!(
            disposition(Some(Route::App {
                app_id: "a".to_owned(),
                org_id: "o".to_owned(),
                stale: true,
            })),
            Disposition::NotReady,
            "a stale-served app is still a live app, not-ready to proxy"
        );
        assert_eq!(
            disposition(Some(Route::Unavailable)),
            Disposition::Unavailable
        );
    }

    #[test]
    fn spec_status_and_retryability_match_the_disposition() {
        let unknown = spec(Disposition::Unknown);
        assert_eq!(unknown.status, StatusCode::NOT_FOUND);
        assert_eq!(unknown.code, "gateway.unknown_host");
        assert!(
            !unknown.retryable,
            "a wrong host does not become right on retry"
        );

        for d in [Disposition::NotReady, Disposition::Unavailable] {
            let s = spec(d);
            assert_eq!(s.status, StatusCode::SERVICE_UNAVAILABLE);
            assert!(s.retryable, "a transient not-serving state is retryable");
            assert!(s.code.starts_with("gateway."), "gateway-namespaced code");
        }
    }

    #[test]
    fn render_produces_a_well_formed_envelope() {
        let id = RequestId::generate();
        let response = render(&spec(Disposition::Unknown), &id);
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            response
                .headers()
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("application/json")
        );
        let json: serde_json::Value =
            serde_json::from_slice(response.body()).expect("body is an envelope");
        let mut keys: Vec<&str> = json
            .as_object()
            .expect("object")
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        assert_eq!(keys, ["code", "hint", "message", "request_id", "retryable"]);
        assert_eq!(json["code"], "gateway.unknown_host");
        assert_eq!(json["request_id"], id.as_str());
    }
}
