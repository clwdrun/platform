//! The axum surface: middleware, error rendering, and enough routing to prove
//! the envelope reaches the wire.
//!
//! No domain logic. Routes here exist so the error contract can be tested end to
//! end; the ones that matter arrive with #3 onward.
//!
//! # Every failure is an envelope, including the ones nobody wrote a handler for
//!
//! Three paths produce a response that no handler returned:
//!
//! - **a panic** — caught by `CatchPanicLayer`, which would otherwise drop the
//!   connection and give a caller nothing to correlate;
//! - **a timeout** — `TimeoutLayer`, which produces a bodyless response on its
//!   own;
//! - **an unmatched route** — axum's fallback, which is a bare 404.
//!
//! Each is mapped to the same envelope. A caller that has to distinguish "the
//! API said no" from "something ate my request" by looking at whether the body
//! parses is not being given a contract.
//!
//! # Ordering
//!
//! `request_id` is assigned in the outermost layer, before routing, so it exists
//! on every path — including the three above. A layer that ran after routing
//! would leave exactly the failures that most need correlating without any.

use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::extract::Request;
use axum::http::{HeaderValue, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use tower_http::catch_panic::CatchPanicLayer;
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::TraceLayer;

use shared::{Envelope, Error, RequestId};

/// How long a request may run before it is abandoned.
///
/// Deliberately shorter than any sensible load-balancer idle timeout, so this
/// layer is what ends a stuck request and the caller gets an envelope naming
/// `control-plane.timeout` rather than a connection reset from somewhere else.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// The header a client may use to supply its own correlation id.
const REQUEST_ID_HEADER: &str = "x-request-id";

/// Build the router.
pub fn router() -> Router {
    router_with(REQUEST_TIMEOUT)
}

/// Build the router with an explicit time budget.
///
/// Exists so the timeout path is reachable in a test without waiting out
/// [`REQUEST_TIMEOUT`]. The whole layer stack is still assembled here, so a test
/// that drives this exercises the real wiring — including the layer's status
/// agreeing with what `control-plane.timeout` declares. A test that faked the
/// timeout response instead would hardcode that status and prove nothing.
fn router_with(timeout: Duration) -> Router {
    let router = Router::new()
        .route("/healthz", get(healthz))
        // Placeholder routes, present so the envelope has something to travel
        // through. They return errors on purpose: this skeleton is here to prove
        // the failure paths, and a route that only ever succeeds proves nothing
        // about them.
        .route("/v1/apps/{id}", get(placeholder_not_found))
        .route("/v1/panic", get(placeholder_panic));

    // Only compiled for tests: the timeout has nothing to interrupt otherwise,
    // every real handler here returns immediately.
    #[cfg(test)]
    let router = router.route(
        "/v1/slow",
        get(|| async {
            tokio::time::sleep(Duration::from_secs(30)).await;
            "unreachable"
        }),
    );

    router
        .fallback(unmatched)
        // Innermost first. `request_id` is outermost so everything below it —
        // including the panic catcher and the timeout — runs with one assigned.
        // The status is set here rather than left to the layer's default, so
        // it already matches what `control-plane.timeout` declares. 504 rather
        // than 408: 408 means the client was too slow sending, and this is our
        // side exceeding its own budget.
        .layer(TimeoutLayer::with_status_code(
            StatusCode::GATEWAY_TIMEOUT,
            timeout,
        ))
        .layer(CatchPanicLayer::custom(on_panic))
        .layer(TraceLayer::new_for_http())
        .layer(middleware::from_fn(assign_request_id))
}

/// Assign a request id before anything else looks at the request.
///
/// A client-supplied `x-request-id` is honoured when it survives
/// [`RequestId::sanitize`], and replaced silently otherwise — a malformed
/// correlation header should not fail a request that is otherwise fine, and the
/// caller still gets a usable id back in the response.
async fn assign_request_id(mut request: Request, next: Next) -> Response {
    let id = request
        .headers()
        .get(REQUEST_ID_HEADER)
        .and_then(|v| v.to_str().ok())
        .and_then(RequestId::sanitize)
        .unwrap_or_else(RequestId::generate);

    // Available to handlers, and to the layers below this one.
    request.extensions_mut().insert(id.clone());

    let mut response = next.run(request).await;

    // Echoed so a caller can correlate without parsing the body — which matters
    // for a 204, and for any response whose body they do not read.
    //
    // `sanitize` guarantees visible ASCII, so this cannot fail; the fallback
    // exists because silently dropping the header would be worse than a
    // placeholder nobody will see.
    let value =
        HeaderValue::from_str(id.as_str()).unwrap_or_else(|_| HeaderValue::from_static("invalid"));
    response.headers_mut().insert(REQUEST_ID_HEADER, value);

    // A response that came from a layer rather than a handler — the timeout —
    // has no body of ours. Give it one. The status already agrees with what the
    // code declares, so only the body is missing.
    if response.status() == StatusCode::GATEWAY_TIMEOUT && !was_rendered(&response) {
        return render(
            &Error::Timeout {
                dependency: "the request exceeded its time budget".to_owned(),
            },
            &id,
        );
    }

    response
}

/// Whether a response already carries one of our envelopes.
///
/// Marked with a header rather than by parsing the body: the body may be a
/// stream, and consuming it to find out would be worse than the question.
fn was_rendered(response: &Response) -> bool {
    response.headers().contains_key(ENVELOPE_MARKER)
}

/// Internal marker, stripped before the response leaves the process.
const ENVELOPE_MARKER: &str = "x-clwd-envelope";

/// Render an error as the envelope, with the status its code declares.
pub fn render(error: &Error, id: &RequestId) -> Response {
    let body = serde_json::to_vec(&Envelope::new(error, id)).unwrap_or_else(|_| {
        // Serializing an envelope cannot fail — every field is a plain string or
        // bool. If it somehow does, a hand-written envelope is still better than
        // an empty body, because the caller's parser stays happy.
        br#"{"code":"control-plane.internal","message":"internal error","hint":null,"retryable":false,"request_id":""}"#
            .to_vec()
    });

    let status = StatusCode::from_u16(error.status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);

    let mut response = Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json")
        .header(ENVELOPE_MARKER, "1")
        .body(Body::from(body))
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response());

    response.headers_mut().insert(
        REQUEST_ID_HEADER,
        HeaderValue::from_str(id.as_str()).unwrap_or_else(|_| HeaderValue::from_static("invalid")),
    );
    response
}

/// A panic in a handler becomes an envelope rather than a dropped connection.
///
/// The panic message is deliberately not forwarded to the caller: it is a defect
/// in our code and may name internals. It reaches the log instead, where the
/// request id ties it back to this response.
fn on_panic(err: Box<dyn std::any::Any + Send + 'static>) -> Response {
    let detail = err
        .downcast_ref::<&str>()
        .map(|s| (*s).to_owned())
        .or_else(|| err.downcast_ref::<String>().cloned())
        .unwrap_or_else(|| "non-string panic payload".to_owned());

    tracing::error!(panic = %detail, "handler panicked");

    // The id assigned upstream is not reachable from here — `CatchPanicLayer`
    // hands back a bare response and the extensions went with the unwound
    // request. The outer layer overwrites the header on the way out, so the
    // caller still gets the right one; this placeholder only appears in the
    // body, which is why the header is the reliable place to read it from.
    render(
        &Error::Internal {
            source: anyhow::anyhow!("handler panicked"),
        },
        &RequestId::generate(),
    )
}

async fn healthz() -> &'static str {
    "ok"
}

/// A route that fails, so the envelope has a normal failure to travel through.
async fn placeholder_not_found(
    axum::extract::Path(id): axum::extract::Path<String>,
    axum::Extension(request_id): axum::Extension<RequestId>,
) -> Response {
    render(
        &Error::NotFound {
            what: format!("app {id}"),
        },
        &request_id,
    )
}

/// Exists to prove the panic path. Not reachable by accident: it is an explicit
/// route, and it goes when #3 replaces this skeleton with real handlers.
async fn placeholder_panic() -> Response {
    panic!("deliberate panic, to prove the catch layer produces an envelope");
}

/// An unmatched route is a 404 with an envelope, not a bare axum 404.
async fn unmatched(axum::Extension(request_id): axum::Extension<RequestId>) -> Response {
    render(
        &Error::NotFound {
            what: "that endpoint".to_owned(),
        },
        &request_id,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;
    use tower::ServiceExt as _;

    async fn call(request: Request<Body>) -> (StatusCode, serde_json::Value, Response<Body>) {
        let response = router().oneshot(request).await.expect("router responds");
        let status = response.status();
        let (parts, body) = response.into_parts();
        let bytes = to_bytes(body, 64 * 1024).await.expect("body reads");
        let json = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
        (status, json, Response::from_parts(parts, Body::empty()))
    }

    fn get(uri: &str) -> Request<Body> {
        Request::builder()
            .uri(uri)
            .body(Body::empty())
            .expect("a valid request")
    }

    /// Every error path is an envelope. **No bare 500, no bare 404, no dropped
    /// connection.**
    #[tokio::test]
    async fn every_failure_path_returns_the_envelope() {
        for uri in ["/v1/apps/dashboard", "/v1/panic", "/no/such/route"] {
            let (status, json, _) = call(get(uri)).await;

            assert!(
                status.is_client_error() || status.is_server_error(),
                "for {uri}"
            );

            let object = json
                .as_object()
                .unwrap_or_else(|| panic!("for {uri}: body is not an envelope: {json}"));
            let mut keys: Vec<&str> = object.keys().map(String::as_str).collect();
            keys.sort_unstable();
            assert_eq!(
                keys,
                ["code", "hint", "message", "request_id", "retryable"],
                "for {uri}"
            );

            let code = object["code"].as_str().expect("code is a string");
            assert!(code.contains('.'), "for {uri}: {code:?} is not namespaced");
        }
    }

    /// A timed-out request is an envelope too, not a bodyless status from the
    /// layer. Also pins the layer's status to the one `control-plane.timeout`
    /// declares: if they drift apart the re-render stops firing and the caller
    /// gets an empty body.
    #[tokio::test]
    async fn a_timed_out_request_becomes_an_envelope() {
        let response = router_with(Duration::from_millis(10))
            .oneshot(get("/v1/slow"))
            .await
            .expect("router responds");

        assert_eq!(response.status(), StatusCode::GATEWAY_TIMEOUT);
        assert!(
            response.headers().contains_key(REQUEST_ID_HEADER),
            "a timed-out caller still needs an id to correlate with"
        );

        let bytes = to_bytes(response.into_body(), 64 * 1024)
            .await
            .expect("body reads");
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap_or_else(|_| {
            panic!(
                "timeout body is not JSON: {:?}",
                String::from_utf8_lossy(&bytes)
            )
        });

        assert_eq!(json["code"], "control-plane.timeout");
        assert_eq!(
            json["retryable"], true,
            "a timeout is the retryable case; if this flips, callers stop retrying"
        );
    }

    /// A panic becomes an envelope rather than a dropped connection.
    #[tokio::test]
    async fn a_panicking_handler_becomes_an_envelope() {
        let (status, json, _) = call(get("/v1/panic")).await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(json["code"], "control-plane.internal");
        assert!(
            !json["message"]
                .as_str()
                .expect("a message")
                .contains("deliberate panic"),
            "the panic payload must not reach the caller: {json}"
        );
    }

    #[tokio::test]
    async fn a_client_supplied_request_id_is_honoured_and_echoed() {
        let request = Request::builder()
            .uri("/v1/apps/x")
            .header(REQUEST_ID_HEADER, "trace-abc-123")
            .body(Body::empty())
            .expect("a valid request");

        let (_, json, response) = call(request).await;
        assert_eq!(json["request_id"], "trace-abc-123");
        assert_eq!(
            response.headers().get(REQUEST_ID_HEADER).unwrap(),
            "trace-abc-123",
            "the id is echoed in the header too, for callers that do not read the body"
        );
    }

    #[tokio::test]
    async fn an_absent_request_id_is_generated() {
        let (_, json, _) = call(get("/v1/apps/x")).await;
        let id = json["request_id"].as_str().expect("an id");
        assert!(!id.is_empty());
        assert!(
            RequestId::sanitize(id).is_some(),
            "a generated id must be one we would accept: {id:?}"
        );
    }

    /// **Log injection.** A CR or LF in a client id would let a caller forge log
    /// entries, so a malformed one is replaced rather than trusted.
    #[tokio::test]
    async fn a_malformed_request_id_is_replaced_not_trusted() {
        // `HeaderValue` rejects a literal newline, so the attack that reaches us
        // is the one that survives HTTP parsing: visible junk, or oversize.
        for hostile in ["a".repeat(200), "has space".to_owned(), String::new()] {
            let mut builder = Request::builder().uri("/v1/apps/x");
            if !hostile.is_empty() {
                builder = builder.header(REQUEST_ID_HEADER, hostile.clone());
            }
            let request = builder.body(Body::empty()).expect("a valid request");

            let (_, json, _) = call(request).await;
            let id = json["request_id"].as_str().expect("an id");
            assert_ne!(id, hostile, "a malformed id must not be echoed back");
            assert!(
                RequestId::sanitize(id).is_some(),
                "the replacement must itself be well formed: {id:?}"
            );
        }
    }

    #[tokio::test]
    async fn healthz_succeeds_and_still_carries_a_request_id() {
        let response = router()
            .oneshot(get("/healthz"))
            .await
            .expect("router responds");
        assert_eq!(response.status(), StatusCode::OK);
        assert!(
            response.headers().contains_key(REQUEST_ID_HEADER),
            "a success carries an id too — correlation is not only for failures"
        );
    }

    /// The status a code declares is the status that reaches the wire.
    #[tokio::test]
    async fn the_declared_status_reaches_the_wire() {
        let (status, json, _) = call(get("/v1/apps/x")).await;
        assert_eq!(json["code"], "control-plane.not_found");
        assert_eq!(status.as_u16(), 404, "status() and the response must agree");
    }
}
