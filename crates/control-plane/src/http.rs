//! The axum surface: middleware, error rendering, and routing.
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
//!
//! # Authenticated by default
//!
//! A route is public only if it is added to the public router, which holds
//! `/healthz` and nothing else. Every other route goes through [`protected`],
//! which requires a scope as an argument. The failure this shape prevents is the
//! common one: a new route that ships unprotected because nobody opted it in.

use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::extract::DefaultBodyLimit;
use axum::extract::Request;
use axum::http::{HeaderValue, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{MethodRouter, delete, get, post};
use tower_http::catch_panic::CatchPanicLayer;
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::TraceLayer;

use shared::{Envelope, Error, RequestId};

use crate::auth::{self, Limiter};
use crate::token::Scope;

/// How long a request may run before it is abandoned.
///
/// Deliberately shorter than any sensible load-balancer idle timeout, so this
/// layer is what ends a stuck request and the caller gets an envelope naming
/// `control-plane.timeout` rather than a connection reset from somewhere else.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// The header a client may use to supply its own correlation id.
const REQUEST_ID_HEADER: &str = "x-request-id";

/// What the routes need to do their work.
///
/// Cloned per request by axum, so every field is cheap to clone: `PgPool` and
/// `ArtifactStore` are handles, not resources, and the limiter is shared.
#[derive(Clone)]
#[non_exhaustive]
pub struct AppState {
    pub pool: sqlx::PgPool,
    pub artifacts: builder::ArtifactStore,
    pub limiter: std::sync::Arc<Limiter>,
}

impl AppState {
    /// Assemble the state, with the default per-token rate limit.
    ///
    /// A constructor rather than a struct literal because the type is
    /// `#[non_exhaustive]` — it will gain fields, and callers outside this
    /// crate should keep compiling when it does. `#[non_exhaustive]` without a
    /// constructor is just a type nobody outside can build.
    #[must_use]
    pub fn new(pool: sqlx::PgPool, artifacts: builder::ArtifactStore) -> Self {
        Self::with_quota(pool, artifacts, auth::default_quota())
    }

    /// Assemble the state with an explicit per-token rate limit.
    ///
    /// Exists so a test can reach the limit in two requests rather than a
    /// hundred; production uses [`AppState::new`].
    #[must_use]
    pub fn with_quota(
        pool: sqlx::PgPool,
        artifacts: builder::ArtifactStore,
        quota: governor::Quota,
    ) -> Self {
        Self {
            pool,
            artifacts,
            limiter: std::sync::Arc::new(Limiter::keyed(quota)),
        }
    }
}

/// Build the router.
pub fn router(state: AppState) -> Router {
    router_with(state, REQUEST_TIMEOUT)
}

/// Add a route that requires authentication and `scope`.
///
/// **The only way to add a protected route**, and it takes the scope as an
/// argument, so "protected but no scope check" is not something a route can
/// be. The authentication layer itself is added once, over every route this
/// has registered, in [`router_with`].
fn protected(
    router: Router<AppState>,
    path: &str,
    scope: Scope,
    method: MethodRouter<AppState>,
) -> Router<AppState> {
    router.route(
        path,
        method.route_layer(middleware::from_fn(move |request: Request, next: Next| {
            auth::require_scope(scope, request, next)
        })),
    )
}

/// Build the router with an explicit time budget.
///
/// Exists so the timeout path is reachable in a test without waiting out
/// [`REQUEST_TIMEOUT`]. The whole layer stack is still assembled here, so a test
/// that drives this exercises the real wiring — including the layer's status
/// agreeing with what `control-plane.timeout` declares. A test that faked the
/// timeout response instead would hardcode that status and prove nothing.
fn router_with(state: AppState, timeout: Duration) -> Router {
    let authenticated = Router::new();
    let authenticated = protected(
        authenticated,
        "/v1/apps/{app_id}/versions",
        Scope::Publish,
        post(crate::publish::publish),
    );
    let authenticated = protected(
        authenticated,
        "/v1/orgs/{org_id}/tokens",
        Scope::Admin,
        post(auth::issue_route),
    );
    let authenticated = protected(
        authenticated,
        "/v1/tokens/{token_id}",
        Scope::Admin,
        delete(auth::revoke_route),
    );
    // `route_layer`, after every protected route is registered: it covers the
    // routes that exist when it is called, and only matched ones, so an
    // unknown path is still the fallback's 404 rather than a 401.
    let authenticated = authenticated.route_layer(middleware::from_fn_with_state(
        state.clone(),
        auth::authenticate,
    ));

    let public = Router::new().route("/healthz", get(healthz));

    // Test-only, and public, because they exist to prove failure paths that
    // happen before or regardless of authentication. They were compiled into
    // production until authentication arrived; a deliberate-panic route did
    // not belong there, and requiring a scope for it would have been worse.
    #[cfg(test)]
    let public = public
        .route("/v1/apps/{id}", get(placeholder_not_found))
        .route("/v1/panic", get(placeholder_panic))
        .route(
            "/v1/slow",
            get(|| async {
                tokio::time::sleep(Duration::from_secs(30)).await;
                "unreachable"
            }),
        )
        // Proves the body limit on a route with no other behaviour in the way.
        .route(
            "/v1/body",
            post(|body: axum::body::Bytes| async move { body.len().to_string() }),
        );

    public
        .merge(authenticated)
        .with_state(state)
        .fallback(unmatched)
        // Innermost first. `request_id` is outermost so everything below it —
        // including the panic catcher and the timeout — runs with one assigned.
        // The status is set here rather than left to the layer's default, so
        // it already matches what `control-plane.timeout` declares. 504 rather
        // than 408: 408 means the client was too slow sending, and this is our
        // side exceeding its own budget.
        // The upload ceiling, applied to every route that reads a body.
        //
        // The constant comes from `shared`, not from `builder`. Reaching into
        // `builder` for it pulled 39 crates into the control plane — the whole
        // opendal stack, zstd, a TLS implementation — to import one `usize`.
        //
        // Axum's own default is 2 MiB, which is *below* what a bundle may
        // legitimately be. Left alone, a valid upload would be refused by a
        // limit nothing in this repository states, and `MAX_BUNDLE_BYTES` would
        // be unreachable — a documented number that never applies.
        //
        // The rejection also arrives from an extractor rather than a handler,
        // so it carries no envelope of ours. `assign_request_id` gives it one;
        // see the 413 arm there.
        .layer(DefaultBodyLimit::max(shared::MAX_BUNDLE_BYTES))
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
    // First, before any layer can see the headers: a sensitive `HeaderValue`
    // prints as `Sensitive` under `Debug`, so a `{:?}` of the request or its
    // headers anywhere below cannot put a token in a log line. Here rather
    // than in the auth layer because the trace layer runs before that one.
    if let Some(credential) = request.headers_mut().get_mut(header::AUTHORIZATION) {
        credential.set_sensitive(true);
    }

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

    // Same situation, different layer. `DefaultBodyLimit` rejects inside the
    // extractor, before any handler runs, so the response is axum's rather than
    // ours. Without this arm an oversized upload is the one reachable path that
    // returns a non-envelope body, which is exactly what #2 asserts cannot
    // happen.
    if response.status() == StatusCode::PAYLOAD_TOO_LARGE && !was_rendered(&response) {
        return render(
            &Error::PayloadTooLarge {
                what: format!(
                    "request body exceeds the {} byte limit",
                    shared::MAX_BUNDLE_BYTES
                ),
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
///
/// Two errors also need a header, because some callers read headers and not
/// bodies: a 401 carries `WWW-Authenticate: Bearer` (RFC 6750), and a rate
/// limit carries `Retry-After`.
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

    let headers = response.headers_mut();
    headers.insert(
        REQUEST_ID_HEADER,
        HeaderValue::from_str(id.as_str()).unwrap_or_else(|_| HeaderValue::from_static("invalid")),
    );
    if status == StatusCode::UNAUTHORIZED {
        headers.insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
    }
    if let Error::RateLimited { retry_after_secs } = error {
        headers.insert(header::RETRY_AFTER, HeaderValue::from(*retry_after_secs));
    }
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
#[cfg(test)]
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

/// Exists to prove the panic path.
#[cfg(test)]
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

    /// State for the envelope tests, which reach no database.
    ///
    /// The pool is `connect_lazy` against an address nothing listens on, with a
    /// short acquire timeout, so any route that does reach for it fails fast
    /// rather than quietly passing against a live one. The authentication tests
    /// below depend on exactly that.
    fn stateless() -> AppState {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .acquire_timeout(Duration::from_millis(500))
            .connect_lazy("postgres://unused@127.0.0.1:1/unused")
            .expect("a lazy pool connects to nothing");
        let operator = opendal::Operator::new(opendal::services::Memory::default())
            .expect("an in-memory operator needs no configuration");
        AppState::new(pool, builder::ArtifactStore::new(operator))
    }

    async fn call(request: Request<Body>) -> (StatusCode, serde_json::Value, Response<Body>) {
        let response = router(stateless())
            .oneshot(request)
            .await
            .expect("router responds");
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

    fn publish_with(authorization: Option<&str>) -> Request<Body> {
        let mut builder = Request::builder()
            .method("POST")
            .uri(format!("/v1/apps/{}/versions", uuid::Uuid::now_v7()));
        if let Some(value) = authorization {
            builder = builder.header(header::AUTHORIZATION, value);
        }
        builder.body(Body::empty()).expect("a valid request")
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

    /// A protected route with no valid credential is 401 — and is decided
    /// **without touching the database**. The pool here cannot connect, so a
    /// lookup would surface as a 5xx; getting 401 proves the malformed cases
    /// are turned away by the format check, which is what makes a garbage
    /// flood cheap.
    #[tokio::test]
    async fn a_protected_route_without_a_well_formed_token_is_401_before_any_lookup() {
        for authorization in [
            None,
            Some("Basic dXNlcjpwYXNz"),
            Some("Bearer"),
            Some("Bearer not-a-token"),
            Some("Bearer clwd_tok_short"),
        ] {
            let (status, json, response) = call(publish_with(authorization)).await;
            assert_eq!(status, StatusCode::UNAUTHORIZED, "for {authorization:?}");
            assert_eq!(
                json["code"], "identity.unauthenticated",
                "for {authorization:?}"
            );
            assert_eq!(
                response
                    .headers()
                    .get(header::WWW_AUTHENTICATE)
                    .map(|v| v.as_bytes()),
                Some(&b"Bearer"[..]),
                "RFC 6750: a 401 names its scheme, for {authorization:?}"
            );
        }
    }

    /// **Fail closed.** A well-formed token whose lookup cannot be made is a
    /// denial, and specifically not a 401: telling the caller their token is
    /// bad would send them to rotate a credential that is fine.
    #[tokio::test]
    async fn a_database_outage_denies_and_does_not_blame_the_token() {
        let token = format!("Bearer {}{}", crate::token::PREFIX, "0".repeat(64));
        let (status, json, _) = call(publish_with(Some(&token))).await;

        assert!(
            status.is_server_error(),
            "an unreachable database must deny with a 5xx, got {status}: {json}"
        );
        let code = json["code"].as_str().expect("an envelope");
        assert!(
            ["control-plane.timeout", "control-plane.internal"].contains(&code),
            "a lookup failure is ours, not the caller's: {code}"
        );
    }

    /// A timed-out request is an envelope too, not a bodyless status from the
    /// layer. Also pins the layer's status to the one `control-plane.timeout`
    /// declares: if they drift apart the re-render stops firing and the caller
    /// gets an empty body.
    #[tokio::test]
    async fn a_timed_out_request_becomes_an_envelope() {
        let response = router_with(stateless(), Duration::from_millis(10))
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

    /// The one path that returns a response no handler produced.
    ///
    /// `DefaultBodyLimit` rejects inside the extractor, so without the 413 arm
    /// in `assign_request_id` this is a bare body from axum — the single
    /// reachable counter-example to "every failure path returns the envelope".
    /// Asserted through the real router rather than by calling `render`, which
    /// would prove only that `render` renders.
    #[tokio::test]
    async fn an_oversized_body_becomes_an_envelope_not_a_bare_413() {
        let oversized = vec![0u8; shared::MAX_BUNDLE_BYTES + 1];
        let request = Request::builder()
            .method("POST")
            .uri("/v1/body")
            .body(Body::from(oversized))
            .expect("a request with a large body is still a valid request");

        let (status, json, _) = call(request).await;

        assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(json["code"], "control-plane.payload_too_large");
        assert_eq!(
            json["retryable"], false,
            "the same body will not fit on a second attempt"
        );
        assert!(
            json["message"]
                .as_str()
                .is_some_and(|m| m.contains(&shared::MAX_BUNDLE_BYTES.to_string())),
            "the caller should learn the limit from the response, got {:?}",
            json["message"]
        );
        assert!(
            json.get("request_id").is_some(),
            "a rejection from a layer still needs to be correlatable"
        );
    }

    /// The same limit, on a body whose length is not known in advance.
    ///
    /// A chunked upload sends no `Content-Length`, so nothing can be rejected
    /// up front — the limit has to hold while the body streams. Axum enforces
    /// it with `http_body_util::Limited`, which counts as it reads and has no
    /// `Content-Length` fast path, so the streaming case should behave like the
    /// sized one.
    ///
    /// "Should" is why this test exists. The sized test above uses
    /// `Body::from(Vec)`, which knows its own length, and would keep passing if
    /// the limit only ever worked for bodies that declare one — proving the
    /// easy half of the property and reporting green about the other.
    #[tokio::test]
    async fn an_oversized_chunked_body_is_also_an_envelope() {
        // A stream of 1 MiB chunks with no total length. `Body::from_stream`
        // reports `size_hint` as unknown, which is what a chunked request looks
        // like to everything downstream of the transport.
        let chunk = vec![0u8; 1024 * 1024];
        let chunks = (shared::MAX_BUNDLE_BYTES / chunk.len()) + 2;
        let stream = futures::stream::iter(
            std::iter::repeat_n(chunk, chunks)
                .map(Ok::<Vec<u8>, std::convert::Infallible>)
                .collect::<Vec<_>>(),
        );
        let body = Body::from_stream(stream);

        {
            use axum::body::HttpBody as _;
            assert!(
                body.size_hint().exact().is_none(),
                "this test is pointless unless the body length is unknown"
            );
        }

        let request = Request::builder()
            .method("POST")
            .uri("/v1/body")
            .body(body)
            .expect("valid request");

        let (status, json, _) = call(request).await;

        assert_eq!(
            status,
            StatusCode::PAYLOAD_TOO_LARGE,
            "a chunked body must hit the same ceiling as a sized one"
        );
        assert_eq!(json["code"], "control-plane.payload_too_large");
        assert!(
            json.get("request_id").is_some(),
            "still correlatable when the rejection came from mid-stream"
        );
    }

    /// The limit is ours, not axum's 2 MiB default. A body over that default
    /// but under our ceiling must reach the handler.
    #[tokio::test]
    async fn a_body_over_axums_default_but_under_ours_is_accepted() {
        // That our ceiling exceeds this is asserted at compile time, beside the
        // constant in `shared::limits`.
        const AXUM_DEFAULT_LIMIT: usize = 2 * 1024 * 1024;

        let body = vec![0u8; AXUM_DEFAULT_LIMIT + 1];
        let request = Request::builder()
            .method("POST")
            .uri("/v1/body")
            .body(Body::from(body))
            .expect("valid request");

        let response = router_with(stateless(), REQUEST_TIMEOUT)
            .oneshot(request)
            .await;
        let response = response.expect("the router answers");
        assert_eq!(
            response.status(),
            StatusCode::OK,
            "axum's 2 MiB default is still capping the body"
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
        let response = router(stateless())
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

    /// `render` gives a rate limit its `Retry-After`, so a client that reads
    /// only headers still learns how long to wait.
    #[test]
    fn a_rate_limit_renders_retry_after() {
        let response = render(
            &Error::RateLimited {
                retry_after_secs: 12,
            },
            &RequestId::generate(),
        );
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(
            response
                .headers()
                .get(header::RETRY_AFTER)
                .map(|v| v.as_bytes()),
            Some(&b"12"[..])
        );
    }
}
