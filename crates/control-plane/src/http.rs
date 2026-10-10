//! The axum surface: the route table, middleware, and error rendering.
//!
//! # Every 4xx and 5xx is an envelope
//!
//! Not "every error a handler returns". Plenty of error responses are produced
//! by something that is not a handler: axum's 405 for a wrong method, the `Path`
//! extractor's plain-text 400, the body limit's 413, the timeout's 504, a panic.
//! Those were found and fixed one at a time, and special-casing never converged
//! — a probe later found 192 more.
//!
//! So the mechanism is general. [`render`] marks the responses it produces with
//! a response extension, and `envelope_every_error` converts **any** 4xx or 5xx
//! that lacks the mark. There is no list of statuses to keep up to date and no
//! list of exempt routes: exception lists are how "every" stopped being true.
//!
//! The mark is an extension rather than a header because extensions are never
//! serialised. An earlier header marker claimed to be "stripped before the
//! response leaves the process"; nothing stripped it, and it reached every
//! caller.
//!
//! # Every route is in the table
//!
//! [`routes`] is the only way into the router. `clippy.toml` disallows every
//! `Router` method that can register a route, and the one call site allowed to
//! is `register`. That is what makes the envelope probe's claim — that it
//! walked every route — true by construction rather than true on the day it was
//! written. See `envelope_probe` for the probe.
//!
//! # Ordering
//!
//! ```text
//! assign_request_id        outermost: the id exists on every path
//! envelope_every_error     inside it, so a synthesised envelope has an id;
//!                          outside everything that can produce a bare response
//! TraceLayer
//! CatchPanicLayer
//! TimeoutLayer
//! DefaultBodyLimit
//! router                   fallback, 405s, extractors, auth, handlers
//! ```
//!
//! One subtlety: `Router::layer` wraps each route's endpoint, and axum's method
//! router appends `Allow` to a 405 *after* that wrapped call returns. So the
//! conversion sees a 405 with no headers, and `Allow` is added around it. The
//! header reaches the wire regardless, which the envelope probe checks.

use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::extract::DefaultBodyLimit;
use axum::extract::{Request, State};
use axum::handler::Handler;
use axum::http::response::Parts;
use axum::http::{HeaderValue, Method, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{MethodFilter, MethodRouter, on};
use tower_http::catch_panic::CatchPanicLayer;
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::TraceLayer;

use shared::{Envelope, Error, RequestId};

use crate::auth::{self, Limiter};
use crate::openapi::{self, Doc, Success};
use crate::token::Scope;

/// How long a request may run before it is abandoned.
///
/// Deliberately shorter than any sensible load-balancer idle timeout, so this
/// layer is what ends a stuck request and the caller gets an envelope naming
/// `control-plane.timeout` rather than a connection reset from somewhere else.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// The header a client may use to supply its own correlation id.
const REQUEST_ID_HEADER: &str = "x-request-id";

/// The most of a bare 4xx's plain-text body that is echoed as the message.
///
/// Enough for axum's rejection text ("Cannot parse `app_id` with value …"),
/// small enough that echoing it costs nothing worth measuring.
const ECHO_LIMIT: usize = 1024;

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
    /// The shared secret a platform service presents to reach
    /// [`Access::Internal`] routes. `None` means no internal route can be
    /// called — fail closed. Set via [`AppState::with_internal_secret`]; #22
    /// (the secret broker) will own where it comes from and how it rotates.
    pub internal_secret: Option<std::sync::Arc<str>>,
    /// Google sign-in. `None` means the sign-in routes answer
    /// `control-plane.internal` — fail closed. Set via
    /// [`AppState::with_signin`].
    pub signin: Option<std::sync::Arc<crate::signin::SignIn>>,
    /// The DNS lookup domain verification uses. `None` means verifying a claim
    /// answers `control-plane.internal` — fail closed. Set via
    /// [`AppState::with_txt_lookup`].
    pub txt_lookup: Option<crate::orgs::SharedTxtLookup>,
    /// The domain apps are served under, for building an app host from its
    /// row in the sign-in handshake. `None` means `/authorize` answers
    /// `control-plane.internal` — fail closed. Set via
    /// [`AppState::with_apps_domain`].
    pub apps_domain: Option<shared::domains::AppsDomain>,
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
            internal_secret: None,
            signin: None,
            txt_lookup: None,
            apps_domain: None,
        }
    }

    /// Set the platform-internal service credential that [`Access::Internal`]
    /// routes require. Without it those routes deny every request.
    #[must_use]
    pub fn with_internal_secret(mut self, secret: impl Into<std::sync::Arc<str>>) -> Self {
        self.internal_secret = Some(secret.into());
        self
    }

    /// Enable the Google sign-in routes.
    #[must_use]
    pub fn with_signin(mut self, signin: crate::signin::SignIn) -> Self {
        self.signin = Some(std::sync::Arc::new(signin));
        self
    }

    /// Set the domain apps are served under.
    #[must_use]
    pub fn with_apps_domain(mut self, apps: shared::domains::AppsDomain) -> Self {
        self.apps_domain = Some(apps);
        self
    }

    /// Enable domain-claim verification through `lookup`.
    #[must_use]
    pub fn with_txt_lookup(mut self, lookup: crate::orgs::SharedTxtLookup) -> Self {
        self.txt_lookup = Some(lookup);
        self
    }
}

/// Who may call a route.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    /// Anyone. Only `/healthz` today.
    Public,
    /// An authenticated caller whose token carries this scope.
    Scoped(Scope),
    /// A platform-internal service, authenticated by the shared internal
    /// credential rather than a customer token (see [`auth::require_internal`]),
    /// so no customer token at any scope can reach it. Served from the table
    /// like any route — walked by the envelope probe, required to carry a
    /// [`Doc`] — but absent from the public OpenAPI document, because it is not
    /// part of the customer API surface. The gateway's host-resolution call is
    /// the only one today.
    Internal,
    /// A browser holding a live session cookie. The handler receives the
    /// session as an `Extension<ActiveSession>`; no session is
    /// `identity.unauthenticated`.
    Session,
    /// A browser route that reads the session cookie but does not require
    /// one — logout, which succeeds whatever it is sent.
    SessionOptional,
}

impl Access {
    /// Whether the route authenticates by the session cookie — which a browser
    /// attaches on its own, so a request carrying it may not be one the user
    /// meant to make.
    #[must_use]
    pub fn uses_session_cookie(self) -> bool {
        matches!(self, Self::Session | Self::SessionOptional)
    }
}

/// A method a route can be registered for.
///
/// Its own type rather than `http::Method`, because `Method` admits extension
/// methods the router cannot filter on, and a fallible conversion at route
/// registration is a failure path that should not exist.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Verb {
    Get,
    Post,
    Put,
    Patch,
    Delete,
}

impl Verb {
    /// The HTTP method.
    #[must_use]
    pub fn method(self) -> Method {
        match self {
            Self::Get => Method::GET,
            Self::Post => Method::POST,
            Self::Put => Method::PUT,
            Self::Patch => Method::PATCH,
            Self::Delete => Method::DELETE,
        }
    }

    /// Whether the method changes state. `GET` never may: `SameSite=Lax` still
    /// sends the session cookie on a cross-site top-level `GET` navigation.
    #[must_use]
    pub fn mutates(self) -> bool {
        !matches!(self, Self::Get)
    }

    fn filter(self) -> MethodFilter {
        match self {
            Self::Get => MethodFilter::GET,
            Self::Post => MethodFilter::POST,
            Self::Put => MethodFilter::PUT,
            Self::Patch => MethodFilter::PATCH,
            Self::Delete => MethodFilter::DELETE,
        }
    }
}

/// One route: what it answers, who may call it, and the handler.
///
/// The verb is stated once and the handler is registered *for* that verb, so
/// the table cannot say `POST` while the router answers `GET`.
pub struct Route {
    pub verb: Verb,
    pub path: &'static str,
    pub access: Access,
    doc: Option<Doc>,
    handler: MethodRouter<AppState>,
}

impl Route {
    /// A production route, which cannot be written without its documentation.
    fn new<H, T>(verb: Verb, path: &'static str, access: Access, doc: Doc, handler: H) -> Self
    where
        H: Handler<T, AppState>,
        T: 'static,
    {
        Self {
            verb,
            path,
            access,
            doc: Some(doc),
            handler: on(verb.filter(), handler),
        }
    }

    /// A test-only route. It is never documented, and exists only under
    /// `#[cfg(test)]`, so production cannot use it to skip documentation.
    #[cfg(test)]
    fn undocumented<H, T>(verb: Verb, path: &'static str, access: Access, handler: H) -> Self
    where
        H: Handler<T, AppState>,
        T: 'static,
    {
        Self {
            verb,
            path,
            access,
            doc: None,
            handler: on(verb.filter(), handler),
        }
    }

    /// How this route is documented, or `None` for a test-only route.
    pub(crate) fn doc(&self) -> Option<&Doc> {
        self.doc.as_ref()
    }
}

/// Every production route, each with its documentation.
///
/// **The only place a production route can be added.** `clippy.toml` disallows
/// registering a route anywhere but `register`, which reads [`routes`], and
/// [`Route::new`] requires a [`Doc`] — so a route cannot reach the router
/// without also reaching the OpenAPI document, which is built from this list.
#[must_use]
pub fn production_routes() -> Vec<Route> {
    vec![
        Route::new(
            Verb::Get,
            "/healthz",
            Access::Public,
            healthz_doc(),
            healthz,
        ),
        Route::new(
            Verb::Get,
            "/openapi.json",
            Access::Public,
            openapi::doc(),
            openapi::serve,
        ),
        Route::new(
            Verb::Get,
            "/auth/google",
            Access::Public,
            crate::signin::start_doc(),
            crate::signin::start,
        ),
        Route::new(
            Verb::Get,
            "/auth/google/callback",
            Access::Public,
            crate::signin::callback_doc(),
            crate::signin::callback,
        ),
        Route::new(
            Verb::Post,
            "/auth/logout",
            Access::SessionOptional,
            crate::signin::logout_doc(),
            crate::signin::logout,
        ),
        Route::new(
            Verb::Get,
            "/authorize",
            Access::SessionOptional,
            crate::handshake::authorize_doc(),
            crate::handshake::authorize_route,
        ),
        Route::new(
            Verb::Post,
            "/internal/handshakes",
            Access::Internal,
            crate::handshake::begin_doc(),
            crate::handshake::begin_route,
        ),
        Route::new(
            Verb::Post,
            "/internal/handshakes/exchange",
            Access::Internal,
            crate::handshake::exchange_doc(),
            crate::handshake::exchange_route,
        ),
        Route::new(
            Verb::Post,
            "/internal/app-sessions/check",
            Access::Internal,
            crate::handshake::check_doc(),
            crate::handshake::check_route,
        ),
        Route::new(
            Verb::Post,
            "/v1/domain-claims",
            Access::Session,
            crate::orgs::claim_doc(),
            crate::orgs::claim_route,
        ),
        Route::new(
            Verb::Post,
            "/v1/domain-claims/{claim_id}/verify",
            Access::Session,
            crate::orgs::verify_doc(),
            crate::orgs::verify_route,
        ),
        Route::new(
            Verb::Patch,
            "/v1/orgs/{org_id}/domains",
            Access::Session,
            crate::orgs::auto_join_doc(),
            crate::orgs::auto_join_route,
        ),
        Route::new(
            Verb::Post,
            "/v1/apps/{app_id}/versions",
            Access::Scoped(Scope::Publish),
            crate::publish::doc(),
            crate::publish::publish,
        ),
        Route::new(
            Verb::Post,
            "/v1/orgs/{org_id}/tokens",
            Access::Scoped(Scope::Admin),
            auth::issue_doc(),
            auth::issue_route,
        ),
        Route::new(
            Verb::Delete,
            "/v1/tokens/{token_id}",
            Access::Scoped(Scope::Admin),
            auth::revoke_doc(),
            auth::revoke_route,
        ),
        Route::new(
            Verb::Get,
            "/internal/orgs/{org}/apps/{app}",
            Access::Internal,
            crate::resolve::doc(),
            crate::resolve::resolve,
        ),
    ]
}

/// Every route the router serves: the production routes, plus test-only
/// routes in a test build.
///
/// The envelope probe walks this, so test routes obey the same registration
/// rule as everything else. The OpenAPI document reads [`production_routes`]
/// instead, so it never describes a route that exists only to prove a failure.
#[must_use]
pub fn routes() -> Vec<Route> {
    let table = production_routes();

    #[cfg(test)]
    let table = {
        let mut table = table;
        table.extend(test_routes());
        table
    };

    table
}

/// Routes that exist to prove failure paths. Compiled only for tests.
#[cfg(test)]
fn test_routes() -> Vec<Route> {
    vec![
        Route::undocumented(
            Verb::Get,
            "/v1/apps/{id}",
            Access::Public,
            placeholder_not_found,
        ),
        Route::undocumented(Verb::Get, "/v1/panic", Access::Public, placeholder_panic),
        Route::undocumented(Verb::Get, "/v1/slow", Access::Public, || async {
            tokio::time::sleep(Duration::from_secs(30)).await;
            "unreachable"
        }),
        Route::undocumented(
            Verb::Post,
            "/v1/body",
            Access::Public,
            |body: axum::body::Bytes| async move { body.len().to_string() },
        ),
        // The envelope probe's planted counter-example: a handler, not a layer,
        // returning a bare error. Without conversion the probe must find it.
        Route::undocumented(Verb::Get, "/v1/bare", Access::Public, || async {
            (StatusCode::BAD_REQUEST, "a planted bare response")
        }),
    ]
}

/// Which listener a router is for.
///
/// Internal routes — the gateway's host resolution, the sign-in handshake's
/// code exchange and session check — are served only on the internal
/// listener, which is never exposed to the internet. Each also checks the
/// internal credential, so reaching one takes both the network position and
/// the secret; neither alone is enough.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Listener {
    /// Everything but internal routes.
    Public,
    /// Internal routes only.
    Internal,
    /// Every route, for the envelope probe, which walks the whole table.
    #[cfg(test)]
    All,
}

impl Listener {
    fn serves(self, access: Access) -> bool {
        match self {
            Self::Public => access != Access::Internal,
            Self::Internal => access == Access::Internal,
            #[cfg(test)]
            Self::All => true,
        }
    }
}

/// Build the public router: every route except internal ones.
pub fn router(state: AppState) -> Router {
    router_with(state, REQUEST_TIMEOUT)
}

/// Build the internal router: internal routes only, each behind the internal
/// credential. Bound to a listener the internet cannot reach.
pub fn internal_router(state: AppState) -> Router {
    build(
        state,
        REQUEST_TIMEOUT,
        BareErrors::Convert,
        Listener::Internal,
    )
}

/// Build the router with an explicit time budget.
///
/// Exists so the timeout path is reachable in a test without waiting out
/// [`REQUEST_TIMEOUT`]. The whole layer stack is still assembled here, so a test
/// that drives this exercises the real wiring.
fn router_with(state: AppState, timeout: Duration) -> Router {
    build(state, timeout, BareErrors::Convert, Listener::Public)
}

/// Whether bare error responses are converted to envelopes.
///
/// Production always converts. `Leave` exists only so the envelope probe can
/// measure what the conversion catches — its positive control is a live count
/// taken from the unconverted stack, which cannot rot the way a fixture can.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BareErrors {
    Convert,
    #[cfg(test)]
    Leave,
}

pub(crate) fn build(
    state: AppState,
    timeout: Duration,
    bare_errors: BareErrors,
    listener: Listener,
) -> Router {
    let table = routes()
        .into_iter()
        .filter(|route| listener.serves(route.access))
        .collect();
    let router = register(table, &state)
        .with_state(state)
        // The upload ceiling, applied to every route that reads a body.
        //
        // The constant comes from `shared`, not from `builder`. Reaching into
        // `builder` for it pulled 39 crates into the control plane — the whole
        // opendal stack, zstd, a TLS implementation — to import one `usize`.
        //
        // Axum's own default is 2 MiB, which is *below* what a bundle may
        // legitimately be. Left alone, a valid upload would be refused by a
        // limit nothing in this repository states.
        .layer(DefaultBodyLimit::max(shared::MAX_BUNDLE_BYTES))
        // 504 rather than 408: 408 means the client was too slow sending, and
        // this is our side exceeding its own budget.
        .layer(TimeoutLayer::with_status_code(
            StatusCode::GATEWAY_TIMEOUT,
            timeout,
        ))
        .layer(CatchPanicLayer::custom(on_panic))
        // Spans record the method and the path, never the query: a query here
        // can carry a sign-in handshake's code or state (#62).
        .layer(TraceLayer::new_for_http().make_span_with(|request: &Request| {
            tracing::debug_span!("request", method = %request.method(), path = %request.uri().path())
        }));

    let router = match bare_errors {
        BareErrors::Convert => router.layer(middleware::from_fn(envelope_every_error)),
        #[cfg(test)]
        BareErrors::Leave => router,
    };

    router.layer(middleware::from_fn(assign_request_id))
}

/// Put every route in the table into a router, with its access control.
#[expect(
    clippy::disallowed_methods,
    reason = "load-bearing: clippy.toml forbids registering routes anywhere but \
              here, which is what makes `routes()` the complete list the envelope \
              probe walks. This is the one sanctioned site. Do not add routes \
              elsewhere, and do not remove the lint to make that easier."
)]
fn register(table: Vec<Route>, state: &AppState) -> Router<AppState> {
    let mut public = Router::new();
    let mut authenticated = Router::new();
    let mut internal = Router::new();
    let mut browser = Router::new();

    for route in table {
        match route.access {
            access @ (Access::Session | Access::SessionOptional) => {
                let mut handler = route.handler;
                if access == Access::Session {
                    handler = handler.route_layer(middleware::from_fn_with_state(
                        state.clone(),
                        crate::session::require,
                    ));
                }
                // Added last, so it runs first: a forged request is refused
                // before the session is even looked up. Decided here, from
                // the table, so no cookie-authenticated mutating route can be
                // registered without it.
                if route.verb.mutates() {
                    handler = handler.route_layer(middleware::from_fn_with_state(
                        state.clone(),
                        require_same_origin,
                    ));
                }
                browser = browser.route(route.path, handler);
            }
            Access::Public => public = public.route(route.path, route.handler),
            Access::Scoped(scope) => {
                let handler = route.handler.route_layer(middleware::from_fn(
                    move |request: Request, next: Next| auth::require_scope(scope, request, next),
                ));
                authenticated = authenticated.route(route.path, handler);
            }
            Access::Internal => {
                // The internal credential check, per route, so an internal route
                // cannot be registered without it. A different auth path from
                // the customer `authenticate` layer below: a customer token can
                // never satisfy it.
                let handler = route.handler.route_layer(middleware::from_fn_with_state(
                    state.clone(),
                    auth::require_internal,
                ));
                internal = internal.route(route.path, handler);
            }
        }
    }

    // After every protected route is registered: `route_layer` covers the
    // routes that exist when it is called, and only matched ones, so an unknown
    // path is still the fallback's 404 rather than a 401.
    if authenticated.has_routes() {
        authenticated = authenticated.route_layer(middleware::from_fn_with_state(
            state.clone(),
            auth::authenticate,
        ));
    }

    public
        .merge(authenticated)
        .merge(internal)
        .merge(browser)
        .fallback(unmatched)
}

/// Refuse a cookie-authenticated, state-changing request that did not come
/// from the control plane's own origin.
///
/// # Why `SameSite=Lax` is not enough
///
/// `SameSite` is about *sites*, and every `{app}.{org}.<apex>` is the same
/// site as the control plane. Script on any customer app can make a browser
/// send a same-site `POST` here with the visitor's session cookie attached.
/// Only an origin check tells that apart from the control plane's own pages.
///
/// # What is accepted
///
/// - `Sec-Fetch-Site` present: it must be `same-origin` (`same-site` is
///   exactly the app-subdomain attack).
/// - Otherwise `Origin` must equal the control plane's origin exactly
///   (`Origin: null` does not).
/// - Neither header: refused. A cookie-authenticated request comes from a
///   browser, which sends at least one; the CLI uses API tokens.
///
/// This holds whatever #62 decides about where the session cookie lives. It
/// mitigates forged requests; it does nothing about cookie tossing or session
/// fixation, which are #62's.
async fn require_same_origin(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    let request_id = request
        .extensions()
        .get::<RequestId>()
        .cloned()
        .unwrap_or_else(RequestId::generate);
    let Some(origin) = state.signin.as_deref().map(crate::signin::SignIn::origin) else {
        return render(
            &Error::Internal {
                source: anyhow::anyhow!("sign-in is not configured on this control plane"),
            },
            &request_id,
        );
    };
    let headers = request.headers();
    let fetch_site = headers
        .get("sec-fetch-site")
        .map(|v| v.to_str().unwrap_or(""));
    let same_origin = match fetch_site {
        Some(site) => site == "same-origin",
        None => headers
            .get(header::ORIGIN)
            .is_some_and(|v| v.as_bytes() == origin.as_bytes()),
    };
    if same_origin {
        next.run(request).await
    } else {
        render(
            &Error::Forbidden {
                what: "a cross-origin request; this operation must come from the control \
                       plane's own pages"
                    .to_owned(),
            },
            &request_id,
        )
    }
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
    // headers anywhere below cannot put a token in a log line.
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
    response
}

/// Marks a response that already carries an envelope.
///
/// An extension, so it is never serialised: nothing has to strip it, and a
/// caller cannot see it or forge it.
#[derive(Debug, Clone, Copy)]
struct Rendered;

/// Give every 4xx and 5xx an envelope, whatever produced it.
///
/// A success is returned untouched: the status is checked first, and below 400
/// there is no extension lookup, no header read and no body. The *decision* is
/// one comparison, but the layer is not free — measured at about 1.1 µs per
/// request in a release build (6.5 µs to 7.7 µs for `GET /healthz` through the
/// whole stack), which is the `from_fn` future and the request id cloned before
/// the inner service runs. Against a database round trip of hundreds of
/// microseconds that is noise; it is stated so nobody assumes it is zero.
async fn envelope_every_error(request: Request, next: Next) -> Response {
    let id = request
        .extensions()
        .get::<RequestId>()
        .cloned()
        .unwrap_or_else(RequestId::generate);

    let response = next.run(request).await;

    if response.status().as_u16() < 400 || response.extensions().get::<Rendered>().is_some() {
        return response;
    }
    envelope(response, &id).await
}

/// Convert a bare error response into the envelope.
async fn envelope(response: Response, id: &RequestId) -> Response {
    let (parts, body) = response.into_parts();
    let status = parts.status;

    let error = match status {
        StatusCode::BAD_REQUEST => Error::InvalidRequest {
            what: echoable_text(&parts, body)
                .await
                .unwrap_or_else(|| "the request could not be read".to_owned()),
        },
        StatusCode::NOT_FOUND => Error::NotFound {
            what: "that resource".to_owned(),
        },
        StatusCode::METHOD_NOT_ALLOWED => Error::MethodNotAllowed {},
        StatusCode::PAYLOAD_TOO_LARGE => Error::PayloadTooLarge {
            what: format!(
                "request body exceeds the {} byte limit",
                shared::MAX_BUNDLE_BYTES
            ),
        },
        StatusCode::GATEWAY_TIMEOUT => Error::Timeout {
            dependency: "the request exceeded its time budget".to_owned(),
        },
        other if other.is_client_error() => {
            tracing::warn!(status = %other, "a bare client error had no code of its own");
            Error::InvalidRequest {
                what: format!("the request was rejected with status {other}"),
            }
        }
        other => {
            tracing::error!(status = %other, "a bare server error reached the edge unrendered");
            Error::Internal {
                source: anyhow::anyhow!("a bare {other} reached the edge unrendered"),
            }
        }
    };

    let mut rendered = render(&error, id);

    // A status with no code of its own keeps its status, even though the code
    // it borrowed declares a different one. Rewriting a 415 into a 400 would
    // misreport what happened; leaving the disagreement in place is what lets
    // the envelope probe count it and force a proper mapping.
    *rendered.status_mut() = status;

    // No headers are copied from the bare response. The one a caller needs,
    // `Allow` on a 405, is appended by axum's method router *after* this layer
    // returns — `Router::layer` wraps each route's endpoint, and the router adds
    // `Allow` around that call — so this layer never sees it and cannot drop it.
    // The envelope probe checks `Allow` on the wire, which is where it matters.
    rendered
}

/// The plain-text body of a bare 4xx, fit to be the envelope's message.
///
/// Only for 400s, only `text/plain`, only under [`ECHO_LIMIT`], and never for a
/// 5xx — whose text is ours and may name internals.
///
/// # Why echoing caller input is safe here and was not in `clwdrun/clwd#34`
///
/// The text contains what the caller sent: "Cannot parse `app_id` with value
/// `…`". `clwd#34` made SDK error bodies `&'static str` for the mirror image of
/// this — there, input from one party would have reached another. Here the input
/// is the caller's own and goes back only to them, so it tells them nothing they
/// did not send. It is not logged. It is JSON-encoded, and control characters
/// are replaced anyway, so a client that prints the message to a terminal
/// cannot be handed an escape sequence decoded from its own URL.
async fn echoable_text(parts: &Parts, body: Body) -> Option<String> {
    let plain = parts
        .headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|ct| ct.starts_with("text/plain"));
    if !plain {
        return None;
    }
    let bytes = axum::body::to_bytes(body, ECHO_LIMIT).await.ok()?;
    let text = std::str::from_utf8(&bytes).ok()?;
    Some(
        text.chars()
            .map(|c| if c.is_control() { '\u{fffd}' } else { c })
            .collect(),
    )
}

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
        .body(Body::from(body))
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response());
    response.extensions_mut().insert(Rendered);

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

fn healthz_doc() -> Doc {
    Doc {
        operation_id: "health",
        summary: "Liveness",
        description: "Answers `ok` while the process is serving requests. For load balancers: it checks nothing downstream.",
        params: &[],
        request: None,
        success: vec![Success {
            status: StatusCode::OK,
            description: "The process is serving requests.",
            body: Some(openapi::Body::text("The literal text `ok`.", || {
                Ok("ok".into())
            })),
        }],
        errors: &[],
    }
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
    use std::convert::Infallible;
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

    /// One bare response, through the conversion layer alone — no router, so
    /// the conversion is what is under test and nothing else can render.
    async fn converted(bare: fn() -> Response) -> (StatusCode, serde_json::Value, Response<Body>) {
        let service = tower::ServiceBuilder::new()
            .layer(middleware::from_fn(envelope_every_error))
            .service(tower::service_fn(move |_: Request| async move {
                Ok::<_, Infallible>(bare())
            }));
        let response = service.oneshot(get("/")).await.expect("infallible");
        let status = response.status();
        let (parts, body) = response.into_parts();
        let bytes = to_bytes(body, 64 * 1024).await.expect("body reads");
        let json = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
        (status, json, Response::from_parts(parts, Body::empty()))
    }

    /// Every error path is an envelope. **No bare 500, no bare 404, no dropped
    /// connection.** The envelope probe generalises this to every route.
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

    /// The marker that says "this is already an envelope" never reaches the
    /// caller. Its predecessor was a header documented as stripped, which
    /// nothing stripped.
    #[tokio::test]
    async fn no_internal_marker_reaches_the_wire() {
        for uri in [
            "/v1/apps/dashboard",
            "/v1/panic",
            "/no/such/route",
            "/healthz",
        ] {
            let (_, _, response) = call(get(uri)).await;
            let leaked: Vec<&str> = response
                .headers()
                .keys()
                .map(axum::http::HeaderName::as_str)
                .filter(|name| name.starts_with("x-clwd"))
                .collect();
            assert!(leaked.is_empty(), "for {uri}: {leaked:?}");
        }
    }

    /// A wrong method is a 405 envelope, and keeps the `Allow` header HTTP
    /// requires — through the real router, where axum produces it.
    #[tokio::test]
    async fn a_wrong_method_is_a_405_envelope_with_allow() {
        let (status, json, response) = call(get("/v1/body")).await;
        assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
        assert_eq!(json["code"], "control-plane.method_not_allowed");
        assert_eq!(json["retryable"], false, "the same method fails forever");
        assert_eq!(
            response
                .headers()
                .get(header::ALLOW)
                .map(HeaderValue::as_bytes),
            Some(&b"POST"[..])
        );
    }

    /// A bare plain-text 400 keeps its text as the message, with control
    /// characters replaced, so a client printing it cannot be handed an escape
    /// sequence.
    #[tokio::test]
    async fn a_bare_plain_text_400_is_echoed_with_controls_replaced() {
        let (status, json, _) = converted(|| {
            (
                StatusCode::BAD_REQUEST,
                "Cannot parse `app_id` with value `\u{1b}[31mred\n`",
            )
                .into_response()
        })
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(json["code"], "control-plane.invalid_request");
        let message = json["message"].as_str().expect("a message");
        assert!(message.contains("Cannot parse `app_id`"), "{message}");
        assert!(
            !message.chars().any(char::is_control),
            "control characters survived: {message:?}"
        );
    }

    /// Only short plain text is echoed. JSON, HTML or a large body is not.
    #[tokio::test]
    async fn only_short_plain_text_is_echoed() {
        let (_, json, _) =
            converted(|| (StatusCode::BAD_REQUEST, "x".repeat(ECHO_LIMIT + 1)).into_response())
                .await;
        assert_eq!(
            json["message"],
            "invalid request: the request could not be read"
        );

        let (_, json, _) = converted(|| {
            (
                StatusCode::BAD_REQUEST,
                [(header::CONTENT_TYPE, "text/html")],
                "<b>internal detail</b>",
            )
                .into_response()
        })
        .await;
        assert_eq!(
            json["message"],
            "invalid request: the request could not be read"
        );
    }

    /// A bare 5xx's body is ours and may name internals: it is never forwarded.
    /// A status with no code of its own keeps that status.
    #[tokio::test]
    async fn a_bare_5xx_is_never_echoed_and_keeps_its_status() {
        let (status, json, _) = converted(|| {
            // The marker has letters no request id can hold: a UUIDv7 id is
            // hex with `-7` at its version position, so a hex-looking marker
            // like `db-7` matched one id in 256 and failed for nothing.
            (
                StatusCode::BAD_GATEWAY,
                "upstream zq-leak-marker.internal refused",
            )
                .into_response()
        })
        .await;
        assert_eq!(
            status,
            StatusCode::BAD_GATEWAY,
            "the status is not rewritten"
        );
        assert_eq!(json["code"], "control-plane.internal");
        assert!(
            !json.to_string().contains("zq-leak-marker"),
            "a server error's text leaked: {json}"
        );
    }

    /// An unmapped 4xx keeps its status, so its code's declared status
    /// disagrees — which the envelope probe counts, forcing a real mapping.
    #[tokio::test]
    async fn an_unmapped_client_error_keeps_its_status() {
        let (status, json, _) =
            converted(|| StatusCode::UNSUPPORTED_MEDIA_TYPE.into_response()).await;
        assert_eq!(status, StatusCode::UNSUPPORTED_MEDIA_TYPE);
        assert_eq!(json["code"], "control-plane.invalid_request");
    }

    /// A response that already carries an envelope passes through unchanged:
    /// the conversion must not alter responses that were already correct.
    #[tokio::test]
    async fn an_envelope_passes_through_untouched() {
        fn already() -> Response {
            render(
                &Error::Conflict {
                    what: "slug taken".to_owned(),
                },
                &RequestId::sanitize("req-1").expect("well formed"),
            )
        }
        let (status, json, _) = converted(already).await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(json["code"], "control-plane.conflict");
        assert_eq!(json["message"], "conflict: slug taken");
        assert_eq!(json["request_id"], "req-1", "not re-rendered with a new id");
    }

    /// A success is returned exactly as produced.
    #[tokio::test]
    async fn a_success_passes_through_untouched() {
        let service = tower::ServiceBuilder::new()
            .layer(middleware::from_fn(envelope_every_error))
            .service(tower::service_fn(|_: Request| async {
                Ok::<_, Infallible>(
                    (
                        StatusCode::CREATED,
                        [(header::CONTENT_TYPE, "text/plain")],
                        "made",
                    )
                        .into_response(),
                )
            }));
        let response = service.oneshot(get("/")).await.expect("infallible");
        assert_eq!(response.status(), StatusCode::CREATED);
        assert_eq!(response.headers()[header::CONTENT_TYPE], "text/plain");
        let bytes = to_bytes(response.into_body(), 1024).await.expect("body");
        assert_eq!(&bytes[..], b"made");
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
                    .map(HeaderValue::as_bytes),
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
    /// declares.
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

    /// The body limit's rejection, which comes from an extractor rather than a
    /// handler, is an envelope. Asserted through the real router rather than by
    /// calling `render`, which would prove only that `render` renders.
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
    /// up front — the limit has to hold while the body streams. The sized test
    /// above would keep passing if the limit only ever worked for bodies that
    /// declare a length.
    #[tokio::test]
    async fn an_oversized_chunked_body_is_also_an_envelope() {
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
