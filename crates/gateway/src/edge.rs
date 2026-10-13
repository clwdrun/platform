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

use crate::authz::Authz;
use crate::host::parse_host;
use crate::lookup::{Route, RouteLookup};
use crate::signin::{
    APP_SESSION_COOKIE, AppSession, COUNTER_COOKIE, COUNTER_WINDOW_SECS, MAX_HANDSHAKES,
    MAX_IN_FLIGHT, STATE_COOKIE_PREFIX, STATE_ID_LEN, SigninClient, begun_state_cookie,
    constant_time_eq, counter_cookie, parse_state_cookie_value, state_cookie, state_cookie_name,
};
use crate::upstream::{
    AppTarget, AppUpstream, UpstreamError, UpstreamRequest, drop_platform_set_cookies,
    strip_client_identity, strip_hop_by_hop,
};
use bytes::Bytes;
use shared::cookie::Found;
use shared::domains::ControlPlaneDomain;
use shared::hop::Caller;
use shared::return_path::ReturnPath;

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
    /// A path under [`RESERVED_PREFIX`] on an app host that is not one the
    /// platform answers: a 404, and never forwarded to the app.
    Reserved,
    /// The request carries a platform cookie twice: refused, not guessed at.
    DuplicateCookie,
    /// A request that is not a navigation, with no app-host session.
    SignInRequired,
    /// Too many handshakes from one browser for one app host in a short window.
    SignInLoop,
    /// The callback's code was refused: used, expired or forged.
    SignInFailed,
    /// The app could not be reached.
    AppUnreachable,
    /// The app could not take this request right now, and the same request
    /// may succeed shortly (#103).
    AppUnavailable,
    /// The app failed on this request, and sending it again fails the same
    /// way (#103).
    AppFailed,
    /// The platform failed to serve the app: a code that names the platform's
    /// own fault, or one no pinned catalogue knows (#103).
    PlatformFailed,
    /// Signed in, but not a member of the app's org: the interim access rule
    /// until #12. No app code runs.
    NotAMember,
}

/// The path prefix the platform reserves on every app host for its own
/// endpoints (the sign-in handshake's callback). Requests under it are never
/// forwarded to the app; an app's own route there is shadowed, and a developer
/// who tries one gets `gateway.reserved_path`.
pub const RESERVED_PREFIX: &str = "/__clwd/";

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
    /// Seconds for a `Retry-After` header, on a retryable answer that has one.
    retry_after: Option<&'static str>,
}

/// The disposition for a failure the worker reported by code (#103).
///
/// The visitor's answer is the gateway's own. The code is matched against the
/// pinned `clwd_runtime` catalogue, and whether the request is worth retrying
/// comes from that crate's own per-code table — never from the worker, whose
/// output is untrusted (#11), and never from the code's spelling. A code the
/// catalogue does not know is not retryable. Pure, so it is tested directly.
fn reported(code: &str) -> Disposition {
    match code {
        // The worker's own refusals. A bundle granting egress is the app's
        // configuration, like `runtime.capability_denied`; an artifact the
        // worker cannot load is ours.
        "worker.egress_not_supported" => return Disposition::AppFailed,
        "worker.artifact_unavailable" => return Disposition::PlatformFailed,
        // The platform stored and serves the bundle, so its absence, or the
        // runtime's own defect, is the platform's failure, not the app's.
        "runtime.bundle_not_found" | "runtime.internal" => return Disposition::PlatformFailed,
        _ => {}
    }
    match clwd_runtime::error::OWNED_RETRYABLE
        .iter()
        .find(|(known, _)| *known == code)
    {
        Some((_, true)) => Disposition::AppUnavailable,
        Some((_, false)) => Disposition::AppFailed,
        // A `bundle.*` code raised at spawn (the platform built and stored that
        // bundle), or a code no pinned catalogue knows.
        None => Disposition::PlatformFailed,
    }
}

/// Map a resolved route (or its absence) to a disposition. `None` means the
/// request had no usable host or a host that is not `{app}.{org}.<apex>` — both
/// unroutable, and both a 404. Pure, so it is tested directly.
fn disposition(route: Option<Route>, path: &str) -> Disposition {
    match route {
        None | Some(Route::Unknown) => Disposition::Unknown,
        Some(Route::App { .. }) if path.starts_with(RESERVED_PREFIX) => Disposition::Reserved,
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
            retry_after: None,
        },
        Disposition::NotReady => EnvelopeSpec {
            status: StatusCode::SERVICE_UNAVAILABLE,
            code: "gateway.not_ready",
            message: "this application is not yet serving requests",
            hint: "the platform is bringing this app online; retry shortly",
            retryable: true,
            retry_after: None,
        },
        Disposition::Reserved => EnvelopeSpec {
            status: StatusCode::NOT_FOUND,
            code: "gateway.reserved_path",
            message: "paths under /__clwd/ are reserved by the platform and never reach the app",
            hint: "serve this route from a different path; /__clwd/ belongs to the platform",
            retryable: false,
            retry_after: None,
        },
        Disposition::DuplicateCookie => EnvelopeSpec {
            status: StatusCode::BAD_REQUEST,
            code: "gateway.duplicate_cookie",
            message: "the request carries a platform cookie more than once",
            hint: "clear this site's cookies and open the app again",
            retryable: false,
            retry_after: None,
        },
        Disposition::SignInRequired => EnvelopeSpec {
            status: StatusCode::UNAUTHORIZED,
            code: "gateway.sign_in_required",
            message: "this app requires signing in",
            hint: "open the app in a browser to sign in, then retry",
            retryable: false,
            retry_after: None,
        },
        Disposition::SignInLoop => EnvelopeSpec {
            status: StatusCode::CONFLICT,
            code: "gateway.sign_in_loop",
            message: "signing in to this app kept restarting, so it was stopped",
            hint: "wait a minute and open the app again; if it repeats, your browser may be blocking cookies for this site",
            retryable: true,
            retry_after: None,
        },
        Disposition::SignInFailed => EnvelopeSpec {
            status: StatusCode::FORBIDDEN,
            code: "gateway.sign_in_failed",
            message: "this sign-in link was already used or has expired",
            hint: "open the app again to sign in",
            retryable: false,
            retry_after: None,
        },
        Disposition::AppUnreachable => EnvelopeSpec {
            status: StatusCode::BAD_GATEWAY,
            code: "gateway.app_unreachable",
            message: "the app could not be reached",
            hint: "retry shortly",
            retryable: true,
            retry_after: None,
        },
        Disposition::NotAMember => EnvelopeSpec {
            status: StatusCode::FORBIDDEN,
            code: "gateway.not_a_member",
            message: "this app is only open to members of its organization",
            hint: "ask an owner of the organization to add you",
            retryable: false,
            retry_after: None,
        },
        Disposition::AppUnavailable => EnvelopeSpec {
            status: StatusCode::SERVICE_UNAVAILABLE,
            code: "gateway.app_unavailable",
            message: "the app could not take this request right now",
            hint: "The app is busy; try again shortly.",
            retryable: true,
            retry_after: Some("1"),
        },
        Disposition::AppFailed => EnvelopeSpec {
            status: StatusCode::BAD_GATEWAY,
            code: "gateway.app_failed",
            message: "the app failed to handle this request",
            hint: "The app failed to handle this request.",
            retryable: false,
            retry_after: None,
        },
        Disposition::PlatformFailed => EnvelopeSpec {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            code: "gateway.internal",
            message: "the platform could not serve this request",
            hint: "This is a fault in the platform, not in your request; it has been logged.",
            retryable: false,
            retry_after: None,
        },
        Disposition::Unavailable => EnvelopeSpec {
            status: StatusCode::SERVICE_UNAVAILABLE,
            code: "gateway.unavailable",
            message: "the platform could not resolve this host right now",
            hint: "a platform dependency is unreachable; retry shortly",
            retryable: true,
            retry_after: None,
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
    if let Some(seconds) = spec.retry_after {
        headers.insert(header::RETRY_AFTER, HeaderValue::from_static(seconds));
    }
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

/// The callback path of the app-host sign-in handshake.
pub const CALLBACK_PATH: &str = "/__clwd/callback";
/// The largest request body forwarded to an app.
const MAX_BODY: usize = 16 * 1024 * 1024;

/// What the edge needs to serve an app: the sign-in client, where the control
/// plane is, and the hop to the app. Absent in production until #11 provides
/// the hop; then a live app answers `gateway.not_ready` as before.
pub struct Serving {
    signin: Arc<SigninClient>,
    /// Every app request's decision: cached when the invalidation stream says
    /// it may be, the control plane's check otherwise (#12).
    authz: Arc<Authz>,
    control_plane: ControlPlaneDomain,
    upstream: Arc<dyn AppUpstream>,
}

impl Serving {
    /// Assemble the serving side. The authorization cache starts in bypass:
    /// it serves nothing from cache until [`crate::authz::follow`] is running
    /// against [`Self::authz`] and the control plane has granted a lease.
    #[must_use]
    pub fn new(
        signin: Arc<SigninClient>,
        control_plane: ControlPlaneDomain,
        upstream: Arc<dyn AppUpstream>,
    ) -> Self {
        let authz = Arc::new(Authz::new(signin.clone()));
        Self {
            signin,
            authz,
            control_plane,
            upstream,
        }
    }

    /// The authorization cache, for following the invalidation stream.
    #[must_use]
    pub fn authz(&self) -> Arc<Authz> {
        self.authz.clone()
    }
}

/// The pingora edge application.
pub struct Edge {
    lookup: Arc<RouteLookup>,
    apps: AppsDomain,
    serving: Option<Serving>,
}

/// A response the edge builds itself: a status, its headers, a body.
fn answer(
    status: StatusCode,
    headers: Vec<(header::HeaderName, String)>,
    body: Vec<u8>,
) -> Response<Vec<u8>> {
    let mut response = Response::new(body);
    *response.status_mut() = status;
    for (name, value) in headers {
        if let Ok(value) = HeaderValue::from_str(&value) {
            response.headers_mut().append(name, value);
        }
    }
    response
}

/// A redirect that carries no `Referer` onward and is never cached.
fn redirect(location: &str, set_cookies: Vec<String>) -> Response<Vec<u8>> {
    let mut headers = vec![
        (header::LOCATION, location.to_owned()),
        (header::REFERRER_POLICY, "no-referrer".to_owned()),
        (header::CACHE_CONTROL, "no-store".to_owned()),
    ];
    headers.extend(set_cookies.into_iter().map(|c| (header::SET_COOKIE, c)));
    answer(StatusCode::SEE_OTHER, headers, Vec::new())
}

impl Edge {
    /// An edge that resolves hosts under the apps domain via `lookup`, and
    /// does not serve apps.
    #[must_use]
    pub fn new(lookup: Arc<RouteLookup>, apps: AppsDomain) -> Self {
        Self {
            lookup,
            apps,
            serving: None,
        }
    }

    /// Serve apps through `serving`: sign-in, the session check, and the hop.
    #[must_use]
    pub fn serving(mut self, serving: Serving) -> Self {
        self.serving = Some(serving);
        self
    }

    /// A live app's request. In order: the platform's callback; other reserved
    /// paths; a duplicate platform cookie; then the session check — and only a
    /// live session for this app reaches the hop, with the platform's cookies
    /// removed. Anything else starts a handshake.
    async fn serve_app(
        &self,
        serving: &Serving,
        session: &mut ServerSession,
        target: AppTarget,
    ) -> Response<Vec<u8>> {
        let head = session.req_header();
        let cookies: Vec<Vec<u8>> = head
            .headers
            .get_all(header::COOKIE)
            .iter()
            .map(|v| v.as_bytes().to_vec())
            .collect();
        let cookie_slices = || cookies.iter().map(Vec::as_slice);
        let path = head.uri.path();

        if path == CALLBACK_PATH {
            let query = head.uri.query().unwrap_or("").to_owned();
            return self.callback(serving, &target, &query, &cookies).await;
        }
        if path.starts_with(RESERVED_PREFIX) {
            return render_disposition(Disposition::Reserved);
        }
        let Ok(forwarded_cookie) = shared::cookie::strip_platform(cookie_slices()) else {
            return render_disposition(Disposition::DuplicateCookie);
        };

        if let Found::One(value) = shared::cookie::find(cookie_slices(), APP_SESSION_COOKIE) {
            match serving
                .authz
                .authorize(&AppSession::new(value), target.app_id())
                .await
            {
                // Refused here, so a denied request never reaches the hop.
                // Every reason today is the interim org-member rule's; #14's
                // reasons get their own dispositions.
                Ok(Some(checked)) if !checked.decision.is_allow() => {
                    return render_disposition(Disposition::NotAMember);
                }
                Ok(Some(checked)) => {
                    return self
                        .forward(serving, session, &target, checked.caller, forwarded_cookie)
                        .await;
                }
                Ok(None) => {}
                Err(error) => {
                    tracing::warn!(%error, "app session check failed; refusing");
                    return render_disposition(Disposition::Unavailable);
                }
            }
        }

        let head = session.req_header();
        if head.method != http::Method::GET && head.method != http::Method::HEAD {
            return render_disposition(Disposition::SignInRequired);
        }
        let return_path = head
            .uri
            .path_and_query()
            .and_then(|pq| ReturnPath::parse(pq.as_str()).ok())
            .unwrap_or_else(ReturnPath::root);
        self.begin(serving, &target, &return_path, &cookies).await
    }

    /// Start a handshake: record it, set the state cookie, send the visitor to
    /// `/authorize` — unless this browser has already started too many.
    async fn begin(
        &self,
        serving: &Serving,
        target: &AppTarget,
        return_path: &ReturnPath,
        cookies: &[Vec<u8>],
    ) -> Response<Vec<u8>> {
        let started = match shared::cookie::find(cookies.iter().map(Vec::as_slice), COUNTER_COOKIE)
        {
            Found::One(n) => n.parse::<u8>().unwrap_or(MAX_HANDSHAKES),
            _ => 0,
        };
        if started >= MAX_HANDSHAKES {
            return render_disposition(Disposition::SignInLoop);
        }
        let state = match serving.signin.begin(target.app_id(), return_path).await {
            Ok(state) => state,
            Err(error) => {
                tracing::warn!(%error, "could not begin a sign-in handshake");
                return render_disposition(Disposition::Unavailable);
            }
        };
        // Wall-clock microseconds, only to tell which handshake is oldest.
        let begun_us = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_micros());
        let Some(set_state) = begun_state_cookie(&state, begun_us) else {
            tracing::warn!("the control plane began a handshake with a malformed state");
            return render_disposition(Disposition::Unavailable);
        };
        let mut set_cookies = vec![
            set_state,
            counter_cookie(started.saturating_add(1), COUNTER_WINDOW_SECS),
        ];
        // Other tabs' handshakes stay in flight (#83); past MAX_IN_FLIGHT the
        // oldest go, and their tabs restart when their callback finds no
        // cookie. Only names of our own exact shape are counted or evicted.
        let mut in_flight: Vec<(u128, &str)> =
            shared::cookie::with_prefix(cookies.iter().map(Vec::as_slice), STATE_COOKIE_PREFIX)
                .into_iter()
                .filter(|(name, _)| {
                    name.strip_prefix(STATE_COOKIE_PREFIX).is_some_and(|id| {
                        id.len() == STATE_ID_LEN && id.bytes().all(|b| b.is_ascii_hexdigit())
                    })
                })
                .map(|(name, value)| {
                    let begun = parse_state_cookie_value(value).map_or(0, |(ms, _)| ms);
                    (begun, name)
                })
                .collect();
        in_flight.sort_unstable();
        let excess = (in_flight.len() + 1).saturating_sub(MAX_IN_FLIGHT);
        for (_, name) in in_flight.into_iter().take(excess) {
            set_cookies.push(state_cookie(name, "", 0));
        }
        redirect(
            &format!("{}/authorize?state={state}", serving.control_plane.origin()),
            set_cookies,
        )
    }

    /// `/__clwd/callback?code=…&state=…`: exchange only if `state` matches the
    /// state cookie this browser was given. A mismatch — another tab began a
    /// newer handshake, or someone else's code was sent here (login CSRF) — is
    /// never exchanged: the visitor starts their own handshake instead, which
    /// counts toward the loop guard.
    async fn callback(
        &self,
        serving: &Serving,
        target: &AppTarget,
        query: &str,
        cookies: &[Vec<u8>],
    ) -> Response<Vec<u8>> {
        let mut code = None;
        let mut state = None;
        for (name, value) in form_urlencoded::parse(query.as_bytes()) {
            match &*name {
                "code" => code = Some(value.into_owned()),
                "state" => state = Some(value.into_owned()),
                _ => {}
            }
        }
        let slices = || cookies.iter().map(Vec::as_slice);
        // This handshake's own cookie, named by its state: another tab's
        // handshake in flight is a different cookie and is left alone.
        let own = state.as_deref().and_then(state_cookie_name);
        let matches = match (&state, &own) {
            (Some(state), Some(name)) => match shared::cookie::find(slices(), name) {
                Found::One(value) => parse_state_cookie_value(value)
                    .is_some_and(|(_, held)| constant_time_eq(state.as_bytes(), held.as_bytes())),
                // Absent (evicted, expired, another browser's) or duplicated.
                _ => false,
            },
            _ => false,
        };

        if let (true, Some(code), Some(state), Some(own)) = (matches, code, state, own.as_deref()) {
            return match serving.signin.exchange(&code, &state).await {
                Ok(Some(exchanged)) => redirect(
                    exchanged.return_path.as_str(),
                    vec![
                        exchanged.set_cookie(),
                        state_cookie(own, "", 0),
                        counter_cookie(0, 0),
                    ],
                ),
                // Already used, expired or forged: an answer, never another
                // redirect — a second callback for one state must not loop.
                Ok(None) => render_disposition(Disposition::SignInFailed),
                Err(error) => {
                    tracing::warn!(%error, "could not exchange a sign-in code");
                    render_disposition(Disposition::Unavailable)
                }
            };
        }

        // Not this browser's handshake. Already signed in (a concurrent tab
        // finished first)? Then just go to the app.
        if let Found::One(value) = shared::cookie::find(slices(), APP_SESSION_COOKIE)
            && matches!(
                serving
                    .signin
                    .check(&AppSession::new(value), target.app_id())
                    .await,
                Ok(Some(_))
            )
        {
            return redirect("/", Vec::new());
        }
        self.begin(serving, target, &ReturnPath::root(), cookies)
            .await
    }

    /// Hand the request to the app named by `target`, platform cookies already
    /// removed, and drop any platform `Set-Cookie` from its answer.
    async fn forward(
        &self,
        serving: &Serving,
        session: &mut ServerSession,
        target: &AppTarget,
        caller: Caller,
        cookie: Option<Vec<u8>>,
    ) -> Response<Vec<u8>> {
        let mut body = Vec::new();
        loop {
            match session.read_request_body().await {
                Ok(Some(chunk)) => {
                    if body.len() + chunk.len() > MAX_BODY {
                        return answer(StatusCode::PAYLOAD_TOO_LARGE, Vec::new(), Vec::new());
                    }
                    body.extend_from_slice(&chunk);
                }
                Ok(None) => break,
                Err(_) => return answer(StatusCode::BAD_REQUEST, Vec::new(), Vec::new()),
            }
        }
        let head = session.req_header();
        let mut headers = head.headers.clone();
        strip_client_identity(&mut headers);
        headers.remove(header::COOKIE);
        if let Some(cookie) = cookie.and_then(|c| HeaderValue::from_bytes(&c).ok()) {
            headers.insert(header::COOKIE, cookie);
        }
        let request = UpstreamRequest::new(
            caller,
            head.method.clone(),
            head.uri
                .path_and_query()
                .map_or_else(|| "/".to_owned(), |pq| pq.as_str().to_owned()),
            headers,
            Bytes::from(body),
        );
        match serving.upstream.forward(target, request).await {
            Ok(mut upstream) => {
                // Here, after the hop, never in the worker: the worker runs
                // untrusted code and its output is filtered as such.
                drop_platform_set_cookies(&mut upstream.headers);
                strip_hop_by_hop(&mut upstream.headers);
                let mut response = Response::new(upstream.body.to_vec());
                *response.status_mut() = upstream.status;
                *response.headers_mut() = upstream.headers;
                response
            }
            Err(UpstreamError::Unreachable(detail)) => {
                tracing::warn!(%detail, "app unreachable");
                render_disposition(Disposition::AppUnreachable)
            }
            // The full code is for the app's author, in the log; the visitor
            // gets the gateway's answer for it. `?` escapes it: the worker's
            // output is untrusted, and a raw code could forge log lines.
            Err(UpstreamError::Reported(code)) => {
                let disposition = reported(&code);
                tracing::warn!(app = %target.app_id(), code = ?code, "the app failed");
                render_disposition(disposition)
            }
        }
    }

    /// Resolve a host string to a route, or `None` when it is not an app host.
    async fn route(&self, host: &str) -> Option<Route> {
        let app_host = parse_host(host, self.apps.as_str()).ok()?;
        Some(self.lookup.resolve(&app_host).await)
    }
}

/// Render a disposition with a fresh request id, logging which answer it was.
fn render_disposition(disposition: Disposition) -> Response<Vec<u8>> {
    let request_id = RequestId::generate();
    let spec = spec(disposition);
    tracing::info!(
        code = spec.code,
        status = spec.status.as_u16(),
        request_id = request_id.as_str(),
        "edge response"
    );
    render(&spec, &request_id)
}

#[async_trait]
impl ServeHttp for Edge {
    async fn response(&self, session: &mut ServerSession) -> Response<Vec<u8>> {
        let request_id = RequestId::generate();

        let route = match requested_host(session.req_header()) {
            Some(host) => self.route(&host).await,
            None => None,
        };
        // A live app, and an edge that serves apps: sign-in and the hop. The
        // target is the resolved row — nothing in the request chooses it.
        if let (
            Some(serving),
            Some(Route::App {
                app_id,
                org_id,
                digest,
                ..
            }),
        ) = (&self.serving, &route)
        {
            // Nothing published yet, or a digest that does not parse: there
            // is no version to run, so the app is not ready. Answered before
            // sign-in, so a visitor is not sent through a handshake for it.
            let Some(digest) = digest.as_deref().and_then(|d| d.parse().ok()) else {
                return render_disposition(Disposition::NotReady);
            };
            let target = AppTarget::new(app_id.clone(), org_id.clone(), digest);
            return self.serve_app(serving, session, target).await;
        }
        let disposition = disposition(route, session.req_header().uri.path());
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
        assert_eq!(disposition(None, "/"), Disposition::Unknown);
        assert_eq!(disposition(Some(Route::Unknown), "/"), Disposition::Unknown);
        assert_eq!(
            disposition(
                Some(Route::App {
                    app_id: "a".to_owned(),
                    org_id: "o".to_owned(),
                    digest: None,
                    stale: false,
                }),
                "/"
            ),
            Disposition::NotReady
        );
        assert_eq!(
            disposition(
                Some(Route::App {
                    app_id: "a".to_owned(),
                    org_id: "o".to_owned(),
                    digest: None,
                    stale: true,
                }),
                "/"
            ),
            Disposition::NotReady,
            "a stale-served app is still a live app, not-ready to proxy"
        );
        assert_eq!(
            disposition(Some(Route::Unavailable), "/"),
            Disposition::Unavailable
        );
        // A reserved path on a live app is the platform's, never the app's.
        for path in ["/__clwd/", "/__clwd/callback", "/__clwd/anything?x=1"] {
            assert_eq!(
                disposition(
                    Some(Route::App {
                        app_id: "a".to_owned(),
                        org_id: "o".to_owned(),
                        digest: None,
                        stale: false,
                    }),
                    path
                ),
                Disposition::Reserved,
                "{path}"
            );
        }
        assert_eq!(spec(Disposition::Reserved).code, "gateway.reserved_path");
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

    /// Every runtime code lands in the row #103 specifies. Exhaustive over the
    /// pinned catalogue: a pin bump that adds a code fails here until someone
    /// places it, rather than inheriting a row by accident.
    #[test]
    fn every_runtime_code_lands_in_its_row() {
        use Disposition::{AppFailed, AppUnavailable, PlatformFailed};
        let expected: &[(&str, Disposition)] = &[
            ("runtime.spawn_deadline_exceeded", AppUnavailable),
            ("runtime.invoke_deadline_exceeded", AppUnavailable),
            ("runtime.stopped", AppUnavailable),
            ("runtime.cpu_budget_exceeded", AppFailed),
            ("runtime.memory_limit_exceeded", AppFailed),
            ("runtime.response_too_large", AppFailed),
            ("runtime.table_limit_exceeded", AppFailed),
            ("runtime.trap", AppFailed),
            ("runtime.capability_denied", AppFailed),
            ("runtime.incompatible_interface", AppFailed),
            ("runtime.bundle_not_found", PlatformFailed),
            ("runtime.internal", PlatformFailed),
        ];
        let listed: std::collections::BTreeSet<&str> = expected.iter().map(|(c, _)| *c).collect();
        let pinned: std::collections::BTreeSet<&str> =
            clwd_runtime::error::OWNED_CODES.iter().copied().collect();
        assert_eq!(
            listed, pinned,
            "the pinned clwd-runtime's codes changed: place each new one in a row"
        );
        for (code, want) in expected {
            assert_eq!(reported(code), *want, "{code}");
        }
        // Where the app is at fault, the visitor's `retryable` is the crate's.
        for (code, retryable) in clwd_runtime::error::OWNED_RETRYABLE {
            if reported(code) != PlatformFailed {
                assert_eq!(spec(reported(code)).retryable, *retryable, "{code}");
            }
        }
        assert_eq!(reported("worker.egress_not_supported"), AppFailed);
        assert_eq!(reported("worker.artifact_unavailable"), PlatformFailed);
    }

    /// The worker's code is matched exactly against the pinned catalogue; a
    /// code it does not know — a typo, a forged lookalike, a code from a newer
    /// runtime than the pin — is the platform's failure and never retryable.
    /// A `bundle.*` code at spawn lands in the same row: the platform built
    /// and stored that bundle.
    #[test]
    fn a_code_no_catalogue_knows_is_not_retryable() {
        for code in [
            "runtime.made_up",
            "runtime.stopped ",
            "RUNTIME.STOPPED",
            "worker.retry_me",
            "",
            "bundle.member_digest_mismatch",
        ] {
            let disposition = reported(code);
            assert_eq!(disposition, Disposition::PlatformFailed, "{code:?}");
            assert!(!spec(disposition).retryable, "{code:?}");
        }
    }

    /// The three rows a reported failure renders to, byte for byte, with their
    /// status and `Retry-After`. Nothing the worker reported appears: the code
    /// goes to the log, never to the visitor.
    #[test]
    fn the_runtime_rows_render_byte_for_byte() {
        let id = RequestId::sanitize("req-42").expect("well formed");
        let rows = [
            (
                "runtime.spawn_deadline_exceeded",
                503,
                Some("1"),
                r#"{"code":"gateway.app_unavailable","message":"the app could not take this request right now","hint":"The app is busy; try again shortly.","retryable":true,"request_id":"req-42"}"#,
            ),
            (
                "runtime.cpu_budget_exceeded",
                502,
                None,
                r#"{"code":"gateway.app_failed","message":"the app failed to handle this request","hint":"The app failed to handle this request.","retryable":false,"request_id":"req-42"}"#,
            ),
            (
                "runtime.internal",
                500,
                None,
                r#"{"code":"gateway.internal","message":"the platform could not serve this request","hint":"This is a fault in the platform, not in your request; it has been logged.","retryable":false,"request_id":"req-42"}"#,
            ),
        ];
        for (code, status, retry_after, body) in rows {
            let response = render(&spec(reported(code)), &id);
            assert_eq!(response.status().as_u16(), status, "{code}");
            assert_eq!(
                response
                    .headers()
                    .get(header::RETRY_AFTER)
                    .and_then(|v| v.to_str().ok()),
                retry_after,
                "{code}"
            );
            let text = std::str::from_utf8(response.body()).expect("utf-8");
            assert_eq!(text, body, "{code}");
            assert!(!text.contains(code), "{code} reached the visitor");
        }
    }

    #[test]
    fn a_non_member_is_refused_for_good() {
        let s = spec(Disposition::NotAMember);
        assert_eq!(s.status, StatusCode::FORBIDDEN);
        assert_eq!(s.code, "gateway.not_a_member");
        assert!(!s.retryable, "membership does not change on retry");
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
