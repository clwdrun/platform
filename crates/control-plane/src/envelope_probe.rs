//! Every 4xx and 5xx from every route is an envelope — enumerated and counted.
//!
//! `#2` said every error path returns the envelope. It was true for the paths
//! that had tests. This walks every route in [`routes`] with every method, with
//! and without a valid token, with several bodies and malformed path segments,
//! and counts. A count required to be 0 is a number that cannot quietly become
//! wrong again; a boolean that says "fine" can.
//!
//! # Why the counts can be believed
//!
//! - **It walks every route there is.** `clippy.toml` confines route
//!   registration to the table this reads, and `routes_matched` must equal the
//!   table's length — a route counts as matched only if some request to it got
//!   an answer other than the fallback's, so a table entry the router does not
//!   actually serve fails here.
//! - **It is not blind.** A request with a valid token that is told
//!   `identity.unauthenticated`, a 429, or a timeout on any route but the one
//!   built to time out, would hide whatever lay behind it. Each is counted and
//!   must be 0. The #52 probe revoked its own token partway through and reported
//!   a lower bound as a count; here the revoke route targets a different token.
//! - **It can see a bare response.** The same walk runs against the stack
//!   *without* the conversion layer and must find some — including the planted
//!   bare route. That is a live measurement, so it cannot rot the way a fixture
//!   can.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::num::NonZeroU32;
use std::time::Duration;

use axum::body::Body;
use axum::extract::Request;
use axum::http::{HeaderValue, Method, StatusCode, header};
use sqlx::PgPool;
use tower::ServiceExt as _;

use crate::http::{AppState, BareErrors, build, routes};
use crate::ids::{AppId, OrgId, TokenId};
use crate::token::Scopes;
use crate::{auth, db};

/// The time budget for every route but [`SLOW`]: far longer than any of them
/// needs, so a timeout can only mean a genuine hang and can never blind the
/// probe on a busy machine.
const BUDGET: Duration = Duration::from_secs(10);

/// The budget for [`SLOW`], which exists to time out and should do so quickly.
const SLOW_BUDGET: Duration = Duration::from_millis(50);

/// The one route whose purpose is to time out.
const SLOW: &str = "/v1/slow";

/// The planted bare response the unconverted walk must find — by its exact
/// class, since other methods on the same path produce 405s that would also
/// end in the path.
const PLANTED: &str = "400 GET /v1/bare";

const METHODS: [Method; 7] = [
    Method::GET,
    Method::POST,
    Method::PUT,
    Method::PATCH,
    Method::DELETE,
    Method::OPTIONS,
    Method::HEAD,
];

/// The bodies each request is tried with: empty, broken JSON, not JSON, and a
/// valid bundle.
///
/// The bundle matters for the same reason [`NAMES_NOTHING`] does. Publish
/// validates the bundle before it looks the app up, so without a valid one it
/// always answers `bundle.*` and its `not_found` is never observed — which let a
/// mutation that stopped documenting `not_found` on publish pass.
fn bodies() -> Vec<bytes::Bytes> {
    const PREAMBLE: [u8; 8] = [0x00, 0x61, 0x73, 0x6d, 0x0d, 0x00, 0x01, 0x00];
    let bundle = clwd_bundle::build(
        clwd_bundle::Runtime::Wasm,
        "app.wasm",
        clwd_bundle::Capabilities {
            version: 1,
            egress: vec![],
            secrets: vec![],
            storage_namespaces: vec![],
            limits: clwd_bundle::Limits {
                cpu_ms: 1_000,
                memory_mb: 64,
            },
        },
        vec![clwd_bundle::File {
            path: "app.wasm".into(),
            data: PREAMBLE.to_vec(),
            executable: false,
        }],
    )
    .expect("a well-formed bundle encodes");
    vec![
        bytes::Bytes::new(),
        bytes::Bytes::from_static(b"{"),
        bytes::Bytes::from_static(b"not json"),
        bytes::Bytes::from(bundle.bytes),
    ]
}

/// A well-formed UUID that no fixture uses, so it names nothing.
const NAMES_NOTHING: &str = "00000000-0000-7000-8000-000000000000";

/// What fills a path parameter.
struct Fixture {
    caller: String,
    org: OrgId,
    app: AppId,
    /// The revoke route's target — never the caller's own token.
    target: TokenId,
}

impl Fixture {
    /// A valid value for a named parameter. An unknown name panics: a new
    /// parameter needs a fixture before the probe can claim to cover its route.
    fn valid(&self, param: &str) -> String {
        match param {
            "app_id" => self.app.to_string(),
            "org_id" => self.org.to_string(),
            "token_id" => self.target.to_string(),
            // The fixture app's label (see `db::create_app` below).
            "host_label" => "one".to_owned(),
            // A session route: the probe holds no session cookie, so its
            // same-origin and session layers answer before any claim is read.
            "claim_id" => NAMES_NOTHING.to_owned(),
            "id" => "dashboard".to_owned(),
            // The internal resolution route. Its `require_internal` layer denies
            // the probe's customer token before the handler runs, so these are
            // never resolved — any valid path segment is enough to reach the 401.
            "org" => "acme".to_owned(),
            "app" => "dashboard".to_owned(),
            other => panic!("the envelope probe has no fixture for path parameter {{{other}}}"),
        }
    }
}

/// Every concrete path to try for a route: all-valid, then each parameter in
/// turn replaced with something malformed, and with a well-formed id that names
/// nothing.
///
/// The last one matters. Without it the probe never asks for a resource that
/// does not exist, so a route's `not_found` is never observed — and a mutation
/// that stopped documenting `not_found` on publish went uncaught.
fn paths(template: &str, fixture: &Fixture) -> Vec<String> {
    let segments: Vec<&str> = template.split('/').collect();
    let params: Vec<usize> = segments
        .iter()
        .enumerate()
        .filter(|(_, s)| s.starts_with('{'))
        .map(|(i, _)| i)
        .collect();

    let fill = |bad: Option<(usize, &str)>| -> String {
        segments
            .iter()
            .enumerate()
            .map(
                |(i, s)| match (s.strip_prefix('{').and_then(|s| s.strip_suffix('}')), bad) {
                    (Some(_), Some((at, value))) if at == i => value.to_owned(),
                    (Some(name), _) => fixture.valid(name),
                    (None, _) => (*s).to_owned(),
                },
            )
            .collect::<Vec<_>>()
            .join("/")
    };

    let mut out = vec![fill(None)];
    for &at in &params {
        for bad in ["not-a-uuid", "%ff%fe", NAMES_NOTHING] {
            out.push(fill(Some((at, bad))));
        }
    }
    out
}

#[derive(Default)]
struct Counts {
    routes: usize,
    routes_matched: usize,
    requests: usize,
    errors: usize,
    bare: usize,
    status_disagrees: usize,
    unknown_code: usize,
    allow_missing: usize,
    blinded_unauthenticated: usize,
    rate_limited: usize,
    timed_out_elsewhere: usize,
    bare_by_class: BTreeMap<String, usize>,
    /// Every code seen, by route path.
    codes: BTreeMap<&'static str, BTreeSet<String>>,
}

impl fmt::Display for Counts {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "routes={} matched={} requests={} errors={} bare={} status_disagrees={} \
             unknown_code={} allow_missing={} blinded_401={} rate_limited={} timed_out_elsewhere={}",
            self.routes,
            self.routes_matched,
            self.requests,
            self.errors,
            self.bare,
            self.status_disagrees,
            self.unknown_code,
            self.allow_missing,
            self.blinded_unauthenticated,
            self.rate_limited,
            self.timed_out_elsewhere,
        )
    }
}

/// The status a code declares: owned codes from `shared`'s table, delegated
/// `bundle.*` codes at 400.
fn declared_status(code: &str) -> Option<u16> {
    shared::error::CATALOGUE
        .iter()
        .find(|entry| entry.code == code)
        .map(|entry| entry.status)
        .or_else(|| code.starts_with("bundle.").then_some(400))
}

fn is_envelope(json: &serde_json::Value) -> bool {
    let Some(object) = json.as_object() else {
        return false;
    };
    let mut keys: Vec<&str> = object.keys().map(String::as_str).collect();
    keys.sort_unstable();
    keys == ["code", "hint", "message", "request_id", "retryable"]
}

async fn walk(state: &AppState, bare_errors: BareErrors, fixture: &Fixture) -> Counts {
    let table = routes();
    let mut counts = Counts {
        routes: table.len(),
        ..Counts::default()
    };
    let bearer = format!("Bearer {}", fixture.caller);
    let bodies = bodies();

    for route in &table {
        let mut matched = false;
        for path in paths(route.path, fixture) {
            for method in &METHODS {
                for authenticated in [true, false] {
                    for body in &bodies {
                        let mut request = Request::builder().method(method.clone()).uri(&path);
                        if authenticated {
                            request = request.header(header::AUTHORIZATION, &bearer);
                        }
                        let request = request
                            .body(Body::from(body.clone()))
                            .expect("a valid request");

                        let budget = if route.path == SLOW {
                            SLOW_BUDGET
                        } else {
                            BUDGET
                        };
                        let response = build(
                            state.clone(),
                            budget,
                            bare_errors,
                            crate::http::Listener::All,
                        )
                        .oneshot(request)
                        .await
                        .expect("the router answers");
                        counts.requests += 1;

                        let status = response.status();
                        let is_json = response
                            .headers()
                            .get(header::CONTENT_TYPE)
                            .is_some_and(|v| v == HeaderValue::from_static("application/json"));
                        let has_allow = response.headers().contains_key(header::ALLOW);
                        let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
                            .await
                            .expect("the body reads");
                        let json: serde_json::Value =
                            serde_json::from_slice(&bytes).unwrap_or_default();

                        // Matched means the router served this path with something
                        // other than the fallback. A HEAD response has no body to tell
                        // by, so only other methods count.
                        if *method != Method::HEAD {
                            matched |= json["message"] != "not found: that endpoint";
                        }

                        if status.as_u16() < 400 {
                            continue;
                        }
                        counts.errors += 1;

                        // A HEAD response has no body by definition; its envelope
                        // is the content type. Everything else must parse.
                        let envelope = if *method == Method::HEAD {
                            is_json
                        } else {
                            is_envelope(&json)
                        };

                        if !envelope {
                            counts.bare += 1;
                            *counts
                                .bare_by_class
                                .entry(format!("{} {method} {}", status.as_u16(), route.path))
                                .or_default() += 1;
                        } else if *method != Method::HEAD {
                            let code = json["code"].as_str().unwrap_or_default();
                            counts
                                .codes
                                .entry(route.path)
                                .or_default()
                                .insert(code.to_owned());
                            match declared_status(code) {
                                None => counts.unknown_code += 1,
                                Some(declared) if declared != status.as_u16() => {
                                    counts.status_disagrees += 1;
                                }
                                Some(_) => {}
                            }
                            // The probe's customer token is *meant* to be
                            // refused on an internal route — that route answers
                            // to the platform credential, not a customer token —
                            // so a 401 there is correct, not the probe being
                            // blinded. Exclude it from the blinded count.
                            if authenticated
                                && code == "identity.unauthenticated"
                                && !matches!(route.access, crate::http::Access::Internal)
                            {
                                counts.blinded_unauthenticated += 1;
                            }
                        }

                        if status == StatusCode::METHOD_NOT_ALLOWED && !has_allow {
                            counts.allow_missing += 1;
                        }
                        if status == StatusCode::TOO_MANY_REQUESTS {
                            counts.rate_limited += 1;
                        }
                        if status == StatusCode::GATEWAY_TIMEOUT && route.path != SLOW {
                            counts.timed_out_elsewhere += 1;
                        }
                    }
                }
            }
        }
        counts.routes_matched += usize::from(matched);
    }
    counts
}

#[sqlx::test(migrations = "../../migrations")]
async fn every_error_response_from_every_route_is_an_envelope(pool: PgPool) {
    let org = db::create_org(&pool, "acme").await.expect("org");
    let app = db::create_app(&pool, org.id, "one", "wasm")
        .await
        .expect("app");
    let all = || Scopes::parse_all(["read", "write", "publish", "admin"]).expect("known");
    let caller = auth::issue(&pool, org.id, None, "probe", all())
        .await
        .expect("caller token");
    let target = auth::issue(&pool, org.id, None, "target", all())
        .await
        .expect("target token");
    let fixture = Fixture {
        caller: caller.secret.expose().to_owned(),
        org: org.id,
        app: app.id,
        target: target.id,
    };

    // A quota no walk can reach, so the limiter cannot blind the probe.
    let generous = governor::Quota::per_second(NonZeroU32::MAX);
    let operator =
        opendal::Operator::new(opendal::services::Memory::default()).expect("in-memory operator");
    let state = AppState::with_quota(pool, builder::ArtifactStore::new(operator), generous);

    let unconverted = walk(&state, BareErrors::Leave, &fixture).await;
    let converted = walk(&state, BareErrors::Convert, &fixture).await;

    println!("envelope probe, without conversion: {unconverted}");
    for (class, n) in &unconverted.bare_by_class {
        println!("  bare without conversion: {n:>4} x {class}");
    }
    println!("envelope probe, with conversion:    {converted}");

    for (label, counts) in [("without", &unconverted), ("with", &converted)] {
        assert_eq!(
            counts.routes_matched, counts.routes,
            "{label} conversion: a table route never matched, so the router does not \
             serve the table the probe walked"
        );
        assert!(
            counts.errors > 0,
            "{label} conversion: no errors at all — probed nothing"
        );
        assert_eq!(
            counts.blinded_unauthenticated, 0,
            "{label} conversion: a valid token was refused, hiding what lay behind it"
        );
        assert_eq!(
            counts.rate_limited, 0,
            "{label} conversion: the limiter blinded the probe"
        );
        assert_eq!(
            counts.timed_out_elsewhere, 0,
            "{label} conversion: a route other than {SLOW} timed out, hiding its answer"
        );
    }

    // The positive control: the walk can see a bare response.
    assert!(
        unconverted.bare > 0,
        "positive control: without conversion the probe found no bare response, so a \
         zero below would mean nothing"
    );
    assert!(
        unconverted.bare_by_class.contains_key(PLANTED),
        "positive control: the planted bare response at {PLANTED} was not found"
    );

    // The property.
    assert_eq!(
        converted.bare, 0,
        "bare error responses remain: {:#?}",
        converted.bare_by_class
    );
    assert_eq!(
        converted.status_disagrees, 0,
        "an envelope's status is not its code's"
    );
    assert_eq!(
        converted.unknown_code, 0,
        "an envelope carries a code nobody declared"
    );
    assert_eq!(
        converted.allow_missing, 0,
        "a 405 without the Allow header HTTP requires"
    );

    // Every code a production route was seen to produce is one the OpenAPI
    // document lists for that route. The reverse — a documented code never
    // produced — cannot be checked here: `internal` and `timeout` cannot be
    // provoked on a real route.
    let mut pairs = 0;
    let mut undocumented = Vec::new();
    for route in routes() {
        let Some(documented) = crate::openapi::documented_codes(&route) else {
            continue;
        };
        for code in converted.codes.get(route.path).into_iter().flatten() {
            pairs += 1;
            if !crate::openapi::covers(&documented, code) {
                undocumented.push(format!("{} {}: {code}", route.verb.method(), route.path));
            }
        }
    }
    println!(
        "envelope probe, codes seen on production routes: {pairs} (route, code) pairs, {} undocumented",
        undocumented.len()
    );
    assert!(
        pairs > 0,
        "the probe saw no codes on production routes, so this checked nothing"
    );
    assert!(
        undocumented.is_empty(),
        "codes a route produces that the OpenAPI document does not list for it: {undocumented:#?}"
    );
}

/// `clippy.toml` is what makes the route table complete, and deleting an entry
/// is how that would be defeated quietly. Deleting the file fails this at
/// compile time.
#[test]
fn clippy_still_confines_route_registration_to_the_table() {
    let config = include_str!("../../../clippy.toml");
    for method in [
        "route",
        "route_service",
        "nest",
        "nest_service",
        "merge",
        "fallback",
        "fallback_service",
        "method_not_allowed_fallback",
    ] {
        let path = format!("\"axum::routing::Router::{method}\"");
        assert!(
            config.contains(&path),
            "clippy.toml no longer disallows {path}, so a route could be registered \
             outside the table the envelope probe walks"
        );
    }
}
