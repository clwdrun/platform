//! Token values never appear in logs or traces.
//!
//! # How this avoids passing vacuously
//!
//! A test that greps captured logs for a token and finds nothing passes just as
//! well when issuance is broken, when no request ran, or when the subscriber
//! was never connected. So absence is asserted only after three positive
//! controls, each of which fails in one of those worlds:
//!
//! 1. **The token is retrievable where it should be.** Issuance returned it,
//!    and the database holds SHA-256 of exactly that string.
//! 2. **The requests really ran.** Each one got the status it should have —
//!    success, forbidden, revoked — so the paths that might log a credential
//!    were all exercised, including the failure paths.
//! 3. **The capture saw them.** The log contains the URI of the revoke
//!    request, which embeds the revoked token's id. An unconnected subscriber,
//!    or one filtering at the wrong level, fails here.
//!
//! One test in its own binary, because it installs a global subscriber.
//!
//! # What it greps for
//!
//! Every token's full text *and* its secret part without the prefix, so a
//! leak that strips or splits the prefix is still caught. At `TRACE`, with span
//! open and close events, so everything `tower-http` and `sqlx` emit is in
//! scope.

use std::io;
use std::sync::{Arc, Mutex};

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use control_plane::http::AppState;
use control_plane::token::{PREFIX, Scopes};
use control_plane::{auth, db};
use sha2::{Digest as _, Sha256};
use sqlx::PgPool;
use tower::ServiceExt as _;
use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::fmt::format::FmtSpan;

/// Every byte the subscriber writes.
#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<u8>>>);

impl io::Write for Capture {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0
            .lock()
            .map_err(|_| io::Error::other("capture poisoned"))?
            .extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for Capture {
    type Writer = Self;

    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

impl Capture {
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.0.lock().expect("capture poisoned")).into_owned()
    }
}

async fn send(
    state: &AppState,
    method: &str,
    uri: &str,
    token: &str,
    body: Body,
) -> (StatusCode, serde_json::Value) {
    let request = Request::builder()
        .method(method)
        .uri(uri)
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(body)
        .expect("a valid request");
    let response = control_plane::http::router(state.clone())
        .oneshot(request)
        .await
        .expect("the router answers");
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .expect("body");
    (status, serde_json::from_slice(&bytes).unwrap_or_default())
}

fn a_bundle() -> Body {
    const PREAMBLE: [u8; 8] = [0x00, 0x61, 0x73, 0x6d, 0x0d, 0x00, 0x01, 0x00];
    let encoded = clwd_bundle::build(
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
    Body::from(encoded.bytes)
}

#[sqlx::test(migrations = "../../migrations")]
async fn token_values_never_reach_the_logs(pool: PgPool) {
    let capture = Capture::default();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(capture.clone())
        .with_max_level(tracing::Level::TRACE)
        .with_span_events(FmtSpan::FULL)
        .with_ansi(false)
        .finish();
    tracing::subscriber::set_global_default(subscriber)
        .expect("the only subscriber in this binary");

    let operator =
        opendal::Operator::new(opendal::services::Memory::default()).expect("in-memory operator");
    let state = AppState::new(pool.clone(), builder::ArtifactStore::new(operator));

    let org = db::create_org(&pool, "acme").await.expect("org");
    let app = db::create_app(&pool, org.id, "one", "wasm")
        .await
        .expect("app");

    // The bootstrap path.
    let admin = auth::issue(
        &pool,
        org.id,
        None,
        "admin",
        Scopes::parse_all(["admin", "publish"]).expect("known"),
    )
    .await
    .expect("bootstrap issuance");
    let admin_token = admin.secret.expose().to_owned();

    // The HTTP path.
    let (status, issued) = send(
        &state,
        "POST",
        &format!("/v1/orgs/{}/tokens", org.id),
        &admin_token,
        Body::from(r#"{"name":"ci","scopes":["publish"]}"#),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{issued}");

    // Control 1: the token is retrievable where it should be.
    let publisher = issued["token"]
        .as_str()
        .expect("issuance returned a token")
        .to_owned();
    let publisher_id = issued["id"].as_str().expect("and an id").to_owned();
    let stored: Vec<u8> = sqlx::query_scalar!(
        "select secret_sha256 from api_tokens where id = $1::text::uuid",
        publisher_id
    )
    .fetch_one(&pool)
    .await
    .expect("the issued token has a row");
    assert_eq!(
        stored,
        Sha256::digest(publisher.as_bytes()).to_vec(),
        "control 1: the database holds the digest of exactly this token"
    );

    // Control 2: every path that might log a credential runs, and does what it should.
    let (status, body) = send(
        &state,
        "POST",
        &format!("/v1/apps/{}/versions", app.id),
        &publisher,
        a_bundle(),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "publish succeeds: {body}");

    let (status, _) = send(
        &state,
        "DELETE",
        &format!("/v1/tokens/{}", admin.id),
        &publisher,
        Body::empty(),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "publish may not administer");

    let revoke_uri = format!("/v1/tokens/{publisher_id}");
    let (status, _) = send(&state, "DELETE", &revoke_uri, &admin_token, Body::empty()).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "revocation succeeds");

    let (status, _) = send(
        &state,
        "POST",
        &format!("/v1/apps/{}/versions", app.id),
        &publisher,
        a_bundle(),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "the revoked token is refused"
    );

    let logs = capture.text();

    // Control 3: the capture saw these requests.
    assert!(
        logs.contains(&revoke_uri),
        "control 3: the log capture did not see the revoke request, so an empty grep \
         would prove nothing. Captured {} bytes.",
        logs.len()
    );

    // Now, and only now, absence means something.
    for (name, token) in [("admin", &admin_token), ("publisher", &publisher)] {
        let secret = &token[PREFIX.len()..];
        assert!(
            !logs.contains(token.as_str()),
            "the {name} token appears in the logs"
        );
        assert!(
            !logs.contains(secret),
            "the {name} token's secret part appears in the logs"
        );
    }
}
