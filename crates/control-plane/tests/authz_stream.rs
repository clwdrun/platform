//! The invalidation stream outlives the internal router's request timeout
//! (#12). Its own test binary because it takes over 30 seconds: in the authz
//! suite it would make every run of `just authz-soak` that long.

use std::time::{Duration, Instant};

use control_plane::http::AppState;
use control_plane::relay::Relay;
use sqlx::PgPool;

const INTERNAL: &str = "test-internal-secret";

async fn with_relay(pool: &PgPool) -> AppState {
    let relay = Relay::start(pool).await.expect("relay");
    let deadline = Instant::now() + Duration::from_secs(10);
    while !relay.healthy() {
        assert!(Instant::now() < deadline, "the relay never became healthy");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    AppState::new(
        pool.clone(),
        builder::ArtifactStore::new(
            opendal::Operator::new(opendal::services::Memory::default()).expect("memory"),
        ),
    )
    .with_internal_secret(INTERNAL)
    .with_relay(relay)
}

/// The stream is not cut by the internal router's 30-second request timeout:
/// that timeout covers the response future, not its body. Held open past it
/// over a real listener, it is still delivering heartbeats. A timeout layer on
/// the body would end it at 30 s and fail this.
#[sqlx::test(migrations = "../../migrations")]
async fn the_stream_outlives_the_request_timeout(pool: PgPool) {
    let state = with_relay(&pool).await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let router = control_plane::http::internal_router(state);
    tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });
    let mut response = reqwest::Client::new()
        .get(format!("http://127.0.0.1:{port}/internal/authz/stream"))
        .bearer_auth(INTERNAL)
        .send()
        .await
        .expect("stream");
    assert_eq!(response.status(), 200);
    let opened = Instant::now();
    let past = Duration::from_secs(33);
    loop {
        let chunk = response
            .chunk()
            .await
            .expect("still streaming")
            .unwrap_or_else(|| panic!("the stream ended after {:?}", opened.elapsed()));
        let text = String::from_utf8_lossy(&chunk);
        if opened.elapsed() > past && text.contains("heartbeat") {
            break;
        }
    }
}
