//! The gateway's route lookup against a real control-plane-shaped server: the
//! cache, the failure posture, and the cost of each path.
//!
//! "Control plane unreachable" is proven by actually closing the port — a
//! graceful shutdown that drops the listener, or a port bound and released — so
//! the real connection handling, timeout and fallback all run. A mocked `Err`
//! would exercise only the match arm.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use axum::Json;
use axum::Router;
use axum::extract::Path;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::get;
use gateway::host::parse_host;
use gateway::lookup::{CacheWindows, Route, RouteLookup};
use tokio::net::TcpListener;
use tokio::sync::oneshot;

const SECRET: &str = "internal-secret";
const APEX: &str = "clwd-apps.test";
const APP_ID: &str = "00000000-0000-7000-8000-0000000000a1";
const ORG_ID: &str = "00000000-0000-7000-8000-0000000000b2";

/// The stand-in control plane: 200 with ids for the one known host, 404 for the
/// rest — the two responses the real internal route produces.
async fn resolver(Path((org, app)): Path<(String, String)>) -> axum::response::Response {
    if org == "acme" && app == "dashboard" {
        Json(serde_json::json!({ "app_id": APP_ID, "org_id": ORG_ID })).into_response()
    } else {
        StatusCode::NOT_FOUND.into_response()
    }
}

/// Start the server. Awaiting the returned handle after sending on the channel
/// guarantees the listener is dropped and the port closed — a deterministic
/// shutdown, no sleep.
async fn start_server() -> (SocketAddr, oneshot::Sender<()>, tokio::task::JoinHandle<()>) {
    // The workspace lint forbids `Router::route` so the control-plane's route
    // table stays the only way into *its* router. This is a throwaway test
    // server in another crate, not that router; `#[expect]` (not `#[allow]`)
    // documents the exception and fails if it ever stops applying.
    #[expect(
        clippy::disallowed_methods,
        reason = "test stand-in control plane, not the guarded control-plane router"
    )]
    let app = Router::new().route("/internal/orgs/{org}/apps/{app}", get(resolver));
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let (tx, rx) = oneshot::channel();
    let handle = tokio::spawn(async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(async {
                let _ = rx.await;
            })
            .await
            .expect("serve");
    });
    (addr, tx, handle)
}

/// A port bound and immediately released: nothing listens on it, so a connection
/// is refused deterministically.
async fn closed_port() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    drop(listener);
    addr
}

#[tokio::test]
async fn a_second_lookup_is_a_fresh_cache_hit_and_cheaper_than_a_round_trip() {
    let (addr, shutdown, handle) = start_server().await;
    let lookup = RouteLookup::new(format!("http://{addr}"), SECRET).expect("lookup");
    let host = parse_host("dashboard.acme.clwd-apps.test", APEX).expect("host");

    // Miss: a real HTTP round trip to the control plane.
    let started = Instant::now();
    let first = lookup.resolve(&host).await;
    let miss = started.elapsed();
    assert!(
        matches!(first, Route::App { stale: false, .. }),
        "{first:?}"
    );

    // Hit: served from cache, no HTTP.
    let started = Instant::now();
    let second = lookup.resolve(&host).await;
    let hit = started.elapsed();
    assert_eq!(first, second);
    assert!(matches!(second, Route::App { stale: false, .. }));

    // Single-shot readings: the hit here is the FIRST post-lookup hit, so it
    // carries cold-call cost and reads far above steady state (~17 µs vs the
    // ~620 ns release baseline). This asserts only hit < miss, the ordering that
    // must always hold; the real per-hit number is characterised in the lib test
    // `cache_hit_cost_is_moka_plus_the_result_allocations`.
    println!("route lookup: miss (control-plane round trip) {miss:?}, hit (cache) {hit:?}");
    assert!(
        hit < miss,
        "a cache hit ({hit:?}) must be cheaper than a control-plane round trip ({miss:?})"
    );

    let _ = shutdown.send(());
    handle.await.expect("server task");
}

#[tokio::test]
async fn an_unknown_host_is_unknown() {
    let (addr, shutdown, handle) = start_server().await;
    let lookup = RouteLookup::new(format!("http://{addr}"), SECRET).expect("lookup");
    let host = parse_host("ghost.acme.clwd-apps.test", APEX).expect("host");

    assert_eq!(lookup.resolve(&host).await, Route::Unknown);

    let _ = shutdown.send(());
    handle.await.expect("server task");
}

#[tokio::test]
async fn a_warm_route_is_served_stale_when_the_control_plane_goes_down() {
    let (addr, shutdown, handle) = start_server().await;
    // fresh_positive = 0 makes the entry stale the instant it is fetched, so the
    // next lookup takes the re-confirm path with no 30-second wait; the stale
    // bound stays long, so the entry is still within it.
    let windows = CacheWindows {
        fresh_positive: Duration::ZERO,
        ..CacheWindows::default()
    };
    let lookup =
        RouteLookup::with_windows(format!("http://{addr}"), SECRET, windows).expect("lookup");
    let host = parse_host("dashboard.acme.clwd-apps.test", APEX).expect("host");

    // Warm the cache with a REAL lookup — a full HTTP round trip that stores the
    // entry in the form the stale path reads, not a direct cache insert.
    let warmed = lookup.resolve(&host).await;
    assert!(
        matches!(warmed, Route::App { stale: false, .. }),
        "{warmed:?}"
    );

    // Take the control plane down for real: the port is closed once the server
    // task has finished.
    let _ = shutdown.send(());
    handle.await.expect("server task");

    // Stale entry + unreachable control plane: the warmed route is served,
    // marked stale.
    match lookup.resolve(&host).await {
        Route::App {
            stale: true,
            app_id,
            org_id,
        } => {
            assert_eq!(app_id, APP_ID);
            assert_eq!(org_id, ORG_ID);
        }
        other => panic!("expected a stale app route, got {other:?}"),
    }
}

#[tokio::test]
async fn a_cold_lookup_with_the_control_plane_down_is_unavailable() {
    let addr = closed_port().await;
    let lookup = RouteLookup::new(format!("http://{addr}"), SECRET).expect("lookup");
    let host = parse_host("dashboard.acme.clwd-apps.test", APEX).expect("host");

    let started = Instant::now();
    let outcome = lookup.resolve(&host).await;
    println!(
        "cold miss, control plane down: {outcome:?} in {:?}",
        started.elapsed()
    );
    assert_eq!(outcome, Route::Unavailable);
}
