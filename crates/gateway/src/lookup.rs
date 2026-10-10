//! Resolving a host to an app against the control plane, with a `moka` cache
//! and an explicit failure posture.
//!
//! The gateway asks the control plane "is `{app}.{org}` a live app?" over the
//! internal route ([`crate::host`] parses the host; this calls the control
//! plane). The answer is cached, because it changes rarely (an app is created,
//! renamed or deleted) and is read on every request.
//!
//! # Failure posture — routing, not authorization
//!
//! Routing decides *where* a request would go; authorization (#12) decides
//! *whether* it may. Those differ, and so do their failure postures:
//!
//! - **Unknown host** → [`Route::Unknown`], a 404. A host the control plane does
//!   not know is not served.
//! - **Control plane unreachable, entry warm** → [`Route::App`] with `stale`,
//!   served from cache. A stale *route* is low-harm: it only says where a
//!   request would go, and #5 serves a placeholder while #11/#12 still gate real
//!   access. Serving it keeps existing apps reachable through a control-plane
//!   blip.
//! - **Control plane unreachable, entry cold** → [`Route::Unavailable`], a 503.
//!   Nothing cached, nothing to confirm the host against: fail closed rather
//!   than invent a route.
//!
//! #12's authorization cache fails closed on a shorter fuse — it *denies* when
//! the control plane is unreachable, and never serves a stale grant, because a
//! stale *whether* is a security exposure where a stale *where* is not.

use std::sync::Arc;
use std::time::{Duration, Instant};

use moka::future::Cache;
use reqwest::StatusCode;
use thiserror::Error;

use crate::host::AppHost;

/// How long a cached answer is trusted, and how long a stale one may still be
/// served when the control plane cannot be reached.
///
/// The [`Default`] values are the production numbers; they are a field rather
/// than a constant so a test can collapse the freshness window to force the
/// stale path, and so they can be tuned from config later without a code change.
#[derive(Debug, Clone, Copy)]
pub struct CacheWindows {
    /// How long a *found* app is trusted before re-confirming. A deleted or
    /// renamed app keeps routing to a placeholder for at most this long; since
    /// #11/#12 gate real access, that is low-harm, so this trades a little
    /// staleness for one control-plane call amortised over the window.
    pub fresh_positive: Duration,
    /// How long a *not-found* answer is trusted. Shorter than `fresh_positive`
    /// because a 404 is the case a user is actively waiting on — a just-created
    /// org or app should become reachable quickly, not after the positive
    /// window.
    pub fresh_negative: Duration,
    /// The longest a *found* answer may be served after its last successful
    /// confirmation while the control plane is unreachable. Long enough to ride
    /// out a control-plane restart or brief partition without dropping all app
    /// routing; short enough that a genuinely removed app stops resolving within
    /// it once the control plane is down and staying down. Enforced by the
    /// cache's own TTL, so an entry cannot outlive it.
    pub stale_bound: Duration,
}

impl Default for CacheWindows {
    fn default() -> Self {
        Self {
            fresh_positive: Duration::from_secs(30),
            fresh_negative: Duration::from_secs(5),
            stale_bound: Duration::from_secs(300),
        }
    }
}

/// The most hosts kept in the cache at once. A bound on memory, not on
/// correctness: an evicted entry is simply looked up again.
const MAX_HOSTS: u64 = 100_000;

/// How long to wait for the control plane to accept a connection, and to answer,
/// before treating it as unreachable. Short: this is on the request path, and a
/// warm cache should serve stale rather than hang on a dead control plane.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

/// What the gateway should do with a request, once its host is resolved.
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use]
pub enum Route {
    /// The host maps to a live app. `stale` is true when this was served from
    /// cache because the control plane was unreachable. #5 serves a placeholder;
    /// #11 will proxy to the app.
    App {
        app_id: String,
        org_id: String,
        stale: bool,
    },
    /// The host is not a live app: answer 404.
    Unknown,
    /// The host could not be resolved and nothing was cached: answer 503.
    Unavailable,
}

/// A resolved answer, as cached.
#[derive(Debug, Clone)]
enum Resolution {
    Found { app_id: String, org_id: String },
    Unknown,
}

impl Resolution {
    fn to_route(&self, stale: bool) -> Route {
        match self {
            Self::Found { app_id, org_id } => Route::App {
                app_id: app_id.clone(),
                org_id: org_id.clone(),
                stale,
            },
            Self::Unknown => Route::Unknown,
        }
    }
}

#[derive(Debug, Clone)]
struct Entry {
    resolution: Resolution,
    fetched_at: Instant,
}

/// The control plane's JSON body for a resolved host.
#[derive(serde::Deserialize)]
struct ResolvedApp {
    app_id: String,
    org_id: String,
}

/// Why a single control-plane fetch did not produce an answer.
#[derive(Debug, Error)]
enum FetchError {
    /// The control plane could not be reached — connection refused or timed out.
    /// This is the error that turns a warm entry stale and a cold one into a 503.
    #[error("the control plane is unreachable")]
    Unreachable,
    /// The control plane answered with an unexpected status.
    #[error("the control plane answered {0}")]
    ControlPlane(StatusCode),
    /// The request or its body failed for some other reason.
    #[error("control-plane request failed: {0}")]
    Transport(#[source] reqwest::Error),
}

/// Errors constructing a [`RouteLookup`].
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum LookupError {
    /// The HTTP client could not be built.
    #[error("building the HTTP client: {0}")]
    Client(#[from] reqwest::Error),
}

/// Resolves hosts to apps against the control plane, caching the answers.
pub struct RouteLookup {
    client: reqwest::Client,
    base: String,
    secret: Arc<str>,
    cache: Cache<AppHost, Entry>,
    windows: CacheWindows,
}

impl RouteLookup {
    /// A lookup against the control plane at `base` (e.g. `http://control-plane:8080`),
    /// presenting `secret` as the internal service credential, with the
    /// production cache windows.
    ///
    /// # Errors
    /// [`LookupError::Client`] if the HTTP client cannot be built.
    pub fn new(base: impl Into<String>, secret: impl Into<Arc<str>>) -> Result<Self, LookupError> {
        Self::with_windows(base, secret, CacheWindows::default())
    }

    /// As [`RouteLookup::new`], with explicit cache windows. For tests that must
    /// force the stale path, and for configuration later.
    ///
    /// # Errors
    /// [`LookupError::Client`] if the HTTP client cannot be built.
    pub fn with_windows(
        base: impl Into<String>,
        secret: impl Into<Arc<str>>,
        windows: CacheWindows,
    ) -> Result<Self, LookupError> {
        let client = reqwest::Client::builder()
            .connect_timeout(CONNECT_TIMEOUT)
            .timeout(REQUEST_TIMEOUT)
            .build()?;
        // The cache TTL is the stale bound: an entry physically cannot be served
        // past it, so the stale path below never exceeds it.
        let cache = Cache::builder()
            .max_capacity(MAX_HOSTS)
            .time_to_live(windows.stale_bound)
            .build();
        Ok(Self {
            client,
            base: base.into(),
            secret: secret.into(),
            cache,
            windows,
        })
    }

    /// Resolve `host` to a [`Route`], consulting the cache and, when it is
    /// missing or stale, the control plane.
    ///
    /// # Cost
    ///
    /// A warm cache hit is **~620 ns in release** (steady state, measured — see
    /// `cache_hit_cost_is_moka_plus_the_result_allocations`). Of that, moka's
    /// concurrent `get` plus the entry clone is ~470 ns, the two id string
    /// allocations ~80 ns, the freshness branch the rest. There is **no
    /// per-request host re-parse** — the host is parsed once, upstream, and this
    /// takes `&AppHost`. This is the hottest path in the system: every request
    /// pays it, and #11/#12 will add to it rather than replace it, so the number
    /// is characterised rather than assumed.
    ///
    /// NB for anyone comparing later: a single-shot `Instant` reading of the
    /// *first* hit after a network lookup reads ~17 µs. That is cold-call and
    /// (in a debug test) build noise — roughly 25× the steady-state figure — not
    /// the baseline. Do not cite it.
    pub async fn resolve(&self, host: &AppHost) -> Route {
        if let Some(entry) = self.cache.get(host).await {
            let fresh = match entry.resolution {
                Resolution::Found { .. } => self.windows.fresh_positive,
                Resolution::Unknown => self.windows.fresh_negative,
            };
            if entry.fetched_at.elapsed() < fresh {
                return entry.resolution.to_route(false);
            }
            // Stale: re-confirm. The cache TTL guarantees this entry is still
            // within the stale bound, so serving it on failure honours the bound.
            return match self.fetch(host).await {
                Ok(resolution) => {
                    self.store(host, resolution.clone()).await;
                    resolution.to_route(false)
                }
                Err(error) => {
                    tracing::warn!(%error, "control-plane re-confirm failed; serving stale route");
                    entry.resolution.to_route(true)
                }
            };
        }

        // Cold: nothing cached. An answer or a 503 — never an invented route.
        match self.fetch(host).await {
            Ok(resolution) => {
                self.store(host, resolution.clone()).await;
                resolution.to_route(false)
            }
            Err(error) => {
                tracing::warn!(%error, "control-plane unreachable on a cold lookup; 503");
                Route::Unavailable
            }
        }
    }

    async fn store(&self, host: &AppHost, resolution: Resolution) {
        self.cache
            .insert(
                host.clone(),
                Entry {
                    resolution,
                    fetched_at: Instant::now(),
                },
            )
            .await;
    }

    async fn fetch(&self, host: &AppHost) -> Result<Resolution, FetchError> {
        let url = format!(
            "{}/internal/orgs/{}/apps/{}",
            self.base,
            host.org.as_str(),
            host.app.as_str()
        );
        let response = self
            .client
            .get(&url)
            .bearer_auth(self.secret.as_ref())
            .send()
            .await
            .map_err(|error| {
                if error.is_connect() || error.is_timeout() {
                    FetchError::Unreachable
                } else {
                    FetchError::Transport(error)
                }
            })?;

        match response.status() {
            StatusCode::OK => {
                let app: ResolvedApp = response.json().await.map_err(FetchError::Transport)?;
                Ok(Resolution::Found {
                    app_id: app.app_id,
                    org_id: app.org_id,
                })
            }
            StatusCode::NOT_FOUND => Ok(Resolution::Unknown),
            other => Err(FetchError::ControlPlane(other)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What the cache-hit path is made of, so the number is understood rather
    /// than assumed. No network: the hit path never touches it, so the cache is
    /// warmed directly and only `resolve`'s hot path is timed. Steady state over
    /// a loop, because a single-shot `Instant` reading is mostly cold-cache and
    /// first-call noise.
    #[tokio::test]
    async fn cache_hit_cost_is_moka_plus_the_result_allocations() {
        let lookup = RouteLookup::new("http://unused.invalid", "secret").expect("lookup");
        let host = crate::host::parse_host("dashboard.acme.clwd-apps.test", "clwd-apps.test")
            .expect("host");
        let missing =
            crate::host::parse_host("ghost.acme.clwd-apps.test", "clwd-apps.test").expect("host");

        // A found entry carries two owned ids (allocations on every clone); an
        // unknown entry carries none. Comparing the two isolates the allocation
        // cost from moka's own machinery.
        lookup
            .store(
                &host,
                Resolution::Found {
                    app_id: "00000000-0000-7000-8000-0000000000a1".to_owned(),
                    org_id: "00000000-0000-7000-8000-0000000000b2".to_owned(),
                },
            )
            .await;
        lookup.store(&missing, Resolution::Unknown).await;

        // Correctness first, outside every timed loop: prove the loops below
        // exercise the hit paths they claim to.
        assert!(matches!(
            lookup.resolve(&host).await,
            Route::App { stale: false, .. }
        ));
        assert_eq!(lookup.resolve(&missing).await, Route::Unknown);

        const N: u32 = 200_000;
        // Warm branch predictor and caches before every measurement.
        for _ in 0..N / 10 {
            let _ = std::hint::black_box(lookup.resolve(&host).await);
        }

        // Full hit, found: moka get (clones the entry) + to_route (clones again).
        let started = Instant::now();
        for _ in 0..N {
            let _ = std::hint::black_box(lookup.resolve(&host).await);
        }
        let found = started.elapsed() / N;

        // Full hit, unknown: moka machinery + branch, no allocation.
        let started = Instant::now();
        for _ in 0..N {
            let _ = std::hint::black_box(lookup.resolve(&missing).await);
        }
        let unknown = started.elapsed() / N;

        // moka get alone (clones the found entry: two allocations).
        let started = Instant::now();
        for _ in 0..N {
            std::hint::black_box(lookup.cache.get(&host).await);
        }
        let get = started.elapsed() / N;

        println!(
            "cache-hit decomposition over {N}: resolve(found)={found:?}, resolve(unknown, no alloc)={unknown:?}, moka get+clone={get:?}; result allocations ~= {:?}",
            found.saturating_sub(unknown)
        );
    }

    #[test]
    fn the_default_windows_are_ordered_negative_lt_positive_lt_stale() {
        // The reasons live on the fields; this pins the relationship the reasons
        // imply, so a careless edit to one number cannot invert it: a 404 is
        // re-checked sooner than a hit, and a hit is re-checked long before its
        // stale bound.
        let w = CacheWindows::default();
        assert!(
            w.fresh_negative < w.fresh_positive,
            "a not-found is re-confirmed sooner than a found app"
        );
        assert!(
            w.fresh_positive < w.stale_bound,
            "an entry is re-confirmed long before it may no longer be served stale"
        );
    }
}
