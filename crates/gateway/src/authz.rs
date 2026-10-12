//! The gateway's authorization cache (#12), and the invalidation stream that
//! keeps it honest.
//!
//! A cache hit costs no I/O: an in-memory lookup and a check of local state.
//! Only allow decisions are cached. Every entry records the stream position it
//! reflects (`as_of`, read by the control plane in the same snapshot as the
//! decision) and the [`Tag`]s it was derived from, and is checked again
//! **when read**: it is served only if
//!
//! - the stream is up and the lease is live (a hung or partitioned gateway
//!   stops serving from cache within [`LEASE`], measured on `CLOCK_BOOTTIME`,
//!   which keeps counting while the machine is suspended),
//! - its sessions have not expired and it is younger than [`MAX_AGE`],
//! - no flush happened at a position after the one it reflects, and
//! - no invalidation of any of its tags is numbered after the one it reflects.
//!
//! The last two are checked on read, not at insert, because moka's
//! invalidation only covers entries already present: a load that read the
//! database before an invalidation can insert its result after it. Checking
//! on read makes that race harmless whatever order the insert lands in.
//!
//! Anything doubtful (a gap in the sequence, a reconnect, a silent stream, a
//! poisoned lock, a failed clock) falls back to the uncached check, never to
//! the cache. `docs/decisions/0003-authorization-cache.md` states the contract.

use std::collections::HashMap;
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use moka::future::Cache;
use sha2::{Digest as _, Sha256};
use shared::authz::{Ack, LEASE, MAX_AGE, Message, Seq, Tag};
use shared::hop::AppId;
use uuid::Uuid;

use crate::signin::{AppSession, Checked, SigninClient, Unreachable};

/// The cache's weight ceiling, in bytes as the weigher counts them.
pub const MAX_WEIGHT: u64 = 64 * 1024 * 1024;

/// What one entry weighs, before its email: key, ids, tags, deadlines and
/// their allocations, rounded up.
const ENTRY_WEIGHT: u32 = 512;

/// The longest line the stream may send. An event naming more tags than fits
/// is sent as a flush.
const MAX_LINE: usize = 256 * 1024;

/// A clock for the lease and for entry deadlines.
pub trait Clock: Send + Sync + 'static {
    /// Time since some fixed point, advancing during suspend.
    fn now(&self) -> Duration;
}

/// `CLOCK_BOOTTIME`. `std::time::Instant` is `CLOCK_MONOTONIC` on Linux
/// (`library/std/src/sys/time/unix.rs`, Rust 1.97), which stops while the
/// machine is suspended: a gateway frozen past its lease would wake believing
/// the lease live and serve a stale allow. Wall-clock time is never used.
#[derive(Debug, Clone, Copy, Default)]
pub struct BootClock;

/// The clock [`BootClock`] reads. Pinned by a test.
pub const LEASE_CLOCK: libc::clockid_t = libc::CLOCK_BOOTTIME;

impl Clock for BootClock {
    fn now(&self) -> Duration {
        let mut ts = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        // SAFETY: `ts` is a valid, writable timespec for the call's duration.
        let rc = unsafe { libc::clock_gettime(LEASE_CLOCK, &raw mut ts) };
        match (rc, u64::try_from(ts.tv_sec), u32::try_from(ts.tv_nsec)) {
            (0, Ok(secs), Ok(nanos)) => Duration::new(secs, nanos),
            // Fail closed: at the end of time every lease and entry is expired.
            _ => Duration::MAX,
        }
    }
}

/// The uncached decision: the control plane's per-request check.
#[async_trait::async_trait]
pub trait Check: Send + Sync + 'static {
    async fn check(
        &self,
        session: &AppSession,
        app_id: &str,
    ) -> Result<Option<Checked>, Unreachable>;
}

#[async_trait::async_trait]
impl Check for SigninClient {
    async fn check(
        &self,
        session: &AppSession,
        app_id: &str,
    ) -> Result<Option<Checked>, Unreachable> {
        SigninClient::check(self, session, app_id).await
    }
}

/// The SHA-256 of an app-host session secret: what the cache is keyed on, so a
/// memory dump of the gateway yields no usable session.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct AppSessionDigest([u8; 32]);

impl AppSessionDigest {
    #[must_use]
    pub fn of(session: &AppSession) -> Self {
        Self(Sha256::digest(session.expose().as_bytes()).into())
    }
}

impl fmt::Debug for AppSessionDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AppSessionDigest(..)")
    }
}

/// One decision's identity: this session, for this app.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct Key {
    app_id: AppId,
    session: AppSessionDigest,
}

/// A cached allow. `Debug` redacts the email (via [`shared::hop::Caller`]).
#[derive(Debug)]
struct Entry {
    checked: Checked,
    /// The stream position the decision reflects ([`Checked::as_of`]).
    loaded_at: Seq,
    /// When it stops being served, on [`Clock`].
    deadline: Duration,
}

/// Why a load produced nothing to cache. Coalesced loads share it.
#[derive(Debug)]
enum NotCached {
    Denied(Checked),
    NoSession,
    Unreachable(Unreachable),
}

#[derive(Debug)]
struct State {
    /// A stream is connected and has said hello.
    live: bool,
    applied: Seq,
    /// Nothing loaded before this position is served.
    floor: Seq,
    /// Cache hits stop at this time on [`Clock`] unless renewed.
    lease_until: Duration,
    /// When each tag was last invalidated: the position, and the clock time
    /// (for pruning after [`MAX_AGE`]).
    invalidated: HashMap<Tag, (Seq, Duration)>,
}

/// Counters. Exported as metrics once there is a metrics path.
#[derive(Debug, Default)]
pub struct Stats {
    pub hits: AtomicU64,
    pub loads: AtomicU64,
    /// Requests that took the uncached check, by reason below.
    pub bypassed: AtomicU64,
    /// No stream is live: before the first hello, or since one ended.
    pub bypass_not_live: AtomicU64,
    /// The stream is up but the lease lapsed: renewals stopped succeeding.
    pub bypass_lease_lapsed: AtomicU64,
    /// The state lock was poisoned by a panic.
    pub bypass_poisoned: AtomicU64,
    /// A load finished but was stale by the time it landed.
    pub bypass_stale_load: AtomicU64,
    /// Cache flushes, by reason below.
    pub flushes: AtomicU64,
    pub flush_hello: AtomicU64,
    pub flush_gap: AtomicU64,
    pub flush_heartbeat_ahead: AtomicU64,
    pub flush_event: AtomicU64,
    pub flush_disconnect: AtomicU64,
    /// Streams that ended, counted by the follower before it tells the cache,
    /// by reason below.
    pub disconnects: AtomicU64,
    pub ended_silent: AtomicU64,
    pub ended_closed: AtomicU64,
    pub ended_error: AtomicU64,
    /// Lease renewals: granted, refused (the relay is unhealthy, for example
    /// a trigger check failed), or not delivered at all.
    pub renewals: AtomicU64,
    pub renewals_refused: AtomicU64,
    pub renewals_failed: AtomicU64,
}

impl Stats {
    /// Every counter, by name, for logs and probes.
    #[must_use]
    pub fn snapshot(&self) -> Vec<(&'static str, u64)> {
        let get = |c: &AtomicU64| c.load(Ordering::Relaxed);
        vec![
            ("hits", get(&self.hits)),
            ("loads", get(&self.loads)),
            ("bypassed", get(&self.bypassed)),
            ("bypass_not_live", get(&self.bypass_not_live)),
            ("bypass_lease_lapsed", get(&self.bypass_lease_lapsed)),
            ("bypass_poisoned", get(&self.bypass_poisoned)),
            ("bypass_stale_load", get(&self.bypass_stale_load)),
            ("flushes", get(&self.flushes)),
            ("flush_hello", get(&self.flush_hello)),
            ("flush_gap", get(&self.flush_gap)),
            ("flush_heartbeat_ahead", get(&self.flush_heartbeat_ahead)),
            ("flush_event", get(&self.flush_event)),
            ("flush_disconnect", get(&self.flush_disconnect)),
            ("disconnects", get(&self.disconnects)),
            ("ended_silent", get(&self.ended_silent)),
            ("ended_closed", get(&self.ended_closed)),
            ("ended_error", get(&self.ended_error)),
            ("renewals", get(&self.renewals)),
            ("renewals_refused", get(&self.renewals_refused)),
            ("renewals_failed", get(&self.renewals_failed)),
        ]
    }
}

/// Why a request could not use the cache.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Bypass {
    NotLive,
    LeaseLapsed,
    Poisoned,
}

/// Why the cache was flushed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Flush {
    Hello,
    Gap,
    HeartbeatAhead,
    Event,
    Disconnect,
}

/// The authorization cache and its stream state.
pub struct Authz {
    cache: Cache<Key, Arc<Entry>>,
    state: Mutex<State>,
    check: Arc<dyn Check>,
    clock: Arc<dyn Clock>,
    stats: Stats,
    /// Whether the last request could use the cache: a change is logged.
    was_caching: std::sync::atomic::AtomicBool,
}

impl fmt::Debug for Authz {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Authz")
            .field("entries", &self.cache.entry_count())
            .finish_non_exhaustive()
    }
}

impl Authz {
    /// A cache in front of `check`, on `CLOCK_BOOTTIME`. It starts in bypass,
    /// and stays there until a stream says hello and a lease is granted.
    #[must_use]
    pub fn new(check: Arc<dyn Check>) -> Self {
        Self::with_clock(check, Arc::new(BootClock))
    }

    #[must_use]
    pub fn with_clock(check: Arc<dyn Check>, clock: Arc<dyn Clock>) -> Self {
        let cache = Cache::builder()
            .max_capacity(MAX_WEIGHT)
            .weigher(|_: &Key, entry: &Arc<Entry>| {
                let email = entry.checked.caller.email.as_ref().map_or(0, String::len);
                ENTRY_WEIGHT.saturating_add(u32::try_from(email).unwrap_or(u32::MAX))
            })
            // The backstop. Per-entry deadlines are checked on read as well.
            .time_to_live(MAX_AGE)
            .build();
        Self {
            cache,
            state: Mutex::new(State {
                live: false,
                applied: Seq::ZERO,
                floor: Seq::ZERO,
                lease_until: Duration::ZERO,
                invalidated: HashMap::new(),
            }),
            check,
            clock,
            stats: Stats::default(),
            was_caching: std::sync::atomic::AtomicBool::new(false),
        }
    }

    /// The decision for `session` on `app_id`: from the cache when it may be
    /// trusted, otherwise from the control plane.
    ///
    /// # Errors
    ///
    /// [`Unreachable`] when the control plane could not be asked: the caller
    /// fails closed.
    pub async fn authorize(
        &self,
        session: &AppSession,
        app_id: &str,
    ) -> Result<Option<Checked>, Unreachable> {
        match self.caching() {
            Ok(()) => {
                if !self.was_caching.swap(true, Ordering::Relaxed) {
                    tracing::info!("authorization cache live");
                }
            }
            Err(reason) => {
                self.stats.bypassed.fetch_add(1, Ordering::Relaxed);
                let counter = match reason {
                    Bypass::NotLive => &self.stats.bypass_not_live,
                    Bypass::LeaseLapsed => &self.stats.bypass_lease_lapsed,
                    Bypass::Poisoned => &self.stats.bypass_poisoned,
                };
                counter.fetch_add(1, Ordering::Relaxed);
                if self.was_caching.swap(false, Ordering::Relaxed) {
                    tracing::warn!(?reason, "authorization cache bypassed");
                }
                return self.check.check(session, app_id).await;
            }
        }
        // The key and the load come from the same session and app, in one
        // place: a load can only ever answer its own key.
        let (key, load) = self.keyed_load(session, app_id);
        if let Some(entry) = self.cache.get(&key).await {
            if self.valid(&entry) {
                self.stats.hits.fetch_add(1, Ordering::Relaxed);
                return Ok(Some(entry.checked.clone()));
            }
            self.cache.invalidate(&key).await;
        }
        match self.cache.try_get_with(key.clone(), load).await {
            Ok(entry) if self.valid(&entry) => Ok(Some(entry.checked.clone())),
            // Loaded across an invalidation, or the stream dropped meanwhile:
            // never served. Ask again, uncached.
            Ok(_) => {
                self.cache.invalidate(&key).await;
                self.stats.bypassed.fetch_add(1, Ordering::Relaxed);
                self.stats.bypass_stale_load.fetch_add(1, Ordering::Relaxed);
                self.check.check(session, app_id).await
            }
            Err(not_cached) => match &*not_cached {
                NotCached::Denied(checked) => Ok(Some(checked.clone())),
                NotCached::NoSession => Ok(None),
                NotCached::Unreachable(error) => Err(error.clone()),
            },
        }
    }

    fn keyed_load(
        &self,
        session: &AppSession,
        app_id: &str,
    ) -> (
        Key,
        impl Future<Output = Result<Arc<Entry>, NotCached>> + use<'_>,
    ) {
        let key = Key {
            app_id: AppId::new(app_id),
            session: AppSessionDigest::of(session),
        };
        let (session, app_id) = (session.clone(), app_id.to_owned());
        let load = async move {
            self.stats.loads.fetch_add(1, Ordering::Relaxed);
            let began = self.clock.now();
            match self.check.check(&session, &app_id).await {
                Ok(Some(checked)) if checked.decision.is_allow() => Ok(Arc::new(Entry {
                    deadline: began.saturating_add(checked.ttl.min(MAX_AGE)),
                    loaded_at: checked.as_of,
                    checked,
                })),
                Ok(Some(checked)) => Err(NotCached::Denied(checked)),
                Ok(None) => Err(NotCached::NoSession),
                Err(error) => Err(NotCached::Unreachable(error)),
            }
        };
        (key, load)
    }

    /// The lock, or `None` if a panic poisoned it: then nothing is cached.
    fn state(&self) -> Option<MutexGuard<'_, State>> {
        self.state.lock().ok()
    }

    /// Whether the cache may be used at all right now, and if not, why.
    fn caching(&self) -> Result<(), Bypass> {
        let now = self.clock.now();
        let state = self.state().ok_or(Bypass::Poisoned)?;
        if !state.live {
            return Err(Bypass::NotLive);
        }
        if now >= state.lease_until {
            return Err(Bypass::LeaseLapsed);
        }
        Ok(())
    }

    /// Whether `entry` may be served now. Checked on every read.
    ///
    /// The boundary: valid iff, for every tag, `invalidated[tag] <= loaded_at`.
    /// An invalidation numbered `loaded_at` was committed in or before the
    /// snapshot the decision was read in, so the decision already reflects
    /// it; one numbered `loaded_at + 1` was not, so the entry is stale.
    fn valid(&self, entry: &Entry) -> bool {
        let now = self.clock.now();
        let Some(state) = self.state() else {
            return false;
        };
        state.live
            && now < state.lease_until
            && now < entry.deadline
            && entry.loaded_at >= state.floor
            && entry.checked.tags.iter().all(|tag| {
                state
                    .invalidated
                    .get(tag)
                    .is_none_or(|(seq, _)| *seq <= entry.loaded_at)
            })
    }

    /// The stream and lease state, for logs and test diagnostics: whether the
    /// cache may be used and if not why, the position applied, and how long
    /// the lease has left (negative once lapsed).
    #[must_use]
    pub fn describe(&self) -> String {
        let now = self.clock.now();
        let caching = self.caching();
        match self.state() {
            Some(state) => {
                let left = if state.lease_until >= now {
                    format!("{}ms", (state.lease_until - now).as_millis())
                } else {
                    format!("-{}ms", (now - state.lease_until).as_millis())
                };
                format!(
                    "caching={caching:?} live={} applied={} floor={} lease_left={left}",
                    state.live, state.applied, state.floor
                )
            }
            None => format!("caching={caching:?} state=poisoned"),
        }
    }

    /// Whether a request now could be answered from the cache.
    #[must_use]
    pub fn is_caching(&self) -> bool {
        self.caching().is_ok()
    }

    /// The last stream position applied.
    #[must_use]
    pub fn applied(&self) -> Seq {
        self.state().map_or(Seq::ZERO, |state| state.applied)
    }

    #[must_use]
    pub fn stats(&self) -> &Stats {
        &self.stats
    }

    /// The lease clock, for timing a renewal from when it was sent.
    #[must_use]
    pub fn now(&self) -> Duration {
        self.clock.now()
    }

    /// Apply one stream message, in order.
    pub fn apply(&self, message: &Message) {
        let now = self.clock.now();
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match message {
            Message::Hello { seq } => {
                self.flush(&mut state, *seq, Flush::Hello);
                state.live = true;
            }
            Message::Event { seq, flush, tags } => {
                if *seq <= state.applied {
                    return;
                }
                if *flush || *seq != state.applied.next() {
                    // A gap: something was missed, so nothing loaded before
                    // here can be trusted. History is never replayed.
                    let reason = if *flush { Flush::Event } else { Flush::Gap };
                    self.flush(&mut state, *seq, reason);
                } else {
                    for tag in tags {
                        state.invalidated.insert(*tag, (*seq, now));
                    }
                    state.applied = *seq;
                }
            }
            Message::Heartbeat { seq } => {
                if *seq > state.applied {
                    self.flush(&mut state, *seq, Flush::HeartbeatAhead);
                }
                // An invalidation older than MAX_AGE outlived every entry it
                // could apply to.
                state
                    .invalidated
                    .retain(|_, (_, at)| now.saturating_sub(*at) <= MAX_AGE);
            }
        }
    }

    fn flush(&self, state: &mut State, seq: Seq, reason: Flush) {
        state.floor = seq;
        state.applied = seq;
        state.invalidated.clear();
        self.cache.invalidate_all();
        self.stats.flushes.fetch_add(1, Ordering::Relaxed);
        let counter = match reason {
            Flush::Hello => &self.stats.flush_hello,
            Flush::Gap => &self.stats.flush_gap,
            Flush::HeartbeatAhead => &self.stats.flush_heartbeat_ahead,
            Flush::Event => &self.stats.flush_event,
            Flush::Disconnect => &self.stats.flush_disconnect,
        };
        counter.fetch_add(1, Ordering::Relaxed);
        if !matches!(reason, Flush::Hello | Flush::Event) {
            tracing::warn!(?reason, %seq, "authorization cache flushed");
        }
    }

    /// The control plane renewed the lease, for a renewal sent at `sent_at`
    /// on [`Clock`]. Counting from the send keeps this side's lease shorter
    /// than the control plane's record of it.
    pub fn renewed(&self, sent_at: Duration) {
        if let Some(mut state) = self.state() {
            state.lease_until = state.lease_until.max(sent_at.saturating_add(LEASE));
        }
    }

    /// The stream ended: stop caching until a new one says hello.
    pub fn disconnected(&self) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.live = false;
        let applied = state.applied;
        self.flush(&mut state, applied, Flush::Disconnect);
    }
}

/// Follow the control plane's invalidation stream for ever: apply each
/// message, acknowledge it, and reconnect after any failure. While
/// disconnected the gateway is in bypass.
pub async fn follow(authz: Arc<Authz>, base: String, secret: Arc<str>, gateway: Uuid) {
    let client = match reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(2))
        .redirect(reqwest::redirect::Policy::none())
        .build()
    {
        Ok(client) => client,
        Err(error) => {
            tracing::error!(%error, "cannot build the invalidation client; staying in bypass");
            return;
        }
    };
    loop {
        let ended = follow_once(&authz, &client, &base, &secret, gateway).await;
        let (counter, why) = match &ended {
            Ended::Silent => (&authz.stats.ended_silent, "silent past the lease"),
            Ended::Closed => (&authz.stats.ended_closed, "closed by the control plane"),
            Ended::Error(error) => (&authz.stats.ended_error, error.as_str()),
        };
        counter.fetch_add(1, Ordering::Relaxed);
        tracing::warn!(why, "invalidation stream ended; bypassing the cache");
        authz.stats.disconnects.fetch_add(1, Ordering::Relaxed);
        authz.disconnected();
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

/// Why a stream ended.
#[derive(Debug)]
enum Ended {
    /// Nothing arrived within the lease, though the connection was open.
    Silent,
    /// The control plane closed it.
    Closed,
    /// It could not be opened, broke, or sent something unreadable.
    Error(String),
}

async fn follow_once(
    authz: &Authz,
    client: &reqwest::Client,
    base: &str,
    secret: &str,
    gateway: Uuid,
) -> Ended {
    match stream(authz, client, base, secret, gateway).await {
        Ok(never) => match never {},
        Err(ended) => ended,
    }
}

async fn stream(
    authz: &Authz,
    client: &reqwest::Client,
    base: &str,
    secret: &str,
    gateway: Uuid,
) -> Result<std::convert::Infallible, Ended> {
    let mut response = client
        .get(format!("{base}/internal/authz/stream"))
        .bearer_auth(secret)
        .send()
        .await
        .map_err(|e| Ended::Error(e.without_url().to_string()))?;
    if response.status() != reqwest::StatusCode::OK {
        return Err(Ended::Error(format!(
            "stream answered {}",
            response.status()
        )));
    }
    let mut buffer = Vec::new();
    loop {
        // Silence past the lease is a dead stream even if TCP has not noticed.
        let chunk = tokio::time::timeout(LEASE, response.chunk())
            .await
            .map_err(|_| Ended::Silent)?
            .map_err(|e| Ended::Error(e.without_url().to_string()))?
            .ok_or(Ended::Closed)?;
        buffer.extend_from_slice(&chunk);
        while let Some(end) = buffer.iter().position(|b| *b == b'\n') {
            let line: Vec<u8> = buffer.drain(..=end).collect();
            let message: Message = serde_json::from_slice(&line)
                .map_err(|e| Ended::Error(format!("bad stream line: {e}")))?;
            authz.apply(&message);
            let sent_at = authz.now();
            let ack = Ack {
                gateway,
                applied: authz.applied(),
            };
            let answer = client
                .post(format!("{base}/internal/authz/ack"))
                .bearer_auth(secret)
                .json(&ack)
                .timeout(LEASE)
                .send()
                .await;
            match answer {
                Ok(r) if r.status() == reqwest::StatusCode::NO_CONTENT => {
                    authz.stats.renewals.fetch_add(1, Ordering::Relaxed);
                    authz.renewed(sent_at);
                }
                Ok(_) => {
                    authz.stats.renewals_refused.fetch_add(1, Ordering::Relaxed);
                }
                Err(_) => {
                    authz.stats.renewals_failed.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
        if buffer.len() > MAX_LINE {
            return Err(Ended::Error("stream line too long".to_owned()));
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicBool;

    use shared::authz::{Decision, Reason};
    use shared::hop::{AppSubject, Caller, OrgId};
    use tokio::sync::{Barrier, Notify};

    use super::*;

    /// A clock the test moves.
    #[derive(Default)]
    struct FakeClock(Mutex<Duration>);

    impl FakeClock {
        fn advance(&self, by: Duration) {
            let mut now = self.0.lock().expect("clock");
            *now += by;
        }
    }

    impl Clock for FakeClock {
        fn now(&self) -> Duration {
            *self.0.lock().expect("clock")
        }
    }

    /// The control plane's check, answering allow (or deny once `deny` is
    /// set), counting calls, and optionally holding a load at a barrier.
    #[derive(Default)]
    struct FakeCheck {
        calls: AtomicU64,
        deny: AtomicBool,
        /// The counter the "database" is at: what an answer reflects.
        db: AtomicU64,
        hold: Mutex<Option<(Arc<Barrier>, Arc<Notify>)>>,
    }

    fn user() -> Uuid {
        Uuid::from_u128(7)
    }

    #[async_trait::async_trait]
    impl Check for FakeCheck {
        async fn check(
            &self,
            session: &AppSession,
            app_id: &str,
        ) -> Result<Option<Checked>, Unreachable> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let hold = self.hold.lock().expect("hold").take();
            let deny = self.deny.load(Ordering::SeqCst);
            let as_of = Seq::new(self.db.load(Ordering::SeqCst));
            if let Some((arrived, release)) = hold {
                arrived.wait().await;
                release.notified().await;
            }
            let decision = if deny {
                Decision::deny(Reason::NotAMember)
            } else {
                Decision::allow(Reason::OrgMember)
            };
            Ok(Some(Checked {
                caller: Caller::new(
                    AppSubject::new(format!("{}:{app_id}", session.expose())),
                    Some("v@example.com".to_owned()),
                    OrgId::new("org"),
                ),
                decision,
                tags: vec![Tag::User(user())],
                ttl: Duration::from_secs(3600),
                as_of,
            }))
        }
    }

    fn setup() -> (Arc<Authz>, Arc<FakeCheck>, Arc<FakeClock>) {
        let check = Arc::new(FakeCheck::default());
        let clock = Arc::new(FakeClock::default());
        clock.advance(Duration::from_secs(100));
        check.db.store(10, Ordering::SeqCst);
        let authz = Arc::new(Authz::with_clock(check.clone(), clock.clone()));
        authz.apply(&Message::Hello { seq: Seq::new(10) });
        authz.renewed(clock.now());
        (authz, check, clock)
    }

    async fn allowed(authz: &Authz, session: &str) -> bool {
        authz
            .authorize(&AppSession::new(session), "app")
            .await
            .expect("reachable")
            .is_some_and(|c| c.decision.is_allow())
    }

    fn calls(check: &FakeCheck) -> u64 {
        check.calls.load(Ordering::SeqCst)
    }

    #[tokio::test]
    async fn a_warm_entry_is_a_hit_with_no_check() {
        let (authz, check, _) = setup();
        assert!(allowed(&authz, "s").await);
        assert!(allowed(&authz, "s").await);
        assert_eq!(calls(&check), 1, "the second request was a hit");
        assert_eq!(authz.stats().hits.load(Ordering::SeqCst), 1);
    }

    /// Test 5: a missing sequence number flushes, so the stale allow is not
    /// served even though its own invalidation was the message lost.
    #[tokio::test]
    async fn a_gap_flushes_the_cache() {
        let (authz, check, _) = setup();
        assert!(allowed(&authz, "s").await);
        check.deny.store(true, Ordering::SeqCst);
        // Event 11 (this user's revocation) is lost; 12 arrives.
        authz.apply(&Message::Event {
            seq: Seq::new(12),
            flush: false,
            tags: vec![],
        });
        assert!(!allowed(&authz, "s").await, "served across a gap");
        assert_eq!(authz.applied(), Seq::new(12));
    }

    /// A heartbeat past what was applied is a gap too: the tail was lost.
    #[tokio::test]
    async fn a_heartbeat_ahead_of_the_stream_flushes() {
        let (authz, check, _) = setup();
        assert!(allowed(&authz, "s").await);
        check.deny.store(true, Ordering::SeqCst);
        authz.apply(&Message::Heartbeat { seq: Seq::new(11) });
        assert!(!allowed(&authz, "s").await);
    }

    #[tokio::test]
    async fn an_event_for_the_entrys_tag_invalidates_it_and_no_other() {
        let (authz, check, _) = setup();
        assert!(allowed(&authz, "s").await);
        authz.apply(&Message::Event {
            seq: Seq::new(11),
            flush: false,
            tags: vec![Tag::User(Uuid::from_u128(8))],
        });
        assert!(allowed(&authz, "s").await);
        assert_eq!(calls(&check), 1, "another user's change left this entry");
        check.deny.store(true, Ordering::SeqCst);
        authz.apply(&Message::Event {
            seq: Seq::new(12),
            flush: false,
            tags: vec![Tag::User(user())],
        });
        assert!(!allowed(&authz, "s").await);
    }

    /// The boundary: an invalidation numbered exactly the entry's `as_of` was
    /// already in the decision's snapshot, so the entry stays; one numbered
    /// `as_of + 1` was not, so it goes.
    #[tokio::test]
    async fn an_invalidation_at_as_of_keeps_the_entry_and_one_after_drops_it() {
        let (authz, check, _) = setup();
        // The gateway has applied 10; the database is at 11, which the
        // decision reflects (as_of 11), though event 11 is still in flight.
        check.db.store(11, Ordering::SeqCst);
        assert!(allowed(&authz, "s").await);
        authz.apply(&Message::Event {
            seq: Seq::new(11),
            flush: false,
            tags: vec![Tag::User(user())],
        });
        assert!(allowed(&authz, "s").await);
        assert_eq!(
            calls(&check),
            1,
            "an invalidation at as_of dropped the entry"
        );
        check.deny.store(true, Ordering::SeqCst);
        authz.apply(&Message::Event {
            seq: Seq::new(12),
            flush: false,
            tags: vec![Tag::User(user())],
        });
        assert!(
            !allowed(&authz, "s").await,
            "an invalidation at as_of + 1 left the entry"
        );
    }

    /// Test 6: a load that began before an invalidation must not be served
    /// after it, whenever its insert lands. Deterministic: the load is held
    /// at a barrier while the invalidation is applied.
    #[tokio::test]
    async fn a_load_begun_before_an_invalidation_is_never_served_after_it() {
        let (authz, check, _) = setup();
        let arrived = Arc::new(Barrier::new(2));
        let release = Arc::new(Notify::new());
        *check.hold.lock().expect("hold") = Some((arrived.clone(), release.clone()));

        let loading = {
            let authz = authz.clone();
            tokio::spawn(async move { allowed(&authz, "s").await })
        };
        arrived.wait().await; // the load has read its answer: allow
        check.deny.store(true, Ordering::SeqCst);
        authz.apply(&Message::Event {
            seq: Seq::new(11),
            flush: false,
            tags: vec![Tag::User(user())],
        });
        release.notify_one();
        let _ = loading.await.expect("joined");

        assert!(
            !allowed(&authz, "s").await,
            "the allow loaded before the revocation was served after it"
        );
    }

    /// Mutation 12's test: the lease runs on the injected clock. A jump past
    /// the lease with no renewal (a suspended VM waking) goes to bypass.
    #[tokio::test]
    async fn a_clock_jump_past_the_lease_bypasses_the_cache() {
        let (authz, check, clock) = setup();
        assert!(allowed(&authz, "s").await);
        clock.advance(LEASE + Duration::from_millis(1));
        assert!(!authz.is_caching());
        assert!(allowed(&authz, "s").await);
        assert_eq!(calls(&check), 2, "served from cache after the lease lapsed");
        assert_eq!(authz.stats().bypassed.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn a_disconnect_bypasses_until_a_new_hello_and_lease() {
        let (authz, check, clock) = setup();
        assert!(allowed(&authz, "s").await);
        authz.disconnected();
        assert!(!authz.is_caching());
        assert!(allowed(&authz, "s").await);
        assert_eq!(calls(&check), 2);
        authz.apply(&Message::Hello { seq: Seq::new(20) });
        authz.renewed(clock.now());
        assert!(authz.is_caching());
    }

    #[tokio::test]
    async fn entries_expire_with_their_session() {
        let (authz, check, clock) = setup();
        assert!(allowed(&authz, "s").await);
        clock.advance(MAX_AGE);
        authz.renewed(clock.now());
        assert!(allowed(&authz, "s").await);
        assert_eq!(calls(&check), 2, "an entry outlived MAX_AGE");
    }

    #[tokio::test]
    async fn denials_are_not_cached() {
        let (authz, check, _) = setup();
        check.deny.store(true, Ordering::SeqCst);
        assert!(!allowed(&authz, "s").await);
        check.deny.store(false, Ordering::SeqCst);
        assert!(allowed(&authz, "s").await, "a cached deny delayed an allow");
    }

    #[tokio::test]
    async fn sessions_never_share_an_entry() {
        let (authz, check, _) = setup();
        let one = authz
            .authorize(&AppSession::new("one"), "app")
            .await
            .expect("ok")
            .expect("some");
        let two = authz
            .authorize(&AppSession::new("two"), "app")
            .await
            .expect("ok")
            .expect("some");
        assert_ne!(one.caller.subject, two.caller.subject);
        assert_eq!(calls(&check), 2);
    }

    #[test]
    fn the_lease_clock_is_boottime_and_advances() {
        assert_eq!(LEASE_CLOCK, libc::CLOCK_BOOTTIME);
        let (a, b) = (BootClock.now(), BootClock.now());
        assert!(a > Duration::ZERO && b >= a);
    }

    #[test]
    fn digests_redact_and_differ_per_session() {
        let a = AppSessionDigest::of(&AppSession::new("a"));
        assert_eq!(format!("{a:?}"), "AppSessionDigest(..)");
        assert_ne!(a, AppSessionDigest::of(&AppSession::new("b")));
    }
}
