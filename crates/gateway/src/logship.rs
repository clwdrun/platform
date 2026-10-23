//! Shipping app logs to the control plane (#78), off the request path.
//!
//! # The request path never waits
//!
//! [`LogShip::record`] is synchronous and does not block: each line goes into
//! a bounded channel with `try_send`. A full channel, or an app over its
//! budget, drops the line and counts it. [`ship`] drains the channel in
//! batches and posts them to the control plane's internal route, and reports
//! each app's dropped count as a platform line of its own, so an author learns
//! their log has gaps rather than reading it as complete.
//!
//! # Who decides what a line is
//!
//! The gateway, never the line. App lines go in one list and the gateway's own
//! lines in another, and the control plane stores each list's lines with that
//! source. Which app a line belongs to is the app this gateway forwarded the
//! request to, not anything the worker said.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use serde::Serialize;
use shared::RequestId;
use shared::hop::HopLogLine;
use tokio::sync::mpsc;

/// Lines waiting to be shipped, across every app.
pub const CHANNEL: usize = 10_000;
/// Each app's sustained rate, lines a second.
pub const RATE_PER_SEC: f64 = 100.0;
/// Each app's burst.
pub const BURST: f64 = 1_000.0;
/// The most lines in one batch.
pub const BATCH: usize = 500;
/// The longest a line waits before its batch is sent.
pub const FLUSH: Duration = Duration::from_millis(500);

/// The gateway's own line about a request of an app.
#[derive(Debug, Clone, Serialize)]
pub struct PlatformLine {
    pub request_id: Option<String>,
    pub text: String,
    pub code: Option<String>,
    pub runtime_code: Option<String>,
    pub hint: Option<String>,
    pub status: Option<i16>,
    pub latency_ms: Option<i32>,
}

enum Entry {
    App {
        app_id: String,
        request_id: String,
        line: HopLogLine,
    },
    Platform {
        app_id: String,
        line: PlatformLine,
    },
}

#[derive(Serialize)]
struct AppLineOut<'a> {
    app_id: &'a str,
    request_id: &'a str,
    stream: &'static str,
    text: &'a str,
}

#[derive(Serialize)]
struct PlatformLineOut<'a> {
    app_id: &'a str,
    #[serde(flatten)]
    line: &'a PlatformLine,
}

#[derive(Serialize, Default)]
struct BatchOut<'a> {
    app: Vec<AppLineOut<'a>>,
    platform: Vec<PlatformLineOut<'a>>,
}

/// One app's token bucket.
struct Bucket {
    tokens: f64,
    at: Instant,
}

impl Bucket {
    fn take(&mut self, now: Instant) -> bool {
        let elapsed = now.saturating_duration_since(self.at).as_secs_f64();
        self.tokens = (self.tokens + elapsed * RATE_PER_SEC).min(BURST);
        self.at = now;
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// The sending side, shared by every request.
pub struct LogShip {
    tx: mpsc::Sender<Entry>,
    // ponytail: one entry per app this gateway has served, never shrunk;
    // evict idle buckets if the number of apps a gateway serves grows large.
    buckets: Mutex<HashMap<String, Bucket>>,
    dropped: Mutex<HashMap<String, u64>>,
    dropped_total: AtomicU64,
}

/// What [`ship`] drains.
pub struct Receiver(mpsc::Receiver<Entry>);

impl LogShip {
    /// A sender with room for `capacity` lines, and its receiver.
    #[must_use]
    pub fn new(capacity: usize) -> (Arc<Self>, Receiver) {
        let (tx, rx) = mpsc::channel(capacity);
        (
            Arc::new(Self {
                tx,
                buckets: Mutex::default(),
                dropped: Mutex::default(),
                dropped_total: AtomicU64::new(0),
            }),
            Receiver(rx),
        )
    }

    /// Queue what one request of `app_id` produced. Never waits: a line that
    /// does not fit is dropped and counted.
    pub fn record(
        &self,
        app_id: &str,
        request_id: &RequestId,
        lines: Vec<HopLogLine>,
        dropped_by_worker: u64,
        platform: Option<PlatformLine>,
    ) {
        let mut dropped = dropped_by_worker;
        let now = Instant::now();
        for line in lines {
            let allowed = self
                .buckets
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .entry(app_id.to_owned())
                .or_insert(Bucket {
                    tokens: BURST,
                    at: now,
                })
                .take(now);
            let sent = allowed
                && self
                    .tx
                    .try_send(Entry::App {
                        app_id: app_id.to_owned(),
                        request_id: request_id.as_str().to_owned(),
                        line,
                    })
                    .is_ok();
            if !sent {
                dropped += 1;
            }
        }
        if let Some(line) = platform {
            let entry = Entry::Platform {
                app_id: app_id.to_owned(),
                line,
            };
            if self.tx.try_send(entry).is_err() {
                dropped += 1;
            }
        }
        self.count_dropped(app_id, dropped);
    }

    fn count_dropped(&self, app_id: &str, n: u64) {
        if n == 0 {
            return;
        }
        self.dropped_total.fetch_add(n, Ordering::Relaxed);
        *self
            .dropped
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .entry(app_id.to_owned())
            .or_default() += n;
    }

    /// Every line dropped since start, for every app.
    #[must_use]
    pub fn dropped_total(&self) -> u64 {
        self.dropped_total.load(Ordering::Relaxed)
    }

    fn take_dropped(&self) -> HashMap<String, u64> {
        std::mem::take(&mut *self.dropped.lock().unwrap_or_else(PoisonError::into_inner))
    }
}

/// Where batches go: the control plane's internal route, with the internal
/// credential.
pub struct Sink {
    pub client: reqwest::Client,
    pub url: reqwest::Url,
    pub secret: Arc<str>,
}

/// The platform line that tells an author `n` of their app's lines are missing.
fn dropped_line(n: u64) -> PlatformLine {
    PlatformLine {
        request_id: None,
        text: format!(
            "{n} log lines dropped: the app wrote more than its log budget, or the log could not keep up"
        ),
        code: None,
        runtime_code: None,
        hint: None,
        status: None,
        latency_ms: None,
    }
}

/// Drain `rx` in batches of up to [`BATCH`], sent at least every [`FLUSH`],
/// until every sender is gone.
pub async fn ship(mut rx: Receiver, ship: Arc<LogShip>, sink: Sink) {
    let mut batch = Vec::with_capacity(BATCH);
    loop {
        // Woken every FLUSH even when no line arrives, so an app's dropped
        // count is reported once it goes quiet, not only when it speaks again.
        let open = tokio::select! {
            n = rx.0.recv_many(&mut batch, BATCH) => n > 0,
            () = tokio::time::sleep(FLUSH) => true,
        };
        let deadline = tokio::time::Instant::now() + FLUSH;
        while open && !batch.is_empty() && batch.len() < BATCH {
            let room = BATCH - batch.len();
            let more = tokio::select! {
                n = rx.0.recv_many(&mut batch, room) => n,
                () = tokio::time::sleep_until(deadline) => break,
            };
            if more == 0 {
                break;
            }
        }
        let dropped = ship.take_dropped();
        if batch.is_empty() && dropped.is_empty() {
            if open {
                continue;
            }
            return;
        }
        let drop_lines: Vec<(String, PlatformLine)> = dropped
            .into_iter()
            .map(|(app, n)| (app, dropped_line(n)))
            .collect();
        let mut out = BatchOut::default();
        for entry in &batch {
            match entry {
                Entry::App {
                    app_id,
                    request_id,
                    line,
                } => out.app.push(AppLineOut {
                    app_id,
                    request_id,
                    stream: line.stream.as_str(),
                    text: &line.text,
                }),
                Entry::Platform { app_id, line } => {
                    out.platform.push(PlatformLineOut { app_id, line });
                }
            }
        }
        for (app_id, line) in &drop_lines {
            out.platform.push(PlatformLineOut { app_id, line });
        }
        let sent = sink
            .client
            .post(sink.url.clone())
            .bearer_auth(sink.secret.as_ref())
            .json(&out)
            .send()
            .await
            .and_then(reqwest::Response::error_for_status);
        if let Err(error) = sent {
            // The batch is gone: count it, so the next batch says so.
            tracing::warn!(%error, lines = batch.len(), "app log batch was not stored");
            for entry in &batch {
                let app_id = match entry {
                    Entry::App { app_id, .. } | Entry::Platform { app_id, .. } => app_id,
                };
                ship.count_dropped(app_id, 1);
            }
        }
        batch.clear();
        if !open {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use shared::hop::LogStream;

    fn lines(n: usize) -> Vec<HopLogLine> {
        (0..n)
            .map(|i| HopLogLine::new(LogStream::Stdout, format!("line {i}")))
            .collect()
    }

    /// A full channel drops and counts; recording never waits for room. Run
    /// on a thread with a deadline, so a `record` that waited fails rather
    /// than hangs.
    #[test]
    fn a_full_channel_drops_and_counts_without_waiting() {
        let (ship, rx) = LogShip::new(10);
        let (done, finished) = std::sync::mpsc::channel();
        let recording = Arc::clone(&ship);
        std::thread::spawn(move || {
            let id = RequestId::generate();
            recording.record("app", &id, lines(25), 0, None);
            let _ = done.send(());
        });
        finished
            .recv_timeout(Duration::from_secs(2))
            .expect("record returned with the channel full");
        assert_eq!(ship.dropped_total(), 15);
        assert_eq!(ship.take_dropped().get("app"), Some(&15));
        drop(rx);
    }

    /// What ships: app lines and platform lines in their two lists, and each
    /// app's dropped count as a platform line of its own.
    #[tokio::test]
    async fn a_batch_carries_both_lists_and_the_dropped_count() {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let url = format!(
            "http://{}/internal/logs",
            listener.local_addr().expect("addr")
        );
        let (ship, rx) = LogShip::new(4);
        let id = RequestId::generate();
        let platform = PlatformLine {
            request_id: Some(id.as_str().to_owned()),
            text: "request failed".to_owned(),
            code: Some("gateway.app_failed".to_owned()),
            runtime_code: Some("runtime.trap".to_owned()),
            hint: None,
            status: Some(502),
            latency_ms: Some(3),
        };
        ship.record("app", &id, lines(5), 2, Some(platform));
        tokio::spawn(super::ship(
            rx,
            Arc::clone(&ship),
            Sink {
                client: reqwest::Client::new(),
                url: reqwest::Url::parse(&url).expect("url"),
                secret: Arc::from("s3cret"),
            },
        ));

        let (mut stream, _) = listener.accept().await.expect("accept");
        let mut raw = Vec::new();
        let mut chunk = [0u8; 8192];
        let body = loop {
            let n = stream.read(&mut chunk).await.expect("read");
            raw.extend_from_slice(&chunk[..n]);
            let text = String::from_utf8_lossy(&raw).into_owned();
            if let Some((head, body)) = text.split_once("\r\n\r\n") {
                let length = head
                    .lines()
                    .find_map(|l| {
                        l.to_ascii_lowercase()
                            .strip_prefix("content-length:")
                            .map(|v| v.trim().to_owned())
                    })
                    .and_then(|v| v.parse::<usize>().ok())
                    .unwrap_or(0);
                if body.len() >= length {
                    assert!(head.contains("authorization: Bearer s3cret"), "{head}");
                    break body.to_owned();
                }
            }
        };
        let _ = stream
            .write_all(b"HTTP/1.1 204 No Content\r\ncontent-length: 0\r\n\r\n")
            .await;
        let batch: serde_json::Value = serde_json::from_str(&body).expect("json");
        // 4 fit: 4 app lines went, the fifth app line and the platform line
        // were dropped along with the worker's 2.
        assert_eq!(batch["app"].as_array().map(Vec::len), Some(4));
        let platform = batch["platform"].as_array().expect("platform");
        assert_eq!(platform.len(), 1);
        assert_eq!(platform[0]["app_id"], "app");
        assert!(platform[0]["request_id"].is_null());
        assert!(
            platform[0]["text"]
                .as_str()
                .is_some_and(|t| t.starts_with("4 log lines dropped")),
            "{batch}"
        );
    }

    /// An app over its budget is dropped; another app is not affected.
    #[tokio::test]
    async fn the_budget_is_per_app() {
        let (ship, _rx) = LogShip::new(CHANNEL);
        let id = RequestId::generate();
        ship.record("noisy", &id, lines(1_200), 0, None);
        ship.record("quiet", &id, lines(10), 0, None);
        let dropped = ship.take_dropped();
        assert_eq!(dropped.get("noisy"), Some(&200));
        assert_eq!(dropped.get("quiet"), None);
    }

    /// What the worker could not fit in the hop is counted with the rest.
    #[tokio::test]
    async fn the_workers_dropped_count_is_carried() {
        let (ship, _rx) = LogShip::new(CHANNEL);
        ship.record("app", &RequestId::generate(), lines(1), 7, None);
        assert_eq!(ship.take_dropped().get("app"), Some(&7));
    }
}
