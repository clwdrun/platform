//! The invalidation relay (#12): from the database's outbox to every gateway.
//!
//! The database numbers each committed change to a decision input and writes
//! what it touched to `authz_outbox` (migration `20261014120000`), with a
//! `pg_notify` as a wake-up. The relay reads the outbox in order and
//! broadcasts each transaction to every connected gateway as a
//! [`Message::Event`], with a [`Message::Heartbeat`] every second while it is
//! healthy. It never trusts a notification's payload, so a lost notification
//! costs latency and never correctness: the outbox is reread on every wake-up,
//! every tick, and after every reconnect of the listening connection.
//!
//! **Healthy** means all of: every [`authz::INPUTS`] table carries every
//! [`authz::TRIGGERS`] trigger, enabled; the listening connection is draining
//! notifications (proved each tick by a ping it must receive back); and the
//! outbox read succeeded. When any fails, heartbeats stop and acks stop
//! renewing leases, so every gateway falls back to the uncached check within
//! [`LEASE`]. Fail closed, never open.
//!
//! The relay never shares with the request path. Its loop (draining,
//! heartbeats, the health checks) runs on a thread and runtime of its own,
//! with its own connections, and acks write through a small pool of their
//! own, so neither request load on the control plane's runtime nor an
//! exhausted request pool can stop heartbeats or lease renewals. If they
//! could, a busy control plane would let every gateway's lease lapse, sending
//! every request to the database at the moment it can least take them. The
//! listening connection is held for ever, so it too must neither shrink the
//! pool #48 sizes nor wait behind requests.

use std::convert::Infallible;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use axum::Extension;
use axum::body::{Body, Bytes};
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use shared::authz::{Ack, HEARTBEAT, LEASE, Message, Seq, Tag};
use shared::{Error, RequestId};
use sqlx::PgPool;
use sqlx::postgres::{PgListener, PgPoolOptions};
use tokio::sync::{Notify, broadcast};

use crate::auth::unavailable;
use crate::authz;
use crate::http::{AppState, render};
use crate::openapi::{Body as DocBody, Doc, Success};

const CHANNEL: &str = "clwd_authz";
const PING: &str = "clwd_authz_ping";

/// An event naming more entities than this is sent as a flush.
const MAX_TAGS: usize = 1000;

/// At most this many transactions per outbox read.
const BATCH: i64 = 100;

/// Above this share of Postgres's notification queue, warn: a full queue
/// fails every commit on every decision input, sign-in included.
const QUEUE_WARN: f64 = 0.5;

/// How long the outbox and idle leases are kept. Gateways never replay
/// history (a gap flushes and jumps to the newest position), so nothing reads
/// further back than the relay's own catch-up.
const RETAIN_SECS: f64 = 3600.0;

/// Outbox rows deleted per pruning statement. Measured in #48 at well under
/// the 2 s statement timeout; see decision record 0004.
const PRUNE_BATCH: i64 = 1000;

/// Pruning statements per relay pass, so a large backlog is cleared over
/// several passes rather than holding up heartbeats.
const PRUNE_BATCHES_PER_PASS: usize = 50;

/// A stream line is `None` when the relay closes every stream.
type Line = Option<Arc<Message>>;

/// A pool of `size` connections opened at once and never closed, the serving
/// pool's shape (see [`crate::pool`]): the relay's connections inherit the
/// serving pool's connect options, so they reopen under the same conditions
/// and the same slow connects (#90).
///
/// The serving timeouts suit them. The listening connection waits for
/// notifications between statements, which neither timeout counts, and every
/// statement the relay runs is a bounded read or a batched delete.
fn fixed(size: u32) -> PgPoolOptions {
    PgPoolOptions::new()
        .max_connections(size)
        .min_connections(size)
        .idle_timeout(None)
        .max_lifetime(None)
}

/// The relay's shared state.
#[derive(Debug)]
pub struct Relay {
    lines: broadcast::Sender<Line>,
    current: AtomicU64,
    healthy: AtomicBool,
    /// Set by [`Relay::shut`]: no new stream is served.
    shut: AtomicBool,
    /// Lease renewals' own connections, apart from the request pool.
    acks: PgPool,
}

impl Relay {
    /// Start relaying from `pool`'s database: on a thread, a runtime and
    /// connections of its own. The thread ends once the relay is dropped.
    ///
    /// # Errors
    ///
    /// If the relay's thread, runtime or listening connection cannot be
    /// started, or the counter read.
    pub async fn start(pool: &PgPool) -> Result<Arc<Self>, sqlx::Error> {
        let options = (*pool.connect_options()).clone();
        // Created here: the ack route runs on this runtime.
        let acks = fixed(2).connect_lazy_with(options.clone());
        let (started, relay) = tokio::sync::oneshot::channel();
        std::thread::Builder::new()
            .name("authz-relay".to_owned())
            .spawn(move || {
                let runtime = match tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    Ok(runtime) => runtime,
                    Err(error) => {
                        let _ = started.send(Err(sqlx::Error::Io(error)));
                        return;
                    }
                };
                runtime.block_on(async move {
                    // Every connection the loop uses is made on this runtime.
                    let own = fixed(2).connect_lazy_with(options.clone());
                    let listening = fixed(1).connect_lazy_with(options);
                    let begun = async {
                        let mut listener = PgListener::connect_with(&listening).await?;
                        // LISTEN commits before the first read, so nothing
                        // committed after that read can be missed (the order
                        // `LISTEN`'s docs prescribe).
                        listener.listen_all([CHANNEL, PING]).await?;
                        let start = latest(&own).await.map_err(|_| sqlx::Error::RowNotFound)?;
                        Ok::<_, sqlx::Error>((listener, start))
                    };
                    let (listener, start) = match begun.await {
                        Ok(begun) => begun,
                        Err(error) => {
                            let _ = started.send(Err(error));
                            return;
                        }
                    };
                    let (lines, _) = broadcast::channel(1024);
                    let relay = Arc::new(Self {
                        lines,
                        current: AtomicU64::new(start.get()),
                        healthy: AtomicBool::new(false),
                        shut: AtomicBool::new(false),
                        acks,
                    });
                    let weak = Arc::downgrade(&relay);
                    if started.send(Ok(relay)).is_err() {
                        return;
                    }
                    let wake = Arc::new(Notify::new());
                    let pong = Arc::new(AtomicU64::new(0));
                    tokio::spawn(listen(listener, wake.clone(), pong.clone()));
                    run(weak, own, wake, pong).await;
                });
            })
            .map_err(sqlx::Error::Io)?;
        relay.await.map_err(|_| sqlx::Error::PoolClosed)?
    }

    /// Everything through here has been broadcast.
    #[must_use]
    pub fn current(&self) -> Seq {
        Seq::new(self.current.load(Ordering::SeqCst))
    }

    #[must_use]
    pub fn healthy(&self) -> bool {
        self.healthy.load(Ordering::SeqCst)
    }

    /// End every open stream. Each gateway sees its stream close and bypasses
    /// its cache until it reconnects: what a relay restart does.
    pub fn close_streams(&self) {
        let _ = self.lines.send(None);
    }

    /// End every open stream and serve no new one: the process is stopping
    /// (#48). A gateway that reconnects in the moment before the listener
    /// closes is refused rather than holding a stream open through the drain.
    pub fn shut(&self) {
        self.shut.store(true, Ordering::SeqCst);
        self.close_streams();
    }

    fn send(&self, message: Message) {
        let _ = self.lines.send(Some(Arc::new(message)));
    }
}

/// Drain the listening connection for ever. Every notification, and every
/// reconnect, wakes the relay to reread the outbox; pings prove draining.
async fn listen(mut listener: PgListener, wake: Arc<Notify>, pong: Arc<AtomicU64>) {
    loop {
        match listener.try_recv().await {
            Ok(Some(notification)) if notification.channel() == PING => {
                if let Ok(n) = notification.payload().parse() {
                    pong.store(n, Ordering::SeqCst);
                }
            }
            // A change, or a lost connection (already re-established and
            // re-subscribed): either way, reread the outbox.
            Ok(_) => wake.notify_one(),
            Err(error) => {
                tracing::warn!(%error, "invalidation listener failed; retrying");
                tokio::time::sleep(HEARTBEAT).await;
            }
        }
    }
}

/// The relay's loop, until the relay is dropped.
async fn run(relay: std::sync::Weak<Relay>, pool: PgPool, wake: Arc<Notify>, pong: Arc<AtomicU64>) {
    let mut tick = tokio::time::interval(HEARTBEAT);
    // After a slow iteration, the next tick waits a full period rather than
    // firing at once: a burst would check for a ping sent milliseconds ago.
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut ping: u64 = 0;
    loop {
        let ticked = tokio::select! {
            () = wake.notified() => false,
            _ = tick.tick() => true,
        };
        // Held only for this iteration, so dropping the relay ends the loop.
        let Some(relay) = relay.upgrade() else {
            return;
        };
        let drained = drain(&relay, &pool).await;
        if !ticked {
            continue;
        }
        // The ping sent two ticks ago must have come back through the
        // listening connection: a relay that cannot drain notifications is not
        // healthy. One tick of slack, so a busy database does not read as a
        // hung listener; a hung one is caught within two ticks.
        let draining = pong.load(Ordering::SeqCst) >= ping.saturating_sub(1);
        ping += 1;
        let pinged = sqlx::query("select pg_notify($1, $2)")
            .bind(PING)
            .bind(ping.to_string())
            .execute(&pool)
            .await
            .is_ok();
        let triggers = triggers_ok(&pool).await.unwrap_or(false);
        let healthy = drained && draining && pinged && triggers;
        if relay.healthy.swap(healthy, Ordering::SeqCst) != healthy {
            if healthy {
                tracing::info!("invalidation relay healthy");
            } else {
                tracing::error!(
                    drained,
                    draining,
                    triggers,
                    "invalidation relay unhealthy: heartbeats stopped, gateways bypass their caches"
                );
            }
        }
        if healthy {
            relay.send(Message::Heartbeat {
                seq: relay.current(),
            });
        }
        housekeeping(&pool).await;
    }
}

/// Broadcast every transaction past [`Relay::current`], in order.
async fn drain(relay: &Relay, pool: &PgPool) -> bool {
    loop {
        let from = relay.current();
        let rows = match sqlx::query!(
            r#"select seq, kind, entity from authz_outbox
                where seq in (select distinct seq from authz_outbox
                               where seq > $1 order by seq limit $2)
                order by seq"#,
            from.to_db(),
            BATCH,
        )
        .fetch_all(pool)
        .await
        {
            Ok(rows) => rows,
            Err(error) => {
                tracing::warn!(%error, "could not read the authz outbox");
                return false;
            }
        };
        if rows.is_empty() {
            return true;
        }
        let mut at = from;
        let mut flush = false;
        let mut tags = Vec::new();
        for row in rows {
            let Some(seq) = Seq::from_db(row.seq) else {
                return false;
            };
            if seq != at {
                if at != from {
                    relay.emit(at, flush, std::mem::take(&mut tags));
                }
                // Gap-free by construction; a hole means the outbox was pruned
                // past us. Fail closed: the gateways flush.
                flush = seq != at.next();
                at = seq;
            }
            match Tag::from_kind(&row.kind, row.entity) {
                Some(tag) => tags.push(tag),
                None => flush = true,
            }
        }
        relay.emit(at, flush, tags);
    }
}

impl Relay {
    fn emit(&self, seq: Seq, flush: bool, mut tags: Vec<Tag>) {
        let flush = flush || tags.len() > MAX_TAGS;
        if flush {
            tags.clear();
        }
        self.current.store(seq.get(), Ordering::SeqCst);
        self.send(Message::Event { seq, flush, tags });
    }
}

/// Whether every decision input carries every invalidation trigger, enabled.
///
/// `tgenabled = 'O'` fires in the default `session_replication_role`. A
/// session set to `replica` skips them invisibly to this check: that is an
/// operator rule (never run manual SQL as `replica`), documented in decision
/// record 0003, not something this can see.
///
/// # Errors
///
/// What the driver reports.
pub async fn triggers_ok(pool: &PgPool) -> Result<bool, sqlx::Error> {
    let tables: Vec<String> = authz::INPUTS.iter().map(|i| i.table.to_owned()).collect();
    let triggers: Vec<String> = authz::TRIGGERS.iter().map(|t| (*t).to_owned()).collect();
    let enabled: i64 = sqlx::query_scalar!(
        r#"select count(distinct (c.relname, t.tgname)) as "n!"
             from pg_trigger t
             join pg_class c on c.oid = t.tgrelid
            where c.relnamespace = current_schema()::regnamespace
              and c.relname = any($1) and t.tgname = any($2) and t.tgenabled = 'O'"#,
        &tables,
        &triggers,
    )
    .fetch_one(pool)
    .await?;
    let tables_len = i64::try_from(tables.len()).unwrap_or(i64::MAX);
    let triggers_len = i64::try_from(triggers.len()).unwrap_or(i64::MAX);
    Ok(enabled == tables_len.saturating_mul(triggers_len))
}

async fn housekeeping(pool: &PgPool) {
    match sqlx::query_scalar!(r#"select pg_notification_queue_usage() as "usage!""#)
        .fetch_one(pool)
        .await
    {
        Ok(usage) if usage > QUEUE_WARN => tracing::warn!(
            usage,
            "the notification queue is filling: when full, every commit on a decision input fails"
        ),
        Ok(_) => {}
        Err(error) => tracing::warn!(%error, "could not read notification queue usage"),
    }
    // In batches, each well inside the serving pool's 2 s statement timeout
    // (#48): one unbounded delete after an outage, or after the relay was
    // down for a day, would be cancelled every time and never finish.
    for _ in 0..PRUNE_BATCHES_PER_PASS {
        match sqlx::query!(
            "delete from authz_outbox where (seq, kind, entity) in
                (select seq, kind, entity from authz_outbox
                  where created_at < now() - make_interval(secs => $1)
                  limit $2)",
            RETAIN_SECS,
            PRUNE_BATCH,
        )
        .execute(pool)
        .await
        {
            Ok(done) if done.rows_affected() < PRUNE_BATCH.unsigned_abs() => break,
            Ok(_) => {}
            Err(error) => {
                tracing::warn!(%error, "could not prune the authz outbox");
                break;
            }
        }
    }
    // One statement: a lease row per gateway, so there are never many.
    if let Err(error) = sqlx::query!(
        "delete from gateway_leases where renewed_at < now() - make_interval(secs => $1)",
        RETAIN_SECS,
    )
    .execute(pool)
    .await
    {
        tracing::warn!(%error, "could not prune gateway leases");
    }
}

/// The newest sequence number committed. A revoke waits on this after its
/// own commit: it is at least the revoke's own number.
///
/// # Errors
///
/// [`unavailable`]'s mapping for a database failure.
pub async fn latest(pool: &PgPool) -> Result<Seq, Error> {
    let n: i64 = sqlx::query_scalar!("select n from authz_seq")
        .fetch_one(pool)
        .await
        .map_err(unavailable)?;
    Seq::from_db(n).ok_or_else(|| Error::Internal {
        source: anyhow::anyhow!("negative authz sequence {n}"),
    })
}

/// Wait until no gateway can serve a decision older than `seq` from cache:
/// every gateway has applied `seq`, or its lease has lapsed. A gateway that
/// stops acknowledging stops renewing, so this returns within [`LEASE`] of its
/// last renewal; a revoke never returns before that.
///
/// # Errors
///
/// `control-plane.timeout` if a gateway keeps renewing without catching up
/// past twice the lease: the revocation is committed but not yet confirmed,
/// and the caller must say so rather than claim it.
pub async fn converged(pool: &PgPool, seq: Seq) -> Result<(), Error> {
    let deadline = Instant::now() + LEASE * 2;
    loop {
        let pending: bool = sqlx::query_scalar!(
            r#"select exists (select 1 from gateway_leases
                               where lease_until > now() and applied_seq < $1) as "pending!""#,
            seq.to_db(),
        )
        .fetch_one(pool)
        .await
        .map_err(unavailable)?;
        if !pending {
            return Ok(());
        }
        if Instant::now() > deadline {
            return Err(Error::Timeout {
                dependency: "a gateway acknowledging the revocation".to_owned(),
            });
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// `GET /internal/authz/stream`.
pub(crate) async fn stream_route(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
) -> Response {
    let Some(relay) = state.relay.clone() else {
        return render(&not_relaying(), &request_id);
    };
    if relay.shut.load(Ordering::SeqCst) {
        return render(&not_relaying(), &request_id);
    }
    // Subscribe before reading the position, so nothing sent between the two
    // is missed; anything at or before the hello is skipped.
    let receiver = relay.lines.subscribe();
    let hello = relay.current();
    let first = futures::stream::once(async move { Some(line(&Message::Hello { seq: hello })) });
    let rest = futures::stream::unfold(receiver, move |mut receiver| async move {
        loop {
            match receiver.recv().await {
                Ok(Some(message)) => {
                    if matches!(*message, Message::Event { seq, .. } if seq <= hello) {
                        continue;
                    }
                    return Some((Some(line(&message)), receiver));
                }
                // Closed by the relay, or this stream fell behind and missed
                // messages: end it, and the gateway resyncs from a new hello.
                Ok(None) | Err(_) => return None,
            }
        }
    });
    let body = futures::StreamExt::filter_map(futures::StreamExt::chain(first, rest), |l| {
        std::future::ready(l.map(Ok::<_, Infallible>))
    });
    (
        StatusCode::OK,
        [(axum::http::header::CONTENT_TYPE, "application/x-ndjson")],
        Body::from_stream(body),
    )
        .into_response()
}

fn line(message: &Message) -> Bytes {
    let mut bytes = serde_json::to_vec(message).unwrap_or_default();
    bytes.push(b'\n');
    Bytes::from(bytes)
}

fn not_relaying() -> Error {
    Error::Timeout {
        dependency: "the invalidation relay".to_owned(),
    }
}

/// `POST /internal/authz/ack`.
pub(crate) async fn ack_route(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    body: Bytes,
) -> Response {
    let result = async {
        let ack: Ack = serde_json::from_slice(&body).map_err(|e| Error::InvalidRequest {
            what: e.to_string(),
        })?;
        // The applied position is always recorded; the lease is renewed only
        // while this relay is healthy, so an unhealthy relay's gateways lapse.
        let renew = state.relay.as_ref().is_some_and(|relay| relay.healthy());
        sqlx::query!(
            r#"insert into gateway_leases (gateway_id, applied_seq, lease_until)
               values ($1, $2, case when $4 then now() + make_interval(secs => $3) else now() end)
               on conflict (gateway_id) do update
                 set applied_seq = greatest(gateway_leases.applied_seq, excluded.applied_seq),
                     lease_until = case when $4 then excluded.lease_until
                                        else gateway_leases.lease_until end,
                     renewed_at = now()"#,
            ack.gateway,
            ack.applied.to_db(),
            LEASE.as_secs_f64(),
            renew,
        )
        .execute(
            state
                .relay
                .as_ref()
                .map_or(&state.pool, |relay| &relay.acks),
        )
        .await
        .map_err(unavailable)?;
        if renew { Ok(()) } else { Err(not_relaying()) }
    }
    .await;
    match result {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => render(&error, &request_id),
    }
}

pub(crate) fn stream_doc() -> Doc {
    Doc {
        operation_id: "streamAuthzInvalidations",
        summary: "Follow the authorization invalidation stream",
        description: "Gateway only. Newline-delimited JSON: a hello naming the current position, then one event per committed change to a decision input, and a heartbeat every second while the relay is healthy. A gateway serves cached decisions only while this stream is up, in sequence, and its lease is renewed; anything else sends it to the uncached check.",
        params: &[],
        request: None,
        success: vec![Success {
            status: StatusCode::OK,
            description: "The stream, until the relay closes it.",
            body: None,
        }],
        errors: &["control-plane.timeout"],
    }
}

pub(crate) fn ack_doc() -> Doc {
    Doc {
        operation_id: "ackAuthzInvalidations",
        summary: "Acknowledge the invalidation stream and renew a lease",
        description: "Gateway only. Records how far the gateway has applied the stream, and renews its 3-second lease while the relay is healthy. A revoke returns only once every gateway has applied it or let its lease lapse.",
        params: &[],
        request: Some(DocBody::json::<AckDoc>(
            "The gateway and the last position it applied.",
            ack_example,
        )),
        success: vec![Success {
            status: StatusCode::NO_CONTENT,
            description: "Recorded, and the lease renewed.",
            body: None,
        }],
        errors: &["control-plane.invalid_request", "control-plane.timeout"],
    }
}

/// [`Ack`]'s schema, for the OpenAPI document.
#[derive(serde::Serialize, utoipa::ToSchema)]
pub(crate) struct AckDoc {
    #[schema(value_type = String, format = Uuid)]
    gateway: uuid::Uuid,
    applied: u64,
}

fn ack_example() -> serde_json::Result<serde_json::Value> {
    serde_json::to_value(AckDoc {
        gateway: uuid::Uuid::nil(),
        applied: 42,
    })
}
