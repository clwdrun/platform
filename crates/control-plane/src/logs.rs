//! App logs (#78): stored from the gateway, read by the app's owner.
//!
//! # Where a line came from is never the line's to say
//!
//! The gateway sends two lists to [`ingest_route`], `app` and `platform`, of
//! two different types. An app line has the app's text and stream and nothing
//! else; only a platform line can carry a code, a hint or a status. The column
//! `source` is set from which list a line arrived in. Nothing reads a line's
//! text to decide anything, so an app that prints `[platform] deployed`, or a
//! JSON object with `"source": "platform"`, is stored and returned as what it
//! is: an app line.
//!
//! The gateway also decides which app a line belongs to: the app it forwarded
//! the request to, never anything the worker said. A compromised worker can
//! still write app lines for any app with a request in flight through it, since
//! it serves them all; a worker per org (#76) closes that.
//!
//! # Ordering, and resuming without gaps
//!
//! Each app's lines are numbered by its row in `app_log_heads`, locked in the
//! inserting transaction: see the migration. A reader that resumes `after` the
//! last cursor it saw neither skips a line nor sees one twice.
//!
//! # Following is long-polling
//!
//! `wait` holds the request until a line arrives or the wait ends, at most
//! [`MAX_WAIT`], within the request timeout. The wait holds no database
//! connection: it polls every [`POLL`]. Waiting requests are capped per caller,
//! per app and per instance, and [`Follows::shut`] answers every one of them at
//! once when the process stops, as the relay closes its streams (#48).
//!
//! # Retention, and what a line may contain
//!
//! [`MAX_LINES_PER_APP`] lines an app, trimmed as lines arrive, and
//! [`MAX_AGE`], trimmed in batches by [`prune`]. App lines are what the app
//! wrote and may hold its visitors' data; platform lines hold the request id,
//! codes, status and latency, and nothing that names a visitor.

use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use axum::Extension;
use axum::body::Bytes;
use axum::extract::{Path, RawQuery, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use shared::{Error, RequestId};
use tokio::sync::watch;

use crate::auth::Caller;
use crate::authz::{self, Action, Context, Principal, Resource};
use crate::http::{AppState, render};
use crate::ids::{AppId, OrgId, TokenId, UserId};
use crate::openapi::{Body, Doc, Success};

/// Lines kept per app.
pub const MAX_LINES_PER_APP: i64 = 5_000;
/// How long a line is kept.
pub const MAX_AGE: Duration = Duration::from_secs(7 * 24 * 60 * 60);
/// The longest text kept for one line, in bytes. Longer text is cut, marked.
pub const MAX_TEXT: usize = 1024;
/// The most lines one read returns, and the default.
pub const MAX_LIMIT: i64 = 1_000;
const DEFAULT_LIMIT: i64 = 100;
/// The longest a follow may wait, inside the request timeout.
pub const MAX_WAIT: Duration = Duration::from_secs(20);
/// How often a waiting follow looks again.
pub const POLL: Duration = Duration::from_secs(1);
/// Waiting follows per caller (token or user), per app, and per instance.
pub const FOLLOWS_PER_CALLER: usize = 4;
pub const FOLLOWS_PER_APP: usize = 8;
pub const FOLLOWS_PER_INSTANCE: usize = 64;

/// Rows deleted per statement, and statements per pass, when trimming by age:
/// each statement stays well inside the 2 s `statement_timeout`.
const PRUNE_BATCH: i64 = 1_000;
const PRUNE_BATCHES_PER_PASS: usize = 50;
/// How often trimming by age runs.
pub const PRUNE_EVERY: Duration = Duration::from_secs(60);

const CUT_MARK: &str = " [cut]";

/// A position in one app's log: the `seq` of the last line a reader has seen.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct LogCursor(i64);

impl LogCursor {
    #[must_use]
    pub fn new(seq: i64) -> Self {
        Self(seq)
    }

    #[must_use]
    pub fn seq(self) -> i64 {
        self.0
    }
}

/// A request id as the gateway mints them: 1–64 of `A-Za-z0-9._-`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct LogRequestId(String);

impl LogRequestId {
    /// Validate a request id.
    ///
    /// # Errors
    ///
    /// When it is empty, longer than 64 bytes, or has any other character.
    pub fn parse(raw: &str) -> Result<Self, String> {
        let ok = (1..=64).contains(&raw.len())
            && raw
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'));
        if ok {
            Ok(Self(raw.to_owned()))
        } else {
            Err(format!("{raw:?} is not a request id"))
        }
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for LogRequestId {
    type Error = String;
    fn try_from(raw: String) -> Result<Self, String> {
        Self::parse(&raw)
    }
}

impl From<LogRequestId> for String {
    fn from(id: LogRequestId) -> Self {
        id.0
    }
}

/// The stream an app line was written to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Stream {
    Stdout,
    Stderr,
}

impl Stream {
    fn as_str(self) -> &'static str {
        match self {
            Self::Stdout => "stdout",
            Self::Stderr => "stderr",
        }
    }
}

/// One line the app wrote, as the gateway sends it.
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppLineIn {
    pub app_id: AppId,
    pub request_id: Option<LogRequestId>,
    pub stream: Stream,
    pub text: String,
}

impl fmt::Debug for AppLineIn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AppLineIn")
            .field("app_id", &self.app_id)
            .field("request_id", &self.request_id)
            .field("stream", &self.stream)
            .field("text", &format_args!("<{} bytes>", self.text.len()))
            .finish()
    }
}

/// The gateway's own line about an app's request, or about its log.
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlatformLineIn {
    pub app_id: AppId,
    pub request_id: Option<LogRequestId>,
    pub text: String,
    pub code: Option<String>,
    pub runtime_code: Option<String>,
    pub hint: Option<String>,
    pub status: Option<i16>,
    pub latency_ms: Option<i32>,
}

impl fmt::Debug for PlatformLineIn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PlatformLineIn")
            .field("app_id", &self.app_id)
            .field("request_id", &self.request_id)
            .field("text", &format_args!("<{} bytes>", self.text.len()))
            .field("code", &self.code)
            .field("runtime_code", &self.runtime_code)
            .field("status", &self.status)
            .finish_non_exhaustive()
    }
}

/// What the gateway sends to [`ingest_route`]. Two lists, so where a line
/// came from is decided by which one it is in.
#[derive(Debug, Default, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IngestBatch {
    #[serde(default)]
    pub app: Vec<AppLineIn>,
    #[serde(default)]
    pub platform: Vec<PlatformLineIn>,
}

/// One stored line, as a reader gets it.
#[derive(Clone, Serialize, utoipa::ToSchema)]
pub struct LogLine {
    /// Pass as `after` to read the lines that follow this one.
    #[schema(value_type = i64)]
    pub cursor: LogCursor,
    pub ts: DateTime<Utc>,
    /// `app` for what the app wrote, `platform` for the platform's own line
    /// about a request. Set by the platform, never by the line's text.
    pub source: String,
    /// `stdout` or `stderr`, for an app line.
    pub stream: Option<String>,
    /// The id the visitor's response carried, in its `x-request-id` header
    /// and, for an error, its envelope.
    pub request_id: Option<String>,
    /// The line's text, exactly as written. It is the app's output: render it
    /// as untrusted text.
    pub text: String,
    /// Platform lines: the code the visitor was sent.
    pub code: Option<String>,
    /// Platform lines: the runtime's own code for the failure.
    pub runtime_code: Option<String>,
    /// Platform lines: what to do about it.
    pub hint: Option<String>,
    /// Platform lines: the HTTP status the visitor was sent.
    pub status: Option<i16>,
    /// Platform lines: how long the request took.
    pub latency_ms: Option<i32>,
}

impl fmt::Debug for LogLine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LogLine")
            .field("cursor", &self.cursor)
            .field("source", &self.source)
            .field("request_id", &self.request_id)
            .field("text", &format_args!("<{} bytes>", self.text.len()))
            .finish_non_exhaustive()
    }
}

/// A page of lines.
#[derive(Debug, Clone, Serialize, utoipa::ToSchema)]
pub struct LogPage {
    pub lines: Vec<LogLine>,
    /// Where to resume: the last line's cursor, or the `after` given when
    /// there were no new lines. `null` when the log is empty and no `after`
    /// was given.
    #[schema(value_type = Option<i64>)]
    pub cursor: Option<LogCursor>,
}

/// `text`, cut to [`MAX_TEXT`] bytes at a character boundary and marked.
fn cut(text: &str) -> String {
    if text.len() <= MAX_TEXT {
        return text.to_owned();
    }
    let mut end = MAX_TEXT;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}{CUT_MARK}", &text[..end])
}

/// One row to insert, either kind.
struct Row {
    source: &'static str,
    stream: Option<&'static str>,
    request_id: Option<String>,
    text: String,
    code: Option<String>,
    runtime_code: Option<String>,
    hint: Option<String>,
    status: Option<i16>,
    latency_ms: Option<i32>,
}

/// Group a batch by app, each app's lines in the order they arrived: app lines
/// first, then the platform's lines about them.
fn rows_by_app(batch: IngestBatch) -> Vec<(AppId, Vec<Row>)> {
    let mut by_app: Vec<(AppId, Vec<Row>)> = Vec::new();
    let mut push = |app: AppId, row: Row| match by_app.iter_mut().find(|(id, _)| *id == app) {
        Some((_, rows)) => rows.push(row),
        None => by_app.push((app, vec![row])),
    };
    for line in batch.app {
        push(
            line.app_id,
            Row {
                source: "app",
                stream: Some(line.stream.as_str()),
                request_id: line.request_id.map(String::from),
                text: cut(&line.text),
                code: None,
                runtime_code: None,
                hint: None,
                status: None,
                latency_ms: None,
            },
        );
    }
    for line in batch.platform {
        push(
            line.app_id,
            Row {
                source: "platform",
                stream: None,
                request_id: line.request_id.map(String::from),
                text: cut(&line.text),
                code: line.code,
                runtime_code: line.runtime_code,
                hint: line.hint,
                status: line.status,
                latency_ms: line.latency_ms,
            },
        );
    }
    by_app
}

/// Store one app's rows, numbered by its head row, and trim it to
/// [`MAX_LINES_PER_APP`], in one transaction.
async fn store(pool: &sqlx::PgPool, app: AppId, rows: Vec<Row>) -> sqlx::Result<()> {
    let mut tx = pool.begin().await?;
    store_in(&mut tx, app, rows).await?;
    tx.commit().await
}

/// [`store`]'s statements, in `tx`, uncommitted.
async fn store_in(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    app: AppId,
    rows: Vec<Row>,
) -> sqlx::Result<()> {
    let n = i64::try_from(rows.len()).unwrap_or(i64::MAX);
    // The row lock taken here is held until commit: the next batch for this
    // app waits for it, so seqs commit in order. See the migration.
    let first = sqlx::query_scalar!(
        r#"insert into app_log_heads (app_id, next_seq) values ($1, 1 + $2::bigint)
           on conflict (app_id) do update set next_seq = app_log_heads.next_seq + $2
           returning next_seq - $2 as "first!""#,
        app.as_uuid(),
        n,
    )
    .fetch_one(&mut **tx)
    .await?;

    let mut source = Vec::with_capacity(rows.len());
    let mut stream = Vec::with_capacity(rows.len());
    let mut request_id = Vec::with_capacity(rows.len());
    let mut text = Vec::with_capacity(rows.len());
    let mut code = Vec::with_capacity(rows.len());
    let mut runtime_code = Vec::with_capacity(rows.len());
    let mut hint = Vec::with_capacity(rows.len());
    let mut status = Vec::with_capacity(rows.len());
    let mut latency = Vec::with_capacity(rows.len());
    for row in rows {
        source.push(row.source.to_owned());
        stream.push(row.stream.map(str::to_owned));
        request_id.push(row.request_id);
        text.push(row.text);
        code.push(row.code);
        runtime_code.push(row.runtime_code);
        hint.push(row.hint);
        status.push(row.status);
        latency.push(row.latency_ms);
    }
    sqlx::query!(
        r#"insert into app_logs (app_id, seq, source, stream, request_id, text,
                                 code, runtime_code, hint, status, latency_ms)
           select $1, $2 + t.ord - 1, t.source, t.stream, t.request_id, t.text,
                  t.code, t.runtime_code, t.hint, t.status, t.latency_ms
             from unnest($3::text[], $4::text[], $5::text[], $6::text[], $7::text[],
                         $8::text[], $9::text[], $10::int2[], $11::int4[])
                  with ordinality
                  as t(source, stream, request_id, text, code, runtime_code, hint,
                       status, latency_ms, ord)"#,
        app.as_uuid(),
        first,
        &source,
        &stream as &[Option<String>],
        &request_id as &[Option<String>],
        &text,
        &code as &[Option<String>],
        &runtime_code as &[Option<String>],
        &hint as &[Option<String>],
        &status as &[Option<i16>],
        &latency as &[Option<i32>],
    )
    .execute(&mut **tx)
    .await?;

    // Trimming by count, on the app's own key range: what this batch pushed
    // past the cap, never more.
    sqlx::query!(
        "delete from app_logs where app_id = $1 and seq < $2",
        app.as_uuid(),
        first + n - MAX_LINES_PER_APP,
    )
    .execute(&mut **tx)
    .await?;
    Ok(())
}

/// `POST /internal/logs`: a batch of lines from a gateway.
pub(crate) async fn ingest_route(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    body: Bytes,
) -> Response {
    let batch: IngestBatch = match serde_json::from_slice(&body) {
        Ok(batch) => batch,
        Err(e) => {
            return render(
                &Error::InvalidRequest {
                    what: format!("log batch: {e}"),
                },
                &request_id,
            );
        }
    };
    for (app, rows) in rows_by_app(batch) {
        // One app's failure is not another's: an app deleted while its lines
        // were in flight is logged and skipped.
        if let Err(error) = store(&state.pool, app, rows).await {
            tracing::warn!(app_id = %app, %error, "app log lines were not stored");
        }
    }
    StatusCode::NO_CONTENT.into_response()
}

/// The parameters of a read.
#[derive(Debug, Default)]
struct ReadParams {
    after: Option<LogCursor>,
    limit: i64,
    request_id: Option<LogRequestId>,
    wait: Duration,
    since: Option<Duration>,
}

fn read_params(query: Option<&str>) -> Result<ReadParams, Error> {
    let bad = |what: String| Error::InvalidRequest { what };
    let mut params = ReadParams {
        limit: DEFAULT_LIMIT,
        ..ReadParams::default()
    };
    for (name, value) in form_urlencoded::parse(query.unwrap_or("").as_bytes()) {
        let number = || {
            value
                .parse::<u64>()
                .map_err(|_| bad(format!("{name}={value:?} is not a whole number")))
        };
        match name.as_ref() {
            "after" => {
                let seq = i64::try_from(number()?).map_err(|_| bad(format!("after={value}")))?;
                params.after = Some(LogCursor::new(seq));
            }
            "limit" => {
                let limit = number()?;
                if !(1..=MAX_LIMIT.unsigned_abs()).contains(&limit) {
                    return Err(bad(format!("limit={limit}: use 1 to {MAX_LIMIT}")));
                }
                params.limit = i64::try_from(limit).unwrap_or(MAX_LIMIT);
            }
            "request_id" => params.request_id = Some(LogRequestId::parse(&value).map_err(bad)?),
            "wait" => {
                let wait = number()?;
                if wait > MAX_WAIT.as_secs() {
                    return Err(bad(format!(
                        "wait={wait}: at most {} seconds",
                        MAX_WAIT.as_secs()
                    )));
                }
                params.wait = Duration::from_secs(wait);
            }
            "since" => params.since = Some(Duration::from_secs(number()?)),
            other => return Err(bad(format!("unknown parameter {other:?}"))),
        }
    }
    Ok(params)
}

struct LineRow {
    seq: i64,
    ts: DateTime<Utc>,
    source: String,
    stream: Option<String>,
    request_id: Option<String>,
    text: String,
    code: Option<String>,
    runtime_code: Option<String>,
    hint: Option<String>,
    status: Option<i16>,
    latency_ms: Option<i32>,
}

/// One page: the lines after `after`, or, with no `after`, the newest
/// `limit` lines, oldest first either way.
async fn page(pool: &sqlx::PgPool, app: AppId, p: &ReadParams) -> sqlx::Result<LogPage> {
    let request_id = p.request_id.as_ref().map(LogRequestId::as_str);
    let since = p.since.map(|d| d.as_secs_f64());
    let rows = match p.after {
        Some(after) => {
            sqlx::query_as!(
                LineRow,
                r#"select seq, ts, source, stream, request_id, text, code, runtime_code,
                          hint, status, latency_ms
                     from app_logs
                    where app_id = $1 and seq > $2
                      and ($3::text is null or request_id = $3)
                      and ($4::float8 is null or ts > now() - make_interval(secs => $4))
                    order by seq
                    limit $5"#,
                app.as_uuid(),
                after.seq(),
                request_id,
                since,
                p.limit,
            )
            .fetch_all(pool)
            .await?
        }
        None => {
            let mut rows = sqlx::query_as!(
                LineRow,
                r#"select seq, ts, source, stream, request_id, text, code, runtime_code,
                          hint, status, latency_ms
                     from app_logs
                    where app_id = $1
                      and ($2::text is null or request_id = $2)
                      and ($3::float8 is null or ts > now() - make_interval(secs => $3))
                    order by seq desc
                    limit $4"#,
                app.as_uuid(),
                request_id,
                since,
                p.limit,
            )
            .fetch_all(pool)
            .await?;
            rows.reverse();
            rows
        }
    };
    let cursor = rows.last().map(|r| LogCursor::new(r.seq)).or(p.after);
    let lines = rows
        .into_iter()
        .map(|r| LogLine {
            cursor: LogCursor::new(r.seq),
            ts: r.ts,
            source: r.source,
            stream: r.stream,
            request_id: r.request_id,
            text: r.text,
            code: r.code,
            runtime_code: r.runtime_code,
            hint: r.hint,
            status: r.status,
            latency_ms: r.latency_ms,
        })
        .collect();
    Ok(LogPage { lines, cursor })
}

/// The live app `app_id` names: its org, and whether `user` is a member.
pub(crate) struct AppAccess {
    pub(crate) org_id: OrgId,
    pub(crate) member: bool,
}

async fn app_access(
    pool: &sqlx::PgPool,
    app: AppId,
    user: Option<UserId>,
) -> sqlx::Result<Option<AppAccess>> {
    sqlx::query_as!(
        AppAccess,
        r#"select a.org_id as "org_id: OrgId",
                  exists (select 1 from org_members m
                           where m.org_id = a.org_id and m.user_id = $2) as "member!"
             from apps a
             join orgs o on o.id = a.org_id
            where a.id = $1 and a.deleted_at is null and o.deleted_at is null"#,
        app.as_uuid(),
        user.map(|u| u.as_uuid()),
    )
    .fetch_optional(pool)
    .await
}

/// Whether `caller` may do `action` to the app `app` in `org`, `member` being
/// whether a session caller belongs to the org. A token bound to one app
/// reaches no other.
pub(crate) fn allowed(
    caller: &Caller,
    action: Action,
    app: AppId,
    org: OrgId,
    member: bool,
) -> bool {
    let (principal, member_of_org) = match caller {
        Caller::Token(token) => {
            if !token.may_reach_app(app) {
                return false;
            }
            (
                Principal::token(token.token_id, token.org_id),
                token.org_id == org,
            )
        }
        Caller::Session(session) => (Principal::user(session.user_id), member),
    };
    authz::POLICY
        .decide(&authz::Request::new(
            principal,
            action,
            Resource::App {
                app_id: app,
                org_id: org,
            },
            Context::new(member_of_org),
        ))
        .is_allow()
}

pub(crate) fn session_user(caller: &Caller) -> Option<UserId> {
    match caller {
        Caller::Token(_) => None,
        Caller::Session(session) => Some(session.user_id),
    }
}

/// `GET /v1/apps/{app_id}/logs`
pub(crate) async fn read_route(
    State(state): State<AppState>,
    Path(app): Path<String>,
    RawQuery(query): RawQuery,
    Extension(caller): Extension<Caller>,
    Extension(request_id): Extension<RequestId>,
) -> Response {
    match read(&state, &app, query.as_deref(), &caller).await {
        Ok(page) => axum::Json(page).into_response(),
        Err(error) => render(&error, &request_id),
    }
}

async fn read(
    state: &AppState,
    app: &str,
    query: Option<&str>,
    caller: &Caller,
) -> Result<LogPage, Error> {
    let not_found = || Error::NotFound {
        what: format!("app {app}"),
    };
    let app_id = app.parse::<AppId>().map_err(|_| not_found())?;
    let params = read_params(query)?;
    let access = app_access(&state.pool, app_id, session_user(caller))
        .await
        .map_err(crate::auth::unavailable)?
        .ok_or_else(not_found)?;
    if !allowed(
        caller,
        Action::ReadLogs,
        app_id,
        access.org_id,
        access.member,
    ) {
        return Err(not_found());
    }

    let first = page(&state.pool, app_id, &params)
        .await
        .map_err(crate::auth::unavailable)?;
    if !first.lines.is_empty() || params.wait.is_zero() {
        return Ok(first);
    }
    let Some(_admitted) = state.follows.admit(caller_key(caller), app_id) else {
        return Err(Error::RateLimited {
            retry_after_secs: 1,
        });
    };
    let mut shut = state.follows.subscribe();
    let deadline = tokio::time::Instant::now() + params.wait;
    let mut params = params;
    params.after = first.cursor;
    loop {
        if *shut.borrow() {
            return Ok(first);
        }
        let now = tokio::time::Instant::now();
        if now >= deadline {
            return Ok(LogPage {
                lines: Vec::new(),
                cursor: params.after,
            });
        }
        tokio::select! {
            () = tokio::time::sleep(POLL.min(deadline - now)) => {}
            _ = shut.changed() => continue,
        }
        let next = page(&state.pool, app_id, &params)
            .await
            .map_err(crate::auth::unavailable)?;
        if !next.lines.is_empty() {
            return Ok(next);
        }
    }
}

/// Who a follow counts against.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum CallerKey {
    Token(TokenId),
    User(UserId),
}

fn caller_key(caller: &Caller) -> CallerKey {
    match caller {
        Caller::Token(token) => CallerKey::Token(token.token_id),
        Caller::Session(session) => CallerKey::User(session.user_id),
    }
}

#[derive(Debug, Default)]
struct Counts {
    by_caller: HashMap<CallerKey, usize>,
    by_app: HashMap<AppId, usize>,
    total: usize,
}

/// Every waiting follow on this instance: the caps, and the shutdown signal.
#[derive(Debug)]
pub struct Follows {
    counts: Mutex<Counts>,
    shut: watch::Sender<bool>,
}

impl Default for Follows {
    fn default() -> Self {
        Self {
            counts: Mutex::default(),
            shut: watch::Sender::new(false),
        }
    }
}

impl Follows {
    /// Admit one more waiting follow for `caller` on `app`, if every cap allows.
    pub(crate) fn admit(self: &Arc<Self>, caller: CallerKey, app: AppId) -> Option<Admitted> {
        let mut counts = self.counts.lock().unwrap_or_else(PoisonError::into_inner);
        let by_caller = counts.by_caller.get(&caller).copied().unwrap_or(0);
        let by_app = counts.by_app.get(&app).copied().unwrap_or(0);
        if counts.total >= FOLLOWS_PER_INSTANCE
            || by_caller >= FOLLOWS_PER_CALLER
            || by_app >= FOLLOWS_PER_APP
            || *self.shut.borrow()
        {
            return None;
        }
        counts.total += 1;
        *counts.by_caller.entry(caller).or_default() += 1;
        *counts.by_app.entry(app).or_default() += 1;
        Some(Admitted {
            follows: Arc::clone(self),
            caller,
            app,
        })
    }

    /// How many follows are waiting.
    #[must_use]
    pub fn waiting(&self) -> usize {
        self.counts
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .total
    }

    fn subscribe(&self) -> watch::Receiver<bool> {
        self.shut.subscribe()
    }

    /// Answer every waiting follow now and admit no more: the process is
    /// stopping (#48).
    pub fn shut(&self) {
        self.shut.send_replace(true);
    }
}

/// One admitted follow. Dropping it releases its place under every cap.
pub(crate) struct Admitted {
    follows: Arc<Follows>,
    caller: CallerKey,
    app: AppId,
}

impl Drop for Admitted {
    fn drop(&mut self) {
        let mut counts = self
            .follows
            .counts
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        counts.total = counts.total.saturating_sub(1);
        if let Some(count) = counts.by_caller.get_mut(&self.caller) {
            *count = count.saturating_sub(1);
        }
        if let Some(count) = counts.by_app.get_mut(&self.app) {
            *count = count.saturating_sub(1);
        }
        counts.by_caller.retain(|_, n| *n > 0);
        counts.by_app.retain(|_, n| *n > 0);
    }
}

/// Trim lines older than [`MAX_AGE`], [`PRUNE_BATCH`] rows a statement and at
/// most [`PRUNE_BATCHES_PER_PASS`] statements. Returns how many were removed.
///
/// # Errors
///
/// Whatever the database reports.
pub async fn prune(pool: &sqlx::PgPool) -> sqlx::Result<u64> {
    let age = MAX_AGE.as_secs_f64();
    let mut removed = 0;
    for _ in 0..PRUNE_BATCHES_PER_PASS {
        let n = sqlx::query!(
            r#"delete from app_logs
                where (app_id, seq) in (select app_id, seq from app_logs
                                         where ts < now() - make_interval(secs => $1)
                                         limit $2)"#,
            age,
            PRUNE_BATCH,
        )
        .execute(pool)
        .await?
        .rows_affected();
        removed += n;
        if n < PRUNE_BATCH.unsigned_abs() {
            break;
        }
    }
    Ok(removed)
}

/// Run [`prune`] every [`PRUNE_EVERY`] until `follows` is shut.
pub async fn prune_forever(pool: sqlx::PgPool, follows: Arc<Follows>) {
    let mut shut = follows.subscribe();
    loop {
        match prune(&pool).await {
            Ok(0) => {}
            Ok(n) => tracing::info!(removed = n, "trimmed app log lines past their age"),
            Err(error) => tracing::warn!(%error, "trimming app log lines failed"),
        }
        tokio::select! {
            () = tokio::time::sleep(PRUNE_EVERY) => {}
            _ = shut.changed() => return,
        }
    }
}

fn page_example() -> serde_json::Result<serde_json::Value> {
    Ok(serde_json::json!({
        "lines": [
            {
                "cursor": 41,
                "ts": "2026-10-23T09:00:00Z",
                "source": "app",
                "stream": "stdout",
                "request_id": "req_01JB3Z4Q7X",
                "text": "saving note",
                "code": null, "runtime_code": null, "hint": null, "status": null, "latency_ms": null
            },
            {
                "cursor": 42,
                "ts": "2026-10-23T09:00:00Z",
                "source": "platform",
                "stream": null,
                "request_id": "req_01JB3Z4Q7X",
                "text": "request failed: gateway.app_failed (runtime.trap), 502 in 12 ms",
                "code": "gateway.app_failed",
                "runtime_code": "runtime.trap",
                "hint": "The app trapped; its log lines show what it was doing.",
                "status": 502,
                "latency_ms": 12
            }
        ],
        "cursor": 42
    }))
}

/// The documentation for `GET /v1/apps/{app_id}/logs`.
pub(crate) fn read_doc() -> Doc {
    Doc {
        operation_id: "readAppLogs",
        summary: "Read an app's logs",
        description: "Returns what the app wrote to stdout and stderr, and the platform's own line about each request of it that failed: the code the visitor got, the runtime's code and hint, the status and the latency. Lines are oldest first.\n\nWith no `after`, returns the newest `limit` lines. To follow, pass the returned `cursor` as `after`, with `wait` to hold the request until a line arrives: no line is skipped and none is repeated.\n\n`source` says where a line came from, and is set by the platform, never by the line's text: an app line is the app's output, untrusted, and may contain its visitors' data. Kept for 7 days, and at most 5,000 lines an app.",
        params: &[(
            "app_id",
            "The app. The caller must be a member of its org, or present a token of that org (bound to this app, if bound at all); otherwise the answer is the same 404 as an app that does not exist.",
        )],
        query: &[
            (
                "after",
                "A `cursor` from an earlier read: return only lines after it.",
            ),
            ("limit", "How many lines, 1 to 1000. Default 100."),
            (
                "request_id",
                "Only lines from the request with this id: the `request_id` of the visitor's error, or the `x-request-id` header of the response.",
            ),
            (
                "wait",
                "Seconds, up to 20, to wait for a line when there is none yet.",
            ),
            ("since", "Only lines from the last this many seconds."),
        ],
        request: None,
        success: vec![Success {
            status: StatusCode::OK,
            description: "A page of lines, and where to resume.",
            body: Some(Body::json::<LogPage>("The lines.", page_example)),
        }],
        errors: &["control-plane.not_found", "control-plane.rate_limited"],
    }
}

/// The documentation for `POST /internal/logs`.
pub(crate) fn ingest_doc() -> Doc {
    Doc {
        operation_id: "ingestAppLogs",
        summary: "Store a batch of app log lines",
        description: "From a gateway: app lines and the gateway's own platform lines, in two lists. Which list a line arrives in is its source.",
        params: &[],
        query: &[],
        request: Some(Body::binary(
            "application/json",
            "`{\"app\": [...], \"platform\": [...]}`: the two kinds of line, in two lists.",
        )),
        success: vec![Success {
            status: StatusCode::NO_CONTENT,
            description: "Stored, except lines for an app that no longer exists.",
            body: None,
        }],
        errors: &[],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_is_cut_at_a_character_boundary_and_marked() {
        assert_eq!(cut("short"), "short");
        let long = "é".repeat(MAX_TEXT);
        let cut = cut(&long);
        assert!(cut.ends_with(CUT_MARK));
        assert!(cut.len() <= MAX_TEXT + CUT_MARK.len());
    }

    #[test]
    fn a_request_id_is_validated() {
        assert!(LogRequestId::parse("req_01JB3Z4Q7X").is_ok());
        for bad in ["", "a b", "x\n", &"a".repeat(65), "<script>"] {
            assert!(LogRequestId::parse(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn read_parameters_are_checked() {
        let p =
            read_params(Some("after=3&limit=10&request_id=req_1&wait=5&since=60")).expect("valid");
        assert_eq!(p.after, Some(LogCursor::new(3)));
        assert_eq!(p.limit, 10);
        assert_eq!(p.wait, Duration::from_secs(5));
        assert_eq!(p.since, Some(Duration::from_secs(60)));
        for bad in [
            "limit=0",
            "limit=1001",
            "wait=21",
            "after=-1",
            "nope=1",
            "request_id=a%20b",
        ] {
            assert!(read_params(Some(bad)).is_err(), "{bad}");
        }
    }

    /// The source of a line is which list it arrived in, whatever its text.
    #[test]
    fn a_line_claiming_to_be_from_the_platform_is_still_an_app_line() {
        let app = AppId::new();
        let batch: IngestBatch = serde_json::from_value(serde_json::json!({
            "app": [
                { "app_id": app, "request_id": "r1", "stream": "stdout",
                  "text": "[platform] deploy succeeded" },
                { "app_id": app, "request_id": "r1", "stream": "stdout",
                  "text": "{\"source\":\"platform\",\"code\":\"gateway.ok\"}" }
            ]
        }))
        .expect("batch");
        let rows = rows_by_app(batch);
        assert!(
            rows[0]
                .1
                .iter()
                .all(|r| r.source == "app" && r.code.is_none())
        );

        // And an app line cannot carry a platform field at all.
        let forged = serde_json::from_value::<IngestBatch>(serde_json::json!({
            "app": [{ "app_id": app, "stream": "stdout", "text": "x", "code": "gateway.ok" }]
        }));
        assert!(forged.is_err());
    }

    #[test]
    fn follows_are_capped_per_caller_per_app_and_per_instance() {
        let follows = Arc::new(Follows::default());
        let caller = CallerKey::User(UserId::new());
        let app = AppId::new();
        let held: Vec<_> = (0..FOLLOWS_PER_CALLER)
            .map(|_| follows.admit(caller, AppId::new()).expect("under the cap"))
            .collect();
        assert!(follows.admit(caller, app).is_none(), "per caller");
        drop(held);
        assert_eq!(follows.waiting(), 0, "dropping releases");

        let held: Vec<_> = (0..FOLLOWS_PER_APP)
            .map(|_| {
                follows
                    .admit(CallerKey::User(UserId::new()), app)
                    .expect("under")
            })
            .collect();
        assert!(
            follows.admit(CallerKey::User(UserId::new()), app).is_none(),
            "per app"
        );
        drop(held);

        let held: Vec<_> = (0..FOLLOWS_PER_INSTANCE)
            .map(|_| {
                follows
                    .admit(CallerKey::User(UserId::new()), AppId::new())
                    .expect("under")
            })
            .collect();
        assert!(
            follows
                .admit(CallerKey::User(UserId::new()), AppId::new())
                .is_none(),
            "per instance"
        );
        drop(held);

        follows.shut();
        assert!(follows.admit(caller, app).is_none(), "none after shut");
    }

    fn app_rows(texts: &[&str]) -> Vec<Row> {
        texts
            .iter()
            .map(|t| Row {
                source: "app",
                stream: Some("stdout"),
                request_id: None,
                text: (*t).to_owned(),
                code: None,
                runtime_code: None,
                hint: None,
                status: None,
                latency_ms: None,
            })
            .collect()
    }

    async fn an_app(pool: &sqlx::PgPool) -> AppId {
        let org = crate::db::create_org(pool, "acme").await.expect("org").id;
        crate::db::create_app(pool, org, "notes", "wasm")
            .await
            .expect("app")
            .id
    }

    fn params(after: Option<i64>) -> ReadParams {
        ReadParams {
            after: after.map(LogCursor::new),
            limit: MAX_LIMIT,
            ..ReadParams::default()
        }
    }

    /// Wait until a backend is blocked on a lock: the barrier that makes the
    /// interleaving below deterministic rather than timed.
    async fn wait_for_a_lock_waiter(pool: &sqlx::PgPool) {
        for _ in 0..500 {
            let waiting: i64 = sqlx::query_scalar(
                "select count(*) from pg_stat_activity where wait_event_type = 'Lock'",
            )
            .fetch_one(pool)
            .await
            .expect("pg_stat_activity");
            if waiting > 0 {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("the second batch never waited for the first");
    }

    /// Two batches for one app, the second started while the first is still
    /// uncommitted. The second waits for the first's head row, so its lines
    /// are numbered after, and a reader that resumes from any cursor sees every
    /// line once, in order. With a plain sequence the second could commit
    /// first and a reader past it would never see the first.
    #[sqlx::test(migrations = "../../migrations")]
    async fn batches_commit_in_cursor_order_and_resuming_misses_nothing(pool: sqlx::PgPool) {
        let app = an_app(&pool).await;

        let mut first = pool.begin().await.expect("begin");
        store_in(&mut first, app, app_rows(&["a1", "a2", "a3"]))
            .await
            .expect("first batch, uncommitted");

        let second = {
            let pool = pool.clone();
            tokio::spawn(async move { store(&pool, app, app_rows(&["b1", "b2"])).await })
        };
        wait_for_a_lock_waiter(&pool).await;

        // Neither batch is visible yet: the first is uncommitted, the second
        // is waiting behind it.
        let seen = page(&pool, app, &params(None)).await.expect("read");
        assert!(seen.lines.is_empty());

        first.commit().await.expect("commit");
        second.await.expect("joined").expect("second batch");

        let all = page(&pool, app, &params(None)).await.expect("read");
        let texts: Vec<_> = all.lines.iter().map(|l| l.text.as_str()).collect();
        assert_eq!(texts, ["a1", "a2", "a3", "b1", "b2"]);
        let seqs: Vec<_> = all.lines.iter().map(|l| l.cursor.seq()).collect();
        assert_eq!(seqs, [1, 2, 3, 4, 5], "no gaps");

        // Resuming from every cursor returns exactly the rest.
        for (i, line) in all.lines.iter().enumerate() {
            let rest = page(&pool, app, &params(Some(line.cursor.seq())))
                .await
                .expect("read");
            let rest: Vec<_> = rest.lines.iter().map(|l| l.text.as_str()).collect();
            assert_eq!(rest, texts[i + 1..]);
        }
    }

    /// Past the cap, the oldest lines go as new ones arrive.
    #[sqlx::test(migrations = "../../migrations")]
    async fn an_app_keeps_its_newest_lines_up_to_the_cap(pool: sqlx::PgPool) {
        let app = an_app(&pool).await;
        let texts: Vec<String> = (0..MAX_LINES_PER_APP + 100)
            .map(|i| format!("l{i}"))
            .collect();
        for chunk in texts.chunks(1_000) {
            let chunk: Vec<&str> = chunk.iter().map(String::as_str).collect();
            store(&pool, app, app_rows(&chunk)).await.expect("stored");
        }
        let (count, oldest): (i64, Option<i64>) =
            sqlx::query_as("select count(*), min(seq) from app_logs where app_id = $1")
                .bind(app.as_uuid())
                .fetch_one(&pool)
                .await
                .expect("count");
        assert_eq!(count, MAX_LINES_PER_APP);
        assert_eq!(oldest, Some(101));
    }

    /// Lines past their age go in batches; newer ones stay.
    #[sqlx::test(migrations = "../../migrations")]
    async fn old_lines_are_trimmed_in_batches(pool: sqlx::PgPool) {
        let app = an_app(&pool).await;
        let old: Vec<String> = (0..2_500).map(|i| format!("old{i}")).collect();
        let old: Vec<&str> = old.iter().map(String::as_str).collect();
        store(&pool, app, app_rows(&old)).await.expect("stored");
        sqlx::query("update app_logs set ts = now() - interval '8 days'")
            .execute(&pool)
            .await
            .expect("aged");
        store(&pool, app, app_rows(&["new"])).await.expect("stored");

        assert_eq!(prune(&pool).await.expect("pruned"), 2_500);
        let left = page(&pool, app, &params(None)).await.expect("read");
        assert_eq!(left.lines.len(), 1);
        assert_eq!(left.lines[0].text, "new");
        assert_eq!(prune(&pool).await.expect("pruned"), 0);
    }

    #[test]
    fn a_lines_text_is_redacted_in_debug() {
        let line = AppLineIn {
            app_id: AppId::new(),
            request_id: None,
            stream: Stream::Stdout,
            text: "visitor@example.com".to_owned(),
        };
        assert!(!format!("{line:?}").contains("visitor"));
    }
}
