-- App logs (#78): what an app wrote, and the platform's line about each request
-- of it that failed, readable by the app's owner.
--
-- Two kinds of line, told apart by `source`, which the ingest path sets and no
-- line's text can: `app` lines carry the app's own text and the stream it
-- wrote to; `platform` lines are written by the gateway and carry the codes,
-- status and latency of a failed request.
--
-- Ordering: `seq` is per app, handed out by `app_log_heads` in the same
-- transaction as the insert. The head row's lock is held until commit, so the
-- next batch for the same app takes its numbers only after this one is
-- visible: an app's lines commit in `seq` order, with no gaps, and a reader
-- resuming `after` a seq neither skips a line nor sees one twice. (A sequence
-- would hand out numbers that commit out of order.)
--
-- Retention: 5,000 lines an app (trimmed at insert, by seq) and 7 days
-- (trimmed in batches by the control plane). Lines are at most 1 KiB of text.

create table app_log_heads (
    app_id   uuid   primary key references apps (id) on delete restrict,
    -- The seq the next line for this app gets.
    next_seq bigint not null default 1 check (next_seq >= 1)
);

create table app_logs (
    app_id       uuid        not null references apps (id) on delete restrict,
    seq          bigint      not null check (seq >= 1),
    ts           timestamptz not null default now(),
    source       text        not null check (source in ('app', 'platform')),
    -- `stdout` | `stderr` for an app line; none for a platform line.
    stream       text        check (stream in ('stdout', 'stderr')),
    -- The id the gateway minted for the request, and sent to the visitor.
    -- None for a line about no one request, such as a count of discarded lines.
    request_id   text        check (char_length(request_id) <= 64),
    text         text        not null check (octet_length(text) <= 1100),
    -- Platform lines only: the visitor's code, the runtime's code when the
    -- pinned catalogue knows it, the catalogue's hint, the status sent and the
    -- request's latency.
    code         text,
    runtime_code text,
    hint         text,
    status       smallint,
    latency_ms   integer,
    primary key (app_id, seq),
    check ((source = 'app') = (stream is not null)),
    check (source = 'platform' or (code is null and runtime_code is null and hint is null
                                   and status is null and latency_ms is null))
);

-- `--request <id>`: one request's lines.
create index app_logs_by_request on app_logs (app_id, request_id, seq)
    where request_id is not null;

-- Trimming by age.
create index app_logs_by_ts on app_logs (ts);
