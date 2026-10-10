-- App-host sessions and the handshake that issues them (#62).
--
-- Apps are served from a separate registrable domain, so the control plane's
-- session cookie (`__Host-clwd_session`, host-only) never reaches them. Each
-- app host gets its own session through a redirect handshake instead:
--
--   1. the gateway asks the control plane to begin one for an app, with the
--      path to return to; the row records both, and a state value goes back;
--   2. `/authorize?state=` finds the row, checks the control-plane session,
--      and issues a single-use code bound to this row and that session — the
--      redirect target is built from the row's app, never from the request;
--   3. the gateway exchanges code + state server-to-server for an app-host
--      session, a child of the control-plane session.
--
-- ROLLBACK PLAN: none required. This migration only creates two tables; it
-- drops and rewrites nothing. Reverting is dropping them, which signs every
-- visitor out of every app host (they sign back in through the handshake).

create table handshakes (
    id                uuid        primary key,
    -- SHA-256 of the state value, which also sits in the visitor's
    -- `__Host-clwd_state` cookie on the app host. Never stored as is.
    state_sha256      bytea       not null unique check (octet_length(state_sha256) = 32),
    app_id            uuid        not null references apps (id) on delete restrict,
    -- Validated as a same-host path when written (shared::return_path), and
    -- again when read back.
    return_path       text        not null check (left(return_path, 1) = '/' and char_length(return_path) <= 2048),
    -- Set by /authorize: the code's digest, the session it is bound to, and
    -- its 60-second deadline. A code is single-use because the exchange
    -- deletes this row.
    code_sha256       bytea       unique check (octet_length(code_sha256) = 32),
    parent_session_id uuid        references sessions (id) on delete restrict,
    code_expires_at   timestamptz,
    created_at        timestamptz not null default now(),
    expires_at        timestamptz not null
);

create table app_sessions (
    id                uuid        primary key,
    -- The control-plane session this one was issued under. Revoking or
    -- expiring the parent ends every child on its next request: the session
    -- check joins on it, so no cascade job is needed.
    parent_session_id uuid        not null references sessions (id) on delete restrict,
    -- The one app this session is for. The session check looks up by
    -- (secret, app): a session for app A presented on app B's host is not a
    -- session there.
    app_id            uuid        not null references apps (id) on delete restrict,
    -- SHA-256 of the cookie secret. Unique, so the per-request check is one
    -- index probe.
    secret_sha256     bytea       not null unique check (octet_length(secret_sha256) = 32),
    expires_at        timestamptz not null,
    created_at        timestamptz not null default now()
);

create index app_sessions_parent_session_id_idx on app_sessions (parent_session_id);
