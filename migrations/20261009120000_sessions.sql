-- Browser sessions (#9). The cookie carries an opaque random secret; this row
-- is the source of truth, so revoking it ends the session at the next request
-- no matter what the browser still holds.
--
-- ROLLBACK PLAN: none required. This migration only creates one table and its
-- index; it rewrites no data. Reverting it is dropping the table, against rows
-- nobody can use once the code that reads them is gone (every session ends,
-- which is a forced sign-out, not data loss).

create table sessions (
    id            uuid        primary key,
    user_id       uuid        not null references users (id) on delete restrict,
    -- SHA-256 of the cookie's secret. Never the secret: a leaked table must
    -- not be a stack of live cookies. A fast hash is correct for the same
    -- reason as api_tokens.secret_sha256 — 256 CSPRNG bits, not a password.
    -- Unique because the lookup finds the row by this value.
    secret_sha256 bytea       not null unique check (octet_length(secret_sha256) = 32),
    created_at    timestamptz not null default now(),
    -- An absolute end. The lookup refuses a row past it whatever the cookie's
    -- own Max-Age says, so a browser that ignores Max-Age gains nothing.
    expires_at    timestamptz not null,
    -- Soft, so #30 can answer when a session stopped and why. The lookup treats
    -- a revoked session exactly as one that never existed.
    revoked_at    timestamptz,
    check (expires_at > created_at)
);

-- "Sign out everywhere" revokes by user.
create index sessions_user_id_idx on sessions (user_id);
