-- API tokens (#4). Until OIDC lands (#9) these are the only way anything
-- authenticates, so nothing here is softened by a second mechanism.
--
-- ROLLBACK PLAN: none required. This migration creates one table and adds one
-- unique constraint; it rewrites no data. Reverting it is removing the table
-- and then the constraint, against rows nobody can use once the code that
-- reads them is gone.

-- ---------------------------------------------------------------- apps ----

-- The target of api_tokens' composite foreign key below. `id` is already
-- unique, so this cannot reject a row that exists today; it exists so the
-- database, not a handler, guarantees a token's app belongs to the token's org.
alter table apps add constraint apps_id_org_id_key unique (id, org_id);

-- ---------------------------------------------------------- api_tokens ----

create table api_tokens (
    id            uuid        primary key,
    -- Tokens belong to an org, not a person: no one can sign in yet (#9), and
    -- an automated caller outlives whoever created its credential.
    org_id        uuid        not null references orgs (id) on delete restrict,
    -- Optional narrowing to one app. Null means every app in the org.
    app_id        uuid,
    -- A label for the humans deciding which token to revoke. Never the secret.
    name          text        not null check (char_length(name) between 1 and 100),
    -- SHA-256 of the whole token string. Never the token.
    --
    -- A fast hash is correct here and would be wrong for a password. The token
    -- carries 256 bits from the system CSPRNG, so recovering it from this
    -- column is a 2^256 search whatever the hash costs; argon2's stretching
    -- multiplies an impossible number by a constant. A password has ~40 bits
    -- drawn from a guessable distribution, and that is what argon2 is for.
    --
    -- Unique because verification looks tokens up by this value, and the
    -- index is what makes that one probe rather than a scan.
    secret_sha256 bytea       not null unique check (octet_length(secret_sha256) = 32),
    -- What the token may do, as independent names. Not hierarchical: `admin`
    -- does not imply `publish`, so "what can this token do" is this column.
    --
    -- Not a role column in the sense the core schema forbids. Membership
    -- permission is still Cedar's (#14); a scope is a ceiling on one
    -- credential, and once #14 lands a request needs both.
    scopes        text[]      not null
                              check (cardinality(scopes) > 0
                                     and scopes <@ array['read', 'write', 'publish', 'admin']::text[]),
    created_at    timestamptz not null default now(),
    -- Soft, for the same reason as orgs: #30 has to answer what a token could
    -- do and when it stopped. Verification treats a revoked token exactly as
    -- one that never existed.
    revoked_at    timestamptz,
    -- A token bound to an app is bound to an app IN ITS ORG. Without the
    -- composite key a token could be bound to another org's app. MATCH SIMPLE,
    -- so a null app_id skips the check, which is what an unbound token is.
    foreign key (app_id, org_id) references apps (id, org_id) on delete restrict
);

create index api_tokens_org_id_idx on api_tokens (org_id);
create index api_tokens_app_id_idx on api_tokens (app_id);
