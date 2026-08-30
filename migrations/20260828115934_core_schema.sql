-- The smallest schema that supports #3 through #8. Nothing here exists for a
-- feature that is not being built: no display names, no membership roles, no
-- version numbers, no updated_at. Through P3 this schema churns weekly, and a
-- column nobody can explain is the thing that makes churn expensive.
--
-- ROLLBACK PLAN: none required. This migration only creates; it drops and
-- rewrites nothing, so reverting it is `drop table` in reverse dependency
-- order against a database that has no rows worth keeping. Every later
-- migration that drops or rewrites data must carry its own plan here — `just
-- rollback-plans` fails the build if one does not.

-- Identifiers are UUIDv7, minted by the application rather than the database.
-- Time-ordered, so inserts append to the index instead of scattering; opaque,
-- so a customer cannot count the gap between two ids to learn our growth rate;
-- and known to the caller before the INSERT, which is what idempotent publish
-- (#7) needs.

-- ---------------------------------------------------------------- orgs ----

-- Slugs that may never become an org subdomain. Seeded below and extended by
-- later migrations; a table rather than an inline CHECK list, because every
-- addition to a CHECK is a constraint rewrite and #18 will add to this.
create table reserved_slugs (
    slug text primary key
);

create table orgs (
    id         uuid        primary key,
    -- The org half of {app}.{org}.clwd.run (#18). LDH, 63 bytes, no leading or
    -- trailing hyphen — the DNS label rules, enforced here rather than in a
    -- handler. The leading-underscore names that matter for certificate
    -- issuance (_acme-challenge, _dmarc) cannot match this pattern, so they
    -- need no reserved_slugs row.
    slug       text        not null unique
                           check (slug ~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$'),
    created_at timestamptz not null default now(),
    -- Soft delete. #17 (revocation) and #30 (audit) both have to answer "who
    -- could reach app X on date D" after X is gone, and a hard delete makes
    -- that unanswerable. Deleting an org also must not free its slug: a
    -- reassigned subdomain is handed a browser's still-live cookie for
    -- *.<slug>.clwd.run, which is session fixation and unfixable after the
    -- fact. The unique constraint above is unconditional for that reason.
    deleted_at timestamptz
);

-- A slug is immutable once set, and never one of the reserved words. Both live
-- in a trigger rather than in application code because a trigger also holds
-- against a hand-run UPDATE in psql, and both live in the same trigger because
-- a CHECK constraint cannot query another table.
create function orgs_slug_guard() returns trigger language plpgsql as $$
begin
    if tg_op = 'UPDATE' and new.slug is distinct from old.slug then
        raise exception 'org slug is immutable (% -> %)', old.slug, new.slug
            using errcode = 'restrict_violation';
    end if;
    if exists (select 1 from reserved_slugs where slug = new.slug) then
        raise exception 'org slug % is reserved', new.slug
            using errcode = 'restrict_violation';
    end if;
    return new;
end;
$$;

create trigger orgs_slug_guard
    before insert or update on orgs
    for each row execute function orgs_slug_guard();

insert into reserved_slugs (slug) values
    ('admin'), ('api'), ('app'), ('assets'), ('auth'), ('blog'), ('cdn'),
    ('clwd'), ('dev'), ('docs'), ('ftp'), ('help'), ('id'), ('internal'),
    ('login'), ('mail'), ('ns1'), ('ns2'), ('smtp'), ('staging'), ('static'),
    ('status'), ('support'), ('test'), ('www');

-- --------------------------------------------------------------- users ----

create table users (
    id         uuid        primary key,
    -- The one stable handle a person can be found by before OIDC lands (#9)
    -- and the one an invite is addressed to (#16). Stored lowercased so the
    -- unique constraint means what it looks like it means.
    email      text        not null unique check (email = lower(email)),
    created_at timestamptz not null default now(),
    -- Soft, for the same reason as orgs: #30 has to resolve a historical actor
    -- after the account is gone, and a released email address is a released
    -- identity.
    deleted_at timestamptz
);

-- --------------------------------------------------------- org_members ----

-- Membership is a fact; permission is Cedar's job (#14). There is deliberately
-- no role column here — an ad-hoc role string would be the hand-rolled authz
-- the architecture rules forbid, and P3 would then have to migrate off it.
create table org_members (
    org_id     uuid        not null references orgs (id) on delete restrict,
    user_id    uuid        not null references users (id) on delete restrict,
    created_at timestamptz not null default now(),
    primary key (org_id, user_id)
);

create index org_members_user_id_idx on org_members (user_id);

-- ---------------------------------------------------------------- apps ----

create table apps (
    id         uuid        primary key,
    org_id     uuid        not null references orgs (id) on delete restrict,
    -- The app half of {app}.{org}.clwd.run. Same DNS label rules as a slug,
    -- but deliberately mutable and with no reserved list: renaming an app is a
    -- reasonable product feature, and #18 makes app names unique within an org
    -- only, so two orgs may both own `dashboard`.
    name       text        not null
                           check (name ~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$'),
    -- 'wasm' | 'microvm', spelled exactly as clwd_bundle::Runtime::as_str().
    --
    -- TEXT with a CHECK rather than a Postgres ENUM: adding an ENUM value is
    -- awkward inside a transaction and cannot be rolled back within one, and
    -- removing a value is unsupported. Swapping a CHECK constraint is fully
    -- transactional. This column gains variants.
    --
    -- The rule that matters more than the storage: this value is stored,
    -- passed and displayed. It is never matched on for control flow above
    -- clwd-runtime. Two runtimes already cost two build pipelines and two
    -- security reviews; branching on this above the Sandbox trait is what
    -- makes them cost two of everything else.
    runtime    text        not null check (runtime in ('wasm', 'microvm')),
    created_at timestamptz not null default now(),
    deleted_at timestamptz,
    -- Unconditional, not partial on deleted_at: a deleted app keeps its name so
    -- a new app cannot inherit its identity, its subdomain, or its links.
    unique (org_id, name)
);

create index apps_org_id_idx on apps (org_id);

-- -------------------------------------------------------- app_versions ----

create table app_versions (
    id      uuid not null primary key,
    app_id  uuid not null references apps (id) on delete restrict,
    -- Content address, never a mutable path. Format per the bundle spec's
    -- bundle.digest_malformed: `blake3:` and 64 lowercase hex characters.
    digest  text not null check (digest ~ '^blake3:[0-9a-f]{64}$'),
    -- The row is written 'pending' BEFORE the artifact is stored, and marked
    -- 'ready' after. The other ordering — store, then insert — leaves an orphan
    -- artifact on a crash: bytes nothing references, invisible until #23 diffs
    -- storage against this table.
    --
    -- Writing the row first also makes the unique index below the concurrency
    -- primitive for idempotent publish (#7): the first
    -- `insert ... on conflict do nothing` that returns a row claims the digest
    -- and uploads, and the losers read the existing row. Ten concurrent
    -- identical publishes converge on one row through the index rather than
    -- through a lock, and "created" versus "already existed" is just whether
    -- the insert returned.
    --
    -- A crash mid-publish therefore leaves exactly one visible, queryable
    -- 'pending' row with no artifact under its digest. A retry of the same
    -- digest completes it; #23 reaps ones that go stale. Neither is silent.
    state   text not null default 'pending'
                          check (state in ('pending', 'ready', 'failed')),
    created_at timestamptz not null default now(),
    -- The idempotency key from #7, as an index.
    unique (app_id, digest)
);

create index app_versions_app_id_idx on app_versions (app_id);
