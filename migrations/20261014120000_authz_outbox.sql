-- Authorization invalidation (#12): the database says when a cached decision
-- may be wrong, so no write path can forget to.
--
-- The gateway caches allow decisions. A cached allow must stop being served
-- the moment anything it was decided from changes: a session revoked, a member
-- removed, an app or org or user deleted, an email changed. Application code
-- cannot be trusted to announce every such change (a new code path forgets; a
-- fix typed into psql during an incident has no code path at all), so the
-- tables announce it themselves. Every table the per-request decision reads
-- carries these triggers, and `control-plane::authz::INPUTS` is the list a
-- test holds against both the decision statement and `pg_trigger`.
--
-- Each committing transaction that touched one of those tables gets exactly
-- one sequence number, from a single counter row, and writes one outbox row
-- per affected entity. The counter is a row, not a `bigserial`: a sequence
-- hands out numbers at call time, so a rolled-back transaction leaves a
-- permanent hole and two transactions can commit in the opposite order to
-- their numbers. Either would read as a gap to every gateway. The row lock is
-- held until commit, so numbers are gap-free and in commit order.
--
-- The counter is taken in a DEFERRABLE INITIALLY DEFERRED constraint trigger,
-- which fires at commit, so the lock is held from just before commit to
-- commit, not from a transaction's first write. Under `SET CONSTRAINTS ALL
-- IMMEDIATE` it fires at the end of each statement instead: still correct,
-- just holding the lock longer.
--
-- `pg_notify` carries only the sequence number, as a wake-up. The relay reads
-- the outbox for what changed, so a lost notification costs latency, never
-- correctness. Notifications are delivered on commit, in commit order.
--
-- Updates that change nothing (`upsert_google_user` rewrites the same email on
-- every sign-in) emit nothing: the `WHEN` guard. Row triggers do not fire on
-- TRUNCATE, so a statement trigger turns a TRUNCATE into a flush of every
-- gateway's cache.
--
-- Triggers can still be bypassed by `ALTER TABLE ... DISABLE TRIGGER` and by
-- `session_replication_role = replica`. The relay checks the first (and stops
-- heartbeating, so gateways stop caching); the second is per session and
-- invisible from outside, so it is a documented operator rule, not a
-- guarantee (docs/decisions/0003-authorization-cache.md).
--
-- ROLLBACK PLAN: drop the triggers and functions, then the two tables. Only do
-- so together with removing the gateway's cache: without these triggers a
-- cached allow outlives a revocation.

create table authz_seq (
    one boolean primary key default true check (one),
    n   bigint  not null default 0 check (n >= 0)
);
insert into authz_seq default values;

-- One row per (sequence, entity). `entity` is the nil UUID for `all`.
create table authz_outbox (
    seq        bigint      not null check (seq > 0),
    kind       text        not null
                           check (kind in ('app_session', 'session', 'user', 'app', 'org', 'all')),
    entity     uuid        not null,
    created_at timestamptz not null default now(),
    primary key (seq, kind, entity)
);
create index authz_outbox_created_at_idx on authz_outbox (created_at);

-- This transaction's sequence number: taken once, at the first call, then
-- read back from a transaction-local setting.
create function authz_txn_seq() returns bigint language plpgsql as $$
declare
    s bigint := nullif(current_setting('clwd.authz_seq', true), '')::bigint;
begin
    if s is null then
        update authz_seq set n = n + 1 returning n into s;
        perform set_config('clwd.authz_seq', s::text, true);
        perform pg_notify('clwd_authz', s::text);
    end if;
    return s;
end $$;

-- tg_argv[0]: the entity kind; tg_argv[1]: the column naming it.
create function authz_emit() returns trigger language plpgsql as $$
declare
    s bigint := authz_txn_seq();
begin
    if tg_op <> 'INSERT' then
        insert into authz_outbox (seq, kind, entity)
        values (s, tg_argv[0], (to_jsonb(old) ->> tg_argv[1])::uuid)
        on conflict do nothing;
    end if;
    if tg_op <> 'DELETE' then
        insert into authz_outbox (seq, kind, entity)
        values (s, tg_argv[0], (to_jsonb(new) ->> tg_argv[1])::uuid)
        on conflict do nothing;
    end if;
    return null;
end $$;

create function authz_flush() returns trigger language plpgsql as $$
begin
    insert into authz_outbox (seq, kind, entity)
    values (authz_txn_seq(), 'all', '00000000-0000-0000-0000-000000000000')
    on conflict do nothing;
    return null;
end $$;

-- One block per decision input. Insert, update (only a real change) and
-- delete, each deferred to commit; and TRUNCATE, which flushes.
create procedure authz_watch(tbl regclass, kind text, col text) language plpgsql as $$
begin
    execute format(
        'create constraint trigger authz_ins after insert on %s deferrable initially deferred
           for each row execute function authz_emit(%L, %L)', tbl, kind, col);
    execute format(
        'create constraint trigger authz_upd after update on %s deferrable initially deferred
           for each row when (old.* is distinct from new.*) execute function authz_emit(%L, %L)',
        tbl, kind, col);
    execute format(
        'create constraint trigger authz_del after delete on %s deferrable initially deferred
           for each row execute function authz_emit(%L, %L)', tbl, kind, col);
    execute format(
        'create trigger authz_truncate after truncate on %s
           for each statement execute function authz_flush()', tbl);
end $$;

call authz_watch('app_sessions', 'app_session', 'id');
call authz_watch('sessions',     'session',     'id');
call authz_watch('users',        'user',        'id');
call authz_watch('apps',         'app',         'id');
call authz_watch('orgs',         'org',         'id');
-- A membership or a subject belongs to a user: invalidating the user's
-- entries is coarser than the pair, and never misses.
call authz_watch('org_members',  'user',        'user_id');
call authz_watch('app_subjects', 'user',        'user_id');

drop procedure authz_watch(regclass, text, text);
