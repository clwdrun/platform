# Per-request authorization, cached (#12)

Decided October 2026. Until #12, every app request ran one uncached statement
against Postgres, so revocation latency was zero. This records the decision
point that replaces it, the cache in front of it, how the cache learns that a
decision is stale, and the guarantee that results.

## The revocation contract

This is the sentence #17, `clwd share --revoke` and any UI quote. Quote it; do
not paraphrase it.

> Any request whose authorization check begins after the revoke API returns is
> denied, on every gateway. Requests already in flight finish. Changes made
> outside the API (a fix in psql, sign-in membership sync) take effect within
> 3 s.

The API revoke path today is sign-out (`POST /auth/logout`). #17 adds share
revocation on the same wait (`control_plane::relay::converged`).

## Where the decision and the cache live

The **gateway** caches; the control plane decides. A hit costs no network and
no database. The gateway has no database, so invalidation is a distributed
problem, designed for N gateways and N control-plane instances even though
there is one of each today.

## The decision point

`control_plane::authz::Authorize` is a pure function from an
`authz::Request` (principal, action, resource, context) to a
`shared::authz::Decision`: allow or deny, with a `Reason`. Everything it needs
is loaded first, by the one statement in `queries/authz_check.sql`, so a
policy is tested without a database and can never add a query to the request
path. The interim rule (`OrgMemberRule`: members of the app's org may view
it) is the first implementation; #14's Cedar evaluation is the next. The
decision, `Reason`, `Action` and `Resource` are `#[non_exhaustive]`.

## What the decision depends on

Every table the statement reads. `control_plane::authz::INPUTS` lists them;
a test reads the statement's plan and fails on any relation that is not in
the list, and on any input missing a trigger.

| Input | Read for | Tag invalidated | Write paths today |
|---|---|---|---|
| `app_sessions` | live, for this app; expiry | `app_session` | insert at the code exchange |
| `sessions` | not revoked; expiry | `session` | insert at sign-in; revoke at sign-out |
| `users` | not deleted; the email returned | `user` | create; `upsert_google_user` rewrites email at every sign-in |
| `apps` | not deleted; its org | `app` | insert |
| `orgs` | not deleted (new in #12) | `org` | insert |
| `org_members` | membership (the interim rule) | `user` | inserts; the #10 domain-sync hard delete at sign-in |
| `app_subjects` | the subject returned | `user` | insert at the exchange |

Expiry is time, not a write: the statement returns the remaining life of the
earlier session on the database's clock, and the gateway's entry dies then.

## Invalidation: from the database, not from code

Every input carries four triggers (`migrations/20261014120000_authz_outbox.sql`):
insert, update and delete as `DEFERRABLE INITIALLY DEFERRED` constraint
triggers, and a statement-level `TRUNCATE` trigger. No write path can forget
to invalidate, because the trigger is the write path, including a fix typed
into psql during an incident.

- **One number per committed transaction, from a counter row.** Not a
  `bigserial`: a sequence hands out numbers at call time, so a rollback
  leaves a permanent hole and two transactions can commit out of order.
  Either would read as a gap to every gateway. The row lock is held until
  commit, so numbers are gap-free and in commit order.
- **Taken at commit.** The counter is taken by the deferred trigger, so the
  lock is held from just before commit to commit, not from a transaction's
  first write. Under `SET CONSTRAINTS ALL IMMEDIATE` it is taken at the end of
  the statement: still correct, just slower.
- **Unchanged rows emit nothing** (`WHEN (OLD.* IS DISTINCT FROM NEW.*)`):
  sign-in rewrites the same email every time.
- **TRUNCATE flushes** every gateway's cache.
- **`pg_notify` is only a wake-up.** The relay rereads the outbox on every
  notification, every second, and after every reconnect of its listening
  connection, so a lost notification costs latency, never correctness.
  (Postgres delivers notifications only on commit, in commit order, and never
  to a session that was not listening; sqlx's `PgListener::recv` reconnects
  silently and drops what was sent meanwhile. Neither matters, because no
  payload is trusted.)

Write cost, pgbench on Postgres 18, medians of three 8-second runs:

| Workload | no triggers | immediate counter | **deferred counter** |
|---|---|---|---|
| `sessions` insert, 1 client | 1.48 ms | 1.45 ms | 1.41 ms |
| `org_members` delete + insert, 1 client | 1.49 ms | 1.40 ms | 1.76 ms |
| 8 clients, each transaction open 5 ms after its insert | 512 tps, 15.6 ms | **126 tps, 63 ms** | 760 tps, 10.5 ms |

With one client, the trigger cost is inside commit-fsync noise. Under
contention, the immediate design serializes every writer behind the slowest
open transaction; the deferred one does not.

### Ways around the triggers, and what closes each

- **A no-op update**: emits nothing, by design (above).
- **TRUNCATE**: a statement trigger that flushes.
- **`ALTER TABLE … DISABLE TRIGGER`**: the relay checks every second that
  every input has every trigger with `tgenabled = 'O'`. If not, it stops
  heartbeating and stops renewing leases, so every gateway falls back to the
  uncached check within the lease.
- **`session_replication_role = replica`** (set by `pg_restore` and some
  tools) skips every trigger, and is per session, so nothing outside the
  session can see it. **This is a documented limit, not a guarantee.**
  Operator rule: **never run manual SQL against the platform database with
  `session_replication_role = replica`.** A change made that way is not
  announced, and a cached decision can outlive it by up to 60 s (the entry
  ceiling below).

## The relay

**The relay never shares with the request path.** Its loop (draining the
outbox, heartbeats, the trigger and ping checks) runs on a thread and runtime
of its own, with connections of its own, including the `LISTEN` connection,
which is held for ever. Acks write through a two-connection pool of their own.
Otherwise a busy control plane, or an exhausted request pool, would stop
heartbeats and lease renewals; every gateway's lease would lapse and every
request would go to the database at the moment it can least take them, which
would keep the cache off. The relay thread ends when the relay is dropped. It serves `GET /internal/authz/stream` on the
internal listener, behind the internal credential: newline-delimited JSON, a
hello with the current position, one event per transaction, and a heartbeat
every second while healthy.

**Healthy** means: every trigger present and enabled; the listening connection
is draining (each tick it must receive back a ping sent the tick before); the
outbox read succeeded. A relay that hangs while still listening would let
Postgres's notification queue fill, and **when it is full every commit on
every decision input fails**, sign-in included. So a relay that cannot drain
stops heartbeating, gateways go to bypass, and the relay logs
`pg_notification_queue_usage()` above 50 %. Alerting on both is a follow-up:
there is no metrics path yet.

**Resync never replays history.** On any gap a gateway flushes and takes the
newest position; it never needs the backlog. So the outbox is pruned after an
hour, and that is safe.

## Acks and leases

A gateway acks each message it applies (`POST /internal/authz/ack`). While the
relay is healthy, each ack renews the gateway's **lease** to 3 s in
`gateway_leases`, on the database's clock. The gateway counts its own copy of
the lease from when it **sent** the ack, so its copy always lapses first. It
serves from cache only while its lease is live.

A revoke commits, then waits until every gateway has either applied the
revocation's number or let its lease lapse. A gateway that hangs or is
partitioned stops renewing, so the wait is bounded by the lease: **the worst
case revoke latency is 3 s**; the normal case is one stream delivery and one
ack. If a gateway keeps renewing without catching up for twice the lease, the
revoke answers `control-plane.timeout`: the revocation is committed, and not
yet confirmed.

`gateway_leases` is **not** a decision input and must never carry the
triggers: a heartbeat that invalidated would flush every cache every second. A
test holds the outbox unchanged across acks. Write rate: one upsert per
gateway per second, plus one per event.

The lease runs on `CLOCK_BOOTTIME`. `std::time::Instant` is `CLOCK_MONOTONIC`
on Linux (Rust 1.97, `library/std/src/sys/time/unix.rs`), which stops while
the machine is suspended: a gateway frozen past its lease (suspend, live
migration, a stopped container) would wake believing its lease live and serve
a stale allow. Wall-clock time is never used.

## The cache

- **Key:** the app id and the SHA-256 of the app-host session secret. A memory
  dump of the gateway yields no usable session.
- **Contents:** the decision, the subject, the email, the org, the tags, the
  stream position when the load began, and a deadline. Nothing that works as
  a credential. `Debug` redacts the email.
- **Only allows are cached.** A new membership (and, later, a grant) takes
  effect at once, with no insert-side invalidation.
- **Bounds:** 64 MiB by a weigher (512 bytes per entry plus the email), about
  128,000 entries; each entry lives until the earlier session expires or 60 s,
  whichever is first. **Memory ceiling: about 110 MiB.** Measured by filling a
  release-build cache past its bound: 127,826 entries at 63 MiB of weight
  raised the process's RSS by 108 MiB (892 bytes per entry, moka's own
  per-entry structures and the allocator included), plus the per-tag
  invalidation map, bounded by the event rate times 60 s.
- **Checked on read, not only at insert.** moka's invalidation only covers
  entries already present, so a load that read the database before an
  invalidation can insert its stale result after it. Each entry records
  `as_of`, the invalidation counter **read as a column of the decision
  statement itself**, so the number and the decision come from one snapshot.
  (Read in a second query, a revocation committing between the two would be
  counted in the number but missing from the decision, and the stale allow
  would look fresh. A test holds the decision statement on a lock, commits a
  revocation, and checks the two agree; mutation 15 reads them separately and
  turns it red.)
- **The boundary:** an entry is valid iff, for every one of its tags,
  `invalidated_at[tag] <= as_of`, and no flush happened at a position after
  `as_of`. An invalidation numbered `as_of` was committed in the decision's
  snapshot, so the decision reflects it; one numbered `as_of + 1` was not.
  Tested both ways. Also required: the stream is up, the lease is live and
  the deadline has not passed.
- **Coalescing:** concurrent misses for one key share one load
  (`try_get_with`). The key and the load are built from the same session and
  app in one function, so a load can only ever answer its own key.
- **A hit does no I/O**: an in-memory lookup and a check of local state under
  a mutex, with no `.await` on a network or database future.

The decision must be read from the **primary**. The read-time guard assumes
the check sees every change the stream has already announced; pointing it at
a lagging replica breaks the revocation contract.

## Failure modes, and which way each fails

| Failure | What the gateway does |
|---|---|
| Stream drops, or is silent past the lease | flushes, bypasses until a new hello and lease |
| A sequence gap, or a heartbeat ahead of what was applied | flushes, takes the new position |
| Relay unhealthy (trigger disabled, listener not draining) | no heartbeats, no lease renewals: bypass within 3 s |
| Control plane down | bypass, and the uncached check fails: **denied** |
| Gateway suspended past its lease | wakes with the lease lapsed (`CLOCK_BOOTTIME`): bypass |
| A bug in all of the above | no entry outlives 60 s |

The cache adds no availability during a control-plane outage, by design.

## Why a gateway bypassed

Every request that takes the uncached path counts its reason
(`gateway::authz::Stats`): no live stream, lease lapsed, poisoned lock, or a
load that landed stale. Every flush counts its reason too (hello, gap,
heartbeat ahead of the stream, flush event, disconnect), as does every stream
that ended (silent past the lease, closed, error) and every renewal (granted,
refused because the relay is unhealthy, or not delivered). A change into
bypass, and every flush other than a hello or a flush event, is logged with its
reason.

## Unauthenticated misses are uncached and unbounded

Denials are not cached, and a request with a garbage cookie is a miss every
time: it reaches the control plane and the database on every request. That is
the pool-exhaustion path measured on #12, and an attacker can drive it on
purpose by varying the cookie. Caching denials would not help. Until the
follow-up lands (a MAC on the app-session cookie the gateway checks without
I/O, and/or a per-client rate limit on misses), **unauthenticated misses are
uncached and unbounded.**

## Measured

#11's test-4 load, all 256 requests at once (64 visitors × 4), against the
real worker, on the i3-7020U. *Before* is this build with the stream cut, so
every request takes the uncached check (`main`'s behaviour); *after* is the
cache live. Rounds after the first are the same visitors again.

| Cores | Mode | Round | Hit rate | Database checks | p50 | p99 |
|---|---|---|---|---|---|---|
| 2 | before | cold | 0 % | 256 | 3317 ms | 3619 ms |
| 2 | before | warm | 0 % | 256 (125/s) | 1497 ms | 1966 ms |
| 2 | after | cold | 0 % | **64** | 3266 ms | 3552 ms |
| 2 | after | warm | **100 %** | **0** | 1047 ms | 1545 ms |
| 4 | before | warm | 0 % | 256 (147/s) | 1238 ms | 1673 ms |
| 4 | after | warm | **100 %** | **0** | 902 ms | 1316 ms |

- The cold round makes 64 checks for 256 requests: concurrent misses for one
  key share one load.
- Warm, the per-request statement is gone: 0 database checks, against 125 to
  155 a second before.
- Latency falls by a third, not more, because the rest of each request is the
  worker running the component; the database was not the whole cost.
- Of 26 warm rounds, 25 were 100 % hits. One (4 cores) was 34 % hits with a
  5.1 s maximum and was not reproduced in the next 15; its diagnostics were
  not captured. A lease that lapses under load sends the gateway to the
  uncached check: slower, never stale.

## What #14, #15, #16 and #17 inherit

- **#14 (Cedar):** implements `Authorize`. Grants, groups and policies become
  tables the statement (or its successor) reads, so each goes into `INPUTS`
  with the triggers, or the gate fails. A grant change tags the app (`app`):
  every cached decision for the app goes, which is #12's original "epoch per
  app". A group membership change tags the user. A policy change is rare and
  touches everything: emit a flush. The cache key gains the action when there
  is more than `view`.
- **#15 (grants):** grant revocation is an API revoke: it waits on
  `relay::converged` and inherits the contract above.
- **#16 (invites):** an invite grants nothing until redeemed; redemption is a
  grant (#15).
- **#17 (revocation):** quotes the contract, and adds its revoke paths to the
  same wait.
