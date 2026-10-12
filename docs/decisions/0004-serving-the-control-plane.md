# Serving the control plane (#48)

Decided October 2026. Until #48 the `control-plane` binary logged a line and
exited: every route was reachable only through `oneshot` in tests. This records
how it serves: the listeners, what it is configured with, the database pool,
what readiness means, how it stops, and what a deployment (#84) must provide.

## Network shape

Three listeners, plain HTTP, each on its own address:

| listener | serves | bind policy |
|---|---|---|
| public (`CLWD_PUBLIC_LISTEN`) | sign-in, tokens, publish, domain claims, `GET /openapi.json` | loopback or private only |
| internal (`CLWD_INTERNAL_LISTEN`) | the gateways' session checks, the handshake exchange, route resolution, the authorization stream and acks | loopback or private only |
| ops (`CLWD_OPS_LISTEN`) | `GET /livez`, `GET /readyz` | loopback or private only |

- **TLS terminates at the gateway.** The control plane never holds a
  certificate. The gateway forwards the apex and `api` hosts to the public
  listener (#95, which needs #57's platform certificate).
- **The internal router is never mounted on the public listener**, by
  construction: both are built from the one route table, filtered by
  `Listener`, and a binary test requests every internal path on the public
  port.
- **All three are private by policy**, the public one included. It serves
  plain HTTP behind the gateway's TLS: a reachable bind would expose sign-in
  and the OAuth callback without TLS and without the gateway. Each listener
  refuses a public address unless its override is set
  (`CLWD_PUBLIC_LISTEN_ALLOW_PUBLIC=1`, `CLWD_INTERNAL_LISTEN_ALLOW_PUBLIC=1`,
  `CLWD_OPS_LISTEN_ALLOW_PUBLIC=1`), and refuses the unspecified address
  (`0.0.0.0`, `::`) even with it: "every interface" includes the public one,
  and any interface added later.
- **Internal transport is plain HTTP plus the internal credential**
  (`CLWD_INTERNAL_SECRET`, at least 32 bytes). That is adequate on one host or
  a trusted private network. Mutual TLS, needed before the gateway and the
  control plane run on separate hosts across an untrusted network, is #96.
- **No forwarded headers are trusted.** Nothing in the control plane reads
  `Host`, `X-Forwarded-*` or the peer address. Same-origin checks compare
  against the origin of the configured redirect URI.
- **Health is not public.** The public `/healthz` is gone: it had no consumers,
  and a public endpoint that only reports health is surface. `/readyz` reports
  internal state, so it lives only on the ops listener, with no credential.

## Connection-level protection

axum 0.8's `serve` builds hyper's connection builder **without a timer**,
which silently disables hyper's header read timeout (hyper warns "timeout has
default, but no timer set" only at debug). A client sending its headers a
byte at a time would hold a connection forever. So connections are served
with hyper directly:

- **HTTP/1.1 only**, keep-alive on.
- **Header read timeout: 10 s**, with hyper's `TokioTimer`. Measured by the
  binary test: trickled headers are cut off at 10 s, and so is an idle
  keep-alive connection, because hyper restarts the same timer whenever it
  waits for the next request's head. No separate idle timeout is needed.
- **At most 512 open connections** on the public and the internal listener, 16
  on ops. At the cap, accepting stops and the kernel's backlog absorbs the
  burst, rather than the process running out of descriptors.

## Configuration

Every variable, its validation and its default are in the table at the top of
`crates/control-plane/src/config.rs`; every failure names its variable, and
secrets (the database URL, the internal secret, the session key, the Google
client secret, the Cloudflare token) never print. Decisions worth recording:

- **`CLWD_CERT_RECONCILER=on|off` is required, with no default.** `on` with any
  ACME setting missing fails startup naming it; `off` with any set also fails.
  A deploy that forgot the ACME settings must not start and silently never
  issue certificates. Account credentials come from a file that nothing
  creates yet (#97, a prerequisite for the first deploy).
- **The issuer and redirect URI must be `https://`.** An issuer pointed at the
  wrong place is a total authentication bypass. Plain HTTP needs
  `CLWD_ALLOW_INSECURE_ISSUER=1`, which only tests set; the issuer is logged at
  startup, with a warning when it is insecure. In secure mode the redirect
  URI's host must be `CLWD_CONTROL_PLANE_DOMAIN`.
- **The session key is at least 32 bytes, enforced in `CookieKey::from_secret`
  itself**, not only in configuration, so no caller can build a weak key.
- **Durations carry a unit** (`500ms`, `5s`); a bare number is refused.
- **Deliberately not configurable:** the drain deadline (it is the request
  timeout, see below), the header read timeout, the statement and
  idle-in-transaction timeouts, and the pool's idle and lifetime limits.

## The pool

| setting | value | why |
|---|---|---|
| `max_connections` | `CLWD_DB_MAX_CONNECTIONS`, default 20 | enough that #11's 256 concurrent uncached checks never wait a second for a connection (measured below), small enough that a rolling deploy of two instances fits a stock Postgres (the budget below) |
| `min_connections` | equal to max | every connection is opened before ready. Opening one under load took 0.5–4.5 s in #90; a pool that opens on demand opens exactly then |
| `acquire_timeout` | `CLWD_DB_ACQUIRE_TIMEOUT`, default 2 s, must be under 5 s | below the gateway's 5 s, so a shortage is `control-plane.timeout`, never a gateway timeout |
| `idle_timeout` | off | an idle timeout closes what the next burst reopens (#90) |
| `max_lifetime` | off | sqlx 0.9 does not jitter it: every connection opened together would expire together, #90's reopen storm on a timer. Jittered recycling is #98 |
| `test_before_acquire` | on | a connection broken by a failover is detected, not handed out |
| `statement_timeout` | 2 s, a startup parameter | a statement stuck behind a lock ends as `control-plane.timeout` (SQLSTATE 57014) instead of holding a connection for the request's 30 s |
| `idle_in_transaction_session_timeout` | 5 s | a transaction left open by a bug is ended by the server |

Neither timeout reaches migrations: `control-plane migrate` connects with
plain options from the URL, because an index build or a backfill legitimately
runs long (tested with a 3 s migration). Outbox pruning, the one bulk delete,
runs in batches of 1000 rows, at most 50 per relay pass. Measured against a
500,000-row backlog (as after a day with the relay down): 5.6–6.1 ms per
batch. The single unbounded delete it replaced took 516 ms for the same
backlog on a local disk, and grows with the backlog, which is how it would
cross the 2 s statement timeout and then never finish.

The relay's connections (2 for acks, 2 for its loop, 1 listening) use the same
connect options and the same never-close shape. The listening connection
waits for notifications between statements, which neither timeout counts; the
catch-up read is bounded by its batch. Readiness has one connection of its
own, so a saturated serving pool does not read as an unreachable database.

### The connection budget

Per instance: `max_connections` + 5 (relay) + 1 (readiness). At the defaults,
26. Postgres reserves `superuser_reserved_connections` (3 by default) from
`max_connections` (100 by default), leaving 97:

| instances | connections | fits under 97? |
|---|---|---|
| 1 | 26 | yes |
| 2 (a rolling deploy of one) | 52 | yes |
| 3 | 78 | yes |
| 4 | 104 | no: lower `CLWD_DB_MAX_CONNECTIONS` or raise `max_connections` |

A rolling deploy briefly runs one more instance than steady state, so size for
steady state plus one. Migrations and operator sessions take a few more.

## Readiness

`/readyz` answers 200 or 503 with a JSON body naming each check's state.

- **Not ready** when: the serving pool is not yet fully open; the database does
  not answer `select 1` within 500 ms; or the instance is stopping.
- **Reported, never failed on:** the relay (`healthy` / `degraded`), sign-in
  discovery (`discovered` / `degraded`), the reconciler (`off`, `starting`,
  `running`, `failing`, `stopped`). Each has a correct degraded mode: gateways
  bypass their caches (#12), sign-in answers `identity.provider_unavailable`,
  certificates renew weeks ahead. These are shared dependencies: failing
  readiness on one would take every instance out of the load balancer at
  once, turning a degraded cache into a full outage. Each change of state is
  logged once (#89's alerting reads it once it exists).
- **The schema gate** runs once, at startup: a database behind the build (a
  migration this binary embeds is not applied, failed, or applied with
  different contents) is refused, and the process exits naming
  `control-plane migrate`. A database ahead of the build is allowed and logged:
  during a rollout the next build's migrations run first, and the old build
  keeps serving until it is replaced.

### Every migration works with the previous build

Allowing a database ahead of the binary is safe only if no migration breaks
the build before it. So no migration drops or renames a column, table or
constraint that the previous build reads, in the same release. Changes of
shape go expand, then contract: add the new shape and make the code read it
in one release; remove the old shape in a later release, once no running build
reads it. A migration that drops or renames anything carries a
`PREVIOUS BUILD:` comment saying why the build before it does not need what it
removes, and `just rollback-plans` (part of the gate) fails without one. The
rule is in `docs/development.md` for contributors.

`/livez` answers `ok` while the process runs.

## Startup

1. Read and validate configuration; exit naming the variable on any failure.
2. Bind all three listeners; a port conflict fails here.
3. Serve the ops listener, not ready.
4. Reach the database, retrying while it is unreachable (readiness says so);
   exit if it refuses the credentials or the database does not exist.
5. The schema gate.
6. Open every pooled connection (exit if not full within 60 s).
7. Start the relay, sign-in discovery and the reconciler. None of them can stop
   the instance serving: OIDC discovery in particular retries in the
   background, so an outage at Google stops new sign-ins, never the session
   checks every gateway depends on.
8. Serve the public and internal listeners; ready.

Cold start to ready, debug build, local Postgres, five runs: 2.6–2.9 s, of
which 2.1–2.3 s is opening the 20 pooled connections one after another
(sqlx's fill). A release build will be faster at the connection handshake;
it was not measured here.

## Stopping

On SIGTERM (or SIGINT):

| step | when | deadline |
|---|---|---|
| readiness goes false; the reconciler is told to stop between rows | at once | |
| wait for the load balancer to stop sending | `CLWD_PRE_STOP_DELAY`, default 5 s, at most 10 s | 5 s |
| close the public and internal listeners; end every authorization stream and refuse new ones | | |
| drain: every connection finishes its in-flight request and closes | up to 30 s, the request timeout | 30 s |
| the reconciler finishes its current row, releasing the rest for any instance to reclaim at once | up to 5 s more, then abandoned (its row is reclaimed once stale) | 5 s |
| close the pools, stop the ops listener, exit 0 | | |

A second signal at any point exits 1 at once.

- **The drain equals the request timeout**, so every admitted request has
  either finished or already timed out when it ends. Cutting it to fit a
  platform default would drop requests that the request timeout allows.
- **Streams end before the drain, not at its deadline.** A gateway whose
  stream ends goes to bypass and reconnects (to another instance); the stream
  route refuses new streams once stopping began, so a reconnect in the moment
  before the listener closes cannot hold the drain open.
- **The drain costs a request nothing**: one watch receiver per connection,
  nothing per request.

**Kill grace: at least 45 s** (5 + 30 + 5 + margin). Docker's default stop
timeout (10 s) and Kubernetes's default `terminationGracePeriodSeconds` (30 s)
are both too short and would kill the process mid-drain (commented on #84).

## Measured

#11's load against the real binary with the default pool (20 connections, 2 s
acquire timeout): 64 visitors × 4 requests, all 256 at once, through a real
gateway's authorization path, five rounds each. Run on the development
machine (4 threads), load average 4.5.

| mode | allowed | wall | p50 | p99 | pool waits over 1 s |
|---|---|---|---|---|---|
| bypass: every request an uncached session check | 256/256 every round | 263–570 ms | 176–395 ms | 226–498 ms | none |
| cache: first round loads, the rest hit | 256/256 every round | 242 ms, then 8–9 ms | 186 ms, then under 1 ms | 210 ms, then under 1 ms | none |

The bypass row is the worst case: what every gateway sends while its cache
is off. The same load against #12's 5-connection test pool waited up to
2.2–3.6 s for a connection; with every connection pre-opened no request
waited a second (the control plane logs every wait over one second, and
logged none).

## What #84 inherits

- Three addresses to assign: public (reached by the gateway, #95), internal
  (reached by the gateways only), ops (reached by the orchestrator only), all
  three on private addresses, never `0.0.0.0`.
- Migrations that keep the previous build working (expand, then contract), run
  with `control-plane migrate` before the new build starts.
- Readiness probe: `GET /readyz` on the ops listener; liveness: `GET /livez`.
- Kill grace ≥ 45 s; `CLWD_PRE_STOP_DELAY` tuned to the load balancer's
  deregistration delay (at most 10 s).
- The server refuses a database behind it and never migrates itself.
- The connection budget above against the database's `max_connections`.
- The ACME account file before `CLWD_CERT_RECONCILER=on` (#97).
- Every variable in `config.rs`'s table; secrets from the secret store, not the
  image.
