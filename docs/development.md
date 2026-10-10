# Development notes — platform (private)

Private workspace for clwd: control plane, gateway, identity/sharing, builder, and
per-app data brokering. Nothing here is published; `publish = false` at the
workspace level. The sandbox runtime, CLI, and SDK are open source in
`github.com/clwdrun/clwd` and consumed from here as a dependency.

## Commands

```bash
just check                           # the gate — everything CI enforces
just --list                          # the rest

cargo build --workspace
cargo fmt --all
```

`just check` runs, cheapest failure first: `secrets`, `fmt-check`, `seam`,
`rollback-plans`, `migrate`, `clippy`, `sqlx-prepared`, `offline-build`,
`migrate-roundtrip`, `test`, `deny`.

`secrets` needs `gitleaks` and `just hooks` installs the matching pre-commit hook.
Everything from `migrate` onward needs a database — `just db-up` first.

`.github/workflows/ci.yml` runs `just check` and nothing else, on every pull
request and every push to `main`. The gate lives in the justfile so that what CI
enforces and what you can run before pushing are the same list: a CI-only check is
one nobody can reproduce, and a local-only check is one nobody runs. Third-party
actions there are pinned to a commit SHA, not a tag — a tag is mutable.

### Images

`.github/workflows/cd.yml` builds one container image per binary on every push to
`main` and pushes it to `ghcr.io/clwdrun/platform/{control-plane,gateway}`, with a
build-provenance attestation. Authentication is the workflow's built-in
`GITHUB_TOKEN`, so no registry credential is stored anywhere.

```bash
docker build --build-arg BIN=control-plane -t control-plane .
docker build --build-arg BIN=gateway       -t gateway .
```

One Dockerfile with a `BIN` argument, because the two services differ only in which
binary comes out — two near-identical Dockerfiles would be two places to forget the
same fix. The build sets `SQLX_OFFLINE=true` and reads the committed `.sqlx`, so no
database is needed to produce an image. It runs as uid 10001, not root.

**Deploy by SHA tag, not by `main`.** Every image gets both; `main` moves, and a
rollback needs a name that does not.

`.github/workflows/images.yml` builds both images without pushing, on pull requests
that touch `Dockerfile`, `.dockerignore`, or a manifest. It is not part of `just
check`: two release builds inside Docker are minutes that no ordinary change needs,
and taxing every pull request for a file most of them do not touch is how a gate
teaches people to skip it. The paths filter is what keeps it honest.

There is no deploy step, and that is deliberate: nothing describes a target yet.
`infra/` is empty and #31 owns filling it. Until then this workflow produces
deployable artifacts and stops.

### Database

The schema tests run against a real Postgres, because a `CHECK` constraint only
asserted in Rust is not a constraint.

```bash
just db-up                           # throwaway Postgres on :55432, prints the URL
export DATABASE_URL=...              # or put it in .env, which is gitignored
just migrate                         # sqlx migrate run
just db-down
```

Two traps when running tests by hand rather than through `just check`:

- **`.env` is not the test's environment.** `sqlx`'s macros read `.env` at
  compile time, so the build succeeds — but the integration tests read
  `DATABASE_URL` at *runtime*, and fail ("DATABASE_URL must be set") unless it
  is exported in the shell. `export DATABASE_URL=...`, don't rely on `.env`.
- **`PEBBLE_CA` must be absolute.** The ACME tests default it to
  `.pebble/pebble.minica.pem`, which `cargo test` resolves from the *crate*
  directory, not the workspace root — so it is not found even with Pebble up.
  Export the absolute path `just pebble-up` prints.

`sqlx` macros are compile-time checked, and `.sqlx/` is what lets CI build with no
database at all. After changing any query or migration, run `just prepare` and
commit `.sqlx/` — `just check` fails if it is stale, and `offline-build` proves the
no-database claim by unsetting `DATABASE_URL` rather than by assertion.

Migrations are forward-only. A destructive one has no `down` to run, so it carries
a written `ROLLBACK PLAN` comment instead; `just rollback-plans` fails without one.

### A check that passes without checking is worse than no check

The recurring failure in this repository is not a check that fails. It is a check that
reports success while measuring nothing — because a green tick is taken as evidence, and
the absent coverage is invisible precisely where someone believes it exists. This has now
happened enough times to be a pattern rather than a run of bad luck:

- The `sqlx` cache key covered one of the two binaries `cargo install sqlx-cli` produces.
  A cache hit skipped the install, `just migrate` passed on the cached binary, and the
  gate failed four minutes later on `error: no such command: sqlx`. The cache was working
  perfectly; it was restoring the wrong thing.
- A `run = []` in a workflow step: present, valid, and executing nothing.
- The `standalone` job could read its tag from `Cargo.toml` while `Cargo.lock` resolved a
  different one. Both jobs pass, both build a different version of the seam, and nothing
  reports the disagreement. Hence the explicit assertion that manifest and lock agree —
  the job asserts *what it is testing*, not just that a build succeeded.
- A `compile_fail` doc test written to prove two identifier newtypes are not
  interchangeable, placed inside `#[cfg(test)]` — where rustdoc does not collect doc
  tests. It reported `ok` and ran **zero tests**. The property it existed to enforce was
  unguarded for as long as it looked guarded.

When adding a check, ask what it does when the thing it guards is absent or wrong, and
make it fail there:

- **Assert the precondition, not just the outcome.** `just secrets` fails when gitleaks
  is missing rather than skipping — a scanner that silently no-ops reports clean.
- **Prove the guard by breaking it.** Every seam guard here was verified by planting a
  violation and watching it fail, then reverting. A guard nobody has seen fail is a guard
  nobody knows works.
- **Name the cause in the failure.** "Build failed" sends the reader to the compiler.
  "A private type leaked, or the tag is not standalone-buildable" sends them to the seam.
- **Read the log, not the tick.** Confirm the job did the work. That has caught real
  problems twice.
- **Read the count, not the colour.** This is the thread running through every instance
  above, and it is the one that keeps being missed:

  ```
  test result: ok. 0 passed; 0 failed; 0 ignored
  test result: ok. 12 passed; 0 failed; 0 ignored
  ```

  Both are green. One ran nothing. Every failure on this list was a check that **executed
  nothing**, not a check that got the wrong answer — so the number is the signal and the
  colour is not. When a check is added, look at what it reported the first time: a new
  test should move a count, a new job should print work it did. If the number did not
  change, the check is not wired up, however green it looks.

  The last two instances were both caught this way rather than by anything failing, and
  the most recent was written *after* this note existed, in a check whose entire purpose
  was to enforce a property. Two more turned up in the single verification round that
  followed — including a log grep that returned zero lines while "CI is green" was being
  reported from the same command. **Knowing the pattern does not protect you from it.
  Only looking does**, which is why this is a rule to apply rather than a fact to recall.

- **A captured exit code must belong to the process you meant.** `$?` after a
  pipeline is the *last* stage's status, so `cmd | tee log; echo $?` and
  `just check | tail; echo $?` report `tee`/`tail` succeeding — a passing pipe
  masks a failing `cmd`. This is count-not-colour in a new form: not a check
  that ran nothing, but a green read off the wrong process. A manual gate run
  was reported "EXIT 0" this way while `cargo test` had exited 101 underneath;
  re-reading the actual `test result:` lines caught it. When capturing exit
  through a pipe, use `${PIPESTATUS[0]}` (or `set -o pipefail` so the pipeline
  itself carries the failure), never bare `$?`. The committed recipes are
  already safe — `test` is unpiped and `envelope-probe`/`openapi-check` test
  `if ! out=$(cmd)` (command-substitution exit, not a pipe) under `pipefail` —
  but the trap is one keystroke away in any ad-hoc invocation.

- **A mutation that did not rebuild proved nothing.** Proving a guard by breaking it
  (above) has a failure mode of its own: restoring the file from a backup copy can
  restore an *older* modification time, older than the build that compiled the mutant.
  Cargo decides what to rebuild by mtime, so it skips the rebuild and the next check
  runs the previous mutant. In #4 one control failed — for the previous mutation's
  reason — and read as caught. The procedure looked like it ran and did not: the
  count-not-colour failure, applied to mutation checks. So, for every mutation:

  - `touch` the file after restoring it, so the next build sees a change;
  - assert the check failed **for this mutation's reason** — match the failure message,
    not just a non-zero exit, which a stale binary or a compile error also produces;
  - hash the working tree before and after the run, and require them to match.

  The message check also cuts the other way: a check that fails on an earlier assertion
  than expected is still caught, and should be recorded as caught, not missed. And a
  mutation that passes is information too — in #4, removing a placeholder route changed
  nothing because the fallback returned the same code, which showed the route was
  redundant rather than that coverage was lost.

- **A cancelled run is not a result.** GitHub's `concurrency` group kills an in-progress
  run when the branch is pushed again, so every commit but the last has CI that ends
  `cancelled` — neither green nor red. The danger is that a dead run still emits a
  partial log, and a partial log reads exactly like evidence: the doc test above was
  observed passing in a run that had already been cancelled. Only the run on the current
  head means anything, which is what `statusCheckRollup` reports and what a bare
  `gh run view` on a remembered id does not.

- **A green gate is a statement about when it ran, not about the commit.**
  Every gate step is deterministic — same commit, same answer — except
  `cargo deny check advisories`, which consults an advisory database that updates
  independently of the code. A commit that passed an hour ago can go red with
  nothing in the diff, because a new advisory landed (RUSTSEC-2026-0285 against
  `rustls` did exactly this, mid-branch). That is the check working. The
  consequence: a PR that passed yesterday and merges today may be merging
  something the database now objects to, so re-run the gate at merge, not only at
  push, and treat a green advisory result as "clean as of now" rather than "clean
  forever".

- **The secrets gate has two halves with different scopes, and a seam between
  them.** `just secrets` runs `gitleaks detect`, which scans committed *history*;
  the pre-commit hook runs `gitleaks protect --staged`, which scans what is about
  to be committed. So a secret in the working tree is invisible to `detect` until
  it is committed — a key-shaped test fixture was written, read by a test, and
  passed several green `just check` runs before the pre-commit hook caught it at
  the commit boundary. That is the design working, but the seam is real: a secret
  written and read by a test and *never committed* is scanned by neither half. A
  green `just check` means "no secret in history", not "no secret on disk" —
  another check honest about a narrower scope than its name.

- **Verify a pinned dependency's actual surface before designing against it.**
  Four times a pinned dependency has not been what an issue assumed: `wasm-opt`
  could not parse components, `keyring`'s API had changed, `instant-acme`'s ARI
  was feature-gated (compiled out without `x509-parser`/`time`), and `pingora`
  ships with no TLS backend at all unless a backend feature is enabled. Every one
  would have surfaced mid-implementation as a confusing failure; caught in Phase 0
  each was a one-line finding. Before building on a pinned crate, read its real
  surface — its `Cargo.toml` features and its cached source under
  `~/.cargo/registry/src/` — not its docs or memory of it.

- **A dependency that compiles is not a dependency that works.** `jsonwebtoken`
  10+ ships no crypto unless exactly one backend feature (`aws_lc_rs` or
  `rust_crypto`) is on; with neither, it builds clean and every sign/verify
  panics at runtime. `identity` had declared it for months without ever signing
  anything, so the gap stayed green until #9's flow cookie made the first real
  call — and only a unit test that actually signed caught it. A crypto library
  with no backend feature enabled is a runtime panic behind a green build:
  count-not-colour one layer deeper, where the check that passed was the
  compiler. A declared-but-unexercised dependency is unverified until a test
  calls through it.

## Crates

| Crate | Role |
|---|---|
| `control-plane` | apps, orgs, versions, share grants (axum + sqlx) |
| `gateway` | routing, TLS, identity injection, cold-start hold (pingora) |
| `identity` | SSO in, per-app authz out (cedar-policy) |
| `builder` | bundle → content-addressed artifact |
| `app-data` | per-app DB/blob/secret broker |
| `shared` | wire types, tracing/otel setup |

Cross-crate dependencies within this workspace use path deps on `shared` — that is
fine and expected. Shared dependency versions live in `[workspace.dependencies]`.

## Architectural rules

**Never branch on runtime type above `clwd-runtime`.** The control plane stores
`runtime: Wasm | MicroVM` as a single field on the app record. It may store it,
pass it, and display it. It must not `match` on it to pick code paths. Two runtimes
already costs two build pipelines, two networking models, two log paths, and two
security reviews; if that branching spreads into the control plane or gateway, the
cost compounds everywhere. When a change seems to require the control plane to know
which backend is in use, the fix belongs in the `Sandbox` trait instead.

**Depend on the public repo via a tag-pinned git dependency, never a path
dependency.** Declared once, in `[workspace.dependencies]`:

```toml
clwd-bundle = { git = "https://github.com/clwdrun/clwd", tag = "v0.0.1" }
```

A path dep across the two checkouts works on a laptop, breaks CI, and lets private
types leak into public crates — the exact thing the split exists to prevent. Bump
the tag deliberately; do not track a branch.

Today that is `clwd-bundle` alone — the bundle format, which the builder decodes and
whose rejection codes `shared::Error` passes through. `clwd-sdk` is the *guest* SDK
app code links against: `no_std`, `wit-bindgen`, built for `wasm32-wasip2`. It
compiles on a host target, but nothing here calls it and it drags
`wit-parser`/`wit-component` in as build dependencies for no call sites. Add it when
a crate needs it, not to satisfy a rule about the seam.

Three mechanisms enforce this, and none is sufficient alone:

- `deny.toml`'s `[sources]` — `unknown-git = "deny"` plus an `allow-git` naming
  exactly one origin. This checks *where* a dependency comes from. It does not care
  whether it is pinned to a tag, a branch, or a bare default ref.
- `just seam` — reads the resolved source out of `Cargo.lock` and requires `?tag=`.
  This checks *how* it is pinned. Reading the lock rather than the manifests means it
  sees what cargo actually resolved, so a transitive git dependency another crate
  introduces is caught too, and a dependency spelled across several lines cannot slip
  past. It also rejects a path dependency reaching out of this workspace.
- **the `standalone` job in `ci.yml`** — clones the public repo at the pinned tag onto
  a machine with no platform checkout and builds it. The first two prove nothing
  private is *referenced* from here; this proves nothing private is *depended on* over
  there. A private type that reached a public crate compiles fine in a tree containing
  both and fails the moment the public half is built alone.

The first two run inside `just check`. The third cannot — it needs a clean machine,
which is a CI shape rather than a recipe anyone runs locally.

All three were verified by breaking them on purpose rather than by assumption:
removing `allow-git` exits 8, naming the wrong origin exits 8, a `?branch=` source
fails `seam`, and a path dependency into a sibling checkout fails `seam`.

A tag is a moving target on the publishing side — a deleted or retargeted tag makes
`cargo` fail with `failed to find tag`, which is loud and correct. If that happens,
confirm what the public repo actually publishes (`git ls-remote --tags`) before
repinning; do not switch to a `rev` to make the error go away, because a `rev` is
the pin that silently becomes branch-tracking when the next person edits it.

### Bumping the pinned tag

**Move forward to a new tag. Never move a published one.** A moved tag is a branch
wearing a version-shaped name: two lockfiles fetched either side of the move record
the same tag against different commits and silently disagree, and nothing in the
build reports it. If a published tag is wrong, cut another.

**Pins are annotated tags, never GitHub Releases.** The reasoning and the enforcement
both live in the public repo — see *Seam pins are tags, never Releases* in `clwd`'s
`docs/development.md`. In short: `gh release create` is reserved for MVP, and `clwd`'s
`cd.yml` makes cutting one `workflow_dispatch`-only rather than trusting anyone to
remember. Not restated here, because two copies of a rule drift.

**The `version` key is load-bearing, and not for the reason it looks like.** It is not
selecting anything — the tag does that. It exists because `deny.toml` sets
`wildcards = "deny"`, and a git dependency with no version reads as `*` and fails the
gate. Its value must equal the version the tag's crates actually declare, because
cargo checks it as a constraint against the fetched manifest:

```
error: failed to select a version for the requirement `clwd-bundle = "^0.1.0"`
candidate versions found which didn't match: 0.0.1
```

That is a hard resolution failure, not a silent fallback — which is the good case. The
bad case is the one that happened: a wrong value stayed hidden because `Cargo.lock`
still pinned the tag's previous commit. The full account is in the comment above the
pin in `Cargo.toml`; do not delete it.

To bump:

```bash
# 1. Change the tag and the version together, in [workspace.dependencies].
# 2. Re-resolve, so a version/tag mismatch surfaces here rather than in CI.
cargo update -p clwd-bundle

# 3. Both halves of the seam, and the gate.
just seam
cargo deny check
just check
```

Commit `Cargo.lock` with the manifest. The `standalone` job reads the tag from
`Cargo.toml` and asserts `Cargo.lock` resolved the same one, so committing one without
the other fails CI with that stated as the reason.

**Private types stay private.** Nothing in this repo should be designed to be moved
into the public repo later without an explicit review of what it exposes about the
control plane, scheduling, or tenancy model.

## Domain and routing

Apps are served on **org-scoped subdomains of a separate registrable domain**:
`myapp.acme.<apps domain>`, never under `clwd.run`. Apps run untrusted code, and a
host on the control plane's registrable domain is *same-site* to a browser: it can
plant cookies the control plane reads, share its renderer process, and get the
control plane blocklisted with one phishing page (#62). Org-scoped rather than flat
`myapp.<apps domain>` avoids a global namespace collision the first time two
customers both want `dashboard`. Do not introduce flat app subdomains, and do not
serve an app from the control plane's domain, as a shortcut.

- `clwd.run` — marketing + sharing UI
- `api.clwd.run` — control plane; its session cookie is `__Host-`, host-only
- `<apps domain>` — apps; `*.{org}.<apps domain>` wildcard cert per org via DNS-01
  (`instant-acme`), with a DNS token scoped to the apps zone only

The two are separate configuration values and separate types
(`shared::domains::ControlPlaneDomain`, `shared::domains::AppsDomain`); the gateway
refuses to start if they share a registrable domain. The apps domain is a
placeholder (`clwd-apps.test`) until one is registered.

## Identity and sharing

Share grants are **Cedar entities from day one** — "viewer / editor / owner on app
X" is exactly what `cedar-policy` was built for. Do not hand-roll role checks in
handler code or add ad-hoc permission booleans to the apps table; add a Cedar policy
and evaluate it. Sharing is a permissions model, not a deploy step: link sharing,
revocation, and org boundaries all need to work like a Google Doc.

The platform injects verified identity and group membership before app code runs.
App authors (usually agents) never touch auth, and app code must never receive
anything it could use to impersonate a user elsewhere.

## Data and secrets

`app-data` is a broker. Apps get scoped handles, never raw connection strings or
long-lived credentials. If a change would put a database URL or an unwrapped secret
into an app's environment, it needs a different design.

Per-app storage backend (`libsql` vs `redb` vs Postgres schema-per-app) is still an
open decision — keep the broker interface backend-agnostic until it is settled.

## Economics to design against

The target shape is an org running ~500 apps, each with ~3 users, each idle ~99% of
the time. Anything with a meaningful per-app fixed cost — a always-warm process, a
dedicated database instance, a per-app cert issuance — should be treated as a design
problem, not an implementation detail. Scale-to-zero is the default assumption.

## `gh pr edit` and Projects (classic)

`gh pr edit` can fail against these repositories with

```
GraphQL: Projects (classic) is being deprecated in favor of the new Projects
experience ... (repository.pullRequest.projectCards)
```

The important part is that it **fails silently from the caller's point of
view**: the error goes to stderr, the exit status is easy to miss in a script,
and the PR body is left unchanged. Anyone who does not re-read the PR afterwards
will believe an edit landed that did not.

Use the REST endpoint instead, which does not touch the deprecated field:

```bash
gh api -X PATCH repos/clwdrun/<repo>/pulls/<N> -F body=@body.md
```

Either way, read the body back after editing. The same applies to `gh issue
edit`.
