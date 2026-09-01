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

`sqlx` macros are compile-time checked, and `.sqlx/` is what lets CI build with no
database at all. After changing any query or migration, run `just prepare` and
commit `.sqlx/` — `just check` fails if it is stale, and `offline-build` proves the
no-database claim by unsetting `DATABASE_URL` rather than by assertion.

Migrations are forward-only. A destructive one has no `down` to run, so it carries
a written `ROLLBACK PLAN` comment instead; `just rollback-plans` fails without one.

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

Two mechanisms enforce this, and neither is sufficient alone:

- `deny.toml`'s `[sources]` — `unknown-git = "deny"` plus an `allow-git` naming
  exactly one origin. This checks *where* a dependency comes from. It does not care
  whether it is pinned to a tag, a branch, or a bare default ref.
- `just seam` — reads the resolved source out of `Cargo.lock` and requires `?tag=`.
  This checks *how* it is pinned. Reading the lock rather than the manifests means
  it sees what cargo actually resolved.

Both were verified by breaking them on purpose rather than by assumption: removing
`allow-git` exits 8, naming the wrong origin exits 8, and a `?branch=` source fails
`seam`.

A tag is a moving target on the publishing side — a deleted or retargeted tag makes
`cargo` fail with `failed to find tag`, which is loud and correct. If that happens,
confirm what the public repo actually publishes (`git ls-remote --tags`) before
repinning; do not switch to a `rev` to make the error go away, because a `rev` is
the pin that silently becomes branch-tracking when the next person edits it.

**Private types stay private.** Nothing in this repo should be designed to be moved
into the public repo later without an explicit review of what it exposes about the
control plane, scheduling, or tenancy model.

## Domain and routing

Apps are served on **org-scoped subdomains**: `myapp.acme.clwd.run`. This was chosen
over flat `myapp.clwd.run` deliberately — it costs one nesting level on the wildcard
cert and avoids a global namespace collision the first time two customers both want
`dashboard`. Do not introduce flat app subdomains as a shortcut.

- `clwd.run` — marketing + sharing UI
- `*.clwd.run` — per-app, wildcard cert via DNS-01 (`instant-acme`)
- `api.clwd.run` — control plane

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
