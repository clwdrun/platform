# Development notes — platform (private)

Private workspace for clwd: control plane, gateway, identity/sharing, builder, and
per-app data brokering. Nothing here is published; `publish = false` at the
workspace level. The sandbox runtime, CLI, and SDK are open source in
`github.com/clwdrun/clwd` and consumed from here as a dependency.

## Commands

```bash
cargo build --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all

sqlx migrate run                     # needs DATABASE_URL
cargo sqlx prepare --workspace       # regenerate offline query data after SQL changes
```

`sqlx` macros are compile-time checked. After changing any query or migration, run
`cargo sqlx prepare` and commit the generated `.sqlx/` directory, or CI will fail
without a live database.

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

**Depend on `clwd-sdk` via a tag-pinned git dependency, never a path dependency.**

```toml
clwd-sdk = { git = "https://github.com/clwdrun/clwd", tag = "v0.1.0" }
```

A path dep across the two checkouts works on a laptop, breaks CI, and lets private
types leak into public crates — the exact thing the split exists to prevent. Bump
the tag deliberately; do not track a branch.

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
