# platform (private)

Control plane, scheduler, identity/sharing, billing, and enterprise audit
for clwd. Depends on the public `clwd-bundle` crate via a tag-pinned git
dependency — never a path dependency across the two checkouts. See
`docs/development.md` for the seam rules and how to bump the pin.

## Crates

- `control-plane` — apps, orgs, versions, share grants (axum + sqlx)
- `gateway` — routing, TLS, identity injection, cold-start hold (pingora)
- `identity` — SSO in, per-app authz out (cedar-policy)
- `builder` — bundle -> content-addressed artifact
- `app-data` — per-app DB/blob/secret broker
- `shared` — wire types, tracing/otel setup
