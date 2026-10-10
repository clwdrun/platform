# platform workspace tasks
#
# `check` grows as the crates gain code and as CI lands; what is in it is what
# is verified green on `main`. A gate that is red on a clean checkout teaches
# people to ignore it.

set shell := ["bash", "-uc"]

default:
    @just --list

# ==========================================
# 1. GATE
# ==========================================

# The gate. Ordered to fail cheapest first.
# `migrate` runs before anything that compiles the workspace: sqlx checks its
# queries against the live database at macro expansion, so a fresh `just db-up`
# with no schema fails `clippy` rather than failing something about schema.
check: secrets fmt-check seam rollback-plans migrate clippy sqlx-prepared offline-build migrate-roundtrip test envelope-probe openapi-check deny

# Secret scan over full history. This repository is private, so GitHub's own
# secret scanning and push protection — both Advanced Security features — are
# unavailable. `detect` walks every commit rather than the working tree,
# because a credential already committed is the case that matters.
#
# Fails loudly when gitleaks is absent. A check that no-ops without its tool
# is worse than no check: it reports green.
[doc('secret scan over full history (needs gitleaks)')]
secrets:
    #!/usr/bin/env bash
    set -uo pipefail
    if ! command -v gitleaks >/dev/null 2>&1; then
      echo "error: gitleaks is not installed — install it or this gate is a lie"
      echo "       https://github.com/gitleaks/gitleaks#installing"
      exit 1
    fi
    gitleaks detect --no-banner --redact --exit-code 1

# Install the pre-commit hook. Catching a credential before the commit is a
# non-event; catching it after a push is a rotation.
[doc('install the gitleaks pre-commit hook')]
hooks:
    git config core.hooksPath .githooks
    @echo "ok: core.hooksPath -> .githooks"

fmt:
    cargo fmt --all

fmt-check:
    cargo fmt --all --check

clippy:
    cargo clippy --workspace --all-targets -- -D warnings

# Needs a database: the schema tests run against a real Postgres, because a
# CHECK constraint that is only asserted in Rust is not a constraint.
[doc('cargo test --workspace (needs a database)')]
test:
    cargo test --workspace

# The envelope probe's counts, printed where a reader of the gate sees them.
#
# The probe already runs and asserts inside `test`, but `cargo test` hides a
# passing test's output — so the count that proves every error response is an
# envelope was asserted and invisible. That is a check reporting its colour
# instead of its count. This runs the probe again with output shown and fails
# unless both count lines appear, so it cannot pass by printing nothing.
#
# `--workspace --lib` rather than `-p control-plane`: `-p` resolves features for
# one crate, not the workspace, so it rebuilt every dependency a second time in
# a second feature set. The name filter still selects only this test.
[doc('print the envelope probe counts: bare error responses, with and without conversion (needs a database)')]
envelope-probe:
    #!/usr/bin/env bash
    set -uo pipefail
    if ! out=$(cargo test --workspace --lib every_error_response_from_every_route -- --nocapture 2>&1); then
      printf '%s\n' "$out" | tail -60
      echo "error: the envelope probe failed"
      exit 1
    fi
    # Matched anywhere on a line, not at its start: the test harness can print its
    # own progress on the same line as the test's output.
    lines=$(printf '%s\n' "$out" | grep -oE 'envelope probe, .*' || true)
    if [ "$(printf '%s\n' "$lines" | grep -c .)" -ne 3 ]; then
      printf '%s\n' "$out" | tail -40
      echo "error: the envelope probe passed without reporting all three counts"
      exit 1
    fi
    printf '%s\n' "$lines"

# The OpenAPI document's counts, printed where a reader of the gate sees them:
# routes documented, schema validity and resolved references, examples checked
# against their schemas, and error codes carrying meaning and hint. Fails unless
# all four lines appear, for the same reason as `envelope-probe`.
[doc('check the committed OpenAPI document and print its counts')]
openapi-check:
    #!/usr/bin/env bash
    set -uo pipefail
    if ! out=$(cargo test --workspace --lib openapi::tests -- --nocapture --test-threads=1 2>&1); then
      printf '%s\n' "$out" | tail -60
      echo "error: the OpenAPI checks failed"
      exit 1
    fi
    lines=$(printf '%s\n' "$out" | grep -oE '(routes documented|openapi document|openapi examples|error codes documented).*' || true)
    if [ "$(printf '%s\n' "$lines" | grep -c .)" -ne 4 ]; then
      printf '%s\n' "$out" | tail -40
      echo "error: the OpenAPI checks passed without reporting all four counts"
      exit 1
    fi
    printf '%s\n' "$lines"

# Regenerate the OpenAPI document from the route table. Written to a temporary
# file first, so a failed build cannot leave an empty document behind — which
# `include_str!` would then embed.
[doc('regenerate crates/control-plane/openapi.json from the route table')]
openapi:
    #!/usr/bin/env bash
    set -euo pipefail
    tmp=$(mktemp)
    cargo run -q -p control-plane -- openapi > "$tmp"
    mv "$tmp" crates/control-plane/openapi.json
    chmod 644 crates/control-plane/openapi.json
    echo "ok: wrote crates/control-plane/openapi.json ($(wc -c < crates/control-plane/openapi.json) bytes)"

deny:
    cargo deny check --hide-inclusion-graph

# The public/private seam, as two greps.
#
# The first: no dependency may reach into a sibling clwd checkout. A path dep
# across the two repositories works on a laptop, breaks CI, and lets private
# types leak into public crates. Path deps *within* this workspace are fine and
# expected — `../shared` does not match.
#
# The second: every git dependency must be pinned to a tag. Read from
# Cargo.lock rather than the manifests, so it sees the resolved source and is
# not defeated by a dependency spelled across several lines. `cargo deny`'s
# `unknown-git = "deny"` covers the origin; this covers the pin. #8 owns
# hardening both into CI.
[doc('no path dep escapes the workspace; every git dep is tag-pinned')]
seam:
    #!/usr/bin/env bash
    set -uo pipefail
    if grep -rn --include='Cargo.toml' -E 'path *= *"[^"]*(\.\./\.\.|clwd)' Cargo.toml crates/; then
      echo "error: a path dependency reaches outside this workspace — see docs/development.md"
      exit 1
    fi
    unpinned=$(grep -n 'source = "git+' Cargo.lock | grep -v '?tag=' || true)
    if [ -n "$unpinned" ]; then
      echo "error: a git dependency is not pinned to a tag"
      echo "$unpinned"
      exit 1
    fi
    echo "ok: no path dependency escapes the workspace; every git dependency is tag-pinned"

# Migrations are forward-only, so a destructive one has no `down` to run and
# the plan has to be written down instead. Deliberately over-matches — a
# migration that merely mentions dropping something still has to say what
# reverting it would mean, and writing that sentence is cheaper than arguing
# with the grep.
[doc('every destructive migration carries a rollback plan')]
rollback-plans:
    #!/usr/bin/env bash
    set -uo pipefail
    missing=""
    for f in migrations/*.sql; do
      if grep -qiE '\b(drop|truncate|rename)\b' "$f" && ! grep -q 'ROLLBACK PLAN' "$f"; then
        missing="${missing}  ${f}"$'\n'
      fi
    done
    if [ -n "$missing" ]; then
      echo "error: destructive migration with no ROLLBACK PLAN comment:"
      printf '%s' "$missing"
      exit 1
    fi
    echo "ok: every destructive migration carries a rollback plan"

# .sqlx is what lets CI build with no database. It rots silently the moment a
# query changes, so the gate checks it rather than trusting it.
[doc('.sqlx is current for every query, including the tests')]
sqlx-prepared:
    cargo sqlx prepare --workspace --check -- --all-targets

# The claim that CI needs no database, proven by removing the variable rather
# than by assertion.
[doc('the workspace builds with no database reachable')]
offline-build:
    env -u DATABASE_URL SQLX_OFFLINE=true cargo check --workspace --all-targets

# Empty to head against a throwaway database, then drop it. `sqlx migrate run`
# on a database that already has the schema proves nothing.
[doc('migrations run empty to head on a throwaway database')]
migrate-roundtrip:
    #!/usr/bin/env bash
    set -euo pipefail
    : "${DATABASE_URL:?DATABASE_URL is unset — run \`just db-up\` first}"
    scratch="${DATABASE_URL%/*}/clwd_migrate_check"
    sqlx database drop -y --database-url "$scratch" >/dev/null 2>&1 || true
    sqlx database create --database-url "$scratch"
    sqlx migrate run --database-url "$scratch"
    sqlx database drop -y --database-url "$scratch"
    echo "ok: migrations run from empty to head"

# ==========================================
# 2. DATABASE
# ==========================================

# A throwaway Postgres for the tests. Nothing in it is worth keeping.
[doc('start a throwaway Postgres for the tests')]
db-up:
    #!/usr/bin/env bash
    set -euo pipefail
    docker rm -f clwd-pg >/dev/null 2>&1 || true
    docker run -d --name clwd-pg \
      -e POSTGRES_USER=postgres -e POSTGRES_PASSWORD=postgres \
      -p 55432:5432 postgres:18 >/dev/null
    until docker exec clwd-pg pg_isready -U postgres >/dev/null 2>&1; do sleep 0.2; done
    echo 'DATABASE_URL=postgres://postgres:postgres@localhost:55432/clwd_platform'
    echo 'export it, or put it in .env (gitignored)'

db-down:
    docker rm -f clwd-pg

# A local ACME test environment: Pebble (a test ACME CA) plus challtestsrv (a
# mock DNS server with an HTTP API to set TXT records). The certificate
# issuance test (`crates/control-plane/tests/acme_issue.rs`) drives real ACME
# against this — and fails RED if it is not up, never skips. See the test's
# header for what this harness does and does NOT prove (no real rate limits,
# no real ARI, no real propagation latency).
[doc('start Pebble + challtestsrv for the ACME issuance test')]
pebble-up:
    #!/usr/bin/env bash
    set -euo pipefail
    docker rm -f clwd-pebble clwd-challtestsrv >/dev/null 2>&1 || true
    docker network create clwd-acme >/dev/null 2>&1 || true
    docker run -d --name clwd-challtestsrv --network clwd-acme \
      -p 8055:8055 ghcr.io/letsencrypt/pebble-challtestsrv:latest \
      -dnsserver :8053 -management :8055 -http01 "" -https01 "" -tlsalpn01 "" -doh "" >/dev/null
    docker run -d --name clwd-pebble --network clwd-acme \
      -e PEBBLE_VA_NOSLEEP=1 -p 14000:14000 ghcr.io/letsencrypt/pebble:latest \
      -config /test/config/pebble-config.json -dnsserver clwd-challtestsrv:8053 >/dev/null
    # The CA that signs Pebble's ACME directory cert — the test must trust it.
    cid=$(docker create ghcr.io/letsencrypt/pebble:latest)
    mkdir -p .pebble
    docker cp "$cid:/test/certs/pebble.minica.pem" .pebble/pebble.minica.pem >/dev/null
    docker rm "$cid" >/dev/null
    # Bounded wait: an unbounded `until` would hang CI to the job timeout if a
    # container failed to start, reading as a hang rather than the startup
    # failure it is.
    for _ in $(seq 1 100); do
      curl -ks https://localhost:14000/dir >/dev/null 2>&1 && break
      sleep 0.2
    done
    if ! curl -ks https://localhost:14000/dir >/dev/null 2>&1; then
      echo "error: Pebble did not become ready; logs follow" >&2
      docker logs clwd-pebble 2>&1 | tail -20 >&2
      exit 1
    fi
    echo 'PEBBLE_DIR=https://localhost:14000/dir'
    echo 'CHALLTESTSRV=http://localhost:8055'
    echo 'PEBBLE_CA='"$(pwd)"'/.pebble/pebble.minica.pem'
    echo 'export these, or the ACME test reads the defaults above'

[doc('stop Pebble + challtestsrv')]
pebble-down:
    docker rm -f clwd-pebble clwd-challtestsrv >/dev/null 2>&1 || true
    docker network rm clwd-acme >/dev/null 2>&1 || true

# `database create` first, and it is a no-op when the database is already
# there. Without it the gate assumes a database someone made by hand, which is
# exactly the assumption CI does not get to make.
[doc('create the database if needed, then run migrations')]
migrate:
    sqlx database create
    sqlx migrate run

# Re-record .sqlx after changing a query. --all-targets so the tests' queries
# are cached too, or the offline build fails on them.
[doc('re-record .sqlx after changing a query')]
prepare:
    cargo sqlx prepare --workspace -- --all-targets
