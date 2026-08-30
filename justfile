# platform workspace tasks
#
# Deliberately thin. Track A and Track B extend `check` as the crates gain
# code and as CI lands; what is here is what is verified green on `main`
# today. A gate that is red on a clean checkout teaches people to ignore it.

set shell := ["bash", "-uc"]

default:
    @just --list

# The gate. Ordered to fail cheapest first.
check: secrets fmt-check

# Secret scan over full history. This repository is private, so GitHub's own
# secret scanning and push protection — both Advanced Security features — are
# unavailable. `detect` walks every commit rather than the working tree,
# because a credential already committed is the case that matters.
#
# Fails loudly when gitleaks is absent. A check that no-ops without its tool
# is worse than no check: it reports green.
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
hooks:
    git config core.hooksPath .githooks
    @echo "ok: core.hooksPath -> .githooks"

fmt:
    cargo fmt --all

fmt-check:
    cargo fmt --all --check
