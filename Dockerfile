# syntax=docker/dockerfile:1
#
# One Dockerfile, one build argument. control-plane and gateway differ only in
# which binary comes out, so two near-identical Dockerfiles would be two places
# to forget the same fix.

ARG RUST_VERSION=1.97.1

FROM rust:${RUST_VERSION}-slim-bookworm AS build
ARG BIN
WORKDIR /src

# Native toolchain the dependency tree needs. Named individually, because
# "build-essential" would hide which dependency wants what:
#
#   pkg-config, libssl-dev  openidconnect reaches reqwest with default features
#                           on, which pulls native-tls. Goes away with #9.
#   cmake, make, g++        pingora -> flate2 -> libz-ng-sys builds zlib-ng
#                           with cmake, which needs a make program and a C++
#                           compiler. rust:slim ships gcc but neither of those.
#   libclang-dev            pingora -> boring-sys builds BoringSSL through
#                           bindgen, which needs libclang at build time. Without
#                           it the gateway image fails with "Unable to find
#                           libclang" while control-plane (no boring) builds.
#   git, ca-certificates    the seam dependency is a private git repository, and
#                           cargo's built-in fetcher cannot carry credentials.
#                           CARGO_NET_GIT_FETCH_WITH_CLI hands the fetch to git,
#                           which can — the same arrangement ci.yml uses.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      pkg-config libssl-dev cmake make g++ libclang-dev git ca-certificates \
 && rm -rf /var/lib/apt/lists/*

COPY . .

# No database at image build time. `.sqlx` is committed for exactly this: the
# query macros read the cached metadata instead of connecting.
ENV SQLX_OFFLINE=true

# --locked so the image is built from the resolved dependency set in the
# repository, not whatever cargo would pick today. The target directory is a
# cache mount, so the binary has to be copied out inside the same layer.
#
# The token arrives as a BuildKit secret, never a build argument: build
# arguments are recorded in image history and readable by anyone who can pull
# the image. A secret mount exists only for the life of this RUN and lands in
# no layer.
#
# It is read from the mounted file inside the shell rather than interpolated
# into the RUN text, so the credential never appears in the build record
# either. GIT_CONFIG_* is used in preference to `git config --global`, which
# would persist the token into the builder stage's filesystem — discarded here,
# but still written, and still in the layer cache.
RUN --mount=type=secret,id=clwd_token \
    --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/src/target,sharing=locked \
    export CARGO_NET_GIT_FETCH_WITH_CLI=true \
 && export GIT_CONFIG_COUNT=1 \
 && export GIT_CONFIG_KEY_0="url.https://x-access-token:$(cat /run/secrets/clwd_token)@github.com/.insteadOf" \
 && export GIT_CONFIG_VALUE_0="https://github.com/" \
 && cargo build --release --locked -p "$BIN" --bin "$BIN" \
 && cp "target/release/$BIN" /usr/local/bin/service

FROM debian:bookworm-slim AS runtime

# ca-certificates because both services make outbound TLS calls — to the
# identity provider, to object storage, to ACME.
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --system --uid 10001 --shell /usr/sbin/nologin --no-create-home clwd

COPY --from=build /usr/local/bin/service /usr/local/bin/service

# Non-root by uid rather than name, so the numeric id survives a base image
# whose passwd file differs, and a read-only root filesystem stays possible.
USER 10001:10001
ENTRYPOINT ["/usr/local/bin/service"]
