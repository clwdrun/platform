# syntax=docker/dockerfile:1
#
# One Dockerfile, one build argument. control-plane and gateway differ only in
# which binary comes out, so two near-identical Dockerfiles would be two places
# to forget the same fix.

ARG RUST_VERSION=1.97.1

FROM rust:${RUST_VERSION}-slim-bookworm AS build
ARG BIN
WORKDIR /src

# pkg-config and libssl-dev: openidconnect reaches reqwest with default
# features on, which pulls native-tls. cmake: pingora's tree needs it.
# Recorded here rather than discovered from a build failure — and both go away
# with #9, which turns those default features off.
RUN apt-get update \
 && apt-get install -y --no-install-recommends pkg-config libssl-dev cmake \
 && rm -rf /var/lib/apt/lists/*

COPY . .

# No database at image build time. `.sqlx` is committed for exactly this: the
# query macros read the cached metadata instead of connecting.
ENV SQLX_OFFLINE=true

# --locked so the image is built from the resolved dependency set in the
# repository, not whatever cargo would pick today. The target directory is a
# cache mount, so the binary has to be copied out inside the same layer.
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/src/target,sharing=locked \
    cargo build --release --locked -p "$BIN" --bin "$BIN" \
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
