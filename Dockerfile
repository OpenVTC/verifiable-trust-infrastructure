# =============================================================================
# VTA Non-TEE Image
# =============================================================================
#
# Plain Docker image running the ordinary `vta` server binary on a normal host
# (EC2, ECS, Kubernetes, a laptop). Use `Dockerfile.nitro` for AWS Nitro
# Enclave / TEE deployments — that image has a different feature set, a
# vsock-proxy entrypoint, and is consumed by `nitro-cli build-enclave`.
#
# Usage:
#   docker build -t vta .
#   docker build --build-arg FEATURES="setup,rest,didcomm" -t vta .
#
# CACHING: dependency builds are cached with cargo-chef. `prepare` distils the
# workspace into a recipe.json describing only the dependency graph; `cook`
# builds that. The expensive dependency layer is therefore keyed on the recipe
# and is reused until a dependency actually changes — a source edit does not
# invalidate it.
#
# Deliberately NOT the manifests-plus-dummy-sources trick `Dockerfile.nitro`
# uses. That approach hand-maintains the list of workspace members four times
# over (COPY manifests, mkdir, dummy sources, COPY sources) and warms the cache
# under `|| true`, so forgetting to add a new crate is silent: you get a
# full-from-scratch dependency rebuild on every build and no error saying why.
# cargo-chef derives the member list from the workspace itself, so adding a
# crate needs no edit here.
# =============================================================================

ARG RUST_VERSION=1.95
# Pinned: cargo-chef's recipe format is tied to its version, and an unpinned
# `cargo install` would silently change the cache key across builds.
ARG CARGO_CHEF_VERSION=0.1.78

# -----------------------------------------------------------------------------
# Stage 1: toolchain + cargo-chef (shared base for planner and builder)
# -----------------------------------------------------------------------------
FROM rust:${RUST_VERSION}-bookworm AS chef
ARG CARGO_CHEF_VERSION
RUN cargo install cargo-chef --locked --version ${CARGO_CHEF_VERSION}
WORKDIR /build

# -----------------------------------------------------------------------------
# Stage 2: plan — reduce the workspace to its dependency graph
# -----------------------------------------------------------------------------
FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

# -----------------------------------------------------------------------------
# Stage 3: build the VTA server binary
# -----------------------------------------------------------------------------
FROM chef AS builder

# Build deps for the non-TEE feature set. libdbus-1-dev is required because
# affinidi-tdk-common (pulled transitively via didcomm/vta-sdk) depends on
# dbus-secret-service-keyring-store, which links libdbus at build time. That is
# independent of VTA's own vti-secrets keyring backend, which is feature-gated
# and off here.
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        clang \
        cmake \
        libdbus-1-dev \
        libssl-dev \
        pkg-config && \
    rm -rf /var/lib/apt/lists/*

# Feature flags for the plain non-TEE image. Override with:
#   docker build --build-arg FEATURES="setup,rest,didcomm,aws-secrets" .
# `keyring` is intentionally excluded — containers have no desktop
# secret-service session. `aws-secrets` reads the instance/task role via IMDS.
ARG FEATURES="setup,rest,didcomm,cli-synthesis,aws-secrets,webvh"

# Dependency layer. No `--locked` here: cook builds from the recipe rather than
# the real manifests, and the flag buys nothing for a warm-up whose output is
# discarded. The real build below is locked, which is where it matters.
COPY --from=planner /build/recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json \
        --package vta-service \
        --no-default-features --features ${FEATURES}

# Source layer. `--locked` so the image is built against the committed
# Cargo.lock and cannot silently resolve a different dependency set than CI
# tested.
COPY . .
RUN cargo build --release --locked --package vta-service \
        --no-default-features --features ${FEATURES}

# -----------------------------------------------------------------------------
# Stage 4: runtime
# -----------------------------------------------------------------------------
FROM debian:bookworm-slim AS runtime

# libdbus-1-3 is the runtime half of the libdbus-1-dev link above; wget backs
# the HEALTHCHECK.
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        ca-certificates \
        libdbus-1-3 \
        wget && \
    rm -rf /var/lib/apt/lists/* && \
    useradd --uid 1000 --system --home-dir /var/lib/vta --create-home --shell /usr/sbin/nologin vta && \
    mkdir -p /var/lib/vta /etc/vta && \
    chown -R vta:vta /var/lib/vta /etc/vta

COPY --from=builder /build/target/release/vta /usr/local/bin/vta

USER vta
EXPOSE 8100
VOLUME ["/var/lib/vta"]

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD wget -qO- http://localhost:8100/health || exit 1

ENTRYPOINT ["/usr/local/bin/vta"]
CMD ["--config", "/etc/vta/config.toml"]
