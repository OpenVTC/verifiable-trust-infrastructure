# =============================================================================
# VTA Non-TEE Image
# =============================================================================
#
# Plain Docker image for running the ordinary `vta` server binary on a normal
# EC2 instance or other non-TEE host. Use Dockerfile.nitro for AWS Nitro
# Enclave / TEE deployments.
# =============================================================================

# -----------------------------------------------------------------------------
# Stage 1: Build the VTA server binary
# -----------------------------------------------------------------------------
FROM rust:1.95-bookworm AS builder

# Build deps for the selected non-TEE feature set. libdbus-1-dev is required
# because affinidi-tdk-common (pulled transitively via didcomm/vta-sdk) depends
# on dbus-secret-service-keyring-store, which links libdbus at build time. This
# is independent of VTA's own vti-secrets keyring backend (feature-gated, unused
# here since we use aws-secrets).
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        clang \
        cmake \
        libdbus-1-dev \
        libssl-dev \
        pkg-config && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Cache dependency builds: copy workspace manifests first, create dummy sources,
# build deps, then copy real sources and rebuild changed crates.
COPY Cargo.toml Cargo.lock ./
COPY cnm-cli/Cargo.toml cnm-cli/Cargo.toml
COPY didcomm-test/Cargo.toml didcomm-test/Cargo.toml
COPY pnm-cli/Cargo.toml pnm-cli/Cargo.toml
COPY tests/e2e/Cargo.toml tests/e2e/Cargo.toml
COPY vta-cli-common/Cargo.toml vta-cli-common/Cargo.toml
COPY vta-config/Cargo.toml vta-config/Cargo.toml
COPY vta-keyspaces/Cargo.toml vta-keyspaces/Cargo.toml
COPY vta-audit/Cargo.toml vta-audit/Cargo.toml
COPY vta-backup/Cargo.toml vta-backup/Cargo.toml
COPY vta-keys/Cargo.toml vta-keys/Cargo.toml
COPY vta-policy/Cargo.toml vta-policy/Cargo.toml
COPY vta-support/Cargo.toml vta-support/Cargo.toml
COPY vta-tee/Cargo.toml vta-tee/Cargo.toml
COPY vta-sweepers/Cargo.toml vta-sweepers/Cargo.toml
COPY vta-vault/Cargo.toml vta-vault/Cargo.toml
COPY vta-webvh/Cargo.toml vta-webvh/Cargo.toml
COPY vta-mcp/Cargo.toml vta-mcp/Cargo.toml
COPY vta-mobile-core/Cargo.toml vta-mobile-core/Cargo.toml
COPY vta-sdk/Cargo.toml vta-sdk/Cargo.toml
COPY vta-service/Cargo.toml vta-service/Cargo.toml
COPY vta-enclave/Cargo.toml vta-enclave/Cargo.toml
COPY vtc-client/Cargo.toml vtc-client/Cargo.toml
COPY vtc-service/Cargo.toml vtc-service/Cargo.toml
COPY vti-common/Cargo.toml vti-common/Cargo.toml
COPY vti-secrets/Cargo.toml vti-secrets/Cargo.toml
COPY vti-webauthn/Cargo.toml vti-webauthn/Cargo.toml

RUN mkdir -p \
        cnm-cli/src \
        didcomm-test/src \
        pnm-cli/src \
        tests/e2e/tests \
        vta-cli-common/src \
        vta-config/src \
        vta-keyspaces/src \
        vta-audit/src \
        vta-backup/src \
        vta-keys/src \
        vta-policy/src \
        vta-support/src \
        vta-tee/src \
        vta-sweepers/src \
        vta-vault/src \
        vta-webvh/src \
        vta-mcp/src \
        vta-mobile-core/src/bin \
        vta-sdk/src \
        vta-service/src \
        vta-enclave/src \
        vtc-client/src \
        vtc-service/src \
        vti-common/src \
        vti-secrets/src \
        vti-webauthn/src && \
    echo 'fn main() {}' > cnm-cli/src/main.rs && \
    echo 'fn main() {}' > didcomm-test/src/main.rs && \
    echo 'fn main() {}' > pnm-cli/src/main.rs && \
    echo '#[test] fn dummy() {}' > tests/e2e/tests/dummy.rs && \
    echo 'pub fn dummy() {}' > vta-cli-common/src/lib.rs && \
    echo 'pub fn dummy() {}' > vta-config/src/lib.rs && \
    echo 'pub fn dummy() {}' > vta-keyspaces/src/lib.rs && \
    echo 'pub fn dummy() {}' > vta-audit/src/lib.rs && \
    echo 'pub fn dummy() {}' > vta-backup/src/lib.rs && \
    echo 'pub fn dummy() {}' > vta-keys/src/lib.rs && \
    echo 'pub fn dummy() {}' > vta-policy/src/lib.rs && \
    echo 'pub fn dummy() {}' > vta-support/src/lib.rs && \
    echo 'pub fn dummy() {}' > vta-tee/src/lib.rs && \
    echo 'pub fn dummy() {}' > vta-sweepers/src/lib.rs && \
    echo 'pub fn dummy() {}' > vta-vault/src/lib.rs && \
    echo 'pub fn dummy() {}' > vta-webvh/src/lib.rs && \
    echo 'fn main() {}' > vta-mcp/src/main.rs && \
    echo 'pub fn dummy() {}' > vta-mobile-core/src/lib.rs && \
    echo 'fn main() {}' > vta-mobile-core/src/bin/uniffi-bindgen.rs && \
    echo 'pub fn dummy() {}' > vta-sdk/src/lib.rs && \
    echo 'pub fn dummy() {}' > vta-service/src/lib.rs && \
    echo 'fn main() {}' > vta-service/src/main.rs && \
    echo 'fn main() {}' > vta-enclave/src/main.rs && \
    echo 'pub fn dummy() {}' > vtc-client/src/lib.rs && \
    echo 'fn main() {}' > vtc-service/src/main.rs && \
    echo 'pub fn dummy() {}' > vti-common/src/lib.rs && \
    echo 'pub fn dummy() {}' > vti-secrets/src/lib.rs && \
    echo 'pub fn dummy() {}' > vti-webauthn/src/lib.rs

# Feature flags for the plain non-TEE VTA image. Override with:
#   docker build --build-arg FEATURES="setup,rest,didcomm,cli-synthesis,aws-secrets,webvh" .
# Keyring is intentionally excluded because containers lack the required
# desktop secret-service session; aws-secrets uses the EC2 instance role via IMDS.
ARG FEATURES="setup,rest,didcomm,cli-synthesis,aws-secrets,webvh"

RUN cargo build --release --package vta-service \
    --no-default-features --features ${FEATURES} \
    2>/dev/null || true

COPY cnm-cli/ cnm-cli/
COPY didcomm-test/ didcomm-test/
COPY pnm-cli/ pnm-cli/
COPY tests/e2e/ tests/e2e/
COPY vta-cli-common/ vta-cli-common/
COPY vta-config/ vta-config/
COPY vta-keyspaces/ vta-keyspaces/
COPY vta-audit/ vta-audit/
COPY vta-backup/ vta-backup/
COPY vta-keys/ vta-keys/
COPY vta-policy/ vta-policy/
COPY vta-support/ vta-support/
COPY vta-tee/ vta-tee/
COPY vta-sweepers/ vta-sweepers/
COPY vta-vault/ vta-vault/
COPY vta-webvh/ vta-webvh/
COPY vta-mcp/ vta-mcp/
COPY vta-mobile-core/ vta-mobile-core/
COPY vta-sdk/ vta-sdk/
COPY vta-service/ vta-service/
COPY vta-enclave/ vta-enclave/
COPY vtc-client/ vtc-client/
COPY vtc-service/ vtc-service/
COPY vti-common/ vti-common/
COPY vti-secrets/ vti-secrets/
COPY vti-webauthn/ vti-webauthn/

RUN find \
        cnm-cli/src \
        didcomm-test/src \
        pnm-cli/src \
        tests/e2e/tests \
        vta-cli-common/src \
        vta-config/src \
        vta-keyspaces/src \
        vta-audit/src \
        vta-backup/src \
        vta-keys/src \
        vta-policy/src \
        vta-support/src \
        vta-tee/src \
        vta-sweepers/src \
        vta-vault/src \
        vta-webvh/src \
        vta-mcp/src \
        vta-mobile-core/src \
        vta-sdk/src \
        vta-service/src \
        vta-enclave/src \
        vtc-client/src \
        vtc-service/src \
        vti-common/src \
        vti-secrets/src \
        vti-webauthn/src \
        -name '*.rs' -exec touch {} +

RUN cargo build --release --package vta-service \
    --no-default-features --features ${FEATURES}

# -----------------------------------------------------------------------------
# Stage 2: Runtime image
# -----------------------------------------------------------------------------
FROM debian:bookworm-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates wget libdbus-1-3 && \
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
