# VTA on AWS Nitro Enclaves — Deployment Guide

Deploy the Verifiable Trust Agent (VTA) inside an AWS Nitro Enclave with
hardware-backed TEE attestation, KMS-based secret bootstrap, encrypted
storage, and signed enclave images.

> **Config baking is a build-time choice (`BAKE_CONFIG`, default = baked).**
> By default `config.toml` **is baked into the EIF** — best for single-tenant /
> self-hosted deploys: the config is committed to PCR0 and fully attested, and no
> runtime config server is needed. Build with `--build-arg BAKE_CONFIG=false`
> (or `VTA_BAKE_CONFIG=false ./build-vta.sh`) to bake only
> `config.fleet-base.toml` (the PCR0-committed **fleet policy** + placeholders)
> and ship **no tenant-specific config**, so **one image / one PCR0 serves every
> tenant** — the multi-tenant / managed-fleet mode. In that mode tenant values
> are delivered at runtime (base-plus-overlay) and **changing them no longer
> changes PCR0**.
>
> **Un-baked delivery (BAKE_CONFIG=false) — typed tenant overlay.** The fleet
> image bakes `config.fleet-base.toml` (the PCR0-committed **fleet policy** plus
> placeholders). At runtime the parent serves a small typed **overlay**
> (`{ "version":1, "overlay":{…}, "integrity":null }`) over **vsock port 5800**;
> `enclave-proxy --config-envelope …` (or `parent-proxy.sh`) starts that server
> when a rendered overlay file is present. The `vta-enclave` binary — built with
> the `tenant-overlay` feature for this mode — fetches the overlay, parses it into
> a `#[serde(deny_unknown_fields)]` allowlist, validates it, and applies it onto
> the baked base **in-process** before boot. The entrypoint no longer touches
> config; the fetch/size-cap/timeout/validation all live in Rust
> (`vta-tee::tenant_overlay`, unit-tested).
>
> **Only the tenant-scoped fields are overlay-settable** — `tee.kms.key_arn`
> (validated against the baked `tee.allowed_kms_accounts`; region is derived from
> the ARN), `tee.kms.vta_did_template`, `messaging.mediator_did`/
> `mediator_url`, `public_url`, `vta_name`, and the KMS-sealed anchor fields.
> Everything else — `tee.mode`, every `allow_*` break-glass flag, `admin_did`,
> `resolver_url`, `server.*`, `store.*`, `policy.*`, **and a bare `vta_did`** — is
> baked or provisioned in-enclave and **structurally cannot** be carried by the
> overlay type. (The VTA's own identity is *provisioned* from
> `vta_did_template` — the enclave derives the keys and signs the `did:webvh`
> document; a bare DID string with no key records is not accepted. See ADR-0109.)
> Render a per-tenant overlay with:
>
> ```bash
> deploy/nitro/render-tenant-overlay.sh \
>   --key-arn arn:aws:kms:us-east-1:1122...:key/abcd \
>   --mediator-did did:webvh:...:mediator \
>   --vta-did-template 'did:webvh:{SCID}:acme.example.com:vta' > tenant-overlay.json
> ```
>
> **`tee.allowed_kms_accounts` is a required fleet setting** (baked, PCR0-
> committed): empty ⇒ **no tenant may onboard** (fail closed, not allow-all).
> `build-vta.sh` fills it from the KMS key's account for you. This PCR0-anchored
> allowlist is an **independent** gate that sits alongside — not instead of — each
> tenant's KMS key policy scoping the calling principal (one image / one PCR0 is
> shared across tenants, so key-policy isolation is still required).
>
> **Fail-closed:** on real Nitro a failed overlay fetch/parse/validate **aborts
> the boot** (it never falls through to the placeholder base). Exactly one process
> may own `vsock:5800` — `parent-proxy.sh`/`enclave-proxy`, or an orchestrated
> deployment's own config server — never both.
>
> **Enforcement floor (defense-in-depth):** on real Nitro hardware (`/dev/nsm`
> present) the enclave still refuses to boot if a parent-influenced config would
> weaken `[tee] mode` below `required`, omit `[tee.kms]`, or set `[tee.kms]
> admin_did`. With the typed overlay those can no longer be *delivered* at all —
> the floor now guards against a bug in the merge, not a malicious parent. Leave
> `admin_did` unset and use the attested sealed-bootstrap flow (Mode B,
> `POST /bootstrap/request`).
>
> **Config attestation anchor — and the verification step it REQUIRES.** Because
> the parent supplies `tee.kms.key_arn`, on first boot the enclave generates its
> seed and encrypts it under whatever key the config named; if that key is one the
> parent controls, the seed is recoverable off-box. The mitigation is the anchor:
> at boot the enclave commits a SHA-384 digest of the delivered config into an NSM
> attestation document (`user_data`) and logs it. PCR0 stays tenant-agnostic, and
> the AWS-signed document proves which config (hence which `key_arn`) the enclave
> booted.
>
> **This is a required verification step, and there is a pull endpoint for it.**
> The boot-time anchor only *produces* signed evidence (log-only, empty nonce) —
> so verification is a **mandatory onboarding gate**, not an automatic property:
>
> > Before onboarding a tenant / trusting a VTA instance, the tenant (or an
> > independent verifier — NOT the parent operator) MUST obtain a fresh config
> > attestation and verify: (1) its signature chains to the AWS Nitro root,
> > (2) `PCR0` matches the pinned image, (3) the bound `nonce` equals the one they
> > sent, and (4) the committed config digest (`user_data`) matches the config
> > the enclave returned — in particular that `tee.kms.key_arn` is the tenant's own
> > key, not one the parent controls.
>
> Use **`POST /attestation/config-report`** with a fresh caller nonce:
>
> ```bash
> curl -s https://<vta>/attestation/config-report \
>   -H 'content-type: application/json' -d '{"nonce":"<hex>"}'
> # → { configDigestSha384, configView (base64), nonce, teeType,
> #     evidence (base64 COSE_Sign1), generatedAt }
> ```
>
> `configView` is the **canonical, secret-free view of the effective config the
> enclave actually booted** — the exact bytes whose SHA-384 the enclave signed as
> `user_data`. The nonce is bound for freshness, so — unlike the boot log — the
> parent **cannot forge or replay** the report (it can still drop the request or
> response; availability stays under the parent, but a *stale/forged* report is
> rejected). Verify with **`vta_sdk::attestation::verify_config_attestation`**
> (feature `attest-verify`) — no `vta-config` dependency, no digest re-derivation:
>
> ```rust
> use vta_sdk::attestation::verify_config_attestation;
> let verified = verify_config_attestation(
>     &resp.evidence,        // base64 COSE_Sign1 from the response
>     &resp.config_view,     // base64 canonical view from the response
>     &nonce,                // the exact nonce bytes you sent
>     &expected_pcr0,        // REQUIRED: pin the approved image measurement
>     Some(&expected_pcr8),  // optional: pin the signing-cert measurement
>     Some(&expected_key_arn), // enforce the tenant's own KMS key
> )?;
> // On success: chain-to-root, PCR0 (+PCR8), nonce, view→digest binding, and
> // key_arn are all verified. The SDK hashes `config_view` and checks it equals
> // the signed `user_data`, so the returned view is authentic; it then enforces
> // `tee.kms.key_arn`. Read further with `verified.config_view_json()`.
> ```
>
> PCR0 is **required** — verifying only "a genuine Nitro enclave signed this"
> (without pinning the approved image) would let a malicious parent run a
> *different* enclave image that echoes the expected view. The digest input is the
> `configView` bytes themselves; you never re-derive them from base+overlay
> (which cannot reproduce the enclave-generated `vta_did`).
>
> **Multi-tenant isolation is now a KMS-policy requirement.** With `key_arn` no
> longer baked, one PCR0 is shared across tenants and the parent supplies the
> key ARN — so `kms:RecipientAttestation:PCR0` alone no longer isolates tenants.
> **Each tenant's KMS key policy MUST additionally constrain the calling
> principal** (the parent instance role / account), not just PCR0. Otherwise any
> enclave satisfying the shared PCR0 could reach another tenant's key.

## Build and deployment modes

There are three scripts in `deploy/nitro/`, each with a different intended
host and prerequisite set. Pick the one that matches your situation.

### `build-vta.sh` — build host / CI

Runs on a build machine (typically CI) with admin-level AWS credentials
and the EIF signing key. Produces a deployable bundle containing
`vta.eif`, the finalized `config.toml`, `pcr0.txt`, `pcr8.txt`, and
`manifest.json`. Also creates/updates the KMS key policy with the
current PCR0/PCR8 and instance role ARN.

Required on this host: `docker`, `nitro-cli`, `openssl`, `aws`, `jq`,
admin AWS creds, and access to the signing key.

### `deploy-enclave.sh` — parent EC2 instance

Runs on the parent EC2 instance that will host the running enclave.
Consumes a bundle (from `build-vta.sh`), installs and starts the DID
resolver sidecar, builds and starts the parent `enclave-proxy`, then
launches the enclave via `nitro-cli run-enclave`.

Required on this host: `nitro-cli` (with the `nitro_enclaves` kernel
module loaded, `ne` group membership, allocator configured), `cargo`,
and `jq`. **Not** required: docker, openssl, the signing key, admin
AWS credentials. The instance's IAM role only needs `kms:Decrypt` and
`kms:GenerateDataKey` on the KMS key.

### `deploy-vta.sh` — single-host wrapper (dev/test only)

Convenience wrapper that runs `build-vta.sh` and `deploy-enclave.sh`
back-to-back on the same machine. **Not appropriate for production**:
it puts the signing key on the same host that runs the enclave, which
defeats the main security goal of PCR8 (attacker with parent access
can re-sign their own EIF). Use it for local dev loops and CI smoke
tests only.

### Recommended production flow

```
┌─────────────────────────┐        ┌──────────────────────────┐
│  CI / Build host        │        │  Parent EC2 instance     │
│  (admin AWS creds,      │  EIF   │  (instance role: minimal │
│   signing key)          │ bundle │   KMS permissions only)  │
│                         │───────▶│                          │
│  ./build-vta.sh         │        │  ./deploy-enclave.sh \   │
│    → .deploy-nitro/     │        │      --bundle /path/...  │
│      vta.eif            │        │                          │
│      config.toml        │        │  Installs sidecar,       │
│      pcr0.txt / pcr8.txt│        │  starts enclave-proxy,   │
│      manifest.json      │        │  runs the enclave.       │
└─────────────────────────┘        └──────────────────────────┘
```

The signing key never leaves CI. The parent EC2 instance never holds
admin credentials and can't modify its own KMS policy.

## Security Model

```
┌─────────────────────────────────────────────────────────────────────┐
│  What stops a compromised EC2 host from stealing secrets?           │
│                                                                     │
│  Layer 1: PCR0 (image hash)                                         │
│    → Different enclave image = different hash = KMS rejects         │
│                                                                     │
│  Layer 2: PCR8 (EIF signing certificate)                            │
│    → Unsigned or wrongly-signed image = KMS rejects                 │
│    → Signing key lives in CI/CD, never on EC2                       │
│                                                                     │
│  Layer 3: PCR3 (IAM role)                                           │
│    → Can't use a different role to bypass the policy                │
│                                                                     │
│  Layer 4: Ephemeral RSA key                                         │
│    → KMS response encrypted to enclave's key                        │
│    → Network MITM can't read the response                           │
│                                                                     │
│  Layer 5: IAM separation                                            │
│    → EC2 role: kms:Decrypt + kms:GenerateDataKey only               │
│    → Admin role (separate account): kms:PutKeyPolicy + MFA          │
│                                                                     │
│  Layer 6: Hardware memory isolation                                  │
│    → Nitro hypervisor prevents parent from reading enclave memory   │
│                                                                     │
│  Layer 7: Encrypted external storage                                │
│    → All fjall data AES-256-GCM encrypted inside TEE                │
│    → Parent EBS only has ciphertext                                 │
│                                                                     │
│  Layer 8: CloudTrail audit                                          │
│    → All KMS policy changes logged and alertable                    │
└─────────────────────────────────────────────────────────────────────┘
```

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│  Nitro Enclave (no network access, isolated memory)                 │
│                                                                     │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │  VTA Service                                                 │   │
│  │                                                              │   │
│  │  Boot: ephemeral RSA key → NSM attestation → KMS Decrypt    │   │
│  │        → seed + JWT key in TEE memory only                   │   │
│  │                                                              │   │
│  │  Runtime: REST :8100 + DIDComm (via vsock proxies)          │   │
│  │           All storage AES-256-GCM encrypted                  │   │
│  │           /dev/nsm for attestation reports                   │   │
│  └──────────────────────────────────────────────────────────────┘   │
│                                                                     │
│  vsock proxies: inbound(:5100) mediator(:5200) HTTPS(:5300) IMDS(:5400) resolver(:5600) │
└────────────┬──────────────┬──────────────┬──────────────────────────┘
             │ vsock        │ vsock        │ vsock
┌────────────▼──────────────▼──────────────▼──────────────────────────┐
│  Parent EC2 Instance                                                │
│  parent-proxy.sh: REST ↔ vsock, mediator ↔ vsock, HTTPS ↔ vsock   │
└─────────────────────────────────────────────────────────────────────┘
```

## Bootstrapping Architecture

The VTA's TEE bootstrap is designed so that **a single EIF build works for
both first and subsequent boots** — no rebuild cycle for identity creation.

```
┌─────────────────────────────────────────────────────────────────────┐
│  BEFORE DEPLOYMENT (build machine / CI)                              │
│                                                                      │
│  Operator provides these deployment inputs in config.toml:           │
│                                                                      │
│  ┌─────────────────────────────────────────────────────────────┐    │
│  │  [tee.kms]                                                   │    │
│  │  key_arn = "arn:aws:kms:..."     ← from setup-kms-policy.sh │    │
│  │  vta_did_template = "did:webvh:{SCID}:example.com:vta"      │    │
│  │                                                               │    │
│  │  public_url = "https://vta.example.com"  ← REST only         │    │
│  │                                                               │    │
│  │  [messaging]                             ← DIDComm profiles   │    │
│  │  mediator_did = "did:web:mediator.example.com"                │    │
│  └─────────────────────────────────────────────────────────────┘    │
│                                                                      │
│  Tenant config served over vsock at runtime → NOT part of PCR0       │
└──────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────┐
│  FIRST BOOT (inside enclave)                                         │
│                                                                      │
│  1. KMS bootstrap: generate seed + JWT key, encrypt to KMS           │
│  2. Derive AES-256 storage key from seed (HKDF)                      │
│  3. Auto-generate did:webvh from template:                           │
│     • Derive signing + key-agreement keys from seed                  │
│     • Create DID (replace {SCID} with real value)                    │
│     • Persist DID in encrypted store                                 │
│     • Write did.jsonl to /mnt/vta-data/files/                      │
│  4. Start serving (auth fully functional)                            │
│                                                                      │
│  Operator: upload did.jsonl to WebVH server                          │
└──────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────┐
│  SUBSEQUENT BOOTS (inside enclave, same EIF)                         │
│                                                                      │
│  1. KMS decrypt: seed + JWT key from ciphertext (attestation-gated)  │
│  2. Derive same storage key (deterministic — same seed + salt)       │
│  3. Restore DID from encrypted store (template not re-evaluated)     │
│  4. Start serving                                                    │
└──────────────────────────────────────────────────────────────────────┘
```

### Deployment Inputs

These values are set in `config.toml` before building the EIF:

| Input | Required | When | Purpose |
|-------|----------|------|---------|
| `tee.kms.key_arn` | Yes | Always | KMS key ARN for secret encryption/decryption |
| `tee.kms.vta_did_template` | Recommended | Always | Template for auto-generating the VTA's did:webvh identity on first boot. Eliminates the manual DID creation / rebuild cycle. |
| `public_url` | Only for REST | Profiles B, C | External HTTPS URL where the VTA is reachable. Used in DID documents for the TEE attestation service endpoint. **Not needed for DIDComm-only (Profile A)** — all communication goes through the mediator. |
| `messaging.mediator_did` | Only for DIDComm | Profiles A, B | DIDComm mediator DID. The mediator URL is always `ws://127.0.0.1:4443` inside the enclave (vsock-proxied). |
| `vta_name` | No | Optional | Human-readable name for the VTA |

**Profile-specific inputs:**

| Profile | `public_url` | `mediator_did` | `vta_did_template` |
|---------|-------------|----------------|-------------------|
| A (Hardened, DIDComm only) | Not needed | Required | Recommended |
| B (Full API, REST + DIDComm) | Required | Required | Recommended |
| C (REST only) | Required | Not needed | Recommended |

## Prerequisites

### EC2 Instance

| Requirement | Details |
|------------|---------|
| Instance type | Nitro Enclave capable: `m5.xlarge`, `c5.xlarge`, `r5.xlarge` or larger |
| AMI | Amazon Linux 2023 or Ubuntu 22.04+ |
| Enclave support | Enabled at launch: `--enclave-options Enabled=true` |
| IMDS hop limit | Must be **2** (see below) |
| IAM role | Minimal: `kms:Decrypt`, `kms:GenerateDataKey` only (see Step 3) |

### Enclave Support

Nitro Enclave support must be **enabled on the EC2 instance** — it cannot be
turned on while the instance is running. If you forgot to enable it at launch
time, you must stop the instance, enable it, then start it again:

```bash
# Check if enclave support is enabled
aws ec2 describe-instances --instance-ids <your-instance-id> \
    --query 'Reservations[].Instances[].EnclaveOptions'
# → [{"Enabled": true}]
```

If `Enabled` is `false`:

```bash
# Stop the instance first (not reboot — enclave options require a full stop)
aws ec2 stop-instances --instance-ids <your-instance-id>
aws ec2 wait instance-stopped --instance-ids <your-instance-id>

# Enable enclave support
aws ec2 modify-instance-attribute --instance-id <your-instance-id> \
    --enclave-options Enabled=true

# Start the instance
aws ec2 start-instances --instance-ids <your-instance-id>
```

Or enable it at launch time:

```bash
aws ec2 run-instances ... --enclave-options Enabled=true
```

Without enclave support enabled, the `nitro_enclaves` kernel module will not
load and the `nitro-enclaves-allocator` service will fail with
*"The CPU pool file is missing. Please make sure the Nitro Enclaves driver is
inserted."*

### IMDS Hop Limit

The AWS SDK inside the enclave fetches IAM credentials from the Instance
Metadata Service (IMDS) via a vsock proxy on the parent. IMDSv2 counts
this proxy as an extra network hop. The default hop limit is 1, which
causes the token response to be dropped before reaching the enclave.

Set the hop limit to 2 on the EC2 instance:

```bash
aws ec2 modify-instance-metadata-options \
    --instance-id <your-instance-id> \
    --http-put-response-hop-limit 2
```

Or set it at launch time:

```bash
aws ec2 run-instances ... \
    --metadata-options "HttpEndpoint=enabled,HttpTokens=required,HttpPutResponseHopLimit=2"
```

### Software on the Parent Instance

```bash
# Amazon Linux 2023
sudo yum install -y aws-nitro-enclaves-cli aws-nitro-enclaves-cli-devel docker socat

# Ubuntu
sudo apt install -y aws-nitro-enclaves-cli docker.io socat

# Enable services
sudo systemctl enable --now nitro-enclaves-allocator docker

# Add your user to the docker and ne groups (required before building images)
sudo usermod -aG docker,ne $USER
```

**Rust toolchain** (required on the parent EC2 instance):

The `enclave-proxy` binary is built from source on the parent instance
(see [Step 6](#step-6-start-the-parent-proxy-before-the-enclave)), and the
DID resolver sidecar is installed via `cargo install`
(see [DID Resolution](#did-resolution)). Both require a working Rust
toolchain — the `enclave-proxy` crate's MSRV is **Rust 1.91.0**.

```bash
# Install rustup (official installer — picks up a current stable toolchain)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source "$HOME/.cargo/env"

# Verify
cargo --version   # cargo 1.91.0 or newer
```

Rust is **not** required on the build machine where the Docker image and
EIF are built — only on the EC2 parent instance that runs the enclave.

> **You MUST log out and log back in** (or start a new SSH session) after
> adding groups. Until your session picks up the new membership, `docker`
> commands will fail with "permission denied" and `nitro-cli` commands will
> fail with "operation not permitted". The `deploy-vta.sh` script checks
> for these group memberships and will refuse to continue if they are missing
> from your current session. Running `newgrp docker && newgrp ne` in your
> current shell is a quick alternative to a full logout.

### Configure Enclave Resources

Edit `/etc/nitro_enclaves/allocator.yaml`:

```yaml
memory_mib: 512
cpu_count: 1
```

```bash
sudo systemctl restart nitro-enclaves-allocator
```

## Quick Start

> **You MUST complete all of the prerequisites above before running the
> deployment script.** The script checks for required tools, AWS credentials,
> and group memberships at startup, but it cannot install packages, configure
> enclave resources, or set the IMDS hop limit for you. Skipping these steps
> will cause hard-to-diagnose failures during the build or enclave launch.

### Production (recommended)

On the CI/build host:

```bash
./deploy/nitro/build-vta.sh --non-interactive
# → produces .deploy-nitro/{vta.eif,config.toml,pcr0.txt,pcr8.txt,manifest.json}
```

Copy the bundle to the parent EC2 instance, then:

```bash
./deploy/nitro/deploy-enclave.sh --bundle ~/vta-bundle --non-interactive
```

The build script needs admin AWS credentials and the signing key. The
deploy script needs neither — only `nitro-cli`, `cargo`, and the EC2
instance role's minimal KMS permissions.

For CI/CD, parameterize via environment variables (see each script's
header for the full list):

```bash
VTA_PROFILE=hardened \
VTA_REGION=us-east-1 \
VTA_ROLE_NAME=vta-enclave-role \
VTA_MEDIATOR_DID="did:web:mediator.example.com" \
VTA_KEY_ARN="arn:aws:kms:us-east-1:123456789012:key/..." \
./deploy/nitro/build-vta.sh --non-interactive
```

### Single-host dev/test

For a quick local loop where you don't care that the signing key sits
on the same box as the enclave:

```bash
./deploy/nitro/deploy-vta.sh
```

This wrapper runs `build-vta.sh` and `deploy-enclave.sh` in sequence on
the current host and prints a warning banner.

The rest of this guide documents each step in detail.

## Step 1: Generate EIF Signing Key

**Run this on your build machine or CI/CD pipeline — NOT on the EC2 instance.**

The signing key ensures only images built by your pipeline can decrypt secrets.
PCR8 (the certificate hash) is included in the KMS key policy.

```bash
chmod +x deploy/nitro/generate-signing-key.sh
./deploy/nitro/generate-signing-key.sh ./signing

# Output:
#   ./signing/signing-key.pem     — Private key (KEEP SECRET)
#   ./signing/signing-cert.pem    — Certificate (include in builds)
#   ./signing/pcr8.txt            — PCR8 hash for KMS policy
```

Store the private key securely:
- **CI/CD pipeline secret** (GitHub Actions secret, GitLab CI variable, etc.)
- **AWS Secrets Manager** in a separate account
- **Hardware security module** for maximum security
- **Never** on the EC2 instance that runs the enclave

## Step 2: Choose a Build Profile

The enclave image uses the `vta-enclave` binary, which has TEE support (KMS
bootstrap, attestation, encrypted storage) built in — no `tee` feature flag
needed. The `FEATURES` build arg controls which transport and storage options
are compiled in.

### Profile A: Hardened (DIDComm only — recommended for production TEE)

All secret-handling operations go through DIDComm (E2E encrypted). REST is
limited to attestation, health, and auth bootstrap (unauthenticated/read-only).
This is the smallest attack surface.

```bash
docker build -f Dockerfile.nitro \
    --build-arg FEATURES="didcomm,vsock-store,vsock-log" \
    -t vta-nitro .
```

| Available on REST | Available on DIDComm |
|---|---|
| `GET /health` | Key management (create, list, get, revoke, secrets) |
| `GET,POST /attestation/report` | ACL management (CRUD) |
| `GET /attestation/status` | Config management |
| `POST /auth/challenge` | Credential generation |
| `POST /auth/` | Context management |
| `POST /auth/refresh` | Seed rotation |
| | WebVH DID operations |

### Profile B: Full API (REST + DIDComm — for development or network-controlled environments)

All operations available on both REST and DIDComm. Use when the REST API is
behind a load balancer, VPN, or other network-level access control.

```bash
docker build -f Dockerfile.nitro \
    --build-arg FEATURES="rest,didcomm,vsock-store,vsock-log" \
    -t vta-nitro .
```

### Profile C: REST only (no DIDComm — for simple deployments without a mediator)

```bash
docker build -f Dockerfile.nitro \
    --build-arg FEATURES="rest,vsock-store,vsock-log" \
    -t vta-nitro .
```

### Customizing Feature Flags

The `FEATURES` build arg maps to Cargo feature flags on the `vta-enclave`
crate. Available features:

| Feature | Purpose | Notes |
|---------|---------|-------|
| `rest` | REST API endpoints | Optional (Profile B/C) |
| `didcomm` | DIDComm v2 messaging | Recommended (Profile A/B) |
| `vsock-store` | Persistent storage via parent proxy | **Recommended** for data persistence across restarts |
| `vsock-log` | Forward enclave logs to parent proxy via vsock | **Recommended** — required for production log visibility |
| `webvh` | did:webvh DID management | Optional |

TEE support (KMS bootstrap, attestation, encrypted storage) is built into
`vta-enclave` by default — no feature flag needed.

Features NOT relevant for enclave builds (the VTA handles secrets via KMS):
`keyring`, `config-seed`, `aws-secrets`, `setup`.

**You do NOT need to edit `[services]` in `config.toml` when switching profiles.**
The `FEATURES` build arg controls which services are compiled into the binary.
The `[services]` section in config is a runtime toggle that can only *disable*
a compiled-in service, never *enable* one that wasn't compiled. For example,
building with `FEATURES="didcomm,vsock-store,vsock-log"` (Profile A) means REST code is
not in the binary — `services.rest = true` in config has no effect.

**KMS bootstrap** handles all secret management in enclave mode:
- The seed is generated inside the TEE on first boot and encrypted to KMS
- The JWT signing key is generated inside the TEE and encrypted to KMS
- On subsequent boots, both are decrypted from KMS with attestation verification

## Step 3: Build and Sign the Enclave Image

```bash
# Build the Docker image (using your chosen profile from Step 2)
docker build -f Dockerfile.nitro -t vta-nitro .

# Build AND SIGN the Enclave Image File
nitro-cli build-enclave \
    --docker-uri vta-nitro \
    --output-file vta.eif \
    --signing-certificate ./signing/signing-cert.pem \
    --private-key ./signing/signing-key.pem
```

Save the output — you need **PCR0** for the KMS policy:

```
Enclave Image successfully created.
{
  "Measurements": {
    "HashAlgorithm": "Sha384 { ... }",
    "PCR0": "abc123def456...",    ← Enclave image hash
    "PCR1": "...",                ← Kernel + boot ramfs
    "PCR2": "...",                ← Application
    "PCR8": "789abc012..."        ← Signing certificate (matches pcr8.txt)
  }
}
```

Verify PCR8 matches your signing key:
```bash
cat ./signing/pcr8.txt
# Should match the PCR8 from build output
```

## Step 4: Set Up IAM Roles and KMS Key Policy

This step creates the IAM roles and a KMS key that **only releases secrets to
your exact enclave image, signed by your certificate, running on your IAM role**.

### 4a: Create the EC2 Instance Role

The EC2 instance running the enclave needs a minimal IAM role. Create it in the
AWS Console or via CLI:

```bash
# Create the role with EC2 trust policy
aws iam create-role \
    --role-name vta-enclave-role \
    --assume-role-policy-document '{
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "ec2.amazonaws.com"},
            "Action": "sts:AssumeRole"
        }]
    }'

# Create an instance profile and attach the role
aws iam create-instance-profile --instance-profile-name vta-enclave-profile
aws iam add-role-to-instance-profile \
    --instance-profile-name vta-enclave-profile \
    --role-name vta-enclave-role
```

The KMS permissions for this role are set by the KMS key policy in Step 4c —
you do NOT need to attach a KMS policy to the role itself. KMS key policies
are authoritative when they grant access to a principal.

If your EC2 instance is already running, attach the profile:
```bash
aws ec2 associate-iam-instance-profile \
    --instance-id i-0123456789abcdef0 \
    --iam-instance-profile Name=vta-enclave-profile
```

### 4b: IAM Permissions for the KMS Setup User

The person (or CI/CD role) running `setup-kms-policy.sh` needs these
permissions. This is your **admin user**, separate from the EC2 instance role:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "AllowKMSKeyManagement",
            "Effect": "Allow",
            "Action": [
                "kms:CreateKey",
                "kms:CreateAlias",
                "kms:PutKeyPolicy",
                "kms:DescribeKey",
                "kms:ListAliases",
                "kms:TagResource"
            ],
            "Resource": "*"
        },
        {
            "Sid": "AllowCheckCallerIdentity",
            "Effect": "Allow",
            "Action": "sts:GetCallerIdentity",
            "Resource": "*"
        }
    ]
}
```

Attach this policy to your IAM user or role:
```bash
# Create the policy
aws iam create-policy \
    --policy-name vta-kms-admin \
    --policy-document file://deploy/nitro/iam-kms-admin-policy.json

# Attach to your IAM user
aws iam attach-user-policy \
    --user-name your-admin-user \
    --policy-arn arn:aws:iam::123456789012:policy/vta-kms-admin

# Or attach to a role (for CI/CD)
aws iam attach-role-policy \
    --role-name your-ci-role \
    --policy-arn arn:aws:iam::123456789012:policy/vta-kms-admin
```

### 4c: Create the KMS Key with Attestation Policy

```bash
chmod +x deploy/nitro/setup-kms-policy.sh

./deploy/nitro/setup-kms-policy.sh \
    --pcr0 "abc123def456..." \
    --pcr8 "789abc012..." \
    --role "arn:aws:iam::123456789012:role/vta-enclave-role" \
    --region us-east-1
```

This creates a KMS key with three policy statements:

| Statement | Principal | Actions | Condition |
|-----------|-----------|---------|-----------|
| Key administration | Your IAM user/role | Full management | None (admin only) |
| **Attestation operations** | EC2 instance role | `kms:Decrypt`, `kms:GenerateDataKey` | **PCR0 + PCR8 must match** |

#### Granting build role admin access

In CI/CD pipelines, the build role needs to update the KMS key policy to rotate
PCR0 after each rebuild. Use `--build-admin` to grant a second principal KMS
admin permissions (policy management only — no encrypt/decrypt access):

```bash
./deploy/nitro/setup-kms-policy.sh \
    --pcr0 "abc123def456..." \
    --pcr8 "789abc012..." \
    --role "arn:aws:iam::123456789012:role/vta-enclave-role" \
    --build-admin "arn:aws:iam::123456789012:role/vta-build-role" \
    --region us-east-1
```

The build role can then update PCR0 in subsequent runs without the original
creator's credentials:

```bash
# CI/CD pipeline runs as vta-build-role:
./deploy/nitro/setup-kms-policy.sh \
    --pcr0 "NEW_PCR0_HASH" \
    --pcr8 "$(cat ./signing/pcr8.txt)" \
    --role "arn:aws:iam::123456789012:role/vta-enclave-role" \
    --build-admin "arn:aws:iam::123456789012:role/vta-build-role" \
    --key-arn "arn:aws:kms:us-east-1:123456789012:key/abc-def-456"
```

To remove build role admin access later, re-run the script without
`--build-admin` — the policy is fully replaced each time:

```bash
./deploy/nitro/setup-kms-policy.sh \
    --pcr0 "abc123def456..." \
    --pcr8 "789abc012..." \
    --role "arn:aws:iam::123456789012:role/vta-enclave-role" \
    --key-arn "arn:aws:kms:us-east-1:123456789012:key/abc-def-456"
```

The script outputs the KMS key ARN. Now update the VTA config and rebuild the
enclave image.

### 4d: Update Config — Deployment Inputs

How you supply the deployment-specific values below depends on the build mode
you chose in Step 2 (`BAKE_CONFIG`, default = baked):

- **Self-host / baked (`BAKE_CONFIG=true`, default):** edit
  `deploy/nitro/config.toml`. These values are **baked into the EIF** and
  committed to PCR0, so changing them requires an image rebuild + KMS-policy
  update (see *4e — Self-host* below).
- **Fleet / un-baked (`BAKE_CONFIG=false`):** do **not** edit `config.toml` for
  tenant values — the image bakes only `config.fleet-base.toml`. Instead render a
  per-tenant `tenant-overlay.json` (below) that the parent serves at runtime over
  vsock:5800. Only the allowlisted fields can be set; **`admin_did` and every
  `allow_*` flag are structurally rejected by the overlay** (admin is established
  per-tenant via the attested sealed-bootstrap flow, not the config channel).

```bash
# Self-host (baked): edit the baked config
nano deploy/nitro/config.toml

# Fleet (un-baked): render the runtime overlay instead (never admin_did)
deploy/nitro/render-tenant-overlay.sh \
  --key-arn arn:aws:kms:us-east-1:123456789012:key/abc-def-456 \
  --mediator-did did:web:mediator.example.com \
  --anchor-table-name vta-rollback-anchor-acme \
  --vta-did-template 'did:webvh:{SCID}:example.com:vta' > tenant-overlay.json
```

The field descriptions below name the `config.toml` keys (baked mode); for fleet
the equivalent overlay flags are shown by `render-tenant-overlay.sh --help`.

**1. KMS key ARN** (required — from Step 4c):

```toml
[tee.kms]
region = "us-east-1"
key_arn = "arn:aws:kms:us-east-1:123456789012:key/abc-def-456"
```

**2. VTA DID template** (recommended — auto-generates identity on first boot):

```toml
[tee.kms]
vta_did_template = "did:webvh:{SCID}:example.com:vta"
did_log_path = "/mnt/vta-data/files/did.jsonl"
```

Replace `example.com:vta` with the domain and path where your WebVH server
hosts this VTA's DID document. The `{SCID}` placeholder is replaced with the
real self-certifying identifier on first boot. See [Automatic DID identity
generation](#automatic-did-identity-generation) for details.

**3. Public URL** (REST deployments only — Profiles B and C):

```toml
public_url = "https://vta.example.com"
```

This is the external HTTPS URL where clients reach the VTA's REST API. It's
embedded in the DID document as the TEE attestation service endpoint. **Not
needed for DIDComm-only (Profile A)** — all communication goes through the
mediator, so no public URL is required.

**4. DIDComm mediator** (Profiles A and B):

```toml
[messaging]
mediator_url = "ws://127.0.0.1:4443"
mediator_did = "did:web:mediator.example.com"
```

- `mediator_url` is always `ws://127.0.0.1:4443` inside the enclave (vsock-proxied)
- `mediator_did` is the DID of your mediator service — the parent proxy resolves
  this DID via the DID resolver to discover the mediator's endpoint URL (WSS or
  HTTPS). If the connection is lost, the proxy re-resolves the DID in case the
  endpoint has changed.

If the mediator doesn't have a resolvable DID, you can set `mediator_host`
as a manual override (skips DID resolution):

```toml
[messaging]
mediator_url = "ws://127.0.0.1:4443"
mediator_did = "did:web:mediator.example.com"
mediator_host = "mediator.example.com"
```

### 4e: Apply the Updated Config

The procedure differs by build mode. Pick the one matching your Step-2 choice —
they are mutually exclusive.

#### 4e (Self-host / baked, `BAKE_CONFIG=true`)

The tenant config is baked into the EIF, so **every config or code change**
rebuilds the image and changes PCR0 (which must then be updated in the KMS key
policy). The `Dockerfile.nitro` default is `BAKE_CONFIG=true`, so the plain
`docker build` below bakes `config.toml`:

```bash
# 1. Rebuild the Docker image with the SAME profile as Step 2 (config is baked)
#    Profile A (Hardened):       --build-arg FEATURES="didcomm,vsock-store,vsock-log"
#    Profile B (Full API):       --build-arg FEATURES="rest,didcomm,vsock-store,vsock-log"
#    Profile C (REST only):      --build-arg FEATURES="rest,vsock-store,vsock-log"
#    Or omit --build-arg to use the Dockerfile default (rest,didcomm,tee)
docker build -f Dockerfile.nitro -t vta-nitro .

# 2. Rebuild and sign the EIF
nitro-cli build-enclave \
    --docker-uri vta-nitro \
    --output-file vta.eif \
    --signing-certificate ./signing/signing-cert.pem \
    --private-key ./signing/signing-key.pem

# 3. Note the new PCR0 from the output
#    PCR0: "new_hash_here..."

# 4. Update the KMS key policy with the new PCR0
./deploy/nitro/setup-kms-policy.sh \
    --pcr0 "NEW_PCR0_HASH" \
    --pcr8 "$(cat ./signing/pcr8.txt)" \
    --role "arn:aws:iam::123456789012:role/vta-enclave-role" \
    --key-arn "arn:aws:kms:us-east-1:123456789012:key/abc-def-456"
```

**Every config or code change follows this cycle:** edit → docker build
(same profile) → nitro build-enclave → update KMS policy with new PCR0.
This is by design — the PCR0 pin ensures nobody can tamper with the baked config
after build.

#### 4e (Fleet / un-baked, `BAKE_CONFIG=false`)

Tenant values are **not** in the image, so a tenant config change (KMS ARN,
mediator DID, did:webvh template, public URL, vta_name) does **not** rebuild the
image and does **not** change PCR0. Instead:

```bash
# 1. Re-render the overlay with the new values (never admin_did — it is rejected)
deploy/nitro/render-tenant-overlay.sh --key-arn <arn> --mediator-did <did> \
    --anchor-table-name <table> --vta-did-template <tmpl> > tenant-overlay.json

# 2. Serve the new overlay and restart the enclave (deploy-enclave.sh restarts
#    the parent proxy when the overlay routing changes)
./deploy/nitro/deploy-enclave.sh --bundle <bundle-dir>   # with tenant-overlay.json present
```

Only code / dependency / Dockerfile changes rebuild the fleet image and change
PCR0 (which must then be updated in the KMS key policy, exactly as in the
self-host cycle above). Rebuild with `--build-arg BAKE_CONFIG=false` so tenant
values stay un-baked and the overlay client is compiled in.

**First boot is auto-detected.** On first deployment, the ciphertext files
don't exist yet, so the VTA generates new secrets inside the TEE and encrypts
them to KMS. On subsequent boots it finds the ciphertexts and decrypts them.
No config changes or redeployment needed between first and subsequent boots.

## Step 5: Copy Artifacts to the EC2 Instance

If building on a separate machine, copy the EIF and finalized config:

```bash
scp vta.eif ec2-user@<instance-ip>:~/
scp deploy/nitro/config.toml ec2-user@<instance-ip>:~/config.toml
```

If building directly on the EC2 instance, the files are already in place.

## Step 6: Start the Parent-Side Services (before the enclave)

> **Important:** Both the DID resolver sidecar and the `enclave-proxy` must
> be running **before** the enclave starts, in that order:
>
>   1. DID resolver sidecar (`affinidi-did-resolver-cache-server` on :8080)
>   2. `enclave-proxy` (bridges vsock ↔ everything else)
>   3. `nitro-cli run-enclave`
>
> On boot, the enclave immediately tries to reach KMS, IMDS, and the DID
> resolver through vsock. If any of these are not listening, the VTA
> crashes during TEE bootstrap or auth initialization.
>
> `deploy-vta.sh` installs and starts both services automatically in Steps
> 9 and 10, and tracks them via pidfiles in `.deploy-nitro/` so re-runs
> don't spawn duplicates. If you're running the steps by hand, do them in
> the order listed above.

The parent proxy bridges all networking between the enclave and the outside
world. This includes DID resolution (`did:web`, `did:webvh`) — the enclave has
no direct network access, so all HTTPS traffic is routed through a vsock proxy
with an allowlist of permitted hosts.

The proxy is a Rust binary that auto-reads the mediator DID and KMS region
from `config.toml` and auto-detects the enclave CID.

**Important:** The proxy needs the **finalized** `config.toml` — the same
values served to the enclave over vsock (with the real KMS ARN, mediator DID,
etc.). A repo checkout on the EC2 instance may have stale values (e.g., `PLACEHOLDER`
for the KMS ARN). There are two ways to provide the config:

**Option A: Copy the finalized config from the build machine** (recommended)

```bash
# On the build/CI machine, after building the EIF:
scp deploy/nitro/config.toml ec2-user@<instance-ip>:~/config.toml

# On the EC2 instance, run the proxy with the copied config:
./deploy/nitro/enclave-proxy/target/release/enclave-proxy -c ~/config.toml
```

**Option B: Pass settings via environment variables** (no config file needed)

```bash
AWS_REGION=us-east-1 \
MEDIATOR_HOST=mediator.example.com \
    ./deploy/nitro/enclave-proxy/target/release/enclave-proxy
```

Build and run the proxy on the EC2 instance:

```bash
# Build the proxy (first time only — on the parent EC2 instance)
cd deploy/nitro/enclave-proxy
cargo build --release
cd ../../..

# Run with the finalized config. Pin --enclave-cid 16 so the proxy doesn't
# auto-detect a stale CID from an old enclave you're about to terminate.
./deploy/nitro/enclave-proxy/target/release/enclave-proxy \
    --config ~/config.toml --enclave-cid 16

# With additional allowlisted hosts (WebVH servers, etc.)
./deploy/nitro/enclave-proxy/target/release/enclave-proxy \
    --config ~/config.toml --enclave-cid 16 webvh-server.example.com:443

```

The proxy starts four channels:

| Channel | Flow | Purpose |
|---------|------|---------|
| Inbound REST | `TCP:8443 → vsock:5100 → Enclave :8100` | External clients access VTA API |
| Outbound DIDComm | `Enclave → vsock:5200 → TLS → mediator` | VTA DIDComm messaging |
| Outbound HTTPS | `Enclave → vsock:5300 → allowlisted hosts` | KMS, WebVH, enclave HTTPS |
| Outbound IMDS | `Enclave → vsock:5400 → 169.254.169.254:80` | AWS IAM credentials |
| Storage | `Enclave → vsock:5500 → fjall on EBS` | Persistent K/V store |
| DID Resolver | `Enclave → vsock:5600 → resolver sidecar` | DID resolution (WebSocket) |

The HTTPS channel implements an **HTTP CONNECT proxy** with an allowlist.
Inside the enclave, `HTTPS_PROXY=http://127.0.0.1:4444` routes all HTTPS
traffic through it. KMS calls and WebVH server access flow through this proxy.

The allowlist is built automatically from:
- KMS endpoint (`kms.<region>.amazonaws.com`)
- Mediator host (if manual override is set)
- Extra hosts (from CLI args or `ALLOWLIST_HOSTS` env var)

### DID Resolution

DID resolution uses two components:

1. **Parent proxy** — embeds the Affinidi DID resolver for mediator DID
   resolution at startup (local mode, no external service needed).

2. **Resolver sidecar** — the `affinidi-did-resolver-cache-server` runs
   on the parent EC2 instance as a sidecar. The VTA inside the enclave
   connects to it via WebSocket (network mode) through vsock:5600.

**Source and crate:** the sidecar is published on crates.io as
[`affinidi-did-resolver-cache-server`](https://crates.io/crates/affinidi-did-resolver-cache-server)
and lives upstream at
[`affinidi/affinidi-tdk-rs`](https://github.com/affinidi/affinidi-tdk-rs)
under `crates/identity/affinidi-did-resolver-cache-server/`. A plain
`cargo install affinidi-did-resolver-cache-server` is all you need —
no git clone, no feature flags. "Network mode" refers to the WebSocket
endpoint at `/did/v1/ws`, which the server exposes by default.

#### Automatic (recommended)

`deploy-vta.sh` does all of this for you in **Step 9**, before the
`enclave-proxy` and the enclave itself:

- Runs `cargo install affinidi-did-resolver-cache-server` if the binary
  isn't on `$PATH` yet.
- Creates a runtime directory at `.deploy-nitro/resolver/` with a
  minimal `conf/cache-conf.toml` (the sidecar hard-codes its config
  path relative to CWD — there is no CLI flag to override it).
- Starts the sidecar in the background with `nohup`, binding to
  `127.0.0.1:8080` (override with `VTA_RESOLVER_LISTEN=host:port`).
- Writes `.deploy-nitro/resolver.pid` so re-runs reuse the existing
  process instead of spawning duplicates.

Logs land in `.deploy-nitro/resolver.log`.

#### Manual

If you're not using the script (e.g., managing the parent instance
with systemd), install and start it by hand:

```bash
# Install (first time only — compiles from source, takes a few minutes)
cargo install affinidi-did-resolver-cache-server

# Create a runtime directory with the required config file.
# The server reads `conf/cache-conf.toml` relative to its CWD — there
# is no CLI flag to override the path.
mkdir -p ~/vta-resolver/conf
cat > ~/vta-resolver/conf/cache-conf.toml <<'EOF'
log_level = "info"
listen_address = "${LISTEN_ADDRESS:127.0.0.1:8080}"
statistics_interval = "${STATISTICS_INTERVAL:60}"
enable_http_endpoint = "${ENABLE_HTTP_ENDPOINT:true}"
enable_websocket_endpoint = "${ENABLE_WEBSOCKET_ENDPOINT:true}"

[cache]
capacity_count = "${CACHE_CAPACITY_COUNT:1000}"
expire = "${EXPIRE:300}"
EOF

# Start it — must run from the directory containing conf/cache-conf.toml
cd ~/vta-resolver
nohup affinidi-did-resolver-cache-server > resolver.log 2>&1 &
```

The VTA's `config.toml` sets `resolver_url = "ws://127.0.0.1:4445/did/v1/ws"`
which routes through socat inside the enclave → vsock:5600 → proxy →
localhost:8080 (sidecar).

**Start the sidecar before the `enclave-proxy` and the enclave** — the
proxy bridges vsock:5600 to localhost:8080, and the VTA connects through
that bridge during boot for auth initialization. If the sidecar isn't up,
the bridge still accepts connections but immediately fails them, and the
VTA will crash during auth init.

### DID Resolution Security

The DID resolver runs on the parent EC2 instance (outside the TEE). An
attacker with parent access could potentially return fake DID documents.
The actual risk depends on the DID method:

| DID Method | Safe through parent resolver? | Why |
|---|---|---|
| `did:key` | **Yes** | No resolution needed — public key is embedded in the DID |
| `did:webvh` | **Yes** | Cryptographic audit trail — the resolver validates the signed log chain. Faking a document requires forging the entire history signed by the original keys. |
| `did:web` | **No** | No signatures on the document — relies solely on HTTPS transport trust. An attacker controlling the resolver can return fake documents. |

**For production TEE deployments:** use `did:key` and `did:webvh` exclusively.
Avoid `did:web` for any security-critical identity (admin DIDs, ACL entries,
DIDComm peers). If you must resolve `did:web` DIDs, route them through the
HTTPS CONNECT proxy (which terminates TLS inside the enclave) rather than
through the parent-side resolver.

> **Fallback:** The shell script `parent-proxy.sh` is still available if you
> prefer not to build the Rust proxy. It requires `socat` and `vsock-proxy`.

## Step 7: Start the Enclave

With the parent proxy running, start the enclave. Use `--enclave-cid 16`
to match the proxy's default CID:

```bash
nitro-cli run-enclave \
    --eif-path ~/vta.eif \
    --cpu-count 1 \
    --memory 512 \
    --enclave-cid 16 \
    --debug-mode

# Verify it's running
nitro-cli describe-enclaves

# Watch the console output (debug mode required)
nitro-cli console \
    --enclave-id $(nitro-cli describe-enclaves | jq -r '.[0].EnclaveID')
```

> **Tip:** Use `--debug-mode --attach-console` to stream console output
> directly to your terminal. See the [Troubleshooting](#troubleshooting)
> section for more details.
>
> **Warning:** In debug mode, the Nitro hypervisor sets **all PCR values
> to zeros** in attestation documents. KMS attestation conditions (PCR0/PCR8)
> will never match your real image hashes, and all attested KMS calls will
> fail with `AccessDeniedException`. To use KMS in debug mode, temporarily
> set the policy to all-zeros PCR values:
> ```bash
> ZEROS="000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
> ./deploy/nitro/setup-kms-policy.sh \
>     --pcr0 "$ZEROS" \
>     --pcr8 "$ZEROS" \
>     --role "arn:aws:iam::ACCOUNT:role/YOUR_ROLE" \
>     --key-arn "arn:aws:kms:REGION:ACCOUNT:key/KEY_ID" \
>     --region REGION
> ```
> **Remember to restore the real PCR values before production use.**

## Step 8: First boot (auto-detected)

First boot is detected automatically — no config changes needed. The VTA
checks if ciphertext files exist on the external storage path:

- **Files missing** → first boot: generate new secrets
- **Files present** → subsequent boot: decrypt from KMS

On first boot, the VTA:
1. Detects TEE mode (required) + KMS config
2. Finds no existing ciphertext files → **first boot**
3. Generates BIP-39 entropy inside the TEE using NSM hardware random
4. Derives seed from entropy
5. Encrypts seed + JWT key with KMS → stores ciphertext on external EBS
6. Derives AES-256 storage key from seed
7. If `vta_did_template` is configured: auto-generates the VTA's did:webvh
   identity and writes `did.jsonl` to disk (see below)
8. Starts serving (auth fully functional if DID was auto-generated)

### Automatic DID identity generation

To avoid a manual DID creation / config update / EIF rebuild cycle, set
`vta_did_template` in `config.toml` before baking the EIF:

```toml
[tee.kms]
vta_did_template = "did:webvh:{SCID}:example.com:vta"
did_log_path = "/mnt/vta-data/files/did.jsonl"
```

On first boot, the VTA:
1. Derives signing and key-agreement keys from the bootstrapped seed
2. Creates a did:webvh DID using the template (replacing `{SCID}` with the real value)
3. Persists the DID in the encrypted store (restored automatically on subsequent boots)
4. Writes the initial `did.jsonl` log entry to `did_log_path`

After the enclave starts, copy `did.jsonl` from the parent EC2 instance and
upload it to your WebVH server:

```bash
# On the parent EC2 instance:
cat /mnt/vta-data/files/did.jsonl

# Upload to your WebVH server at the matching path:
# e.g., https://example.com/vta/did.jsonl
curl -X POST https://webvh-server.example.com/api/publish \
    -H 'Content-Type: application/json' \
    -d @/mnt/vta-data/files/did.jsonl
```

**No EIF rebuild is needed.** The template is stable across boots — the actual
DID (with real SCID) is generated once on first boot and persisted in the
encrypted store. Subsequent boots restore it directly.

The template format follows the did:webvh spec. Examples:

| Template | Resulting URL |
|----------|--------------|
| `did:webvh:{SCID}:example.com:vta` | `https://example.com/vta` |
| `did:webvh:{SCID}:example.com:org:agents:vta-1` | `https://example.com/org/agents/vta-1` |
| `did:webvh:{SCID}:example.com%3A8080:vta` | `https://example.com:8080/vta` |

> **Note on ciphertext deletion:** If an attacker deletes the ciphertext files,
> the next boot will generate a new identity. This is a denial-of-service (the old
> identity and data are lost), not a privilege escalation — the attacker still
> can't authenticate to the new VTA without admin credentials. Back up the
> ciphertext files and monitor for unexpected identity changes.

**The mnemonic is never displayed.** To export it for backup:

```bash
# Terminate the enclave
nitro-cli terminate-enclave --enclave-id $(nitro-cli describe-enclaves | jq -r '.[0].EnclaveID')

# Restart with a 5-minute export window
VTA_MNEMONIC_EXPORT_WINDOW=300 nitro-cli run-enclave \
    --eif-path vta.eif --cpu-count 1 --memory 512 --enclave-cid 16

# Authenticate as super admin and export within 5 minutes:
TOKEN=$(curl -s -X POST http://localhost:8443/auth/challenge -H 'Content-Type: application/json' \
    -d '{"did":"did:key:z6Mk..."}' | jq -r '.data.challenge')
# ... complete auth flow to get JWT ...

# Check export window status
curl -s http://localhost:8443/attestation/mnemonic \
    -H "Authorization: Bearer $JWT" | jq

# Export (one-time, entropy zeroed after)
curl -s -X POST http://localhost:8443/attestation/mnemonic \
    -H "Authorization: Bearer $JWT" | jq '.mnemonic'
```

After 5 minutes (or one successful export), the entropy is permanently zeroed.
The VTA continues running — only the mnemonic words are gone.

## Step 9: Subsequent Boots

On subsequent boots, the VTA:
1. Finds existing ciphertext files on external storage
2. Generates ephemeral RSA keypair
3. Gets NSM attestation document (RSA public key embedded)
4. Calls KMS Decrypt with attestation → KMS verifies PCR0 + PCR8
5. Decrypts seed + JWT key inside TEE memory
6. Opens encrypted fjall store (same seed → same storage key)
7. Resumes normal operation

No mnemonic export is possible on subsequent boots (no entropy exists).

## Step 10: Verify

```bash
# Health check
curl http://localhost:8443/health
# → {"status":"ok","version":"0.1.2","tee_status":{"tee_type":"nitro","detected":true}}

# TEE attestation
curl http://localhost:8443/attestation/status

# Fresh attestation report
curl -X POST http://localhost:8443/attestation/report \
    -H 'Content-Type: application/json' \
    -d '{"nonce":"deadbeef0123456789abcdef01234567"}'
```

## Troubleshooting

### Viewing enclave console output

Nitro Enclaves have no SSH access and no network. The only way to see what's
happening inside is through the console, which requires **debug mode**.

```bash
# Start the enclave in debug mode with console attached to your terminal.
# You'll see kernel boot messages, entrypoint output, and any errors.
nitro-cli run-enclave \
    --eif-path vta.eif \
    --cpu-count 1 \
    --memory 512 \
    --debug-mode \
    --attach-console
```

If you prefer to run the enclave in the background and read the console
separately:

```bash
# Start in debug mode (background)
nitro-cli run-enclave \
    --eif-path vta.eif \
    --cpu-count 1 \
    --memory 512 \
    --debug-mode

# Read the console output (streams until Ctrl+C or enclave stops)
nitro-cli console \
    --enclave-id $(nitro-cli describe-enclaves | jq -r '.[0].EnclaveID')
```

> **Note:** `--debug-mode` must be specified at launch time. You cannot
> attach a console to an enclave that was started without it. Debug mode
> enables the console output channel but also **zeros all PCR values** in
> attestation documents, which breaks KMS attestation conditions. See the
> warning in [Step 7](#step-7-launch-the-enclave) for the workaround.

### Common startup errors

| Symptom | Cause | Fix |
|---------|-------|-----|
| `Error loading shared library ...` | Missing runtime library in the Alpine image | Add the library to the `apk add` list in `Dockerfile.nitro` and rebuild |
| `Error relocating ... symbol not found` | glibc binary uses a function Alpine/musl doesn't provide | Check if the symbol needs a compat stub (see `libresolv_compat.so` in `Dockerfile.nitro`) |
| Enclave exits immediately (hang-up event) | Process inside crashed — use `--attach-console` to see why | Start with `--debug-mode --attach-console` and read the error output |
| `KMS ... failed [ACCESS_DENIED]` | PCR0 mismatch — the EIF was rebuilt but KMS policy wasn't updated | Re-run `setup-kms-policy.sh` with the new PCR0 from the build output |
| `KMS ... failed [ACCESS_DENIED]` in debug mode | Debug mode zeros all PCR values — KMS attestation conditions can't match | Use all-zeros PCR values in the KMS policy for testing, or launch without `--debug-mode` |
| `failed to load IMDS session token` | IMDS hop limit too low or HTTP_PROXY interfering | Set IMDS hop limit to 2: `aws ec2 modify-instance-metadata-options --instance-id <id> --http-put-response-hop-limit 2` |
| `KMS Decrypt failed [NETWORK]` | Can't reach KMS — parent proxy not running or allowlist wrong | Start the enclave-proxy on the parent and verify the KMS endpoint is allowlisted |
| VTA hangs or crashes during auth init, no TEE errors in console | DID resolver sidecar (`affinidi-did-resolver-cache-server`) not running on the parent | Start it before the enclave: `nohup affinidi-did-resolver-cache-server > resolver.log 2>&1 &` — or re-run `deploy-vta.sh`, which handles this in Step 9 |
| `KMS Decrypt failed [KEY_NOT_FOUND]` | Wrong KMS key ARN in config.toml | Verify `[tee.kms] key_arn` matches the key created by `setup-kms-policy.sh` |
| `failed to open /dev/nsm` | Not running inside a Nitro Enclave | The VTA binary must run inside an enclave, not directly on the EC2 host |
| `TEE mode is 'required' but no TEE hardware detected` | TEE mode set to required but `/dev/nsm` not found | Ensure you're running inside a Nitro Enclave, or set `tee.mode = "optional"` for testing |
| Health endpoint returns but no `tee_status` | TEE subsystem didn't initialize | Check console logs for TEE init errors; verify the `tee` feature was included in the build |

### Checking enclave status

```bash
# List running enclaves
nitro-cli describe-enclaves

# Check if the VTA is responding (via the parent proxy)
curl http://localhost:8443/health

# Terminate a running enclave
nitro-cli terminate-enclave \
    --enclave-id $(nitro-cli describe-enclaves | jq -r '.[0].EnclaveID')
```

### Checking parent proxy logs

The enclave-proxy logs to stderr. If started in the foreground, logs appear
in your terminal. If started via `deploy-vta.sh`, logs are written to
`.deploy-nitro/proxy.log`:

```bash
# View proxy logs
tail -f .deploy-nitro/proxy.log

# Check if the proxy is running
cat .deploy-nitro/proxy.pid | xargs ps -p
```

### Rebuilding after changes

Any change to `config.toml`, the VTA source code, or the Dockerfile requires
the full rebuild cycle because PCR0 changes:

```bash
# 1. Rebuild Docker image
docker build -f Dockerfile.nitro --build-arg FEATURES="rest,didcomm,vsock-store,vsock-log" -t vta-nitro .

# 2. Rebuild and sign EIF — note the new PCR0
nitro-cli build-enclave --docker-uri vta-nitro --output-file vta.eif \
    --signing-certificate signing-cert.pem --private-key signing-key.pem

# 3. Update KMS policy with new PCR0
./deploy/nitro/setup-kms-policy.sh \
    --pcr0 "NEW_PCR0" --pcr8 "$(cat signing/pcr8.txt)" \
    --role "arn:aws:iam::ACCOUNT:role/vta-enclave-role" \
    --key-arn "arn:aws:kms:REGION:ACCOUNT:key/KEY_ID"

# 4. Terminate old enclave and start new one
nitro-cli terminate-enclave --enclave-id $(nitro-cli describe-enclaves | jq -r '.[0].EnclaveID')
nitro-cli run-enclave --eif-path vta.eif --cpu-count 1 --memory 512 --debug-mode
```

## Upgrading the Enclave Image

Every time you rebuild the Docker image, the PCR0 (image hash) changes. The
KMS policy must be updated to allow the new image to decrypt the existing
secrets. (Tenant config changes do **not** rebuild the image — see below.)

### What triggers a PCR0 change

Any of these require a KMS policy update:
- Code changes in the VTA (Rust source)
- Dependency updates (Cargo.lock changes)
- Dockerfile changes (base image, packages, build args)
- Feature flag changes

Note: **tenant config changes no longer trigger a PCR0 change** —
tenant config is delivered at runtime over vsock, not baked into the EIF.

**PCR8 does NOT change** unless you regenerate the signing key.

### Rolling upgrade (preserves identity and secrets)

This is the standard upgrade procedure. The KMS policy temporarily allows
both the old and new PCR0, so the new image can decrypt secrets that were
encrypted by the old image.

```bash
# 1. Record the current PCR0 before building
OLD_PCR0=$(cat last-build-pcr0.txt)
# Or from a running enclave:
# OLD_PCR0=$(nitro-cli describe-enclaves | jq -r '.[0].Measurements.PCR0')

# 2. Build the new image
docker build -f Dockerfile.nitro --build-arg FEATURES="rest,didcomm,vsock-store,vsock-log" -t vta-nitro .
nitro-cli build-enclave --docker-uri vta-nitro --output-file vta.eif \
    --signing-certificate signing-cert.pem --private-key signing-key.pem
# Save the new PCR0 from the output
NEW_PCR0="<from build output>"
echo "$NEW_PCR0" > last-build-pcr0.txt

# 3. Update KMS policy to allow BOTH old and new PCR0
#    Security: PCR8 (signing cert) is still enforced, so only YOUR
#    signed images can decrypt — not an attacker's custom image.
./deploy/nitro/setup-kms-policy.sh \
    --pcr0 "$NEW_PCR0" \
    --old-pcr0 "$OLD_PCR0" \
    --pcr8 "$(cat signing/pcr8.txt)" \
    --role "arn:aws:iam::ACCOUNT:role/ROLE" \
    --key-arn "arn:aws:kms:REGION:ACCOUNT:key/KEY_ID"

# 4. Terminate old enclave and start new one
nitro-cli terminate-enclave --enclave-id $(nitro-cli describe-enclaves | jq -r '.[0].EnclaveID')
nitro-cli run-enclave --eif-path vta.eif --cpu-count 1 --memory 512 --enclave-cid 16 --debug-mode

# 5. Verify the new image works
curl http://localhost:8443/health
curl http://localhost:8443/attestation/status

# 6. Lock down: remove the old PCR0 from the policy
./deploy/nitro/setup-kms-policy.sh \
    --pcr0 "$NEW_PCR0" \
    --pcr8 "$(cat signing/pcr8.txt)" \
    --role "arn:aws:iam::ACCOUNT:role/ROLE" \
    --key-arn "arn:aws:kms:REGION:ACCOUNT:key/KEY_ID"
```

> **Security note:** During step 3-6, both the old and new PCR0 are
> authorized. PCR8 (your signing certificate) prevents an attacker from
> using a custom image during this window. Step 6 removes the old PCR0
> to close the window completely.

### Auto-recovery (forgot to update KMS policy)

If you deploy a new image without updating the KMS policy, the VTA will:
1. Find existing ciphertexts in the bootstrap keyspace
2. Fail to decrypt them (PCR0 mismatch)
3. Log a warning: *"KMS decrypt failed — clearing stale bootstrap data"*
4. Clear the old bootstrap data
5. Do a fresh first boot with a **new identity**

This is safe (denial of service, not privilege escalation) but results in
a new DID identity. Use the rolling upgrade procedure above to preserve
the existing identity across image updates.

### Fresh deployment (new identity)

If you intentionally want a clean start:

```bash
# 1. Delete the persistent store
rm -rf /mnt/vta-data/store/*

# 2. Update KMS policy with only the new PCR0
./deploy/nitro/setup-kms-policy.sh --pcr0 "NEW_PCR0" ...

# 3. Start the enclave — it will do a fresh first boot
```

Or simply deploy without updating the KMS policy — the auto-recovery
will handle it (see above).

### CI/CD upgrade workflow

For automated deployments, the CI/CD pipeline should:

```bash
# Build + sign
docker build -f Dockerfile.nitro --build-arg FEATURES="..." -t vta-nitro .
NEW_PCR0=$(nitro-cli build-enclave --docker-uri vta-nitro --output-file vta.eif \
    --signing-certificate cert.pem --private-key key.pem | jq -r '.Measurements.PCR0')

# Rolling update: allow both old and new PCR0
OLD_PCR0=$(cat /opt/vta/last-pcr0.txt)
./setup-kms-policy.sh --pcr0 "$NEW_PCR0" --old-pcr0 "$OLD_PCR0" \
    --build-admin "$BUILD_ROLE_ARN" ...

# Deploy new EIF
nitro-cli terminate-enclave --enclave-id $(nitro-cli describe-enclaves | jq -r '.[0].EnclaveID')
nitro-cli run-enclave --eif-path vta.eif ...

# Health check
sleep 10
curl --fail http://localhost:8443/health || exit 1

# Lock down: remove old PCR0
./setup-kms-policy.sh --pcr0 "$NEW_PCR0" --build-admin "$BUILD_ROLE_ARN" ...

# Save for next upgrade
echo "$NEW_PCR0" > /opt/vta/last-pcr0.txt
```

## Disaster Recovery

| Scenario | Recovery |
|----------|----------|
| Enclave restart | Automatic — KMS Decrypt retrieves seed from bootstrap keyspace |
| EBS volume lost | Use mnemonic backup with `vta tee recover --mnemonic "..."` |
| KMS key deleted | Use mnemonic to regenerate seed with a new KMS key |
| PCR0 mismatch after rebuild | Rolling upgrade with `--old-pcr0`, or fresh deploy |
| Signing key lost | Generate new key, rebuild + re-sign EIF, update PCR8 in KMS policy |

## IAM Role Configuration

### EC2 Instance Role (Minimal)

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "kms:Decrypt",
                "kms:GenerateDataKey"
            ],
            "Resource": "arn:aws:kms:REGION:ACCOUNT:key/KEY_ID"
        }
    ]
}
```

**This role intentionally does NOT include:**
- `kms:PutKeyPolicy` — cannot modify the KMS key policy
- `kms:CreateGrant` — cannot delegate access
- `kms:ScheduleKeyDeletion` — cannot destroy the key
- `iam:*` — cannot modify its own permissions

### Admin Role (Separate, MFA-Protected)

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": "kms:*",
            "Resource": "arn:aws:kms:REGION:ACCOUNT:key/KEY_ID",
            "Condition": {
                "Bool": {"aws:MultiFactorAuthPresent": "true"}
            }
        }
    ]
}
```

## CI/CD Integration

### GitHub Actions Example

```yaml
name: Build VTA Enclave

on:
  push:
    branches: [main]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Build Docker image
        run: docker build -f Dockerfile.nitro -t vta-nitro .

      - name: Write signing key
        run: |
          echo "${{ secrets.EIF_SIGNING_KEY }}" > /tmp/signing-key.pem
          echo "${{ secrets.EIF_SIGNING_CERT }}" > /tmp/signing-cert.pem

      - name: Build and sign EIF
        run: |
          nitro-cli build-enclave \
              --docker-uri vta-nitro \
              --output-file vta.eif \
              --signing-certificate /tmp/signing-cert.pem \
              --private-key /tmp/signing-key.pem | tee build-output.json

      - name: Extract PCR0 and update KMS policy
        env:
          AWS_REGION: us-east-1
          KMS_KEY_ARN: ${{ secrets.KMS_KEY_ARN }}
          EC2_ROLE_ARN: ${{ secrets.EC2_ROLE_ARN }}
        run: |
          PCR0=$(jq -r '.Measurements.PCR0' build-output.json)
          PCR8=$(cat signing/pcr8.txt)
          ./deploy/nitro/setup-kms-policy.sh \
              --pcr0 "$PCR0" --pcr8 "$PCR8" \
              --role "$EC2_ROLE_ARN" --key-arn "$KMS_KEY_ARN"

      - name: Upload EIF
        run: aws s3 cp vta.eif s3://my-bucket/vta/vta.eif

      - name: Cleanup signing key
        if: always()
        run: rm -f /tmp/signing-key.pem /tmp/signing-cert.pem
```

## Port Reference

| Vsock Port | Direction | Purpose |
|-----------|-----------|---------|
| 5100 | Parent → Enclave | Inbound REST API |
| 5200 | Enclave → Parent | Outbound DIDComm (mediator WebSocket) |
| 5300 | Enclave → Parent | Outbound HTTPS (DID resolution, KMS) |
| 5400 | Enclave → Parent | Outbound IMDS (AWS IAM credentials) |
| 5500 | Enclave → Parent | Persistent K/V storage |
| 5600 | Enclave → Parent | DID resolver (WebSocket to sidecar) |

## Files

| File | Where | Purpose |
|------|-------|---------|
| `Dockerfile.nitro` | Build host | Multi-stage build → Docker image |
| `build-vta.sh` | Build host / CI | Builds + signs the EIF and emits a deployable bundle (EIF, config, PCR values, manifest) |
| `deploy-enclave.sh` | Parent EC2 | Consumes a bundle, installs the resolver sidecar, starts the enclave-proxy, launches the enclave |
| `deploy-vta.sh` | Build host *and* EC2 (dev only) | Thin wrapper around the two scripts above — single-host dev/test convenience |
| `deploy-common.sh` | (sourced) | Shared helpers: logging, prompting, pid tracking, group checks |
| `generate-signing-key.sh` | Build host / CI | Generate EC P-384 signing key + certificate |
| `setup-kms-policy.sh` | Admin workstation | Create/update KMS key with PCR-pinned policy |
| `iam-kms-admin-policy.json` | Admin workstation | IAM policy for the user running setup-kms-policy.sh |
| `enclave-entrypoint.sh` | Enclave | Set up lo, vsock proxies, start VTA |
| `enclave-proxy/` | Parent EC2 | Rust proxy binary — bridges vsock ↔ TCP/TLS, HTTPS CONNECT proxy |
| `parent-proxy.sh` | Parent EC2 | Shell script fallback (requires socat + vsock-proxy) |
| `affinidi-did-resolver-cache-server` | Parent EC2 | DID resolver sidecar — `cargo install` from crates.io (upstream at `affinidi/affinidi-tdk-rs`), listens on `localhost:8080` with WebSocket endpoint `/did/v1/ws`, bridged over vsock:5600 |
| `.deploy-nitro/resolver/conf/cache-conf.toml` | Parent EC2 (generated) | Minimal config for the sidecar — written by `deploy-vta.sh` Step 9 |
| `config.toml` | Reference | Example config with KMS + DIDComm |
