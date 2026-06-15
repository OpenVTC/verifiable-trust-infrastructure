# Feature Flags

The VTI workspace uses Cargo feature flags to control which
capabilities are compiled in. This chapter is the reference for what
each flag does, what it pulls in, and which deployment profile uses
it.

For the operator-facing view of secret-storage backends (which one
to pick, how to configure each), see
[`secret-backends.md`](secret-backends.md). This chapter is the
build-time perspective.

## vta-service features

These are the flags on the `vta-service` library crate. Front-end
binaries (`vta-enclave`, etc.) forward relevant flags to
`vta-service`.

| Feature | Purpose | Dependencies |
|---|---|---|
| `rest` | REST API endpoints (axum routes) | None |
| `didcomm` | DIDComm v2 messaging transport | None |
| `tee` | TEE attestation types, providers, KMS bootstrap | `libc`, `hmac`, `aws-sdk-kms`, `aws-config`, `rsa`, `didwebvh-rs` |
| `webvh` | did:webvh DID management (create, update, delete) | `didwebvh-rs`, `url`, `reqwest` |
| `setup` | Interactive setup wizard (requires TTY) | `webvh`, `tempfile` |
| `keyring` | OS keyring seed storage | `keyring` |
| `config-seed` | Load seed from config file | None |
| `aws-secrets` | AWS Secrets Manager seed storage | `aws-sdk-secretsmanager`, `aws-config` |
| `gcp-secrets` | GCP Secret Manager seed storage | `google-cloud-secretmanager`, `google-cloud-auth`, `bytes` |
| `azure-secrets` | Azure Key Vault seed storage | `azure_security_keyvault_secrets`, `azure_identity` |
| `vault-secrets` | HashiCorp Vault seed storage (KV v2; Kubernetes / token / AppRole auth) | `vaultrs` |
| `k8s-secrets` | Kubernetes `Secret` seed storage (in-cluster SA or kubeconfig) | `kube`, `k8s-openapi` |
| `vsock-store` | Vsock-proxied persistent storage (for enclaves) | `vti-common/vsock-store` |
| `vsock-log` | Vsock-proxied log forwarding (for enclaves) | `vti-common/vsock-log` |

**Default features:** `setup`, `keyring`, `rest`, `didcomm`

**Compile-time constraint:** at least one of `rest` or `didcomm` must
be enabled, or the build fails with a compile error.

## Feature dependency graph

```
default = [setup, keyring, rest, didcomm]

setup ──→ webvh ──→ [didwebvh-rs, url, reqwest]

tee ──→ [libc, hmac, aws-sdk-kms, aws-config, rsa, didwebvh-rs]

vsock-store ──→ vti-common/vsock-store ──→ [tokio-vsock, libc]
```

**Key relationships:**

- `setup` automatically enables `webvh` (the wizard creates
  did:webvh identities).
- `tee` pulls in `didwebvh-rs` (for automatic DID generation on
  first boot).
- `vsock-store` is a cross-crate feature chain:
  `vta-enclave` → `vta-service` → `vti-common`.

## vti-common features

| Feature | Purpose |
|---|---|
| `encryption` | AES-256-GCM encryption for `KeyspaceHandle.with_encryption()` |
| `vsock-store` | `VsockStore` and `VsockKeyspaceHandle` for vsock-proxied storage |

## vta-enclave features

| Feature | Purpose |
|---|---|
| `rest` | Forwards to `vta-service/rest` |
| `didcomm` | Forwards to `vta-service/didcomm` |
| `webvh` | Forwards to `vta-service/webvh` |
| `vsock-store` | Forwards to `vta-service/vsock-store` |

The `tee` feature is always enabled on `vta-service` (hardcoded in
the dependency: `features = ["tee"]`). No need to specify it.

## Deployment profiles

| Profile | vta-service binary | vta-enclave binary |
|---|---|---|
| Local development | `default` (setup, keyring, rest, didcomm) | N/A |
| Nitro Hardened (DIDComm only) | N/A | `didcomm,vsock-store` |
| Nitro Full API (REST + DIDComm) | N/A | `rest,didcomm,vsock-store` |
| Nitro REST only | N/A | `rest,vsock-store` |
| Cloud (no TEE), AWS | `rest,didcomm,aws-secrets` | N/A |
| Cloud (no TEE), GCP | `rest,didcomm,gcp-secrets` | N/A |
| Cloud (no TEE), Azure | `rest,didcomm,azure-secrets` | N/A |
| Kubernetes (Vault available) | `rest,didcomm,vault-secrets` | N/A |
| Kubernetes (native Secret) | `rest,didcomm,k8s-secrets` | N/A |

For the runtime configuration that pairs with each backend feature
(TOML keys, env vars, IAM/Vault setup), see
[`secret-backends.md`](secret-backends.md).
