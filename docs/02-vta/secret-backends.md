# Secret-Storage Backends

The VTA's master seed is the root of every key it manages. This
chapter is the single reference for where that seed can live, how to
wire each backend up, and which one to pick for a given deployment.

If you just want to get going, the answer for most cases is:

| Deployment | Backend |
|---|---|
| Local development on a workstation | OS keyring (default) |
| AWS Nitro Enclave | KMS-TEE (automatic via `vta-enclave`) |
| EKS / GKE / AKS / on-prem Kubernetes, Vault available | HashiCorp Vault with Kubernetes auth |
| EKS / GKE / AKS / on-prem Kubernetes, no Vault | Kubernetes `Secret` (native, no extra infra) |
| Single EC2 / GCE / Azure VM, no TEE | AWS Secrets Manager / GCP Secret Manager / Azure Key Vault |
| CI / sealed images / unattended bootstrap | Config-seed (with the seed coming in via a sealed channel) |

Read [Picking a backend](#picking-a-backend) below if you want the
trade-offs rather than the cheat-sheet.

---

## How backend selection works

`vti_common::seed_store::SeedStore` is a small async trait
(`get` / `set` / `delete`). Every backend implements it. The concrete
backends and the factory live in the shared **`vti-secrets`** crate
(`vti_secrets::create_seed_store(&secrets, &data_dir)`), so any external
VTI integration can reuse them without depending on `vta-service`.
`vta-service` re-exports them from `keys::seed_store` and keeps a thin
`create_seed_store(&config)` wrapper, so first-party call sites are
unchanged. At startup that wrapper walks the configured backends in
priority order and returns the first one whose feature is compiled in
**and** whose config is populated:

| Priority | Backend | Cargo feature | Activates when… |
|---|---|---|---|
| 1 | AWS Secrets Manager | `aws-secrets` | `secrets.aws_secret_name` is set |
| 2 | GCP Secret Manager | `gcp-secrets` | `secrets.gcp_secret_name` is set |
| 3 | Azure Key Vault | `azure-secrets` | `secrets.azure_vault_url` is set |
| 4 | HashiCorp Vault | `vault-secrets` | `secrets.vault_addr` is set |
| 5 | Kubernetes `Secret` | `k8s-secrets` | `secrets.k8s_secret_name` is set |
| 6 | Config-seed | `config-seed` | `secrets.seed` is set |
| 7 | OS keyring | `keyring` | always (the default) |
| 8 | Plaintext file | always available | unconditional fallback |

If no secure-backend feature is compiled and no config is set, the
service falls back to a plaintext file in the data directory and
**logs a warning**. The plaintext backend exists for first-boot
testing only — never use it in production.

In TEE mode (`vta-enclave`), the KMS-backed bootstrap path provides
the seed directly via attested decryption; the table above is
bypassed entirely. See
[`../01-concepts/tee-architecture.md`](../01-concepts/tee-architecture.md).

## Encoding

Every backend stores the master seed as a **hex-encoded string** of
the BIP-39 entropy bytes (32 bytes for 24-word mnemonics, 16 for
12-word). This is consistent across AWS / GCP / Azure / Vault /
Kubernetes / keyring / config-seed / plaintext. Mismatched encodings are the
single most common foot-gun when migrating between backends — they
are otherwise wire-compatible.

---

## Backends

### AWS Secrets Manager

Cargo feature: `aws-secrets` · File: `vti-secrets/src/seed_store/aws.rs`

Stores the seed in a named AWS Secrets Manager secret in the VTA's
deployment region. AWS credentials resolve from the standard SDK
chain: IAM role on EC2/EKS, env vars, `~/.aws/credentials`, etc.

```toml
[secrets]
aws_secret_name = "vta/master-seed"
aws_region      = "us-east-1"   # optional; falls back to AWS_REGION env / IMDS
```

Equivalent env vars:

```bash
VTA_SECRETS_AWS_SECRET_NAME=vta/master-seed
VTA_SECRETS_AWS_REGION=us-east-1
```

IAM policy on the secret:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "secretsmanager:GetSecretValue",
        "secretsmanager:PutSecretValue",
        "secretsmanager:CreateSecret"
      ],
      "Resource": "arn:aws:secretsmanager:us-east-1:*:secret:vta/master-seed-*"
    }
  ]
}
```

`CreateSecret` is needed only on the very first `vta setup`. Drop it
from the policy after first-boot if you'd like the principle of
least privilege.

### GCP Secret Manager

Cargo feature: `gcp-secrets` · File: `vti-secrets/src/seed_store/gcp.rs`

Stores the seed as a Secret Manager secret version. Authentication
uses Application Default Credentials — service-account JSON, GCE
metadata server, or Workload Identity in GKE.

```toml
[secrets]
gcp_project     = "my-project-id"
gcp_secret_name = "vta-master-seed"
```

Equivalent env vars:

```bash
VTA_SECRETS_GCP_PROJECT=my-project-id
VTA_SECRETS_GCP_SECRET_NAME=vta-master-seed
```

IAM role on the secret resource (or project, broader): `roles/secretmanager.secretVersionManager`
covers reads + writes of new versions; downgrade to
`roles/secretmanager.secretAccessor` after first-boot.

### Azure Key Vault

Cargo feature: `azure-secrets` · File: `vti-secrets/src/seed_store/azure.rs`

Stores the seed as a Key Vault secret. Authentication uses the
DefaultAzureCredential chain — Managed Identity, az CLI session,
service principal, etc.

```toml
[secrets]
azure_vault_url    = "https://my-vault.vault.azure.net"
azure_secret_name  = "vta-master-seed"   # default if omitted
```

Equivalent env vars:

```bash
VTA_SECRETS_AZURE_VAULT_URL=https://my-vault.vault.azure.net
VTA_SECRETS_AZURE_SECRET_NAME=vta-master-seed
```

The principal needs `Get` and `Set` permissions on secrets in the
target vault. After first-boot the `Set` permission can be revoked.

### HashiCorp Vault

Cargo feature: `vault-secrets` · File: `vti-secrets/src/seed_store/vault.rs`

Stores the seed as a field within a Vault KV v2 secret. Designed for
in-cluster Kubernetes deployments but works anywhere. Three auth
methods are supported, picked by `secrets.vault_auth_method`:
`kubernetes` (default), `token`, or `approle`.

The Vault token is **auto-renewed** in the background: a tokio task
renews at half the lease duration and re-authenticates from scratch
when the lease can no longer be extended. SA JWTs are re-read from
the kubelet-mounted projected-volume path on every authentication so
kubelet rotations are picked up transparently.

#### Kubernetes auth (default — pod talks to Vault directly)

```toml
[secrets]
vault_addr         = "https://vault.svc.cluster.local:8200"
vault_secret_path  = "vta/master-seed"
vault_kv_mount     = "secret"      # default
vault_secret_key   = "seed"        # default
vault_auth_method  = "kubernetes"  # default
vault_k8s_role     = "vta"
vault_k8s_mount    = "kubernetes"  # default
# vault_k8s_jwt_path defaults to /var/run/secrets/kubernetes.io/serviceaccount/token
```

Equivalent env vars (canonical Vault names work too):

```bash
VAULT_ADDR=https://vault.svc.cluster.local:8200
VAULT_NAMESPACE=engineering            # Vault Enterprise only
VTA_SECRETS_VAULT_SECRET_PATH=vta/master-seed
VTA_SECRETS_VAULT_K8S_ROLE=vta
```

Vault server-side configuration (one-time):

```bash
# Enable the K8s auth method
vault auth enable kubernetes

# Tell Vault how to reach the cluster's API
vault write auth/kubernetes/config \
    kubernetes_host="https://kubernetes.default.svc"

# Bind the VTA's ServiceAccount to a policy that grants KV read/write
vault policy write vta-policy - <<EOF
path "secret/data/vta/master-seed" {
  capabilities = ["read", "create", "update"]
}
EOF

vault write auth/kubernetes/role/vta \
    bound_service_account_names="vta" \
    bound_service_account_namespaces="vta-prod" \
    policies="vta-policy" \
    ttl="1h"
```

The pod runs with a ServiceAccount named `vta` in the `vta-prod`
namespace; the kubelet-mounted SA JWT presents that identity to
Vault.

#### Static-token auth

```toml
[secrets]
vault_addr        = "https://vault.example.com"
vault_secret_path = "vta/master-seed"
vault_auth_method = "token"
# Don't put the token in the config file — pass via env:
```

```bash
VAULT_TOKEN=hvs.xxx...
```

Suited to local development and CI. Renewal is best-effort — static
tokens have no auth-time lease, so the renewal task polls every 5
minutes and re-authenticates on token rotation.

#### AppRole auth

```toml
[secrets]
vault_addr               = "https://vault.example.com"
vault_secret_path        = "vta/master-seed"
vault_auth_method        = "approle"
vault_approle_mount      = "approle"   # default
vault_approle_role_id    = "abc-123-..."
vault_approle_secret_id  = "def-456-..."
```

Equivalent env vars:

```bash
VTA_SECRETS_VAULT_APPROLE_ROLE_ID=abc-123-...
VTA_SECRETS_VAULT_APPROLE_SECRET_ID=def-456-...
```

Useful for non-K8s machines where you still want short-lived,
auto-renewable Vault tokens (Nomad, plain VMs with a sidecar that
provisions the secret-id, etc.).

#### TLS

`vault_skip_verify = true` (or `VAULT_SKIP_VERIFY=1`) disables TLS
certificate verification. **Dev/test only.** Production deployments
should run a Vault that presents a CA-trusted certificate; the VTA
uses the system trust store to validate.

#### Common pitfalls

- **`vault_kv_mount` vs Vault path notation.** In the Vault CLI you
  write `vault kv put secret/vta/master-seed seed=<hex>` (the `/data/`
  segment is implicit). In our config you set `vault_kv_mount =
  "secret"` and `vault_secret_path = "vta/master-seed"` — also no
  `/data/`. The vaultrs library injects it for KV v2.
- **Field name.** The seed lives at `data.seed` by default. If you
  put it under a different key (e.g. `bip39_seed`), set
  `vault_secret_key = "bip39_seed"` to match.
- **Pod restarts on token expiry.** Don't rely on it. The renewal
  task is in-process; pod restarts will re-authenticate cleanly.
- **CrashLoopBackOff with `kubernetes auth` errors.** The most
  common cause is the ServiceAccount name/namespace not matching the
  Vault role's `bound_service_account_*` lists. Run
  `vault read auth/kubernetes/role/vta` and double-check.

### Kubernetes `Secret`

Cargo feature: `k8s-secrets` · File: `vti-secrets/src/seed_store/k8s.rs`

Stores the seed as a hex string inside a namespaced Kubernetes
`Secret`. For in-cluster deployments that want to keep secret
material native to Kubernetes without standing up HashiCorp Vault or
reaching out to a cloud secret manager. Credentials are resolved by
`kube`'s `Client::try_default()`: the pod's mounted ServiceAccount
token in-cluster, or your local kubeconfig (`~/.kube/config` /
`$KUBECONFIG`) when running `vta` outside the cluster (e.g. during
`vta setup`).

```toml
[secrets]
k8s_secret_name = "vta-master-seed"
k8s_namespace   = "vta-prod"   # optional; see below
k8s_secret_key  = "seed"       # optional; default "seed"
```

Equivalent env vars:

```bash
VTA_SECRETS_K8S_SECRET_NAME=vta-master-seed
VTA_SECRETS_K8S_NAMESPACE=vta-prod
VTA_SECRETS_K8S_SECRET_KEY=seed
```

**Namespace resolution.** If `k8s_namespace` is omitted, the
backend uses the client's default namespace — the pod's own
namespace in-cluster (from the mounted ServiceAccount), or the
current kubeconfig context's namespace out-of-cluster — falling back
to `default`. The most common in-cluster pattern is to inject the
pod's namespace via the Downward API so you don't hard-code it:

```yaml
env:
  - name: VTA_SECRETS_K8S_SECRET_NAME
    value: vta-master-seed
  - name: VTA_SECRETS_K8S_NAMESPACE
    valueFrom:
      fieldRef:
        fieldPath: metadata.namespace
```

**RBAC.** The pod's ServiceAccount needs `get` on the Secret, plus
`create` (first `vta setup`, when the Secret doesn't exist yet) and
`update` (re-keying / writes). After first-boot you can drop down to
`get` only if the seed never rotates.

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: vta-seed-secret
  namespace: vta-prod
rules:
  - apiGroups: [""]
    resources: ["secrets"]
    verbs: ["get", "create", "update"]
    # Optionally scope to the single Secret by name:
    resourceNames: ["vta-master-seed"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: vta-seed-secret
  namespace: vta-prod
subjects:
  - kind: ServiceAccount
    name: vta
roleRef:
  kind: Role
  name: vta-seed-secret
  apiGroup: rbac.authorization.k8s.io
```

#### Vault vs native Kubernetes `Secret`

Both target in-cluster deployments. Reach for **Vault** when you
already run it, want envelope encryption / dynamic secrets / a full
audit trail, or your security posture requires secrets never to sit
in `etcd` in (only base64-encoded) plaintext. Reach for the
**native `Secret`** backend when you want zero extra
infrastructure — particularly when etcd encryption-at-rest is already
enabled on the cluster (so the Secret is encrypted at rest by the API
server) and a `Secret` + RBAC is all you need.

#### Common pitfalls

- **etcd plaintext.** A bare Kubernetes `Secret` is only
  base64-encoded in etcd, not encrypted, unless the cluster has
  [encryption at rest](https://kubernetes.io/docs/tasks/administer-cluster/encrypt-data/)
  configured. Enable it (or use Vault / a cloud secret manager) before
  treating this as production-grade.
- **Wrong namespace.** A `get` returning "not found" when the Secret
  clearly exists almost always means the resolved namespace differs
  from where the Secret lives. Set `k8s_namespace` explicitly to rule
  it out.
- **Key name mismatch.** The seed lives under `data.seed` by default.
  If your Secret stores it under a different key, set `k8s_secret_key`
  to match — the backend fails loudly (rather than minting a new seed)
  when the Secret exists but the configured key is absent.

### KMS-TEE (Nitro Enclave)

Cargo feature: `tee` · File: `vti-secrets/src/seed_store/kms_tee.rs`

In `vta-enclave` deployments the seed never enters the file system.
Instead, the enclave performs an **attested decryption** at boot:

1. Generate an attestation document (PCR0/1/2 measurements, optional
   nonce, ephemeral RSA pubkey).
2. Send it to KMS via `kms:Decrypt` with the encrypted seed
   ciphertext.
3. KMS verifies the attestation against a Condition policy on the
   key, then encrypts the plaintext seed back to the enclave's
   ephemeral pubkey.
4. The enclave decrypts using its in-memory private key. The seed
   lives in `Zeroizing<[u8; 64]>` for the rest of the process
   lifetime.

There is no operator-visible config for this backend beyond the
upstream KMS key and the encrypted-seed ciphertext (provided via
`vta-enclave`'s parent-instance bootstrap). See
[`../01-concepts/tee-architecture.md`](../01-concepts/tee-architecture.md)
for the full design.

### OS keyring

Cargo feature: `keyring` (default) · File: `vti-secrets/src/seed_store/keyring.rs`

The default for local development. Stores the seed under
`service = "vta"`, `username = "master_seed"` in the OS-native
credential store: macOS Keychain, GNOME Keyring / KWallet via
libsecret on Linux, Windows Credential Manager on Windows.

```toml
[secrets]
keyring_service = "vta"   # default
```

Set `keyring_service` to a different value to run multiple VTA
instances on the same workstation (e.g. `"vta-dev"`, `"vta-staging"`).

The keyring is **interactive** on macOS — a Keychain unlock prompt
may appear when `vta` first reads the seed in a fresh terminal
session. CI / headless environments should use a different backend.

### Config-seed

Cargo feature: `config-seed` · File: `vti-secrets/src/seed_store/config.rs`

Reads the hex-encoded seed directly from the config file:

```toml
[secrets]
seed = "abcdef0123456789..."   # 32 or 64 hex chars
```

Designed for **CI / sealed images / unattended bootstrap** where
the seed arrives via an out-of-band sealed channel
(`vta bootstrap open …` writes the unsealed seed material into the
config). Not appropriate for long-running production deployments —
the seed sits on disk in plaintext.

If you find yourself reaching for this in production, use Vault or a
cloud secret manager instead.

### Plaintext file (fallback only)

File: `vti-secrets/src/seed_store/plaintext.rs`

Always available, no Cargo feature required. Stores the seed as a
hex string in `<data_dir>/seed.hex`. The service emits a `WARN` log
line at startup when this backend is selected:

```
WARN no secure seed store backend available — falling back to plaintext file storage
```

Use only when first-boot-bringing-up a VTA in a sandbox where you
plan to migrate to a real backend before any production traffic hits
the system. Or when you are deliberately testing failure modes.

---

## Picking a backend

### Decision flowchart

```
Are you running inside an AWS Nitro Enclave?
├── Yes → KMS-TEE (automatic, no config)
└── No  ↓

Are you running inside a Kubernetes cluster?
├── Yes, and you run HashiCorp Vault → Vault, kubernetes auth
├── Yes, no Vault                     → Kubernetes Secret (k8s-secrets)
└── No  ↓

Do you have a managed cloud secret store you already trust?
├── AWS  → AWS Secrets Manager
├── GCP  → GCP Secret Manager
├── Azure → Azure Key Vault
└── No  ↓

Do you have HashiCorp Vault deployed (any auth method)?
├── Yes → HashiCorp Vault
└── No  ↓

Is this a developer workstation?
├── Yes → OS keyring
└── No  → Stand up Vault before going to production. Use config-seed
         only as a sealed-image / CI bridge.
```

### Trade-offs

| | AWS SM | GCP SM | Azure KV | Vault | K8s Secret | KMS-TEE | Keyring | Config | Plaintext |
|---|---|---|---|---|---|---|---|---|---|
| Encrypted at rest | ✅ | ✅ | ✅ | ✅ (Vault internal) | ⚠️ only if etcd encryption on | ✅ (KMS) | ✅ (OS) | ❌ | ❌ |
| Auto rotation friendly | ✅ | ✅ | ✅ | ✅ | ✅ | n/a | ❌ | ❌ | ❌ |
| Works in TEE | via parent | via parent | via parent | via parent | via parent | ✅ native | ❌ | ❌ | ❌ |
| Works headless / CI | ✅ | ✅ | ✅ | ✅ | ✅ | n/a | ⚠️ macOS prompts | ✅ | ✅ |
| In-process auto-renewal | implicit (IAM) | implicit (ADC) | implicit (MI) | ✅ explicit | implicit (SA token) | implicit (KMS) | n/a | n/a | n/a |
| Extra infra required | cloud SM | cloud SM | cloud KV | Vault | none (in-cluster) | KMS | none | none | none |
| Production-ready | ✅ | ✅ | ✅ | ✅ | ✅ (with etcd enc.) | ✅ | dev only | dev only | never |

## Migrating between backends

Every backend stores the seed as the **same hex-encoded string**, so
migrating is a copy operation between two trusted CLIs.

> The VTA does **not** ship a built-in seed export. There is no
> `vta keys seeds export` command. Exposing the master seed from the
> CLI would be a single-step path to leaking the root of the entire
> key hierarchy, so we rely on the source backend's vendor CLI for
> the read step — that CLI already has the audit logging and access
> controls your organization has standardized on. `vta keys seeds`
> only lists generation metadata; it never prints the seed bytes.

### Procedure

1. **Stop the VTA.** Migration is offline. Take a backup of the
   local fjall store first (`pnm backup export`).

2. **Read the seed from the source backend** with the vendor CLI.
   The output is hex (32 or 64 chars):

   | Source | Command |
   |---|---|
   | macOS keyring | `security find-generic-password -s vta -a master_seed -w` |
   | Linux keyring | `secret-tool lookup service vta username master_seed` |
   | AWS Secrets Manager | `aws secretsmanager get-secret-value --secret-id vta/master-seed --query SecretString --output text` |
   | GCP Secret Manager | `gcloud secrets versions access latest --secret=vta-master-seed` |
   | Azure Key Vault | `az keyvault secret show --vault-name my-vault --name vta-master-seed --query value -o tsv` |
   | HashiCorp Vault | `vault kv get -field=seed secret/vta/master-seed` |
   | Kubernetes Secret | `kubectl -n vta-prod get secret vta-master-seed -o jsonpath='{.data.seed}' \| base64 -d` |
   | Config-seed | `awk '/^seed/ {print $3}' config.toml` (already plaintext) |
   | Plaintext file | `cat <data_dir>/seed.hex` |

   Sanity-check the length: 64 chars for a 24-word mnemonic, 32 for
   a 12-word. Anything else is wrong and you should stop here.

3. **Write the same hex value to the destination backend** with its
   vendor CLI. Substitute `<hex>` for the value you read in step 2:

   | Destination | Command |
   |---|---|
   | macOS keyring | `security add-generic-password -s vta -a master_seed -w '<hex>' -U` |
   | Linux keyring | `secret-tool store --label='vta' service vta username master_seed` (then paste hex on stdin) |
   | AWS Secrets Manager | `aws secretsmanager create-secret --name vta/master-seed --secret-string '<hex>'` (use `put-secret-value` if it already exists) |
   | GCP Secret Manager | `printf %s '<hex>' \| gcloud secrets versions add vta-master-seed --data-file=-` |
   | Azure Key Vault | `az keyvault secret set --vault-name my-vault --name vta-master-seed --value '<hex>'` |
   | HashiCorp Vault | `vault kv put secret/vta/master-seed seed='<hex>'` |
   | Kubernetes Secret | `kubectl -n vta-prod create secret generic vta-master-seed --from-literal=seed='<hex>'` |

   Pass the hex via env var or stdin where possible; argv exposes
   it to `ps`. For example:

   ```bash
   HEX=$(security find-generic-password -s vta -a master_seed -w)
   vault kv put secret/vta/master-seed seed="$HEX"
   unset HEX
   ```

4. **Update `[secrets]` in `config.toml`** to reference the
   destination backend. The simplest path is to **remove** the old
   backend's keys so there's no ambiguity — but if you leave both,
   the priority order in [How backend selection works](#how-backend-selection-works)
   resolves the destination first, so it still works.

5. **Restart the VTA.** Local fjall state (key records, ACL,
   contexts, sessions) is untouched. The VTA reads the seed from
   the new backend at boot and resumes.

6. **Verify** with `vta status` and at least one authenticated REST
   or DIDComm call. If anything is wrong (signing fails, DIDComm
   handshake mismatches), **stop, revert config.toml**, and
   investigate before deleting anything.

7. **Once verified, delete the seed from the source backend** with
   the vendor CLI. Don't leave it lying around just in case —
   that's a leak waiting to happen.

### Cross-checks

The pubkey of `<vta_did>#key-0` is deterministic from the seed and
the BIP-32 path stored in the key record. After the restart in
step 5, run `vta keys list --context vta` and confirm the
`Public Key Multibase` matches the value the running service
publishes via `GET /config`. If they differ, the seed you migrated
is not the seed the existing key records were derived from — back
out before continuing.

### Treat it like key rotation

Schedule the migration as a maintenance window, take the backup,
keep the source backend's secret retained until you've observed the
new backend through a full operator flow (auth + a signing call +
DIDComm round-trip if applicable), then delete. Don't migrate
under time pressure.

### Future: built-in seed migration

A `vta keys seeds export-hex --confirm` and matching
`vta keys seeds import-hex` pair would shorten this procedure to
two commands. The code already has `seed_store.get()` and
`seed_store.set()` as the underlying primitives. The reason it's
not exposed today is the foot-gun risk; if your operations posture
makes a CLI export safe (e.g. you run the VTA as an unprivileged
user and sudo controls the relevant binary), open an issue with
your threat-model writeup and we can wire it up.

## See also

- [`feature-flags.md`](feature-flags.md) — Cargo-level feature
  reference (build profiles, dependency graph).
- [`cold-start.md`](cold-start.md) — first-boot setup walkthrough,
  including how the wizard interacts with the chosen backend.
- [`non-interactive-setup.md`](non-interactive-setup.md) —
  `vta setup --from <file>` with a TOML config that pre-selects the
  backend.
- [`../01-concepts/tee-architecture.md`](../01-concepts/tee-architecture.md) —
  Nitro Enclave / KMS bootstrap design, including the parent-side
  seed-encryption procedure.
