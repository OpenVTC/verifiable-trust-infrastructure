# Non-Interactive VTA Setup

`vta setup --from <file>` provisions a VTA end-to-end from a single TOML
inputs file — no prompts, no terminal needed. Use it for CI pipelines,
immutable images, sealed-image redeploys, or any unattended bootstrap.

For the prompted walkthrough, see
[`cold-start.md`](cold-start.md). Both paths produce
identical state on disk.

## When to use which

| Scenario | Command |
|---|---|
| First time, you want to be guided through choices | `vta setup` |
| You already know what you want, want it scripted | `vta setup --from setup.toml` |
| CI pipeline, sealed image, headless host | `vta setup --from setup.toml` |
| You want to seed the first admin and seal the VTA in one step | `vta setup --from setup.toml` (with `admin_did` set) |

## Quick start

A minimum viable setup file:

```toml
config_path = "/srv/vta/config.toml"
data_dir    = "/srv/vta/data"

[secrets]
backend = "keyring"
service = "vta-prod"
```

Run it:

```bash
vta setup --from setup.toml
```

This generates a fresh seed, writes `config.toml`, initialises the store,
and prints next-step guidance. The VTA's ACL starts empty — seed an
admin separately:

```bash
vta bootstrap-admin --did did:key:z6Mk... --label ops
```

To add an integration (mediator, webvh hosting server, etc.) **after**
setup — offline, file-based, no running VTA required — see
[`../02-vta/provision-integration.md`](../02-vta/provision-integration.md).
The integration emits a signed VP, the VTA runs
`vta bootstrap provision-integration` locally, the integration opens
the returned sealed bundle. Same three-phase flow for every template-
driven integration.

## Full example with admin seeding and DID minting

```toml
config_path = "/srv/vta/config.toml"
data_dir    = "/srv/vta/data"
vta_name    = "trust-prod-1"
public_url  = "https://trust.example.com"

# Seed the first super-admin and seal the VTA atomically with the rest of
# setup. Skip this if you'd rather seed admin(s) later via `pnm setup`.
admin_did   = "did:key:z6MkABCDEFGHIJKLMNOPQRSTUVWXYZ"
admin_label = "ops-bootstrap"

[secrets]
backend     = "aws"
region      = "us-east-1"
secret_name = "vta/prod/seed"

[messaging]
kind    = "create_mediator"
context = "mediator"
url     = "https://mediator.example.com"

[vta_did]
kind               = "create_webvh"
url                = "https://trust.example.com/dids/vta"
portable           = true
pre_rotation_count = 2
```

A complete annotated reference is at
[`examples/vta-setup.example.toml`](examples/vta-setup.example.toml).

## Enterprise: owner + bounded staff

For an enterprise-managed VTA (the org owns and manages it; a staff member uses
it within bounds), add one or more `[[staff]]` entries. Each one creates a
context, applies its initial **context policy** (the guardrail), and seeds a
**context-scoped** ACL row — the bounded *user*. The super-admin `admin_did` is
the *owner*. Separation of duty is enforced VTA-side: the staff entry is scoped
to its context and bound by the policy; only the owner can change config or the
policy. (A personal VTA omits `[[staff]]` — owner and user are the same DID.)

```toml
config_path = "/etc/vta/config.toml"
data_dir    = "/var/lib/vta"

# The enterprise owner (super-admin).
admin_did   = "did:key:z6MkOWNER..."

[secrets]
backend = "keyring"

# A staff member, bounded to the `sales` context.
#
# `context` must be a slug: lowercase letters, digits and hyphens, no
# leading or trailing hyphen, 64 chars max. Setup fails on anything
# else rather than creating a context that `pnm contexts create` would
# later refuse.
[[staff]]
did     = "did:key:z6MkSTAFF..."
context = "sales"
label   = "Sales user"
role    = "application"          # use keys/present/vault within the context, never manage it

# The guardrail the staff member works within (all fields optional; absent = no
# constraint, resolved by intersection down the context tree, so a child can
# only narrow). Enforced even against the super-admin on this context's
# resources — relax by editing the policy, not by bypassing it.
[staff.context_policy]
export_allowed    = false                          # no sealed-transfer export / vault release
trusted_verifiers = ["did:web:partner.example"]    # may only present to these verifiers
presentable_types = ["MembershipCredential"]       # may only present these credential types
signable_keys     = ["sales-signing-key"]          # signing oracle limited to these key ids

[staff.context_policy.quotas]
per_day = { sign = 1000, "vault/release" = 10 }     # per-context daily ceilings
```

The same guardrails can be set/changed on a running VTA via
`pnm contexts update` (super-admin). Credentials received into a context — via
the receive request's `contextId`, or auto-bound when the caller has a single
context — are governed by that context's policy at presentation time.

## Schema

The schema is defined in Rust by `vta_service::setup::WizardInputs`
(vta-service/src/setup.rs). Field-level rustdoc on that struct is the
authoritative source — the snippets below are the operator-facing
summary.

### Top-level fields

| Field | Required | Default | Notes |
|---|---|---|---|
| `config_path` | yes | — | Where to write `config.toml`. Refuses to overwrite an existing file unless `overwrite_config` is set. |
| `overwrite_config` | no | `false` | Permit overwriting an existing `config_path`. The file is written only after everything else succeeds, so a failed run never destroys it. |
| `data_dir` | yes | — | On-disk fjall store location. |
| `vta_name` | no | `null` | Human-readable name. |
| `public_url` | no | `null` | Used as the `VTARest` service endpoint when minting a DID. |
| `data_dir_exists` | no | `"error"` | What to do if `data_dir` already holds a **store**. `"delete"` wipes the directory's contents (not the directory — so it works on a mount point) for CI re-runs; `"reuse"` initializes into it as-is. An existing-but-empty `data_dir` is never a conflict: see [Mounted data directories](#mounted-data-directories). |
| `admin_did` | no | `null` | If set, seeds a super-admin and seals the VTA atomically. Must start with `did:`. See [`seal-and-unseal.md`](seal-and-unseal.md) for the consequences of sealing at setup time and the recommended seal-last alternative. |
| `admin_label` | no | `null` | Label on the seeded admin's ACL row. |
| `staff` | no | `[]` | Array of `[[staff]]` entries — each creates a context, applies its `context_policy`, and seeds a context-scoped ACL row (the bounded *user*). See [Enterprise: owner + bounded staff](#enterprise-owner--bounded-staff). |

### Sections

- **`[services]`** — `rest = true` and `didcomm = true` by default. Seeds the
  *initial* enable state on first boot; subsequent runtime changes via
  `pnm services {kind} {enable,disable}` persist to a fjall keyspace
  (`service_state`), not back into `config.toml`. Hand-editing this block after
  first boot has no effect — use the runtime commands.
  `tsp = true` additionally advertises `#tsp` in the VTA DID document at mint,
  pointing at the same mediator as DIDComm. It requires `didcomm = true` (that
  is where the mediator is configured) and a binary built with
  `--features tsp`; setup refuses either combination by name rather than
  publishing a transport the VTA cannot answer on. Nothing checks that the
  mediator actually routes TSP — its services belong to its own controller.
- **`[server]`** — `host = "0.0.0.0"`, `port = 8100`.
- **`[log]`** — `level = "info"`, `format = "text"`.
- **`[secrets]`** — required; tagged enum on `backend`. See below.
- **`[messaging]`** — optional; tagged enum on `kind`. Default `"skip"`.
- **`[vta_did]`** — optional; tagged enum on `kind`. Default `"skip"`.
- **`[hardened]`** — optional; disabled by default. Enables storage encryption
  and managed JWT key material for non-TEE deployments. See below.

### Seed-store backends

`backend` selects the variant; per-variant fields are required.

| Backend | Fields |
|---|---|
| `"keyring"` | `service` (default `"vta"`) |
| `"aws"` | `secret_name`, optional `region` |
| `"gcp"` | `project`, `secret_name` |
| `"azure"` | `vault_url`, `secret_name` |
| `"vault"` | `addr`, `secret_path`, optional `kv_mount`/`secret_key`/`namespace`/`auth_method`/auth fields |
| `"kubernetes"` | `secret_name`, optional `namespace`, optional `secret_key` (default `"seed"`) |
| `"config_seed"` | none — hex seed embedded in `config.toml`. **Not recommended.** |
| `"plaintext"` | none — plaintext file under `data_dir`. **Dev only.** |

Cloud / external backends require the matching feature at compile time
(`aws-secrets`, `gcp-secrets`, `azure-secrets`, `vault-secrets`,
`k8s-secrets`) — the wizard refuses to proceed with a clear error if the
feature isn't compiled in.

A Kubernetes `Secret` backend, for example:

```toml
[secrets]
backend     = "kubernetes"
secret_name = "vta-master-seed"
namespace   = "vta-prod"   # optional; omit to use the pod's ServiceAccount namespace
secret_key  = "seed"       # optional; default "seed"
```

### Messaging

| `kind` | Fields | Use when |
|---|---|---|
| `"skip"` | — | No DIDComm. |
| `"existing"` | `did` | You already have a mediator DID. |
| `"create_mediator"` | `url`, `context` (default `"mediator"`) | Mint a new mediator using the built-in `didcomm-mediator` template. |

### VTA DID

| `kind` | Fields | Use when |
|---|---|---|
| `"skip"` | — | No VTA DID — the VTA has no signing identity. **The daemon refuses to boot in this state** (see note below). |
| `"existing"` | `did` | You already have a VTA DID. |
| `"create_webvh"` | `url`, `portable` (default `true`), `pre_rotation_count` (default `1`) | Mint a new did:webvh in "simple mode". |

`create_webvh` writes the DID's `did.jsonl` to
`<data_dir>/did-logs/<label>-did.jsonl` for re-publishing or audit.
Operators who need advanced DID options (template-from-file, pre-signed
log import, user-specified key IDs) should use interactive setup.

> **Booting without an identity.** A VTA whose `vta_did` (or JWT signing
> key) is unset has no usable signing identity: every authenticated
> endpoint answers `401` even though the port is open. To stop that from
> looking healthy to a liveness probe, `vta` **refuses to start** in this
> state and exits non-zero with a message naming the missing piece. If you
> deliberately want to boot a not-yet-provisioned instance — e.g. to
> inspect it or finish provisioning out-of-band — pass `vta --allow-degraded`,
> which restores the old serve-anyway behaviour. TEE/enclave deployments are
> unaffected: their identity is auto-generated during enclave boot.

## Mnemonic policy

Setup **always generates** a fresh 24-word BIP-39 mnemonic. There is no
way to provide your own at setup time — pasting a mnemonic into a
terminal exposes it to shell history, scrollback, and clipboard, and
that risk isn't worth the convenience.

If you need a known seed (disaster-recovery import, controlled key
ceremony), run after setup:

```bash
vta keys rotate-seed --mnemonic "<your 24 words>"
```

If you want a backup of the generated seed, run after the first admin
connects:

```bash
pnm backup export --output vta-backup.vtabak
```

The backup is password-encrypted and contains the seed plus the rest of
the VTA's persistent state.

## CI re-run pattern

For pipelines that re-run setup against a clean state each time:

```toml
config_path      = "/srv/vta/config.toml"
overwrite_config = true        # replace the previous run's config
data_dir         = "/srv/vta/data"
data_dir_exists  = "delete"    # wipe on re-run
admin_did        = "did:key:..."

[secrets]
backend = "aws"
secret_name = "vta/ci/seed"
```

Then in your pipeline:

```bash
vta setup --from setup.toml
vta --config /srv/vta/config.toml &    # ready to serve
```

The seed is generated fresh on each run, so the AWS secret value
changes each time — fine for CI, not what you want in production.

## Mounted data directories

`data_dir` is routinely a Docker volume, a bind mount, or a Kubernetes
PVC — and the container runtime creates that path *before* the container
starts. Setup accounts for this:

- **The existence check is store presence, not directory presence.** An
  empty `/app/vta-data` is a normal first-boot state and is initialized
  into silently. `data_dir_exists` is consulted only when the directory
  actually holds a fjall store.
- **`"delete"` clears the directory's contents, not the directory.**
  `rmdir` on a mount point fails with `EBUSY` on Linux (and a sharing
  violation on Windows) however empty it is, so removing the mount point
  itself is never attempted.
- **Setup refuses to run over an initialized VTA.** If the store already
  carries master seed generation 0, setup stops rather than minting a
  second master seed on top of the first, which would orphan every key
  derived from the original. Choose `"delete"` if you genuinely want to
  start over.

## Validation and errors

The wizard validates the file in two phases:

1. **TOML parse + schema** — happens at deserialization. Unknown fields,
   missing required fields, wrong types, and unknown enum variants all
   fail here with serde-quality messages.
2. **Cross-field rules** — happens before any state is mutated. All
   errors are collected and reported in a single message:

```
Setup failed: setup file has 2 validation error(s):
  - messaging.kind = "create_mediator" requires services.didcomm = true
  - admin_did = "not-a-did" must be a DID (starts with `did:`)
```

If validation passes, the wizard makes incremental changes (open store,
write seed, mint DIDs, seal). A failure mid-flight leaves whatever was
written on disk; the safest recovery is to delete `config_path` and
`data_dir` and re-run.

## What you get afterwards

```bash
# Inspect what was written
vta --config /srv/vta/config.toml config show

# Confirm the admin row landed
vta --config /srv/vta/config.toml acl list

# Start serving
vta --config /srv/vta/config.toml
```

If you set `admin_did`, the VTA is sealed and ready for production
management via the authenticated REST API or DIDComm. If you didn't,
follow the
[interactive admin-grant flow in `cold-start.md`](cold-start.md)
(`pnm setup` → `vta import-did` → start VTA → first authenticated
command auto-rotates).

## Non-interactive `pnm setup` (deferred-VTA-DID)

For automated VTA hosting — e.g. a Terraform module that needs the PNM
admin DID *before* the VTA is running — `pnm setup` has a two-phase
non-interactive mode that pairs naturally with `admin_did` in the
`vta setup --from` file above.

**Phase 1** mints the ephemeral admin `did:key` and parks it in the OS
keyring. Pass the slug-producing `--name`:

```bash
$ pnm setup --name "Trust Prod 1"
{"slug":"trust-prod-1","admin_did":"did:key:z6Mk...","state":"pending"}
```

The JSON line is the only thing on **stdout**; all narration is on
**stderr**, so pipelines can `jq` this directly:

```bash
ADMIN_DID=$(pnm setup --name "Trust Prod 1" | jq -r .admin_did)
```

Feed `$ADMIN_DID` into the VTA's `setup.toml`:

```toml
admin_did   = "${ADMIN_DID}"   # the one we just minted
admin_label = "pnm-bootstrap"
```

Run `vta setup --from setup.toml` on the VTA host, boot the VTA, capture
the VTA's DID (`vta config show`).

**Phase 2** binds the VTA DID and finalizes the PNM session:

```bash
$ pnm setup continue trust-prod-1 --vta-did did:webvh:...
{"slug":"trust-prod-1","admin_did":"did:key:z6Mk...","state":"complete"}
```

The same `did:key` from phase 1 is preserved — don't re-mint. The first
authenticated PNM command rotates to a fresh did:key and drops the
original from the ACL, same as the classic flow.

### Flags

| Flag | Phase | Effect |
|---|---|---|
| `--name <human-name>` | 1 | Slugified and used as the VTA identifier. Required in non-interactive mode. |
| `--overwrite` | 1 | Replace an *existing pending* setup for the same slug. Never overwrites a complete VTA — use `pnm vta remove <slug>` first. |
| `--vta-did <did:...>` | 2 | Non-interactive VTA DID. Omit for the interactive prompt. |

### Exit codes

- `0` — success. JSON written to stdout.
- `2` — input or state error. Targeted message on stderr (e.g.
  "pending setup already exists for slug 'X', pass `--overwrite`" or
  "'X' is already set up, use `pnm vta remove X` to start over").

### Idempotency notes

- Multiple concurrent pending VTAs are supported (distinct slugs).
- Phase 2 is idempotent only up to the `bind_vta_did` call: once the
  VTA DID is bound, re-running `pnm setup continue` errors with
  "already set up". To change the VTA DID, remove and redo.
- A keyring entry without a matching config entry (or vice versa) is
  treated as orphaned and falls through to the generic
  "not-configured" error path; re-run `pnm setup --name … --overwrite`
  to reset.

### Hardened configuration

Enables **storage encryption** (all fjall keyspaces AES-256-GCM encrypted,
identical VAE1 format to TEE) and **managed JWT key material** (a random key
generated at first boot and stored in the encrypted `KEYS` keyspace at
`hardened:jwt_key` — never written to `config.toml`). Disabled by default; no
changes to existing behaviour unless `enabled = true` is set.

The JWT key gets no special-case crypto: it is a `VAE1` row like every other
secret this VTA stores. That is one encryption layer instead of two, and it is
also slightly stronger — `VAE1` binds each value to its `(keyspace, key)`
location via AEAD associated data, whereas the bespoke seal it replaced carried
no associated data, so a copied ciphertext would still have opened. The separate
SHA-256 fingerprint row that partially covered that gap is gone.

A VTA still on the old layout moves across automatically on its next boot: the
sealed row is opened, rewritten into `KEYS`, and the two legacy rows removed.
**The key itself is carried over unchanged, so live sessions survive.**

This is the non-TEE equivalent of TEE layer 3 (encrypted storage). The trust anchor shifts from the Nitro Enclave / KMS to the configured `[secrets]` backend — pick a production-grade one.

| Field | Default | Description |
|---|---|---|
| `enabled` | `false` | Enable hardened configuration. All fjall keyspaces are encrypted with AES-256-GCM (same VAE1 format as TEE). JWT signing key is randomly generated, AES-GCM sealed, and stored in the `bootstrap` keyspace — absent from `config.toml`. |
| `storage_key_salt` | random per-VTA (generated by `vta setup`) | HKDF salt for the storage-encryption key. **Treat it as permanent** — changing it after first boot makes all encrypted data unreadable. Omitted from an existing `config.toml`, it falls back to the legacy constant `"vta-storage-v1"` so already-written stores keep working. |

Requires a real `[secrets]` backend (OS keyring, AWS SM, GCP SM, …). Two
backends defeat the feature entirely, and both now log a startup warning:

- the **`plaintext` seed file** fallback, and
- **`[secrets] seed`** (the config-seed backend), which inlines the hex master
  seed in `config.toml` itself.

In either case anyone who can read that one file re-derives the
storage-encryption key **and** the JWT signing key — enough to decrypt the whole
store and forge any token. That is the exact capability hardened configuration
exists to remove, so at-rest encryption provides no protection in these two
configurations.

Both log a `SECURITY:` warning at every boot. They are warnings rather than a
hard refusal because `config.toml` can legitimately be mounted from a
Kubernetes Secret, where the seed is not sitting on a disk an attacker reaches.
If that is not your situation, treat the warning as a misconfiguration to fix
before the VTA carries anything real.

#### Enabling on a VTA that already has data

Supported, and handled for you. The first boot after setting `enabled = true`
converts the existing plaintext rows to the encrypted format before anything
reads them, logging a `hardened: migrated a pre-existing plaintext store` warning
with the row count. The pass is idempotent and crash-safe — later boots do one
prefix scan per keyspace and no writes, and an interrupted run is completed by
the next boot.

This has to be automatic rather than advisory: the store's decrypt path is
deliberately fail-closed with no plaintext fallback, so a VTA started against an
unconverted store would fail to read every pre-existing row — including its own
ACL entries, locking you out.

**Take a backup before the first hardened boot** (`vta backup export`). The
conversion rewrites every row in place, and the salt plus the seed are jointly
required to read the result afterwards.

```toml
[hardened]
enabled          = true
storage_key_salt = "my-unique-per-vta-salt"   # permanent — never change after first boot
```

To rotate the JWT signing key (invalidates all existing sessions):

```bash
# Stop the daemon, then:
vta --config /path/to/config.toml hardened rotate-jwt
# Restart the daemon — a new key is generated on first boot.
```

`rotate-jwt` needs the storage key (the row is encrypted), so it reads the seed
from the `[secrets]` backend. A wrong `storage_key_salt` or an unreachable
backend therefore fails here with a clear cause, rather than at the next daemon
start.

See [Secret-storage backends](secret-backends.md) for backend selection guidance, 
and [Security model](../01-concepts/security-model.md#layer-3-encrypted-storage) for where this fits in the defense-in-depth layers.

> The `vta-enclave` binary derives its storage-encryption key and JWT signing key
> from the TEE KMS bootstrap — the hardened configuration code path is never
> reached. The enclave logs a warning and ignores the field if it is set.
