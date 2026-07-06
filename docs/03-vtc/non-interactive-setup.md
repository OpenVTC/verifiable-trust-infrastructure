# Non-interactive VTC setup

`vtc setup` provisions a VTC against an already-running VTA. For CI, an
immutable image, or a Kubernetes deployment there's no TTY to answer
prompts, so setup runs **headless in two phases** — the same shape the
mediator (`mediator-setup --setup-key-out`) and did-hosting
(`did-hosting-daemon setup --setup-key-out`) services use.

For the guided walkthrough, see [`getting-started.md`](getting-started.md).
Both paths produce identical on-disk state.

## Why two phases

A VTC is not its own key authority — the VTA mints its DID and keys (via
the `vtc-host` DID template). To ask the VTA to do that, the VTC first
authenticates with an **ephemeral `did:key`**, and that DID must already
be **ACL-authorised at the VTA**. The interactive wizard generates the key
and pauses for you to grant it. A headless run can't pause, so the grant
happens out of band, between two commands:

| Phase | Command | What it does |
|---|---|---|
| 1 | `vtc setup --setup-key-out <path> [--context <id>]` | Mints an ephemeral `did:key`, persists it to `<path>` (0600), and prints the exact `pnm contexts create … --admin-did` command. Touches nothing else. |
| — | *(operator / CI step holding VTA admin)* | Runs that `pnm` command to enrol the setup DID at the VTA. |
| 2 | `vtc setup --from <toml>` | Loads the now-authorised key (via `setup_key_file`) and provisions end-to-end: the VTA mints the VTC DID + keys, swaps in the long-term admin DID, and setup writes `config.toml`, the `did.jsonl`, the key bundle, and a one-shot install URL. |

> **Note.** The between-phases grant needs VTA admin. This flow is
> deliberately *not* a self-grant — the VTC never holds a VTA admin
> credential, matching the mediator and did-hosting services. Whatever
> automation runs step 1½ (a human, a CI job, a K8s init step) is what
> holds VTA admin.

## Phase 1 — mint the setup key

```bash
vtc setup --setup-key-out /srv/vtc/setup-key.json --context default
```

`--context` only shapes the printed grant command; it must match
`context` in the phase-2 TOML (default `default`). Output (to stderr):

```
  Setup DID (ephemeral):
    did:key:z6Mk…

  Key stored at /srv/vtc/setup-key.json (0600)

  Using your Personal Network Manager (PNM) connected to this VTA,
  create the vtc context and grant admin access to the setup DID:

    pnm contexts create --id default --name "VTC" \
      --admin-did did:key:z6Mk… --admin-expires 1h

  Then finalise with:
    vtc setup --from <your-setup.toml>   (with setup_key_file = "/srv/vtc/setup-key.json")
```

## Phase 1½ — grant at the VTA

Run the printed command on a host with `pnm` authenticated to the VTA (or
`pnm acl create --did <setup-did> --role admin --contexts <ctx> --expires 1h`
if the context already exists). The `--admin-expires 1h` grant is promoted
to permanent on the setup DID's first authenticated call, which phase 2
performs.

## Phase 2 — provision

Point `setup_key_file` at the phase-1 output and run:

```bash
vtc setup --from /srv/vtc/vtc-setup.toml
```

The full TOML schema is
[`examples/vtc-setup.example.toml`](examples/vtc-setup.example.toml). A
minimal Vault-backed file:

```toml
config_path    = "/srv/vtc/config.toml"
base_url       = "https://vtc.example.com"
vta_did        = "did:webvh:vta.example.com:abc"
context        = "default"
setup_key_file = "/srv/vtc/setup-key.json"

[secrets]
backend           = "vault"
vault_addr        = "https://vault.internal:8200"
vault_secret_path = "vtc/key-bundle"
vault_auth_method = "kubernetes"   # pod ServiceAccount token — nothing to mount
vault_k8s_role    = "vtc"
```

Phase 2 prints a terse, scrape-friendly block (`vtc_did=…`, `admin_did=…`,
`install_url=…`, `claim_code=…`); it never prints the admin private key.

## Choosing a secret-store backend

Set `[secrets] backend` to select the store **explicitly** — recommended
for declarative deploys. When set it wins outright and setup validates that
the backend's required fields are present (rather than silently picking a
different backend whose field happens to also be set). Omit it to keep the
legacy "whichever field is set wins" resolution.

| `backend` | Feature | Required field(s) | Notes |
|---|---|---|---|
| `keyring` | `keyring` (default) | — | `keyring_service` to run several VTCs on one host. |
| `vault` | `vault-secrets` | `vault_addr` | KV v2; k8s / token / approle auth. |
| `k8s` | `k8s-secrets` | `k8s_secret_name` | Reads a Kubernetes `Secret`. |
| `aws` | `aws-secrets` | `aws_secret_name` | |
| `gcp` | `gcp-secrets` | `gcp_secret_name` (+ `gcp_project`) | |
| `azure` | `azure-secrets` | `azure_vault_url` | |
| `config` | `config-secret` | `secret` (written by setup) | Hex bundle inline in config.toml; read-only at runtime. |
| `plaintext` | always | — | NOT secure; dev/test only. |

A backend selected on a binary built without its feature is a hard config
error — never a silent fall-through to keyring/plaintext. (TEE-KMS is
intentionally not a VTC backend; only the VTA runs in a TEE.)

`[secrets]` is flat here (e.g. `vault_addr`, `k8s_secret_name`), matching
the runtime `config.toml` — the same table setup writes and the daemon
reads back at boot.

## Kubernetes

The two phases map cleanly onto a cluster bring-up:

1. **Phase 1** in a short Job (or locally) mints the key and surfaces the
   setup DID. A step holding VTA admin runs the printed `pnm` grant. In a
   GitOps flow this is a one-time bootstrap task.
2. **Phase 2** runs as an init container (or a Job) before the VTC
   Deployment. Mount the phase-1 key file and the setup TOML, then run
   `vtc setup --from …`.

For the store itself, the two K8s-native choices are:

- **`backend = "vault"` with `vault_auth_method = "kubernetes"`** — the VTC
  pod authenticates to Vault with its ServiceAccount token; no static
  secret to mount.
- **`backend = "k8s"`** — the VTC reads its key bundle directly from a
  Kubernetes `Secret` (`k8s_secret_name` in `k8s_namespace`).

Once phase 2 has run, the VTC Deployment starts normally with the written
`config.toml`; `create_secret_store` honours the same `backend` at boot.
