# Cold-Start Guide: Non-TEE VTA + PNM

This guide walks through bootstrapping a working **non-TEE Verifiable Trust
Agent** and connecting a PNM CLI to it. Everything runs on one machine
(or across two — operator workstation + VTA host); no external services
(mediator, WebVH hosting, Redis) are required.

For enclave-hosted (TEE) deployments and the full multi-service trust
network (VTA + mediator + WebVH DID hosting), see the follow-up sections
at the end.

## Prerequisites

- **Rust 1.94.0+** (`rustup update stable`)
- **OS keyring support** (macOS Keychain, GNOME Keyring, Windows Credential
  Manager) — the default seed storage backend
- **git** and **curl**

## The flow in one diagram

```
   ┌────────────────────┐             ┌────────────────────┐
   │  Operator laptop   │             │      VTA host      │
   │      (pnm-cli)     │             │     (vta server)   │
   └────────────────────┘             └────────────────────┘
              │                                  │
              │                                  │
              │ 1. vta setup (offline)           │
              │    (config + seed + VTA DID)     │
              │                                  │
              │ 2. pnm setup ──────────┐         │
              │    mint temp did:key   │         │
              │    print `vta import-did`────────▶
              │                        │         │ 3. vta import-did
              │                        │         │    (offline, writes ACL)
              │                        │         │
              │                                  │ 4. vta --config ...
              │                                  │    (VTA process starts)
              │ 5. pnm health  ─────────────────▶│
              │    auto-rotate did:key           │ (auth + rotate)
              │    done                          │
```

The temp did:key lives only long enough for PNM's first authenticated
request; auto-rotation mints a fresh long-lived did:key and drops the
temp from the ACL.

## Phase 1: Build

```bash
cd ~/devel/fpp/verifiable-trust-infrastructure
cargo build --workspace
```

Verify the two binaries used in this guide:

```bash
cargo run --package vta-service -- --help
cargo run --package pnm-cli    -- --help
```

## Phase 2: Run the VTA Setup Wizard (Offline)

The setup wizard runs with **no services needed**. It generates a BIP-39
seed, configures the server, optionally creates a VTA did:webvh, and
writes `config.toml`.

```bash
cd ~/devel/fpp/verifiable-trust-infrastructure
cargo run --package vta-service --features setup -- setup
```

### 2.1 Server configuration

```
Config file path [config.toml]: config.toml
VTA name: My Trust Network
Services to enable: [x] REST API   [ ] DIDComm Messaging
Public URL for this VTA: http://localhost:8100
Server host [0.0.0.0]: 0.0.0.0
Server port [8100]: 8100
Log level [info]: info
Log format: text
Data directory [data/vta]: data/vta
```

(For a REST-only setup, uncheck DIDComm. DIDComm requires a mediator —
see "Adding DIDComm messaging" at the end.)

### 2.2 BIP-39 mnemonic

Choose **Generate new 24-word mnemonic**. Write down and store the
mnemonic securely — it is the root of every key in the VTA's BIP-32
hierarchy.

### 2.3 Seed storage

Choose **OS keyring** for local development. The seed is stored in your
platform's credential manager (macOS Keychain, GNOME Keyring, etc.).
For headless / server deployments see the built-in alternatives
(AWS Secrets Manager, GCP Secret Manager, Azure Key Vault, config-seed
in `config.toml`).

### 2.4 VTA DID (optional but recommended)

If you want a resolvable VTA DID:

```
VTA DID:
  > Create a new did:webvh DID
```

Point it at wherever you plan to host the `did.jsonl` (a DID-hosting server,
static host, or a `did:web`-style URL). Choose **Simple** mode.

If you skip this, the VTA will use `did:key` as its identity; clients
still resolve it fine, but there's no stable DID log.

### 2.5 What to do next

At the end, the wizard prints instructions tailored for your config.
They look roughly like:

```
── What to do next ──

  1. On your operator workstation (with the VTA still stopped),
     run `pnm setup` and choose "Connect to an existing non-TEE
     VTA". When it asks for the VTA DID, enter:

       did:webvh:Qm...:localhost%3A8000:dids:vta

     `pnm setup` mints a temp did:key and prints an
     `vta import-did` command.

  2. Back on this host, run the `vta import-did` command pnm
     printed. This grants admin access to the temp did:key by
     writing to the local store — no network call, no running VTA
     required.

  3. Start the VTA:
       vta --config config.toml

     On the operator workstation's first authenticated command
     (e.g. `pnm health`), PNM rotates to a fresh long-lived
     did:key and removes the temp from the ACL.
```

## Phase 3: Run `pnm setup` on the operator workstation

With the VTA still stopped (so `vta import-did` can take the store lock
next), run:

```bash
cd ~/devel/fpp/verifiable-trust-infrastructure
cargo run --package pnm-cli -- setup
```

```
What would you like to do?
  > Connect to an existing non-TEE VTA

VTA DID (see `vta config show` on the VTA host): did:webvh:...:dids:vta
Name for this VTA [vta]: my-trust-network
```

PNM mints a did:key locally, stores a rotation-pending session in the
OS keyring, and prints:

```
Temp admin identity created.

  VTA slug:  my-trust-network
  VTA DID:   did:webvh:...:dids:vta
  Temp DID:  did:key:z6Mk...

Ask your VTA admin to grant this identity admin access. On the VTA host,
they should run:

  vta import-did --did did:key:z6Mk... --role admin
```

Copy the `vta import-did` command — you'll run it in Phase 4.

> **Tip:** if you forget the VTA DID, run `vta config show` on the VTA
> host. It prints everything `pnm setup` asks for.

### Alternate: deferred-VTA-DID flow (for automated VTA hosting)

If you're automating VTA hosting — for example, a Terraform module or
a bootstrap script that needs the PNM admin DID *before* the VTA
exists — you can mint the PNM admin identity first, pass it into
`vta setup`, and finish PNM later once the VTA is running:

```bash
# Phase 1 (non-interactive): mint + park the ephemeral did:key.
$ pnm setup --name "My VTA"
{"slug":"my-vta","admin_did":"did:key:z6Mk...","state":"pending"}
```

Feed the `admin_did` into your VTA's `setup.toml` at the `admin_did`
key (see `non-interactive-setup.md`), or pass it to `vta import-did`
on an already-running VTA. Once the VTA is up and you know its DID:

```bash
# Phase 2 (non-interactive): bind the VTA DID and finalize.
$ pnm setup continue my-vta --vta-did did:webvh:...
{"slug":"my-vta","admin_did":"did:key:z6Mk...","state":"complete"}
```

The same `did:key` is preserved across both phases; on first successful
authentication PNM auto-rotates to a fresh did:key and drops the
original from the ACL, same as the classic flow. Interactive variants
(`pnm setup` / `pnm setup continue my-vta`) prompt instead of
consuming flags. Multiple concurrent pending VTAs are allowed (distinct
slugs); colliding on a pending slug requires `--overwrite`
(non-interactive) or confirmation (interactive).

## Phase 4: Grant admin access on the VTA host

Still with the VTA **stopped** (the `vta import-did` CLI takes the
store lock), run the command pnm printed:

```bash
vta import-did --did did:key:z6Mk... --role admin
```

This writes a single `AclEntry` directly to the fjall store. No
network call, no server required. The VTA stays unsealed — the
offline CLI remains usable for any further provisioning work
(mediator, did-hosting-daemon, etc.) before you start the daemon. See
[`seal-and-unseal.md`](seal-and-unseal.md) for when (and whether) to
seal explicitly with `vta bootstrap-admin`.

## Phase 5: Start the VTA

```bash
cd ~/devel/fpp/verifiable-trust-infrastructure
cargo run --package vta-service
```

## Phase 6: Verify + auto-rotate

On the operator workstation, run any authenticated command:

```bash
cargo run --package pnm-cli -- health
```

What happens internally:

1. PNM loads its session, sees `needs_rotation = true`.
2. Authenticates as the temp did:key (challenge-response).
3. Mints a fresh Ed25519 did:key from CSPRNG.
4. `GET /acl/<temp-did>` — reads the role + contexts the admin granted.
5. `POST /acl` with the new DID, same role + contexts.
6. Challenge-responds as the new DID to verify the grant is live.
7. `DELETE /acl/<temp-did>` — removes the temp from the ACL.
8. Saves the session with the new DID, clears the rotation flag.
9. Finishes the original `pnm health` request.

If the delete fails, PNM logs a warning and continues — the old temp
is stale anyway. Re-running `pnm health` is a no-op after rotation.

## That's it

A fresh VTA with a rotated admin identity on the operator's workstation.
No admin credentials ever crossed the wire; the temp did:key that briefly
existed in `pnm setup`'s output is gone from the ACL after step 6.

---

## Reference: `vta` offline CLI commands used here

All of these operate on the fjall store directly and require the VTA
process to be stopped (they take a store-level lock).

```bash
# Inspect config.toml — works while the VTA is running (doesn't open the store)
vta config show

# Check status (opens the store; requires VTA stopped)
vta status

# Add a DID to the ACL
vta import-did --did <did> --role admin [--label <text>] [--context <id>]...

# List / update / delete ACL entries
vta acl list [--context <id>] [--role <role>]
vta acl get <did>
vta acl update <did> [--role <role>] [--label <text>] [--contexts <id,...>]
vta acl delete <did>

# Manage keys offline
vta keys list [--context <id>] [--status active|revoked]
vta keys secrets <key-id...> [--context <id>]
vta keys seeds
vta keys rotate-seed [--mnemonic <phrase>]

# DID creation (offline, no server required)
vta create-did-key    --context <id> [--admin] [--label <text>]
vta create-did-webvh  --context <id> [--label <text>]

# Sealed-transfer bootstrap (consumer side — cold-start hosts that don't
# have pnm installed). Mints an ephemeral did:key, persists the seed
# under ~/.config/vta/bootstrap-secrets/, opens the returned bundle.
# Same wire format and same on-disk seed cache shape as `pnm bootstrap`.
vta bootstrap request --out request.json [--label <text>] [--seed-dir <path>]
vta bootstrap open    --bundle <armor>   --expect-digest <hex> [--seed-dir <path>]

# Sealed-transfer bootstrap (producer side — VTA host).
vta bootstrap seal                  --request <req.json> --payload <payload.json> --out <armor>
vta bootstrap provision-integration --request <req.vp.json> --context <id>        --out <armor>
```

`vta bootstrap request` / `open` are the consumer-side commands a
cold-start integration uses when `pnm` is not yet available — for
example, when the integration *is* the mediator that pnm would normally
rely on. Both delegate to the same shared `vta_cli_common::sealed_consumer`
layer that pnm uses, so on-disk seed format and HPKE handling are
byte-identical.

---

## Adding an integration (mediator, WebVH hosting, future kinds)

DIDComm is optional. Without a mediator, PNM authenticates via HTTP
challenge-response. To add a mediator — or any other VTA-managed
integration (WebVH hosting server, credential issuer, …) — use the
`provision-integration` flow.

Provisioning an integration is a single operator action that:
- Mints the integration's DID + key material (VTA-side, via a DID
  template).
- Issues a short-lived W3C Verifiable Credential attesting the
  integration's authorization.
- Seals everything (VC, keys, rendered DID doc, `did.jsonl` log, VTA
  trust bundle) into an armored bundle the integration opens at first
  boot.

Two transports, same operation:

- **Offline** — run on the VTA host itself when the operator is
  physically there. Uses `vta bootstrap provision-integration`.
- **Online via PNM** — when the operator is on a workstation with an
  authenticated PNM session, `pnm bootstrap provision-integration`
  bridges to the VTA's `POST /bootstrap/provision-integration` endpoint.
  Same shared library function runs on the VTA regardless of transport.

Full design: [`../02-vta/provision-integration.md`].

For the operator-focused end-to-end walkthrough (including the
WEBVH_PATH/WEBVH_SERVER knobs and SDK-level integration), see
[`../02-vta/provision-integration.md`].

### Example: provision a DIDComm mediator

1. On the **mediator host**, run the mediator's setup wizard (or the
   generic CLI) to mint an ephemeral `client_did` (Ed25519) and emit a
   VP-framed bootstrap request naming the target template:
   ```
   vta bootstrap provision-request \
       --template     didcomm-mediator \
       --var          URL=https://mediator.example.com \
       --context-hint prod-mediator \
       --admin-template vta-admin \
       --out          mediator-request.vp.json
   ```
   (`pnm bootstrap provision-request` is identical; different default
   seed directory.) Ship `mediator-request.vp.json` to whoever will
   drive provisioning on the VTA side. The JSON is signed by
   `client_did`; any tamper rejects at verification.

2. On the **VTA host** (offline / air-gapped):
   ```
   vta bootstrap provision-integration \
       --request  mediator-request.vp.json \
       --context  prod-mediator \
       --out      mediator.armor
   ```
   Or **via PNM** from an authenticated operator workstation:
   ```
   pnm bootstrap provision-integration \
       --request  mediator-request.vp.json \
       --context  prod-mediator \
       --vta      <vta-slug> \
       --out      mediator.armor
   ```
   Either way the VTA:
   - Mints the mediator's signing + key-agreement keys and renders the
     `didcomm-mediator` DID template.
   - Creates an admin ACL entry for the mediator's `client_did` in
     `prod-mediator`.
   - Issues a `VtaAuthorizationCredential` (1h validity by default).
   - Seals it all to `client_did`'s X25519 derivation and prints the
     SHA-256 digest.

3. Ship `mediator.armor` (and the printed digest) back to the mediator
   host. The mediator opens the bundle, verifies the VTA signature
   offline against the shipped `VtaTrustBundle`, writes its webvh log
   to `/.well-known/did.jsonl`, and rotates on first connect.

The `didcomm-mediator` template is a built-in. Custom integration
shapes register their own template via `pnm did-templates upload` and
pass the name in the request's `ask.template.name`.

Revocation is the ACL — `pnm acl delete <mediator-did>` cuts access
regardless of VC expiry. VCs are bootstrap-transport only.

### did.jsonl retrieval (audit, republication, debugging)

The VTA exposes the provisioning-time `did.jsonl` log publicly (webvh
logs are world-readable by design):

```
pnm did-mgmt dids get-log <did:webvh:...>
vta did-mgmt dids get-log <did:webvh:...>              # offline from the VTA host
GET /did/{did}/log                             # HTTP, unauthenticated
```

Snapshot-only — once the integration publishes on its own webvh host,
that copy is the live source. Use this for audit, republication
fallback, or debugging resolution issues.

[`../02-vta/provision-integration.md`]: ../02-vta/provision-integration.md

---

## Provisioning complex clients (sealed offline flow)

For services that need a full identity (DID + signing key + KA key +
VTA DID/URL) *before* they can contact the VTA — typically mediators
and DID-hosting servers — the VTA admin uses the sealed-transfer flow:

**On the client's host** (1-time):

```bash
pnm bootstrap request --out request.json [--label "my-mediator"]
# → writes request.json; persists the ephemeral X25519 secret under
#   ~/.config/pnm/bootstrap-secrets/
```

If the client's host doesn't have `pnm` installed (e.g. cold-start of
the very mediator pnm would otherwise rely on), use the equivalent
`vta` subcommand — same wire format, seeds cached under
`~/.config/vta/bootstrap-secrets/`:

```bash
vta bootstrap request --out request.json [--label "my-mediator"]
```

**On a PNM-authenticated workstation** (admin):

```bash
pnm contexts provision \
    --id myservice \
    --name "My service" \
    --did-url "http://webvh.example.com/dids/myservice" \
    --mediator-service \
    --recipient request.json
# → prints an armored VTA SEALED BUNDLE + SHA-256 digest
```

When the DID is hosted on a registered server (`--server`), the host
allocates its path label by default. Add `--did-path <label>` to pick
the label yourself — the same selector as `pnm did-mgmt dids create
--path`, so `.well-known` claims the reserved root slot and any other
value becomes an explicit path segment.

**Back on the client's host**:

```bash
pnm bootstrap open --bundle myservice.armor --expect-digest <hex>
# → decrypts the bundle, surfaces DID + keys + VTA info for the client
#   to install
```

`vta bootstrap open --bundle myservice.armor --expect-digest <hex>` is
the equivalent for hosts without `pnm`.

The complex client rotates its VTA-admin credential on first successful
VTA connect using the same `needs_rotation` flag the PNM flow uses
(see `vta-sdk::session::SessionStore::rotate_key`).

---

## Troubleshooting

### `pnm setup` can't resolve the VTA DID

PNM's interactive prompt only stores the DID — endpoints are resolved
at runtime from the DID document (`#vta-rest` service endpoint, or
did:web / did:webvh domain parsing). If resolution fails:

- Check the DID document is actually hosted where the DID claims
  (for did:webvh: `<domain>/<path>/did.jsonl`).
- Override the URL explicitly per-command: `pnm --url http://... health`.

### `vta import-did` fails with "could not open store"

The VTA process is running and holding the fjall lock. Stop the VTA
first (Ctrl+C / systemctl stop), run `vta import-did`, then restart.

### `pnm health` fails with 401 / 403 after setup

The admin hasn't run `vta import-did` for the temp did:key yet. Re-run
it on the VTA host (VTA stopped) using the command `pnm setup` printed.

### Rotation succeeded but old temp DID lingers in ACL

The new DID is live; the delete-old step failed (e.g. transient
network). Run:

```bash
pnm acl delete <temp-did>   # after authenticating — new did is active
```

or on the VTA host (stopped):

```bash
vta acl delete <temp-did>
```

### "Keyring not available" errors

Common in headless / SSH sessions. Use `config-seed` for the VTA seed
and a keyring-less PNM session:

```bash
# VTA: pick "Config file (hex in TOML)" during setup
cargo run --package vta-service \
    --no-default-features \
    --features setup,config-seed,rest -- setup
```

---

## Version / MSRV

- Rust workspace MSRV: **1.94.0** (see `Cargo.toml`).
- VTA / PNM binaries: **0.5.0**.

## Further reading

- [`sealed-bootstrap.md`](../../sealed-bootstrap.md) — design doc for
  the sealed-transfer primitive used by complex-client provisioning.
- [`bip32-paths.md`](../04-reference/bip32-paths.md) — how contexts
  map to BIP-32 derivation paths.
- [`feature-flags.md`](feature-flags.md) — compile-time feature matrix
  (TEE mode, secret backends, REST vs DIDComm, etc.).
- [`../02-vta/provision-integration.md`](../02-vta/provision-integration.md) —
  operator walkthrough for the three-phase provision flow
  (generate VP request → provision → open+install), covering mediator
  and did-hosting-daemon greenfield setup.
