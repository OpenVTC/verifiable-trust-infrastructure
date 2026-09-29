# Personal Network Manager (PNM) CLI

The PNM CLI is a single-VTA client for managing a personal
[Verifiable Trust Agent (VTA)](../README.md). Unlike the
[CNM CLI](../cnm-cli/README.md) which supports multiple communities and a
personal VTA, PNM focuses on managing one VTA instance with a simpler
non-interactive setup flow.

## Table of Contents

- [Feature Flags](#feature-flags)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Authentication](#authentication)
- [CLI Reference](#cli-reference)
- [Additional Resources](#additional-resources)

## Feature Flags

| Feature          | Description                                                                                                                                                                                                          | Default |
| ---------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------- |
| `keyring`        | Store sessions in the OS keyring (macOS Keychain, Linux secret-service, Windows Credential Manager).                                                                                                                  | Yes     |
| `tsp`            | Round-trip TSP probe in `pnm health` -- opens a TSP websocket to the mediator and sends a Trust Task to the VTA. Without it `pnm health` still reports an advertised `TSPTransport` service but never exercises it.    | Yes     |
| `config-session` | Store sessions in `~/.config/pnm/sessions.json`. Useful for containers and CI where no keyring is available. **Warning:** sessions are stored on disk unprotected -- do not use in production.                        | No      |
| `azure-secrets`  | Store sessions in Azure Key Vault, vault URL read from `AZURE_KEYVAULT_URL`. Only takes effect when `keyring` is disabled.                                                                                            | No      |

The session backend is chosen at compile time in the order **`keyring` ->
`azure-secrets` -> `config-session` -> plaintext fallback**; the first enabled
feature wins. Nothing enforces that one of them is enabled -- a build with none
still stores sessions in plaintext at `~/.config/pnm/sessions.json`, and prints
`WARNING: No secure session store — using plaintext file storage` on every
access. Pick one deliberately.

### Build examples

`--no-default-features` drops `tsp` along with `keyring`, so re-add it unless
you mean to give up the `pnm health` TSP probe.

```sh
# Default build (keyring + tsp)
cargo build --package pnm-cli --release

# Keyring-free build for containers / CI, keeping the TSP probe
cargo build --package pnm-cli --release \
  --no-default-features --features config-session,tsp

# Azure Key Vault sessions (requires keyring off; set AZURE_KEYVAULT_URL)
cargo build --package pnm-cli --release \
  --no-default-features --features azure-secrets,tsp
```

## Installation

### From source

Requires **Rust 1.95.0+**.

```sh
cargo build --package pnm-cli --release
```

The binary is at `target/release/pnm`.

### During development

All examples below use `pnm` directly. When developing from the workspace,
substitute `cargo run --package pnm-cli --` for `pnm`.

## Quick Start

### 1. Set up the VTA connection

`pnm setup` mints an ephemeral `did:key` locally and parks it as a
"pending VTA binding" entry in your OS keyring. You then provide the VTA's
URL, the operator running the VTA grants your DID admin in their ACL, and
`pnm` finalises the binding.

```sh
# Phase 1: mint local did:key, name the VTA you'll connect to
pnm setup --name "my-vta"

# Phase 2 (after the VTA operator adds your did:key to their ACL):
#   bind the VTA's DID to the local entry, then connect
pnm setup continue my-vta --vta-did did:webvh:abc:vta.example.com:primary
```

Cold-start operators (running `vta` themselves) pair this with
`vta import-did --did <pnm-did> --role admin` on the VTA host before
phase 2. See `docs/02-vta/cold-start.md` for the full script.

For a TEE-attested first-boot against a fresh Nitro Enclave VTA, the
single-step path is:

```sh
pnm bootstrap connect --vta-did "$VTA_DID" --expect-pcr0 "$EXPECTED_PCR0"
```

This drives `POST /bootstrap/request`, opens the sealed admin bundle, and
imports the resulting credential into the keyring. Set `VTA_DID` to the
deployed VTA's DID and `EXPECTED_PCR0` to the 96-character hex image
measurement from your trusted EIF build. Wait until the VTA's DID log is
published and resolvable. The DID is resolved locally (including SCID and
log verification for `did:webvh`); bootstrap uses the advertised REST
endpoint, including its port and path, and rejects a credential for a
different VTA DID.

Resolution here is **local only**: unlike every other PNM command, bootstrap
ignores `PNM_RESOLVER_URL` / `[resolver_url]`. The resolved document chooses
the endpoint that mints a super-admin credential, against a carve-out that
can only be spent once, so that choice is not delegated to a remote resolver.
A reachable resolver sidecar therefore does not make `--vta-did` work in a
restricted-egress deployment — use `--vta-url` there.

If the DID is not yet resolvable, explicitly replace `--vta-did "$VTA_DID"`
with `--vta-url https://enclave.example.com`. Exactly one target is required;
the URL fallback does not pin the VTA identity. Resolution failure never
silently falls back to a URL guessed from the DID. If the DID *does* resolve
but advertises an endpoint the client refuses to call (a private or
link-local address, cloud metadata, a non-HTTP scheme), that is an endpoint
guard rejection, not a resolution failure — the remedy is
`--allow-private-endpoints` / `VTA_ALLOW_PRIVATE_ENDPOINTS` where the address
is legitimately private, not `--vta-url`, which skips the guard entirely.

Both `--expect-pcr0` and `--expect-pcr8` are checked for well-formedness
before anything is sent, because the VTA closes its first-boot carve-out
before it hands back the bundle: a typo caught after the request would leave
that VTA with no remaining bootstrap.

PCR0 anchors online connect without a digest flag or TOFU warning, since
the digest is generated during that call. `--expect-digest` remains an
optional additional check; `--no-verify-digest` remains an explicit opt-out
that warns, and cannot be combined with `--expect-digest`. A DID alone or
`--expect-pcr8` alone does not replace the required anchor. Offline
`bootstrap open` still requires `--expect-digest` or `--no-verify-digest`.

### 2. Verify connectivity

```sh
pnm health
```

### 3. Start using the CLI

```sh
# List application contexts
pnm contexts list

# Create a signing key
pnm keys create --key-type ed25519 --context-id myapp --label "Signing Key"

# List keys
pnm keys list
```

## Authentication

PNM uses **DID-based challenge-response authentication** with short-lived JWT
tokens:

1. **Import a credential** -- a base64-encoded bundle containing your client
   DID, private key, and the VTA DID.
2. **Challenge-response** -- the CLI requests a nonce from the VTA, signs a
   DIDComm v2 message, and receives a JWT.
3. **Token caching** -- tokens are cached in the OS keyring and refreshed
   automatically when they expire.

```sh
# Apply a sealed admin credential bundle (e.g. a backup-restore handoff
# or a sealed transfer from another operator)
pnm auth login --credential-bundle <file>

# Check auth status
pnm auth status

# Clear credentials
pnm auth logout
```

After initial login, all subsequent commands authenticate transparently.

### Credential storage

With the default `keyring` feature, sessions are stored in the platform's
credential manager:

| Platform | Backend                             |
| -------- | ----------------------------------- |
| macOS    | Keychain                            |
| Linux    | secret-service (e.g. GNOME Keyring) |
| Windows  | Credential Manager                  |

Built without `keyring`, sessions go to Azure Key Vault instead
(`--features azure-secrets`, vault URL from `AZURE_KEYVAULT_URL`), or to
plaintext `~/.config/pnm/sessions.json` (`--features config-session`). See
[Feature Flags](#feature-flags) for details.

## Configuration

### Config file

`~/.config/pnm/config.toml`

```toml
url = "http://localhost:8100"
```

### Environment variables

| Variable   | Description                          |
| ---------- | ------------------------------------ |
| `VTA_URL`  | Override the VTA base URL            |
| `RUST_LOG` | Set log level (e.g. `debug`, `info`) |

## CLI Reference

### Global flags

| Flag            | Description                              |
| --------------- | ---------------------------------------- |
| `--url <URL>`   | Override VTA base URL (or set `VTA_URL`) |
| `-v, --verbose` | Enable debug logging                     |

### Setup

| Command                                                  | Description                                                                                              |
| -------------------------------------------------------- | -------------------------------------------------------------------------------------------------------- |
| `setup --name <slug> [--overwrite]`                      | Phase 1: mint an ephemeral `did:key`, park it in the keyring as a pending VTA binding under `<slug>`. |
| `setup continue <slug> --vta-did <did>`                  | Phase 2: bind the VTA's DID to the entry from phase 1 and mark it ready to authenticate.                  |
| `bootstrap connect --vta-did <did> --expect-pcr0 <hex>`   | DID-first TEE-attested first-boot; explicit `--vta-url` fallback. Drives `POST /bootstrap/request`.        |
| `auth login --credential-bundle <file>`                  | Apply a sealed admin credential bundle delivered out-of-band (e.g. a backup-restore handoff or a sealed transfer from another operator). |

### Authentication

| Command                                 | Description                              |
| --------------------------------------- | ---------------------------------------- |
| `auth login --credential-bundle <file>` | Apply a sealed admin credential bundle   |
| `auth logout`                           | Clear stored credentials and tokens      |
| `auth status`                           | Show current authentication status       |

### Health

| Command  | Description                                            |
| -------- | ------------------------------------------------------ |
| `health` | Check VTA service health and version                   |

### Configuration

| Command                   | Description                                       |
| ------------------------- | ------------------------------------------------- |
| `config get`              | Show current VTA configuration                    |
| `config update [options]` | Update VTA metadata (DID, name, description, URL) |

### Keys

| Command                                                                    | Description     |
| -------------------------------------------------------------------------- | --------------- |
| `keys list [--status active\|revoked] [--limit N] [--offset N]`            | List keys       |
| `keys create --key-type ed25519\|x25519\|p256 [--context-id ID] [--label LABEL]` | Create a key (BIP-32 derived) |
| `keys import --key-type TYPE --private-key KEY [--label L] [--context-id ID]` | Import an external private key |
| `keys get <key_id>`                                                        | Get a key by ID |
| `keys revoke <key_id>`                                                     | Revoke a key               |
| `keys rename <key_id> <new_key_id>`                                        | Rename a key               |
| `keys secrets [key_ids...] [--context ID]`                                 | Export secret key material |
| `keys seeds`                                                               | List seed generations      |
| `keys rotate-seed [--mnemonic PHRASE]`                                     | Rotate to a new seed       |

The `keys import` command accepts `--private-key <multibase>` or `--private-key-file <path>` and supports key types `ed25519`, `x25519`, and `p256`. The private key is wrapped with ECDH-ES+AES-256-GCM before transmission over REST.

### Contexts

| Command                                                             | Description                             |
| ------------------------------------------------------------------- | --------------------------------------- |
| `contexts list`                                                     | List application contexts               |
| `contexts get <id>`                                                 | Get a context by ID                     |
| `contexts create --id ID --name NAME [--description DESC]`          | Create a context                        |
| `contexts update <id> [--name ...] [--did ...] [--description ...]` | Update a context                        |
| `contexts delete <id>`                                              | Delete a context                        |
| `contexts bootstrap --id ID --name NAME [--admin-label LABEL]`      | Create context + first admin credential |

### ACL

| Command                                                                   | Description             |
| ------------------------------------------------------------------------- | ----------------------- |
| `acl list [--context ID]`                                                 | List ACL entries        |
| `acl get <did>`                                                           | Get an ACL entry by DID |
| `acl create --did DID --role ROLE [--label LABEL] [--contexts ctx1,ctx2] [--expires N[s\|m\|h\|d\|w]]` | Create an ACL entry     |
| `acl update <did> [--role ROLE] [--label LABEL] [--contexts ctx1,ctx2]`   | Update an ACL entry     |
| `acl delete <did>`                                                        | Delete an ACL entry     |

Roles: `admin`, `initiator`, `application`. An admin with no contexts listed
has unrestricted access across all contexts.

### Auth Credentials

| Command                                                                     | Description                                  |
| --------------------------------------------------------------------------- | -------------------------------------------- |
| `auth-credential create --role ROLE [--label LABEL] [--contexts ctx1,ctx2]` | Generate a did:key credential with ACL entry |

### Backup & Restore

| Command                                                     | Description                                    |
| ----------------------------------------------------------- | ---------------------------------------------- |
| `backup export [--include-audit] [--output FILE] [--force]` | Export encrypted backup of all VTA state        |
| `backup import <file> [--preview]`                          | Import backup (preview or apply + restart VTA) |

Backups are encrypted with Argon2id + AES-256-GCM using a user-provided password (minimum 15 characters). The `.vtabak` file contains the seed, keys, ACL, contexts, WebVH records, and config. It is created readable by its owner only (`0600` on Unix, an owner-only ACL on Windows), and an existing file is not overwritten unless you pass `--force`.

### VTA Management

| Command       | Description                                           |
| ------------- | ----------------------------------------------------- |
| `vta list`    | List configured VTAs                                  |
| `vta use`     | Set the default VTA                                   |
| `vta delete`  | Delete a local VTA connection and its stored credential (the VTA's ACL entry stays — `acl delete` revokes it) |
| `vta info`    | Show current VTA details                              |
| `vta qr`      | Show the VTA's DID as a QR code for a phone (Keyring) to scan. Offline; `--did <DID>` draws another DID, `--out <file.svg>` also writes an SVG |
| `vta restart` | Trigger a soft restart (reloads config, reconnects)   |

The QR code holds the bare DID and nothing else, so it is safe to show on a
shared screen. It is always drawn dark on white, whatever the terminal's
theme, because many phone cameras refuse an inverted code.

### Messaging

| Command | Description |
| ------- | ----------- |
| `messaging console [--context ID] [--did DID] [--mediator DID]` | Open the mediator console as a DID of a context |
| `messaging console --as-session` | Open it as this pnm session's own `did:key` |
| `messaging grant DID --role admin\|standard [--context ID] [--did DID] [--mediator DID]` | Give another DID an account role at a mediator |

`pnm messaging grant` is how a browser wallet's console comes to see a whole
relay: its Mediator Lens prints the exact command, naming the wallet's holder
`did:key` for that agent. Run it as the mediator's administrator (its
`admin_did`); it acts as a DID exactly as `console` does, and prints the role
the mediator *recorded*, failing if that is not the one asked for. `rootAdmin`
is not offered — it reads other accounts' message bodies and changes a running
mediator, which is not a standing to give a key held in a browser.

`pnm messaging console` opens a full-screen console for an Affinidi messaging
mediator, acting as a DID this VTA manages — no profile file or secrets to keep:

- an **administrator** DID sees the whole mediator: statistics, every account's
  queues with green-to-red quota bars, any account's messages (inspect, delete,
  preview-then-confirm purges), the audit log, and a live traffic monitor;
- **any other** DID manages its own queues and messages and watches its own
  traffic.

**Which DID.** Any DID whose keys are in a context you can see is offered,
with each context's own DID listed first. When there's more than one, pnm
asks you to pick. `--context` narrows the list to one context and `--did`
picks the DID directly; with a context that holds several DIDs and no `--did`,
you pick from that context's DIDs.

The mediator decides which view you get, from its own record of the DID. The mediator comes
from `--mediator`, else the DID document's `DIDCommMessaging` service, else this
pnm's configured mediator. Screens and keys are documented with the console
itself: [`affinidi-messaging-mediator-tui`](https://github.com/affinidi/affinidi-tdk-rs/tree/main/crates/messaging/affinidi-messaging-mediator-tui).

**Names instead of hashes.** The mediator knows accounts only as SHA-256
hashes of their DIDs. pnm fills the console's address book with every DID
this VTA can name:
- the DIDs of your contexts, named after the context;
- webvh DIDs it hosts, as `context · mnemonic`;
- anyone with access to the VTA, by their ACL label (listing ACLs needs an
  admin; otherwise this source is skipped);
- the VTA itself and this pnm session.

Those names aren't saved. Names you add in the console with `n` are saved to
the same address book the standalone `mediator-console` uses
(`~/.config/mediator-console/address-book.json`), and a name you saved wins.

**What it needs from the VTA.** The console signs requests and decrypts the
mediator's replies, and the VTA cannot do key agreement on its behalf, so the
DID's keys are exported for the session — one at a time with `keys/export-secret`,
which needs the **`KeyExport`** capability and is audited on every export
(VTI-VTA-003). Only the DID's own verification-method keys are exported; a key
marked non-exportable is refused; the keys are held in memory and gone when the
console closes. `--as-session` exports nothing — pnm's own key is already here.

## Additional Resources

- [VTA Service & Architecture](../README.md)
- [CNM CLI (multi-community)](../cnm-cli/README.md)
- [First Person Network White Paper](https://www.firstperson.network/white-paper)
- [Documentation index](../docs/README.md)
- [Architecture](../docs/01-concepts/architecture.md)
- [BIP-32 Path Specification](../docs/04-reference/bip32-paths.md)
