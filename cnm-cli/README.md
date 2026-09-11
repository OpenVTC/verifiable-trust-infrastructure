# Community Network Manager (CNM) CLI

The CNM CLI is the primary client for operating a
[Verifiable Trust Agent (VTA)](../README.md) and participating in
[Verifiable Trust Communities](https://www.firstperson.network/white-paper).
It provides authentication, key management, access control, and
multi-community support from a single command-line tool.

## Table of Contents

- [Feature Flags](#feature-flags)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Multi-Community Support](#multi-community-support)
- [Authentication](#authentication)
- [Configuration](#configuration)
- [CLI Reference](#cli-reference)
- [Additional Resources](#additional-resources)

## Feature Flags

| Feature          | Description                                                                                                                                                                                    | Default |
| ---------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------- |
| `keyring`        | Store sessions in the OS keyring (macOS Keychain, GNOME Keyring, Windows Credential Manager)                                                                                                   | Yes     |
| `config-session` | Store sessions in `~/.config/cnm/sessions.json`. Useful for containers and CI where no keyring is available. **Warning:** sessions are stored on disk unprotected -- do not use in production. | No      |

At least one of `keyring` or `config-session` must be enabled. When `keyring`
is enabled it takes priority over `config-session`.

### Build examples

```sh
# Default build (keyring)
cargo build --package cnm-cli --release

# Keyring-free build for containers / CI
cargo build --package cnm-cli --release --no-default-features --features config-session
```

## Installation

### From source

Requires **Rust 1.94.0+**.

```sh
cargo build --package cnm-cli --release
```

The binary is at `target/release/cnm`.

### During development

All examples below use `cnm` directly. When developing from the workspace,
substitute `cargo run --package cnm-cli --` for `cnm`.

## Quick Start

### 1. Run the setup wizard

The setup wizard walks you through connecting to your first community:

```sh
cnm setup
```

The wizard prompts for:

1. **Personal VTA URL** and **credential** -- your personal VTA instance.
2. **Community name**, **slug**, and **VTA URL** -- the community you want to join.
3. **Join method** -- import an existing credential from a community admin, or
   generate a DID via your personal VTA and request access.

Configuration is saved to `~/.config/cnm/config.toml`.

### 2. Verify connectivity

```sh
cnm health
```

### 3. Start using the CLI

```sh
# List application contexts
cnm contexts list

# Create a signing key
cnm keys create --key-type ed25519 --context-id myapp --label "Signing Key"

# List keys
cnm keys list
```

## Multi-Community Support

CNM supports connecting to multiple communities simultaneously. Each community
has its own VTA service, credentials, and session stored independently in the
OS keyring.

### Add a community

```sh
# Interactive wizard
cnm community add
```

### List communities

```sh
cnm community list
```

### Switch the default community

```sh
cnm community use <slug>
```

### Override community per-command

```sh
cnm -c acme keys list
```

### Show active community status

```sh
cnm community status
```

### Remove a community

```sh
cnm community remove <slug>
```

## Authentication

CNM uses **DID-based challenge-response authentication** with short-lived JWT
tokens:

1. **Import a credential** -- a base64-encoded bundle containing your client
   DID, private key, and the community's VTA DID.
2. **Challenge-response** -- the CLI requests a nonce from the VTA, signs a
   DIDComm v2 message, and receives a JWT.
3. **Token caching** -- tokens are cached in the OS keyring and refreshed
   automatically when they expire.

```sh
# Apply a sealed admin credential bundle (e.g. a backup-restore handoff
# or a sealed transfer from another operator). The digest comes from the
# operator who sealed it, over a separate channel you trust; the credential
# must be for the community's configured VTA DID.
cnm auth login --credential-bundle <file> --expect-digest <sha256>

# Check auth status
cnm auth status

# Clear credentials
cnm auth logout
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

When built with `--features config-session` (and without `keyring`), sessions
are stored in `~/.config/cnm/sessions.json` instead. See
[Feature Flags](#feature-flags) for details.

## Configuration

### Config file

`~/.config/cnm/config.toml`

```toml
default_community = "storm"

[personal_vta]
url = "https://personal.vta.example.com"

[communities.storm]
name = "Storm Network"
url = "https://vta.storm.ws"
context_id = "cnm-storm-network"
vta_did = "did:webvh:..."

[communities.acme]
name = "Acme Corp"
url = "https://vta.acme.example.com"
# vta_did and context_id are optional
```

### VTA service configuration

```sh
# View current VTA config
cnm config get

# Update VTA metadata
cnm config update --community-vta-name "My VTA" --public-url "https://vta.example.com"
```

### Environment variables

| Variable   | Description                          |
| ---------- | ------------------------------------ |
| `VTA_URL`  | Override the VTA base URL            |
| `RUST_LOG` | Set log level (e.g. `debug`, `info`) |

## CLI Reference

### Global flags

| Flag                     | Description                                |
| ------------------------ | ------------------------------------------ |
| `--url <URL>`            | Override VTA base URL (or set `VTA_URL`)   |
| `-c, --community <slug>` | Override active community for this command |
| `-v, --verbose`          | Enable debug logging                       |

### Setup & Communities

| Command                   | Description                                |
| ------------------------- | ------------------------------------------ |
| `setup`                   | Interactive first-time setup wizard        |
| `community list`          | List configured communities                |
| `community use <slug>`    | Set default community                      |
| `community add`           | Add a new community interactively          |
| `community remove <slug>` | Remove a community                         |
| `community status`        | Show active community info and auth status |

### Authentication

| Command                                 | Description                              |
| --------------------------------------- | ---------------------------------------- |
| `auth login --credential-bundle <file>` | Apply a sealed admin credential bundle   |
| `auth logout`                           | Clear stored credentials and tokens      |
| `auth status`                           | Show current authentication status       |

### Health

| Command  | Description                                            |
| -------- | ------------------------------------------------------ |
| `health` | Check VTA service health, resolve DIDs, show endpoints |

### Configuration

| Command                   | Description                                       |
| ------------------------- | ------------------------------------------------- |
| `config get`              | Show current VTA configuration                    |
| `config update [options]` | Update VTA metadata (DID, name, description, URL) |

### Keys

| Command                                                                    | Description     |
| -------------------------------------------------------------------------- | --------------- |
| `keys list [--status active\|revoked] [--limit N] [--offset N]`            | List keys       |
| `keys create --key-type ed25519\|x25519\|p256 [--context-id ID] [--label LABEL]` | Create a key    |
| `keys get <key_id>`                                                        | Get a key by ID |
| `keys revoke <key_id>`                                                     | Revoke a key    |
| `keys rename <key_id> <new_key_id>`                                        | Rename a key    |
| `keys secrets [key_ids...] [--context ID]`                                 | Export secret key material |
| `keys seeds`                                                               | List seed generations      |
| `keys rotate-seed [--mnemonic PHRASE]`                                     | Rotate to a new seed       |

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

### Vetting

Peer identity vetting on the community (VTC admin REST; needs a community-admin
session). Guide: [Peer identity vetting](../docs/03-vtc/vetting.md) §7–8.

| Command | Description |
| ------- | ----------- |
| `vetting vetters list` | Every vetter grant: status, origin, validity, endorsement id, profile |
| `vetting vetters grant <memberDid> [--validity 180d]` | Name a current member a vetter |
| `vetting vetters revoke <endorsementId>` | Withdraw a vetter grant |
| `vetting vetters resend <memberDid>` | Deliver a live grant credential again |
| `vetting auto-grant show` | Automatic-grant configuration and last sweep |
| `vetting auto-grant set [--enabled BOOL] [--sweep-minutes N] [--validity D]` | Change it (unset flags keep their value) |
| `vetting branding show` / `set [--display-name] [--accent-color] [--logo-url] [--clear FIELD]` | Community branding on the join manifest |
| `vetting revocations` | Statement withdrawals and the memberships they touch |
| `vetting bootstrap-pgp --keyring FILE --roots FPR,… --max-depth N --links DIR [--dry-run] [--validity D]` | Name vetters from an OpenPGP web of trust (run `--dry-run` first) |

## Additional Resources

- [VTA Service & Architecture](../README.md)
- [PNM CLI (single-VTA)](../pnm-cli/README.md) -- simpler alternative for personal use
- [First Person Network White Paper](https://www.firstperson.network/white-paper)
- [Documentation index](../docs/README.md)
- [Architecture](../docs/01-concepts/architecture.md)
- [BIP-32 Path Specification](../docs/04-reference/bip32-paths.md)
