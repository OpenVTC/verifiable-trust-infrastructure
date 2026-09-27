# vta-service

Verifiable Trust Agent (VTA) service for the [First Person Network](https://www.firstperson.network/white-paper). A VTA manages cryptographic keys, DID-based authentication, DIDComm messaging, and access control policies for a Verifiable Trust Community.

## Quick Start

```bash
# Build (includes setup wizard and OS keyring by default)
cargo build --package vta-service

# Run the interactive setup wizard
vta setup

# Start the server
vta

# Start with a custom config file
vta --config /path/to/config.toml
```

The setup wizard walks through DID creation, mediator configuration, seed storage backend selection, and admin credential generation.

## CLI Reference

```
vta [OPTIONS] [COMMAND]
```

Running `vta` with no subcommand starts the server.

**Global options:**

| Flag | Description |
|------|-------------|
| `-c, --config <PATH>` | Path to configuration file (default: `config.toml` or `$VTA_CONFIG_PATH`) |

**Subcommands:**

| Command | Description |
|---------|-------------|
| `setup` | Run the interactive setup wizard (requires `setup` feature) |
| `export-admin` | Export admin DID and credential bundle |
| `status` | Show VTA status and statistics |
| `create-did-key` | Create a `did:key` in a context (offline) |
| `create-did-webvh` | Create a `did:webvh` DID for a context (requires `setup` feature) |
| `import-did` | Import an external DID and create an ACL entry (offline) |
| `acl` | Manage Access Control List entries (offline) |
| `keys` | Manage keys (offline) |

### create-did-key

```
vta create-did-key --context <ID> [--admin] [--label <LABEL>]
```

| Flag | Description |
|------|-------------|
| `--context <ID>` | Target context ID (required) |
| `--admin` | Also create an ACL entry with Admin role |
| `--label <LABEL>` | Human-readable label for the key record and ACL entry |

### create-did-webvh

```
vta create-did-webvh --context <ID> [--label <LABEL>]
```

| Flag | Description |
|------|-------------|
| `--context <ID>` | Target context ID (required) |
| `--label <LABEL>` | Label prefix for key records (defaults to context ID) |

### import-did

```
vta import-did --did <DID> [--role <ROLE>] [--label <LABEL>] [--context <CTX>...]
```

| Flag | Description |
|------|-------------|
| `--did <DID>` | The DID to import (required) |
| `--role <ROLE>` | Role to assign: `admin`, `initiator`, or `application` |
| `--label <LABEL>` | Human-readable label for the ACL entry |
| `--context <CTX>` | Restrict to specific context(s); repeatable. Omit for unrestricted access |

### acl

```
vta acl <SUBCOMMAND>
```

| Subcommand | Description |
|------------|-------------|
| `list [--context <CTX>] [--role <ROLE>]` | List all ACL entries, optionally filtered |
| `get <DID>` | Show details of a single ACL entry |
| `update <DID> [--role <ROLE>] [--label <LABEL>] [--contexts <CTX,...>]` | Update an existing ACL entry |
| `delete <DID> [-y]` | Delete an ACL entry (`-y` to skip confirmation) |

### keys

```
vta keys <SUBCOMMAND>
```

| Subcommand | Description |
|------------|-------------|
| `list [--context <CTX>] [--status <STATUS>]` | List keys (filter by context or status: `active`/`revoked`) |
| `secrets [KEY_IDS...] [--context <CTX>]` | Export secret key material for specified keys or all active keys in a context |
| `seeds` | List seed generations and their status |
| `rotate-seed [--mnemonic <WORDS>]` | Rotate to a new master seed (generates random if mnemonic omitted) |

## HTTP API

All routes except `/health` and `/auth/*` require a valid JWT bearer token (`Authorization: Bearer <token>`).

### Health

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/health` | Health check |

Health details are Trust Tasks: `vta/health/details/0.1` (public flags, any
caller) and `vta/restore/status/0.1` (version and restore record,
administrators only).

### Authentication

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/auth/challenge` | Request a DID-based auth challenge |
| `POST` | `/auth/` | Authenticate with a signed challenge response |
| `POST` | `/auth/refresh` | Refresh an access token |
| `POST` | `/auth/credentials` | Generate credentials |

Sessions are the `auth/sessions/list/0.1` and `auth/revoke-session/0.2` Trust
Tasks; the ephemeral key-import wrapping key is `keys/import-wrapping-key/0.1`.

### Keys

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/keys` | List keys |
| `POST` | `/keys` | Create a new key |
| `GET` | `/keys/{key_id}` | Get key details |
| `PATCH` | `/keys/{key_id}` | Rename a key |
| `DELETE` | `/keys/{key_id}` | Invalidate (revoke) a key |
| `GET` | `/keys/{key_id}/secret` | Export secret key material |
| `GET` | `/keys/seeds` | List seed generations |
| `POST` | `/keys/seeds/rotate` | Rotate to a new master seed |

### Contexts

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/contexts` | List contexts |
| `POST` | `/contexts` | Create a context |
| `GET` | `/contexts/{id}` | Get context details |
| `PATCH` | `/contexts/{id}` | Update a context |
| `DELETE` | `/contexts/{id}` | Delete a context |

### Access Control

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/acl` | List ACL entries |
| `POST` | `/acl` | Create an ACL entry |
| `GET` | `/acl/{did}` | Get an ACL entry |
| `PATCH` | `/acl/{did}` | Update an ACL entry |
| `DELETE` | `/acl/{did}` | Delete an ACL entry |

### Configuration

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/config` | Get current configuration |
| `PATCH` | `/config` | Update configuration |

### Backup & Restore

The `vta/backup/*` Trust Tasks (super-admin, TSP or DIDComm), with the bytes
over `GET|POST /backup/blob/{id}`. See `docs/02-vta/backup-restore.md`.

### VTA Management

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/vta/restart` | Trigger soft restart (Admin) |

## Configuration

Configuration is loaded from a TOML file (default: `config.toml`). Every field can be overridden with an environment variable.

### Top-level

| TOML Field | Env Var | Description |
|------------|---------|-------------|
| `vta_did` | `VTA_DID` | The VTA's own DID |
| `vta_name` | — | Human-readable name (alias: `community_name`) |
| `public_url` | `VTA_PUBLIC_URL` | Public-facing URL of this VTA instance |

### `[services]`

| TOML Field | Default | Description |
|------------|---------|-------------|
| `rest` | `true` | Enable the REST API thread |
| `didcomm` | `true` | Enable the DIDComm messaging thread |

At least one service must be enabled. These can also be disabled at compile time via the `rest` and `didcomm` Cargo features.

### `[server]`

| TOML Field | Env Var | Default | Description |
|------------|---------|---------|-------------|
| `host` | `VTA_SERVER_HOST` | `0.0.0.0` | Bind address |
| `port` | `VTA_SERVER_PORT` | `8100` | Bind port |

### `[log]`

| TOML Field | Env Var | Default | Description |
|------------|---------|---------|-------------|
| `level` | `VTA_LOG_LEVEL` | `info` | Log level (also: `RUST_LOG`) |
| `format` | `VTA_LOG_FORMAT` | `text` | `text` or `json` |

### `[store]`

| TOML Field | Env Var | Default | Description |
|------------|---------|---------|-------------|
| `data_dir` | `VTA_STORE_DATA_DIR` | `data/vta` | Path to the fjall KV store data directory |

### `[messaging]`

| TOML Field | Env Var | Description |
|------------|---------|-------------|
| `mediator_url` | `VTA_MESSAGING_MEDIATOR_URL` | DIDComm mediator endpoint URL |
| `mediator_did` | `VTA_MESSAGING_MEDIATOR_DID` | DIDComm mediator DID |

### `[auth]`

| TOML Field | Env Var | Default | Description |
|------------|---------|---------|-------------|
| `access_token_expiry` | `VTA_AUTH_ACCESS_EXPIRY` | `900` | Access token lifetime in seconds |
| `refresh_token_expiry` | `VTA_AUTH_REFRESH_EXPIRY` | `86400` | Refresh token lifetime in seconds |
| `challenge_ttl` | `VTA_AUTH_CHALLENGE_TTL` | `300` | Auth challenge TTL in seconds |
| `session_cleanup_interval` | `VTA_AUTH_SESSION_CLEANUP_INTERVAL` | `600` | Expired session cleanup interval in seconds |
| `jwt_signing_key` | `VTA_AUTH_JWT_SIGNING_KEY` | — | Base64url-encoded 32-byte Ed25519 private key for JWT signing |

### `[secrets]`

| TOML Field | Env Var | Default | Description |
|------------|---------|---------|-------------|
| `seed` | `VTA_SECRETS_SEED` | — | Hex-encoded BIP-32 seed (`config-seed` feature) |
| `aws_secret_name` | `VTA_SECRETS_AWS_SECRET_NAME` | — | AWS Secrets Manager secret name |
| `aws_region` | `VTA_SECRETS_AWS_REGION` | — | AWS region override |
| `gcp_project` | `VTA_SECRETS_GCP_PROJECT` | — | GCP project ID |
| `gcp_secret_name` | `VTA_SECRETS_GCP_SECRET_NAME` | — | GCP secret name |
| `azure_vault_url` | `VTA_SECRETS_AZURE_VAULT_URL` | — | Azure Key Vault URL |
| `azure_secret_name` | `VTA_SECRETS_AZURE_SECRET_NAME` | — | Azure Key Vault secret name |
| `keyring_service` | `VTA_SECRETS_KEYRING_SERVICE` | `vta` | OS keyring service name |

## Cargo Features

| Feature | Default | Description |
|---------|---------|-------------|
| `setup` | Yes | Interactive setup wizard and `did:webvh` creation |
| `keyring` | Yes | OS keyring seed storage backend |
| `rest` | Yes | REST API thread (module and thread spawning) |
| `didcomm` | Yes | DIDComm messaging thread (module and thread spawning) |
| `config-seed` | No | Store BIP-32 seed as hex in the TOML config file |
| `aws-secrets` | No | AWS Secrets Manager seed storage backend |
| `gcp-secrets` | No | Google Cloud Secret Manager seed storage backend |
| `azure-secrets` | No | Azure Key Vault seed storage backend |

A plaintext file fallback (`seed.plaintext` in the data directory) is always available regardless of feature flags.

## Architecture

The server runs up to three dedicated OS threads, each with its own single-threaded Tokio runtime. The REST and DIDComm threads are conditional — they only start when enabled by both the `[services]` config and their corresponding Cargo feature flag.

1. **REST thread** (`vta-rest`) — Serves the Axum HTTP API. Requires the `rest` feature and `services.rest = true`.

2. **DIDComm thread** (`vta-didcomm`) — Connects to the configured mediator and processes inbound DIDComm messages. Requires the `didcomm` feature and `services.didcomm = true`. Stays idle if `vta_did` or messaging is not configured.

3. **Storage thread** (`vta-storage`) — Always runs. Handles periodic session cleanup and persists the fjall KV store on shutdown. Guarantees all writes are flushed before the database closes.

At least one of REST or DIDComm must be enabled or the server will refuse to start. Shutdown is coordinated via a `watch` channel — SIGINT or SIGTERM triggers graceful shutdown of all threads.

### Key Modules

| Module | Description |
|--------|-------------|
| `server` | `AppState`, thread orchestration, auth initialization |
| `routes` | Axum router and HTTP handler modules |
| `config` | TOML config loading with env var overrides |
| `keys` | BIP-32 key derivation, key records, seed management |
| `auth` | DID challenge-response auth, JWT tokens, sessions |
| `messaging` | DIDComm mediator connection and message loop |
| `store` | fjall KV store wrapper with keyspace handles |
| `acl` | Access control list management |
| `contexts` | Context CRUD operations |

## Seed Storage Backends

The BIP-32 master seed can be stored in any of the following backends. The seed store is selected based on which `[secrets]` fields are configured (checked in order):

| Backend | Feature | Config Fields |
|---------|---------|---------------|
| AWS Secrets Manager | `aws-secrets` | `aws_secret_name` (+ optional `aws_region`) |
| GCP Secret Manager | `gcp-secrets` | `gcp_project` + `gcp_secret_name` |
| Azure Key Vault | `azure-secrets` | `azure_vault_url` + `azure_secret_name` |
| Config file (hex) | `config-seed` | `seed` |
| OS keyring | `keyring` | `keyring_service` |
| Plaintext file | — (always available) | Falls back to `seed.plaintext` in `data_dir` |

## License

Apache-2.0
