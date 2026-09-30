# vtc-service

Verifiable Trust Community (VTC) service for the
[First Person Network](https://www.firstperson.network/white-paper).
Part of the
[Verifiable Trust Infrastructure](https://github.com/OpenVTC/verifiable-trust-infrastructure)
workspace.

## What this crate provides

The VTC is a **self-governing community service** that sits on top
of an already-running VTA. It manages a community's members,
policies, credentials, public website, and admin UX in one process.

Unlike the VTA (which mints keys), the VTC receives a sealed key
bundle from the VTA at setup and caches the keys locally for
signing. Every Verifiable Membership / Endorsement / Relationship
Credential issued by the VTC is signed in-process by the cached
signer.

For the architectural overview see
[`docs/01-concepts/overview.md`](../docs/01-concepts/overview.md);
for the VTC-specific chapter see
[`docs/03-vtc/`](../docs/03-vtc/).

## Capabilities

| Capability | Documentation |
|---|---|
| Setup against a VTA via the `vtc-host` template | [`docs/03-vtc/getting-started.md`](../docs/03-vtc/getting-started.md) |
| Member CRUD + join requests + removal dispositions | [`docs/03-vtc/community-lifecycle.md`](../docs/03-vtc/community-lifecycle.md) |
| Embedded `regorus` policy engine (`join.rego`, `removal.rego`, `personhood.rego`, `relationships.rego`, `registry.rego`, `cross_community_roles.rego`) | [`docs/03-vtc/community-lifecycle.md`](../docs/03-vtc/community-lifecycle.md) |
| VMC / role VAC / statement (VSC) / IDVC issuance | [`docs/03-vtc/credentials.md`](../docs/03-vtc/credentials.md) |
| BitstringStatusList revocation | [`docs/03-vtc/credentials.md`](../docs/03-vtc/credentials.md) |
| Trust-registry sync + cross-community recognition | [`docs/03-vtc/trust-registry.md`](../docs/03-vtc/trust-registry.md) |
| Personhood ceremony + VRC trust graph | [`docs/03-vtc/personhood-and-graph.md`](../docs/03-vtc/personhood-and-graph.md) |
| Public community website (live + managed deploy modes) | [`docs/03-vtc/website-and-admin.md`](../docs/03-vtc/website-and-admin.md) |
| Embedded admin SPA at `/admin/*` | [`docs/03-vtc/website-and-admin.md`](../docs/03-vtc/website-and-admin.md) |
| Path-prefix + subdomain routing modes | [`docs/03-vtc/website-and-admin.md#routing-modes`](../docs/03-vtc/website-and-admin.md#routing-modes) |
| HMAC-actor-hashing audit log | (VTC MVP spec §11) |
| WebAuthn-based passkey install ceremony | [`docs/03-vtc/getting-started.md`](../docs/03-vtc/getting-started.md) |

## Differences from the VTA

| | **VTA** | **VTC** |
|---|---|---|
| Mints keys | Yes | No (receives bundle from VTA) |
| BIP-32 derivation | Yes | No |
| Contexts | Yes — multi-context | No — single-community |
| JWT audience | `"VTA"` | `"VTC"` (cross-audience tokens rejected) |
| Default port | 8100 | 8200 |
| TEE deployment | Yes (`vta-enclave`) | **Never** (permanent non-goal) |
| Storage keyspaces | `keys`, `contexts`, `acl`, `sessions`, … | `members`, `policies`, `credentials`, `relationships`, `endorsements`, … |
| Policy engine | No (ACL + role only) | Yes (`regorus`) |

## Quick start

Assumes you have a running VTA at `https://vta.example.com` with
an authorised `did:key` admin DID. See
[`docs/03-vtc/getting-started.md`](../docs/03-vtc/getting-started.md)
for the full walkthrough.

```sh
# Build the workspace
cargo build --workspace

# Run the setup wizard (provisions the VTC against the VTA)
cargo run --package vtc-service -- setup

# Start the daemon
cargo run --package vtc-service

# Verify
curl http://localhost:8200/health
```

The daemon listens on `0.0.0.0:8200` by default (configurable via
`VTC_SERVER_HOST` / `VTC_SERVER_PORT`).

## Feature flags

See [`docs/03-vtc/feature-flags.md`](../docs/03-vtc/feature-flags.md)
for the full reference.

| Feature | Default | Purpose |
|---|---|---|
| `setup` | ✓ | Interactive setup wizard + `did:webvh` template plumbing |
| `keyring` | ✓ | OS keyring secret backend |
| `website` | ✓ | Public community website + bundle deploy |
| `admin-ui` | ✓ | Embedded admin SPA + `/admin/build-info.json` |
| `config-secret` | – | Inline secret in config.toml (dev only) |
| `aws-secrets` | – | AWS Secrets Manager backend |
| `gcp-secrets` | – | GCP Secret Manager backend |
| `azure-secrets` | – | Azure Key Vault backend |

## Configuration

The daemon loads config from `config.toml` by default (override with
`--config /path/to/config.toml`). Every field can be overridden via
the `VTC_` environment-variable prefix (e.g. `VTC_SERVER_PORT=9000`).

The `vtc setup` wizard writes a working config. See the
[getting-started doc](../docs/03-vtc/getting-started.md) for the
prompt-by-prompt walkthrough, and the
[website + admin doc](../docs/03-vtc/website-and-admin.md#configuration)
for the routing / website / admin-UI knobs.

## Architecture

| Module | Purpose |
|---|---|
| `acl/` | VTC role enum (Admin, Moderator, Issuer, Member, Custom) + storage |
| `admin_ui/` | `include_dir!`-baked admin SPA serve handler |
| `auth/` | JWT + cookie + bearer extractors |
| `community/` | Profile CRUD |
| `credentials/` | VMC / VAC / VRC builders + `LocalSigner` |
| `endorsement_types/` | Operator-uploaded type registry |
| `endorsements/` | Custom endorsement issuance + revocation |
| `install/` | Install token + WebAuthn ceremony |
| `join/` | Join request lifecycle + retention |
| `members/` | Member row + personhood + DID rotation |
| `policy/` | `regorus` engine + policy storage + defaults |
| `recognition/` | Foreign-credential verifier for cross-community session mint |
| `registry/` | Trust-registry client + `MembershipSyncer` |
| `relationships/` | VRC primary keyspace + per-DID secondary index |
| `routes/` | All axum handlers |
| `routing/` | Phase 5 middleware (host_dispatch, csrf, security_headers) |
| `server.rs` | `AppState` + three-thread runtime (REST / DIDComm / storage) |
| `setup/` | Setup wizard + sealed-bundle opener |
| `status_list/` | BitstringStatusList minting + slot allocator |
| `website/` | Public website serve + bundle deploy + default landing page |

For the full module documentation see
[`docs/03-vtc/architecture.md`](../docs/03-vtc/architecture.md).

## Default ports + paths

| | Default | Override |
|---|---|---|
| HTTP listener | `0.0.0.0:8200` | `VTC_SERVER_HOST` / `VTC_SERVER_PORT` |
| Fjall data dir | `./vtc-data` | `VTC_STORE_DATA_DIR` or `[store].data_dir` |
| Admin UX mount | `/admin` | `[routing.admin_ui].mount` |
| Website mount | `/` | `[routing.website].mount` |
| Public website root | (unset → in-tree default landing page) | `[website].root_dir` |

## License

Apache-2.0. See the workspace [`LICENSE`](../LICENSE).
