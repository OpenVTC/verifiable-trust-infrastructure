# VTA Integration Guide

This guide walks through integrating a 3rd-party application or service with a
Verifiable Trust Agent (VTA). By the end you will have a service that:

- Authenticates to a VTA using a credential bundle
- Fetches its DID and private keys for signing or DIDComm
- Caches secrets locally for offline resilience
- Refreshes credentials automatically

## Prerequisites

- A running VTA instance (local or remote)
- A **credential bundle** (base64url string) issued by the VTA admin
- Rust 1.94.0+ (or use the REST API directly from any language)

## Concepts

| Term | Description |
|------|-------------|
| **VTA** | Verifiable Trust Agent — manages keys, DIDs, and access control |
| **Context** | A logical namespace within the VTA (e.g., `my-app`, `mediator`) |
| **Credential bundle** | A portable base64url token containing your DID, private key, and VTA endpoint |
| **`DidSecretsBundle`** | A JSON bundle containing a DID and its associated private keys |

## Step 1: Provision a Context and Credential

The VTA admin creates a context for your application and issues a credential:

```sh
# Using the PNM CLI (admin)
pnm context provision \
  --id my-service \
  --name "My Service" \
  --admin-label "Service Admin"
```

This outputs a base64url credential string. Store it securely — it grants
access to the `my-service` context.

## Step 2: Add the SDK Dependency

```toml
[dependencies]
vta-sdk = { version = "0.4", features = ["integration"] }
tokio = { version = "1", features = ["rt-multi-thread", "macros"] }
tracing = "0.1"
tracing-subscriber = "0.3"
```

The `integration` feature enables the unified startup module, which
includes the HTTP client, session management, and offline caching support.

## Step 3: Implement a Secret Cache

The `SecretCache` trait lets your service persist secrets locally so it can
start even when the VTA is temporarily unreachable. The simplest
implementation writes to a file:

```rust,ignore
use std::path::PathBuf;
use vta_sdk::did_secrets::DidSecretsBundle;
use vta_sdk::integration::SecretCache;

struct FileCache {
    path: PathBuf,
}

impl SecretCache for FileCache {
    async fn store(
        &self,
        bundle: &DidSecretsBundle,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // DidSecretsBundle is plain serde — JSON is the canonical wire form.
        // For at-rest secrecy, layer your own encryption (e.g. age, AES-GCM
        // keyed off OS-keyring) or front this with a secret manager.
        let encoded = serde_json::to_string(bundle)?;
        tokio::fs::write(&self.path, encoded).await?;
        Ok(())
    }

    async fn load(
        &self,
    ) -> Result<Option<DidSecretsBundle>, Box<dyn std::error::Error + Send + Sync>> {
        match tokio::fs::read_to_string(&self.path).await {
            Ok(data) => Ok(Some(serde_json::from_str(&data)?)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }
}
```

For production, consider encrypting the cached file or using your platform's
secret manager (AWS Secrets Manager, GCP Secret Manager, OS keyring, etc.).

## Step 4: Start Up with the Integration Module

```rust,ignore
use vta_sdk::integration::{startup, VtaServiceConfig, SecretSource};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::init();

    let config = VtaServiceConfig {
        credential: load_credential()?,   // Load from env, file, or secret manager
        context: "my-service".into(),
        url_override: None,               // Use the URL embedded in the credential
    };

    let cache = FileCache {
        path: "/var/lib/my-service/vta-secrets.cache".into(),
    };

    let result = startup(&config, &cache).await?;

    match result.source {
        SecretSource::Vta => tracing::info!("Started with fresh secrets from VTA"),
        SecretSource::Cache => tracing::warn!("Started with CACHED secrets (VTA unreachable)"),
    }

    tracing::info!(did = %result.did, secrets = result.bundle.secrets.len());

    // Use result.bundle.secrets for DIDComm or signing
    // Use result.client (if Some) for additional VTA API calls

    Ok(())
}
```

### What `startup()` Does

1. **Authenticates** to the VTA using the credential bundle (lightweight REST
   auth with automatic fallback to DIDComm session auth)
2. **Fetches** the latest `DidSecretsBundle` from the VTA context
3. **Caches** the bundle locally via your `SecretCache` implementation
4. **Falls back** to the cached bundle if the VTA is unreachable

On first run (no cache), the VTA must be reachable. On subsequent runs, the
service can start with cached secrets and refresh them later.

## Step 5: Use Keys for Signing

The `DidSecretsBundle` contains private keys that you can use directly:

```rust,ignore
use vta_sdk::did_key::secret_from_key_response;

// The bundle contains SecretEntry items with key_id and private_key_multibase
for entry in &result.bundle.secrets {
    tracing::info!(
        key_id = %entry.key_id,
        key_type = %entry.key_type,
        "Available key"
    );
}
```

Or use the VTA as a remote signing oracle (keys never leave the VTA):

```rust,ignore
if let Some(ref client) = result.client {
    let signature = client.sign("my-key-id", b"payload to sign", "EdDSA").await?;
    tracing::info!(signature = %signature.signature, "Signed payload");
}
```

## Alternative: Direct Client Usage

If you don't need offline resilience, use the client directly:

```rust,ignore
use vta_sdk::prelude::*;

// One-line auth from a credential bundle
let client = VtaClient::from_credential(&credential_b64, None).await?;

// Token refresh is automatic — no manual token management needed

// Create keys
let key = client.create_key(
    CreateKeyRequest::new(KeyType::Ed25519)
        .label("signing-key")
        .context("my-app")
).await?;

// List keys
let keys = client.list_keys(None, None, None, None, None).await?;

// Get a key's private material (for local signing)
let secret = client.get_key_secret(&key.key_id).await?;

// Server-side signing (key never leaves VTA)
let sig = client.sign(&key.key_id, b"hello", "EdDSA").await?;

// Fetch all secrets for a context as a portable bundle
let bundle = client.fetch_did_secrets_bundle("my-app").await?;
```

## Alternative: REST API (Any Language)

The VTA exposes a standard REST API. Any HTTP client can integrate:

### Authentication

```
POST /auth/challenge
Content-Type: application/json
{"did": "did:key:z6Mk..."}

→ {"session_id": "...", "data": {"challenge": "..."}}

POST /auth/
Content-Type: text/plain
<DIDComm-packed authenticate message>

→ {"data": {"access_token": "...", "refresh_token": "..."}}
```

### Key Operations

```
# List keys
GET /keys?context_id=my-app&status=active
Authorization: Bearer <token>

# Create a key
POST /keys
Authorization: Bearer <token>
{"key_type": "Ed25519", "label": "my-key", "context_id": "my-app"}

# Sign a payload
POST /keys/<key_id>/sign
Authorization: Bearer <token>
{"payload": "<base64url>", "algorithm": "EdDSA"}

# Get private key material
GET /keys/<key_id>/secret
Authorization: Bearer <token>
```

### What authorizes a sign request

The VTA **does not inspect what it signs** — `POST /keys/{key_id}/sign` signs
the bytes you hand it. What stops a caller signing as something it isn't is
therefore entirely *which keys it may name*, and that is enforced. A sign
request passes four gates, in order:

1. **The caller's context scope.** If the key carries a `context_id`, the
   caller must be authorized in that context (or an ancestor of it). A caller
   scoped to `domain-b` naming a key in `domain-a` is refused `403`.
2. **The key's context policy.** `signable_keys` on the context restricts which
   key ids may be used for signing at all. This is *resource-bound*: it
   constrains the key's context **regardless of the actor, including a
   super-admin**. An operator relaxes it through policy CRUD, never by holding
   a bigger role. `quota_for("sign")` applies a daily cap the same way.
3. **Unscoped keys are super-admin only.** A key with no `context_id` has no
   context and therefore no policy to constrain it, so the role floor is the
   only guardrail — non-super-admin callers are refused.
4. **The caller's own key filter** (`allowedKeys` on its ACL entry, #818).
   Where gate 2 is resource-bound, this is *actor-scoped*: it names the key
   ids **this caller** may invoke the oracle on, and it only ever
   **intersects** with the context scope — a key named in the filter but
   outside the caller's contexts is still refused by gate 1, which runs
   first. Absent means every key the caller's contexts reach (every
   pre-existing entry behaves exactly as before); **present-but-empty means
   no keys at all** — emptiness is never a wildcard. The gate reads the
   stored ACL row on every request, so an operator narrowing a filter binds
   the subject's *next* sign call — no session revocation, no waiting out a
   token TTL.

The same four gates apply on **every** transport: REST, the DIDComm
`key-management/1.0/sign-request` protocol, and the `keys/sign` Trust Task all
funnel through one enforcement point (`operations::keys::sign_payload`).

> **Granularity: per context by default, per key id on request.** Gate 1
> authorizes a caller for *every* key in a context it holds. If one credential
> signs for several domains, give **each domain its own context** — putting
> several domains' keys in one context and scoping the caller to it authorizes
> all of them. For a caller that legitimately needs *one key out of a shared
> context*, grant it `--allowed-keys <key-id>` (gate 4) instead of carving a
> context per key; and use gate 2 (`signable_keys`) when the restriction
> should bind every actor uniformly. Both narrowings are opt-in; neither is
> the default.

This is the property that makes a multi-tenant signer safe without the VTA
understanding the payload. Pinned by
`sign_payload_refuses_a_key_outside_the_callers_contexts`,
`sign_payload_restricts_unscoped_keys_to_super_admin`,
`sign_payload_honours_context_policy_signable_keys`,
`sign_payload_honours_acl_allowed_keys`, and
`sign_payload_allowed_keys_only_narrows_never_widens`.

### Context Operations

```
# List contexts
GET /contexts
Authorization: Bearer <token>

# Create a context
POST /contexts
Authorization: Bearer <token>
{"id": "my-app", "name": "My Application"}
```

See the [VTA Service README](../../vta-service/README.md) for the
complete API reference.

## Security Best Practices

1. **Store credentials securely** — Use your platform's secret manager
   (AWS Secrets Manager, GCP Secret Manager, Azure Key Vault, or OS keyring).
   Never commit credentials to source control.

2. **Encrypt cached secrets** — The `SecretCache` file contains private keys.
   Encrypt it at rest or use a secret manager backend.

3. **Use context scoping and least-privilege roles** — Each application
   should have its own VTA context with the minimum required role:
   - **Reader** — for services that only need to read keys and config
   - **Application** — for services that need to sign or write to cache
   - **Admin** — only for services that manage keys and DIDs
   Avoid sharing admin credentials across services. For a signer that acts for
   several identities, the context boundary *is* the security boundary — see
   [What authorizes a sign request](#what-authorizes-a-sign-request).

4. **Prefer server-side signing** — Use `POST /keys/{id}/sign` instead of
   exporting private keys when possible. This keeps keys inside the VTA's
   security boundary.

5. **Monitor token expiry** — `VtaClient` handles refresh automatically, but
   long-running services should monitor `client.token_expires_at()` for
   health checks.

6. **Handle offline gracefully** — The integration module's cache fallback
   ensures your service can start during VTA outages, but cached keys may be
   stale (e.g., after a key rotation). Log the `SecretSource::Cache` state
   prominently and refresh as soon as the VTA is reachable.

## Architecture Overview

```
┌─────────────────────────────────────┐
│          Your Application           │
│                                     │
│  ┌───────────┐  ┌───────────────┐   │
│  │ vta-sdk   │  │ SecretCache   │   │
│  │ integration│  │ (your impl)  │   │
│  └─────┬─────┘  └──────┬────────┘   │
│        │               │            │
└────────┼───────────────┼────────────┘
         │               │
         ▼               ▼
    ┌─────────┐   ┌────────────┐
    │   VTA   │   │ Local disk │
    │ Service │   │ / keyring  │
    └─────────┘   └────────────┘
```

1. On startup, `vta_sdk::integration::startup()` authenticates and fetches secrets.
2. Fresh secrets are cached locally via your `SecretCache` implementation.
3. If the VTA is unreachable, cached secrets are loaded instead.
4. Your application uses the DID and keys for signing, DIDComm, or other operations.
