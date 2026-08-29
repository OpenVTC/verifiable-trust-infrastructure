# did:webvh — Update + Key Rotation

> **See also:** for the operator-facing surface that drives DIDComm
> protocol changes through this update primitive, see
> [DIDComm Protocol Management](didcomm-protocol-management.md).

Generic update + key-rotation operations for an existing webvh DID
managed by a VTA. Two operations sit on top of `didwebvh_rs::update_did`:

- **Update DID** — apply new state (optional new document, witnesses,
  watchers, TTL, pre-rotation toggle).
- **Rotate keys** — convenience that mints fresh BIP-32 keys for every
  verificationMethod, rebuilds the document, and drives the update path.
  Auth keys + pre-rotation rotate as a consequence.

Both are exposed via three surfaces: REST, DIDComm, and `vta-sdk`'s
`VtaClient`. ACL is `require_admin` scoped to the DID's context.

## Coupling rules

- **Document update ⇒ key rotation.** Whenever you supply a new DID
  document, the VTA forces a parallel rotation of the webvh
  authorization keys (`update_keys`) and pre-rotation commitments
  (`next_key_hashes`). Doc keys and auth keys are not independent — a
  doc update without rotating auth would leave the chain inconsistent.
- **Metadata-only updates skip key rotation.** Witness / watcher / TTL
  changes (and toggling pre-rotation on/off) all leave VM keys
  untouched.
- **The entry that turns pre-rotation on does not rotate `update_keys`,
  even when it carries a new document.** From that entry forward the
  next update is authorized by the key committed in `next_key_hashes`,
  not by anything minted alongside the document — so a fresh update key
  here would be published, stored, and never able to sign. The previous
  entry's `update_keys` stay in force (inheritance is legal because
  pre-rotation was not yet active on that entry), and the next update
  reveals the committed key as required. Later entries, with pre-rotation
  already active, restate `update_keys` on every update.
- **`rotate-keys`** is the explicit "rotate everything" entry point.
  Same effective state as `update` with a freshly rebuilt doc.

## REST

### Update

```http
POST /contexts/{ctx_id}/dids/{scid}/update
Authorization: Bearer <admin token for ctx_id>
Content-Type: application/json
```

Body:

```json
{
  "document":           { "id": "did:webvh:...", "@context": [...], ... } | null,
  "pre_rotation_count": 2 | null,
  "witnesses":          { "threshold": 1, "witnesses": [{ "id": "z6Mk..." }] } | null,
  "watchers":           ["https://watcher.example.com"] | null,
  "ttl":                3600 | null,
  "label":              "rotate after audit" | null
}
```

Response `200`:

```json
{
  "did":                       "did:webvh:Q.../host:slug",
  "new_version_id":            "3-zMk...",
  "new_scid":                  "Q...",
  "new_log_entry":             "{\"versionId\":\"3-...\",...}",
  "update_keys_count":         1,
  "pre_rotation_key_count":    2
}
```

Error mapping:

| Status | Cause |
|---|---|
| 400 | Invalid document (id mismatch / missing required fields), invalid witness DID, invalid watcher URL |
| 404 | Unknown SCID OR caller is not admin in the DID's context (collapsed for cross-context privacy) |
| 409 | Optimistic-concurrency mismatch — DID was updated by another caller between load and write; retry |
| 500 | Library error, persistence error, publish error |

### Rotate keys

```http
POST /contexts/{ctx_id}/dids/{scid}/rotate-keys
Authorization: Bearer <admin token for ctx_id>
Content-Type: application/json
```

Body:

```json
{
  "pre_rotation_count": 2 | null,
  "label":              "scheduled key rotation" | null
}
```

Response: same `UpdateDidWebvhResultBody` shape as the update endpoint.

### `curl` example

```bash
# Update — toggle pre-rotation off
curl -X POST \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"pre_rotation_count": 0}' \
  https://vta.example.com/contexts/primary/dids/Q.../update

# Rotate keys
curl -X POST \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"label": "Q3 scheduled rotation"}' \
  https://vta.example.com/contexts/primary/dids/Q.../rotate-keys
```

## DIDComm

Two new message types extend `https://firstperson.network/protocols/did-management/1.0`:

- `update-did-webvh` / `update-did-webvh-result`
- `rotate-did-webvh-keys` / `rotate-did-webvh-keys-result`

Body shape (envelope wrapping the same fields as the REST body):

```json
{
  "context_id": "primary",
  "scid":       "Q...",
  "body":       { ... UpdateDidWebvhBody ... }
}
```

Result body identical to REST. Errors surface as `problem-report` with
the same semantic mapping as the HTTP status codes above.

## SDK

```rust
use vta_sdk::client::VtaClient;
use vta_sdk::protocols::did_management::update::{
    UpdateDidWebvhBody, RotateDidWebvhKeysBody,
};

// Update
let result = client.update_did_webvh(
    "primary",
    "Q...",
    UpdateDidWebvhBody {
        pre_rotation_count: Some(0),
        ..Default::default()
    },
).await?;

// Rotate keys
let result = client.rotate_did_webvh_keys(
    "primary",
    "Q...",
    RotateDidWebvhKeysBody {
        label: Some("scheduled".into()),
        ..Default::default()
    },
).await?;
```

`UpdateDidWebvhBody.witnesses` is opaque JSON in the SDK wire types so
the SDK stays free of a `didwebvh-rs` dependency. The vta-service
intake handler deserializes into `didwebvh_rs::witness::Witnesses` and
validates each witness DID resolves (5s timeout per witness) before
committing the new log entry.

## Key-label convention

The VTA stores per-DID, per-log-version key handles in the keys
keyspace under:

```
webvh:<scid>:<version-id>:<hash>                         ← active update key
webvh:<scid>:<version-id>:pre-rotation:<hash>            ← committed pre-rotation key
webvh:<scid>:<version-id>:vm:<fragment-id>:<hash>        ← verificationMethod key
superseded:webvh:<scid>:<version-id>:...                 ← any of the above, retired
```

The hash is the `base58btc(sha256(public_key_multibase))` form that
webvh stores in the log entry's `update_keys` / `next_key_hashes`,
so a hash from any log entry maps directly to a stored handle.

### Lazy migration

DIDs created before this convention existed have their keys under the
legacy `key:{key_id}` records. The first call to `update_did_webvh`
falls back to scanning the legacy keyspace for a public-key match and
synthesising a `WebvhKeyHandle` with `version_id: "legacy"` so the
update can proceed. New keys allocated by the update are written under
the new convention; subsequent updates use the fast path.

## Behaviour notes

- **Verification-method fragment ids are monotonic.** Each rotate-keys
  call mints `#key-N`, `#key-N+1`, … starting from the DID's
  `next_fragment_id`. Old fragment ids are never reused so external
  references to specific keys remain unambiguous across log history.
- **Old keys are not deleted.** After a rotation, the previous
  version's handles move from `webvh:` to `superseded:webvh:` for
  audit / recovery. The legacy `key:{key_id}` records are left alone.
- **Concurrent updates** are detected via optimistic concurrency on
  `WebvhDidRecord.log_entry_count`. The second caller gets `409`.
- **Witness DIDs are resolved (not signature-verified).** The VTA
  checks each witness DID resolves through the cache resolver within
  5 seconds. Witness signature verification happens at log-entry
  resolve time, not at update intake.
- **Watchers** must be `https://` URLs in production builds (`http://`
  allowed under `cfg(debug_assertions)` for local dev), no fragment,
  no query string.
- **Out of scope for these endpoints**: deactivate, migrate-to-new-URL,
  portable toggle. The underlying `didwebvh-rs` library exposes them
  but the VTA reserves separate operations for those.

## Promoting a serverless DID to a server-managed one

If a DID was created with `server_id: "serverless"` (no webvh host
at the time) and the operator later wants it published to a host,
use:

```bash
pnm did-mgmt servers add --id primary --did did:web:webvh.example.com
pnm did-mgmt dids register --did <serverless-did> --server primary
```

The second command pushes the existing local `did.jsonl` to the
host and flips `server_id` so subsequent updates auto-publish.
The DID identifier is unchanged. See
`docs/02-vta/runtime-service-management.md` for the full
walkthrough. Refused if the DID is already server-managed.

## Open follow-ups

- `did.update` audit event emission.
- End-to-end integration test against `didwebvh_rs::resolve` (the
  log-entry-validity invariant).
