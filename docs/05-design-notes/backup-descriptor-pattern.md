# Backup descriptor pattern

Design for the trust-task migration of VTA backup export + import. The
legacy `/backup/export` and `/backup/import` REST routes inline the
entire encrypted `BackupEnvelope` in the request/response. The
trust-task variant decouples the envelope/control plane from the bulk
byte transport: an `initiate-{export,import}` trust task hands back a
**bundle descriptor** containing a one-shot signed transport URL, the
bytes flow over a separate REST endpoint (or future S3 / DIDComm
transport), and a `finalize-import` (or optional `complete-export`)
closes the audit loop.

Modelled on OCI image distribution (blob upload sessions), Sigstore
(transparency-log entries), and Git LFS (large-object handoff).

**Status**: implemented, and the default `pnm backup export|import`
path (rollout step 5, #892), for both transfer algorithms: `stream` over
REST and `chunkedTrustTask` over DIDComm/TSP. The specifications are
published upstream in `dtgwg-trust-tasks-tf` (`specs/vta/backup/*`: the
five 1.0 tasks, the 1.1 initiators and finalizer, `get-chunk/1.0` and
`put-chunk/1.0`) and listed in
`docs/05-design-notes/trust-task-uri-registry.md` §"Backup slice". A VTA
with no `public_url` answers a `stream` request with
`vta/backup/initiate-{export,import}:transportUnavailable`. See
[DIDComm/TSP-only VTAs](#didcommtsp-only-vtas-the-chunkedtrusttask-algorithm).

## Goals

1. **No 1MB cap problem.** Trust-task envelopes are capped at 1MB
   per workspace policy. A serious VTA's backup (audit logs +
   `did.jsonl` entries + imported secrets) blows that easily.
   Bulk bytes must flow out-of-band.
2. **Transport-pluggable.** The v1 implementation hosts bytes on
   the VTA itself (`stream` algorithm). The wire shape must
   accommodate future S3-presigned URLs and DIDComm-chunked
   transport without breaking v1 clients.
3. **One-shot tokens.** A leaked descriptor must not allow
   re-downloading the backup after the original client has
   retrieved it. Tokens expire on first successful read and on a
   short TTL (5 minutes).
4. **Backwards compatible during transition.** The legacy REST
   routes keep working until external clients have migrated.
   Internal callers move first.
5. **Symmetric for export and import.** Both directions follow the
   same descriptor pattern. An export hands the operator bytes;
   an import hands the VTA bytes. The control plane (`initiate-*`
   / `finalize-import` / `complete-export`) goes through
   trust-task; the bytes always flow on a separate channel.

## Non-goals

- **Backup encryption changes.** The on-disk `.vtabak` format —
  Argon2id KDF + AES-256-GCM — is unchanged. The descriptor
  pattern is *transport*, not *encryption*. Password handling
  semantics are identical to legacy.
- **Streaming chunked decryption.** v1 buffers the full backup
  in memory between phases. Streaming is a future optimisation
  (likely paired with the `chunkedTrustTask` algorithm).
- **Cross-VTA migration UX.** The descriptor shape supports it
  (the URL can point at a different VTA) but operator-side
  tooling for cross-VTA flows is out of scope here.

## URIs

Five trust-task URIs under `spec/vta/backup/*`, plus two REST-only
endpoints for the actual byte transport:

| URI / endpoint                          | Type        | Purpose                                                |
|-----------------------------------------|-------------|--------------------------------------------------------|
| `spec/vta/backup/initiate-export/1.0`   | trust-task  | Mint export bundle; return descriptor (URL + token)    |
| `spec/vta/backup/complete-export/1.0`   | trust-task  | Optional client ack; closes the audit loop             |
| `spec/vta/backup/initiate-import/1.0`   | trust-task  | Mint upload slot; return descriptor (URL + token)      |
| `spec/vta/backup/finalize-import/1.0`   | trust-task  | Apply uploaded bytes; return `ImportResult`            |
| `spec/vta/backup/abort/1.0`             | trust-task  | Cancel an in-flight bundle by `bundle_id`              |
| `GET /backup/blob/{bundle_id}`          | REST-only   | Download exported bytes (one-shot, token-gated)        |
| `POST /backup/blob/{bundle_id}`         | REST-only   | Upload import bytes (token-gated)                      |

The blob endpoints are deliberately REST-only, analogous to
`GET /did/{did}/log`. Bulk bytes are wrong on top of a JSON envelope.

## DIDComm/TSP-only VTAs: the `chunkedTrustTask` algorithm

A VTA that advertises only DIDComm and/or TSP — a supported deployment,
since runtime service management lets REST be disabled while another
transport remains — has no HTTPS address to publish a `transportUrl` at,
and its transport will not carry a whole bundle in one message: a
mediator refuses messages over its `message_size` (1 MiB by default, of
which DIDComm's nested base64 leaves roughly 500–700 KB). Before this
algorithm such a VTA could not be backed up remotely at all.

`chunkedTrustTask` is specified upstream in [trustoverip/dtgwg-trust-tasks-tf#474](https://github.com/trustoverip/dtgwg-trust-tasks-tf/pull/474). The name was
`chunked-trust-task` in earlier revisions of this note; it is
**`chunkedTrustTask`** because trusttasks SPEC §4.10 requires
lowerCamelCase for values a specification defines. The shapes:

- `vta/backup/initiate-export/1.1` and `initiate-import/1.1` — a
  `chunkedTrustTask` descriptor carries a manifest (chunk size, chunk
  count, per-chunk `DigestMultibase` digests, whole-bundle digest,
  expiry) instead of `transportUrl` / `transportToken`. A `stream`
  request is wire-identical to 1.0, and a VTA never answers one with a
  chunked descriptor. Relaxing the required members is a MINOR because
  the specifications are `draft` (SPEC §5.2).
- `vta/backup/get-chunk/1.0` — the client **pulls** chunk *i*.
- `vta/backup/put-chunk/1.0` — the client writes chunk *i*, checked
  against the manifest it committed at `initiate-import`.
- `vta/backup/finalize-import/1.1` — as 1.0, and names missing chunks
  (`incompleteUpload`) or a manifest that did not describe the bundle
  (`bundleDigestMismatch`) before the password is used.

### How VTI implements it

**Algorithm selection (`vta_sdk::client`).** The client uses `stream` when
its Trust-Task transport is REST and `chunkedTrustTask` when it is DIDComm
or TSP. That transport is chosen from the VTA's DID document, so the
algorithm follows what the VTA advertises. There is no fallback in either
direction. A DIDComm client's `rest_url` is never used to reach the blob
endpoint, because it may come from the caller rather than from a `VTARest`
service.

**Server (`vta-backup::ops::chunked`).**
- A chunked bundle reuses the descriptor pattern's `BundleRecord` state
  machine and staging directory unchanged. What is new — the manifest and
  which indices have moved — is a `ChunkPlan` stored beside the record at
  `chunks:{bundle_id}`.
- **Serving.** `get-chunk` reads only that chunk's byte range from the
  staged file, re-checks it against the manifest digest, and never
  consumes it.
- **Completion.** `complete-export` releases the bundle. `downloaded` means
  every index was served at least once.
- **Writing.** `put-chunk` refuses bytes whose digest is not the committed
  one, so a repeat of a stored index is `stored: false` and a mismatched
  one is `digestMismatch`. It writes at the chunk's offset in a staging
  file sized up front, and syncs before answering `stored: true`.
- **Finalizing.** `finalize-import` (either version) assembles and verifies
  a chunked upload before the password is used. Only then does the bundle
  move to `ImportReceived`, the one state the finalize op accepts.
- **Expiry.** Each chunk request slides `expires_at` to one TTL from now,
  never past `created_at + MAX_BUNDLE_TTL_SECS` (one hour).
- **Rate limit.** Chunk requests are limited per authenticated DID
  (`ChunkRateLimiter`, 50/s with a burst of 100), because the per-IP REST
  limiter never sees mediator traffic. Over budget is answered
  `unavailable` with `retryAfter`, which `VtaClient::idempotent` honours.
- **Abort and sweeper.** Abort and the sweeper's retention pass delete the
  plan with the record.

**Client (`vta_sdk::client::backup_chunked`).**
- Chunks are pulled and written one at a time, each through
  `VtaClient::idempotent`, with no retry loop of its own.
- Each chunk is verified on arrival, and the assembled bundle against the
  whole-bundle digest and size.
- A failed pass leaves `ChunkedDownload` / `ChunkedUpload` holding what
  moved. Calling `fetch_missing` / `put_missing` again resumes with only
  the missing indices.
- The high-level `backup_export_via_descriptor` /
  `backup_import_via_descriptor` abort the bundle on failure, so a
  half-transferred copy is not left retrievable until expiry.

**Why pull, not push.** A mediator queue caps at 1000 messages per DID
with a 7-day expiry, and a send `Ok` is not delivery (R1.1). A chunk the
client has to ask for is a chunk it knows it lacks.

**Why 256 KiB.** 262144 raw bytes become 349526 characters of base64url.
That survives DIDComm authcrypt and two nested forward wrappers, each
×4⁄3, inside a 1 MiB message; 512 KiB would not survive even one wrapper.
With at most 4096 chunks a bundle is capped at 1 GiB, and the manifest's
digests still fit one message.

## Wire format

### `BundleDescriptor`

The shared shape every `initiate-*` returns:

```rust
pub struct BundleDescriptor {
    /// Server-generated UUID v4. Unique to this bundle for its
    /// entire lifecycle.
    pub bundle_id: String,

    /// Transport algorithm. v1 supports only `"stream"` (VTA hosts
    /// the bytes on its own blob endpoint). `"chunkedTrustTask"` uses a
    /// different descriptor shape (see above). Future: `"s3-presigned"`. The wire shape is forward-compatible
    /// — unknown algorithms surface as `MalformedRequest` at the
    /// dispatcher.
    pub algorithm: String,

    /// HTTPS URL for the byte transfer. For `stream`, this is the
    /// VTA's `GET /backup/blob/{bundle_id}` or
    /// `POST /backup/blob/{bundle_id}` URL. For `s3-presigned`,
    /// this is the presigned object URL.
    pub transport_url: String,

    /// Bearer token for the byte endpoint. Passed in the
    /// `X-Backup-Token` header for `stream`. Server-side stored
    /// hashed; constant-time comparison on validation. Token rotates
    /// per bundle — never reused.
    pub transport_token: String,

    /// Hex-encoded SHA-256 of the byte stream. Mandatory for export
    /// (the VTA computes it before issuing the descriptor); mandatory
    /// for import (the client computes it before requesting the upload
    /// slot, the VTA verifies after the POST). Wire-level integrity
    /// check independent of the encrypted envelope's internal MAC.
    pub expected_sha256: String,

    /// Total byte count. Lets the recipient pre-allocate buffers and
    /// detect truncated transfers.
    pub expected_size_bytes: u64,

    /// RFC 3339 timestamp after which the bundle is garbage-collected
    /// and the token rejected. 5 minutes from `created_at` by default.
    /// Operators can tune via `BACKUP_BUNDLE_TTL_SECS` env var with
    /// a hard ceiling of 1 hour.
    pub expires_at: DateTime<Utc>,
}
```

### Per-URI bodies

```rust
pub struct InitiateExportBody {
    /// Password to derive the AES-256-GCM key (Argon2id KDF).
    /// Minimum length is `MIN_BACKUP_PASSWORD_LEN`, enforced at the op
    /// layer via `validate_backup_password`.
    pub password: String,

    /// Include audit logs in the backup. Default: false.
    #[serde(default)]
    pub include_audit: bool,

    /// Preferred transport algorithm. Defaults to `"stream"`.
    /// Forward-compat hook — the slice rejects unknown values.
    #[serde(default = "default_stream")]
    pub algorithm: String,
}

pub struct InitiateExportResultBody {
    pub descriptor: BundleDescriptor,
    /// Hint for the CLI: print `pnm backup save --bundle-id {id}
    /// --token {token} --output backup.vtabak` so the operator
    /// can complete the download.
    pub completion_hint: String,
}

pub struct CompleteExportBody {
    pub bundle_id: String,
}

pub struct CompleteExportResultBody {
    pub bundle_id: String,
    /// True if the byte stream was successfully downloaded before
    /// this ack arrived. False if the operator skipped the download
    /// or the bundle was already garbage-collected.
    pub downloaded: bool,
}

pub struct InitiateImportBody {
    /// Hex-encoded SHA-256 of the .vtabak bytes the client is about
    /// to upload. Pre-committed so the VTA can detect tampered
    /// uploads.
    pub expected_sha256: String,

    /// Byte count of the bytes the client is about to upload.
    pub expected_size_bytes: u64,

    /// Preferred transport algorithm. Defaults to `"stream"`.
    #[serde(default = "default_stream")]
    pub algorithm: String,
}

pub struct InitiateImportResultBody {
    pub descriptor: BundleDescriptor,
    /// Hint for the CLI: print `pnm backup restore --bundle-id {id}
    /// --token {token} --input backup.vtabak --password <pw>` so the
    /// operator can complete the upload + finalize.
    pub completion_hint: String,
}

pub struct FinalizeImportBody {
    pub bundle_id: String,
    /// Password to derive the AES-256-GCM key. Same semantics as
    /// the legacy `ImportRequest::password` field. Not sent with
    /// the upload bytes — kept in the trust-task envelope so it's
    /// authcrypted (DIDComm) / bearer-protected (REST), and never
    /// touches the blob endpoint's logs.
    pub password: String,

    /// Preview mode. When false, the VTA validates the bytes and
    /// returns counts without mutating state — same semantics as
    /// the legacy `ImportRequest::confirm` field but inverted to
    /// match the verb (preview vs commit).
    #[serde(default = "default_true")]
    pub confirm: bool,
}

pub struct FinalizeImportResultBody {
    pub bundle_id: String,
    /// `"preview"` or `"committed"`.
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_did: Option<String>,
    pub key_count: usize,
    pub acl_count: usize,
    pub context_count: usize,
    pub audit_count: usize,
    #[serde(default)]
    pub imported_secret_count: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

pub struct AbortBundleBody {
    pub bundle_id: String,
}

pub struct AbortBundleResultBody {
    pub bundle_id: String,
    pub aborted: bool,
}
```

`default_stream()` → `"stream".into()`. `default_true()` → `true`.

## State machine

Bundles are stored in a new fjall keyspace `backup_bundles`. Bytes
live on disk under `${data_dir}/backups/{bundle_id}.vtabak`
(0600, owner-only).

```text
            initiate-export                            ┌──────────┐
        ─────────────────────────────────────────────▶ │ ExportReady │
                                                       └──────┬───┘
                                                              │ GET /backup/blob/{id}
                                                              ▼
                                                       ┌──────────┐
                                                       │ ExportDownloaded │ ← terminal (sweeper deletes bytes)
                                                       └──────┬───┘
                                                              │ complete-export (optional)
                                                              ▼
                                                       ┌──────────┐
                                                       │ ExportAcked │
                                                       └──────────┘

            initiate-import                            ┌──────────┐
        ─────────────────────────────────────────────▶ │ ImportPending │
                                                       └──────┬───┘
                                                              │ POST /backup/blob/{id}
                                                              ▼
                                                       ┌──────────┐
                                                       │ ImportReceived │
                                                       └──────┬───┘
                                                              │ finalize-import (preview)
                                                              ▼
                                                       ┌──────────┐
                                                       │ ImportPreviewed │ ←─ optionally loop
                                                       └──────┬───┘
                                                              │ finalize-import (commit)
                                                              ▼
                                                       ┌──────────┐
                                                       │ ImportCommitted │ ← terminal
                                                       └──────────┘

            abort  (any non-terminal state)            ┌──────────┐
        ─────────────────────────────────────────────▶ │ Aborted   │ ← terminal
                                                       └──────────┘

            TTL expiry (any non-terminal state)        ┌──────────┐
        ─────────────────────────────────────────────▶ │ Expired   │ ← terminal (sweeper deletes bytes)
                                                       └──────────┘
```

### Bundle record (fjall value)

```rust
pub struct BundleRecord {
    pub bundle_id: Uuid,
    pub kind: BundleKind, // Export | Import
    pub state: BundleState,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub created_by: String,    // DID
    pub algorithm: String,
    pub expected_sha256: String,
    pub expected_size_bytes: u64,
    /// SHA-256 of the bearer token. Plaintext token is returned once,
    /// at descriptor mint time, and never persisted.
    pub token_hash: [u8; 32],
    /// On-disk path to the .vtabak bytes. Populated after a
    /// successful upload (import) or export-mint (export).
    pub blob_path: Option<PathBuf>,
}
```

### Sweeper

A background task starting at boot + tick every 60s:

1. Scan all `BundleRecord`s where `state ∉ {ExportAcked,
   ImportCommitted, Aborted, Expired}` and `expires_at <= now`.
2. For each: delete `blob_path` if present, then transition
   `state = Expired`.
3. Separately, delete `BundleRecord`s in any terminal state
   that are older than 24 hours (audit retention window).

Boot-time replay: same scan as the periodic tick. No special
handling for "in-flight at shutdown" cases — the operator just
re-issues `initiate-*` with a fresh bundle.

## Auth model

| URI / endpoint                          | Auth                  | Notes                                                  |
|-----------------------------------------|-----------------------|--------------------------------------------------------|
| `spec/vta/backup/initiate-export/1.0`   | super-admin           | Same gate as legacy `/backup/export`                   |
| `spec/vta/backup/complete-export/1.0`   | super-admin           | Caller must own the bundle (DID match)                 |
| `spec/vta/backup/initiate-import/1.0`   | super-admin           | Same gate as legacy `/backup/import`                   |
| `spec/vta/backup/finalize-import/1.0`   | super-admin           | Caller must own the bundle (DID match)                 |
| `spec/vta/backup/abort/1.0`             | super-admin           | Caller must own the bundle (DID match)                 |
| `GET /backup/blob/{bundle_id}`          | bearer token          | `X-Backup-Token`; constant-time compare; one-shot      |
| `POST /backup/blob/{bundle_id}`         | bearer token          | `X-Backup-Token`; multi-shot until first successful PUT-equivalent then locked |

The blob endpoints are NOT JWT-authenticated. The bearer token IS
the auth. Justification:

- The token is freshly minted, randomly generated, never reused,
  short-TTL (5min), and one-shot for GET. Compromise blast radius
  is tiny.
- Requiring a JWT on the blob endpoint forces clients to maintain
  a session through the byte transfer — which on chunked uploads
  could outlive the JWT (refresh during upload is painful).
- The token is bound to the bundle_id in storage. A leaked JWT
  without the matching token gets nothing. A leaked token without
  the matching bundle_id gets nothing.

**Caller ownership check**: every state-mutating trust-task URI
checks that `auth.did == record.created_by`. A super-admin who
didn't initiate the bundle can't complete or abort it. This
prevents one super-admin from snooping on another's backup mid-flight.

## Token issuance + validation

```rust
// At mint:
let token_plain: [u8; 32] = rand::random();
let token_b64 = base64_url::encode(&token_plain);  // → BundleDescriptor.transport_token
let token_hash: [u8; 32] = sha256(&token_b64);     // → BundleRecord.token_hash
// token_plain dropped (zeroized) once b64 + hash computed.

// At blob endpoint:
let provided = req.headers().get("X-Backup-Token")?;
let provided_hash = sha256(provided.as_bytes());
if !provided_hash.ct_eq(&record.token_hash) {
    return 403;
}
if record.expires_at < now() { return 410; }
if record.state == Aborted    { return 410; }
if record.state == Expired    { return 410; }
// proceed with transfer
```

Use `subtle::ConstantTimeEq` for the hash comparison. Don't compare
plaintext tokens — keeps the DB safe even if read out.

## Algorithm enum forward-compat

v1 ships `algorithm: "stream"` only. The slice handler rejects
anything else with `MalformedRequest`:

```rust
match req.algorithm.as_str() {
    "stream" => {}
    other => return reject_with(
        &doc,
        RejectReason::MalformedRequest {
            reason: format!("unsupported transport algorithm: {other}; this VTA supports: stream"),
        },
    ),
}
```

When `s3-presigned` lands, the slice adds a match arm and the
op layer dispatches to the S3 client. No URI version bump needed —
the descriptor's `algorithm` field is the discriminator.

## Coexistence with the legacy `/backup/export` + `/backup/import`

Both surfaces ship alongside each other through the migration window.
After every internal caller (pnm-cli, cnm-cli, vta-cli-common) has
moved to the descriptor pattern, the legacy routes get a
deprecation warning + removal in a future release.

Internal flow during transition:

```
v1.X  pnm backup export   → legacy /backup/export (inline envelope)
v1.Y  pnm backup export   → spec/vta/backup/initiate-export/1.0 then GET /backup/blob/...
      pnm backup export --use-rest-legacy → legacy route (REST client), or the
                            legacy protocol message on a DIDComm client (warned)
```

There is **no offline `vta backup` command** — earlier revisions of this
note and of the operator docs referred to one, but it was never built.
Backup and restore always go through a running VTA: `pnm backup export`
/ `pnm backup import` (with `--transport rest` against a VTA that
advertises REST).

## Cross-VTA migration

The descriptor's `transport_url` can point at a different host.
This unlocks "export from VTA A, import to VTA B" without ever
exposing the encrypted bytes to the operator's filesystem:

```
operator → VTA A:    initiate-export        → descriptor_A
operator → VTA B:    initiate-import(...)   → descriptor_B
                     (operator now has descriptor_A's URL + token
                      and descriptor_B's URL + token)

operator → VTA B:    instruct VTA B to:
                       1. GET descriptor_A's URL (with descriptor_A.transport_token)
                       2. Verify sha256 matches descriptor_A.expected_sha256
                       3. POST the bytes to descriptor_B's URL
                          (with descriptor_B.transport_token)
                       4. finalize-import(descriptor_B.bundle_id, password)
```

V1 doesn't ship the "VTA B fetches from VTA A directly" path
(needs an outbound HTTPS client + identity story). The operator
acts as the proxy: download with `pnm backup save`, upload with
`pnm backup restore`. The wire shape supports the direct path
once we add an `auto-relay` algorithm.

## Test plan

1. **Unit**: sweeper transitions, token hash compare, state-machine
   reject-on-terminal-state.
2. **Integration (vta-service lib)**:
   - Export round-trip: `initiate-export` → blob GET → assertion
     bytes match the bytes the op-layer produced.
   - Import round-trip: blob POST → `finalize-import` (preview) →
     `finalize-import` (commit) → assertion VTA state mutated as
     expected.
   - Token rejection: wrong token, expired token, replay after
     one-shot terminal.
   - Cross-DID rejection: super-admin B can't complete super-admin
     A's bundle.
3. **CLI**: `pnm backup save/restore --use-trust-task` flag during
   transition (gated until descriptor pattern is the default).

## Rollout

1. Ship the SDK module + URI consts (no consumer yet).
2. Ship the op layer (`operations::backup::descriptors::*`) and the
   blob REST endpoints, gated behind a `backup-descriptors`
   compile-time feature.
3. Ship the trust-task slice in vta-service, also feature-gated.
4. Add the `pnm backup save/restore --use-trust-task` flag.
5. After bake-in (one release cycle), flip the CLI default to
   trust-task; legacy `--use-rest-legacy` remains for emergency.
   **Done (#892).** `--use-trust-task` is gone; the descriptor flow is
   what `pnm backup export|import` does. The SDK's inline
   `backup_export` / `backup_import` are deprecated — they ride a legacy
   protocol message and so have no TSP dispatcher, which is the concrete
   reason the descriptor flow is the default rather than merely the
   newer option.
6. Next release: remove the `--use-*` flags, remove the legacy
   REST routes.

## Open questions

- **Multi-blob bundles**: should an export ever produce multiple
  blobs (e.g., separate audit-log blob)? v1 says no — one bundle
  = one blob. The `BundleDescriptor.transport_url` is singular by
  design. If multi-blob is needed later, the wire shape extends
  with `transport_urls: Vec<TransportSegment>` and the algorithm
  enum picks the multi variant.
- **Rate limiting**: the blob endpoints sit on the unauth tier
  (token IS the auth). Need to confirm the existing
  `tower-governor` policy is appropriate or if a different
  per-bundle rate limit is needed.
- **Bundle quota**: should there be a per-DID limit on
  simultaneously-open bundles? E.g., one operator can't tie up
  10GB of disk by spamming `initiate-export`. v1: hardcode a
  cap of 3 open bundles per DID; reject 4th with `Conflict`.
