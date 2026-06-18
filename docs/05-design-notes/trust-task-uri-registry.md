# Trust-task URI registry — VTA + webvh-service migration

**Status:** Draft (Phase 0.2 of the trust-task envelope migration initiative).
**Updated:** 2026-05-19; revised 2026-05-20 (cryptosuite dropped; passkey-login-{start,finish} URIs added; migrated to framework-canonical `/spec/<hierarchical-slug>/<ver>` URI form).
**Scope:** Both services + all dependent consumers.

This document is the authoritative catalogue of trust-task URIs across
the VTA (`verifiable-trust-infrastructure`) and the WebVH services
(`affinidi-webvh-service`) for the duration of the trust-task envelope
migration. Each URI corresponds to one operation on the wire and is the
target both REST handlers and DIDComm dispatchers route on.

Once the migration ships, the source-of-truth for each URI lives in the
service's own const registry (`vta-sdk::trust_tasks::specs` for VTA,
`did-hosting-common::did_hosting_tasks` for WebVH). This document
catalogues them once for design review.

## Naming convention

```
https://trusttasks.org/spec/{namespace}/{op-path}/{maj}.{min}
```

| Slot | Rule |
|---|---|
| **scheme + host** | Always `https://trusttasks.org/`. Identifier only, not resolvable. |
| **`spec/`** | Mandatory per framework SPEC.md §6.1. Required for `trust_tasks_rs::TypeUri::from_str` to accept the URI when deserialising the wire-format `type` field. |
| **namespace** | First slug segment — one of `vta`, `did-hosting`, `webvh`. See namespace table below. |
| **op-path** | Remaining hierarchical slug segments (one or more `/`-delimited path segments per spec meta-schema). Each segment lowercase kebab-case. Examples: `auth/challenge`, `services/didcomm/enable`. |
| **version** | `{major}.{minor}` only. No patch component. A new minor or major requires registering a new URI; the old URI keeps routing to the old handler until removed in a future release. |

The slug as understood by the framework is the full `{namespace}/{op-path}`
(e.g. `vta/auth/challenge`); the framework's slug grammar (`spec.meta.schema.json`)
explicitly permits `/`-delimited path segments, modelled on the spec's
own `acl/grant` example.

The router does NOT do version-family matching. `1.0` and `1.1` are
completely separate identifiers and may have completely different
payload shapes.

### Why canonical form (and the breaking-change history)

Earlier drafts of this registry used a "flat" form
(`https://trusttasks.org/vta/auth/challenge/1.0` — no `/spec/`). That
shape is fine as a Rust `&'static str` identifier but fails
`serde_json::from_slice::<TrustTask<Value>>` at the wire boundary
because `trust_tasks_rs::TypeUri::from_str` requires the `/spec/<slug>/
<version>` shape (pinned by the
`framework_requires_canonical_uri_in_wire_type_field` test in
`vta-service::routes::trust_tasks`).

Migrated to the canonical form before any external clients existed.
The hierarchical slug (`vta/auth/challenge`) preserves the folder-like
organisation that informed the earlier flat form — no organisational
loss.

## Namespaces

| Namespace | Owner service | Scope |
|---|---|---|
| `vta` | VTA (`vta-service`, `vta-enclave`) | All VTA operations — auth, keys, contexts, ACL, bootstrap, services management, templates, audit, backup |
| `did-hosting` | webvh-service (`did-hosting-control`, `did-hosting-server`, `did-hosting-daemon`) | DID-method-agnostic hosting operations — auth, DID lifecycle, server registration, domain management, registry |
| `webvh` | webvh-service | WebVH-protocol-specific operations — witness publish/confirm, log sync. Other DID methods (`webs`, `webplus`) would get sibling namespaces. |

The boundary between `spec/vta/webvh/*` (VTA-controlled WebVH operations) and
`spec/did-hosting/*` is explicitly resolved below — see "Boundary between VTA
and WebVH".

## VTA URIs (new — all to be added)

VTA has no trust-task URIs registered yet. The full surface migrates in
Phase 3 slices; this section enumerates the target URIs by slice.

### Auth slice (`spec/vta/auth/*`)

| URI | Today's surface | Direction | Payload sketch |
|---|---|---|---|
| `spec/vta/auth/challenge/1.0` | `POST /auth/challenge` | request | `{ did }` → returns `{ session_id, challenge }` as generic OK-response (no separate URI; follows webvh-service convention) |
| `spec/vta/auth/authenticate/1.0` | `POST /auth/` | request | `{ session_id, challenge, session_pubkey_b58btc? }` (+ `eddsa-jcs-2022` proof on trust-task). **Note:** legacy DID-key-JWS auth path. Passkey-based authentication uses `spec/vta/auth/passkey-login-{start,finish}/1.0` instead — see Passkey login slice below. |
| `spec/vta/auth/passkey-login-start/1.0` | **NEW** (mirrors webvh `spec/did-hosting/auth/passkey-login-start/1.0`) | request | `{ did }` → returns `{ session_id, challenge, allowCredentials[] }` |
| `spec/vta/auth/passkey-login-finish/1.0` | **NEW** (mirrors webvh `spec/did-hosting/auth/passkey-login-finish/1.0`) | request | `{ session_id, authenticatorData, clientDataJSON, signature, credential_id, session_pubkey_b58btc? }`. WebAuthn assertion verified via webauthn-rs against DID-resolved VM. `clientData.challenge` MUST equal `SHA-256(canonical trust-task body)` (document binding). |
| `spec/vta/auth/authenticate-response/1.0` | response of `/auth/` | response | `{ access_token, refresh_token, access_expires_at, refresh_expires_at, session_id }` |
| `spec/vta/auth/refresh/1.0` | `POST /auth/refresh` | request | `{ refresh_token }` (+ proof from session key) |
| `spec/vta/auth/refresh-response/1.0` | response of `/auth/refresh` | response | same shape as authenticate-response |
| `spec/vta/auth/revoke-session/1.0` | `DELETE /auth/sessions/{id}` | request | `{ session_id }` |

### Bootstrap slice (`spec/vta/bootstrap/*`)

| URI | Today's surface | Notes |
|---|---|---|
| `spec/vta/bootstrap/request/1.0` | `POST /bootstrap/request` (TEE Mode B carve-out) | Carries Nitro attestation in the trust-task `proof` block; single-use, MODE_B_LOCK still applies |
| `spec/vta/bootstrap/request-response/1.0` | response | sealed admin VP bundle (HPKE), CRC24-armored |
| `spec/vta/bootstrap/provision-integration/1.0` | `POST /bootstrap/provision-integration` | Body is the template-bootstrap VP; sealed reply unchanged |
| `spec/vta/bootstrap/provision-integration-response/1.0` | response | sealed `TemplateBootstrapPayload` |

### Keys slice (`spec/vta/keys/*`)

| URI | Today's surface | Notes |
|---|---|---|
| `spec/vta/keys/list/1.0` | `GET /keys` + `key-management/1.0/list-keys` | |
| `spec/vta/keys/create/1.0` | `POST /keys` + `key-management/1.0/create-key` | |
| `spec/vta/keys/get/1.0` | `GET /keys/{key_id}` + DIDComm equivalent | |
| `spec/vta/keys/rename/1.0` | DIDComm `rename-key` (no REST today) | |
| `spec/vta/keys/revoke/1.0` | DIDComm `revoke-key` + REST equivalent | |
| `spec/vta/keys/sign/1.0` | `POST /keys/{key_id}/sign` + `key-management/1.0/sign-request` | Raw-bytes signing oracle |
| `spec/vta/keys/sign-trust-task-proof/1.0` | **NEW** (Phase 2 task 2.1) | Returns a ready-to-splice trust-task `proof` block; cryptosuites `eddsa-jcs-2022` and `ecdsa-jcs-2019` |
| `spec/vta/keys/import-wrapping-key/1.0` | `GET /keys/import/wrapping-key` | |
| `spec/vta/keys/import/1.0` | `POST /keys/import` | |

**Note:** the legacy `GET /keys/{key_id}/secret` mnemonic-export
endpoint moves to the seeds slice (it was per-seed, not per-key — the
URL was misleading). See `spec/vta/seeds/export-mnemonic/1.0`.

### Seeds slice (`spec/vta/seeds/*`)

| URI | Today's surface | Notes |
|---|---|---|
| `spec/vta/seeds/list/1.0` | `GET /keys/seeds` + DIDComm `list-seeds` | |
| `spec/vta/seeds/rotate/1.0` | `POST /keys/seeds/rotate` + DIDComm `rotate-seed` | |
| `spec/vta/seeds/export-mnemonic/1.0` | `GET /keys/{key_id}/secret` (formerly under keys) | One-shot BIP-39 mnemonic export under `MnemonicExportGuard`. Super-admin only. Zeroized on drop. Audit event renames `keys.get-secret` → `seeds.export-mnemonic`. |

### Contexts slice (`spec/vta/contexts/*`)

| URI | Today's surface |
|---|---|
| `spec/vta/contexts/list/1.0` | `GET /contexts` + DIDComm `list-contexts` |
| `spec/vta/contexts/create/1.0` | `POST /contexts` + DIDComm `create-context` |
| `spec/vta/contexts/get/1.0` | `GET /contexts/{id}` + DIDComm `get-context` |
| `spec/vta/contexts/update/1.0` | `PATCH /contexts/{id}` + DIDComm `update-context` |
| `spec/vta/contexts/update-did/1.0` | DIDComm `update-context-did` (and REST equivalent) |
| `spec/vta/contexts/preview-delete/1.0` | DIDComm `preview-delete-context` + REST |
| `spec/vta/contexts/delete/1.0` | `DELETE /contexts/{id}` + DIDComm `delete-context` |

### ACL slice (`spec/vta/acl/*`)

| URI | Today's surface |
|---|---|
| `spec/vta/acl/list/1.0` | `GET /acl` + DIDComm `list-acl` |
| `spec/vta/acl/create/1.0` | `POST /acl` + DIDComm `create-acl` |
| `spec/vta/acl/get/1.0` | `GET /acl/{did}` + DIDComm `get-acl` |
| `spec/vta/acl/update/1.0` | `PATCH /acl/{did}` + DIDComm `update-acl` |
| `spec/vta/acl/delete/1.0` | `DELETE /acl/{did}` + DIDComm `delete-acl` |

### Audit slice (`spec/vta/audit/*`)

| URI | Today's surface |
|---|---|
| `spec/vta/audit/list-logs/1.0` | `GET /audit/logs` + DIDComm `list-logs` |
| `spec/vta/audit/get-retention/1.0` | DIDComm `get-retention` + REST |
| `spec/vta/audit/update-retention/1.0` | DIDComm `update-retention` + REST |

### Attestation slice (`spec/vta/attestation/*`)

| URI | Today's surface |
|---|---|
| `spec/vta/attestation/status/1.0` | `GET /attestation/status` |
| `spec/vta/attestation/did-log/1.0` | `GET /attestation/did-log` |

### Services management slice (`spec/vta/services/*`)

This is the runtime service-management surface (REST + DIDComm
transports, drain windows, mediator reports). All eleven ops migrate.

| URI | Today's surface |
|---|---|
| `spec/vta/services/list/1.0` | `GET /services` + DIDComm `services/list` |
| `spec/vta/services/rest/enable/1.0` | `POST /services/rest/enable` |
| `spec/vta/services/rest/update/1.0` | `POST /services/rest/update` |
| `spec/vta/services/rest/disable/1.0` | `POST /services/rest/disable` |
| `spec/vta/services/rest/rollback/1.0` | `POST /services/rest/rollback` |
| `spec/vta/services/didcomm/enable/1.0` | `POST /services/didcomm/enable` (REST-only by construction) |
| `spec/vta/services/didcomm/update/1.0` | `POST /services/didcomm/update` |
| `spec/vta/services/didcomm/disable/1.0` | `POST /services/didcomm/disable` |
| `spec/vta/services/didcomm/rollback/1.0` | `POST /services/didcomm/rollback` |
| `spec/vta/services/didcomm/drain/list/1.0` | `GET /services/didcomm/drain` |
| `spec/vta/services/didcomm/drain/cancel/1.0` | `POST /services/didcomm/drain/cancel` |
| `spec/vta/services/mediators/report/1.0` | `GET /mediators/report` |

### WebVH-DID-lifecycle slice (`spec/vta/webvh/*`)

Operations VTA performs on WebVH DIDs it owns — distinct from the
WebVH host's own DID lifecycle ops under `spec/did-hosting/did/*`. See
boundary discussion below.

**Status**: implemented in Phase 3 (commit `feat(vta-service): Phase 3
— WebVH-DID-lifecycle slice`). Feature-gated on `webvh`; URIs declared
unconditionally in `vta-sdk::trust_tasks` and tracked by the
dispatcher's `KNOWN_FEATURE_GATED_URIS` allowlist for builds where
`webvh` is off.

| URI | Today's surface | Status |
|---|---|---|
| `spec/vta/webvh/servers/list/1.0` | webvh server CRUD on VTA side | implemented |
| `spec/vta/webvh/servers/add/1.0` | (REST `POST /webvh/servers`) | implemented |
| `spec/vta/webvh/servers/update/1.0` | | implemented |
| `spec/vta/webvh/servers/remove/1.0` | | implemented |
| `spec/vta/webvh/dids/list/1.0` | DIDs hosted/known to this VTA | implemented |
| `spec/vta/webvh/dids/create/1.0` | Mint new DID via template + register with host | implemented |
| `spec/vta/webvh/dids/get/1.0` | | implemented |
| `spec/vta/webvh/dids/get-log/1.0` | `GET /webvh/dids/{did}/log` (authed) | implemented |
| ~`spec/vta/webvh/dids/get-log-public/1.0`~ | `GET /did/{did}/log` (unauthed mirror) | **REST-only forever** (load-bearing as the DID-resolver failover path; wrapping it in a trust-task envelope would defeat the failover) |
| `spec/vta/webvh/dids/delete/1.0` | | implemented |
| `spec/vta/webvh/dids/update/1.0` | DID-doc patch (trust-task envelope carries `did` in payload — no path) | implemented |
| `spec/vta/webvh/dids/rotate-keys/1.0` | (trust-task envelope carries `did` in payload — no path) | implemented |
| `spec/vta/webvh/dids/register-with-server/1.0` | Promote serverless → server-managed (one-way) | implemented |

### DID templates slice (`spec/vta/did-templates/*`)

Global + context-scoped CRUD. Distinct URI hierarchies — see
"URI hierarchy mirrors resource hierarchy" decision below.

**Status**: implemented (commit `feat(vta-service): Phase 3 —
DID-templates slice`). Wire bodies in
`vta_sdk::protocols::did_template_management::*` (each op has its own
submodule with separate global and context-scoped body types).

**Global (super-admin writes, any-authed reads):**

| URI | Today's surface | Status |
|---|---|---|
| `spec/vta/did-templates/list/1.0` | `GET /did-templates` | implemented |
| `spec/vta/did-templates/create/1.0` | `POST /did-templates` | implemented |
| `spec/vta/did-templates/get/1.0` | `GET /did-templates/{name}` | implemented |
| `spec/vta/did-templates/update/1.0` | `PATCH /did-templates/{name}` | implemented |
| `spec/vta/did-templates/delete/1.0` | `DELETE /did-templates/{name}` | implemented |
| `spec/vta/did-templates/render/1.0` | `POST /did-templates/{name}/render` | implemented |

**Context-scoped (super-admin OR admin-with-context writes; any-authed-with-context reads):**

| URI | Today's surface | Status |
|---|---|---|
| `spec/vta/contexts/did-templates/list/1.0` | `GET /contexts/{id}/did-templates` | implemented |
| `spec/vta/contexts/did-templates/create/1.0` | `POST /contexts/{id}/did-templates` | implemented |
| `spec/vta/contexts/did-templates/get/1.0` | `GET /contexts/{id}/did-templates/{name}` | implemented |
| `spec/vta/contexts/did-templates/update/1.0` | `PATCH /contexts/{id}/did-templates/{name}` | implemented |
| `spec/vta/contexts/did-templates/delete/1.0` | `DELETE /contexts/{id}/did-templates/{name}` | implemented |
| `spec/vta/contexts/did-templates/render/1.0` | `POST /contexts/{id}/did-templates/{name}/render` | implemented |

**Why two URI hierarchies instead of one with `context_id: Option<String>`?**
Global and context templates aren't the same resource filtered
differently — they have different owners (super-admin vs
context-admin), different lifecycles, and different visibility scopes.
Modelling them as distinct URIs makes the auth contract self-evident
from the wire `type` field, removes the need for slice handlers to
branch on `Option<String>`, and mirrors the REST path hierarchy. The
WebVH-list pattern (single URI with `context_id: Option<String>`) is
the right call where `context_id` is a *filter*; here it's an
*ownership boundary*.

### Passkey VM slice (`spec/vta/passkey-vms/*`)

**Scope clarification:** this slice is **DID-level passkey VM enrolment** —
adding a passkey as a `verificationMethod` in a DID document that this VTA
controls. Once enrolled, the passkey is usable across *any* RP that resolves
the DID. Distinct from webvh-service's `spec/did-hosting/auth/passkey-*` URIs,
which are *service-level* credentials (direct passkey login to webvh-service
for users who don't have a VTA). Both can coexist; our initiative uses the
DID-level path.

| URI | Today's surface |
|---|---|
| `spec/vta/passkey-vms/enroll-challenge/1.0` | `POST /did/verification-methods/passkey/challenge` |
| `spec/vta/passkey-vms/enroll-submit/1.0` | `POST /did/verification-methods/passkey` |
| `spec/vta/passkey-vms/list/1.0` | `GET /did/verification-methods/passkey?did=…` |
| `spec/vta/passkey-vms/revoke/1.0` | `DELETE /did/verification-methods/passkey/{fragment}` |

### Backup slice (`spec/vta/backup/*`)

Three-phase descriptor pattern (initiate → transport → finalize) — bulk
bytes flow out-of-band so the trust-task framework's 1MB cap is never
hit, and the transport can be swapped (VTA-streamed in v1, S3-presigned
later) without changing clients. Modelled on OCI image distribution +
Sigstore + Git LFS.

**Status**: implemented (Stages 1–5 of the rollout plan landed; sweeper
+ CLI still pending). Full design in
`docs/05-design-notes/backup-descriptor-pattern.md`.

| URI | Purpose | Status |
|---|---|---|
| `spec/vta/backup/initiate-export/1.0` | Request export. Returns `BundleDescriptor { bundle_id, transport_url, transport_token, expected_sha256, expected_size_bytes, algorithm, expires_at }`. Authed + audit-logged. | implemented |
| `spec/vta/backup/complete-export/1.0` | Optional client ack of successful download. Closes the audit loop. | implemented |
| `spec/vta/backup/initiate-import/1.0` | Request import. Returns upload BundleDescriptor with POST target. | implemented |
| `spec/vta/backup/finalize-import/1.0` | Apply uploaded bytes; returns `{ status, source_did, key/acl/context/audit/imported counts }`. | implemented |
| `spec/vta/backup/abort/1.0` | Cancel an in-flight bundle by `bundle_id`. Idempotent on terminal. | implemented |

**Plus REST endpoints that stay REST (deliberate, not migrated):**
- `GET /backup/blob/{bundle_id}` — one-shot download. `X-Backup-Token`
  header bound to bundle_id, hashed server-side. Implemented in
  `routes::backup_blob`.
- `POST /backup/blob/{bundle_id}` — upload-once. Same token-based auth.

Analogous to `GET /did/{did}/log` — bulk transport is wrong on top of
a JSON envelope. The 1 MB global body cap is overridden for these
routes (100 MB; enforced in-handler via `to_bytes(_, CAP)`).

Algorithms supported initially: `stream` (this VTA serves the bytes).
Future: `s3-presigned`, `chunked-trust-task` (for DIDComm-only deployments
with no HTTPS transport).

### Config slice (`spec/vta/config/*`)

| URI | Today's surface |
|---|---|
| `spec/vta/config/get/1.0` | DIDComm `get-config` |
| `spec/vta/config/update/1.0` | DIDComm `update-config` |

### Discovery slice (`spec/vta/discovery/*`)

| URI | Today's surface |
|---|---|
| `spec/vta/discovery/capabilities/1.0` | `GET /capabilities` |

### VTA management slice (`spec/vta/management/*`)

| URI | Today's surface | Notes |
|---|---|---|
| `spec/vta/management/reload-services/1.0` | `POST /vta/restart` (current implementation does soft reload, not process restart) | Tears down and re-initializes REST, DIDComm, storage threads with current config. Does NOT restart the process. Use after `spec/vta/config/update/1.0` to apply changes. Super-admin only. URI renamed from `restart` to `reload-services` to match actual semantics. |

Metrics is excluded from migration entirely — see "Excluded from
migration" below.

### Join requests (`spec/vta/join-requests/*`)

VTC↔VTA bridge — currently DIDComm-only.

| URI | Today's surface |
|---|---|
| `spec/vta/join-requests/request/1.0` | DIDComm `join-requests/request` |
| `spec/vta/join-requests/decision/1.0` | DIDComm `join-requests/decision` |
| `spec/vta/join-requests/list/1.0` | DIDComm `join-requests/list` |

**VTA URI count:** ~79 (precise count after slice-by-slice spec lockdown). VTC ops excluded from this initiative.

## WebVH URIs (already registered, plus additions for this initiative)

The complete set lives in `did-hosting-common::did_hosting_tasks`
(61 URIs as of 2026-05-19) and is authoritative. Highlights:

### Existing — auth (relevant to first-light)

| URI | Status |
|---|---|
| `spec/did-hosting/auth/authenticate/1.0` | registered; handler still uses legacy `affinidi.com/webvh/1.0/authenticate` (Phase 4.4 work) |
| `spec/did-hosting/auth/authenticate-response/1.0` | registered |
| `spec/did-hosting/auth/challenge/1.0` | registered |
| `spec/did-hosting/auth/refresh/1.0` | registered |
| `spec/did-hosting/auth/passkey-{enroll,login}-{start,finish}/1.0` | registered — passkey flow already specced |
| `spec/did-hosting/auth/passkey-invite/1.0` | registered |

### Existing — ACL, DID lifecycle, server registration, domain management, registry, observability

All registered. See `did_hosting_tasks.rs` for the full list. No new URIs
required for these in this initiative.

### Existing — WebVH-protocol-specific (`spec/webvh/*`)

| URI | Status |
|---|---|
| `spec/webvh/did/witness-publish/1.0` | registered |
| `spec/webvh/did/witness-confirm/1.0` | registered |
| `spec/webvh/did/sync-update/1.0` | registered |
| `spec/webvh/did/sync-update-ack/1.0` | registered |
| `spec/webvh/did/sync-delete/1.0` | registered |
| `spec/webvh/did/sync-delete-ack/1.0` | registered |

### Net-new for this initiative

| URI | Purpose | Slice |
|---|---|---|
| `spec/did-hosting/admin/swap-did/1.0` | DID swap ceremony (cold-start finalisation per `[[project-browser-plugin-rp-login]]`). **Payload shape:** `{ new_did, new_did_proof: <embedded DataIntegrityProof by new DID's authentication VM> }`. Outer trust-task proof is by the OLD DID's session key (`eddsa-jcs-2022`); inner `new_did_proof` proves control of the new DID via any standard cryptosuite (`eddsa-jcs-2022` for VTA-managed Ed25519 `#key-1`, or `ecdsa-jcs-2019` for P-256). | Phase 4.2 (mega-project: Phase 2.2) |
| `spec/did-hosting/admin/swap-did-response/1.0` | response with fresh capability JWT | Phase 4.2 |

That's it for webvh side — two new URIs.

## Boundary between `spec/vta/webvh/*` and `spec/did-hosting/*`

Both services touch WebVH DIDs. Disambiguation:

| Operation lives in | Means |
|---|---|
| `spec/vta/webvh/*` | VTA-side: VTA mints the DID and its keys, owns the local `did.jsonl`, decides when to update or rotate. VTA pushes updates to the WebVH host. |
| `spec/did-hosting/*` | Host-side: receives DID-doc updates from controllers, publishes WebVH log entries, runs witness/watcher, serves resolution requests. Doesn't own the keys. |
| `spec/webvh/*` | Protocol-mechanical ops on WebVH's append-only log (witness publish/confirm, sync). Host runs these but they're protocol-level, not host-admin-level. |

Concrete examples:
- VTA wants to rotate a key on a DID it controls → `spec/vta/webvh/dids/rotate-keys/1.0` to the VTA, which then sends `spec/webvh/did/sync-update/1.0` to the host. Two different URIs, two different actions, on two different services.
- Operator wants to add a host to their VTA's known-hosts list → `spec/vta/webvh/servers/add/1.0`. Adding a controller authorisation to the host itself → `spec/did-hosting/acl/create/1.0`.

## Excluded from migration

These wire surfaces do NOT become trust-task envelopes:

| Surface | Reason |
|---|---|
| `GET /health/details` | Operator/infra observability. Health checks must be cheap and proxy-friendly; trust-task overhead is wrong here. |
| `GET /metrics` | Prometheus scrape format. Standard exporter contract; not application-level. |
| `GET /did/{did}/log` (public, unauthed) | **LOAD-BEARING**: failover path for WebVH log resolution. When a WebVH hosting service drops a LogEntry, any DID resolver in the world must be able to fetch the canonical copy from the minting VTA. Wrapping it in a trust-task envelope makes it useless for that purpose. Stays plain REST + public-unauthed forever. (The authed admin equivalent `GET /webvh/dids/{did}/log` DOES migrate to `spec/vta/webvh/dids/get-log/1.0`.) |
| Mediator pickup (DIDComm transport infrastructure) | Mediator protocol is its own DIDComm spec (`coordinate-mediation/2.0`, `messagepickup/3.0`); not application-level. |
| Internal server-push from server → control plane (webvh stats sync over HTTP) | Already trust-task in webvh-service (`spec/did-hosting/server/stats-sync/1.0`); no VTA equivalent needed. |
| KMS attest/unwrap (TEE startup-time only) | Pre-bootstrap; no JWT, no client, no envelope. |

## Migration mapping (legacy → trust-task URI)

For each VTA wire-surface element, what it becomes. The format is:
`<today's surface> → <trust-task URI>`. This is the table the migration
PRs work from in Phase 3.

```
REST:
  POST /auth/challenge                              → vta/auth/challenge/1.0
  POST /auth/                                       → vta/auth/authenticate/1.0
  POST /auth/refresh                                → vta/auth/refresh/1.0
  DELETE /auth/sessions/{session_id}                → vta/auth/revoke-session/1.0
  POST /bootstrap/request                           → vta/bootstrap/request/1.0
  POST /bootstrap/provision-integration             → vta/bootstrap/provision-integration/1.0
  GET    /keys                                      → vta/keys/list/1.0
  POST   /keys                                      → vta/keys/create/1.0
  GET    /keys/{id}                                 → vta/keys/get/1.0
  DELETE /keys/{id}                                 → vta/keys/revoke/1.0
  GET    /keys/{id}/secret                          → vta/keys/get-secret/1.0
  POST   /keys/{id}/sign                            → vta/keys/sign/1.0
  GET    /keys/{id}/secret                          → vta/seeds/export-mnemonic/1.0  (relocated from keys to seeds)
  GET    /keys/import/wrapping-key                  → vta/keys/import-wrapping-key/1.0
  POST   /keys/import                               → vta/keys/import/1.0
  GET    /keys/seeds                                → vta/seeds/list/1.0
  POST   /keys/seeds/rotate                         → vta/seeds/rotate/1.0
  GET    /contexts                                  → vta/contexts/list/1.0
  POST   /contexts                                  → vta/contexts/create/1.0
  GET    /contexts/{id}                             → vta/contexts/get/1.0
  PATCH  /contexts/{id}                             → vta/contexts/update/1.0
  DELETE /contexts/{id}                             → vta/contexts/delete/1.0
  GET    /acl                                       → vta/acl/list/1.0
  POST   /acl                                       → vta/acl/create/1.0
  PATCH  /acl/{did}                                 → vta/acl/update/1.0
  DELETE /acl/{did}                                 → vta/acl/delete/1.0
  GET    /audit/logs                                → vta/audit/list-logs/1.0
  GET    /attestation/status                        → vta/attestation/status/1.0
  GET    /attestation/did-log                       → vta/attestation/did-log/1.0
  GET    /services                                  → vta/services/list/1.0
  POST   /services/rest/enable                      → vta/services/rest/enable/1.0
  POST   /services/rest/update                      → vta/services/rest/update/1.0
  POST   /services/rest/disable                     → vta/services/rest/disable/1.0
  POST   /services/rest/rollback                    → vta/services/rest/rollback/1.0
  POST   /services/didcomm/enable                   → vta/services/didcomm/enable/1.0
  POST   /services/didcomm/update                   → vta/services/didcomm/update/1.0
  POST   /services/didcomm/disable                  → vta/services/didcomm/disable/1.0
  POST   /services/didcomm/rollback                 → vta/services/didcomm/rollback/1.0
  GET    /services/didcomm/drain                    → vta/services/didcomm/drain/list/1.0
  POST   /services/didcomm/drain/cancel             → vta/services/didcomm/drain/cancel/1.0
  GET    /mediators/report                          → vta/services/mediators/report/1.0
  POST   /webvh/servers                             → vta/webvh/servers/add/1.0
  GET    /webvh/servers                             → vta/webvh/servers/list/1.0
  …(see WebVH-DID-lifecycle slice for the rest)…
  GET    /did-templates                             → vta/did-templates/list/1.0
  POST   /did-templates                             → vta/did-templates/create/1.0
  …(see DID templates slice)…
  POST   /did/verification-methods/passkey/challenge → vta/passkey-vms/enroll-challenge/1.0
  POST   /did/verification-methods/passkey          → vta/passkey-vms/enroll-submit/1.0
  GET    /did/verification-methods/passkey          → vta/passkey-vms/list/1.0
  DELETE /did/verification-methods/passkey/{fragment} → vta/passkey-vms/revoke/1.0
  POST   /backup/export                             → vta/backup/initiate-export/1.0 + GET /backup/blob/{id}
                                                       + vta/backup/complete-export/1.0
  POST   /backup/import                             → vta/backup/initiate-import/1.0 + POST /backup/blob/{id}
                                                       + vta/backup/finalize-import/1.0
  POST   /vta/restart                               → vta/management/reload-services/1.0
  GET    /capabilities                              → vta/discovery/capabilities/1.0

  GET /health/details, GET /metrics,
  GET /did/{did}/log (public),
  GET/POST /backup/blob/{id} (token-gated bulk transport) — EXCLUDED, stay REST.

DIDComm protocols:
  key-management/1.0/{create,get,list,rename,revoke,sign,get-secret}-key/-request
                                                    → vta/keys/{create,get,list,rename,revoke,sign,get-secret}/1.0
  seed-management/1.0/{list-seeds,rotate-seed}       → vta/seeds/{list,rotate}/1.0
  context-management/1.0/{create,get,list,update,update-did,preview-delete,delete}
                                                    → vta/contexts/{create,get,list,update,update-did,preview-delete,delete}/1.0
  acl-management/1.0/{create,get,list,update,delete} → vta/acl/{create,get,list,update,delete}/1.0
  audit-management/1.0/{list-logs,get-retention,update-retention}
                                                    → vta/audit/{list-logs,get-retention,update-retention}/1.0
  attestation-management/1.0/*                      → vta/attestation/*/1.0
  backup-management/1.0/{export,import}             → vta/backup/{export,import}/1.0
  did-management/1.0/*                              → vta/webvh/*/1.0 (server + did sub-ops)
  did-template-management/1.0/*                     → vta/did-templates/*/1.0 + vta/contexts/did-templates/*/1.0
  discovery/1.0/capabilities                        → vta/discovery/capabilities/1.0
  join-requests/1.0/*                               → vta/join-requests/*/1.0
  protocol-management/services-management/1.0/*     → vta/services/*/1.0
  provision-integration/1.0/*                       → vta/bootstrap/provision-integration/1.0 (single op now)
  vta-management/1.0/restart                        → vta/management/restart/1.0
```

Total VTA: ~79 URIs. Total WebVH (existing + new): 63.

## Cross-cutting design notes

### Cryptosuite use

| Cryptosuite | Where used |
|---|---|
| **WebAuthn (no cryptosuite)** | Browser-side passkey assertions carried as **trust-task payload data** (NOT a Data Integrity proof on the trust-task itself). Verified via webauthn-rs against DID-resolved VMs. Used by `spec/vta/auth/passkey-login-finish/1.0`, `spec/did-hosting/auth/passkey-login-finish/1.0`, and any task that needs step-up user-presence (e.g. `spec/vta/backup/initiate-export/1.0` for sensitive exports). |
| `eddsa-jcs-2022` | Per-call proofs by session keys (Ed25519, `did:key:z6Mk…`), cold-start `did:key` direct signing |
| `ecdsa-jcs-2019` | When the user's primary VM is P-256 and they sign with it directly (rare; passkey path is normal) |

### Proof-policy stance during migration

webvh-service `enforce_proofs` flag defaults to false today. During
this initiative it stays default-false until each service is fully on
trust-task envelopes; flipping to true is a hardening step in Phase 7.

### Session-pubkey binding stays uniform

Both services bind a session pubkey at auth time and require subsequent
trust-task proofs to use `did:key:{session-pk}#{session-pk}` as
`verificationMethod`. The mechanism is identical across VTA and
webvh-service. The plugin maintains one session key per authenticated
service.

### Versioning policy

- New URI for every breaking change to a payload shape.
- A service may accept multiple versions concurrently during deprecation; clients send the highest version they understand.
- We do NOT plan any `1.1`/`2.0` URIs for the initial migration — all ops launch at `1.0`. The first `*/1.1` happens only when a real schema-breaking refinement lands.

## Architectural questions for Phase 2/3

These are NOT spec/naming decisions — they're implementation patterns that
should be decided once and applied uniformly across all slices. Surfaced
here so they're not relitigated per-slice.

1. **Single dispatcher endpoint vs per-resource routes.** webvh-service uses
   one `POST /api/trust-tasks` that dispatches by URI. VTA could do the same
   (single endpoint, simpler routing, one body cap, one auth middleware) or
   keep per-resource routes (cleaner Prometheus path metrics, easier
   per-resource rate limiting). **Recommendation:** follow webvh's
   single-endpoint pattern for consistency. Resolve in Phase 3.1.

2. **DIDComm-side dispatch.** Same question for the DIDComm transport — one
   inbound message type that carries any trust-task envelope, or per-protocol
   dispatch on the outer DIDComm `type`? webvh uses the former. **Recommendation:**
   same as above.

3. **Cross-crate parity harness.** webvh-service has a T9 test invariant that
   pins every URL const byte-for-byte against the client crate. VTA needs the
   same: `vta-sdk::trust_tasks::specs` consts and any client mirror must agree.
   Land alongside Phase 3.1.

## Resolved decisions (2026-05-19 review)

1. **`spec/vta/management/reload-services/1.0`** — keep, renamed from `restart`. The current implementation does an in-process soft reload, not a binary restart, and the URI now reflects that.
2. **`spec/vta/keys/get-secret/1.0`** → **`spec/vta/seeds/export-mnemonic/1.0`** — relocated to the seeds slice and renamed. Misleading "per-key" semantics fixed; same guard machinery (`MnemonicExportGuard`).
3. **`GET /did/{did}/log`** — excluded from migration. Load-bearing failover path for public WebVH resolution. Marked in "Excluded from migration" with a `LOAD-BEARING` comment that should appear on the route itself in code.
4. **VTC** — out of scope. `vtc-service` stays on bespoke DIDComm/REST until a follow-on initiative.
5. **Sealed-armor envelopes** — payload-of. The trust-task envelope holds metadata; the armor blob IS the payload value (a string). No double-wrapping. Applies to `spec/vta/bootstrap/request-response/1.0` and `spec/vta/bootstrap/provision-integration-response/1.0`.
6. **Large backup payloads** — three-phase descriptor pattern (initiate → out-of-band transport → finalize). Bulk bytes flow over a token-gated streaming REST endpoint that's excluded from the trust-task migration; the descriptor in the trust-task carries hash + size + transport URL + token, so integrity is verified end-to-end against signed metadata. Pluggable transport (stream-from-VTA in v1, S3-presigned later) without breaking clients. See revised `spec/vta/backup/*` slice and Excluded list.

## Action items

- [ ] **0.2g** — review the boundary section ("VTA vs WebVH") and the migration mapping; confirm no URI is in the wrong namespace.
- [ ] **0.2h** — propagate URI consts into `vta-sdk::trust_tasks::specs` (mirrors the `did_hosting_tasks.rs` pattern); add the cross-crate parity harness referenced as T9 in webvh-service.
- [ ] **0.2i** — add `LOAD-BEARING` comment on the public `/did/{did}/log` route handler explaining the WebVH resolver failover invariant (so a future "tidy-up" PR doesn't quietly remove it).
- [ ] **0.2j** — pin `BundleDescriptor` schema (Phase 3.7 design item; not blocking lighthouse).

## 0.2 dual-accept migration (2026-06)

The upstream Trust-Tasks framework published **0.2** of a set of specs. The
only wire change from 0.1 is the minor-version bump in the `type` URI plus a
fixed set of enum **values** switching kebab-case → camelCase (`vault-read` →
`vaultRead`, `apple-app-attest` → `appleAppAttest`, …); Rust struct shapes are
unchanged. The VTA **dual-accepts** both versions during a migration window:
the `*_0_1` URI constants are `#[deprecated]` (still served; removed in a
future release) and each gained a `*_0_2` successor.

Specs with no upstream 0.2 stay on 0.1 untouched: `auth/{authenticate,refresh,
challenge,revoke-session,whoami,sessions/list}`, `device/{disable,wipe}`,
`vault/delete`, and all `did-management/*`. The VTA's own `*/1.0` URIs (acl,
contexts, keys, seeds, audit, config, …) are not framework specs and are
unaffected.

### Vault archival lifecycle (openvtc extension, 0.1)

The vault gained a full archival lifecycle on top of the canonical
`vault/delete`. These URIs are **openvtc-defined** (no upstream framework
spec); they stay on `0.1`:

- **Password vault** (`VaultWrite`): `vault/archive`, `vault/unarchive`,
  `vault/restore`, `vault/purge`. `vault/delete` is now a **recoverable
  soft delete** (tombstone + grace window); its body gained `force: bool`
  for an immediate hard delete. The wire response is unchanged — the
  previously-cosmetic `graceUntil` is now a real deadline.
- **Credential store** (`CredentialWrite`, a new capability — removing a
  holder's credentials is higher-trust than `vault/credentials/receive`'s
  `VaultWrite`): `vault/credentials/{archive,unarchive,delete,restore,purge}`.

Archival state (`Active`/`Archived`/`Deleted`) is orthogonal to a
credential's *validity* (`CredentialStatus`); non-`Active` entries are
excluded from list/query and refused for use (release / proxy-login /
sign / present). A background sweeper hard-purges grace-expired tombstones.
Every vault Trust Task — read or write, success or denied — is audited once
at the dispatch spine (`vault.*` / `vault.cred.*` actions; the `reason`
field lands in the audit row's `detail`).

Two mechanisms, split by whether the payload is signed:

- **Edge transform** (`routes/trust_tasks/wire_v0_2.rs`) — for
  bearer-authenticated specs with no signature over the payload: **device/***
  and **vault/***. An inbound 0.2 request is down-converted (enum values →
  kebab at the spec's declared enum field *paths*), retyped to the canonical
  0.1 URI, dispatched through the existing 0.1 handler unchanged, and the
  response up-converted (→ camelCase at the response enum paths, retyped to
  `…/0.2#response`). `kebabize`/`camelize` are deterministic inverses;
  transforms are **path-targeted** so opaque / free-text values (JWEs, DIDs,
  labels) are never rewritten even if they coincidentally equal an enum token.
  This delivers full per-version camelCase **without** modifying the
  `vti_common` vault types.
- **Typed handler** — for signed payloads (**`auth/step-up/approve-response`**,
  where the approver signs the document). The bytes MUST NOT be mutated, so the
  handler parses its v0_1 typed payload from a *copy* whose only renamed field
  (`evidence.kind`) is normalised, while proof verification and the echoed
  response use the original signed 0.2 document.
- **Declarative** — **passkey-login** start/finish are REST-routed flat JSON
  whose VTA-facing types carry no renamed enum, so a 0.2 client is structurally
  identical; the 0.2 URIs are simply declared REST-routed.
- **As-received VP verify** — **`provision/integration`** is not on the
  trust-task dispatcher; it has its own DIDComm message-type route
  (`vta_sdk::protocols::provision_integration_management`) and a REST endpoint.
  Its payload carries a **signed VP** whose `ask.type` is camelCased in 0.2
  (`templateBootstrap` / `adminRotation`) *inside* the proof coverage, so the
  bytes MUST NOT be re-cased. The handler verifies the proof over the VP
  **exactly as received** (`BootstrapRequest::verify_value`) rather than
  re-serialising the typed struct, and the `BootstrapAsk` enum carries
  deserialize aliases for both casings. Both `…/0.1` and `…/0.2` route to the
  same handler; `result_uri_for` picks the matching `#response`. The legacy
  `firstperson.network` provision URI was retired here (the other
  `firstperson.network` management protocols are untouched).
- **Version-label dual-accept** — **`vta/passkey-vms/*`** shipped at `/1.0`
  before the registry published it; the canonical version is `/0.1` (#308/#309).
  The payload/response shapes are byte-identical across the two — only the URI
  version label differs — so the four dispatch arms accept `…/0.1 | …/1.0` and
  `success_response` (`doc.respond_with`) echoes the request version into the
  reply. No edge transform, no typed-handler copy: just both URIs in
  `ALL_URIS` / the slice `DISPATCHED_URIS` / `KNOWN_FEATURE_GATED_URIS`.
  Retirement plan: drop the `…/1.0` URIs once the browser plugin cuts over to
  `…/0.1` (it currently emits `/1.0`).

**Adding the next 0.2 spec:** add the `*_0_2` const + `ALL_URIS` entry in
`vta-sdk::trust_tasks` and `#[deprecate]` the 0.1; for an edge-transform spec,
add a `WireSpecV02` entry (with request/response enum-path tables) +
`WIRE_V0_2_URIS` entry and a JSON round-trip test; for a signed spec, add a
typed dispatch arm. The parity harness fails until the new 0.2 URI is tracked.

**Client migration (mobile / companions):** the VTA accepting 0.2 *enables*
clients to emit 0.2; it does not require them to. `vta-mobile-core` keeps
emitting 0.1 approve-response (and the VTA keeps emitting 0.1 approve-request)
so field clients interoperate with not-yet-upgraded peers. Client 0.2 emission
is a fleet-rollout-gated follow-up.
