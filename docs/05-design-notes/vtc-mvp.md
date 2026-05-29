# Spec: Verifiable Trust Community (VTC) — MVP

Status: **Reference** — Phases 0–5 shipped. Section bodies retain
"in Phase X this happens" wording for context; the actual code +
operator behaviour is what's documented in `docs/03-vtc/`.
Owner: Glenn Gore
Last updated: 2026-05-11 (spec)
Last reconciled: 2026-05-15 (this header)

## 1. Objective

Turn the skeletal `vtc-service` crate (auth, ACL, sessions, DIDComm,
setup, `did:webvh`) into a minimum-viable **Verifiable Trust
Community** — a self-governing community service that sits on top of
an existing VTA, manages members through policy-driven join/leave,
issues DTG credentials, integrates with a trust-registry, and
optionally hosts a public website. The admin web UX lives in a
separate sibling repo and consumes the REST API.

**Non-goals (MVP)**

- Multi-tenant VTC. One binary, one community.
- Custom credential types. Strictly the DTG catalog (§6.1).
- TEE deployment of the VTC. *Permanent* non-goal (§3).
- N-of-M admin approvals; webhooks; bulk ops; WASM plugins; i18n at
  the resource layer. Defensible retrofits (§18).

## 2. Dependencies

Rust workspace, edition 2024, MSRV 1.94.0.

Internal: `vti-common`, `vta-sdk` (REST + DIDComm + sealed-transfer),
`affinidi-messaging-didcomm-service`, `fjall`, `axum`.

New external:

- [`dtg-credentials`](https://github.com/OpenVTC/dtg-credentials) —
  the closed credential catalog.
- [`affinidi-trust-registry-rs`](https://github.com/affinidi/affinidi-trust-registry-rs)
  — TRQP v2.0 client.
- [`affinidi-status-list`](https://github.com/affinidi/affinidi-tdk-rs)
  — W3C Bitstring Status List v1.0.
- `regorus` — embedded Rego engine.
- `webauthn-rs` — passkey enrolment.

## 3. Pinned architectural decisions

Single source of truth. Downstream sections cite §3 by row letter and
do not restate.

| | Decision | Rationale |
|---|---|---|
| **A** | **1 VTC ⇄ 1 VTA**; **VTA mints + controls keys, VTC caches + signs locally** | The VTA is the canonical issuer of the integration DID's keys: it mints them at first-boot via the existing provision-integration flow and remains the only party authorised to mint or rotate them. The VTC retains a cached working copy of those keys in its own secret store (mediator / webvh-service pattern) and signs locally — every VMC, VEC, status-list credential, install-token JWT, and DIDComm outbound message is signed in-process. "No key custody" in earlier drafts meant "no key minting / rotation authority", not "no key storage" — clarified per Phase 2 M2.16. |
| **B** | **VTC is always authoritative for its own state** | ACL + keyspaces are truth. VMC/VEC are *projections* useful only when the member operates outside the VTC. VTC authz never reads its own issued VCs. |
| **C** | **Credentials limited to the DTG catalog** | New credential needs go upstream into `dtg-credentials`, not local extensions. |
| **D** | **Embedded `regorus`, no OPA sidecar** | Single artefact, lower latency. Policy activation is explicit; no hot-reload watchers. |
| **E** | **Trust-registry and StatusList are complementary** | StatusList = "is this VC revoked?"; trust-registry = "is this entity an active member?". Robust verifiers consult both. |
| **F** | **VMC `validUntil` is mandatory, finite, configurable** (default 30d) | External verifiers MUST see a bounded VMC. Inside the community, ACL is authoritative — expired VMC does not lock the member out (membership renewal is unconditional on ACL membership; see §6.3). |
| **G** | **Admin UX is a separate sibling repo** | VTC ships pure backend; admin UX consumed as a release artefact (§12.2). |
| **H** | **Public website is feature-gated and filesystem-backed** | Operators can disable to host externally, or update files in place via standard tools (§12.1). |
| **I** | **Extensibility = Rego + opaque JSON blobs** | Communities customise behaviour via policies and data via `extensions: JsonValue` slots. No plugin loader. |
| **J** | **Hygiene from day one** | Versioned audit events with HMAC-hashed actors, idempotency keys, `/v1/` URL prefix, cursor pagination, multi-passkey-per-admin. Retrofits are painful. |
| **K** | **VTC never targets TEE deployment** | *Permanent* non-goal. Trust anchor for TEE remains the VTA. |
| **L** | **Every wire op is a registered Trust Task** | REST endpoints and DIDComm messages bind to a versioned Trust Task on [trusttasks.org](https://trusttasks.org). Soft gate for MVP — stable IDs + Draft `spec.md` required before an endpoint ships (§9.4). |
| **M** | **`extensions: JsonValue` is the universal extensibility slot** | Present on `CommunityProfile`, `Member`, `JoinRequest`, `AdminEntry`, audit envelopes. Opaque to the VTC. Validated only for size and JSON well-formedness. Communities own its shape. |

## 4. Bootstrap & install

### 4.1 CLI wizard — minimal handoff to web UX

`vtc setup` is a five-prompt interactive wizard that provisions
the VTC's identity against a running VTA and prints the one-shot
install URL the operator uses to claim their admin passkey.

**Amended 2026-05-12.** This section was originally specified as
a three-prompt wizard that minted a local BIP-39 seed; that
contradicted §4.5's recovery model and was reworked under
`tasks/vtc-mvp/vta-driven-keys.md` §3. The VTA is now the sole
key authority — there is no locally-held mnemonic anywhere.

Prompts:

1. Config path (default `config.toml`).
2. VTC URL (e.g. `https://vtc.example.com/v1`).
3. Admin UX URL (e.g. `https://admin.vtc.example.com`).
4. VTA URL (e.g. `https://vta.example.com`).
5. VTA DID (e.g. `did:webvh:vta.example.com:abc`).
6. Context name at the VTA for this community.

(Plus the secrets-backend prompt for `keyring` / `aws` / `gcp` /
`azure` / `inline` / `plaintext`, surfaced via the shared
`vti_common::setup::secrets_prompt` helper.)

Flow:

1. Mint an ephemeral Ed25519 `did:key` used only for the
   round-trip.
2. Print the ephemeral DID and pause. The operator runs
   `pnm acl create --did <…> --role admin --contexts <ctx>
   --expires 1h` against the VTA to authorize the ephemeral
   DID, then presses Enter.
3. Drive `vta_sdk::provision_client::run_provision` with
   `VtaIntent::FullSetup` and `ProvisionAsk::for_template
   ("vtc-host", { URL, ADMIN_UX_URL }, ctx)`.
4. Open the returned sealed bundle. Extract the integration
   DID + its `DidKeyMaterial` (Ed25519 + X25519) into a
   `VtcKeyBundle`; write to the chosen secret-store backend.
5. Write the `did.jsonl` log from
   `TemplateBootstrapPayload.config.outputs` to
   `<store.data_dir>/did/<scid>.jsonl`. The daemon publishes
   it at `GET /.well-known/did.jsonl` (Trust-Task-exempt) — the
   URL a serverless `did:webvh:<scid>:<host>` resolves to.
6. Write `config.toml` (`vtc_did`, `vta_did`, `public_url`,
   `store`, `secrets`, `auth.jwt_signing_key`).
7. Initialise all fjall keyspaces (§13).
8. Mint a single-use **install token** (signed JWT, 15-minute
   TTL, with a one-time WebAuthn ceremony nonce embedded).
9. Print the install URL. The operator runs `vtc` to start
   the daemon.

**Install token transport hardening.** The install URL is printed
once to the operator's terminal alongside a short **claim code**
(10-char unambiguous alphanumeric, Argon2id-hashed at rest). The
URL alone is *insufficient* to claim admin — `POST /v1/install/
claim/start` requires the matching claim code plus a WebAuthn
ceremony bound to the embedded nonce. Operators deliver URL and
code through separate channels so a leak on one channel doesn't
yield admin. Stolen tokens cannot be claimed without both the
authenticator and the claim code.

### 4.2 Web install flow

Admin UX opens the URL, then:

1. **Claim** — the operator types the out-of-band claim code, then
   the SPA submits `POST /v1/install/claim/start` (with
   `claim_secret`) followed by `…/finish` with the WebAuthn
   ceremony. VTC verifies the code against the row's Argon2id
   hash, the per-row state machine ensures single-use (`Issued`
   → `Consumed`), and a 5-minute claim window (gated by a
   process-wide async mutex; mirrors VTA's `MODE_B_LOCK`
   invariant) prevents concurrent ceremonies on the same `jti`.
   Discriminated 401 codes — `claim_secret_required`,
   `claim_secret_invalid` — surface in the SPA as targeted
   messages.
2. **Passkey ↔ DID binding.** The admin DID is carried in the
   install token (not derived from the passkey), so any algorithm
   the authenticator offers (ES256, RS256, EdDSA) works — platform
   passkeys (iCloud Keychain, Windows Hello, Chrome) are
   supported. The WebAuthn attestation proves the operator
   controls the credential's key without any separate raw-bytes
   binding signature.
3. **Profile + policies** — operator enters community profile, picks
   a seed policy template, configures trust-registry behaviour.
4. **Bootstrap** — `POST /v1/admin/bootstrap` writes the first ACL
   entry (`role: Admin`) and emits `CommunityInstalled`.

After bootstrap the install URL is dead.

### 4.3 Multi-passkey per admin DID

Admin entries carry `passkeys: Vec<RegisteredPasskey>` from day one.
Each passkey records `credential_id`, `public_key`, `transports`,
`label`, `registered_at`, `last_used_at`.

Endpoints:

- `POST /v1/admin/passkeys/register` — enrol an additional device.
- `DELETE /v1/admin/passkeys/{credential_id}` — revoke a device.
- `GET /v1/admin/passkeys` — list.

**Reauth invariant.** Passkey enrolment and revocation **require a
fresh WebAuthn user-verification ceremony in the same request** (not
just a valid session). A stolen session cannot persist by binding a
new authenticator. The user-verification flag in the WebAuthn
assertion must be `true`.

**Concurrency invariant.** Passkey writes serialise per admin DID
under a fjall compare-and-set. The "refuses to leave zero passkeys"
check executes inside the same transaction.

**REST-only.** Passkey ceremonies are origin-bound by the browser.
The corresponding DIDComm protocol is **not** provided — passkey
registration over DIDComm would bypass WebAuthn's RP-ID enforcement
and is explicitly forbidden.

### 4.4 The `vtc-host` DID template

Built-in template in `vta-sdk::did_templates::builtin`. Required
var: `URL` (no trailing slash). Optional: `STATUS_LIST_PATH`
(default `/v1/status-lists`).

Mints two keys, following the workspace convention used by every
other built-in template:

- **`#key-0`** Ed25519 — `assertionMethod` + `authentication` (one
  signing key serves both purposes; matches `did-hosting-control` and
  friends).
- **`#key-1`** X25519 — `keyAgreement` (sealed-transfer + later
  DIDComm reception).

Service entries: `#vtc-rest` (`type: VTCRest`, endpoint = `{URL}`),
`#vtc-status-list` (`type: VTCStatusList`, endpoint =
`{URL}{STATUS_LIST_PATH}`). The status-list endpoint is gracefully
present from day one so external verifiers can pre-cache resolution;
the actual BitstringStatusList credentials are populated in Phase 2.

DIDComm is not advertised by default — communities that need a
mediator add it later via the existing runtime-service-management
flow.

### 4.5 Emergency bootstrap (recovery)

If every admin passkey is lost: `vtc admin emergency-bootstrap` on
a stopped daemon clears the local admin state and mints a fresh
install URL + claim code, **gated on the operator's continued
ability to authenticate as an admin against the VTA**.

**Amended 2026-05-12.** This section originally specified a
mnemonic-gated recovery path; that was incompatible with §4.1's
revised VTA-as-key-authority model (the VTA's `provision-integration`
returns random integration keys that no BIP-39 mnemonic decodes
to). Reworked under `tasks/vtc-mvp/vta-driven-keys.md` §4.

Flow:

1. Operator stops the daemon and runs
   `vtc admin emergency-bootstrap [--context <ctx>]`.
2. The command mints a fresh ephemeral Ed25519 `did:key` and
   prints the `pnm acl create` command needed to authorize it
   at the VTA. The operator runs that against PNM (or any
   equivalent VTA admin tool they hold credentials for) and
   presses Enter.
3. The driver calls
   `vta_sdk::provision_client::run_provision(VtaIntent::AdminRotated,
   ProvisionAsk::vta_admin_rotated(ctx))`. The VTA's accept
   IS the recovery authority: if the ephemeral DID was just
   granted admin role in `ctx`, the call succeeds.
4. On VTA accept: locally clear every `Role::Admin` ACL entry,
   every `admin:<did>` sister record, every PasskeyUser /
   credential mapping for those admins; mint a fresh single-use
   install URL + Argon2id-hashed claim code (both printed to the
   CLI for the operator to type at claim time); persist a one-
   shot `install:emergency_pending` marker so the daemon's next
   boot emits an `EmergencyBootstrapInvoked` audit envelope
   (operator hostname + timestamp).
5. On VTA reject (`AppError::Unauthorized`): no local state is
   touched. The recovery either re-runs after a successful
   `pnm acl create`, or the operator has lost admin access at
   the VTA too — at which point the community is lost (by
   design; there is one trust root, not two).

**What persists**: the community profile (§5.1), the audit log
(emergency bootstrap is itself audited), and the `VtcKeyBundle`
(the VTC's integration DID + keys stay put — only the admin ACL
state resets).

**Trust boundary**: a filesystem-level attacker who stops the
process and runs this command still has to clear the VTA's
`provision-integration` check. Possession of the VTC's data
directory is not sufficient.

Documented as a destructive operator action with a loud audit
trail.

## 5. Domain model

### 5.1 `CommunityProfile` (singleton, key `community/profile`)

Fields: `community_did` (immutable), `name`, `description`,
`logo_url`, `public_url`, `contact_email`, `language` (BCP 47,
default `"en"`), `created_at`, `extensions` (§3-M).

### 5.2 `Member`

```
did, role, joined_at, status_list_index, publish_consent,
departure_preference, current_vmc_id, current_role_vec_id, extensions,
personhood, personhood_asserted_at
```

Admin entries additionally carry `passkeys: Vec<RegisteredPasskey>`
(§4.3).

**Personhood fields (Phase 4 M4.1 + planning-review D2).** Two
fields persist: `personhood: bool` (default `false`) and
`personhood_asserted_at: Option<DateTime<Utc>>` (timestamp of
the most recent successful assert). The presented VP itself is
**not** persisted — Phase 4's planning review pinned a
verify-then-discard model. Operators wanting persistent
evidence storage layer it via custom rego + the existing
`extensions` slot.

### 5.3 `Role`

```
enum VtcRole { Admin, Moderator, Issuer, Member, Custom(String) }
```

Default permission matrix for **standard roles**:

| Action | Admin | Mod | Issuer | Member |
|---|---|---|---|---|
| Edit community profile | ✓ | | | |
| Author / activate policies | ✓ | | | |
| Approve / reject join requests | ✓ | ✓ | | |
| Issue VEC / VWC / RCard on behalf of community | ✓ | | ✓ | |
| Issue VMC | (only via join flow) | | | |
| Promote to Admin | ✓ (§10.4) | | | |
| Remove other members | ✓ | ✓ (policy-gated) | | |
| Self-remove | ✓ (§10.2) | ✓ | ✓ | ✓ |
| Renew own VMC | ✓ | ✓ | ✓ | ✓ |
| Publish self-issued VRC | ✓ | ✓ | ✓ | ✓ |
| Rotate own DID | ✓ | ✓ | ✓ | ✓ |

**Custom roles**: `Role::Custom(String)` receives *no* implicit
grants from the matrix. The only authoritative source of Custom-role
permissions is `role_definitions.rego` (§7.1). Unspecified actions
default-deny. The standard matrix above applies *only* to the four
named roles; do not bridge it onto Custom roles by similarity.

### 5.4 `Policy`

Rego module + metadata (`id`, `name`, `purpose`, `rego_source`,
`compiled` bytecode, `sha256`, `activated_at`, `author_did`). Exactly
one policy per `purpose` is active. Activating a new policy
atomically supersedes the prior one; the prior is retained as
archived.

### 5.5 `JoinRequest`

```
id, applicant_did, vp, submitted_at, status,
policy_decision, registry_consent, extensions
```

`status ∈ { Pending, Approved, Rejected, Withdrawn, Deferred }`.
Rejected and withdrawn requests retained for 30 days (configurable
via `join_requests.retention_days`), then purged by the retention
sweeper. VP contents may include PII — the retention window is the
sole control.

### 5.6 `StatusListState`

```
purpose ∈ { Revocation, Suspension }
capacity (default 2^17 = 131_072)
next_random_seed
occupied
list_credential_id
```

### 5.7 `RegistryRecord`

```
record_id, member_did, status ∈ { Active, Departed },
active_from, active_to, last_synced_at
```

## 6. Credentials — DTG catalog

### 6.1 Mapping

| Use | Type | Issuer | Subject | Notes |
|---|---|---|---|---|
| Membership | **VMC** | community DID | member DID | `personhood: bool` gated by §6.4. `validUntil` mandatory (§3-F). |
| Role grant | **VEC** | community DID | member DID | `endorsement = { type: "CommunityRole", role, communityDid }`. Re-issued on role change. |
| Invitation | **VIC** | community DID (admin/issuer) | applicant DID | Required by gated communities' join policies. |
| Member ↔ member trust edge | **VRC** | member DID | other member DID | Self-issued, optionally published (§12.3). |
| Member contact card | **RCard** | member or community | member | jCard value. |
| Event/proximity witness | **VWC** | external | applicant | Consumed in join VPs; VTC does not issue. |
| Custom endorsement (badges, attestations) | **VEC** | community (issuer role) | any DID | Community-defined `endorsement` value. **Operator-uploaded type registry** (Phase 4 M4.8.1, planning-review D4) — only registered types are issuable. Workspace-reserved `"CommunityRole"` URI refused at registration time. |
| Persona | VPC | community | member | **v2**. Not in MVP. |

**Custom endorsement type registry (Phase 4 M4.8.1).** Operators
register endorsement type URIs via
`POST /v1/endorsement-types` before the issuance path accepts
them. The issue handler refuses unknown types with `400
endorsement-type-not-registered`. The delete-type handler
refuses with `409 endorsement-type-in-use` when any live
endorsement still references the type.

**Self-issued VRC (Phase 4 M4.6).** Members publish trust edges
via `POST /v1/relationships`. The caller's session DID must
equal the VC's `issuer` field — the VTC verifies the
data-integrity proof against the issuer's resolved `#key-0`
but never mints VRCs on a member's behalf. Per planning-review
D7, VRCs carry **no `credentialStatus`** — revocation is row
deletion in the `relationships:` keyspace via
`DELETE /v1/relationships/{id}`.

### 6.2 Status list

- VTC mints two `BitstringStatusListCredential`s on install
  (revocation + suspension), capacity 131K each. Hosted under the
  `#vtc-status-list` service entry on the VTC DID — not the
  deployment URL — so a host migration does not break issued VMCs.
- Every VMC carries `credentialStatus` referencing the appropriate
  list and index.
- **Index allocation is random with decoys** (affinidi-status-list's
  privacy mode).
- **Flipped indices are never reallocated.** Once a member departs
  and their bit is flipped (revoked or suspended), the index is
  permanently reserved as a decoy. Allocating it to a new member
  would let external verifiers correlate the new member's slot with
  the departed identity. Index space is sized accordingly.
- Telemetry emits `StatusListOccupancyWarning` at 75% (live +
  reserved). Chaining is v2 (§17).
- **Custom endorsements share the `Revocation` status list**
  (Phase 4 M4.8 + planning-review D8). The reserved-slot
  discipline above applies uniformly across VMC slots +
  endorsement slots — a revoked endorsement's slot stays
  permanently reserved.

### 6.3 Renewal — unconditional on ACL membership

`POST /v1/members/me/renew`. Auth check verifies the caller's
session matches an active ACL entry. **No expiry check, no grace
window.** Per §3-F, VMC validity is an external-verifier concern;
inside the community, ACL is truth.

Issuance steps:

1. Mint new VMC (`validFrom = now`, `validUntil = now + community.membership.validity`)
   via the VTC's local signer (§3-A — cached integration-DID keys).
   Same status-list index.
2. Re-issue role VEC (always — both for ACL/role drift and to keep
   external chains current).
3. Re-evaluate `personhood.rego` (§6.4) and surface the resulting
   `personhood` flag on the new VMC. If the flag changes from the
   prior VMC, the audit event `MembershipRenewed` records
   `personhood_changed: true`.

   **Renewal-time policy failure is operator-configurable** (Phase
   4 M4.2.2 + planning-review D5) via
   `vtc.renewal.on_personhood_fail`:
   - `downgrade` (default): flag flips to `false`, VMC re-mints
     with `personhood: false`, paired `PersonhoodRevoked
     { reason: "renewal-policy" }` audit envelope fires. Preserves
     §3-B "ACL is authoritative".
   - `refuse`: returns `422 personhood-renewal-refused`; Member
     row untouched; no VMC re-mint. The member must re-assert
     before retrying renewal.
4. Sealed-transfer to member's DID.

### 6.4 Personhood

`personhood.rego` ships as a **minimal-allow default** (Phase 4
M4.2.1): allow when the applicant's VP carries at least one
`WitnessCredential` from a non-empty issuer. Operators upload
stricter policies when the witness-only baseline isn't enough.

**Assert flow (Phase 4 M4.3, planning-review D2 — VP-only body).**

1. Caller mints a single-use nonce via
   `POST /v1/members/{did}/personhood/challenge` (10-min TTL).
2. Caller assembles a W3C Verifiable Presentation signed by
   their `#key-0`, with `proof.challenge` set to the nonce,
   and submits via `POST /v1/members/{did}/personhood`.
3. Handler consumes the challenge, verifies the VP proof
   against the member's resolved `#key-0`, runs
   `extract_vp_claims`, evaluates `personhood.rego`.
4. On allow: flag flips, `personhood_asserted_at` stamps now,
   VMC re-mints with `personhood: true`,
   `PersonhoodAsserted { vmc_id, asserted_at }` audit emitted.
5. **The presented VP is then discarded** (planning-review
   D2). Only the flag + timestamp persist on the `Member` row.

**Revoke flow.** `DELETE /v1/members/{did}/personhood` is
admin-driven OR self-revoke. Idempotent no-op when already
`false`. Emits `PersonhoodRevoked { vmc_id, reason: "admin" |
"self" }`. The renewal-policy downgrade arm (§6.3 step 3) is
the third trigger, emitting `reason: "renewal-policy"`.

Policy input contract:
`data.input = { applicant_did, vp_claims }` for the assert
path; `data.input = { applicant_did, current_personhood,
asserted_at_seconds_ago, vp_claims }` for the renewal re-eval.
The empty `vp_claims` on renewal is intentional — operators
wanting evidence-aware renewal eval upload custom rego that
consults live inputs (trust-registry queries, etc.).

## 7. Policy engine

### 7.1 Required policies

| Name | Purpose | Default-ship |
|---|---|---|
| `join` | Decide join requests | Template `policies.open` (accept any signed VP) |
| `removal` | Decide admin-initiated removals | Any admin may remove any non-admin |
| `personhood` | Decide personhood assertion | **Minimal-allow on `WitnessCredential` presence** (Phase 4 M4.2.1) |
| `registry` | Trust-registry publish + departure disposition | Publish on join; default disposition `Tombstone` |
| `directory` | Member-directory visibility | Members see DID + role only |
| `role_definitions` | Map roles to permissions (incl. Custom) | The matrix in §5.3 for standard roles only |
| `cross_community_roles` | Honour external VEC role grants | **Deny-all** |
| `cross_community_relationships` | Store external VRCs | **Deny-all** |
| `relationships` | Store published VRCs | Store if both parties are current members |

### 7.2 Activation

`POST /v1/policies` (admin) uploads + compiles via `regorus` — 400
with compilation errors on failure. `POST /v1/policies/{id}/activate`
atomically swaps the active policy for its purpose; in-flight
requests against the old policy complete; new requests use the new.
`POST /v1/policies/{id}/test` evaluates without activating. No
file-watching, no auto-reload.

### 7.3 Input contracts

| Policy | `input` shape |
|---|---|
| `join` | `{ applicant_did, vp_claims, action: "join", now }` |
| `removal` | `{ actor_did, target_did, target_role, reason, action: "remove", now }` |
| `personhood` | `{ applicant_did, vp_claims }` |
| `registry` | `{ member, action, requested_disposition? }` |
| `directory` | `{ viewer_did, viewer_role, target_member, fields_requested }` |
| `role_definitions` | `{ role, action, resource? }` |
| `cross_community_roles` | `{ foreign_vec, target_role, vtc_state }` |
| `cross_community_relationships` | `{ vrc, viewer_member, vtc_state }` |
| `relationships` | `{ vrc, issuer_member, subject_member }` |

## 8. Trust-registry integration

### 8.1 Startup

VTC publishes its issuer profile via an in-tree
`TrustRegistryClient` wrapping the upstream
`affinidi-trust-registry-rs` server's two transports (HTTP for
reads, DIDComm for admin writes; see workspace
`vtc_service::registry::client` + `upstream`). Idempotent.
Publish failures are non-fatal but raise a state flag in
`GET /v1/community/profile` (`registry_status: "degraded" |
"active"`) and in `/v1/health/diagnostics`. Operators see the
lag without having to grep telemetry.

**Implementation note (Phase 3, post-closeout).** The TRQP
v2.0 wire shape for `recognise` (used by §8.4) is pinned
against the upstream's `POST /recognition` route at
`affinidi/affinidi-trust-registry-rs`. The request is a
4-tuple of snake_case strings (`entity_id`, `authority_id`,
`action`, `resource`); the response carries a top-level
`recognized: bool`. The VTC sends `entity_id =
<foreign-issuer-did>`, `authority_id = <local-vtc-did>`,
`action = "recognise"`, `resource = "trust-graph"`. A `404`
response is mapped to `Ok(false)` (clean not-found),
semantically equivalent to a stored record with `recognized:
false`. End-to-end tests stand up an in-process axum server
exercising the same wire codepath. Production deployments
need only the upstream's `registry.url` set + the VTC's
`vtc_did` populated.

**PII boundary.** Only `member_did`, `status`, `active_from`,
`active_to`, and `record_id` are written to the registry. The VTC
refuses to publish `extensions`, emails, names, or any other
community-defined fields.

### 8.2 Departure dispositions

| Disposition | Record state | Use case |
|---|---|---|
| **Purge** | Record deleted | Right-to-be-forgotten; private communities |
| **Tombstone** | `status: Departed`, no date range | "Was a member, no longer" — minimal disclosure |
| **Historical** | `status: Departed`, dates populated | Audit / retroactive verification |

Decision flow: `registry.rego` sets the envelope
(`publish_on_join`, `departure_options`, `default_departure`,
`min_disposition` floor). Member preference clamps within the
envelope. A member-initiated `Purge` **always overrides
`min_disposition`** (RTBF). Logged as
`RegistryRecordPolicyOverride { reason: "rtbf" }` with HMAC-hashed
identifier (§11.1).

**Timing-correlation mitigation.** RTBF-triggered registry mutations
are coalesced into a daily batch (configurable;
`registry.rtbf_batch_window_hours`, default 24) so that record
disappearance cannot be timed-aligned with a specific override
event. Status-list bit flips remain immediate locally.

### 8.3 Reconciliation (`MembershipSyncer`)

Tokio task subscribed to `MemberAdded`, `MemberRemoved`,
`RoleChanged`. Enqueues `SyncJob`s into a `sync_queue` keyspace;
retries with exponential backoff. Boot-time replay.

**Visible failure.** Persistent sync failure (default ≥ 1 hour
behind, configurable) surfaces in:
- `GET /v1/community/profile` (`registry_status`)
- `GET /v1/health/diagnostics`
- Admin UX status pings

For `Purge` jobs that fail to sync, the warning is escalated — a
locally-deleted member still recognised externally is the silent
privacy regression the disposition is meant to prevent.

### 8.4 Cross-community recognition

`cross_community_roles.rego` decides whether a foreign VEC's role
claim maps to a local ACL role. Default deny-all.

**Session-mint hardening.**

- The foreign VEC must pass StatusList revocation check at
  session-mint time (the issuer's status list URL is resolved live).
- The foreign issuer must be present in the trust-registry's
  recognition graph at the time of mint.
- The minted session's TTL is clamped to the shortest of: the JWT
  audience default, the foreign VEC's `validUntil`, the foreign
  VMC's `validUntil`.
- Recognition is **not cached**; every session mint re-runs the
  full policy + StatusList + trust-registry check.
- **Cross-community sessions do not refresh.** The standard
  `POST /v1/auth/refresh` route doesn't carry the foreign
  credentials, so re-issuing a token without re-verifying
  would defeat the "peer community removed mid-session loses
  access" invariant. Cross-community sessions expire on their
  clamped TTL; the caller mints a fresh one with the latest
  credentials. Session IDs are prefixed `xc-` to distinguish
  them from local-member sessions.
- The verifier runs four checks in order (proof verify →
  validity window → StatusList revocation → registry
  recognise) and short-circuits on the first failure. Stable
  reason codes for SIEM filtering live in
  `vtc_service::recognition::RecognitionError::reason_code`.

## 9. Wire protocols

### 9.1 Common conventions

- **URL versioning.** All REST under `/v1/`. Adding `/v2/` is the
  explicit mechanism for breaking changes.
- **Idempotency keys.** Every mutating endpoint accepts
  `Idempotency-Key: <uuid>`. Cache key is `(session_id, idempotency_key)` —
  **not** global. Idempotent retries from a different principal
  receive their own response, not the cached one. Cache TTL: 24 h
  for non-destructive operations; **destructive operations
  (`DELETE`, removal, revocation) cache for 60 s only**, and re-validate
  target state before returning a cached response. Same key + different
  body → 422 `IdempotencyKeyConflict`.
- **Cursor pagination.** All list endpoints accept
  `?cursor=&limit=` (limit 1..200). Response includes `next_cursor`
  (nullable) and optional `total_estimate`.

### 9.2 Routing modes

Each surface (API, admin UX, website) mounts on a path prefix, a
Host header, or both. Default is **path-prefix on a single host** —
works on day one without DNS configuration.

```toml
# Default (path mode)
[routing.api]       mount = "/v1"
[routing.admin_ui]  mount = "/admin"
[routing.website]   mount = "/"            # catch-all, lowest priority
```

Route priority (highest first): `/health`, `/v1/*`,
`/v1/website/*` (management API), `/admin/*`, `/*` (public site).

**Subdomain mode**: per-surface `host` set; tower middleware routes
by `Host`. Hosts not matching any surface return 404. Subdomain mode
implies the operator handles per-surface TLS certs and DNS.

The strictness of unknown-Host dispatch is configured by
`routing.subdomain_mode_strict: bool` (default `true`). When `false`,
unknown hosts fall back to path-mode prefix matching against the
parent router. Use this only as a debugging aid — production
deployments should leave it at the default so a misconfigured
proxy can't silently serve API responses on the wrong host.

**Multi-process daemons are not in MVP.** fjall is not multi-process-safe.
Operators who need isolation strip surfaces at compile time via cargo
features and put a reverse proxy / CDN in front.

### 9.3 CORS + cookie scope

`cors.allowed_origins` is a configured allowlist. Wildcards refused.

**Isolation invariant.** When the public website (§12.1) and the
admin UX (§12.2) are served on the same domain, they **must** be on
different cookie scopes. Path-mode default achieves this by setting
the admin session cookie with `Path=/admin; SameSite=Strict;
Secure; HttpOnly`; the public website's origin gains no
implicit access to admin session cookies.

Admin UX in `embedded` mode: same-origin or near-origin; no CORS
allowance for the admin UX itself.
Admin UX in `external` mode: install flow writes the external origin
into `cors.allowed_origins`.

The public website's origin is **not** auto-allowed for admin
endpoints. The public site can POST to `/v1/join-requests`
(unauthenticated) without preflight via simple-request semantics.

**CSRF on admin mutating endpoints.** Every admin endpoint requires
either `Sec-Fetch-Site: same-origin` or a CSRF double-submit cookie.
Both checks are belt-and-braces: form-encoded POSTs from public-site
JavaScript can't forge admin actions.

### 9.4 Trust Tasks

Every wire op binds to a versioned Trust Task identified by URL on
[trusttasks.org](https://trusttasks.org):

```
https://trusttasks.org/{org}/{domain}/{path}/{major}.{minor}
```

For this workspace: `org = openvtc`, `domain = vtc`. Example:
`https://trusttasks.org/openvtc/vtc/join/request/submit/1.0`.

**REST binding.** Every request carries a `Trust-Task` header. The
header is **exact-matched** against the handler's registered task
URL at route attach time — not by prefix, not by major-version
family. Mismatch → 415 `TrustTaskMismatch`; missing → 400
`TrustTaskMissing`. **Exception**: `/health` is exempt to keep
monitoring trivial; this is the only exempt endpoint and is
documented.

**DIDComm binding.** The DIDComm message `type` field **is** the
Trust Task URL. No shorthand; no parallel registry.

**Spec format.** Two artefacts under `trust-tasks/{path}/{major}.{minor}/`:

- `spec.md` — narrative with frontmatter (id, title, status,
  authors, inputs/outputs, trust assumptions, related).
- `schema.json` — JSON Schema for input/output.

Plus `trust-tasks/index.json` manifest. trusttasks.org publishes
from this manifest via CI on merge to main.

**Status lifecycle.** Draft → Reviewing → Published → Deprecated.
Draft entries are wire-referenceable. Published entries have frozen
schemas; further changes require a major bump.

**MVP gate (soft).** Every operation that ships in MVP must have a
Trust Task with a stable ID and at least a Draft `spec.md` before
its endpoint ships. Published status is the target for v1.0 of the
VTC, not the MVP gate. Published requires `schema.json` complete +
at least one conformance test + no breaking changes since first
Draft.

Source-of-truth location, full ~50-entry catalog, governance, and
the workspace's `vti-trust-tasks` integration crate live in the
sibling document `trust-tasks-spec.md` — they are too long for the
core MVP spec.

### 9.5 REST surface (canonical)

```
# Install + admin
POST   /v1/install/claim/start
POST   /v1/install/claim/finish
POST   /v1/admin/bootstrap
POST   /v1/admin/passkeys/register
DELETE /v1/admin/passkeys/{credential_id}
GET    /v1/admin/passkeys

# Admin runtime configuration
GET    /v1/admin/config
PATCH  /v1/admin/config
POST   /v1/admin/config/reload
POST   /v1/admin/config/restart
POST   /v1/admin/config/export
POST   /v1/admin/config/import

# Community
GET    /v1/community/profile
PUT    /v1/community/profile

# Members
GET    /v1/members
GET    /v1/members/{did}
GET    /v1/members/{did}/relationships
PATCH  /v1/members/{did}                        # role / extensions
POST   /v1/members/{did}/promote-to-admin       # separate audited path
DELETE /v1/members/{did}                        # admin removal
DELETE /v1/members/me                           # self removal
POST   /v1/members/me/renew
POST   /v1/members/me/rotate
POST   /v1/members/{did}/personhood/assert
DELETE /v1/members/{did}/personhood

# Join
POST   /v1/join-requests                        # submit (unauth, rate-limited)
GET    /v1/join-requests
GET    /v1/join-requests/{id}
POST   /v1/join-requests/{id}/approve
POST   /v1/join-requests/{id}/reject
POST   /v1/join-requests/{id}/defer

# Invitations / policies / relationships / credentials issued
POST,GET,DELETE /v1/invitations[/{id}]
GET,POST       /v1/policies[/{id}/{activate,test}]
POST,GET,DELETE /v1/relationships[/{id}]
POST           /v1/credentials/{endorsements,witnesses,rcards}

# Status lists, audit, backup, registry
GET            /v1/status-lists/{revocation,suspension}
GET            /v1/audit
POST           /v1/admin/backup/{export,import}
GET,POST       /v1/registry/{profile,refresh}

# Public website (feature: website)
GET,PUT,DELETE /v1/website/files[/{path}]
POST           /v1/website/deploy
GET,POST       /v1/website/{generations,rollback/{gen}}

# Health
GET            /health                          # Trust-Task exempt (§9.4)
GET            /v1/health/diagnostics           # admin only
```

### 9.6 DIDComm surface

Every REST mutating op has a DIDComm twin under the Trust Task URL.
The DIDComm `type` field is the Trust Task URL directly — no
shorthand. Notable absences:

- Install + passkey registration: REST-only (§4.3).
- `/health` + diagnostics: REST-only.
- Website management: REST-only.

**Per-DID rate limit.** DIDComm strips IP, so unauthenticated rate
limiting on `community/1.0/join-request` uses a per-sender-DID
leaky bucket (`didcomm.join_rate.bucket_capacity` and `refill_per_min`)
in the DIDComm handler, executed *before* policy evaluation. Other
DIDComm routes inherit the same per-DID limit, configurable per
Trust Task ID.

### 9.7 Auth + sessions

- Challenge-response with JWT audience `"VTC"` — cross-audience
  tokens rejected.
- Sessions issued from REST (Bearer) or DIDComm (authcrypt sender).
- **Step-up reauth** required for: passkey enrolment / revocation,
  admin promotion, emergency operations. Implemented as a fresh
  WebAuthn user-verification ceremony embedded in the request.
- Cross-community sessions (§8.4): TTL clamped to inputs, recognition
  re-evaluated on every refresh.

## 10. Member lifecycle

### 10.1 Join

```
applicant → POST /v1/join-requests (or DIDComm twin)
  { applicant_did, vp, registry_consent?, extensions? }

VTC:
  1. Verify VP signature → VerifiedJoinRequest (typestate)
  2. Run join.rego with input.vp_claims
  3. allow:
     a. Allocate status-list index (random; flipped slots excluded)
     b. Mint VMC + role VEC via the VTC's local signer (§3-A; in-process)
     c. Write ACL + Member, enqueue registry.rego decision
     d. Sealed-transfer credentials to applicant_did
     e. Audit: JoinRequestApproved + MemberAdded
  4. deny:
     a. Persist JoinRequest as Rejected with decision rationale
     b. DIDComm reject (where reachable)
     c. Audit: JoinRequestRejected
```

### 10.2 Removal

**No-last-admin invariant.** Self-removal by the sole remaining
admin is refused with 409 `LastAdminProtected`. Admin must demote
or promote a successor first. Same check applies to admin removal
of another admin — refused if the result would be zero admins.

Self-removal (`DELETE /v1/members/me`):

```
{ disposition: Purge | Tombstone | Historical | PolicyDefault }
```

Atomic local: delete ACL, anonymise Member record, flip status-list
bit (immediate), emit `MemberRemoved`. Registry sync enqueued.

Admin removal (`DELETE /v1/members/{did}`): admin role plus
`removal.rego` policy gate. Otherwise same effects.

### 10.3 Renewal

See §6.3. Unconditional on ACL membership.

### 10.4 Role change

`PATCH /v1/members/{did}` accepts role changes **except** to
`Admin`. Admin promotion is a separate endpoint:

```
POST /v1/members/{did}/promote-to-admin
```

requiring:

- caller role = `Admin`
- step-up WebAuthn UV ceremony in the same request (§9.7)
- audit event `AdminPromoted` (its own variant, not a generic
  `RoleChanged`) — distinct event type for SIEM filtering

ACL update + new VEC issuance + sealed transfer + DIDComm
notification mirror non-admin role change.

### 10.5 DID rotation

| Member DID method | Mechanism |
|---|---|
| **did:webvh** | Native: VTC resolves new DID, walks `did.jsonl` history, verifies prior-key signature. No additional credential. |
| **did:key** | Co-signed rotation attestation. |

**did:key rotation contract.**

- VTC issues a single-use `rotation_id` via
  `POST /v1/members/me/rotate/challenge` (auth: old DID's current session).
  Server-issued, bound to old DID, 10-minute TTL.
- Rotation payload `{ old_did, new_did, vtc_did, rotation_id, expires_at }`
  is **domain-tag-prefixed** with the literal `vtc-did-rotation/v1\0`
  before signing (mirrors `vta-sealed-transfer/v1` doctrine). Domain
  separation prevents cross-protocol signature reuse.
- Payload signed by **both** old and new keys.
- `POST /v1/members/me/rotate` authenticates via the *new* DID's
  session; VTC verifies both signatures, the rotation_id is consumed,
  ACL updated atomically.
- **All sessions, refresh tokens, idempotency-cached responses, and
  in-flight DIDComm threads keyed on the old DID are revoked in the
  same transaction.**
- Status-list index reused (member identity continuous), VMC + role
  VEC re-issued to new DID.

Members must use `did:key` or `did:webvh` (workspace doctrine).

### 10.6 Personhood

See §6.4.

## 11. Audit log

### 11.1 Envelope + identifier hashing

```
struct AuditEnvelope {
    event_id: Uuid,
    event_version: u32,        // bumped on breaking shape change
    schema_version: u32,
    timestamp: DateTime<Utc>,
    actor_did_hash:  [u8; 32], // HMAC-SHA256(audit_key, did_bytes)
    actor_did_plain: Option<String>,
    target_did_hash:  Option<[u8; 32]>,
    target_did_plain: Option<String>,
    event: AuditEvent,         // tagged enum, see §11.4
}
```

**HMAC, not plain hash.** The audit secret `audit_key` is stored
separately from the audit log (own keyspace, encrypted under the
VTC seed), per-community. Plain SHA-256 over a DID is reversible by
enumeration (DIDs are a small public space).

**RTBF.** Right-to-be-forgotten requests null the `*_plain` fields
and **rotate the `audit_key`**. Pre-rotation hashes become opaque to
anyone without the prior key; post-rotation events use the new key.
Audit chain integrity preserved via the per-envelope `event_id`.

### 11.2 Query

`GET /v1/audit?since=&until=&type=&actor_did=&target_did=&cursor=&limit=`.
Indices on `timestamp`, `type`, `actor_did_hash`, `target_did_hash`
maintained on write.

### 11.3 Retention

Default: retain forever. Per-event-type max retention configurable
via `audit.retention.<event_type>`. **Pruner concurrency**: pruner
reads a snapshot cutoff timestamp; writes are append-only above the
cutoff. Pruner never deletes events younger than
`cutoff + audit.pruner_safety_margin` (default 1 h) — protects
against in-flight events being dropped.

### 11.4 Event vocabulary

Tagged enum (`#[serde(tag = "type", content = "data")]`). Variants
emitted from each lifecycle section (§4, §10, §6, §8, §14.6).
`AdminPromoted` is its own variant (§10.4). `ConfigChanged` carries
per-key sensitivity: keys flagged `sensitive: true` redact
`old_value` + `new_value` in the audit record (e.g., TLS paths;
future webhook URLs with tokens). Complete catalog lives alongside
the source in `vti-common::audit::events`.

**Phase 4 additions (M4.1.2 + D4 review — eight new variants):**
- `VrcPublished { vrc_id, subject_did?, edge_type }` — self-issued
  trust edge stored.
- `VrcRevoked { vrc_id, revoked_by }` — paired with the
  `relationships:` row deletion (per D7, no `credentialStatus`
  bit-flip).
- `PersonhoodAsserted { vmc_id, asserted_at }` — after a
  successful `POST .../personhood`. VP is discarded post-eval
  (D2 review) so no evidence hash appears here.
- `PersonhoodRevoked { vmc_id?, reason }` — `reason ∈ {
  "admin", "self", "renewal-policy" }`. `vmc_id` is `None`
  only on the `refuse`-arm of M4.2.2 (no VMC re-mint).
- `CustomEndorsementIssued { endorsement_id, endorsement_type,
  status_list_index }` + paired `VecIssued` for accounting.
- `CustomEndorsementRevoked { endorsement_id, endorsement_type }`
  + paired `StatusListFlipped` (same shared-list discipline as
  VMC revocation).
- `EndorsementTypeRegistered { type_uri, description? }` /
  `EndorsementTypeDeleted { type_uri }` — admin-driven registry
  CRUD (M4.8.1).

## 12. Optional surfaces

### 12.1 Public community website (`website` feature)

Filesystem-backed static hosting. Files live at
`website.root_dir`; can be edited directly (`scp`, `rsync`, `git`)
or via the REST API. No template engine, no opinions about site
structure.

**Deploy modes** (config `website.deploy_mode`):

- **`"live"`** (default): files served as-is from `root_dir`; bundle
  deploys extract via a *staging directory + atomic rename*, never
  in place (avoids partial reads under concurrent serving).
- **`"managed"`**: `root_dir/gen-N/` directories + `current → gen-N`
  symlink. Bundle deploys extract to a fresh generation; symlink
  swapped atomically. Last 5 generations retained.

**Path safety.**

- All paths canonicalised to `root_dir` real path; any resolution
  that escapes `root_dir` is rejected (400).
- Symlinks within `root_dir` are not followed.
- Unicode-normalised to NFC; non-NFC paths rejected.
- Null bytes, control characters in paths rejected.
- Hidden files (leading `.`) not served.

**Content security.**

- `X-Content-Type-Options: nosniff` on every response.
- Default CSP disables inline JavaScript on the public site:
  `default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'`.
  Configurable per-site for SPA needs.
- MIME types from extension (`mime_guess`), no sniffing.
- Forbid serving files with executable bits or with extensions in
  the configured `website.executable_blocklist` (default: `.cgi`,
  `.php`, `.exe`).

**Cookie isolation.** See §9.3. The website's origin must not share
cookie scope with the admin UX.

**Form submission.** The static site POSTs directly to
`/v1/join-requests`. No proxy endpoint.

`ETag` (SHA-256 of content) + `Cache-Control` so a CDN can sit in
front. Live-mode file-descriptor cache TTL configurable
(`website.live_cache_ttl_seconds`, default 5).

### 12.2 Admin UX (`admin-ui` feature)

> **Amended (post-Phase 5):** the in-tree-React + `build.rs`
> outcome captured in `vtc-service/admin-ui/README.md` is the
> shipped reality. The original placeholder design + the Phase 5
> deviation note below are retained for context; the live wire
> shape is React + TypeScript + Vite, baked via `include_dir!`
> from `vtc-service/admin-ui/dist/` after `build.rs` runs
> `npm install && npm run build`. Air-gapped operators ship a
> pre-built `dist/` and set `VTC_SKIP_ADMIN_UI_BUILD=1`.

The admin UX is a SPA whose source lives **in-tree** at
`vtc-service/admin-ui/`. The `include_dir!` macro bakes the
directory at compile time; there is no out-of-tree dependency
and no signed-tarball fetch. `cargo build` runs the SPA build via
`build.rs` and produces a self-contained binary including the
compiled SPA.

The Phase 5 MVP started as a plain HTML/CSS/JS placeholder
(status panel + build-info readout) but outgrew it during Phase 5
itself as the plugin API + design-language pass landed. Operators
wanting a different UX point `admin_ui.mode = "external"` at
their own origin. See `vtc-service/admin-ui/README.md` for the
contract.

`admin_ui.mode = "embedded"` (default) serves the baked SPA at
`routing.admin_ui.mount`. `mode = "external"` skips embedding;
the operator hosts the SPA elsewhere and the daemon allowlists
their origin via `cors.allowed_origins`.

`GET /admin/build-info.json` (unauth) returns
`{ version, indexSha256, fileCount, mode }` so operators can
pin which build is running. The boot path emits an
`AdminUiServed` audit envelope capturing the same `indexSha256`.

**WebAuthn `RP ID`.** Configured via `admin_ui.rp_id`. When
unset, derived from the routing mode at WebAuthn ceremony time:
path-mode → base host; subdomain-mode → base domain (so
credentials remain valid across subdomains). Migrating the
admin UX to a different base domain re-registers all passkeys;
documented in the operator runbook.

**Phase 5 deviation note**: an earlier draft of this section
called for a sibling `OpenVTC/vtc-admin-ui` repo with a signed
release tarball + `build.rs` fetch. The user chose the in-tree
path at Phase 5 D1 to keep `cargo build` self-contained. The
release-pipeline machinery may resurface later if a Vite/React
SPA outgrows the in-tree placeholder.

### 12.3 VRC graph

Self-issued only in MVP. Members mint VRCs in their wallet/PNM, then:

`POST /v1/relationships` — caller submits a VRC they signed. VTC
verifies signature against the issuer's known DID, runs
`relationships.rego` (default: store if both parties are current
members). Stored in the `relationships` keyspace.

`GET /v1/members/{did}/relationships` returns published VRCs where
the DID is issuer or subject (paginated).

**Departure handling.** When a member is removed:
- VRCs they *issued* are handled per their departure disposition
  (purged on `Purge`).
- VRCs naming them as *subject* — issued by remaining members — are
  also redacted from list endpoints when the departed member chose
  `Purge`. The VRC record itself remains in storage referenced by
  issuer; the public listing strips it.

Bilateral counter-signing is v2.

## 13. Storage

| Keyspace | Existing | Schema |
|---|---|---|
| `sessions` | ✓ | unchanged |
| `acl` | ✓ | extended: `VtcRole` enum + `extensions` |
| `community` | new | singleton key `profile` |
| `policies` | new | active + archived |
| `members` | new | `did → Member` |
| `join_requests` | new | with retention sweeper |
| `invitations` | new | |
| `relationships` | new | |
| `status_lists` | new | per-purpose state + reserved index set |
| `registry_records` | new | |
| `sync_queue` | new | `MembershipSyncer` jobs |
| `audit` | new | `AuditEnvelope` + secondary indices |
| `audit_key` | new | per-community HMAC key + rotation history |
| `idempotency` | new | `(session_id, key) → (request_hash, response, expires_at)` |
| `config` | new | DB-layer overrides |

Public website lives on filesystem at `website.root_dir`, not in
fjall (§3-K).

## 14. Operational

### 14.1 Backup / restore

`POST /v1/admin/backup/export` returns an encrypted dump (Argon2id +
AES-256-GCM). Password strength enforced via `zxcvbn` (minimum
score 3) — `≥12 chars` alone is too weak.

**Cross-VTC restore protection.** Each backup is wrapped under a key
derived from the VTC's master seed (`HKDF(seed, "vtc-backup-key")`),
not just the public DID. A spoofer who provisions a new VTC with the
same DNS cannot restore a stolen backup — they would need the
original master seed, which is OS-keyring-resident.

A fresh-install VTC accepts any backup once. A configured VTC refuses
backups whose `community_did` doesn't match. Same primitive as VTA's
`check_vta_did_compatibility`.

**Scrub on export.** `sessions` and `idempotency` keyspaces are
excluded from backups — they contain ephemeral state and may include
secret-bearing cached responses.

### 14.2 Runtime configuration

Three-layer overlay:
`env_vars > db_overrides > config.toml > defaults`.

`GET /v1/admin/config` returns the effective config with per-field
`source` annotation and `requires_restart: bool`. `PATCH` writes to
the `config` keyspace. `POST .../reload` re-applies hot-reloadable
settings; `POST .../restart` initiates graceful shutdown.

**Restart-endpoint supervisor handshake.** The restart endpoint
refuses to exit unless a supervisor is detected — either
`VTC_SUPERVISED=1` or the systemd notify socket (`NOTIFY_SOCKET`)
or k8s downward-API marker present. Without a supervisor, restart
would be a one-shot DoS.

**Sensitive-path PATCH guard.** Mutable config keys carry a
sensitivity flag. `server.tls.cert_path`, `server.tls.key_path`,
and `storage.path` are configured to **a directory allowlist**;
PATCH values outside the allowlist are rejected (refusing requests
to point TLS at `/etc/shadow` or to relocate storage transparently).

**Config import audit.** `POST /v1/admin/config/import` runs a
diff-and-confirm flow: the response surfaces every changed field
with a pre-apply preview; a second call with `confirm=true` applies.
Per-field audit events emitted on apply.

Full config taxonomy (which key reloads, which restarts, which is
UX-settable, sensitive-flag) lives in `docs/04-reference/vtc-config.md`,
not in this spec.

**Remote-dependency breakers.** VMC + VEC issuance is in-process
in Phase 2 (§3-A — cached-locally signer), so the per-call
timeout and circuit-breaker configuration apply to **non-VMC
remote dependencies only**: the trust-registry publish path in
Phase 3 (`MembershipSyncer`), the cross-community
`recognise` query (§8.4), and the did:webvh resolver walk in
M2.15.2's rotation slice. The configuration knobs retain their
names (`vta.signing_timeout_seconds`, default 5;
`vta.circuit_breaker_threshold`, default 5 consecutive failures)
for forward compatibility — they are the workspace's canonical
"remote-call discipline" handles. The breaker-open semantics
(join → `Deferred`, renewal → 503,
`/v1/health/diagnostics` surfaces remote health) apply to those
non-VMC paths once they land. Clarified per Phase 2 M2.16 +
Phase 3 M3.13.

**Trust-registry-specific settings (Phase 3 M3.2 + M3.7).** The
`registry` config block adds three knobs:

- `registry.url` — base URL of the upstream TRQP registry.
  When unset, the registry features no-op and
  `registry_status` reports `"degraded"`.
- `registry.health_probe_interval_seconds` — periodic probe
  cadence (default 60s; `0` disables).
- `registry.http_timeout_seconds` — per-call HTTP timeout
  (default 5s).
- `registry.rtbf_batch_window_hours` — RTBF coalescing
  window (default 24h; `0` disables — test convenience
  only).

### 14.3 Telemetry + diagnostics

Reuses `vti_common::telemetry::TelemetrySink`.
`/v1/health/diagnostics` (admin) surfaces the trust-registry
reconciler state. As-shipped Phase 3 M3.8 response shape:

```
{
  "registry_status": "active" | "degraded",
  "queue_depth": <integer>,              // Pending + InFlight
  "rtbf_batched_count": <integer>,       // Parked behind window
  "failed_count": <integer>,             // Terminal failures
  "oldest_pending_age_seconds": <int|null>,  // excludes RTBF-parked
  "last_success_at": "<rfc3339>" | null,
  "last_failure_at": "<rfc3339>" | null,
  "last_error": "<string>" | null
}
```

Aggregate-only — individual member DIDs are not surfaced; the
`rtbf_batched_count` field discloses how many RTBF jobs are
in flight but not which members. Phase 5 admin UX may add
the status-list occupancy + active-policy snapshots + ring
buffer named in earlier drafts.

`/health` (unauthenticated, Trust-Task-exempt §9.4) returns 200 when
the daemon is responsive and storage is reachable.

### 14.4 Runtime guards (workspace doctrine)

Inherited from the workspace's standard guards: tower-governor on
unauth routes (5 rps + 10 burst per IP); 1 MB global body cap;
audience-isolated JWTs; install tokens are single-use per row
(`Issued` → `Consumed`) and gated by an Argon2id-hashed
out-of-band claim secret (§4).

**Phase 5 note.** The §14.4 guards were aspirational until Phase 5
M5.1.4 + M5.1.5 wired the actual `DefaultBodyLimit` + tower-governor
layers. Phase 0-4 documented this section but did not land the
middleware. The PR-1a commit message records the prior-phase gap.

The unauth governor applies to 5 dedicated POST routes:
`/v1/auth/{challenge,authenticate,refresh}` +
`/v1/install/claim/{start,finish}`. `/v1/auth/admin-login`
(Phase 5 M5.2.3) joins this set since it's the bootstrapping
cookie-mint endpoint. Authenticated routes inherit the JWT auth
as their rate-limit gate.

`SmartIpKeyExtractor` reads `X-Forwarded-For` / `X-Real-IP` /
`Forwarded` headers first and falls back to peer IP via
`ConnectInfo<SocketAddr>` (wired in production via
`into_make_service_with_connect_info::<SocketAddr>()`). Test
fixtures using `Router::oneshot` get a synthetic `127.0.0.1`
inserted by an in-handler middleware so the extractor doesn't
500 on header-less requests.

**Body-cap exception.** Website upload routes
(`POST /v1/website/deploy`, `PUT /v1/website/files/{*path}`)
override the global body cap with a per-route 64 MiB allowance;
the route handler then enforces the operator-configured
`website.max_bundle_size_mb` (default 50) and
`max_file_size_mb` (default 10) at runtime. All other routes
inherit 1 MB.

## 15. CLI

`cnm-cli` gains `cnm community` subcommands grouped by area
(`setup`, `status`, `profile`, `policies`, `members`, `join`,
`invitations`, `website`, `registry`, `status-lists`, `audit`,
`backup`, `config`, `daemon`).

Commands are thin wrappers over `vta-sdk` REST/DIDComm clients —
workspace doctrine. Detailed verb list lives in
`docs/04-reference/cnm-vtc-cli.md`.

## 16. Phasing

| Phase | Deliverable | Gate |
|---|---|---|
| **0** | `vtc-host` template, install wizard, WebAuthn install flow, multi-passkey admin DID, community profile, config plumbing | DID + auth foundation. |
| **1** | Role enum + custom roles, ACL extension, member CRUD with manual approval, self/admin removal (no-last-admin), audit envelope + HMAC, idempotency, `/v1/` versioning, cursor pagination | Members can exist. |
| **2** | `regorus`, policy upload + activate, `join.rego` + `removal.rego`, **in-process VMC + VEC issuance** (cached-locally signer per §3-A), status-list with reserved-index discipline, renewal, DID rotation (`did:key` + `did:webvh`, domain-tagged) | Live policy + credentials. |
| **3** | Trust-registry publish, three departure dispositions, `registry.rego`, `MembershipSyncer` + diagnostic surfacing, RTBF override + batched timing, cross-community recognition (session-mint hardening) | Community on the wider network. |
| **4** | VRC self-issuance + `relationships.rego`, `personhood.rego` (deny-all stub) + assert/revoke + renewal re-eval, custom endorsement issuance (issuer role) | Graph + personhood live. |
| **5** | Public website (filesystem-backed, CSP, path safety), admin UX baked in-tree via `include_dir!` (per Phase 5 D1; the original "sibling repo + signed tarball" plan was renegotiated), path-prefix routing default + subdomain support | MVP complete. |

Phase 5 sub-tasks parallelise with phases 3–4. Phases 0–4 strictly
serial. Each phase's PR set includes the Draft Trust Task spec files
alongside the code that implements the operations (§9.4 soft gate).

## 17. Open questions

These have proposed answers in the design history but remain to
validate at implementation:

1. **Personhood policy reference implementation.** Stub ships
   deny-all; the workspace should publish at least one reference
   policy (`docs/04-reference/personhood-templates.md`) once Phase 4
   lands so communities don't reinvent from scratch.
2. **Status-list chaining strategy.** MVP alerts at 75% and refuses
   beyond capacity. Production communities will exceed 131K members
   eventually. Plan: chained-list pointer in the BitstringStatusList
   credential header.
3. **Trust Tasks source-of-truth location.** Currently
   `trust-tasks/` in this workspace. May factor out to a dedicated
   `OpenVTC/trust-tasks` repo when VTA-side tasks appear.
4. **Conformance test pattern for Published Trust Tasks.** Probably
   golden request/response pairs + schema validation. Land with the
   first Published task and standardise.
5. **Audit `audit_key` rotation cadence.** RTBF triggers rotation;
   spec is silent on routine rotation. Default policy TBD —
   probably annual + on every backup-export rekey.
6. **VRC issuance over DIDComm vs REST UX.** Both work; member
   wallets typically prefer DIDComm. No technical fork; UX call.

## 18. Explicitly NOT in MVP

- **TEE / Nitro Enclave deployment of the VTC binary** — permanent
  non-goal (§3-K). Trust anchor for TEE remains the VTA.
- **Multi-tenant** (one binary hosts multiple communities).
- **Multi-process daemons sharing fjall storage.** Operator
  isolation via cargo features + reverse proxy is the MVP path.
- **N-of-M admin approvals.** Retrofit is bounded (insert a
  `proposal` phase before ~8 endpoints).
- **Webhooks / external event subscribers.** Stable audit event
  vocabulary (§11.4) makes this a delivery layer on top.
- **Bulk operations** (mass-invite, mass-remove, mass-export).
- **WASM / plugin extensions.** Communities extend via Rego +
  JSON blobs only.
- **i18n at the resource layer** (translated profile fields, role
  names). Additive migration via `name_translations` field with
  fallback.
- **VPC (Persona credentials)** beyond type-reservation.
- **Bilateral VRC counter-signing.** Self-issued only in MVP.
- **VTC-to-VTC community migration tooling.** Config export +
  backup are the primitives; packaged scripts are a follow-up.
- **Onboarding state machine** for new members. Encode in policy +
  admin UX initially.
- **Filesystem / S3 backends for fjall keyspaces** beyond the
  public website root.

## 19. Related work

- [`trusttasks.org`](https://trusttasks.org) — canonical Trust Task
  registry (§9.4).
- `docs/05-design-notes/runtime-service-management.md` — service-
  advertisement primitives the VTC inherits via `vta-sdk`.
- `docs/02-vta/provision-integration.md` — how the VTC's own
  DID is minted from its VTA.
- `docs/05-design-notes/pnm-setup-deferred-vta-did.md` — deferred-
  DID pattern, useful reference for the VTC install flow.
- [`openvtc/dtg-credentials`](https://github.com/OpenVTC/dtg-credentials)
  — the credential catalog (§6).
- [`affinidi/affinidi-trust-registry-rs`](https://github.com/affinidi/affinidi-trust-registry-rs)
  — TRQP v2.0 server + client (§8).
- [`affinidi/affinidi-tdk-rs`](https://github.com/affinidi/affinidi-tdk-rs)
  — `affinidi-status-list`, `affinidi-vc`, `affinidi-data-integrity`.
