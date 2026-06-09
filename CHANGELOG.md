# Changelog

## Unreleased

### Removed: legacy `affinidi.com/atm/1.0` auth aliases (legacy strip)

The VTA's DIDComm auth path no longer accepts the legacy
`affinidi.com/atm/1.0/authenticate` and `…/authenticate/refresh` message
types — only the canonical `auth/authenticate/0.1` / `auth/refresh/0.1`
Trust-Task URIs. In the same change the **vta-sdk** DIDComm auth path
(`session.rs`, `auth_light.rs`) now *emits* the canonical types, so SDK
clients move to canonical automatically.

- **Deployment note (breaking):** a client still on the pre-canonical SDK
  (emitting `atm/1.0`) fails auth against an upgraded VTA with
  `unexpected message type`. Roll clients onto this SDK with/before the VTA.
- **Follow-up:** `vtc-service` still dual-accepts `atm/1.0` (incl. its SIOP
  envelope path); the SDK switch doesn't break it. Its `atm/1.0` removal is a
  separate change (its SIOP path may have other clients).

### Removed: pre-spec `vta/passkey-vms/*/1.0` URIs (legacy strip)

The pre-spec `…/1.0` passkey-vms task URIs — kept dual-accepted alongside the
canonical `…/0.1` during the browser plugin's migration — are removed. The
plugin has been on `…/0.1` since vta-sdk 0.10, so the alias is no longer
needed. A `…/1.0` document now falls through to `UnsupportedType`.

- **vta-sdk**: dropped `TASK_PASSKEY_VMS_{ENROLL_CHALLENGE,ENROLL_SUBMIT,LIST,REVOKE}_1_0`
  constants and their `ALL_URIS` entries. **Breaking** — bump at next release.
- **vta-service**: the dispatcher matches only the `…/0.1` arms; the parity
  harness now asserts the 0.1 URIs are dispatched.

### Built-in DID templates renamed `did-hosting-*` → `did-host-*` (capability-named)

The three did-hosting built-in templates are renamed from service-named to
capability-named, so the name describes the DID-document shape the template
mints rather than a particular binary. The suffix names the endpoints the
DID advertises: `http` = a `WebVHHosting` (HTTP resolution) endpoint,
`didcomm` = a `DIDCommMessaging` endpoint.

- **Renames**: `did-hosting-control` → `did-host-http-didcomm`,
  `did-hosting-daemon` → `did-host-http`, `did-hosting-server` →
  `did-host-didcomm`. The on-disk JSON files, the embedded loader, the
  `BUILTIN_DID_HOST_*_TEMPLATE` constants, and the `ProvisionAsk::did_host_*`
  builders all carry the new names.
- **Back-compat**: both prior generations resolve for one release.
  `load_embedded` silently maps `webvh-*` **and** `did-hosting-*` to the
  `did-host-*` templates; the returned `DidTemplate.name` carries the
  canonical name. The `BUILTIN_DID_HOSTING_*_TEMPLATE` constants and
  `ProvisionAsk::did_hosting_*` builders remain as `#[deprecated]` shims
  (the `webvh_*` shims now delegate to the new names too). Update configs
  to the `did-host-*` names before the aliases are dropped.
- **Method lock unchanged**: these templates stay `did:webvh`-specific (the
  `WebVHHosting` service type and `methods` field are baked into the
  template body, not caller-set) — the rename is naming only.
- `vta-sdk` 0.9.5 → 0.9.6 (additive: new canonical names, old names
  deprecated but functional).

### DIDComm session: receive unsolicited inbound messages

`vta-sdk`'s `DIDCommSession` gains `receive_next(timeout_secs)` — polls the
mediator's live stream and returns the next **unsolicited** inbound message
(unpacked, as JSON), not bound to a sent request's thread id. This is the
foundation for the mobile approver receiving a VTA-pushed
`auth/step-up/approve-request/0.1` over the mediator (the engine FFI for the
iOS proxied step-up wraps it). Reuses the proven `message_pickup().live_stream_next`
path. `vta-sdk` 0.9.4 → 0.9.5 (additive).

### Set a delegated step-up approver at grant *and update* time

The ACL create/grant and update bodies gain an optional `step_up_approver`
— the VID a delegated AAL2 step-up's approve-request is addressed to (the
holder's mobile/browser approver). It's stored on the entry and read by the
step-up gate's delegated mode. Makes delegated step-up operable end-to-end:
previously the gate could route to an approver but there was no way to set
one outside tests. `update` follows the existing set-if-`Some`/leave-if-
`None` semantics (clearing isn't expressible, matching `label`).

- `vta-sdk` `CreateAclBody` + `CreateAclResultBody` gain
  `step_up_approver: Option<String>` (additive, `serde(default)`); the REST
  `POST /acl` request + the `vta/acl/create/1.0` trust task accept it and
  the result reflects it. `UpdateAclBody` + the REST `PATCH /acl/{did}` +
  the `vta/acl/update/1.0` trust task likewise accept it. `vta-sdk`
  0.9.2 → 0.9.4.
- Still pending (optional): the wire `auth/step-up/policy/0.1` handler for
  *remote* policy management — the `vta step-up` CLI already covers local
  management.

### Key rotation goes through `acl/swap-key`

The SDK's first-auth key rotation (`session::rotate_key`, REST path) now
uses the atomic `POST /acl/swap` (`acl/swap-key`) instead of the
create-then-delete sequence on `POST /acl`. The VTA moves the temp DID's
ACL entry (same role + contexts) onto the freshly-minted DID and removes
the temp in one transaction — no transient over-privilege window, and the
rotation travels the structurally non-escalating swap-key path, so an
*enabled* step-up policy carrying the rotation carve-out still admits it
at AAL1.

- `vta-sdk` gains `protocols::acl_management::swap::build_swap_presentation`
  (client feature) — builds the Ed25519 VP-JWT the swap verifier accepts;
  round-trip-tested against `AclSwapPresentation::verify`.
- `vta-sdk` 0.9.1 → 0.9.2 (additive public API). The DIDComm rotation path
  still uses create-then-delete; migrating it onto swap-key is a follow-up.

### Fix: server-managed provisioning drops the DID path (`e.p.did.path-invalid`)

When a consumer (e.g. the did-hosting-daemon) provisions an integration
against a VTA that has **exactly one** registered webvh server, the SDK
auto-selects that server and runs the server-managed path. In that mode
the hosting server reads `WEBVH_PATH` and ignores the path folded into
the `URL` template var — but `run_provision` passed `webvh_path = None`,
so `WEBVH_PATH` was never injected and the hosting server received an
empty path, rejecting with `e.p.did.path-invalid: path must not be
empty` (HTTP 500 at the gateway).

Fixed at two layers (defense-in-depth):

- **SDK (vta-sdk, the fix):** `run_provision`'s `PreflightDone` handler
  now derives the path from the ask's `URL` var (via the new
  `runner::webvh_path_from_url`) when it auto-selects a server, and
  passes it as `webvh_path` to `run_provision_flight`. The var-injection
  is factored into `runner_didcomm::inject_webvh_vars` and unit-tested.
  Serverless mode (no server selected) is unchanged — it reads the path
  straight from `URL`.
- **VTA service (vta-service, safety net):** `provision_integration`
  falls back to the path parsed from the `URL` var
  (`webvh::webvh_path_from_url_var`) when a `WEBVH_SERVER` is set but no
  explicit `WEBVH_PATH` was provided. Read-only; never overrides an
  explicit `WEBVH_PATH`.

Derivation is conservative on both sides: bare origins, empty paths and
`.well-known` (the webvh log marker, never a DID path) yield no path,
letting the server run its own allocation; `…/webvh` → `webvh`,
`…/dids/daemon` → `dids/daemon`, query/fragment stripped.

### Dependencies: DIDComm 0.15 across the affinidi-messaging stack

Moved the whole workspace to `affinidi-messaging-didcomm 0.15`, now that
the affinidi side published the releases that close the previous split:

- `affinidi-tdk` 0.7.2 → **0.7.3** (`didcomm ^0.15`) — the production
  unblock. tdk re-exports didcomm and our `DIDCommSession` passes
  `Message` values into its transport, so tdk and our direct didcomm dep
  must share one version. While tdk capped at `^0.14`, 0.15 was
  unreachable (two incompatible `Message` types).
- `affinidi-messaging-mediator` 0.15.11 → **0.15.12** (`^0.15`) +
  `affinidi-messaging-test-mediator` 0.2.3 → **0.2.4** (the embedded test
  fixture).
- `affinidi-messaging-sdk` 0.18.4 → **0.18.6** and
  `affinidi-messaging-didcomm-service` 0.3.2 → **0.3.3** (both already on
  `^0.15`, now selected).
- `affinidi-crypto` 0.1.10, `affinidi-status-list` 0.1.3 (latest).

Code migration for the 0.15 API:

- didcomm 0.15 removed its own `crypto` module; `Curve` /
  `PrivateKeyAgreement` / `PublicKeyAgreement` now live in
  `affinidi_crypto::jose::key_agreement`. Updated the imports in
  `vta-sdk` (`didcomm_light`) and `vta-mobile-core` (`didcomm`), and added
  `affinidi-crypto` to vta-sdk's `client` feature (it now names that type
  in its own right). `anoncrypt`'s shape is otherwise unchanged; the
  `pack_anoncrypt` JWE round-trip test still passes.
- `affinidi-messaging-sdk` 0.18.5 added
  `WebSocketResponses::Disconnected`; handled it in `didcomm-test`'s
  listen loop (logs and stops — the socket is gone).

Resolution note: the dev-only test tree still pulls a second
`didcomm 0.14.1` transitively through the **published** `vta-sdk 0.9.0`
that `affinidi-messaging-mediator` depends on. The mediator pins
`vta-sdk = "^0.9"`, so this self-heals the moment `vta-sdk 0.9.1` (this
release, on didcomm 0.15) is published — the resolver then selects it for
the mediator too and the duplicate disappears. `cargo deny` treats the
transient duplicate as a warning, consistent with the other accepted
build-graph duplicates.

### Version bumps

This cycle's bumps for the provision-path fix + the didcomm 0.15 move
(the publish boundary already advanced to `vta-sdk` 0.9.0 /
`vta-service` 0.8.0 in the #183 release bump):

- `vta-sdk` 0.9.0 → 0.9.1 — provision bugfix (crate-internal helpers, no
  API change) **plus** the `affinidi-messaging-didcomm` 0.14 → 0.15 dep
  bump. Kept in the `0.9.x` line on purpose: `affinidi-messaging-mediator`
  0.15.12 pins `vta-sdk = "^0.9"` *and* `didcomm = "^0.15"` at the same
  time, so the affinidi side explicitly expects a `0.9.x` of vta-sdk that
  carries didcomm 0.15. A `0.10.0` bump would fall outside their `^0.9`
  pin and lock them on the old didcomm-0.14 `vta-sdk 0.9.0` — defeating
  the unification. (Strict semver would call a public-dep major bump
  breaking; here it's deliberate ecosystem coordination, not an
  accident.) External consumers pinned at `"0.9"` pick it up with no pin
  change.
- `vta-service` 0.8.0 → 0.8.1 — patch: carries the Option B safety net +
  the didcomm 0.15 pin; bumped so it can be republished. `vta-enclave`'s
  `"0.8"` pin is unaffected.

Historical (0.7 → 0.8 cycle, retained for context):

Only the two crates external repos (did-hosting-common,
webvh-witness, rp-sdk, …) consume are bumped:

- `vta-sdk` 0.7.0 → 0.8.0
- `vti-common` 0.7.0 → 0.8.0

Minor bump (not patch) is required by the additive public API + the
const-value change on `BUILTIN_WEBVH_*_TEMPLATE` (now resolves to
`"did-hosting-control"` etc.) + the manual `Debug` redaction on
secret-bearing wire types + the REST `import_key` hardening. Each
of those is detailed in its own section below. Consumer repos pull
the changes by updating their pin from `"0.7"` to `"0.8"`.

The other workspace crates (`vta-service`, `vta-enclave`,
`vta-cli-common`, `pnm-cli`, `cnm-cli`, `vtc-service`,
`didcomm-test`) stay at their current versions — they're
binaries / CLI tools, not libraries consumed externally, so their
Cargo.toml version is cosmetic for the install-the-binary use case.
Their internal `vta-sdk` / `vti-common` dep pinnings are updated
`"0.7"` → `"0.8"` to point at the bumped crates.

### Built-in DID templates renamed `webvh-*` → `did-hosting-*`

Aligns the SDK's built-in template names with the broader OpenVTC
service-role terminology already in `auth-architecture.md` and
`trust-task-uri-registry.md`.

- **Renames**: `webvh-control` → `did-hosting-control`,
  `webvh-daemon` → `did-hosting-daemon`,
  `webvh-server` → `did-hosting-server`. The on-disk JSON files,
  `name` + `kind` fields, builtin-loader constants, and curated
  `ProvisionAsk` builders (`did_hosting_control` / `did_hosting_daemon`
  / `did_hosting_server`) all flip to the new names.
- **Back-compat alias for one release.**
  `load_embedded("webvh-control")` still resolves to
  `did-hosting-control` (same for daemon and server); the returned
  `DidTemplate.name` carries the canonical name. The
  `BUILTIN_WEBVH_*_TEMPLATE` constants and `ProvisionAsk::webvh_*`
  builders are marked `#[deprecated(since = "0.8.0")]` and forward
  to the new names. Operator configs should switch to
  `did-hosting-*` before the alias is dropped in the next minor.
- **Doc cross-refs.** Tracker mentions of `webvh-witness` (a service
  role in the webvh-service repo) follow the same rename to
  `did-hosting-witness`. Protocol URIs and module names that refer
  to the `did:webvh` DID-method itself are unchanged.

### CLI restructure: `pnm webvh` / `vta webvh` → `did-mgmt {servers,dids}`

The operator CLI surface restructured to match the SDK umbrella
module `vta_sdk::protocols::did_management`. Two intermediate verbs
split the noun:

- `pnm webvh add-server` → `pnm did-mgmt servers add`
- `pnm webvh list-servers` → `pnm did-mgmt servers list`
- `pnm webvh update-server <id>` → `pnm did-mgmt servers update <id>`
- `pnm webvh remove-server <id>` → `pnm did-mgmt servers remove <id>`
- `pnm webvh create-did` → `pnm did-mgmt dids create`
- `pnm webvh edit-did` → `pnm did-mgmt dids edit`
- `pnm webvh register-did` → `pnm did-mgmt dids register`
- `pnm webvh list-dids` → `pnm did-mgmt dids list`
- `pnm webvh get-did` → `pnm did-mgmt dids get`
- `pnm webvh delete-did` → `pnm did-mgmt dids delete`
- `pnm webvh did-log` → `pnm did-mgmt dids get-log`

Same rename applies to the offline `vta` binary (no `get-did`
variant). The `webvh` cargo feature is **not** renamed — it gates
`didwebvh-rs`, which refers to the DID *method*, not the operator
UX.

**Back-compat alias for one release.** The old `pnm webvh …` /
`vta webvh …` paths still dispatch through the same handlers
(`Webvh` variant is `#[command(hide = true)]` — absent from `--help`
but invocable). Each call prints a yellow stderr deprecation note
pointing at the new path; alias removed in the next minor.

Operator-facing docs (`docs/02-vta/{cold-start,
runtime-service-management,provision-integration,did-templates,
did-webvh-update}.md`, `docs/03-vtc/getting-started.md`,
`docs/04-reference/cli-style.md`, `CLAUDE.md`) updated to the new
command shapes. Prose mentions of "WebVH server" are now
"DID-hosting server" where they refer to the hosting role;
references to `did:webvh` the DID method itself are intentionally
unchanged.

Rationale: `did-management` is the right umbrella because half the
surface isn't hosting at all (DID lifecycle: create/edit/delete/
get/get-log/register) and the SDK module of the same name already
groups both halves. `did-hosting` is reserved by
`trust-task-uri-registry.md` for the host-side trust-task namespace
(`spec/did-hosting/*`), a distinct concern.

### Adopt `did-management/0.1` Trust-Task surface + per-DID domain selection

Pairs with [`affinidi/affinidi-webvh-service` PR #15](https://github.com/affinidi/affinidi-webvh-service/pull/15)
and the draft spec category in
[`trustoverip/dtgwg-trust-tasks-tf` PR #40](https://github.com/trustoverip/dtgwg-trust-tasks-tf/pull/40).
The VTA's webvh client now speaks the v0.1 `did-management/...`
surface and lets operators direct DID provisioning at a specific
hosting domain when the remote backplane serves multiple tenants.

#### Outbound Trust-Task URIs migrated to v0.1

- **`vta-service/src/webvh_didcomm.rs`** stops emitting the legacy
  `https://affinidi.com/webvh/1.0/did/...` constants. Every outbound
  DIDComm message now carries a v0.1 `did-management/...` type URI:
  `did/check-name/0.1` (with `reserve: true`) replaces
  `did/request/1.0` for slot reservations; `did/register/0.1`,
  `did/publish/0.1`, and `did/delete/0.1` replace their 1.0
  siblings. Response sides use the framework's `#response`
  fragment rather than a paired URI.
- **`vta-service/src/webvh_client.rs`** (REST) sends the same v0.1
  payload shape on `POST /api/dids` and `POST /api/dids/register`:
  `method` discriminator + `didData` field (replacing the legacy
  `did_log`). The remote `did-hosting-control` accepts both
  shapes through its alias map during the v0.7 deprecation window,
  but moving outbound traffic to the canonical surface keeps the
  VTA off the runtime deprecation warn lines those hosts now
  emit (`legacy_task=... successor=... sunset=v0.8.0`).
- **`POST /api/dids/check`** payload gains a `reserve: bool` flag.
  When set + path available, the host atomically commits a
  reservation under the caller and returns `{ available, reserved,
  mnemonic, didUrl }` in one round-trip — absorbs the legacy
  request_uri call for the common "check, then claim" flow.

#### Per-DID domain selection threaded through the stack

A VTA managing slots across multiple tenant domains on one shared
`did-hosting-control` backplane can now name the target domain on
every relevant call. Every layer carries the field optionally;
omitted means "let the server resolve via the caller's ACL
default → its system default."

- **Data model**:
  `CreateDidWebvhBody` / `CreateDidWebvhRequest` /
  `CreateDidWebvhParams` gain `domain: Option<String>`.
  `RegisterDidWithServerBody` / `RegisterDidWithServerParams` ditto.
  All five wire shapes serialise with `skip_serializing_if =
  "Option::is_none"` so v0.7 callers and hosts that don't yet
  understand the field are unaffected.
- **Outbound calls**:
  `WebvhClient::{request_uri, register_did_atomic, publish_did,
  delete_did, check_path}` and the parallel `WebvhDIDCommClient`
  all take `Option<&str>` domain. The transport enum and the
  `_authenticated` wrappers thread it through.
- **End-to-end**: explicit `--domain` (CLI) → `CreateDidWebvhRequest`
  body → vta-service handler → `WebvhTransport` → DIDComm/REST
  payload → did-hosting-control resolves it. An unknown domain on
  the remote comes back as the spec-level error
  `did-management:unknown_domain` (per the category conventions in
  the trust-tasks PR), which the CLI surfaces unchanged so
  operators can correlate.

#### Operator CLI gains domain UX

- **`pnm did-mgmt dids create --domain <name>`** and
  **`pnm did-mgmt dids register --domain <name>`** are new optional
  flags. When omitted the server resolves through the standard
  chain.
- **Interactive prompt** when stdin is a TTY, the operator targeted
  a specific hosting server, and `--domain` was omitted: the CLI
  fetches the server's available domains (caller-scoped view) and
  asks the operator to pick — single-domain servers, non-TTY
  invocations (CI / scripts), and servers that fail the
  domain-list call all skip the prompt and let the server resolve.
- **`pnm did-mgmt dids list-domains --server <id>`** is a new
  top-level subcommand. Walks the server's `/api/me/domains`
  (proxied through the VTA, authenticated with the VTA's
  credentials) and prints the caller-scoped subset, flagging the
  system default. Use this to discover legitimate `--domain`
  values before the first call.

#### Supporting plumbing

- New SDK protocol message id
  `https://firstperson.network/protocols/did-management/1.0/list-webvh-server-domains`
  + result variant. `VtaClient::list_webvh_server_domains()`
  exposes it.
- New `vta-service` REST route `GET /webvh/servers/:id/domains`
  authenticates the VTA to the named hosting server through the
  existing `WebvhTransport` / `auth_cache` machinery and forwards
  the response. DIDComm-only servers return an empty list (the
  v0.1 `me/domains` task is REST-only on the hosting-control
  side); the CLI then falls back to the server-side resolution
  chain rather than blocking the operator.
- All call sites updated: `operations/did_webvh/mod.rs`,
  `update/orchestrator.rs`, `provision_integration/mod.rs`,
  `setup/{from_toml,interactive}.rs`, `webvh_cli.rs`,
  `messaging/handlers.rs`, `routes/{did_webvh,trust_tasks/webvh}.rs`,
  and the SDK tests under `vta-sdk/tests/client_rest.rs`.

Out of scope for this change — to land separately:

- The DID-method extension shape
  (`ext.vnd.trusttasks.did-method-webvh.*` carrying SCID, witness
  URLs, update-key multibase) is sketched in the trust-tasks PR
  but the VTA's outbound payloads don't emit it yet. The
  framework's ignore-unknown rule keeps current hosts accepting
  our absence and our consumers accepting hosts that include
  theirs.

### Security review follow-ups (external patches 02, 03, 04, 05, 07, 08, 09, 10)

Eight findings from the April 2026 external security review.
Patches 01 + 06 (DIDComm sender-DID binding on `/auth/refresh`) were
already closed by the prior auth-handler consolidation. Each fix
below ships with a focused regression test. Tracker file at
`~/Downloads/patches/verifiable-trust-infrastructure/REVIEW_2026-04_TRACKER.md`
maps each patch to the commit that addressed it.

- **#4 (Critical) — BIP-32 `allocate_path` race.**
  `vta-service/src/keys/paths.rs`: the read-increment-write of the
  per-base path counter was a TOCTOU race. Two concurrent
  `allocate_path` calls could be handed identical derivation paths,
  producing two `KeyRecord`s that share a private key. Serialised
  with a process-wide `tokio::sync::Mutex`. Regression test launches
  64 concurrent allocations against one base and asserts all paths
  are distinct.
- **#10 (High) — `delete_did_webvh` cross-context.**
  `vta-service/src/operations/did_webvh/mod.rs`: only checked
  `require_admin`, never `require_context(record.context_id)`, so a
  context-scoped admin could trigger remote deletion (via the stored
  mnemonic) and local key cleanup of did:webvh records owned by
  other contexts on the same VTA. Now mirrors the scoping that
  create / get / get_log / list already enforce.
- **#7 (High) — `AuthConfig` / `SecretsConfig` Debug leak.**
  `vti-common/src/config.rs`: replace `#[derive(Debug)]` with manual
  impls that print `<redacted>` for `jwt_signing_key` (Ed25519
  access-token signer) and `inline_secret` (master seed / HMAC).
  Serialize is intact — config files still round-trip. Enclave-mode
  logs forward over vsock to the host, where a stray `{:?}` would
  otherwise be a near-total compromise.
- **#8 (High) — vta-sdk protocol message Debug leaks.**
  Manual `Debug` impls across `vta-sdk/src/protocols/{auth,
  backup_management/types, did_management/create, key_management/
  {create,secret}, seed_management/rotate}.rs`. Mnemonics, seeds,
  private keys, access / refresh tokens, backup passwords no longer
  appear in `{:?}` output. Wire formats and sealed-transfer payloads
  unchanged. Note the original audit named `AuthenticateData` — that
  type was replaced by `TokenBundle` during the auth consolidation;
  the fix applies to the current shape.
- **#9 (High) — REST `POST /keys/import` no longer accepts plaintext
  `private_key_multibase`.** Posting raw key material over a
  session-bearer-authenticated REST call relies entirely on TLS for
  confidentiality — on Nitro Enclave the TLS terminator is on the
  host, which means the host network stack reads plaintext private
  keys out of memory. The handler now uses
  `#[serde(deny_unknown_fields)]` so any client posting the legacy
  field gets a specific `unknown field private_key_multibase` 422
  pointing them at the migration path. Use one of:
  - `private_key_sealed` — armored sealed-transfer bundle. Fetch
    the ephemeral wrapping pubkey via
    `GET /keys/import/wrapping-key`, then seal locally and POST.
  - `private_key_jwe` — legacy ECDH-ES + A256GCM compact JWE,
    wrapped against the same ephemeral key.

  The DIDComm transport (no server-side handler yet) keeps the
  multibase field on its SDK shape because authcrypt already
  provides end-to-end confidentiality. **Operator-facing side
  effect**: the `pnm/cnm import-key` CLI's fall-back-to-multibase
  branch (active when the wrapping-key fetch failed) is removed —
  the CLI now surfaces the wrapping-key-fetch error directly with a
  clear message ("the VTA must support sealed-transfer key import —
  `vta-sdk ≥ 0.8`"). The mediator-setup and did-hosting-setup flows
  are **not** affected: they use `provision-integration` (the VTA
  mints keys via BIP-32 from the master seed and returns a sealed
  bundle to the consumer), never `POST /keys/import`.
- **#3 (Medium) — `delete_acl` role floor.**
  `vta-service/src/operations/acl.rs`: an Initiator whose
  `allowed_contexts` overlapped an Admin entry could delete that
  Admin. `update_acl` was already protected by an admin-only floor;
  the delete path now also calls `validate_role_assignment(auth,
  &entry.role)` after the visibility check.
- **#5 (Medium) — `get_key` / `list_keys` Reader-role floor.**
  `vta-service/src/operations/keys.rs`: `Monitor`-role principals
  (intended for metrics/health only) could read key records when
  context scope happened to overlap. Both operations now call
  `auth.require_read()` at the top so the floor fires before any
  per-record filter and covers REST + DIDComm equally.
- **#2 (Medium DoS) — backup nonce/salt length validation.**
  `vta-service/src/operations/backup/mod.rs`: `Nonce::from_slice`
  panics on wrong-length input, so a crafted backup envelope with a
  non-12-byte nonce (or non-32-byte salt) would take the import
  handler down. The KDF-parameter bounds half of the patch was
  already in; the length checks complete the fix.

### Auth-architecture consolidation (S1+S2+S3)

A cross-repo consolidation of the `/auth/*` surface. Five
near-duplicate implementations (VTA REST + DIDComm, VTC REST +
DIDComm, did-hosting control SIOPv2, did-hosting server
DIDComm, webvh-witness DIDComm) collapse into thin route
dispatchers around a canonical handler in `vti_common::auth::
handlers`. Closes the structural follow-ups from the May 2026
cross-system security review.

#### Added

- **Canonical `Session` superset** — `vti_common::auth::Session`
  is now the single source of truth for the wallet/holder
  session row across both repos. Adds `token_id` (per-token
  rotation pin) and `session_pubkey_b58btc` (ephemeral
  Ed25519 multikey for Data-Integrity-proof binding) on top
  of the existing `tee_attested` + `amr` + `acr`. did-hosting's
  `Session` is deleted; the type re-exports from vti-common via
  a cross-repo dep.
- **`vti_common::auth::backend::AuthBackend` trait + canonical
  `/auth/*` handlers**. Five services (VTA, VTC,
  did-hosting-control, did-hosting-server, webvh-witness) now
  share challenge / authenticate / refresh flow logic. The
  trait abstracts over associated `Store`, `Error`, `Role`
  types so each backend keeps its own storage layer + AppError;
  default-method policy hooks (`validate_did`,
  `attest_challenge`, `max_pending_challenges_per_did`,
  `audit`, `didcomm_freshness_window`) carry safe defaults.
  The canonical handlers enforce the load-bearing invariants
  — signer-DID-binds-to-session-DID, constant-time challenge
  compare, atomic refresh-token claim, AAL preservation across
  rotation, ACL re-look-up at every step — once, not five
  times. ~500 lines of duplicated flow logic removed across
  the callers.
- **`KeyspaceHandle::take_raw`** — atomic GET+DELETE on the
  Local (fjall) variant via a single `blocking_with_timeout`
  closure. Vsock backend falls back to `get_raw` + `remove`
  with a per-call `warn!()` and a doc note flagging the
  cross-replica TOCTOU window; single-replica TEE deployments
  are unaffected. Backs the canonical
  `take_session_id_by_refresh` helper.
- **`SessionStore` adapters** — `KeyspaceSessionStore` (vti-
  common's KeyspaceHandle) and `DidHostingSessionStore`
  (did-hosting's). VTA + VTC use the first directly; did-hosting
  implements its own to honour its separate storage + error
  primitives.
- **`@openvtc/rp-sdk` (`rp-sdk-js`, new repo)** — server-side
  TypeScript SDK for Relying Parties consuming SIOPv2
  `id_token`s from the OpenVTC browser plugin. `verifyIdToken`
  enforces the OIDC Core §3.1.3.7 + SIOPv2 §6 checks (alg
  pinning, self-issued constraint, audience + nonce match, iat
  / exp window, DID-resolved JWS verification). Closes the
  gap where the browser-plugin demo accepted POSTs without
  verifying the signature.

#### H/M/L security review follow-ups

Numbering matches the May 2026 cross-system auth review (`H`igh
/ `M`edium / `L`ow).

- **L1** — JWT `iat` claim. Standard OIDC/RFC 7519 §4.1.6.
  `#[serde(default)]` so legacy tokens deserialise as `iat=0`.
- **L4** — `/auth/` + `/auth/refresh` handlers accept both the
  legacy `affinidi.com/atm/1.0/...` / `affinidi.com/webvh/1.0/...`
  URIs and the canonical
  `trusttasks.org/spec/auth/{authenticate,refresh}/0.1`. Drop
  the legacy alias one minor release after every client
  upgrades.
- **L2** — `server.trust_xff: bool` config flag (default `false`)
  on both VTA and VTC. Selects `PeerIpKeyExtractor` (safe for
  direct-binding deployments; not bypassable by header spoofing)
  vs. `SmartIpKeyExtractor` (honours `X-Forwarded-For` /
  `Forwarded`; only safe behind a trust-boundary reverse proxy
  that overwrites these headers). Closes a silent rate-limit
  bypass.
- **M3** — DIDComm `created_time` freshness window. VTA + VTC
  authenticate handlers now thread `msg.created_time` into the
  canonical handler instead of `None`; 60s default window
  against `session.created_at` bounds replay risk.
- **M1** — `vti_common::auth::StepUpAuth` extractor. Axum
  extractor that requires the JWT's `acr == "aal2"`; rejection
  returns 403 with body
  `{ "error": "step_up_required", "requiredAcr": "aal2" }` —
  a distinct signal the wallet uses to trigger a step-up
  ceremony. Mirrors did-hosting-common's existing impl.
- **M2** — `AuthBackend::access_token_ttl_for_aal2()`. Default
  1/3 of base TTL with a 60s floor; canonical handlers pick
  TTL by `acr`. A leaked aal2 token now has a ~5-minute
  window (default) instead of 15.
- **M6** — `AclEntry.version: u32` + `update_acl_entry_versioned`
  helper. Optimistic-concurrency-checked write that refuses to
  overwrite if the stored row has moved ahead; raises
  `AppError::Conflict` on stale write. Closes "two admins
  silently lose one update" on concurrent ACL edits.
- **H2** — RP-side `id_token` verification — see `@openvtc/rp-sdk`
  under Added.
- **H3 + H4 + H5** — closed as side-effects of the canonical-
  handler migration:
  - per-DID challenge rate limit now uniform across all five
    services (was missing on VTA/VTC, O(N) prefix-scan on
    did-hosting-server/witness, O(1) tracker on
    did-hosting-control);
  - `allowed_did_methods` rejection error collapsed to a
    generic `Forbidden` so the operator-configured allowlist
    isn't echoed to callers.
- **M4** — `chrome.runtime.onMessage` sender check in the
  browser plugin's background + offscreen listeners. Rejects
  messages whose `sender.id !== chrome.runtime.id`. MV3
  isolation enforces this at the manifest layer already;
  belt-to-the-braces defence-in-depth.
- **M5** — origin → RP-DID pinning in the browser plugin. New
  `origin-pin.ts` module persists `chrome.storage.local`
  mappings; the consent prompt renders a loud red warning
  ("⚠ Relying-party identity changed") when a site asks for
  a different `rpDid` than the previously-approved one. Both
  SIOP and DIDComm login flows wired.
- **H1 (foundation)** — pluggable `SecretWrap` trait in
  `@pnm/core` + a working `WebAuthnPrfSecretWrap` impl in the
  extension. The wallet's Ed25519 root secret can be persisted
  through an encryption wrap (WebAuthn PRF → HKDF →
  non-extractable AES-256-GCM key) rather than plaintext
  base64url in IndexedDB. **Not yet auto-enabled**; the
  operator-visible UX (settings toggle, first-enroll
  ceremony, lock/unlock, migration of existing plaintext
  wallets) is the second half.

#### Behaviour / wire changes worth flagging

- **VTC `/auth/refresh` response shape** is now the canonical
  `{ session, tokens }` body (was the legacy `{ sessionId,
  data: { accessToken, accessExpiresAt } }`). Matches VTA and
  the cross-cutting `spec/auth/refresh/0.1` schema; no
  in-tree callers consumed the legacy shape. External clients
  of VTC's `/auth/refresh` need to migrate.
- The 2^-256 nonce-collision check on VTA's `/auth/challenge`
  is dropped during the canonical-handler migration — defence
  in depth that wasn't anchored by anything else, and the
  canonical handler doesn't carry it for the four other
  backends. Random 32 bytes is sufficient.

#### Deferred

- **H1 (operator-visible flow)** — settings toggle, first-
  enroll UX, migration UX for existing plaintext wallets,
  lock/unlock UX from the popup. The encryption infrastructure
  is in (`SecretWrap` trait + `WebAuthnPrfSecretWrap` impl);
  not yet auto-enabled in `holder.ts` so existing users aren't
  locked out.
- **L5** — workspace lint for trust-task `recipient`
  enforcement. Tooling-heavy; needs design.

### Added

- **Runtime service management** — operators can now enable, update,
  disable, or roll back the VTA's advertised REST and DIDComm
  service entries on a running VTA without rebuilding. Twelve
  commands across two transport kinds (`pnm services {rest,didcomm}
  {enable,update,disable,rollback}` plus `pnm services list`,
  `pnm services didcomm drain {list,cancel}`, `pnm services
  report`). Each mutation publishes a new WebVH LogEntry;
  `verificationMethod` is byte-identical before and after. At least
  one transport must remain advertised at all times — disabling
  the last one is refused with `LastServiceRefused`, no `--force`.
  Rollback is fail-forward (appends a new LogEntry that re-applies
  the prior config; never rewinds the chain). Default drain TTL
  raised from 1h to 24h, hard cap 30d, 1h floor over DIDComm
  transport. Reachable from both `pnm` (over REST or DIDComm) and
  the offline `vta services …` binary on a stopped VTA.
  See `docs/02-vta/runtime-service-management.md` for the
  operator guide and
  `docs/05-design-notes/runtime-service-management.md` for the
  spec.
- **`pnm bootstrap provision-integration --create-context`** —
  PNM matches the offline `vta` flag. Creates the target context
  inline if it doesn't exist, instead of failing the whole call
  with "context not registered." **Requires super-admin** —
  context-admin callers get `Forbidden` against a missing
  context (the super-admin gate sits inside
  `operations::contexts::create_context`, the one place context
  creation is authorised). Idempotent when the context already
  exists. The response carries a new `context_created: bool`
  field so operators see whether their flag actually did
  something — the CLI prints `Context: <id> (created inline …)`
  on first run and `Context: <id> (already existed; --create-context
  was a no-op)` on idempotent retries. Same wire field is honoured
  on REST and DIDComm; old senders continue to work because
  `create_context` defaults to `false` on the wire.
- **`pnm bootstrap provision-integration` works over DIDComm** —
  the SDK's `VtaClient::provision_integration` now dispatches to
  the existing `provision-integration/1.0` DIDComm handler when
  the client is in DIDComm transport mode, instead of returning
  `UnsupportedTransport`. Whichever transport the client opened
  carries the VP and the sealed bundle.

  Both REST and DIDComm support the **operator-as-relayer** flow
  needed for air-gap onboarding: a third-party integration signs
  a BootstrapRequest with its own ephemeral did:key, transfers
  the request to the operator's host, the operator's PNM relays
  it to the VTA, and the operator carries the encrypted bundle
  back. The auth model is layered the same on both transports —
  outer transport authenticates the relayer (bearer token or
  authcrypt sender, ACL-gated), inner VP authenticates the
  holder (the bundle is HPKE-sealed to the holder's X25519). The
  relayer can't decrypt the bundle and can't forge the VP
  signature, so relaying is safe.

  Adds a workspace-specific `e.p.msg.forbidden` problem-report
  code so genuine permission failures don't collapse into the
  SDK's `Auth` variant — fixes a misleading "Token may be
  expired" CLI hint that fired for `Forbidden` errors over
  DIDComm. SDK clients that predate this code fall back to
  `DidcommRemote { code, comment }` cleanly.
- **Promote a serverless WebVH DID to a server-managed one** —
  `pnm webvh register-did --did <did> --server <server-id>` (and
  the offline `vta webvh register-did …`) push an existing local
  `did.jsonl` to a registered host and flip `server_id` so future
  `pnm services …` mutations auto-publish there. Use this when a
  VTA was set up serverless and a webvh host became available
  later — the DID identifier is unchanged so existing integrations
  keep working. Refused if the DID is already server-managed
  (re-pointing a hosted DID at a different host is a separate
  operation, out of scope).

### Breaking

- **`pnm mediator …` subcommand surface retired** in favour of
  the unified `pnm services …` tree. Calling `pnm mediator
  migrate|rollback|drain|report` prints a copy-pasteable redirect
  to the equivalent `pnm services …` command and exits 2.
  Migration map: `pnm mediator migrate --to X` → `pnm services
  didcomm update --mediator-did X`; `pnm mediator rollback` →
  `pnm services didcomm rollback`; `pnm mediator drain cancel
  --mediator-did X` → `pnm services didcomm drain cancel
  --mediator-did X`; `pnm mediator report` → `pnm services
  report`. Likewise `pnm services {enable,disable} didcomm` →
  `pnm services didcomm {enable,disable}`. The `--to` muscle
  memory is preserved as a clap `visible_alias` on `update`.
- **DIDComm message-type rename for symmetry**:
  `services-management/1.0/disable` → `services-management/1.0/
  didcomm-disable`. Other DIDComm-side ops already followed the
  `didcomm-{verb}` shape; this aligns the laggard.
- **Default drain TTL raised from 1h to 24h** when the operator
  omits `--drain-ttl`. The 1h floor over DIDComm transport is
  unchanged. Operators who relied on the prior default need to
  pass `--drain-ttl 3600` explicitly.

## vta-service 0.5.1 — 2026-05-05

### Fixed

- `vta bootstrap provision-integration` now produces an actionable error
  when the target context is missing and `--create-context` wasn't
  passed. The error names both the flag the operator can pass to
  provision the context inline and the `vta contexts create --id <id>`
  command they can run first. Previously the failure surfaced as a
  generic precondition error from inside the library fn, with no hint
  at the missing flag — operators pasting wizard-generated commands
  against fresh VTAs had to grep the docs to recover. CLI-only behavior
  change; library API and wire formats unchanged.

## 0.5.0 — 2026-05-04

The `sealed-bootstrap` release: every secret-bearing transfer between
VTA, integrations, and CLIs now moves as an HPKE-sealed bundle, DID
minting is template-driven, and the DIDComm protocol surface can be
enabled, disabled, or migrated on a running VTA without rebuilding it.

### Added

- **DIDComm protocol management** — enable, disable, and migrate
  the DIDComm protocol surface on a running VTA without rebuilding
  it, re-issuing admin credentials, or rotating the VTA's
  verification keys. Six new operator commands:
  `pnm services {enable,disable} didcomm`, `pnm mediator {migrate,
  rollback,drain cancel,report}`. Each protocol change publishes a
  new WebVH LogEntry; `verificationMethod` is byte-identical
  before and after. Mediator changes go through a drain set
  (persisted to fjall, restart-resilient, 30-day TTL cap) so
  in-flight messages from senders with stale DID-doc caches keep
  landing while the new mediator picks up traffic. Telemetry sink
  is pluggable behind a trait — default impl is a 10k-event ring
  buffer; the `mediator report` command queries it for
  per-mediator inbound counts and per-sender last-seen mediator.

  The full pre-promotion handshake fires end-to-end:
  `migrate`/`rollback` use a live `DIDCommServiceProver` against
  the running service; first-enable spins up a transient
  `DIDCommService` just for the round-trip (lifecycle managed
  by `messaging::transient_handshake`). Drain TTLs fire
  end-to-end via the per-mediator `JoinSet` sweeper + boot-time
  replay. All five admin operations are available over both REST
  and DIDComm transport (`enable` is REST-only by nature).

  See `docs/02-vta/didcomm-protocol-management.md` and
  `docs/05-design-notes/didcomm-protocol-management.md`. New
  modules: `vti_common::telemetry`,
  `vta_service::messaging::{registry, drain_store, drain_sweeper,
  handshake, live_prover, transient_handshake, handlers_protocol}`,
  `vta_service::operations::protocol::*`, `vta_sdk::protocol`,
  `vta_sdk::protocols::protocol_management`,
  `vta_cli_common::commands::{services, mediator}`.

### Breaking

- **WebVH built-in templates renamed by deployment role.**
  `webvh-hosting-server` → `webvh-daemon`, `webvh-service` → `webvh-server`,
  and a new `webvh-control` joins them. Three fixed shapes, one per role:
  `webvh-control` exposes both `WebVHHosting` and `DIDCommMessaging`
  (hosting + DIDComm); `webvh-daemon` exposes `WebVHHosting` only (no
  DIDComm); `webvh-server` exposes `DIDCommMessaging` only (witness,
  watcher, server consumed via DIDComm). The renderer stays declarative —
  no conditionals — so the template name is a 1:1 promise of what comes
  out. See `docs/02-vta/provision-integration.md` for the
  comparison matrix.
- **`ProvisionAsk` builders renamed to match.** `ProvisionAsk::webvh_service`
  → `ProvisionAsk::webvh_server`, `ProvisionAsk::webvh_hosting_server` →
  `ProvisionAsk::webvh_daemon`, plus a new `ProvisionAsk::webvh_control`.
  Constants follow: `BUILTIN_WEBVH_SERVICE_TEMPLATE` →
  `BUILTIN_WEBVH_SERVER_TEMPLATE`, `BUILTIN_WEBVH_HOSTING_TEMPLATE` →
  `BUILTIN_WEBVH_DAEMON_TEMPLATE`, plus `BUILTIN_WEBVH_CONTROL_TEMPLATE`.
  `WebvhServiceMessages` → `WebvhServerMessages`.
- **`webvh-daemon` document shape normalized to `key-0`/`key-1`** (was
  `key-1`/`key-2`). Matches the other webvh templates. Existing
  `webvh-hosting-server` deployments must re-provision against
  `webvh-daemon`.
- **`webvh-server`/`webvh-control` declare `URL` and `WEBVH_SERVER` in
  `optionalVars`** for discoverability. The runtime check that "URL or
  WEBVH_SERVER must be set for any webvh-method template" is unchanged
  — declaring them in the template just makes the contract visible to
  consumers.

### Changed

- **Provisioning error message** when neither `URL` nor `WEBVH_SERVER` is
  supplied now names the satisfying built-in templates explicitly and
  shows the exact `--var` flags to pass.

---

### Publish-readiness review

A multi-agent review across software design, security, test coverage,
and consumer ergonomics produced a punch-list of pre-publish items.
The entries below are the actionable changes that landed.

### Breaking

- **`VtaError` tightened — lossy auto-conversions removed.**
  `impl From<String>`, `impl From<&str>`, and `impl From<Box<dyn Error>>`
  for `VtaError` are gone; every conversion path now picks a typed
  variant explicitly. `from_http` is now `pub` (consumers wiring their
  own HTTP transport produce typed errors directly), and a new
  `VtaError::from_problem_report(code, comment)` mirrors the REST
  mapping for DIDComm so callers `match` on the same variants
  regardless of transport.
- **`verify_vta_authorization_credential` returns a typestate.** Was
  `Result<(), _>`; now `Result<VerifiedAuthorizationCredential, _>`
  carrying the eagerly-parsed claim. Forgetting the `parse_claim`
  follow-up is now a compile error. `parse_claim` itself is `pub(crate)`.
- **Refresh tokens rotate on every `/auth/refresh`** (RFC 6749 §10.4).
  A presented refresh token is single-use; replay surfaces as
  "refresh token not found". Response shape unified with `POST /auth/`:
  refresh now returns the same `AuthenticateResponse`. The bespoke
  `RefreshResponse`/`RefreshData` types are removed.
- **`server_internal_super_admin` removed.** Replaced with a sealed
  `operations::internal_authority::InternalAuthority` marker whose
  constructor is `pub(super)` to the operations module — route
  handlers cannot reach it. `operations::keys::get_key_secret_internal`
  is the parallel `InternalAuthority`-gated entry point. Closes a
  type-system gap where any code path could synthesize a fake
  super-admin claim.
- **`SessionBackend::save` error type bound** in the trait stays sync
  for now; the AzureBackend runtime panic that motivated an async
  migration is fixed via `block_on_isolated` (a side-thread dedicated
  runtime). The full async-trait migration is deferred to a later
  cycle.

### Added

- **`VtaError::suggested_fix(&self) -> Option<&'static str>`** — lifts
  the CLI's "did you mean…" hint into the SDK so non-CLI consumers
  (web UIs, GUIs, custom dashboards) get the same operator-actionable
  guidance without forking the dispatch logic.
- **CLI `--json` flag** (`pnm`, `cnm`) — global flag wired into
  `acl list`, `contexts list`, `keys list`, `did-templates list`. Empty
  results emit the canonical empty shape so `jq` pipelines have a stable
  contract. Uses a new `vta_cli_common::render::OutputFormat` /
  `is_json_output` / `print_json` infrastructure that other commands
  can opt into with a one-line guard.
- **Two runnable examples** under `vta-sdk/examples/`:
  `sealed_transfer_round_trip` (HPKE round-trip end-to-end) and
  `bootstrap_request` (provision-integration request build + sign +
  verify). Each has `required-features = […]`; both double as compile-
  time API-surface locks.
- **`vtc-service` library surface + integration tests.** New `lib.rs`
  exposes the module tree so `tests/` can drive the route stack
  end-to-end. First test file is `tests/auth_audience.rs` (3 cases:
  VTA-audience, unknown-audience, no-token rejection through the full
  router).
- **`pnm did-templates list`, `pnm acl list`, etc. now respect global
  `--json`** — emits the canonical wire shape ready for automation.

### Security

- **Backup KDF parameter clamps on import.** `decrypt_backup` rejects
  `m_cost` outside `[8 MiB, 1 GiB]`, `t_cost` outside `[1, 10]`, and
  any non-`argon2id`/`aes-256-gcm` algorithm. Closes a Nitro-fatal
  memory-bomb vector where a hostile envelope could force `m_cost =
  u32::MAX`.
- **Per-route body caps on unauth endpoints** — `/bootstrap/request`
  and the three `/auth/*` routes now share a 64 KiB cap (vs the global
  1 MiB) so an attacker can't drive expensive crypto with 1 MiB blobs
  ahead of any auth check.
- **`BootstrapRequestBody.label` capped at 256 bytes** via
  `serde(deserialize_with = ...)`. Prevents an MB-scale free-form
  string from spilling into audit logs.
- **`tee_attested` JWT claim is per-session.** Was sourced from
  `state.tee.is_some()` (compile-time TEE feature on); now read from
  the `Session` record set at challenge issue time. A TEE binary in
  `Optional` mode that fell through to an unattested challenge writes
  `false` here; older session JSON deserializes as `false` via
  `#[serde(default)]`.
- **`Session::Debug` redacts `refresh_token`.** Hand-implemented
  `Debug` so a stray `tracing::debug!("{session:?}")` or panic
  backtrace can't surface a bearer-equivalent secret.
- **`SessionInfo` and `TokenResult`** also redact private-key /
  access-token fields in `Debug`.
- **`vta did-webvh create-did --print-mnemonic`** is now opt-in. The
  generated mnemonic is no longer printed to stderr by default —
  protects against shell history, scrollback, CI log collectors, and
  tmux/screen buffers.
- **Auth nonce GC.** `cleanup_expired_sessions` collects live
  `session_id`s in the same pass and removes orphan `nonce:` reverse-
  index rows. The keyspace no longer grows linearly with every
  challenge ever issued — relevant in long-running TEEs.
- **Reject unknown armor headers.** `vta-sdk/src/sealed_transfer/armor.rs`
  used to silently drop unknown headers for forward compatibility;
  now returns `SealedTransferError::Armor("unknown header: …")`. New
  test cases mutate `Bundle-Id`/`Chunk i/N`/`Digest-Algo` through the
  textual armor wire form and assert open fails.
- **`AzureBackend` runtime panic isolated.** The Azure Key Vault
  session backend used `tokio::runtime::Handle::current().block_on(…)`
  inside a sync trait method; that panics under the current-thread
  runtime most CLIs use. New `block_on_isolated` helper spawns a
  dedicated OS thread with its own runtime. Cost is one thread per
  call — acceptable for human-rate session ops.

### Tests

- **`MODE_B_LOCK` concurrency contract** — 16 concurrent
  `mint_mode_b`-style "lock → check → ... await ... → write" tasks
  race against the actual `MODE_B_LOCK` static and the actual
  `BOOTSTRAP_CARVEOUT_CLOSED_KEY` constant. Asserts exactly one task
  writes the sentinel.
- **`KeyspaceHandle` behavioural conformance suite** — 14 cases that
  define the observable contract every `KeyspaceHandle` backend must
  satisfy (round-trip, prefix scan, large-value, binary-safe keys,
  empty values, approximate_len). Today exercises `Local`; harness is
  parameterised on `&KeyspaceHandle` so a future Linux-only fake
  vsock proxy runs the same suite against `Vsock`.
- **Nitro attestation negative-path suite** — 8 cases covering wrong
  proof variant, unknown format, case-insensitive Nitro-format
  matching, malformed base64, empty/random quote bytes, BadProducerDid.
  Documents that the cryptographic-signature path requires a
  fixture-bearing on-host harness.
- **KMS CMS-envelope failure paths** — 5 cases (wrong RSA key,
  corrupted CEK, tampered AES-GCM ciphertext, empty envelope,
  malformed PKCS#8) covering the unwrap path the security review
  flagged as fixture-only.
- **JWT audience isolation through the full route stack** — VTA-side
  in `vta-service/tests/api_integration.rs`, VTC-side in the new
  `vtc-service/tests/auth_audience.rs`. Cross-audience tokens return
  401, unknown audiences return 401.
- **Backup KDF parameter clamps** — 5 unit tests covering each
  out-of-bounds class.
- **`Session::Debug` redaction regression test** — guards against a
  future derive-`Debug` regression re-leaking refresh tokens.
- **Refresh-rotation contract tests** — `delete_refresh_index`
  isolation + idempotence.
- **Sealed-transfer armor tampering** — 4 new cases through the
  textual wire form.

### Refactored

- **`client.rs` → `client/types.rs` + `client.rs`.** The 2269-line
  `client.rs` had request/response DTOs (~36 of them, plus their
  builder impls) inline. Types now live in `client/types.rs` and are
  re-exported via `mod types; pub use types::*;`. `client.rs` shrinks
  to 1858 lines and is mostly methods.
- **`session.rs` → `session/backends/{file,keyring,azure}.rs`.** Each
  backend gets its own focused file (~80 lines apiece); a sibling
  `mod.rs` keeps the `default_backend` selection and the `pub(super)`
  re-exports. `session.rs` drops 260 lines.
- **Shared seal helper for provision-integration.** The end-of-flow
  block (`pick assertion → seal_payload → armor → digest`) was
  copy-pasted between the `TemplateBootstrap` and `AdminRotation`
  paths in `operations/provision_integration/`. Extracted into a
  `pub(super)` `seal_provision_payload` helper in
  `provision_integration/seal.rs`. New payload variants pick up the
  same sealing contract by default.

### Polish

- **`#[must_use]` on every builder** — `CreateKeyRequest`,
  `CreateContextRequest`, `CreateAclRequest`, `EnableDidcommRequest`,
  `MigrateMediatorRequest`, `ProvisionRequestBuilder`,
  `VtaAuthorizationParams`. Catches dropped builder chains at
  compile time.
- **Missing derives.** `SessionInfo`, `SessionStatus`, `LoginResult`,
  `TokenResult`, `TokenStatus` now carry `Debug + Clone` (and
  `Copy + PartialEq + Eq` where appropriate). `SessionInfo` and
  `TokenResult` use a hand-implemented `Debug` that redacts
  bearer-equivalent fields.
- **CLI flag consistency.** `pnm keys create/import` now accept
  `--context` (keeps `--context-id` as a hidden alias for backward
  compat) — matches the rest of the CLI surface.
- **`vta-enclave` `publish = false`.** Linux-only Nitro Enclave
  binary; consumed via the deploy pipeline, not `cargo install`.
- **Crate-level doc on `vta-sdk/src/lib.rs`.** First page of
  `cargo doc` is no longer empty — covers Quick Start, sealed-transfer
  pointer, feature-flag table, module map.
- **README + integration-guide fixes.** Workspace `README.md`,
  `pnm-cli/README.md`, and `docs/02-vta/integration-guide.md`
  no longer document non-existent flags or missing API methods.
  Version pins bumped from `0.4` to `0.5`.
- **Stale CLAUDE.md notes struck.** The "backup `vta_did` cross-check
  not implemented" warning was already false (implemented at
  `backup.rs:286-307`); removed.

### Dependencies

- **`keyring-core` 1.0** replaces the legacy `keyring` v3. Each
  binary registers a platform store at startup via
  `vta_sdk::keyring_init::install_default_store()`; per-target
  stores: `apple-native-keyring-store` (macOS Keychain),
  `windows-native-keyring-store` (Windows Credential Manager),
  `dbus-secret-service-keyring-store` (Linux Secret Service —
  matches prior behaviour and survives reboot, vs `linux-keyutils`
  which doesn't).
- **`affinidi-tdk` 0.6 → 0.7**, **`affinidi-messaging-didcomm-service`
  0.2 → 0.3**, **`affinidi-tdk-common` 0.5 → 0.6**.
  `TDKSharedState::default()` is removed; all 5 call sites switched
  to `TDKSharedState::new(TDKConfig::builder().build()?).await?`.
  The `secrets_resolver` field is now private; uses now go through
  the `secrets_resolver()` accessor.
- **`metrics-exporter-prometheus`** patch-bumped 0.18.2 → 0.18.3.

### Deferred

The following items are real but cascade beyond a focused commit
and don't gate publish. Queued for the next breaking-change cycle:

- **`SessionBackend` async trait migration.** Trait shape stays sync
  for now; AzureBackend uses `block_on_isolated`. Native-async would
  ripple through ~30 SessionStore call sites + both CLIs.
- **`VtaClient<T: Transport>` god-object split.** Same shape of
  cascade as SessionBackend.
- **Hot-spot file split for `did_webvh/update.rs`** — the
  recommended boundaries (update/rotate/state/keys_helper) share
  helpers more entangled than the agent's recommendation suggested,
  needs its own design pass.
- **Provision-integration mid-sequence failure test** — needs a
  fault-injecting `KeyspaceHandle` wrapper. Existing happy-path +
  ACL-gate tests cover the externally-visible contract.
- **Generic `--json` rollout** — wired into 4 high-value list
  commands; remaining list commands (audit logs, services, mediator,
  webvh) keep their human renderers and can opt in with a one-line
  guard when needed.

### Added (sealed-transfer foundation)

- **Sealed-transfer wire format** (`vta-sdk::sealed_transfer`) —
  HPKE-AEAD envelope (X25519-HKDF-SHA256 + ChaCha20-Poly1305),
  OpenPGP-style ASCII armor with CRC24 line checksums, and a tagged
  `SealedPayloadV1` enum covering admin credentials, context
  provision bundles, DID secrets, admin key sets, raw private keys,
  and template-bootstrap payloads. One format, one seal/open path,
  one set of tamper tests for every secret we move.
- **Provision-integration flow** — a holder posts a VP-framed
  `BootstrapRequest` naming a DID template + variables; the VTA
  mints keys, renders the template, registers the holder in the
  ACL, issues a `VtaAuthorizationCredential` (W3C VC + Data
  Integrity), seals the whole bundle to the holder's X25519, and
  returns armored output. Works over three transports (offline
  file, PNM REST bridge, DIDComm) through the same library function.
- **DID templates feature** — declarative JSON describing the shape
  of a DID document with `{TOKEN}` placeholders. Four built-ins ship
  with the SDK (`didcomm-mediator`, `vta-admin`,
  `webvh-hosting-server`, `webvh-service`). Operators can upload
  global or context-scoped custom templates via REST / DIDComm. See
  `docs/did-templates.md`.
- **`webvh-service` built-in template** — generic webvh DID for
  control plane, DID-hosting server, witness, and watcher services
  that route DIDComm through a shared mediator DID.
- **TEE Mode B bootstrap** — `pnm bootstrap connect --vta-url`
  performs a one-command attested first-boot against a fresh Nitro
  enclave. The `/bootstrap/request` carve-out closes permanently on
  first success. Full Nitro attestation verification (COSE_Sign1 +
  cert chain + PCR match) in `pnm-cli` via the `attest-verify`
  feature.
- **Cold-start admin credential flow** — unified temp-did:key flow
  with auto-rotation to a fresh did:key on first authenticated call.
  `vta import-did` seeds the temp DID into the ACL offline; PNM
  completes the handshake + rotation in one `pnm setup` run.
- **Non-interactive VTA setup** — `vta setup --from <file>` for
  CI / sealed images / unattended bootstrap. See
  `docs/non-interactive-setup.md`.
- **Persistent bundle-id anti-replay store** — sealed-transfer nonce
  reuse rejected via fjall-backed `PersistentNonceStore`.
- **Rate limiting** on unauth routes (`/bootstrap/request`,
  `/auth/*`, public `/did/{did}/log`): 5 rps + 10 burst per IP via
  `tower-governor`.
- **Deferred-VTA-DID `pnm setup` flow** (non-TEE) — operators can now
  mint the PNM admin `did:key` **before** the VTA exists, paste it
  into the VTA's `admin_did` input, boot the VTA, then finish PNM
  with `pnm setup continue <slug>`. Unblocks automated VTA hosting:
  Terraform / scripted provisioners no longer hit the chicken-and-egg
  where PNM wanted the VTA DID first and VTA wanted the admin DID
  first. Interactive (`pnm setup` → prompt VTA DID blank to defer)
  and non-interactive (`pnm setup --name <n>` phase 1 with JSON on
  stdout, `pnm setup continue <slug> --vta-did <did>` phase 2) modes.
  Same ephemeral `did:key` preserved across both phases. Multiple
  concurrent pending VTAs allowed (distinct slugs). Spec:
  `docs/design/pnm-setup-deferred-vta-did.md`.
- **`vta-sdk` `test-support` feature** — exposes
  `vta_sdk::session::testing::InMemorySessionBackend` for consumer
  integration tests. Avoids OS-keyring prompts / Secret-Service
  availability in CI. Additive, zero-cost when off.

### Changed

- **MSRV bumped to Rust 1.94.0.**
- **Replaced `rsa` crate with `aws-lc-rs`** for the KMS CMS envelope
  unwrap in the Nitro attested bootstrap path. Drops RUSTSEC-2023-0071
  exposure; constant-time OAEP via BoringSSL heritage. Also dropped
  the SHA-1 MGF1 OAEP fallback (AWS KMS always uses symmetric
  `RSAES_OAEP_SHA_256`).
- **Replaced plaintext credential / DID-secret transfer** with sealed
  bundles everywhere. Plaintext `encode/decode` helpers on bundle
  types are gone — the only way to move secrets is through
  `sealed_transfer::seal_payload` + `open_bundle`.
- **`VtaError::Protocol(String)`** split into typed DIDComm variants
  (`UnsupportedTransport`, `DidcommTransport`, `DidcommRemote`)
  so the CLI can emit operator-specific remediation.
- **Client-side keygen for admin credential issuance** — the VTA no
  longer returns raw secret material. Clients mint their Ed25519
  locally and register the public DID via ACL.
- **`TemplateBootstrap` payload** is now the canonical integration
  bundle shape; replaces ad-hoc `ContextProvisionBundle` exports.
- **Coordinated RustCrypto 0.11 ecosystem bump**: `sha2` 0.10→0.11,
  `hmac` 0.12→0.13, `hkdf` 0.12→0.13, `aes` 0.8→0.9, `cbc` 0.1→0.2.
- **Azure crates bumped**: `azure_identity` 0.33→0.35,
  `azure_security_keyvault_secrets` 0.12→0.14.
- **[breaking] `vta-sdk::session` public-type `vta_did`** is now
  `Option<String>` on `Session` (internal), `SessionInfo`,
  `SessionStatus`, and `LoginResult`. `None` encodes the new
  `PendingVtaBinding` state used by deferred-VTA-DID `pnm setup`.
  `SessionStore` gains `store_pending_vta_binding`, `bind_vta_did`,
  and `has_pending_vta_binding`. Existing session JSON still
  deserializes (serde default). No external `SessionBackend`
  implementors exist outside the in-tree built-ins.

### Security

Design-review hardening pass (see CLAUDE.md for the full write-up):

- **S-1** KMS attested-only on real Nitro hardware. Previously a
  transient NSM hiccup silently downgraded to an IAM-only KMS call,
  bypassing PCR-enforced policy. Now terminal unless
  `tee.kms.allow_unattested_fallback = true`.
- **S-2** JWT key fingerprint no longer silently re-baselines on
  missing record. Operators migrating from a pre-fingerprint VTA
  opt in explicitly via `tee.kms.allow_fingerprint_init`.
- **S-3** Constant-time challenge + DID compare on `/auth/`.
- **S-4** `AuthClaims::local_cli` renamed to
  `unsafe_local_cli_super_admin` and feature-gated behind
  `cli-synthesis`. Enclave builds cannot compile a call to it.
  Added a separate `server_internal_super_admin` for the library-
  internal privilege-elevation case.
- **S-5** `verify_producer_assertion_with_pubkey` now returns a
  `VerifiedAssertion` typestate (`DidSignedVerified` /
  `PinnedOnlyAcknowledged` / `AttestedNeedsNitroCheck`). Callers
  must match exhaustively — no more silent `Ok(())` for Attested.
- **S-6** `TeeProvider::verify(report) -> bool` renamed to
  `smoke_check_structure(report) -> StructuralCheckOutcome` with
  doc comments spelling out that this is structural only, not
  cryptographic verification.
- **S-7** Refresh tokens keyed by SHA-256 in the session reverse-
  index. A storage dump now yields hashes, not live credentials.
- **S-8** `validate_identifier` on context-id and template-name at
  the DID-template operations boundary. Guards against
  `{context}:{name}` → `tpl:ctx:a:b:c` keyspace injection.
- **S-9** Backup import rejects mismatched `vta_did`. Fresh installs
  accept any backup (disaster recovery); running VTAs refuse to
  overwrite their identity with a foreign backup.
- **S-10** `open_bundle` couples `PinnedOnly` producer assertions to
  an OOB digest at the type level via `PinnedOnlyPolicy`.
- **Backup encryption** uses Argon2id (m=64 MiB, t=3, p=4) +
  AES-256-GCM with 12-char minimum password and AEAD tag check.

### Tests

Reference-quality coverage across foundation crates:

- **T-1** vsock-store wire-format tests (25) — protocol constants,
  encode/decode tamper cases, request payload shape.
- **T-2** ACL unit tests (26) — CRUD, role assignment matrix,
  context-scope visibility, expiration boundary, serde
  forward-compat with pre-`expires_at` entries.
- **T-3** JWT rejection tests (7) — expired, tampered signature,
  `alg=none`, foreign signer, missing required claims, empty,
  malformed shape.
- **T-4** Session lifecycle tests (17) — CRUD, refresh-token S-7
  regression guard, cleanup of expired sessions.
- **T-5** vtc-service wire-shape + config parse tests (18).
- **Mutation-coverage suite** for VP verify in
  `provision_integration/request.rs` — bit-flip in nonce, ask,
  `validUntil`, admin template, type arrays.
- **Sealed-transfer adversarial suite** — armor CRC24 tamper, AAD
  tamper caught by AEAD, missing chunk, nonce replay, wrong
  recipient, PinnedOnly-without-digest rejection.

### Refactored

- `vta-service/src/operations/provision_integration.rs` (1942 lines)
  split into `mod.rs` + `mint` + `preconditions` + `templates` +
  `vta_keys` + `webvh` submodules.
- `vta-service/src/operations/did_webvh.rs` (1444 lines) split into
  `mod.rs` + `document` + `lifecycle` + `servers`.
- `vta-service/src/setup/` split into `interactive` + `from_toml`.
- New `vta-service/src/test_support` for the shared test harness.

### Removed

- **`/auth/credentials` endpoint and `VtaClient::auth_credential_*`
  client methods** — clients mint did:key locally and register the
  DID in the ACL; the VTA never holds the private key.
- **Plaintext `encode/decode` helpers** on `CredentialBundle`,
  `ContextProvisionBundle`, `DidSecretsBundle`, `AdminKeySet`,
  `RawPrivateKey` — the only way to move these is via
  `sealed_transfer`.
- **`rsa` and `sha1` crates** from direct dependencies.

## 0.4.1 — 2026-04-15

### Added

- **`VtaClient` and `DIDCommSession` are now `Clone`** — Cloning a
  `VtaClient` is cheap; clones share the underlying HTTP connection pool
  and authentication state via `Arc<Mutex>`, avoiding redundant auth
  round-trips.
- **Cold-start bootstrap guide** (`docs/cold-start-guide.md`) —
  Step-by-step walkthrough for bootstrapping a VTA + Mediator + WebVH
  environment from scratch.

### Changed

- **Consolidated security documentation** — Merged `threat-model.md`
  and `security-architecture.md` into a single `docs/security.md`.
  Removed stale `docs/VTA_Service_Overview.md` and
  `docs/store-migration.md`.

## 0.4.0 — 2026-04-13

### Changed

- **Upgrade to `affinidi-messaging-didcomm-service` v0.2** — Both VTA
  and VTC now use the v0.2 DIDComm service framework, which provides
  production-ready lifecycle management for mediator connections.
- **VTA DIDComm bridge simplified** — The bridge no longer captures the
  listener's ATM from handler context. Instead, it uses
  `DIDCommService::send_message_with_retry()` for resilient delivery
  with exponential backoff across mediator reconnects, and
  `listener_did()` for dynamic DID lookup.
- **VTA startup blocks until mediator is ready** — The server now calls
  `wait_connected()` after starting the DIDComm service, ensuring the
  mediator connection is established before accepting REST traffic.
- **VTC migrated to DIDComm service framework** — Replaced the manual
  ATM/WebSocket dispatch loop with `DIDCommService` + `Router`. VTC
  now gets automatic reconnection, typed message routing, and lifecycle
  event logging for free.

### Added

- **DIDComm lifecycle event logging** — Both VTA and VTC log mediator
  connection events (`Connected`, `Disconnected`, `Restarting`) via
  the service's `subscribe()` broadcast channel.

### Removed

- **`vta-sdk::didcomm_init`** — Manual ATM/WebSocket/profile setup
  module removed. All DIDComm connection management is now handled by
  `DIDCommService`.
- **`vta-sdk::didcomm_transport`** — The `send_and_wait_raw` function
  and `DIDCommSendParams` struct removed. The `PendingMap` type has
  moved into the VTA service's `DIDCommBridge`.

## 0.3.3 — 2026-04-13

### Fixed

- **DIDComm message expiry** — Outbound DIDComm messages now include
  `created_time` and `expires_time` fields, preventing stale messages
  from accumulating at the mediator between sessions. Expiry matches
  the caller's timeout (30 seconds for WebVH operations).
- **Problem-report logging** — Unhandled problem-report messages (e.g.,
  protocol-specific types from WebVH servers) now log `code`, `comment`,
  `from`, and `msg_type` instead of just "unknown message type". The
  standard problem-report handler also includes `msg_type` to
  distinguish between protocol-specific and standard problem reports.
- **Stale message detection** — The DIDComm bridge now logs unmatched
  responses (messages with a `thid` that don't match any pending
  request) at DEBUG level, identifying them as likely stale messages
  from a previous session.

## 0.3.2 — 2026-04-12

### Fixed

- **DIDComm outbound response routing** — The `DIDCommBridge` now
  correctly receives responses to outbound request-response messages
  (e.g., WebVH DID creation via DIDComm transport). Previously,
  `try_complete()` was never called on inbound messages, so
  `send_and_wait` would always time out.
- **Single mediator connection** — Replaced the dual-ATM architecture
  (one for the listener, one for the bridge) with a single shared
  connection. The new `BridgeHandler` wrapper captures the listener's
  ATM from `HandlerContext` and intercepts response messages before
  normal handler dispatch. This eliminates the
  `w.websocket.duplicate-channel` error loop that occurred when two
  connections used the same DID.

## 0.3.1 — 2026-04-11

### Client-Provided DID Documents for WebVH Creation

- **Three DID creation modes** — `POST /webvh/dids` now supports three
  mutually exclusive modes:
  - **VTA-built** (default) — VTA derives keys and builds the DID
    Document internally (existing behavior, unchanged).
  - **Template mode** (`did_document` field) — Client provides a DID
    Document template with `{DID}` placeholders. VTA derives keys,
    signs the log entry, and resolves placeholders via `didwebvh-rs`.
    `add_mediator_service` and `additional_services` are ignored.
  - **Final mode** (`did_log` field) — Client provides a complete,
    pre-signed `did.jsonl` log entry. VTA publishes it as-is without
    deriving keys or creating a log entry. No key records are stored.
- **`set_primary` flag** — Optional boolean (default `true`). When
  `false`, the context's primary DID (`ctx.did`) is not updated,
  allowing multiple DIDs per context without overwriting the primary.
- **CLI support** — `pnm webvh create-did` gains `--did-document <FILE>`,
  `--did-log <FILE>`, and `--no-primary` flags.
- **5 new integration tests** — Mutual exclusivity validation, template
  mode with custom keys, final mode storage, and `set_primary`
  true/false behavior.

### User-Specified Keys for DID Creation

- **`signing_key_id` / `ka_key_id` fields** — Optionally specify
  existing VTA-managed keys (imported or derived) for DID creation
  instead of having the VTA derive fresh keys. The signing key must
  be Ed25519; the KA key must be X25519.
- **Signing-only DIDs** — When only `signing_key_id` is provided, the
  DID Document is created with authentication/assertion but no
  keyAgreement, suitable for non-DIDComm use cases.
- **DIDComm validation** — If the DID Document includes
  `DIDCommMessaging` services (via `add_mediator_service`,
  `additional_services`, or a template), `ka_key_id` is required.
- **CLI support** — `pnm webvh create-did` gains `--signing-key` and
  `--ka-key` flags.
- **5 new integration tests** — Signing-only, both keys, KA-without-
  signing rejection, DIDComm-requires-KA, wrong key type rejection.

### Setup Wizard Improvements

- **Simple/advanced toggle** — VTA DID creation now offers a simple
  path (VTA creates everything) and an advanced path that reveals
  template mode, pre-signed log import, and user-specified key options.
- **Consolidated DID creation** — `did_webvh.rs` standalone CLI
  rewritten as a thin interactive wrapper around `operations::create_did_webvh()`,
  removing ~200 lines of duplicate key derivation and document building.
- **VTA DID via operations layer** — `create_vta_did()` in the setup
  wizard now uses `build_wizard_did()` → `operations::create_did_webvh()`
  instead of direct `didwebvh-rs` calls.
- **Pre-rotation UX** — Replaced interactive loop ("Generate another?")
  with a count prompt ("Number of pre-rotation keys", default: 1).
- **Post-creation hosting instructions** — After saving `did.jsonl`,
  the wizard now shows the URL where it should be uploaded.

### Capabilities Discovery

- **`GET /capabilities`** — New authenticated endpoint reporting VTA
  features (webvh, didcomm, tee, rest), enabled services, configured
  WebVH servers, and supported DID creation modes. Allows 3rd party
  apps using `vta-sdk` to probe what the VTA supports before attempting
  operations.
- **DIDComm discovery protocol** — `discover-capabilities` message type
  returns the same information via DIDComm.
- **`VtaClient::capabilities()`** — SDK client method for discovery.

### Infrastructure & Bug Fixes

- **Unified `build_did_document`** — merged `build_did_document` and
  `build_did_document_from_keys` into a single function with `include_ka`
  parameter.
- **DID deletion cleans up key records** — `delete_did_webvh` now removes
  associated signing, KA, and pre-rotation key records.
- **DIDComm bridge wired in handler path** — WebVH server communication
  via DIDComm now uses the real bridge instead of a dummy.
- **Pre-rotation keys in TEE autogen** — TEE auto-generated DIDs now
  include 1 pre-rotation key by default.
- **Mediator DID format validation** — Setup wizard validates `did:`
  prefix when entering an existing mediator DID.

### Code Consolidation

- **Eliminated `CreateDidRequest`** — REST route now uses
  `CreateDidWebvhBody` from SDK protocol types directly.
- **`From<CreateDidWebvhBody> for CreateDidWebvhParams`** —
  Centralizes default value logic, replacing boilerplate conversions
  in REST and DIDComm handlers.
- **Removed ~316 lines of duplicate code** — Deleted `create_webvh_did()`
  and `prompt_pre_rotation_keys()` from `setup.rs` after migrating
  all callers to `build_wizard_did()`.
- **Cleaned up unused imports** — Removed `didwebvh-rs` direct
  dependencies from `setup.rs` now that it uses the operations layer.

## 0.3.0 — 2026-04-01

### Reader Role & Action Classification

- **New `Reader` role** — Context-scoped read-only access to keys,
  contexts, DIDs, and configuration. Sits between Application and
  Monitor in the hierarchy. Readers can observe all business data
  within their allowed contexts but cannot sign, write to cache,
  create keys, or perform any mutating operation.
- **Action classification** — Every endpoint is now classified as
  read, write, or manage:
  - **Read** (Reader+): list/get keys, contexts, DIDs, config, cache
  - **Write** (Application+): sign, cache write/delete
  - **Admin**: key create/delete/import, seeds, audit, DID management
  - **Manage** (Initiator+): ACL operations, credential generation
  - **Super Admin**: config update, context CRUD, backup, restart
- **`require_read()` / `require_write()`** — New methods on
  `AuthClaims` for action-level authorization checks.
- **`WriteAuth` extractor** — Route-level extractor requiring at
  least Application role. Applied to sign and cache write endpoints.
- **Tightened auth on sign and cache** — `POST /keys/{id}/sign`,
  `PUT /cache/{key}`, and `DELETE /cache/{key}` now require
  Application role or higher (previously any authenticated user).
- **Backup export route** — Changed from `AuthClaims` to
  `SuperAdminAuth` extractor, matching the operations layer.
- **DIDComm handler auth fixes** — 17 handlers now have explicit
  role checks matching their REST counterparts (defense-in-depth).
  Fixed `handle_update_retention` from `require_admin()` to
  `require_super_admin()` to match REST.

### Role Hierarchy (updated)

```
Super Admin  (Admin + unrestricted)
  Admin      — key mgmt, DID ops, audit, seeds
    Initiator  — ACL management, credential generation
      Application — sign, cache write, standard API
        Reader     — read-only business data access
          Monitor  — metrics and health only
```

### Version Bumps

All crates bumped from 0.2.1 to **0.3.0**.

### Testing

- **18 new tests** — Reader role parsing, `require_read`/`require_write`
  enforcement across all roles, ACL validation (Reader cannot assign
  roles, Initiator/Admin can create Reader), integration tests (Reader
  can list keys, cannot sign, cannot create keys).
- **Total: 263 tests** (up from 245).

### VTA SDK Integration Module

- **`vta_sdk::integration::startup()`** — Unified startup pattern for
  any service that manages its DID and secrets through a VTA. Handles
  authentication, secret fetching, local caching, and offline fallback
  in a single call. Returns a `StartupResult` with the service DID,
  secrets bundle, source indicator, and an optional `VtaClient` for
  follow-up calls.
- **`SecretCache` trait** — Pluggable local cache for VTA secrets.
  Services implement `store()` and `load()` using their preferred
  backend (keyring, AWS Secrets Manager, filesystem, etc.) to enable
  offline resilience.
- **`authenticate()`** — Two-tier authentication strategy: lightweight
  REST auth first (`VtaClient::from_credential`), with session-based
  DIDComm fallback for non-`did:key` VTAs. Network errors propagate
  immediately without fallback.
- **`integration` feature flag** — New opt-in feature on `vta-sdk`
  (implies `client` + `session`) that enables the integration module.

### Key Labels as Verification Method IDs

- **`fetch_did_secrets_bundle()`** — When a key has a label, it is now
  used as the verification method fragment (e.g., `did:example#my-label`)
  instead of the raw key ID. This produces cleaner, human-readable DID
  documents for services that use labeled keys.

### Workspace Dependency Consolidation

- **`ed25519-dalek`** — Moved to `workspace.dependencies`, updated 6
  crates to use `workspace = true`.
- **`dialoguer`** — Moved to `workspace.dependencies`, updated 4
  crates to use `workspace = true`.
- **`chrono` in `vta-cli-common`** — Now uses workspace definition
  (gains `serde` feature that was previously missing).

### HTTP Client Improvements

- **`auth_light` client reuse** — `challenge_response_light()` and
  `refresh_token_light()` now accept a `&reqwest::Client` parameter
  instead of creating a new client per call, enabling connection
  pooling across authentication flows.
- **`authenticate_with_credential()`** — Returns the HTTP client
  alongside the auth result, which `VtaClient::from_credential()`
  now reuses directly (eliminating a redundant client allocation).
- **`WebvhClient` refactor** — Extracted `send()` and `with_auth()`
  helpers to eliminate repeated request/error-handling boilerplate
  across 4 methods.

### Code Quality

- **Zero clippy warnings** — Resolved all clippy warnings across the
  workspace: collapsible ifs, `.is_multiple_of()`, needless `Ok(?)`,
  `Default` impl for `WrappingKeyCache`, type alias for complex KMS
  return type.
- **`Keyspaces` struct** — New `operations::Keyspaces` bundles keyspace
  handles with `from_app_state()` and `from_vta_state()` constructors.
  Reduces argument counts for `export_backup` (11→6), `apply_import`
  (10→5), `delete_context` (8→5).
- **`DIDCommSendParams`** — New params struct for `send_and_wait_raw`,
  replacing 10 positional arguments.
- **`cargo fmt`** — Full workspace formatting pass.

### Security

- **VTC key material zeroization** — Added `zeroize` dependency to
  `vtc-service`. Replaced `.unwrap()` on key material slices with
  proper error propagation. Secrets bundle now written to file
  instead of stdout (preventing key leakage to logs).
- **Session error visibility** — Replaced `.ok()?` chains in keyring,
  file, and Azure session backends with explicit error logging via
  `tracing::warn`. Users can now diagnose auth failures from logs.

### Architecture

- **Shared `SeedStore` trait** — Extracted seed/secret store trait
  from `vta-service` into `vti-common/src/seed_store.rs`. Both VTA
  (`SeedStore`) and VTC (`SecretStore`) now implement the shared
  interface. Cloud backend implementations remain in each service crate.

### Testing

- **Operation-level unit tests** — New tests for `create_key` (Ed25519,
  P256), `sign_payload` (EdDSA roundtrip), and `rotate_seed` (archive
  + generation increment). Uses mock `SeedStore` and temp fjall stores.
- **Total: 245 tests** (up from 241).

### CI/CD

- **GitHub Actions pipeline** (`.github/workflows/ci.yml`) — Four
  parallel jobs: `cargo check`, `cargo test`, `cargo clippy -D warnings`,
  `cargo fmt --check`. Triggers on push to main/nightly and PRs to main.
  Cargo registry and target caching via `actions/cache`.

### Documentation

- **Integration Guide** (`docs/integration-guide.md`) — Comprehensive
  guide for 3rd-party developers integrating applications and services
  with the VTA. Covers credential provisioning, authentication patterns,
  key management, the SDK integration module, offline resilience, and
  security best practices.

---

## 0.3.0 — 2026-03-31

### Imported Secrets

- **Import external private keys** — New `POST /keys/import` endpoint
  and `pnm keys import` command allow importing externally-created
  private keys (Ed25519, X25519, P-256) into the VTA. Imported keys
  are stored encrypted at rest and participate in signing, secret
  export, backup/restore, and revocation alongside BIP-32-derived keys.
- **Ephemeral wrapping keys (REST)** — REST key import uses
  ECDH-ES + AES-256-GCM key wrapping via ephemeral X25519 keypairs
  (`GET /keys/import/wrapping-key`). Each wrapping key is single-use
  with a 60-second TTL. DIDComm transport sends keys directly inside
  the end-to-end encrypted envelope.
- **Encrypted storage layer** — Imported secrets are encrypted with
  AES-256-GCM using a KEK derived from the BIP-32 master seed via
  HKDF-SHA256 with a random 32-byte salt. Each ciphertext is bound
  to its `key_id:key_type` via authenticated associated data (AAD),
  preventing blob-swap attacks.
- **Secure deletion on revoke** — Revoking an imported key overwrites
  the encrypted blob with zeros and deletes it from the keyspace.
  The `KeyRecord` is retained for audit trail.
- **Seed rotation re-encryption** — When the BIP-32 seed is rotated,
  all imported secrets are automatically re-encrypted with the new
  seed-derived KEK.
- **Backup & restore** — Imported secrets are included in the
  encrypted backup payload (plaintext inside the Argon2id+AES-256-GCM
  envelope) and restored on import. The KEK salt is also backed up
  for deterministic KEK reconstruction.

### Data Model

- **`KeyOrigin` enum** — New `origin` field on `KeyRecord`:
  `derived` (default, BIP-32) or `imported` (external). Backward
  compatible via `#[serde(default)]`.
- **`ImportedSecretBackup`** — New type in `BackupPayload` for
  portable imported secret backup.
- **`imported_secret_count`** — Added to `ImportResult` for
  visibility during backup preview/import.

### Security

- **Zeroize** — All private key buffers are zeroized after use
  via the `zeroize` crate (import, signing, backup export/import,
  seed rotation re-encryption).
- **AAD binding** — AES-GCM encryption of imported secrets includes
  `key_id:key_type` as additional authenticated data, preventing
  ciphertext swapping between key entries.
- **Independent KEK salt** — A random 32-byte salt is generated
  per VTA instance and stored alongside the keyspace, ensuring
  two VTAs with the same seed produce different KEKs.
- **Admin-only import** — The import endpoint requires Admin role
  (stricter than key creation which allows Initiator).

### CLI

- **`pnm keys import`** — Import a private key from multibase
  string (`--private-key`) or file (`--private-key-file`).
  Supports `--key-type ed25519|x25519|p256`, `--label`, and
  `--context-id`. Prints a secure-deletion warning on success.

### Testing

- **6 new unit tests** — Imported secret encrypt/decrypt roundtrip,
  wrong-AAD rejection, secure deletion, seed rotation re-encryption,
  ephemeral wrapping key generation + unwrap, single-use enforcement.
- **Total: 234 tests** (up from 228).

### Breaking Changes

- **Operation signatures** — `get_key_secret()`, `sign_payload()`,
  `revoke_key()`, `rotate_seed()`, `export_backup()`, and
  `apply_import()` now accept an `imported_ks` parameter.
- **`AppState`** — Added `imported_ks: KeyspaceHandle` and
  `wrapping_cache: WrappingKeyCache` fields.
- **`VtaState` (DIDComm)** — Added `imported_ks: KeyspaceHandle`.
- **Workspace version bumped to 0.3.0** — All crates updated.

### Dependency Updates

- `hkdf` 0.12 (new — KEK derivation for imported secrets)

### VTA SDK Improvements for Service Integration

- **Lightweight DIDComm auth (`auth_light`)** — New
  `challenge_response_light()` and `refresh_token_light()`
  functions perform DIDComm challenge-response authentication
  without requiring ATM/TDK runtime initialization. Uses a
  hand-rolled JWE packer (`didcomm_light`) with
  ECDH-ES+A256KW key agreement and A256GCM content
  encryption. Available behind the `client` feature (not
  `session`).
- **`VtaClient::from_credential()`** — One-line constructor
  that decodes a base64 credential bundle, authenticates via
  lightweight auth, and returns a ready-to-use client with
  auto-refresh enabled.
- **Automatic token refresh** — `VtaClient` now stores
  credential material and automatically refreshes expired
  tokens before each API call. Tries the `/auth/refresh`
  endpoint first (cheap), falls back to full
  challenge-response if the refresh token is expired.
  Token expiry is checked with a 30-second buffer.
- **`fetch_context_secrets()`** — Convenience method that
  paginates through all active keys in a context and returns
  TDK `Secret` objects ready for DIDComm or signing. Pages
  in batches of 100 to handle large key sets.
- **`check_auth()`** — Verifies the current token is valid
  by calling `GET /health/details`. Returns `true`/`false`
  for readiness checks.
- **`token_expires_at()`** — Exposes token expiry for health
  monitoring in long-running services.
- **`set_token()` is now `&self`** — No longer requires
  `&mut self`, simplifying usage in shared contexts.

### Lightweight DIDComm Packer (`didcomm_light`)

- **DIDComm v2 anoncrypt** — Minimal JWE (General JSON)
  packer producing messages compatible with any DIDComm v2
  unpacker (including `affinidi-tdk`'s `ATM::unpack()`).
- **ECDH-ES+A256KW** key agreement with ephemeral X25519.
- **A256GCM** content encryption (simpler than A256CBC-HS512).
- **Concat KDF** (NIST SP 800-56A) for key derivation.
- **AES-256 Key Wrap** (RFC 3394) for CEK wrapping.
- **`did:key` → X25519** conversion (Edwards→Montgomery).
- **8 unit tests** — Key wrap roundtrip, KDF determinism,
  did:key parsing, Ed25519→X25519 conversion, JWE structure
  validation.

### VTA SDK Ergonomics

- **`vta_sdk::prelude`** — Re-exports the most commonly used
  types (`VtaClient`, `VtaError`, `KeyRecord`, `KeyType`,
  `CredentialBundle`, request/response types) for single-line
  imports.
- **Builder patterns** — `CreateKeyRequest::new(KeyType::Ed25519)
.label("my-key").context("app")` replaces verbose struct
  construction with many `None` fields. Builders added for
  `CreateKeyRequest`, `CreateContextRequest`, `CreateAclRequest`,
  and `GenerateCredentialsRequest`. All accept `impl Into<String>`.
- **`fetch_did_secrets_bundle()`** — One-call replacement for the
  4-step pattern (get context → list keys → get secrets → build
  bundle). Returns a portable `DidSecretsBundle`.
- **`From<GetKeySecretResponse> for SecretEntry`** — Eliminates
  manual field-by-field mapping when building secret bundles.

---

## 0.2.1 — 2026-03-30

### Bug Fixes

- **Health check deserialization** — Made `version` field optional
  in `vta-sdk::HealthResponse` so the unauthenticated `GET /health`
  endpoint (which returns only `{"status": "ok"}`) deserializes
  correctly. Previously `pnm health` and `cnm health` reported
  "error decoding response body".

### Improvements

- **Audit log levels** — Audit events now use `INFO` for successful
  outcomes and `ERROR` for failures (e.g. `denied:*`). Previously
  all audit events were emitted at `ERROR` level regardless of
  outcome.

## 0.2.0 — 2026-03-29

### Observability

- **Prometheus metrics endpoint** — `GET /metrics` serves
  request count and latency histograms in Prometheus text
  format. Requires authentication (any role including the
  new Monitor role).
- **Monitor role** — New lowest-privilege role for
  observability-only access. Can read `/metrics` and
  `/health` but nothing else. Create with
  `pnm acl create --role monitor`.

### Hardening

- **Admin credential delete-after-read** — The
  `/attestation/admin-credential` endpoint now deletes the
  credential from the store after first retrieval.
  Subsequent calls return 404.
- **Server-side backup password minimum** — The backup
  export API enforces a 12-character minimum password.
- **Super admin for backup/restart** — Backup export,
  import, and VTA restart now require super admin (admin
  with no context restrictions).
- **Enclave bootstrap error handling** — Replaced all
  `.expect()` calls in `vta-enclave/src/main.rs` with
  proper error handling and `tracing::error` before exit.
- **Clippy clean** — Fixed all actionable warnings:
  `Role::from_str` → `Role::parse`, `.clamp()`, needless
  borrows, collapsed ifs.

### Testing

- **31 REST API integration tests** — Full axum server
  with temp fjall store, programmatic JWT tokens, and
  pre-inserted sessions. Covers auth enforcement (6),
  role hierarchy (4), CRUD operations (5), backup (3),
  cache (1), audit (2), context scoping (1), key
  lifecycle (3), P-256 keys (1), seed list (1),
  wrong password (1), ACL lifecycle (1), context
  lifecycle (1), audit retention (1).
- **20 security-focused unit tests** — Auth role
  enforcement, ACL privilege escalation prevention,
  context access scoping, backup crypto validation.
- **Total: 226 tests** (up from 175 at start of release).

### Documentation

- **6 Mermaid diagrams** — Crate dependencies, REST vs
  DIDComm request flow, auth challenge-response sequence,
  BIP-32 derivation tree, TEE bootstrap sequence, enclave
  proxy architecture.
- **Consolidated docs** — Removed ~170 lines of
  duplicated content from README.md (feature flags, CLI
  reference). Cross-references to canonical sources.
- **Doc comments** on 35 public route handler functions.
- **Expanded CONTRIBUTING.md** — Development setup, test
  commands, PR checklist, coding guidelines.

### Architecture

- **vta-service / vta-enclave split** — `vta-service` is
  now a library crate exporting all business logic.
  `vta-enclave` is a separate binary crate for Nitro
  Enclave deployments with TEE-specific bootstrap (KMS,
  vsock-store, attestation). Future front-ends (SGX,
  serverless) follow the same pattern.
- **Soft restart** — The VTA server can now restart
  in-process without a process restart. Service threads
  shut down gracefully, auth/crypto re-initialize, and
  threads restart. Exposed via `POST /vta/restart`,
  DIDComm protocol, and `pnm vta restart`.
- **Patched affinidi-messaging-didcomm-service** — Local
  patch adds `tdk_config` field to `ListenerConfig` so
  the VTA can pass its network-mode DID resolver to the
  DIDComm service listener.

### TEE / Nitro Enclave

- **KMS-based secret bootstrap** — First boot generates
  BIP-39 seed and JWT key inside the enclave, encrypts
  with KMS `GenerateDataKey` (with Nitro attestation),
  stores ciphertext. Subsequent boots decrypt via KMS
  `Decrypt` with PCR enforcement.
- **Encrypted storage** — AES-256-GCM encryption of all
  sensitive keyspaces. Key derived from seed via HKDF.
- **Auto-generated VTA identity** — `did:webvh` DID
  created automatically on first boot from a template.
- **Admin credential bootstrap** — Operator-provided
  admin DID or auto-generated `did:key` with credential
  bundle stored for retrieval.
- **Seal mechanism** — Ed25519 challenge-response seal
  prevents offline CLI modification after bootstrap.
- **Nitro deployment infrastructure** — Dockerfile,
  enclave entrypoint, KMS setup scripts, IAM policies,
  full deployment guide (1,200+ lines).

### DIDComm

- **Migrated to affinidi-messaging-didcomm-service** —
  Replaced manual message dispatch with typed Router,
  handler functions, MessagePolicy middleware, and
  RequestLogging. Handlers use `Extension<Arc<VtaState>>`
  for shared state injection.
- **WebSocket-based DIDComm session** — PNM CLI now uses
  WebSocket streaming for response delivery, fixing
  reliability issues with REST-only polling.
- **Backup management protocol** —
  `backup-management/1.0/export` and
  `backup-management/1.0/import` DIDComm message types.
- **VTA restart protocol** —
  `vta-management/1.0/restart` DIDComm message type.

### P-256 Key Support

- **P-256 (secp256r1) key derivation** — New key type
  with BIP-32 derivation using domain-separated paths
  (`m/13'/256'/...`).
- **Signing oracle endpoint** — `POST /keys/{key_id}/sign`
  (REST) and `key-management/1.0/sign` (DIDComm) for
  server-side signing with managed keys.
- **Token cache API** — `GET/PUT/DELETE /cache/{key}` for
  ephemeral key-value storage with TTL support.

### Backup & Restore

- **Export** — `POST /backup/export` and DIDComm protocol
  serialize all VTA state (seed, keys, ACL, contexts,
  WebVH, config, optional audit logs) into a
  password-protected `.vtabak` file.
- **Encryption** — Argon2id (64 MiB, 3 iterations, 4
  parallel) derives AES-256-GCM key from user password.
- **Import** — `POST /backup/import` decrypts, validates,
  replaces all state, and triggers soft restart. Preview
  mode (`confirm=false`) shows what would change.
- **TEE re-encryption** — On import in TEE mode,
  `re_encrypt_bootstrap_secrets()` re-encrypts the
  imported seed and JWT key with the enclave's KMS key.
- **PNM CLI** — `pnm backup export [--include-audit]`
  and `pnm backup import <file> [--preview]`.

### Performance

- **DIDComm service DID resolver fix** — The DIDComm
  service listener was creating a local-mode DID resolver
  (ignoring network-mode config), causing ~1s of uncached
  HTTP DID resolution per message through the HTTPS proxy.
  Fixed via patched crate with `tdk_config` passthrough.
- **Reusable TrustPingSession** — PNM health command now
  creates one ATM + WebSocket connection for both mediator
  and VTA pings, eliminating ~4s of duplicate setup.
- **Shared DID resolver** — Single `DIDCacheClient` across
  all health check operations.

### CLI

- **DIDComm-only mode** — PNM CLI works without a REST
  URL, using DIDComm through the mediator for all
  operations.
- **Multi-VTA support** — `pnm vta list/use/remove/info`
  for managing connections to multiple VTAs.
- **`pnm vta restart`** — Trigger soft restart remotely.
- **`pnm backup export/import`** — Remote backup and
  restore with password protection.
- **Trust-ping in health** — `pnm health` now pings both
  the mediator and VTA through DIDComm with latency
  display.

### Enclave Proxy

- **Rust rewrite** — Replaced shell-based parent proxy
  with a Rust binary (`enclave-proxy`).
- **7-channel multiplexer** — Inbound REST, outbound
  mediator (TLS), HTTPS CONNECT proxy, IMDS credential
  proxy, persistent storage (fjall), DID resolver bridge,
  log forwarding.
- **Embedded Affinidi DID resolver** — Resolves mediator
  DID locally without external resolver service.
- **Connection limit** — Semaphore-based limit (256) per
  channel to prevent resource exhaustion.

### Breaking Changes

- **`vta-service` is now a library** — The local/dev
  binary is still included, but TEE deployments use
  `vta-enclave` which depends on `vta-service` as a
  library.
- **DIDComm handler signatures changed** — Handlers now
  use `(HandlerContext, Message, Extension<Arc<VtaState>>)`
  pattern from `affinidi-messaging-didcomm-service`.
- **Workspace version bumped to 0.2.0** — All crates
  updated.

### Dependency Updates

- `affinidi-messaging-didcomm-service` 0.1.2 (patched
  locally for TDK config passthrough)
- `didwebvh-rs` 0.3 → 0.4
- `tokio-vsock` 0.5 → 0.7
- `argon2` 0.5 (new — backup encryption)
- `aes-gcm` 0.10
- `hmac` 0.12

---

## 2026-03-21

### vti-common `0.1.1` (new crate)

- **Shared foundation crate** — Extracts common code
  from `vta-service` and `vtc-service` into a shared
  library: auth (JWT, sessions, extractors), ACL, error
  types, config types, and the fjall key-value store.
- **Key-only prefix scan** — New `prefix_keys()` method
  on `KeyspaceHandle` for efficient iteration when only
  keys are needed (no value decryption overhead).

### vta-service `0.1.3`

- **Audit logging system** — New structured audit log
  with persistence to fjall keyspace. Includes REST
  endpoints (`GET /audit/logs`, `GET /audit/retention`,
  `PATCH /audit/retention`) and DIDComm protocol
  support. Audit events emitted via tracing at the
  `audit` target and persisted for API retrieval.
- **Connection rate limiting** — Enclave proxy now
  enforces a configurable maximum concurrent connection
  limit (default 256) per proxy channel to prevent
  resource exhaustion.
- **Refactored to use vti-common** — Auth, ACL, store,
  error, and config modules now delegate to the shared
  `vti-common` crate, reducing duplication with
  `vtc-service`.
- **Code quality cleanup** — Eliminated unnecessary
  `KeyspaceHandle::clone()` calls in auth routes,
  combined redundant config lock acquisitions, removed
  duplicate `AuditLogQuery` struct in favor of SDK's
  `ListAuditLogsBody`, and optimized audit cleanup to
  use key-only iteration.

### vtc-service `0.1.2`

- **Refactored to use vti-common** — Auth, ACL, store,
  error, and config modules now delegate to the shared
  `vti-common` crate.

### vta-sdk `0.1.2`

- **Audit management protocol** — New
  `audit_management` module with types and client
  methods for listing audit logs
  (`list_audit_logs`), querying retention
  (`get_audit_retention`), and updating retention
  (`update_audit_retention`).

### vta-cli-common `0.1.2`

- **Audit commands** — New `cmd_list_audit_logs` (with
  colored table output), `cmd_get_retention`, and
  `cmd_update_retention` commands.
- **Simplified `cmd_list_audit_logs` API** — Accepts
  `&ListAuditLogsBody` directly instead of 8 individual
  parameters.

### pnm-cli `0.1.2`

- **`pnm audit list`** — List audit logs with filtering
  by time range, action, actor, outcome, and context.
- **`pnm audit retention get/set`** — View and update
  audit log retention period.

### Security Documentation

- **Security architecture** (`docs/security-architecture.md`)
  — Comprehensive security architecture document.
- **Threat model** (`docs/threat-model.md`) — Detailed
  threat model analysis.

---

## 2026-03-16

### vta-sdk `0.1.1`

- **Context provision bundle** — New
  `ContextProvisionBundle` type for encoding/decoding
  portable application onboarding bundles (context
  credentials, VTA config, and optional DID material).
- **Pluggable session storage (`SessionBackend` trait)**
  — `SessionStore` now uses a `SessionBackend` trait
  instead of compile-time feature flags. Consumers can
  provide their own storage implementation via
  `SessionStore::with_backend()`. Built-in backends
  (keyring, file, Azure) remain available as trait
  implementations.
- **DID log retrieval** — New `get_did_webvh_log()`
  client method and `GET_DID_WEBVH_LOG` protocol
  constant for retrieving stored DID logs.
- **Context deletion preview** — New
  `preview_delete_context()` and `delete_context()`
  client methods with cascading resource cleanup.
- **Serverless DID creation** —
  `CreateDidWebvhRequest` now supports an optional
  `url` field for serverless DID creation. Response
  includes `did_document` and `log_entry` for
  self-hosting.

### vta-service `0.1.2`

- **Serverless WebVH DID creation (`--did-url`)** —
  Create a DID document and log entry locally without
  a pre-registered WebVH server. Keys are derived and
  stored, and the DID document and log entry are
  returned for self-hosting.
- **Cascading context deletion** — Deleting a context
  removes all associated keys, WebVH DIDs (and logs),
  and cleans up ACL entries. A preview endpoint lets
  callers inspect what will be removed before
  committing.
- **DID log retrieval API** — New
  `GET /webvh/dids/{did}/log` endpoint (REST and
  DIDComm) to retrieve the stored DID log for a given
  WebVH DID.
- **Serverless DIDs now persist data** — Serverless
  DID creation stores the `WebvhDidRecord`, DID log,
  and updates the context DID field, matching
  server-managed behavior.
- **Upgraded to didwebvh-rs 0.3 `create_did()` API**
  — Replaced manual `DIDWebVHState` +
  `create_log_entry` + SCID/DID extraction with the
  high-level `CreateDIDConfig` builder and
  `create_did()`. DID documents now use `{DID}`
  placeholders.

### vta-cli-common `0.1.1`

- **`cmd_context_provision`** — Creates a context,
  generates admin credentials, and optionally creates
  a WebVH DID. Outputs a portable base64 bundle for
  application onboarding.
- **`cmd_context_reprovision`** — Regenerates a
  provision bundle for an existing context. Supports
  selecting an existing VTA-stored key interactively
  or via `--key`, or creating a new admin key.
  Includes full DID material (document, log entry,
  secrets).
- **`cmd_context_delete`** — Cascading delete with
  preview and interactive confirmation.
- **Serverless DID support** in
  `cmd_webvh_did_create` via `--did-url`.

### pnm-cli `0.1.1`

- **`pnm context provision`** — Single command for
  application onboarding with optional DID creation.
- **`pnm context reprovision`** — Regenerate provision
  bundles for existing contexts.
- **`pnm context delete`** — Cascading delete with
  preview and `--force` flag.
- **`pnm webvh create-did --did-url`** — Serverless
  DID creation.

### cnm-cli `0.1.1`

- **`cnm context delete`** — Cascading delete with
  preview and `--force` flag.

### vtc-service `0.1.1`

- **Upgraded to didwebvh-rs 0.3 `create_did()` API**
  — Same refactoring as vta-service for DID creation
  flows.

### Dependency Updates (all crates)

- `didwebvh-rs` 0.2 → 0.3
- `affinidi-tdk` 0.5 → 0.6
- `azure_security_keyvault_secrets` 0.11 → 0.12
- `azure_identity` 0.32 → 0.33
- All compatible transitive dependencies updated to
  latest versions
