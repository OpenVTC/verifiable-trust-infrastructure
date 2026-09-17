# Phase 5 Cutover: Removing Plaintext Bundle Encode/Decode

Status: **Design — not yet implemented**
Scope: workspace-wide (`verifiable-trust-infrastructure`)
Companion to: [`sealed-bootstrap.md`](sealed-bootstrap.md)

## Context

Phases 1–4 of Sealed Bootstrap landed. `vta_sdk::sealed_transfer` is the canonical transport for every sensitive bundle; `POST /bootstrap/request` replaces ad-hoc credential delivery in Modes A and B; REST key import uses sealed transfer (Phase 4).

The deprecation landed in `d15dd0c` flagged every remaining `.encode()` / `.decode()` call on `CredentialBundle`, `ContextProvisionBundle`, and `DidSecretsBundle` with a `#[deprecated(since = "0.4.2")]` attribute. Phase 5 deletes those methods.

The commit message explicitly deferred the actual cutover:

> actually removing the methods requires redesigning every provisioning and auth-login UX to accept armored sealed bundles instead of base64 strings — a dedicated refactor with its own design pass.

This is that design pass.

## Why Phase 5 is not mechanical

`.encode()` / `.decode()` are doing **three distinct jobs** in current code, and each needs a different replacement:

| Job | Current shape | Problem with Phase 5 delete | Correct replacement |
|---|---|---|---|
| **A. Intra-process plumbing** — "I have a `CredentialBundle`, I need to pass it to a function that takes a `&str`" (e.g. `auth::login(&encoded, ...)` inside `pnm bootstrap connect`). | Struct → base64 → pass → base64 → struct. | Pointless round-trip through a plaintext envelope. | Change function signatures to take `&CredentialBundle` directly. No serialization at all. |
| **B. At-rest storage** — pnm-cli persists opened credentials into the OS keyring (under `vta:<slug>`). | Stores the base64url-JSON envelope as the keyring value. | The envelope has no integrity, but the OS keyring already provides at-rest confidentiality — so the base64 wrapper adds complexity without adding protection. | Store canonical JSON (`serde_json::to_string(&bundle)`) in the keyring. Explicit `StoredCredentialV1` wrapper with a version tag, no claim of being a transport format. |
| **C. Transport across a trust boundary** — CLI prints the bundle to stdout for an operator to copy; REST endpoint returns it in a JSON body; setup wizard writes it to a file. | Plaintext base64url-JSON — exactly what Sealed Bootstrap was built to kill. | This is the whole point. | `vta_sdk::sealed_transfer` — armored sealed bundle, recipient pubkey from a `BootstrapRequest`. |

Phase 5 splits along those three jobs.

## Call-site inventory

Grouped by job (A/B/C) so the sub-phases can work one job at a time.

### Job A: intra-process plumbing (struct should cross the boundary, not a string)

- `vta-sdk/src/auth_light.rs:149–169` — `authenticate_with_credential(credential_b64: &str, ...)` decodes immediately. Callers already have a `CredentialBundle`.
- `vta-sdk/src/session.rs:411–420` — `Session::login(credential_b64: &str, ...)` decodes as its first step.
- `vta-sdk/src/integration/auth.rs:31` — integration layer decodes `config.credential`.
- `pnm-cli/src/setup.rs:62,189` — decodes a CLI-provided base64, re-encodes a new bundle for a discarded `_credential_b64` local (dead code lane — treat as removal, not rewrite).
- `pnm-cli/src/bootstrap.rs:181,324` — after opening a sealed bundle, `credential.encode()` is called solely to feed `auth::login(&encoded, ...)` or a `println!`. Once `auth::login` takes a struct, both calls disappear.
- `cnm-cli/src/setup.rs:163,320` — decodes `resp.credential` from the deprecated `/auth/credentials` endpoint. Folded into Job C when that endpoint goes away.

### Job B: at-rest keyring storage

**Verified during 5a implementation — this is a no-op.** The keyring does not store a base64-encoded `CredentialBundle`; it stores a JSON-serialized `Session` struct (see `vta-sdk/src/session.rs::Session` + `save_session`/`load_session`). The fields needed for auth (client DID, private key multibase, VTA DID, VTA URL, cached tokens) are already extracted and flattened at login time. No plaintext base64 exists at rest anywhere in pnm-cli or cnm-cli.

Confirmed by `rg 'base64|\.encode\(\)|\.decode\('` across both CLI crates after 5a: the only remaining hits are the `#[allow(deprecated)]` CLI-boundary decode sites explicitly marked for removal in 5c.

No migration, no `StoredCredential::V1` wrapper, no code change. 5b is satisfied by 5a.

No persistent disk storage of `ContextProvisionBundle` or `DidSecretsBundle` at rest either — they flow through stdout/file and get dismantled by the consumer.

### Job C: transport across a trust boundary (the real target)

- `vta-service/src/operations/credentials.rs:58` — `POST /auth/credentials` returns `{ credential: "<base64>" }`. Survived Phase 2: still plaintext.
- `vtc-service/src/routes/auth.rs:346` — VTC mirror of the same endpoint.
- `vta-cli-common/src/commands/contexts.rs:359` (`cmd_context_provision`), `:403` (`credential_from_key` helper), `:553` (`cmd_context_reprovision`) — print `ContextProvisionBundle` / `CredentialBundle` as base64 to stdout.
- `vta-cli-common/src/commands/keys.rs:349` — `cmd_key_bundle` prints `DidSecretsBundle` as base64 to stdout.
- `vta-service/src/setup.rs:1022` — first-boot wizard writes `DidSecretsBundle` as base64 to a user-chosen file.
- `vta-service/src/did_webvh.rs:249`, `vtc-service/src/did_webvh.rs:237` — DID-creation paths emit encoded secrets bundles.
- `vtc-service/src/setup.rs:916` — VTC setup wizard equivalent.

### Nested encoding (special case)

`ContextProvisionBundle.credential: String` at `vta-sdk/src/context_provision.rs:28` stores an *already-base64-encoded* `CredentialBundle`. Consumers decode the outer bundle, then decode the inner field separately. Phase 5 flattens this to `credential: CredentialBundle` — one fewer indirection and no residual `.encode()` call inside the provisioning path.

## Proposed API shape after cutover

### `vta-sdk::credentials`

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialBundle { /* unchanged fields */ }

impl CredentialBundle {
    pub fn new(...) -> Self { ... }
    pub fn vta_url(self, url: impl Into<String>) -> Self { ... }
    // No more encode/decode. Callers use serde_json or sealed_transfer.
}
```

Error type `CredentialBundleError` — deleted. Mirror for the other two bundle types.

### `vta-sdk::auth_light` / `vta-sdk::session`

```rust
// Before
pub async fn authenticate_with_credential(credential_b64: &str, ...) -> Result<...>;

// After
pub async fn authenticate_with_credential(credential: &CredentialBundle, ...) -> Result<...>;
```

`Session::login` changes the same way. The "login from base64" convenience goes away — there is no legitimate source of a base64 `CredentialBundle` post-cutover.

### `vta-sdk::context_provision`

```rust
pub struct ContextProvisionBundle {
    pub context_id: String,
    pub context_name: String,
    pub vta_url: Option<String>,
    pub vta_did: Option<String>,
    pub credential: CredentialBundle,   // was: String
    pub admin_did: String,
    pub did: Option<ProvisionedDid>,
}
```

`serde(rename_all = ...)` stays as-is. The only producers of this bundle are `vta-cli-common` and the VTC setup wizard; both move together in sub-phase 5c.

### At-rest keyring envelope (Job B)

No change. The keyring backend (`vta-sdk/src/session.rs`) already stores the `Session` struct as JSON — `serde_json::to_string` on write, `serde_json::from_str` on read. The fields needed at runtime (client DID, private key, VTA DID/URL, cached tokens) are extracted from the `CredentialBundle` at login time and flattened into the `Session`, which is the canonical at-rest form. Base64 is never involved.

Originally this section proposed a `StoredCredential::V1` wrapper for readability-under-incident and future-compat. Both properties are already satisfied: the JSON is already `jq`-friendly, and `Session` fields carry `#[serde(default)]` for additive evolution. Adding an explicit version tag would be future-proofing beyond what Phase 5 requires (see "Don't add things the task doesn't require"). If a future migration becomes necessary, introduce it then.

### CLI surfaces (Job C)

Provision and key-export commands acquire `--recipient` flags and emit armored output:

```
# Before
vta context provision --name foo --id foo
  → prints <base64 ContextProvisionBundle> to stdout

# After
vta context provision --name foo --id foo --recipient <bootstrap-request.json>
  → prints armored `-----BEGIN VTA SEALED BUNDLE-----` block to stdout
  → prints sha256 digest (for OOB verification) to stderr
```

The `--recipient` file is a `BootstrapRequest` JSON (existing Mode C shape): client pubkey + nonce + optional label. The consumer produces it with `pnm bootstrap request --out request.json` and hands it to the operator. Symmetric to Mode C's `vta bootstrap seal`.

Consumer side:

```
# Before
pnm auth login <base64>

# After
pnm auth login --credential-bundle bundle.armor [--expect-digest <hex>]
```

`pnm auth login` opens the armored bundle, verifies the producer assertion (DID-signed or attestation), extracts the `CredentialBundle`, and writes it to the keyring via the new `StoredCredential::V1` path. No base64 ever appears in the CLI argv.

`did-git-sign --credential <base64>` becomes `did-git-sign --credential-bundle <file>` — same shape, armored input.

### REST surfaces (Job C)

- `POST /auth/credentials` (vta-service + vtc-service) — **deleted**. The only legitimate callers are internal setup flows, which migrate to `POST /bootstrap/request`. External callers (if any) get 404 after upgrade; this is the intended Sealed Bootstrap behavior from the original design (see `sealed-bootstrap.md` §"Upgrade path").
- The `GetKeySecret` flow (REST key import) already uses sealed transfer after Phase 4 — no change.
- Setup wizards (`vta-service/src/setup.rs`, `vtc-service/src/setup.rs`) that currently write a DID-secrets bundle to disk as base64 change to: accept an operator pubkey (entered in the wizard from a `bootstrap request`), seal to it, write armored. Operators who want the bundle for offline stash pass `--print-digest` and record the digest out-of-band.

## Phased sub-steps

Each sub-phase compiles, passes CI, and is individually revertable.

### 5a — Struct plumbing (Job A)

1. Change `authenticate_with_credential`, `Session::login`, `integration::auth` entrypoints to take `&CredentialBundle`.
2. In `pnm-cli/src/bootstrap.rs`: delete the `.encode()` round-trip at line 324; pass the opened struct into `auth::login` directly.
3. Delete the dead-code encode at `pnm-cli/src/setup.rs:189`.
4. In `pnm-cli/src/setup.rs:62` and `cnm-cli/src/setup.rs:163,320` — these ingest a user-pasted base64 today. Leave them on the deprecated path for this sub-phase; they exit in 5c.

After 5a: internal code paths pass structs. The `.encode()/.decode()` deprecation warnings remain, but only at true trust-boundary sites.

### 5b — Keyring storage (Job B)

**No action required.** Verified during 5a that the keyring already stores JSON `Session` structs; no base64 at rest anywhere to migrate. See the updated "Job B" note above.

After 5a: no deprecated calls inside pnm-cli/cnm-cli outside of the scoped `#[allow(deprecated)]` CLI-boundary sites. The last `.encode()/.decode()` users are the user-facing CLI paste paths and the REST endpoints, all addressed in 5c.

### 5c — Trust-boundary transport (Job C)

Largest sub-phase; split into independent PRs if needed:

1. **ContextProvisionBundle struct flattening.** `credential: String → CredentialBundle`. Update `vta-cli-common/src/commands/contexts.rs:349–357` to assign the struct. Update every consumer that read the `.credential` field as a string. (Currently the only consumer is the outer encode() call at line 359, which is about to be replaced anyway.)
2. **CLI producers adopt `--recipient`**:
   - `vta context provision` / `reprovision`
   - `vta key bundle`
   Each reads a `BootstrapRequest` JSON, seals a `SealedPayloadV1::ContextProvision` / `::DidSecrets`, writes armored stdout, prints digest to stderr. Producer assertion is `DidSigned` using the operator's VTA admin key.
3. **Consumer paste paths become `--credential-bundle <file>`**:
   - `pnm auth login` / `pnm setup` accept armored input.
   - `cnm-cli setup` mirrors.
   - `did-git-sign` flag rename.
   - `openvtc-cli2` TUI — replace the base64 paste page with a "drop armored bundle" page.
4. **REST `/auth/credentials` deletion.** Remove the route, the `operations/credentials.rs` encode call, and the dependent helpers in vta-service and vtc-service. Confirm no consumer inside the workspace — everything goes through `/bootstrap/request` now.
5. **Setup-wizard DID-secrets export** (`vta-service/src/setup.rs:1022`, `vtc-service/src/setup.rs:916`, `*/did_webvh.rs`): same pattern as §2.

After 5c: zero in-workspace call sites of `.encode()` / `.decode()` on the three bundle types.

### 5d — Delete the methods

1. Remove `.encode()`, `.decode()`, `CredentialBundleError`, `ContextProvisionBundleError`, `DidSecretsBundleError` base64 variants from `vta-sdk`.
2. Remove the `base64` import from the three bundle modules (if unused).
3. Remove the `#[allow(deprecated)]` from the test modules; replace the round-trip tests with `serde_json` round-trips to lock the on-wire struct shape.
4. Bump `vta-sdk` from `0.4.x` to `0.5.0` (breaking API change). Bump every dependent workspace crate's `vta-sdk` dep from `0.4` → `0.5`.

## Compatibility

### In-flight bundles

None. Bundles are single-use and ephemeral — a pasted base64 credential either succeeds once and is stored, or is discarded. There is no coordinated flight of bundles to migrate. Any operator mid-bootstrap at upgrade time restarts with the new CLI flags; the operation is seconds long.

### Stored keyring entries

Sub-phase 5b handles this — legacy base64 is auto-migrated on next read. Operators see no disruption.

### Third-party consumers of `/auth/credentials`

None known inside the workspace. External consumers (if any) get a 404 and must adopt `POST /bootstrap/request`. This matches `sealed-bootstrap.md`'s declared upgrade policy.

### Versioning

- `vta-sdk` → `0.5.0` (breaks public API).
- `vta-service`, `vtc-service`, `vta-cli-common`, `pnm-cli`, `cnm-cli`, `did-git-sign`, `vta-enclave` — bump minor, update `vta-sdk` dep to `0.5`.

## Resolved decisions

1. **`pnm auth login --credential-bundle <file>` supports `--no-verify-digest`.** Default strict with explicit opt-out warning — matches `pnm bootstrap open`.
2. **CLI producers accept both `--recipient <file>` and `--recipient-pubkey <b64>`.** File form is the normal workflow; inline is the escape hatch for terminals without convenient file transfer. Mirrors `pnm bootstrap seal`.
3. **`openvtc-cli2` TUI offers both file-path and paste-field input, user's choice.** Two-step wizard: pick input method, then provide. Layout decided last in sub-step 5c3.
4. **`ProvisionedDid.secrets` (nested in `ContextProvisionBundle`) inherits the outer sealing — no separate envelope.**
5. **`vta-service/src/did_webvh.rs:249` and `vtc-service/src/did_webvh.rs:237` sealing requirement** — verify during 5c5 whether they're internal helpers (serde_json) or trust-boundary crossings (sealed transfer).

## Out of scope

- Changes to `sealed_transfer` itself (already stable after Phase 4).
- Changes to the armor format or digest algorithm.
- Coordination with the separate `openvtc` workspace (tracked separately; this design is workspace-internal only).
- Feature flags or backwards-compat shims for the deleted methods — Sealed Bootstrap's declared policy is clean cutover.
