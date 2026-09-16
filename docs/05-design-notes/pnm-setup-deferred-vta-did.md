# Spec: Deferred-VTA-DID `pnm setup` (non-TEE)

Status: Phase 1 / Specify — pending approval to advance to Phase 2 (Plan).
Target branch: `sealed-bootstrap` (0.5.0, unreleased).

## Objective

Enable a two-phase `pnm setup` flow where the PNM admin `did:key` can be
minted and shown to the operator **before** the VTA exists. This unblocks
**automated VTA hosting**: `vta setup --from <setup.toml>` already accepts
an optional `admin_did` input (`vta-service/src/setup/from_toml.rs:113`).
Today PNM demands the VTA DID first, so the operator can't pre-mint the
admin DID — they have to set up the VTA, copy its DID back to PNM, run
`pnm setup`, then run `vta import-did` separately. Deferred-VTA-DID
collapses this to: mint in PNM → paste into VTA setup → finish PNM after
VTA boots.

## Success criteria

1. `pnm setup` (interactive) prints the ephemeral admin `did:key` on the
   first screen, with guidance pointing operators at
   `vta setup --from setup.toml` (`admin_did = "<pasted>"`) or
   `vta import-did --did <pasted> --role admin`.
2. `pnm setup --name <n>` (non-interactive) mints + persists pending
   state + prints the DID to stdout as JSON, then exits 0. Suitable for
   CI / Terraform / shell pipelines.
3. If the operator provides a VTA DID in the interactive wizard →
   behaviorally identical to today's flow (session stored
   `needs_rotation`, same `vta import-did` guidance, same auto-rotate on
   first authenticate).
4. If VTA DID is left blank (interactive) or not available yet
   (non-interactive) → PNM persists a **pending** VTA record. Operator
   later runs `pnm setup continue <vta-name>` (interactive) or
   `pnm setup continue <vta-name> --vta-did <did>` (non-interactive) to
   finish.
5. `pnm setup continue` is idempotent w.r.t. the ephemeral keypair —
   same `did:key` survives both phases; no new key is minted at
   continuation. This is the core value proposition: the operator has
   already handed the phase-1 DID to the VTA.
6. Authenticated commands (`pnm health`, `pnm keys list`, …) against a
   pending slug fail fast with a targeted "run `pnm setup continue
   <slug>`" message.
7. Running `pnm setup` or `pnm setup --name <n>` with a slug that is
   already in-flight (pending) warns and prompts to override
   (interactive) or requires `--overwrite` (non-interactive). Running
   against a slug that is already **complete** is an error in both
   modes; overwriting a completed VTA requires the existing
   `pnm vta delete` path first (out of scope).
8. Existing one-shot `pnm setup` users experience zero behavior change
   beyond **prompt ordering** (DID shown first, then name + VTA DID).

## Tech stack

No new workspace dependencies. Uses existing: `dialoguer`, `clap`,
`serde`, `serde_json`, `toml`, `ed25519-dalek`, `vta-sdk`,
`vta-cli-common::local_keygen`.

## Commands

```
# Interactive: mint, optionally capture VTA DID, else leave pending.
pnm setup

# Non-interactive phase 1: mint + persist pending, emit JSON.
pnm setup --name <human-name> [--overwrite]
  → stdout: {"slug": "<slug>", "admin_did": "did:key:z...", "state": "pending"}

# Phase 2 (interactive): finish setup for a pending slug.
pnm setup continue <slug>

# Phase 2 (non-interactive): finish setup, no prompts.
pnm setup continue <slug> --vta-did <did:...>
  → stdout: {"slug": "<slug>", "admin_did": "did:key:z...", "state": "complete"}
```

Flags:
- `--name` (required for non-interactive phase 1). Accepts a human-readable
  string; slugified the same way as today.
- `--overwrite` (non-interactive phase 1 only). Required iff a pending
  entry already exists for the slug. Never permits overwriting a complete
  VTA — operator must remove the existing one first.
- `--vta-did` (non-interactive phase 2). Must start with `did:`.
- `--json` implied on all non-interactive paths. No separate flag.

Bare `pnm setup` (no `--name`, no subcommand) stays interactive — today's
shape.

## Code locations touched

```
pnm-cli/src/main.rs
  → Commands::Setup gains an optional subcommand group:
    Setup { #[command(subcommand)] command: Option<SetupCommands>, name, overwrite }
  → new SetupCommands::Continue { slug, vta_did }

pnm-cli/src/setup.rs
  → split connect_to_non_tee_vta into:
      start_non_tee_setup_interactive()
      start_non_tee_setup_non_interactive(name, overwrite)
      continue_non_tee_setup_interactive(slug)
      continue_non_tee_setup_non_interactive(slug, vta_did)
  → shared helpers: mint_ephemeral_identity(), finalize_session()
  → setup_tee() untouched.

pnm-cli/src/auth.rs
  → new pub fn store_pending_vta_binding(keyring_key, did, private_key)
    (no vta_did arg — this is the breaking change)
  → existing store_session / store_session_pending_rotation keep their
    signatures but now forward to a session-store API that accepts
    Option<&str> for vta_url (already Option) + maintains the invariant
    that needs_rotation ⇒ vta_did.is_some()

pnm-cli/src/config.rs
  → resolve_vta() detects pending state (VtaConfig.vta_did.is_none() AND
    keyring has a PendingVtaBinding entry) and returns a new error variant
    PnmError::PendingSetup { slug } with the corrective hint.
  → VtaConfig already has vta_did: Option<String> — no schema change.

vta-sdk/src/session.rs   [BREAKING]
  → Session.vta_did: Option<String>           (was: String)
  → SessionInfo.vta_did: Option<String>       (was: String)
  → SessionStatus.vta_did: Option<String>     (was: String)
  → LoginResult.vta_did: Option<String>       (was: String)
  → SessionStore::store_pending_vta_binding(key, did, private_key)
    new method; stores `{ client_did, private_key, vta_did: None,
    needs_rotation: false, access_token: None, access_expires_at: None }`
  → SessionStore::bind_vta_did(key, vta_did, vta_url)
    new method; lifts a pending entry into a needs_rotation session.
    Errors if the entry already has a vta_did bound.
  → ensure_authenticated() + connect() + every method that today returns
    Err on a missing vta_did now return a typed error variant so the CLI
    layer can emit the "run `pnm setup continue`" hint.

cnm-cli/src/auth.rs   [BREAKING — compilation only]
  → forward the new Option<&str> / field shape; no new CNM setup flow.
    CNM is a separate operator surface — it doesn't need deferred-VTA-DID
    today. Only fixed for compilation.

vta-cli-common/src/local_keygen.rs
  → add generate_unbound_admin_did_key() returning just (did,
    private_key_multibase) — no CredentialBundle (which requires vta_did).
    Sibling of the existing generate_admin_did_key(), not a replacement.

docs/02-vta/cold-start.md   → add §on deferred-VTA-DID flow
docs/02-vta/non-interactive-setup.md → document the non-interactive variants
CHANGELOG.md (0.5.0 entry, unreleased) → note the feature + breaking change
```

No changes to: `vta-service`, `vta-enclave`, `didcomm-test`, any wire
formats, any routes, any DIDComm protocols, attestation, sealed-transfer.
This is purely a PNM-side UX + a contained SDK session-store breaking
change.

## Persistence model

**Single source of truth: the OS keyring** (existing
`SessionStore` with the `keyring` feature), keyed by slug as today
(`vta:<slug>`). No separate on-disk pending file — the keyring is the
secure store, reused.

Three session states, all stored in the same keyring entry:

| state | `vta_did` | `needs_rotation` | usable for auth? |
|---|---|---|---|
| **Pending VTA binding** | `None` | `false` | no — error with `pnm setup continue <slug>` |
| **Pending rotation** | `Some(did)` | `true` | yes — rotates on first successful auth |
| **Direct** | `Some(did)` | `false` | yes — TEE flow, no rotation |

State transitions:
```
(nothing)
    │
    │ pnm setup --name foo
    ▼
Pending VTA binding
    │
    │ pnm setup continue foo --vta-did did:...
    ▼
Pending rotation
    │
    │ first successful authentication
    ▼
Direct (post-rotation)
```

`PnmConfig.vtas[slug]` mirrors the state via `vta_did: Option<String>`:

```toml
# Pending:
[vtas.my-vta]
name = "My VTA"
# vta_did omitted

# Complete:
[vtas.my-vta]
name = "My VTA"
vta_did = "did:webvh:..."
```

**Invariant:** `vta_did.is_none()` in `VtaConfig` MUST correspond to a
keyring entry in the `PendingVtaBinding` state. If the keyring entry is
missing, the config is orphaned and `resolve_vta` returns the generic
"not configured" error, not the pending-setup hint.

## Prompt flow — phase 1 (interactive)

```
$ pnm setup
What would you like to do?
  > Connect to an existing non-TEE VTA
    Set up a new VTA in a TEE ...

Generating ephemeral admin identity...

  Admin DID: did:key:z6Mk...

  Next steps:
    1. Use this DID when setting up the VTA. Either:
         a. Run: vta setup --from setup.toml
            with:  admin_did = "did:key:z6Mk..."
         b. Or, on an already-running VTA:
            vta import-did --did did:key:z6Mk... --role admin
    2. Once the VTA is running, finish here with:
         pnm setup continue <name-you-pick>

Name for this VTA: my-vta
VTA DID (leave blank to finish setup later):

Saved pending VTA 'my-vta'.
Run `pnm setup continue my-vta` once the VTA is running and you know its DID.
```

If VTA DID is typed at the blank prompt → today's path (store session
pending rotation, print `vta import-did` hint, done).

If slug `my-vta` already has a **pending** keyring entry → prompt:
```
A pending setup already exists for 'my-vta':
  Admin DID: did:key:z6Mk...
  Created:   2026-04-24T12:34:56Z

  [1] Show the existing DID again and continue pending
  [2] Override — mint a fresh DID, discard the old keypair
  [3] Cancel

Choose:
```

If slug `my-vta` already has a **complete** keyring entry → error:
```
error: 'my-vta' is already set up (VTA DID: did:webvh:...)
hint:  use `pnm vta show my-vta` to inspect, or
       `pnm vta delete my-vta` to start over.
```

## Prompt flow — phase 1 (non-interactive)

```
$ pnm setup --name "My VTA"
{"slug": "my-vta", "admin_did": "did:key:z6Mk...", "state": "pending"}

$ pnm setup --name "My VTA"
error: pending setup already exists for slug 'my-vta'
hint:  pass --overwrite to replace, or `pnm setup continue my-vta` to finish it.
exit code: 2

$ pnm setup --name "My VTA" --overwrite
{"slug": "my-vta", "admin_did": "did:key:z6Mk...new...", "state": "pending"}

$ pnm setup --name "Existing"    # slug 'existing' is complete
error: 'existing' is already set up (VTA DID: did:webvh:...)
hint:  `pnm vta delete existing` to start over.
exit code: 2
```

Stderr carries human-readable guidance on the happy path too (mirroring
today's color output). stdout is JSON-only so scripts can `jq` it
without stripping banners.

## Prompt flow — phase 2 (interactive)

```
$ pnm setup continue my-vta
Continuing setup for 'my-vta'.

  Admin DID: did:key:z6Mk...   (unchanged from phase 1)

VTA DID: did:webvh:abc:vta.example.com:primary

Stored session for 'my-vta'.

Ask your VTA admin to grant this identity admin access:
  vta import-did --did did:key:z6Mk... --role admin

Once the grant is in place, run any PNM command (e.g. `pnm health`). PNM
will rotate to a fresh long-lived did:key on first connect.
```

## Prompt flow — phase 2 (non-interactive)

```
$ pnm setup continue my-vta --vta-did did:webvh:...
{"slug": "my-vta", "admin_did": "did:key:z6Mk...", "state": "complete"}
```

## Error matrix

| Situation | Exit code | stdout | stderr |
|---|---|---|---|
| `pnm setup continue` (no slug) | clap 2 | — | usage |
| `pnm setup continue <slug>` — slug unknown | 2 | — | "no pending VTA '<slug>'" + `pnm vta list` hint |
| `pnm setup continue <slug>` — slug complete | 2 | — | "'<slug>' is already set up" + `pnm vta show` hint |
| `pnm setup continue <slug>` — config complete but keyring missing | 2 | — | "keyring entry missing" + recovery guidance |
| `pnm setup --name X` — slug pending, no `--overwrite` | 2 | — | "pending setup exists" + `--overwrite` or `continue` hint |
| `pnm setup --name X` — slug complete | 2 | — | "already set up" + `pnm vta delete` hint |
| Any authenticated command against a pending slug | 2 | — | "'<slug>' is pending setup — run `pnm setup continue <slug>`" |
| Ctrl-C after DID shown but before keyring write | N/A | — | no state persisted; keypair discarded |
| Ctrl-C after keyring write but before config save | N/A | — | keyring entry is orphaned; next `pnm setup --name X` will prompt to override |

## Testing strategy

**Unit tests — `pnm-cli/src/setup.rs` / `auth.rs`:**
- `mint_ephemeral_identity()` produces a valid `did:key`, 32-byte seed,
  and roundtrippable private key multibase.
- `resolve_vta()` against a pending slug returns `PnmError::PendingSetup`
  with the expected slug.

**Unit tests — `vta-sdk/src/session.rs`:**
- `store_pending_vta_binding` + `bind_vta_did` round-trips through
  keyring (use the mock `SessionBackend` already present in tests).
- `bind_vta_did` rejects re-binding a session that already has a
  vta_did.
- Sessions in pending-VTA-binding state fail `ensure_authenticated`
  with a typed error, not a panic.

**Integration tests — `pnm-cli/tests/setup_deferred.rs` (new file):**
- Phase 1 (non-interactive) → phase 2 (non-interactive) yields the same
  terminal `VtaConfig` as today's one-shot flow.
- Phase 1 twice with `--overwrite` mints different `did:key`s; without
  `--overwrite`, second call exits 2.
- `did:key` is byte-identical across phase 1 → phase 2.
- Authenticated PNM commands against a pending slug error with the
  expected hint.
- TOML round-trip of `VtaConfig` with `vta_did: None` loads cleanly.

**Integration tests — `cnm-cli`:**
- Compile-only. No behavior change expected. Snapshot test against
  `cnm auth status` output to catch accidental regression from the
  `Option<String>` field change.

**Manual verification checklist** (documented, not automated):
- Run the interactive phase-1 → phase-2 flow end-to-end against a
  local dev VTA (non-TEE).
- Confirm the phase-1 DID appears unchanged in phase 2.
- Confirm `vta import-did` on the VTA grants the phase-1 DID and that
  `pnm health` triggers the auto-rotation.

**Out of scope for tests:** any TEE flow, any DIDComm path, any
sealed-transfer envelope. None of those are touched.

## Boundaries

**Always:**
- The ephemeral keypair minted in phase 1 is the keypair used in phase
  2 — never re-mint at continuation.
- Both phases write to the same keyring entry (`vta:<slug>`), reusing
  the `affinidi-secrets-resolver` / `keyring`-crate backend pick-chain
  already in `SessionStore`.
- `slugify()` behavior is unchanged; same slug → same keyring key.
- Non-interactive paths emit JSON on stdout, narration on stderr.
- A pending keyring entry is the authoritative flag for "pending
  state" — never infer pending state from anything else.

**Ask first:**
- Adding a `--force` flag that overwrites a *complete* VTA (out of
  scope for this spec; operator must use `pnm vta delete` today).
- Exposing a "bulk create N pending VTAs" path for fleet operators.
- Changing `vta_did: Option<String>` in `VtaConfig` to anything more
  structured (e.g., a state enum). Today it's already `Option` — keeping
  it avoids a second migration.

**Never:**
- Persist the ephemeral private key outside the keyring. No dotfile
  fallback under `~/.config/pnm/pending/`.
- Contact the VTA during phase 1 or phase 2. Setup stays fully offline
  — the operator is the transport between PNM and VTA in this flow.
- Rotate or discard the ephemeral keypair between phase 1 and phase 2.

## Breaking changes

1. `vta-sdk::session::{Session, SessionInfo, SessionStatus, LoginResult}`:
   `vta_did` field becomes `Option<String>`. Downstream must handle the
   pending case.
2. New required methods on `SessionBackend` / `SessionStore`:
   `store_pending_vta_binding`, `bind_vta_did`. External implementors
   of `SessionBackend` (none in-tree besides the built-ins) must add
   these.
3. `pnm-cli` `Commands::Setup` reshapes from unit variant to
   `Setup { command: Option<SetupCommands>, name, overwrite }`. Clap
   parses `pnm setup` (bare), `pnm setup --name foo`, and
   `pnm setup continue foo` all off the same subcommand.

Acceptable because 0.5.0 is unreleased and unmerged.

## Success criteria (restated as testable conditions)

- [ ] `pnm setup --name foo` (no `--vta-did`) exits 0 with the documented
      JSON stdout shape.
- [ ] Re-running `pnm setup --name foo` without `--overwrite` exits 2.
- [ ] Re-running with `--overwrite` mints a different DID (asserted via
      integration test).
- [ ] `pnm setup continue foo --vta-did ...` exits 0 and the resulting
      `VtaConfig` matches the one-shot flow.
- [ ] `pnm health` against a pending slug emits the targeted hint.
- [ ] `cnm-cli` still compiles and passes its existing test suite.
- [ ] `cargo test --workspace` green.
- [ ] `docs/02-vta/cold-start.md` and `docs/02-vta/non-interactive-setup.md`
      updated.

## Open questions (resolved)

All four from the previous round answered:
1. Pending ephemeral → OS keyring. Breaking-change budget accepted.
2. Multiple concurrent pending setups allowed. Per-slug collision
   warns interactively, requires `--overwrite` non-interactively.
3. Non-interactive mint-only mode required (`pnm setup --name …`).
4. Lands on `sealed-bootstrap`, under the 0.5.0 section of
   `CHANGELOG.md`.

No open questions remaining. Ready to advance to Phase 2 (Plan).
