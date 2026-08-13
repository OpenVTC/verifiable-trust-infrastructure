# Design note: tenant-config allowlist (replace whole-config-over-vsock)

Status: **Implemented** (T1–T5). The allowlist overlay (`vta-config::tenant_overlay`),
the `vta_did` store-precedence fix (`vta-tee/src/did_autogen.rs`), the Rust-side
vsock fetch/apply behind the `tenant-overlay` Cargo feature
(`vta-tee::tenant_overlay` + `vta-enclave` wiring), the `deploy/nitro/*` +
`Dockerfile.nitro` fleet-base/overlay changes, and the doc fixes below are all in
tree. The DEV/PROD single-image question (§3.5 / §8.1, T6) remains open.
Tracking: supersedes the whole-config vsock delivery designed in
`a4c16512`..`a7d32c1f` (the "un-bake tenant config" PR chain). **That chain
has not merged to `main` and has not been deployed anywhere** — it is the
same still-open GitHub PR this note is amending, still under implementation
review. Nothing below is a migration of a running system; it's a correction
to an in-flight design before it ships. Depends on nothing new; touches
`vta-config`, `vta-tee`, `vta-enclave`, `deploy/nitro/*`.

**Amended per review**: an earlier draft of this note proposed collapsing
`BAKE_CONFIG` into a single always-baked-base image (§3.1 below, old text).
That is reverted. `BAKE_CONFIG` is **kept** as a hard build-time gate:
`BAKE_CONFIG=true` (single-tenant/self-host) continues to ship zero vsock
config-fetch code and zero parent-side config listener — an image property,
not a runtime-data property. The allowlist/overlay redesign in this note
applies **only** to the `BAKE_CONFIG=false` (fleet) branch, which is the only
branch that ever had the denylist gap described in §2. See §3.1 for the
rationale.

Related code (current-state map, verified while writing this note):
- Whole-config fetch (to be replaced): `deploy/nitro/enclave-entrypoint.sh:186-259`
  (`fetch_config_over_vsock`), `deploy/nitro/enclave-proxy/src/channels.rs:618-672`
  (`run_config_server`).
- Denylist floor (to be narrowed, not removed): `vta-enclave/src/main.rs:454-494`
  (`config_floor_violation`).
- The five ungated break-glass flags: `vta-config/src/lib.rs:505-579`
  (`TeeKmsConfig::allow_unattested_fallback/allow_fingerprint_init/
  allow_kms_reinit/allow_anchor_init/allow_unanchored`).
- The stale safety premise: `docs/05-design-notes/tee-anti-rollback-anchor.md:440-447`
  (Open-Q#4, "RESOLVED" on the assumption that TEE config is always baked —
  no longer true once un-baked mode exists).
- The build-time all-or-nothing toggle to be superseded:
  `Dockerfile.nitro:56-204` (`BAKE_CONFIG`), `deploy/nitro/build-vta.sh:69-75,429-434`.
- The vsock connect-with-retry pattern to reuse:
  `vta-enclave/src/main.rs:50-78` (`connect_vsock_with_retry`),
  `vti-common/src/store/vsock.rs:67-90` (`VsockConnection::connect`).
- The store-precedence gap to close in the same slice:
  `vta-tee/src/did_autogen.rs:59-89` (`maybe_generate_vta_did`).

---

## 1. Objective

Replace "send the whole `config.toml` over vsock, then denylist the fields
we thought of" with "bake everything except a small, named tenant overlay;
the enclave parses the overlay into a `#[serde(deny_unknown_fields)]` struct,
so a field that isn't named **cannot** reach the running config, full stop."

Concretely, after this work:

- Sending `allow_unanchored = true` / `allow_kms_reinit = true` /
  `allow_unattested_fallback = true` / `allow_fingerprint_init = true` inside
  the tenant channel is **structurally impossible** (no field carries it),
  not merely rejected by a floor that has to be kept in sync by hand.
- `tee.kms.key_arn` is validated against a **baked, compiled-in** allowlist of
  AWS account IDs before it is used for anything.
- `docs/05-design-notes/tee-anti-rollback-anchor.md` Open-Q#4 is re-resolved
  honestly instead of left referencing a premise this repo already broke.
- The `BAKE_CONFIG` build-time gate **stays** — `BAKE_CONFIG=true`
  (single-tenant/self-host) remains a fully-baked image with no vsock
  config-fetch code and no parent-side config listener at all, exactly as
  today. The allowlist/typed-overlay work below replaces the whole-config
  delivery **only** in the `BAKE_CONFIG=false` (fleet) branch, which is
  where the denylist gap in §2 actually lives.

## 2. Why the current design (denylist-on-whole-config) doesn't hold

Already demonstrated in review and confirmed against the tree:

- The floor (`config_floor_violation`) checks 3 fields. `TeeKmsConfig` has
  ~15. Every field the floor doesn't name is silently parent-controlled the
  moment `BAKE_CONFIG=false`.
- Extending a denylist is an *ongoing tax*: each new `TeeKmsConfig` field
  (already up to 5 `allow_*` bools plus `anchor`) requires someone to
  remember to add a floor rule. Nothing fails the build if they don't.
- The anti-rollback design note's own justification for defaulting
  `allow_unanchored = false` — "safe to expose as config because TEE config
  is baked into the measured EIF, so the parent can't flip it at
  runtime" — is **falsified** by `BAKE_CONFIG=false` existing at all. That
  note was never revisited when the un-baking PRs landed.
- `key_arn` has zero validation of any kind — not account, not region,
  not even ARN shape.

An allowlist inverts the failure mode: a bug is "I forgot to add a field
tenants clearly need" (a support ticket), not "I forgot to add a floor rule
for a field that grants root" (a security incident).

## 3. Design

### 3.1 Keep `BAKE_CONFIG` as a hard build-time gate; allowlist applies only to the un-baked branch

`BAKE_CONFIG=true` builds (single-tenant / self-host) keep working exactly
as today: `config.toml` is fully rendered at build time and baked into the
EIF (measured into PCR0) via `Dockerfile.nitro`'s existing `COPY` path; the
resulting binary contains **no vsock config-fetch/parse/apply code path**,
and `deploy-enclave.sh` never passes `--config-envelope`, so
`enclave-proxy`'s `run_config_server` is never started — there is no
listener to reach. This is a *code-path absence*, not merely "an unused
code path that happens not to trigger" — it is provable from PCR0 + a code
audit with no dependency on runtime data, and it is strictly what a
security-conscious self-host operator wants: zero vsock config exposure,
full stop.

An earlier draft of this section proposed collapsing `BAKE_CONFIG` into a
single always-baked-base image, where every image ships the overlay-fetch
code and `vta-enclave` decides at runtime whether to invoke it (e.g., "is
`key_arn` a placeholder?"). That is **rejected** on review: it downgrades
single-tenant deployments from "the fetch code doesn't exist" to "the fetch
code exists, gated by a runtime heuristic over config-field shape." That
heuristic can misfire, it makes the PCR0/attestation claim strictly weaker
(the auditor now has to trust the trigger condition, not just its absence),
and it wires a parent-side vsock listener into deployments that never
wanted one — all for zero security benefit to the multi-tenant case, whose
actual problem (the denylist gap, §2) is fixed entirely by §3.2's typed
overlay regardless of how many Dockerfile stages exist.

So: two Dockerfile stages remain, selected by `BAKE_CONFIG` at build time,
same as today —

- **`BAKE_CONFIG=true`** (single-tenant/self-host, default): `config.toml`
  fully rendered and baked; the overlay-fetch module (§3.8) is excluded from
  the build (a Cargo feature, not a runtime `if`) so the binary contains no
  vsock-config code; `enclave-entrypoint.sh` goes straight to
  `exec vta-enclave --config "$CONFIG_PATH"`; `enclave-proxy` is never asked
  to run `run_config_server`.
- **`BAKE_CONFIG=false`** (fleet): `config.toml` bakes every field *outside*
  the §3.3 allowlist (fleet policy, with placeholders for the tenant-scoped
  fields); the overlay-fetch module is included; `vta-enclave` fetches,
  parses (`deny_unknown_fields`), validates, and applies the typed
  `TenantConfigOverlay` (§3.2–3.7) instead of the old whole-config denylist
  path.

Everything else in this note — the typed overlay, `deny_unknown_fields`,
`key_arn` account-allowlisting, the Rust-side
fetch module — is unchanged and applies exclusively inside the
`BAKE_CONFIG=false` branch. Single-tenant/self-host builds are untouched by
this whole redesign; they neither gain nor need it.

### 3.2 The overlay is a typed, `deny_unknown_fields` struct — not TOML text

New types in `vta-config` (or a new `vta-config::tenant_overlay` module):

```rust
/// Everything a fleet operator is allowed to hand a running enclave at
/// runtime, over vsock:5800. Anything not named here CANNOT reach the
/// enclave's config — `deny_unknown_fields` makes an unrecognized key a
/// hard parse error, not a silently-ignored one.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TenantConfigOverlay {
    #[serde(default)]
    pub vta_did: Option<String>,
    #[serde(default)]
    pub vta_name: Option<String>,
    #[serde(default)]
    pub public_url: Option<String>,
    #[serde(default)]
    pub tee_kms: Option<TenantKmsOverlay>,
    #[serde(default)]
    pub messaging: Option<TenantMessagingOverlay>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TenantKmsOverlay {
    /// Full KMS key ARN. Region is *derived* from the ARN (see 3.5) rather
    /// than accepted as a separate field, so there is no "region says X,
    /// key_arn says Y" ambiguity to adjudicate.
    pub key_arn: String,
    #[serde(default)]
    pub vta_did_template: Option<String>,
    #[serde(default)]
    pub anchor_table_name: Option<String>,
    #[serde(default)]
    pub anchor_writer_credential_ciphertext: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TenantMessagingOverlay {
    #[serde(default)]
    pub mediator_did: Option<String>,
    #[serde(default)]
    pub mediator_url: Option<String>,
}
```

Note what is **absent** on purpose: `admin_did`, `mode`, `embed_in_did`,
`attestation_cache_ttl`, `allowed_did_methods`, `storage_key_salt`,
`admin_context_id`, every `allow_*` bool, `resolver_url`, `server.*`,
`log.*`, `store.*`, `services.*`, `policy.*`,
`trusted_presentation_verifiers`. None of these types can carry them —
`serde(deny_unknown_fields)` turns "operator typos a field name" and "a
malicious parent injects an unlisted field" into the *same* parse error,
which is exactly the fail-closed property a denylist can't give you.

**Applying** the overlay is explicit field-by-field assignment (never a
generic/recursive merge, so the "what can change" set is visible in one
function body, not implied by struct shape):

```rust
pub fn apply_tenant_overlay(base: &mut AppConfig, overlay: TenantConfigOverlay)
    -> Result<(), TenantOverlayError>
{
    if let Some(v) = overlay.vta_did { base.vta_did = Some(v); }
    if let Some(v) = overlay.vta_name { base.vta_name = Some(v); }
    if let Some(v) = overlay.public_url { base.public_url = Some(v); }
    if let Some(kms_overlay) = overlay.tee_kms {
        let kms = base.tee.kms.as_mut()
            .ok_or(TenantOverlayError::BaseMissingKmsSection)?;
        validate_key_arn(&kms_overlay.key_arn, &base.tee.kms_allowed_accounts)?; // §3.5
        kms.key_arn = kms_overlay.key_arn;
        kms.region = region_from_arn(&kms.key_arn)?;               // §3.5, derived
        if let Some(v) = kms_overlay.vta_did_template { kms.vta_did_template = Some(v); }
        if let Some(v) = kms_overlay.anchor_table_name { /* .anchor.table_name */ }
        if let Some(v) = kms_overlay.anchor_writer_credential_ciphertext { /* .anchor.writer_credential_ciphertext */ }
    }
    if let Some(m) = overlay.messaging {
        let msg = base.messaging.get_or_insert_default();
        if let Some(v) = m.mediator_did { msg.mediator_did = Some(v); }
        if let Some(v) = m.mediator_url { msg.mediator_url = Some(v); }
    }
    Ok(())
}
```

### 3.3 Allowlist table (matches the proposal, both columns)

| Hardcoded (baked, never in the overlay type) | Passed via overlay (validated) |
|---|---|
| `tee.mode = "required"` | `tee.kms.key_arn` (account+shape validated, §3.5) |
| `tee.kms.allow_unattested_fallback = false` | `tee.kms.region` — **derived from key_arn**, not accepted separately |
| `tee.kms.allow_fingerprint_init = false` | `tee.kms.vta_did_template` / `vta_did` (first-boot only, §3.6) |
| `tee.kms.allow_kms_reinit = false` | `messaging.mediator_did` |
| `tee.kms.allow_unanchored = false` | `messaging.mediator_url` |
| `tee.kms.allow_anchor_init = true` *(only if `anchor.table_name` also baked-required)* | `public_url` |
| `tee.embed_in_did`, `tee.attestation_cache_ttl`, `tee.allowed_did_methods` | `vta_name` (optional) |
| `tee.kms.admin_context_id` | `tee.kms.anchor.table_name` |
| `resolver_url`, `server.*`, `store.*`, `log.*`, `services.*` | `tee.kms.anchor.writer_credential_ciphertext` (self-protecting — KMS-sealed) |
| `policy.*`, `trusted_presentation_verifiers` | — |
| **`tee.kms.allowed_accounts`** (new, baked-only — see §3.5) | — |
| `admin_did` — **never** in the overlay; established at runtime via Mode-B TOFU | — |

### 3.4 Envelope wire shape

```json
{
  "version": 1,
  "overlay": {
    "vta_name": "acme-corp",
    "public_url": "https://vta.acme.example.com",
    "tee_kms": {
      "key_arn": "arn:aws:kms:us-east-1:111122223333:key/abcd-ef01-...",
      "vta_did_template": "did:webvh:{SCID}:acme.example.com:vta",
      "anchor_table_name": "vta-rollback-anchor-acme",
      "anchor_writer_credential_ciphertext": "..."
    },
    "messaging": { "mediator_did": "did:webvh:...:mediator" }
  },
  "integrity": null
}
```

This is `version: 1` — not a bump. The whole-config envelope this note
replaces (`{"version": 1, "config_toml": "..."}`) never shipped to any
running fleet (see the tracking note above), so there is nothing to be
compatible with and no reason to burn a version number pretending there
was. The `version` field itself is kept, and the existing hard-refuse
behavior on an unrecognized value is kept too — that's just ordinary
forward-proofing for the *next* time this envelope's shape needs to change,
after it's actually deployed somewhere. §6 covers what that means in
practice for this PR (nothing).

### 3.5 `key_arn` validation (closes the previously-unimplemented gap)

New **baked-only** field (never overlay-settable — absent from
`TenantKmsOverlay` on purpose):

```rust
// vta-config/src/lib.rs, on TeeConfig (fleet policy, baked)
/// AWS account IDs this image's tenant overlay may hand a key_arn from.
/// Baked, PCR0-committed — the parent cannot extend this list at runtime.
/// Empty means "no tenant overlay accepted" (fail closed, not "allow all").
#[serde(default)]
pub allowed_kms_accounts: Vec<String>,
```

Validation at overlay-apply time:

```rust
fn validate_key_arn(key_arn: &str, allowed: &[String]) -> Result<(), TenantOverlayError> {
    // arn:aws:kms:<region>:<account>:key/<id>
    let parts: Vec<&str> = key_arn.splitn(6, ':').collect();
    let (region, account) = match parts.as_slice() {
        ["arn", "aws", "kms", region, account, _rest] => (*region, *account),
        _ => return Err(TenantOverlayError::MalformedKeyArn(key_arn.to_string())),
    };
    if allowed.is_empty() {
        return Err(TenantOverlayError::NoAccountsAllowlisted);
    }
    if !allowed.iter().any(|a| a == account) {
        return Err(TenantOverlayError::KeyArnAccountNotAllowed {
            account: account.to_string(),
            allowed: allowed.to_vec(),
        });
    }
    let _ = region; // used by region_from_arn
    Ok(())
}

fn region_from_arn(key_arn: &str) -> Result<String, TenantOverlayError> { /* same split */ }
```

**Open item carried from the proposal, unresolved by this note** (needs a
security-team answer before Phase 3 ships, not before Phase 1/2): does one
image accept both an Atlas DEV and a PROD account (`allowed_kms_accounts =
["DEV_ACCT", "PROD_ACCT"]`), or does DEV/PROD require separate images (two
different `allowed_kms_accounts`, hence two PCR0s)? Recommend the
**separate-image** answer by default — a single image spanning trust tiers
means a DEV-tenant compromise and a PROD-tenant compromise share a PCR0,
which is the isolation property tenants are relying on (see the third-party
review's point 3, "multi-tenant isolation moves onto the KMS key policy" —
this allowlist is an *additional* independent gate, not a replacement for
tenant-scoped key policies).

### 3.6 `vta_did` store-precedence fix (same slice, small)

`vta-tee/src/did_autogen.rs::maybe_generate_vta_did` currently returns early
on `config.vta_did.is_some()` **before** checking the store (line 60), so a
directly-supplied `vta_did` (not routed through `vta_did_template`) never
gets compared against an already-established stored identity. Fix: check the
store first unconditionally; if the store holds a DID and the overlay/config
supplies a *different* one, log a loud warning and prefer the store's value
(never let a later boot silently redirect an already-established identity).
Small, independent, but lands in the same PR slice as the overlay work since
it's directly about the same "what may the parent redirect on a later boot"
property, and `vta_did` is in the allowlist table above.

### 3.7 The floor becomes defense-in-depth, not the primary control

With the overlay type-enforced, `config_floor_violation`'s job changes from
"catch a maliciously-shaped whole config" to "catch a bug in *our* merge
code." Keep it, narrow its inputs to match (it no longer needs `admin_did`
from the parent — that path is gone structurally), and add the proof test
that matters more than the floor itself:

```rust
#[test]
fn overlay_cannot_carry_any_allow_flag_or_admin_did_or_mode() {
    for poison in [
        r#"{"tee_kms":{"key_arn":"arn:...","allow_unanchored":true}}"#,
        r#"{"tee_kms":{"key_arn":"arn:...","allow_kms_reinit":true}}"#,
        r#"{"admin_did":"did:key:zEvil"}"#,
        r#"{"mode":"optional"}"#,
    ] {
        assert!(serde_json::from_str::<TenantConfigOverlay>(poison).is_err(),
            "overlay must reject unknown/forbidden field: {poison}");
    }
}
```

This test is the real guarantee the old floor was trying to approximate at
runtime — it fails the **build**, not a specific boot, if the allowlist type
ever regresses.

### 3.8 Fetch + parse + apply moves into Rust (`vta-tee`), behind a Cargo feature

Move the whole fetch/retry/timeout/size-cap/version-check/apply sequence out
of `enclave-entrypoint.sh` into a new `vta-tee/src/tenant_overlay.rs`,
reusing the `connect_vsock_with_retry` backoff shape already in
`vta-enclave/src/main.rs:50-78` and the `tokio_vsock::VsockStream` pattern
already in `vti-common/src/store/vsock.rs:67-90` (both already workspace
dependencies — no new crates). This module is gated behind a Cargo feature
(e.g. `tenant-overlay`) that only `BAKE_CONFIG=false` builds enable — a
`BAKE_CONFIG=true` build doesn't compile it in, per §3.1, so there is no
runtime "should I fetch?" branch to get wrong; the binary either has the
code or it doesn't. Rationale for moving it to Rust in the first place:

- The size cap, connect-timeout, and read-timeout become `tokio::time::timeout`
  + a bounded reader in one auditable, unit-testable function, instead of a
  `socat | head -c | jq` shell pipeline nobody can unit-test (there is no
  shellcheck in CI — noted by the second review).
- `deny_unknown_fields` parsing and the `key_arn`/account validation are
  naturally Rust-side; doing them in `jq` would mean hand-rolling an
  allowlist check in shell, which is exactly the fragile thing this note is
  trying to get away from.
- `enclave-entrypoint.sh` gains one build-time-known branch (which stage it
  was assembled from) instead of a runtime `VTA_CONFIG_SOURCE`/`fetch_rc`
  dance: the `BAKE_CONFIG=true` image's entrypoint is just bring up loopback
  + vsock proxies, then `exec vta-enclave --config "$CONFIG_PATH"`; the
  `BAKE_CONFIG=false` image's entrypoint additionally invokes the
  tenant-overlay fetch before exec'ing. No `set -e`-vs-`if` footgun (the
  second review's earlier catch), because there's no runtime decision left
  to get wrong.
- `enclave-proxy`'s `run_config_server` (parent side) is **unchanged in
  shape** for the fleet branch — it still just streams whatever bytes are at
  `--config-envelope <path>` (now a small overlay JSON file instead of a
  whole rendered config.toml). For `BAKE_CONFIG=true` deployments,
  `deploy-enclave.sh` continues to never pass `--config-envelope`, so this
  code path is never invoked and no vsock config port is opened — same as
  today.

## 4. What changes in `deploy/nitro/*`

- **`Dockerfile.nitro`**: `BAKE_CONFIG` build-arg and its two staged `FROM`s
  (`config-${BAKE_CONFIG}`) stay as-is. Only the `BAKE_CONFIG=false` stage's
  content changes shape (whole rendered config → fleet-policy base +
  placeholders); the `BAKE_CONFIG=true` stage is untouched. The
  overlay-fetch module (§3.8) is compiled in only when building the
  `vta-enclave` binary that goes into the `BAKE_CONFIG=false` stage (Cargo
  feature, not a runtime switch).
- **`build-vta.sh`**: unchanged branch structure. `BAKE_CONFIG=true` (Step
  10, single-tenant) continues to sed-fill the tenant fields in-place, no
  overlay involved. `BAKE_CONFIG=false` (fleet) now emits a **tenant overlay
  template** (§3.4, `tenant-overlay-template.json`, documenting the §3.3
  allowlist inline) instead of the old `config-envelope.json` (whole
  config). A new small script, `render-tenant-overlay.sh --key-arn
  --mediator-did --vta-did-template ... > tenant-overlay.json`, produces the
  per-tenant file an operator hands to `deploy-enclave.sh
  --config-envelope`.
- **`deploy-enclave.sh`**: flag name/plumbing to `enclave-proxy
  --config-envelope` is unchanged for the fleet path; only the file's
  contents differ (small overlay object, not a whole config). For
  `BAKE_CONFIG=true` builds it continues to never pass `--config-envelope`
  — no behavior change.
- **`enclave-entrypoint.sh`**: gains no new runtime branch — the
  `BAKE_CONFIG=true` image's entrypoint is unchanged (bring up proxies,
  `exec vta-enclave --config "$CONFIG_PATH"`); the `BAKE_CONFIG=false`
  image's entrypoint additionally invokes the Rust-side tenant-overlay fetch
  (§3.8) instead of the old shell `fetch_config_over_vsock`. Drop
  `SUPPORTED_CONFIG_ENVELOPE_VERSION`, `MAX_CONFIG_ENVELOPE_BYTES`,
  `CONFIG_FETCH_*_TIMEOUT`, `VTA_CONFIG_SOURCE`/`fetch_rc` from the
  fleet-branch shell script — superseded by the Rust module. The
  `BAKE_CONFIG=true` branch never had this logic and doesn't gain it.
- **`enclave-proxy`**: no source change required for the fleet path (§3.8's
  last bullet); `--config-envelope`'s doc comment updates to describe the
  new file shape. `BAKE_CONFIG=true` deployments never invoke
  `run_config_server` — unchanged.

## 5. Docs to fix in the same slice

- `docs/05-design-notes/tee-anti-rollback-anchor.md:440-447` (Open-Q#4): the
  "safe to expose because config is baked" premise is no longer universally
  true. Re-resolve it: state that `allow_unanchored` (and the other four
  `allow_*` flags) are safe to leave defaulted specifically **because this
  design note's allowlist makes them un-overlayable**, not because the whole
  image happens to be baked. Cross-reference this note.
- `deploy/nitro/README.md`, `deploy/nitro/config.toml`: keep the
  `BAKE_CONFIG` explanation (single-tenant = fully baked, no vsock config
  path at all; fleet = fleet-policy base baked, tenant-scoped fields served
  via the typed overlay); update only the fleet-side description to name the
  new overlay file/format instead of the old whole-config envelope. Document
  the `allowed_kms_accounts` baked field as a **required** setting for fleet
  builds (empty ⇒ no tenant may onboard, by design); add the multi-tenant
  KMS-key-policy requirement from the first review's point 3 alongside it
  (PCR0-allowlist and key-policy-principal-scoping are independent,
  both-required layers).

## 6. Rollout

There isn't one, for this change specifically. The whole-config-over-vsock
design (`a4c16512`..`a7d32c1f`) this note replaces has not merged to `main`
and has not been deployed to any environment — it's the same open PR, still
under review. There is no running `enclave-proxy` anywhere serving a
`config-envelope.json` in the old whole-config shape, so there is no
compatibility surface to manage, no dual-version window, and no "regenerate
every tenant's envelope" step. The overlay shape in §3.4 simply **is** the
shape this feature ships with, once it ships.

The one thing worth keeping from the earlier (wrong) draft of this section:
*after* this design is deployed for real, a future incompatible change to
the envelope *will* need the coordinated-rollout treatment described there —
bump `version`, rely on the existing hard-refuse-unknown-version check, ship
binary + regenerated envelopes together, no partial/rolling mixed state. That's
just not a concern this PR needs to solve, since it's the first thing to
actually reach a fleet.

## 7. Phased implementation plan (PR slices)

- **T1 — `TenantConfigOverlay` + `apply_tenant_overlay` + `key_arn`
  validation + poison tests (§3.2, 3.3, 3.5, 3.7).** Pure `vta-config`
  addition, no wiring yet. *(M)*
- **T2 — `vta_did` store-precedence fix (§3.6).** Independent, small,
  can land before or in parallel with T1. *(S)*
- **T3 — Rust-side fetch/apply in `vta-tee` behind a `tenant-overlay` Cargo
  feature + `vta-enclave` wiring, the overlay envelope shape (§3.4), fleet-branch
  `enclave-entrypoint.sh` update (§3.8).** Depends on T1. Does not
  touch the `BAKE_CONFIG=true` branch at all. *(L)*
- **T4 — `build-vta.sh` / `deploy-enclave.sh` / `Dockerfile.nitro` changes
  scoped to the `BAKE_CONFIG=false` stage, `render-tenant-overlay.sh`
  (§3.1, §4).** Depends on T3. `BAKE_CONFIG` itself is not removed. *(M)*
- **T5 — Docs: re-resolve Open-Q#4, README/config.toml rewrite, this note's
  own "resolved" pass (§5).** Can ride with T4. *(S)*
- **T6 — *(follow-up, not blocking)* the DEV/PROD single-image-vs-two-image
  decision for `allowed_kms_accounts` (§3.5's open item) — needs a security
  sign-off, not a design decision this note can make alone.**

Each slice is independently reviewable; T1+T2 are mergeable and useful (the
poison tests alone are a regression guard) before T3 exists.

## 8. Open questions for review

1. **Single image across DEV/PROD accounts, or one image per account?**
   (§3.5). Recommend: one image per trust tier, `allowed_kms_accounts` holds
   exactly one account in the common case; needs security sign-off before T3.
2. **Does `region` disappear as an overlay field** (derived from `key_arn`
   always), or stay as a required-and-cross-checked field for operator
   clarity in error messages? Recommend: derive-only, one less field to
   validate for equality.
3. **Does `vta_name` belong in the overlay at all**, or is it purely
   cosmetic/baked? Proposal marks it optional; no objection found — keeping
   it in §3.3 as-is.
4. **T4's `render-tenant-overlay.sh` — new script or a flag on
   `build-vta.sh`?** Recommend a separate script since it's a *per-tenant,
   repeatable* operation distinct from the *per-image, one-time* build.

