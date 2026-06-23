# Spec: Enterprise fleet management & owner/user separation of duty

Status: **Proposed (design)**
Owner: Glenn Gore
Last updated: 2026-06-23

## 1. Objective

Today the VTA is designed for the individual who **owns and uses** their own
agent — owner and user are the same person, and that works well. This spec
adds the **enterprise** case: an organisation owns and manages a VTA (or a
whole fleet of VTAs) that staff *use* day-to-day, with a hard **separation of
duty** between:

* the **VTA owner** (enterprise manager / IT) — sets policy, controls config,
  grants and revokes access, manages the fleet at scale; and
* the **VTA user** (staff member) — operates within the scope the owner
  defines and **cannot relax** the guardrails placed on them.

The design has two layers:

1. **Single-VTA separation of duty** — express "owner vs user" entirely on
   the existing super-admin ↔ context-scoped axis, plus one new per-context
   policy primitive. (§3–§4)
2. **Fleet management** — an enterprise operator persona (**Enterprise/Fleet
   Network Manager, ENM**) that manages *N* VTAs at scale via desired-state
   reconciliation over DIDComm. (§5–§8)

The guiding principle: **do not build an "enterprise mode" as a parallel trust
root.** Every enterprise concept maps onto primitives already in the workspace
(super-admin, contexts, capabilities, step-up, templates, bootstrap/attestation,
the pluggable telemetry sink). The new build is small and additive.

### 1.1 Repository boundary (open-core split)

The work splits across **two repos** along a clean open-core line:

* **This workspace (`verifiable-trust-infrastructure`, OSS)** ships the
  generic *management surface* — the mechanism that makes any VTA
  fleet-manageable without prescribing which fleet manager:
  `ContextPolicy` (§4), admin-over-DIDComm coverage (§6 step 2), the
  super-admin-only audit query, attested/provision enrollment hooks (already
  present), and the pluggable `TelemetrySink` (already present). These are
  separation-of-duty primitives useful to *any* operator.
* **A new Affinidi-specific repo at `~/devel/<crate>` (proprietary)** ships
  the opinionated *fleet-management product* — the **ENM** control plane:
  desired-state model + reconciler, VTA inventory/registry, fleet-seed /
  per-VTA super-admin orchestration, the telemetry/audit aggregator (consuming
  the OSS sink trait), and the CLI → control-plane service.

It depends on the OSS crates exactly as `pnm-cli` does — `vta-sdk`,
`vta-cli-common`, `vti-common` by **path** during development (sibling
checkout) and by **crates.io version** for release (all three are
`publish.workspace = true`). It must depend **only** on the published
crates (`vta-sdk` / `vta-cli-common` / `vti-common`), never on
`vta-service`/`vtc-service` internals — the reconciler drives VTAs over the
wire (SDK), it does not link their runtime.

The OSS half (§3–§4, §6 steps 1–2 + audit query) is documented here; the
detailed ENM product design (§5, §6 steps 3–6) relocates to a design note in
the new repo once it is scaffolded — this note keeps the boundary + the
"what the OSS side must expose" contract.

### Why this matters

* Enterprises will not deploy an agent that a staff member can re-configure to
  exfiltrate keys, present arbitrary credentials, or remove org controls.
  Separation of duty is the price of entry.
* At any real headcount this becomes a *fleet* problem: provision, configure,
  observe, rotate, suspend and decommission hundreds-to-thousands of staff
  VTAs — most of them intermittently-connected devices behind NAT.
* The workspace already has the hard parts (DID-native ACL, DIDComm admin
  surface, mediator store-and-forward, BIP-32 derivation, attested bootstrap,
  templates, pluggable telemetry). Fleet management is largely *composition*
  of these, not new cryptography or new trust.

### Non-goals

* **MDM / device management.** This is identity-and-agent management, not OS
  device management. We manage what the VTA advertises, authorises and
  attests — not the host OS.
* **Replacing per-VTA autonomy.** Each managed VTA stays authoritative over
  its own ACL/policy in steady state (per `CLAUDE.md`). The fleet manager
  holds *desired state* and reconciles; it is **not** a runtime dependency.
  A staff VTA must keep working when the control plane is offline.
* **A new authorization envelope.** Owner→user authorization assertions remain
  VC/VP-shaped; admin operations remain the existing ACL/policy/service ops.
* **Cross-tenant trust federation.** One enterprise managing its own fleet.
  Inter-enterprise trust is the VTC's job, out of scope here.

## 2. Tech stack & codebase context

* Rust workspace, edition 2024, resolver 3, MSRV 1.95.0.
* Existing modules this builds on (extend, do **not** fork):
  * `vti-common/src/acl/mod.rs` — `Role`, `Capability`, `AclEntry`,
    super-admin predicate, visibility filter.
  * `vti-common/src/auth/{extractor,jwt,step_up}.rs` — request-path auth
    gates (`SuperAdminAuth`, `AdminAuth`, context checks), `StepUpPolicy`
    (the additive-strictness lattice to mirror).
  * `vta-service/src/operations/{acl,contexts}.rs` — ACL/context CRUD and
    their auth gates.
  * `vta-service/src/operations/credential_exchange.rs` — `ConsentPolicy`
    (`trusted_presentation_verifiers`), the present-query enforcement point.
  * `vta-service/src/trust_tasks/*` + signing-oracle route — the dispatch
    spine where capabilities are already enforced (where `ContextPolicy`
    enforcement also lands).
  * `vta-service/src/operations/protocol/*`, `vta-service/src/messaging/*`,
    `vta-service/src/routes/protocol.rs` — runtime service management +
    **admin-over-DIDComm** (the pattern the fleet API fans out).
  * `vta-service/src/routes/bootstrap.rs`, `vta-service/src/tee/` — Mode B
    attested bootstrap + provision-integration (the enrollment flows).
  * `vti-common/src/telemetry/` — pluggable `TelemetrySink` (point at a
    fleet collector instead of the default ring buffer).
  * `vta-sdk` — REST + DIDComm client; `did_templates`; `protocol::*` wire
    types. Consumed by the external ENM repo as its wire transport; not
    extended here beyond the admin-over-DIDComm coverage in §6.
  * `vta-cli-common` — shared CLI command impls; `pnm-cli`/`cnm-cli` are the
    thin-wrapper precedent the external ENM CLI follows.

* Existing invariants that must continue to hold:
  * The ACL is the steady-state source of authorization truth.
  * Step-up overrides are **additive-only** (strictest wins; a relaxing
    override is ignored).
  * A context-scoped actor cannot mint an unrestricted (super-admin) entry,
    cannot change VTA config, and cannot see/modify higher-privilege entries.
  * Audience isolation between VTA and VTC JWTs.

## 3. Functional requirements — single-VTA separation of duty

The owner/user split is **already expressible** with one addition. The mapping:

| Enterprise concept | Existing primitive |
|---|---|
| VTA owner (enterprise) | **Super-admin** = `role=Admin` + `allowed_contexts=[]` (`acl/mod.rs:419`) |
| VTA user (staff) | Context-scoped ACL entry: `role=Application`/`Reader` + `allowed_contexts=[ctx]` + explicit `capabilities` + `expires_at` |
| Team lead | Context-admin = `role=Admin` scoped to a sub-context |
| "What you can/can't do" | The 10 `Capability` flags, per-entry (`acl/mod.rs:122`) |
| "Within the org's scope" | `allowed_contexts` + segment-aware ancestry |

Separation-of-duty guarantees already enforced (no new work):

* Scoped actor **cannot change VTA config** (`SuperAdminAuth`,
  `routes/config.rs`).
* Scoped actor **cannot create top-level contexts** (super-admin only,
  `contexts.rs:91`) nor **mint an unrestricted ACL entry** (`acl.rs:626-629`).
* Scoped actor **cannot enumerate or modify** the super-admin entry
  (visibility filter `acl.rs:671-679`).
* Step-up overrides are additive — staff can be made *stricter*, never looser.
* `role=Application` can *use* keys (signing oracle never exports) but cannot
  back up (super-admin only) or mint unrestricted access. No exfiltration path.

### FR-1: `ContextPolicy` — the one missing primitive

Capabilities give coarse on/off of an *operation class*; they cannot say
"this operation, but only against these targets." The existing policy objects
(`StepUpPolicy`, `ConsentPolicy`) are **VTA-wide**, which doesn't fit a
multi-staff or fleet world. Introduce a per-context policy:

```rust
/// Attached to a context. Mutable only by super-admin; a context-admin with
/// PolicyAdmin may *narrow* (never widen) it on a sub-context — same additive
/// discipline as StepUpPolicy.
pub struct ContextPolicy {
    /// Verifier DIDs staff in this context may present to. None = inherit.
    pub trusted_verifiers: Option<BTreeSet<String>>,
    /// Credential types staff may present. None = inherit; Some = allow-list.
    pub presentable_types: Option<BTreeSet<String>>,
    /// Key ids the signing oracle may be invoked on. None = inherit.
    pub signable_keys: Option<BTreeSet<String>>,
    /// false = sealed-transfer export disabled for this context.
    pub export_allowed: bool,
    /// Per-operation-class rate/quota ceilings. None = inherit.
    pub quotas: Option<Quotas>,
}
```

**Resolution** at the enforcement spine = intersect
`global ∩ ancestor-contexts ∩ leaf ∩ per-entry-override`, where every step can
only **narrow**. This mirrors the step-up strictness lattice and makes
non-removability structural: a deeper/closer actor can tighten but never
loosen what an ancestor (ultimately the owner) set.

**Enforcement points** (reuse where capabilities are already checked):
* present/disclosure: `credential_exchange.rs::present_query` + vault release.
* signing: the signing-oracle route / `key-management/1.0/sign-request`.
* export: the `sealed_transfer` emit path.

`ContextPolicy` is additive to existing wire types — no reshaping of
`SealedPayloadV1` or any verified form.

## 4. Single-VTA: what's left to build

1. `ContextPolicy` type, store (alongside the context record), resolution
   function, enforcement at the three spines above, super-admin CRUD route +
   `pnm`/`vta` CLI, additive-narrow gate for context-admins.
2. Super-admin-only, context-scoped **audit query** over the existing audit
   log (`audit::record`) so the owner can see what staff did.
3. **Provisioning**: extend `vta setup --from <toml>` to bake in
   `super-admin = enterprise DID` + the staff context + the scoped staff
   entry + the initial `ContextPolicy`, so an enterprise can stamp out a
   pre-configured VTA in one shot.

That alone delivers separation of duty for a single shared or per-staff VTA.
Everything below scales it to a fleet.

## 5. Fleet management lives in the external Affinidi repo

The fleet-management product — **ENM**, the control plane that manages *N* VTAs
at scale — is **not** part of this workspace. It is the proprietary,
Affinidi-specific repo **`affinidi-vti-enm`** (§1.1), built on the OSS crates.
Its full architecture (identity-as-super-admin + control loop, desired-state
reconciliation, DIDComm-via-mediator transport, per-VTA super-admin derived
from a fleet seed, enrollment via Mode B / provision-integration, policy
profiles as templates, telemetry aggregation, CLI → control-plane service
staging) is specified there:
`affinidi-vti-enm/docs/design/fleet-management.md`.

### 5.1 The contract this workspace owes the fleet manager

The OSS side's entire obligation to ENM is to **expose** the surface ENM
drives. Nothing fleet-specific is built here — these are generic, reusable
management primitives any operator benefits from:

* **`ContextPolicy`** (§3–§4) — per-context policy + additive-narrow resolution
  + enforcement at the present/sign/export spines.
* **Full admin-over-DIDComm coverage** for every admin op (ACL CRUD, policy
  set, service management) so a fleet can drive a VTA over the mediator.
* **Super-admin context-scoped audit query** (§4) — the read side ENM
  aggregates.
* **Attested / provision enrollment** (already present) and the pluggable
  **`TelemetrySink`** (already present) pointed at a fleet collector.

## 6. Build order (this workspace)

Only the OSS prerequisites live here; the ENM product steps are in
`affinidi-vti-enm/docs/design/fleet-management.md` §4.

1. **`ContextPolicy`** (§4) — type, store, additive-narrow resolution,
   enforcement at the present/sign/export spines, super-admin CRUD route +
   `pnm`/`vta` CLI, context-admin narrow-only gate. Nothing fleet-wide is
   meaningful until per-VTA policy exists to distribute.
2. **Admin-over-DIDComm coverage audit** — confirm every admin op the fleet
   needs (ACL CRUD, policy set, service management) is reachable over
   DIDComm-via-mediator; fill gaps. Plus the super-admin context-scoped
   **audit query** (§4). *Together these are the fleet's actual API.*
3. **Provisioning** — extend `vta setup --from <toml>` to bake in the
   enterprise super-admin + staff context + scoped staff entry + initial
   `ContextPolicy` (§4).

These are the only prerequisites the ENM repo cannot supply itself.

## 7. Key decisions (OSS scope)

* **No enterprise mode / no new trust root** — compose existing primitives.
* **Owner = super-admin, user = context-scoped actor** — separation of duty is
  the existing super-admin ↔ scoped axis, made complete by `ContextPolicy`.
* **Policy is per-context and additive-narrow** — resolution intersects down the
  tree; deeper actors tighten, never loosen.
* **Backward-compatible by construction** — `ContextPolicy` absent / empty
  allow-list = inherit (unrestricted), serde-`default` on new fields. Existing
  deployments are a no-op; the enterprise split is a new provisioning *choice*,
  not a change to anything already running.

Fleet-side decisions (reconciliation-over-RPC, DIDComm transport, per-VTA
fleet-seed super-admin, one-core-two-front-ends) live in
`affinidi-vti-enm/docs/design/fleet-management.md` §5.

## 8. Open questions (OSS scope)

* **`Quotas` granularity** — per-operation-class counters vs token-bucket;
  where the counter state lives (per-VTA fjall vs reported to a collector).
* **Shared-VTA (context-per-staff) vs per-staff-VTA fleet** — both reuse the
  same spine; affects provisioning shape. ENM assumes per-staff but does not
  preclude shared tenants on a single VTA.

Fleet-side open questions (group model, kill switch, recovery) live in the ENM
doc §6.

## 9. Related docs

* `affinidi-vti-enm/docs/design/fleet-management.md` — the ENM fleet-management
  product design (external Affinidi repo).
* `docs/05-design-notes/runtime-service-management.md` — the admin-over-DIDComm
  pattern the fleet API fans out.
* `docs/05-design-notes/hierarchical-contexts.md` — context tree + ancestry.
* `docs/05-design-notes/auth-architecture.md` — roles, capabilities, step-up.
* `docs/02-vta/provision-integration.md`, `sealed-bootstrap.md` — enrollment.
* `docs/02-vta/did-templates.md` — the author-once/render-everywhere pattern
  reused for policy profiles.
