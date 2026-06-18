# VTA Audit-Trail Coverage Review

**Scope:** Does every VTA operation that changes/modifies state get written to the
durable audit trail with a clear record of *what* happened, *who* requested it, and
*which resource* was modified?

**Verdict:** **No — coverage is partial.** The mechanism is sound and the caller
identity is already plumbed into every handler, but a number of state-mutating
operations never call it. Several of the gaps are high-value, privilege- or
identity-affecting operations.

---

## 1. The mechanism (what "audit trail" means in the VTA)

Two independent sinks live in `vta-service/src/audit.rs`:

1. **`audit!` macro** → emits a `tracing` event at target `"audit"` (INFO on success,
   ERROR on `denied:*`). Ephemeral; intended for log shipping / SIEM.
2. **`audit::record(audit_ks, action, actor, resource, outcome, channel, context_id)`**
   → persists an `AuditLogEntry` to the durable `audit` fjall keyspace, keyed
   `log:{timestamp}:{uuid}`. **This is the queryable audit trail** (served by the
   audit-management API).

An `AuditLogEntry` already captures everything the request asks for:

| Field | Meaning |
|---|---|
| `action` | what happened (e.g. `acl.create`) |
| `actor` | **who** — caller DID (`auth.did`) |
| `resource` | which resource was modified |
| `outcome` | `success` / `denied:*` |
| `channel` | transport (`rest` / `didcomm`) |
| `context_id` | scoping context |
| `timestamp` | when |

> Note: a richer HMAC-hashed, RTBF-aware audit subsystem (`vti_common::audit::AuditWriter`,
> `AuditEnvelope`) exists, but it is wired into the **VTC**, not the VTA. The VTA relies
> solely on the simpler `audit::record` above.

**Key finding about feasibility:** every gap operation below already receives
`auth: &AuthClaims` (so `auth.did` is in hand) **and** a `channel: &str` argument — the
exact two inputs `audit::record` needs. The plumbing is complete; the call is simply
missing. These handlers were built to be audited.

---

## 2. Operations that ARE audited (good)

| Area | Operations | Location |
|---|---|---|
| ACL | create / update / delete / swap | `operations/acl.rs` (4 sites) |
| Keys | create / import / rename / revoke / sign | `operations/keys.rs` (6 sites) |
| Seeds | rotate | `operations/seeds.rs` |
| Device | register / disable / wipe / set-wake | `operations/device.rs` (5 sites) |
| DID templates | global + context create / update / delete | `operations/did_templates.rs` (6 sites) |
| Provision integration | main provision path | `operations/provision_integration/mod.rs:814` |
| WebVH | register-with-server, update orchestrator | `register_server.rs`, `update/orchestrator.rs` |
| Backup | export **and** import (resource = target vta_did) | `routes/backup.rs:41,93` |
| Bootstrap (TEE) | admin provisioning | `routes/bootstrap.rs:161` |
| Audit policy | retention update | `operations/audit.rs:142` |
| DIDComm handlers | 3 mutating handlers | `messaging/handlers.rs:1089,1134,1190` |

---

## 3. GAPS — state-mutating operations NOT written to the audit trail

> All of these have `auth.did` and `channel` already in scope. Fixing each is a single
> `audit::record(...)` call on the success path.

| # | Operation(s) | File | What it mutates | Severity |
|---|---|---|---|---|
| 1 | `create_context`, `update_context`, `update_context_did`, `delete_context` | `operations/contexts.rs` | Context tree; **`delete_context` cascade-deletes keys, ACLs and templates of the whole subtree** | **High** |
| 2 | `update_config` | `operations/config.rs` | VTA DID, name, public URL — written to disk | **High** |
| 3 | `create_did_webvh`, `delete_did_webvh` | `operations/did_webvh/mod.rs` | Creates / destroys a WebVH DID, its log and keys | **High** |
| 4 | `provision_admin_rotation` | `operations/provision_integration/mod.rs:838` | Mints a fresh admin key, creates ACL row, updates DID doc — but **returns at `:250` before the audit call at `:814`**, so the cold-start admin-rotation path is unaudited | **High** |
| 5 | Service mgmt: `enable/disable/update/rollback` for `rest`/`didcomm`/`webauthn` | `operations/protocol/*` | Advertised transport services **and the VTA's own published DID document (a WebVH LogEntry)**. Some emit a *telemetry* event (default `RingBufferTelemetry` = in-memory, bounded, lost on restart); `enable_rest`/`rollback_rest` emit nothing. **None write the durable audit trail.** | **High** |
| 6 | `receive_issued_credential`, `defer_presentation`, `approve_pending_presentation`, `deny_pending_presentation` | `operations/credential_exchange.rs` | Vault credential receipt; pending-presentation approve/deny | Medium |
| 7 | `set_step_up_policy` | `operations/step_up_policy.rs` | Step-up authentication policy | Medium |
| 8 | `put_cached`, `delete_cached` | `operations/cache.rs` | Per-DID cache entries | Low (likely acceptable to omit — decide explicitly) |

---

## 4. Quality issues even where audit IS present

1. **Failed audit writes are silently swallowed.** Every call site is
   `let _ = audit::record(...).await;`. If the durable write errors, the trail gets a
   silent hole. At minimum log a `warn!` on `Err`. (The `audit!` tracing macro still
   fires, so there's a SIEM record, but the queryable keyspace entry is lost without
   notice.)

2. **Inconsistent dual-sink usage.** Some paths call the `audit!` macro only
   (`routes/auth.rs` — 10 macro calls, no `record()`), some call `record()` only
   (contexts would, if fixed), some call both. Decide a convention: durable
   `record()` for every state mutation; macro additionally for SIEM-relevant events.

3. **Documentation overstates coverage.** `docs/01-concepts/security-model.md:268`
   claims *"Structured audit logging (target: 'audit') for all admin operations."*
   That is currently inaccurate (contexts, config, did:webvh create/delete, service
   management, credential exchange are all admin operations and are not audited).
   Reconcile the doc with reality once the gaps are closed.

4. **Service-management telemetry ≠ audit.** The runtime-service-management design
   routes `service.<kind>.<verb>` events to the pluggable `TelemetrySink`, whose
   default impl is an in-memory ring buffer. That is fine for the "report" surface but
   is not a durable audit trail and must not be mistaken for one.

---

## 5. Recommended remediation

1. Add `audit::record(...)` on the success path of every gap operation in §3
   (#1–#7), passing the already-available `auth.did`, a stable `action` string, the
   modified resource id, `"success"`, the `channel`, and `context_id` where it
   applies. For `delete_context`, record the cascade (e.g. resource =
   `"<ctx-id> (+N keys, +M acls)"`).
2. Audit `provision_admin_rotation` before its early return (#4).
3. Add a durable `audit::record` to each service-management mutation (#5) in
   addition to the existing telemetry event.
4. Replace `let _ = audit::record(...)` with a form that logs on error.
5. Decide explicitly whether cache writes (#8) are in or out of scope, and note it.
6. Update `security-model.md` to match the (now-true) claim, or scope the claim.

All of §3 is mechanical and low-risk: the inputs are already in scope, the sink is
async and best-effort, and no signatures need to change.
