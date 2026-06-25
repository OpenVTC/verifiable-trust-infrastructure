//! DIDComm message types for runtime service management
//! (`pnm services rest …` / `pnm services didcomm …`).
//!
//! Spec: `docs/05-design-notes/runtime-service-management.md`.
//!
//! Naming follows the `firstperson.network/protocols/<name>/1.0`
//! convention used elsewhere in this crate. Two protocols:
//!
//! - **services-management/1.0** — REST + DIDComm enable / update /
//!   disable / rollback / list. (`didcomm-enable` is REST-only by
//!   nature, since DIDComm isn't running yet at first-enable; the
//!   `enable-not-available-via-didcomm` placeholder surfaces this
//!   to callers who try.)
//! - **mediator-management/1.0** — drain-cancel / report (the
//!   per-mediator drain set + telemetry surface, which is DIDComm-
//!   only by definition since REST has no in-flight state).
//!
//! For each request type, a matching `*-result` type exists on the
//! response side. The body shapes mirror the REST request/response
//! types in [`crate::protocol`].

pub const SERVICES_PROTOCOL_BASE: &str =
    "https://firstperson.network/protocols/services-management/1.0";
pub const MEDIATOR_PROTOCOL_BASE: &str =
    "https://firstperson.network/protocols/mediator-management/1.0";

// ── services-management ─────────────────────────────────────────────

pub const DISABLE_DIDCOMM: &str =
    "https://firstperson.network/protocols/services-management/1.0/didcomm-disable";
pub const DISABLE_DIDCOMM_RESULT: &str =
    "https://firstperson.network/protocols/services-management/1.0/didcomm-disable-result";

// REST-side service management. Spec:
// `docs/05-design-notes/runtime-service-management.md` §3.4.
// All three are reachable over DIDComm — REST is always running
// (per spec §3.2 at-least-one-service invariant), so a request
// adding/updating/removing the REST advertisement can travel over
// DIDComm without hitting the same chicken-and-egg problem as
// `enable_didcomm` (which can't be invoked over a transport that
// isn't running yet).

pub const ENABLE_REST: &str =
    "https://firstperson.network/protocols/services-management/1.0/rest-enable";
pub const ENABLE_REST_RESULT: &str =
    "https://firstperson.network/protocols/services-management/1.0/rest-enable-result";

pub const UPDATE_REST: &str =
    "https://firstperson.network/protocols/services-management/1.0/rest-update";
pub const UPDATE_REST_RESULT: &str =
    "https://firstperson.network/protocols/services-management/1.0/rest-update-result";

pub const DISABLE_REST: &str =
    "https://firstperson.network/protocols/services-management/1.0/rest-disable";
pub const DISABLE_REST_RESULT: &str =
    "https://firstperson.network/protocols/services-management/1.0/rest-disable-result";

// Fail-forward rollback ops (T3.x). Read the per-kind snapshot
// and dispatch into the equivalent forward operation. Reachable
// over both transports — REST is always running per spec §3.2,
// and the dispatched forward ops handle the chicken-and-egg
// concerns themselves (e.g. enable_didcomm is REST-only by
// nature; rollback into it falls back to that constraint).

pub const ROLLBACK_REST: &str =
    "https://firstperson.network/protocols/services-management/1.0/rest-rollback";
pub const ROLLBACK_REST_RESULT: &str =
    "https://firstperson.network/protocols/services-management/1.0/rest-rollback-result";

pub const ROLLBACK_DIDCOMM: &str =
    "https://firstperson.network/protocols/services-management/1.0/didcomm-rollback";
pub const ROLLBACK_DIDCOMM_RESULT: &str =
    "https://firstperson.network/protocols/services-management/1.0/didcomm-rollback-result";

// TSP-side service management. Same shape as REST — single value on
// the `#tsp` service entry — but the value is a **mediator DID** (the
// VTA's TSP VID), not a URL. All four are reachable over both REST
// and DIDComm: unlike `enable_didcomm` (which can't arrive over a
// transport that isn't running yet), DIDComm is always running when
// REST is, so a TSP enable/update/disable/rollback can travel over
// either transport.

pub const ENABLE_TSP: &str =
    "https://firstperson.network/protocols/services-management/1.0/tsp-enable";
pub const ENABLE_TSP_RESULT: &str =
    "https://firstperson.network/protocols/services-management/1.0/tsp-enable-result";

pub const UPDATE_TSP: &str =
    "https://firstperson.network/protocols/services-management/1.0/tsp-update";
pub const UPDATE_TSP_RESULT: &str =
    "https://firstperson.network/protocols/services-management/1.0/tsp-update-result";

pub const DISABLE_TSP: &str =
    "https://firstperson.network/protocols/services-management/1.0/tsp-disable";
pub const DISABLE_TSP_RESULT: &str =
    "https://firstperson.network/protocols/services-management/1.0/tsp-disable-result";

pub const ROLLBACK_TSP: &str =
    "https://firstperson.network/protocols/services-management/1.0/tsp-rollback";
pub const ROLLBACK_TSP_RESULT: &str =
    "https://firstperson.network/protocols/services-management/1.0/tsp-rollback-result";

// WebAuthn-RP service ops. Same shape as REST — single URL on the
// `#vta-webauthn` service entry — but with different runtime
// availability semantics + the hard-disable passkey-VM cleanup.

pub const ENABLE_WEBAUTHN: &str =
    "https://firstperson.network/protocols/services-management/1.0/webauthn-enable";
pub const ENABLE_WEBAUTHN_RESULT: &str =
    "https://firstperson.network/protocols/services-management/1.0/webauthn-enable-result";

pub const UPDATE_WEBAUTHN: &str =
    "https://firstperson.network/protocols/services-management/1.0/webauthn-update";
pub const UPDATE_WEBAUTHN_RESULT: &str =
    "https://firstperson.network/protocols/services-management/1.0/webauthn-update-result";

pub const DISABLE_WEBAUTHN: &str =
    "https://firstperson.network/protocols/services-management/1.0/webauthn-disable";
pub const DISABLE_WEBAUTHN_RESULT: &str =
    "https://firstperson.network/protocols/services-management/1.0/webauthn-disable-result";

pub const ROLLBACK_WEBAUTHN: &str =
    "https://firstperson.network/protocols/services-management/1.0/webauthn-rollback";
pub const ROLLBACK_WEBAUTHN_RESULT: &str =
    "https://firstperson.network/protocols/services-management/1.0/webauthn-rollback-result";

// Read-only inspection (T4.2). Auth: super-admin. The result
// payload uses the SDK's `ServicesListResponse` shape — one
// entry per kind, canonical DIDComm-before-REST order.

pub const LIST_SERVICES: &str =
    "https://firstperson.network/protocols/services-management/1.0/list";
pub const LIST_SERVICES_RESULT: &str =
    "https://firstperson.network/protocols/services-management/1.0/list-result";

pub const LIST_DRAIN: &str =
    "https://firstperson.network/protocols/services-management/1.0/didcomm-drain-list";
pub const LIST_DRAIN_RESULT: &str =
    "https://firstperson.network/protocols/services-management/1.0/didcomm-drain-list-result";

// ── services-management (DIDComm side, continued) ───────────────────

// T2.3 rename — was MIGRATE_MEDIATOR / mediator-management/1.0/migrate.
// The operation isn't really "migrating the mediator," it's updating
// which mediator the DIDComm service is using (spec §3.4). Renamed
// end-to-end (URL, Rust constant, request / response types, handler
// functions, telemetry kind) to align with the unified
// `services {kind} {verb}` surface.
pub const UPDATE_DIDCOMM: &str =
    "https://firstperson.network/protocols/services-management/1.0/didcomm-update";
pub const UPDATE_DIDCOMM_RESULT: &str =
    "https://firstperson.network/protocols/services-management/1.0/didcomm-update-result";

// ── mediator-management (drain bookkeeping only) ────────────────────
//
// These remain under mediator-management/ — they operate on the
// drain set, not the active mediator advertisement, so the original
// name is still accurate.

pub const DRAIN_CANCEL: &str =
    "https://firstperson.network/protocols/mediator-management/1.0/drain-cancel";
pub const DRAIN_CANCEL_RESULT: &str =
    "https://firstperson.network/protocols/mediator-management/1.0/drain-cancel-result";

pub const MEDIATOR_REPORT: &str =
    "https://firstperson.network/protocols/mediator-management/1.0/report";
pub const MEDIATOR_REPORT_RESULT: &str =
    "https://firstperson.network/protocols/mediator-management/1.0/report-result";
