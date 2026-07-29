//! Wire-format protocol bodies and DIDComm message-type constants
//! for DID-template management.
//!
//! Each operation lives in its own submodule (`list`, `create`,
//! `get`, `update`, `delete`, `render`) and defines one body type
//! per operation. Scope is selected by the body's **optional
//! `context_id`** field (serialized as `contextId` on the wire,
//! lowerCamelCase per the Trust Task framework): absent = the
//! global scope (super-admin gated for writes), present = that
//! context's scope (context-admin gated for writes, context access
//! for reads).
//!
//! This is the 2.0 shape of the family
//! (`spec/vta/did-templates/*/2.0`, trust-tasks registry issue
//! OpenVTC/verifiable-trust-infrastructure#851), which merged the
//! former global (`spec/vta/did-templates/*/1.0`) and context
//! (`spec/vta/contexts/did-templates/*/1.0`) URI hierarchies — the
//! per-scope ACL moved from the slug structure into the `contextId`
//! field plus party gating. The twelve 1.0 URIs are retired and no
//! longer accepted.
//!
//! Trust-task URIs are declared in
//! [`crate::trust_tasks`] under the `TASK_DID_TEMPLATES_*` prefix.
//!
//! Template management over DIDComm ships as a **Trust Task**: the
//! `VtaClient` dispatches the
//! `trusttasks.org/spec/vta/(contexts/)did-templates/*` tasks through
//! the binding envelope, and the VTA serves them via its trust-task
//! dispatcher. The `firstperson.network/protocols/did-template-management/1.0`
//! message-type constants below are **deprecated** — they were the
//! never-routed raw-protocol scheme and are retained only for
//! backward compatibility; no current code path emits them.

pub mod create;
pub mod delete;
pub mod get;
pub mod list;
pub mod render;
pub mod update;

pub const PROTOCOL_BASE: &str = "https://firstperson.network/protocols/did-template-management/1.0";

pub const LIST_TEMPLATES: &str =
    "https://firstperson.network/protocols/did-template-management/1.0/list-templates";
pub const LIST_TEMPLATES_RESULT: &str =
    "https://firstperson.network/protocols/did-template-management/1.0/list-templates-result";

pub const GET_TEMPLATE: &str =
    "https://firstperson.network/protocols/did-template-management/1.0/get-template";
pub const GET_TEMPLATE_RESULT: &str =
    "https://firstperson.network/protocols/did-template-management/1.0/get-template-result";

pub const CREATE_TEMPLATE: &str =
    "https://firstperson.network/protocols/did-template-management/1.0/create-template";
pub const CREATE_TEMPLATE_RESULT: &str =
    "https://firstperson.network/protocols/did-template-management/1.0/create-template-result";

pub const UPDATE_TEMPLATE: &str =
    "https://firstperson.network/protocols/did-template-management/1.0/update-template";
pub const UPDATE_TEMPLATE_RESULT: &str =
    "https://firstperson.network/protocols/did-template-management/1.0/update-template-result";

pub const DELETE_TEMPLATE: &str =
    "https://firstperson.network/protocols/did-template-management/1.0/delete-template";
pub const DELETE_TEMPLATE_RESULT: &str =
    "https://firstperson.network/protocols/did-template-management/1.0/delete-template-result";

pub const RENDER_TEMPLATE: &str =
    "https://firstperson.network/protocols/did-template-management/1.0/render-template";
pub const RENDER_TEMPLATE_RESULT: &str =
    "https://firstperson.network/protocols/did-template-management/1.0/render-template-result";
