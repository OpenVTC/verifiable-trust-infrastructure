//! Wire-format protocol bodies and DIDComm message-type constants
//! for DID-template management.
//!
//! Each operation lives in its own submodule (`list`, `create`,
//! `get`, `update`, `delete`, `render`). Each module defines two
//! body types when relevant: a **global**-scope variant
//! (`*DidTemplateBody`) and a **context**-scope variant
//! (`*ContextDidTemplateBody`). The context-scope variant carries
//! a required `context_id` field (serialized as `contextId` on the
//! wire, lowerCamelCase per the Trust Task framework); the global
//! variant doesn't.
//!
//! The split is deliberate. Global and context templates are not
//! the same resource filtered differently — they have different
//! owners (super-admin vs context-admin), different lifecycles, and
//! different visibility scopes. Modelling them as distinct wire
//! types makes the auth contract self-documenting from the
//! payload, mirrors the URI hierarchy
//! (`spec/vta/did-templates/*` vs `spec/vta/contexts/did-templates/*`),
//! and removes the need for slice handlers to branch on
//! `Option<String>`.
//!
//! Trust-task URIs are declared in
//! [`crate::trust_tasks`] under the `TASK_DID_TEMPLATES_*` and
//! `TASK_CONTEXTS_DID_TEMPLATES_*` prefixes.
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
