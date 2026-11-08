pub mod create;
pub mod delete;
pub mod get;
pub mod list;
pub mod secrets;
pub mod update;
pub mod update_did;

pub const PROTOCOL_BASE: &str = "https://firstperson.network/protocols/context-management/1.0";

pub const CREATE_CONTEXT: &str =
    "https://firstperson.network/protocols/context-management/1.0/create-context";
pub const CREATE_CONTEXT_RESULT: &str =
    "https://firstperson.network/protocols/context-management/1.0/create-context-result";

pub const GET_CONTEXT: &str =
    "https://firstperson.network/protocols/context-management/1.0/get-context";
pub const GET_CONTEXT_RESULT: &str =
    "https://firstperson.network/protocols/context-management/1.0/get-context-result";

pub const LIST_CONTEXTS: &str =
    "https://firstperson.network/protocols/context-management/1.0/list-contexts";
pub const LIST_CONTEXTS_RESULT: &str =
    "https://firstperson.network/protocols/context-management/1.0/list-contexts-result";

pub const UPDATE_CONTEXT: &str =
    "https://firstperson.network/protocols/context-management/1.0/update-context";
pub const UPDATE_CONTEXT_RESULT: &str =
    "https://firstperson.network/protocols/context-management/1.0/update-context-result";

pub const UPDATE_CONTEXT_DID: &str =
    "https://firstperson.network/protocols/context-management/1.0/update-context-did";
pub const UPDATE_CONTEXT_DID_RESULT: &str =
    "https://firstperson.network/protocols/context-management/1.0/update-context-did-result";

pub const DELETE_CONTEXT: &str =
    "https://firstperson.network/protocols/context-management/1.0/delete-context";
pub const DELETE_CONTEXT_RESULT: &str =
    "https://firstperson.network/protocols/context-management/1.0/delete-context-result";

pub const PREVIEW_DELETE_CONTEXT: &str =
    "https://firstperson.network/protocols/context-management/1.0/preview-delete-context";
pub const PREVIEW_DELETE_CONTEXT_RESULT: &str =
    "https://firstperson.network/protocols/context-management/1.0/preview-delete-context-result";
