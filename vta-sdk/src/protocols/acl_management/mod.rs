pub mod create;
pub mod delete;
pub mod entry;
pub mod get;
pub mod list;
pub mod swap;
pub mod update;

pub const PROTOCOL_BASE: &str = "https://firstperson.network/protocols/acl-management/1.0";

pub const CREATE_ACL: &str = "https://firstperson.network/protocols/acl-management/1.0/create-acl";
pub const CREATE_ACL_RESULT: &str =
    "https://firstperson.network/protocols/acl-management/1.0/create-acl-result";

pub const GET_ACL: &str = "https://firstperson.network/protocols/acl-management/1.0/get-acl";
pub const GET_ACL_RESULT: &str =
    "https://firstperson.network/protocols/acl-management/1.0/get-acl-result";

pub const LIST_ACL: &str = "https://firstperson.network/protocols/acl-management/1.0/list-acl";
pub const LIST_ACL_RESULT: &str =
    "https://firstperson.network/protocols/acl-management/1.0/list-acl-result";

pub const UPDATE_ACL: &str = "https://firstperson.network/protocols/acl-management/1.0/update-acl";
pub const UPDATE_ACL_RESULT: &str =
    "https://firstperson.network/protocols/acl-management/1.0/update-acl-result";

pub const DELETE_ACL: &str = "https://firstperson.network/protocols/acl-management/1.0/delete-acl";
pub const DELETE_ACL_RESULT: &str =
    "https://firstperson.network/protocols/acl-management/1.0/delete-acl-result";

pub const SWAP_ACL: &str = "https://firstperson.network/protocols/acl-management/1.0/swap-acl";
pub const SWAP_ACL_RESULT: &str =
    "https://firstperson.network/protocols/acl-management/1.0/swap-acl-result";

/// Canonical Trust Task URI for ACL swap-key. The FPN-private `SWAP_ACL`
/// constant is retained for backwards compatibility during the deprecation
/// window; new producers SHOULD emit `ACL_SWAP_KEY` and new verifiers
/// MUST accept both. The canonical task's payload shape is described in
/// `vta_sdk::protocols::acl_management::swap::SwapKeyBody`.
pub const ACL_SWAP_KEY: &str = "https://trusttasks.org/spec/acl/swap-key/0.1";
pub const ACL_SWAP_KEY_RESPONSE: &str = "https://trusttasks.org/spec/acl/swap-key/0.1#response";
