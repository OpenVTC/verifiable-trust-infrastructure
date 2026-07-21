pub mod agent_name;
pub mod create;
pub mod delete;
pub mod get;
pub mod lifecycle;
pub mod list;
pub mod passkey_vms;
pub mod servers;
pub mod update;

pub const PROTOCOL_BASE: &str = "https://firstperson.network/protocols/did-management/1.0";

pub const CREATE_DID_WEBVH: &str =
    "https://firstperson.network/protocols/did-management/1.0/create-did-webvh";
pub const CREATE_DID_WEBVH_RESULT: &str =
    "https://firstperson.network/protocols/did-management/1.0/create-did-webvh-result";

pub const GET_DID_WEBVH: &str =
    "https://firstperson.network/protocols/did-management/1.0/get-did-webvh";
pub const GET_DID_WEBVH_RESULT: &str =
    "https://firstperson.network/protocols/did-management/1.0/get-did-webvh-result";

pub const LIST_DIDS_WEBVH: &str =
    "https://firstperson.network/protocols/did-management/1.0/list-dids-webvh";
pub const LIST_DIDS_WEBVH_RESULT: &str =
    "https://firstperson.network/protocols/did-management/1.0/list-dids-webvh-result";

pub const GET_DID_WEBVH_LOG: &str =
    "https://firstperson.network/protocols/did-management/1.0/get-did-webvh-log";
pub const GET_DID_WEBVH_LOG_RESULT: &str =
    "https://firstperson.network/protocols/did-management/1.0/get-did-webvh-log-result";

pub const DELETE_DID_WEBVH: &str =
    "https://firstperson.network/protocols/did-management/1.0/delete-did-webvh";
pub const DELETE_DID_WEBVH_RESULT: &str =
    "https://firstperson.network/protocols/did-management/1.0/delete-did-webvh-result";

pub const ADD_WEBVH_SERVER: &str =
    "https://firstperson.network/protocols/did-management/1.0/add-webvh-server";
pub const ADD_WEBVH_SERVER_RESULT: &str =
    "https://firstperson.network/protocols/did-management/1.0/add-webvh-server-result";

pub const LIST_WEBVH_SERVERS: &str =
    "https://firstperson.network/protocols/did-management/1.0/list-webvh-servers";
pub const LIST_WEBVH_SERVERS_RESULT: &str =
    "https://firstperson.network/protocols/did-management/1.0/list-webvh-servers-result";

/// `pnm did-mgmt list-domains --server <id>` and the interactive
/// domain prompt in `create-did` / `register-did` use this op to
/// fetch the hosting server's caller-scoped `GET /api/me/domains`
/// view through the VTA.
pub const LIST_WEBVH_SERVER_DOMAINS: &str =
    "https://firstperson.network/protocols/did-management/1.0/list-webvh-server-domains";
pub const LIST_WEBVH_SERVER_DOMAINS_RESULT: &str =
    "https://firstperson.network/protocols/did-management/1.0/list-webvh-server-domains-result";

pub const UPDATE_WEBVH_SERVER: &str =
    "https://firstperson.network/protocols/did-management/1.0/update-webvh-server";
pub const UPDATE_WEBVH_SERVER_RESULT: &str =
    "https://firstperson.network/protocols/did-management/1.0/update-webvh-server-result";

pub const REMOVE_WEBVH_SERVER: &str =
    "https://firstperson.network/protocols/did-management/1.0/remove-webvh-server";
pub const REMOVE_WEBVH_SERVER_RESULT: &str =
    "https://firstperson.network/protocols/did-management/1.0/remove-webvh-server-result";

pub const UPDATE_DID_WEBVH: &str =
    "https://firstperson.network/protocols/did-management/1.0/update-did-webvh";
pub const UPDATE_DID_WEBVH_RESULT: &str =
    "https://firstperson.network/protocols/did-management/1.0/update-did-webvh-result";

pub const ROTATE_DID_WEBVH_KEYS: &str =
    "https://firstperson.network/protocols/did-management/1.0/rotate-did-webvh-keys";
pub const ROTATE_DID_WEBVH_KEYS_RESULT: &str =
    "https://firstperson.network/protocols/did-management/1.0/rotate-did-webvh-keys-result";

/// Promote a serverless WebVH DID to a server-managed one. Pushes
/// the existing local log to a registered host without re-issuing
/// the DID identifier. See `vta-service/src/operations/did_webvh/
/// register_server.rs` for semantics.
pub const REGISTER_DID_WITH_SERVER: &str =
    "https://firstperson.network/protocols/did-management/1.0/register-did-with-server";
pub const REGISTER_DID_WITH_SERVER_RESULT: &str =
    "https://firstperson.network/protocols/did-management/1.0/register-did-with-server-result";

pub const ENROLL_PASSKEY_VM_CHALLENGE: &str =
    "https://firstperson.network/protocols/did-management/1.0/enroll-passkey-vm-challenge";
pub const ENROLL_PASSKEY_VM_CHALLENGE_RESULT: &str =
    "https://firstperson.network/protocols/did-management/1.0/enroll-passkey-vm-challenge-result";

pub const ENROLL_PASSKEY_VM_SUBMIT: &str =
    "https://firstperson.network/protocols/did-management/1.0/enroll-passkey-vm-submit";
pub const ENROLL_PASSKEY_VM_SUBMIT_RESULT: &str =
    "https://firstperson.network/protocols/did-management/1.0/enroll-passkey-vm-submit-result";

pub const LIST_PASSKEY_VMS: &str =
    "https://firstperson.network/protocols/did-management/1.0/list-passkey-vms";
pub const LIST_PASSKEY_VMS_RESULT: &str =
    "https://firstperson.network/protocols/did-management/1.0/list-passkey-vms-result";

pub const REVOKE_PASSKEY_VM: &str =
    "https://firstperson.network/protocols/did-management/1.0/revoke-passkey-vm";
pub const REVOKE_PASSKEY_VM_RESULT: &str =
    "https://firstperson.network/protocols/did-management/1.0/revoke-passkey-vm-result";
