pub mod list;
pub mod retention;
pub mod verify;

pub const PROTOCOL_BASE: &str = "https://firstperson.network/protocols/audit-management/1.0";

pub const LIST_LOGS: &str = "https://firstperson.network/protocols/audit-management/1.0/list-logs";
pub const LIST_LOGS_RESULT: &str =
    "https://firstperson.network/protocols/audit-management/1.0/list-logs-result";

pub const GET_RETENTION: &str =
    "https://firstperson.network/protocols/audit-management/1.0/get-retention";
pub const GET_RETENTION_RESULT: &str =
    "https://firstperson.network/protocols/audit-management/1.0/get-retention-result";

pub const UPDATE_RETENTION: &str =
    "https://firstperson.network/protocols/audit-management/1.0/update-retention";
pub const UPDATE_RETENTION_RESULT: &str =
    "https://firstperson.network/protocols/audit-management/1.0/update-retention-result";
