pub mod create;
pub mod derive_and_sign;
pub mod derive_and_sign_document;
pub mod get;
pub mod list;
pub mod rename;
pub mod revoke;
pub mod secret;
pub mod sign;

pub const PROTOCOL_BASE: &str = "https://firstperson.network/protocols/key-management/1.0";

pub const CREATE_KEY: &str = "https://firstperson.network/protocols/key-management/1.0/create-key";
pub const CREATE_KEY_RESULT: &str =
    "https://firstperson.network/protocols/key-management/1.0/create-key-result";

pub const GET_KEY: &str = "https://firstperson.network/protocols/key-management/1.0/get-key";
pub const GET_KEY_RESULT: &str =
    "https://firstperson.network/protocols/key-management/1.0/get-key-result";

pub const LIST_KEYS: &str = "https://firstperson.network/protocols/key-management/1.0/list-keys";
pub const LIST_KEYS_RESULT: &str =
    "https://firstperson.network/protocols/key-management/1.0/list-keys-result";

pub const RENAME_KEY: &str = "https://firstperson.network/protocols/key-management/1.0/rename-key";
pub const RENAME_KEY_RESULT: &str =
    "https://firstperson.network/protocols/key-management/1.0/rename-key-result";

pub const REVOKE_KEY: &str = "https://firstperson.network/protocols/key-management/1.0/revoke-key";
pub const REVOKE_KEY_RESULT: &str =
    "https://firstperson.network/protocols/key-management/1.0/revoke-key-result";

pub const GET_KEY_SECRET: &str =
    "https://firstperson.network/protocols/key-management/1.0/get-key-secret";
pub const GET_KEY_SECRET_RESULT: &str =
    "https://firstperson.network/protocols/key-management/1.0/get-key-secret-result";

pub const SIGN_REQUEST: &str =
    "https://firstperson.network/protocols/key-management/1.0/sign-request";
pub const SIGN_RESULT: &str =
    "https://firstperson.network/protocols/key-management/1.0/sign-result";

pub const IMPORT_KEY: &str = "https://firstperson.network/protocols/key-management/1.0/import-key";
pub const IMPORT_KEY_RESULT: &str =
    "https://firstperson.network/protocols/key-management/1.0/import-key-result";

pub const GET_WRAPPING_KEY: &str =
    "https://firstperson.network/protocols/key-management/1.0/get-wrapping-key";
pub const GET_WRAPPING_KEY_RESULT: &str =
    "https://firstperson.network/protocols/key-management/1.0/get-wrapping-key-result";
