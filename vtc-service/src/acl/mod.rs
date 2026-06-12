pub mod admin;
pub mod entry;
pub mod role;
pub mod storage;

pub use entry::VtcAclEntry;
pub use role::VtcRole;
pub use storage::{
    delete_acl_entry, get_acl_entry, list_acl_entries, list_acl_entries_paginated,
    map_vtc_role_to_auth_role, resolve_auth_role, store_acl_entry, validate_vtc_role_assignment,
};
pub use vti_common::acl::{
    Role, check_acl, check_acl_full, is_acl_entry_visible, validate_acl_modification,
    validate_role_assignment,
};
