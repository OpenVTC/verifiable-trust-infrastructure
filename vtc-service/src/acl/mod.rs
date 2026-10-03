pub mod admin;
pub mod admin_consent;
pub mod approver;
pub mod bound_step_up;
pub mod capability;
pub mod console_key;
pub mod delegation;
pub mod elevation;
pub mod entry;
pub mod granting;
pub mod migrate;
pub mod role;
pub mod single_admin;
pub mod storage;

pub use capability::{
    AdminAuthority, AdminRole, CapRef, Capability, CapabilityGrant, CapabilityScope,
    ResourceQualifier, VtcActScope,
};
pub use entry::VtcAclEntry;
pub use role::{VtcRole, as_vti_role};
pub use storage::{
    auth_role_for, capability_refusal, delete_acl_entry, get_acl_entry, list_acl_entries,
    list_acl_entries_paginated, require_any_capability, require_capability, resolve_auth_role,
    store_acl_entry,
};
/// The authority a test fixture written before role-based administration
/// means by `(community role, contexts)`.
///
/// No contexts: the authority the community role implies under the 0.1
/// convention ([`VtcRole::implied_authority`]) — `admin` is a community
/// administrator. Contexts: what used to be "an administrator of some
/// contexts" — an administrator, but not a community administrator — which
/// stands as a `moderator`. A community holds no contexts (VTI-VTC-010), so the
/// list itself confers nothing.
#[doc(hidden)]
pub fn legacy_seed_authority<S: AsRef<str>>(role: &VtcRole, contexts: &[S]) -> AdminAuthority {
    match contexts.first() {
        None => role.implied_authority(),
        Some(_) if *role == VtcRole::Admin => AdminAuthority::for_role(AdminRole::Moderator),
        Some(_) => AdminAuthority::none(),
    }
}

pub use vti_common::acl::{
    ActScope, Role, check_acl, check_acl_full, is_acl_entry_visible, validate_acl_modification,
    validate_role_assignment,
};
