//! Predicate IRIs for the VTN statement profiles.
//!
//! **Assumption A1** (`docs/assumptions.md`): until the DTG WG decides (discussion #82,
//! item 3), a one-sided listing is a VSC under [`LISTS_V1`], not an unacknowledged VMC
//! grant, and the profiles live in a VTN-controlled namespace rather than the DTG VSC
//! registry. Moving them is a constant change here plus a re-issue of live listings.

/// Namespace under which the VTN predicate profiles are minted.
pub const VTN_VSC_NAMESPACE: &str = "https://openvtc.org/vtn/vsc/";

/// The network lists the subject. `object.value` = `{ kind, framework }`.
/// Attests a curation decision; establishes nothing (VTI-VTN-020).
pub const LISTS_V1: &str = "https://openvtc.org/vtn/vsc/lists/1";

/// The subject (a network) is repudiated by the issuer (the listed party).
/// `object.digestMultibase` = the listing VSC, or the VMC grant, being repudiated.
/// Repudiating a listing makes the entry `repudiated` (VTI-VTN-012); repudiating a grant
/// is departure.
pub const REPUDIATES_V1: &str = "https://openvtc.org/vtn/vsc/repudiates/1";

/// The issuer (a member) registers the subject (a group it owns) to serve a network role.
/// `object.value` = `{ network, role }`. Used by network groups (phase 2).
pub const SERVES_ROLE_V1: &str = "https://openvtc.org/vtn/vsc/servesRole/1";

/// The network accepts a group registration. `object.digestMultibase` = the servesRole VSC.
pub const GROUP_REGISTERED_V1: &str = "https://openvtc.org/vtn/vsc/groupRegistered/1";
