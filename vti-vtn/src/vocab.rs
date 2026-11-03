//! Predicate IRIs for the VTN statement profiles.
//!
//! A one-sided listing is a VSC under [`LISTS_V1`], not an unacknowledged VMC grant, as
//! the DTG WG agreed (dtgwg-cred-spec discussion #82). [`LISTS_V1`] and
//! [`REPUDIATES_V1`] are registered in the DTG VSC registry (dtgwg-vsc-registry #33).
//! The group predicates are not registered yet and stay in a VTN-controlled namespace
//! (**assumption A1**, `docs/assumptions.md`).

/// Namespace under which the VTN's unregistered predicate profiles are minted.
pub const VTN_VSC_NAMESPACE: &str = "https://openvtc.org/vtn/vsc/";

/// The network lists the subject. `object.value` = `{ nodeType, framework }`
/// ([`LISTING_SCHEMA`]). Attests a curation decision; establishes nothing (VTI-VTN-020).
pub const LISTS_V1: &str = "https://registry.trustoverip.org/dtg/vsc/lists/1";

/// The JSON Schema for a [`LISTS_V1`] statement's `object.value`.
pub const LISTING_SCHEMA: &str =
    "https://registry.trustoverip.org/dtg/vsc/lists/1/listing.schema.json";

/// The issuer (the listed party) does not accept the credential the network (the
/// subject) issued about it. `object.digestMultibase` = the listing VSC, or the VMC
/// grant, being repudiated. Repudiating a listing makes the entry `repudiated`
/// (VTI-VTN-012); repudiating a grant is departure.
pub const REPUDIATES_V1: &str = "https://registry.trustoverip.org/dtg/vsc/repudiates/1";

/// The issuer (a member) registers the subject (a group it owns) to serve a network role.
/// `object.value` = `{ network, role }`. Used by network groups (phase 2).
pub const SERVES_ROLE_V1: &str = "https://openvtc.org/vtn/vsc/servesRole/1";

/// The network accepts a group registration. `object.digestMultibase` = the servesRole VSC.
pub const GROUP_REGISTERED_V1: &str = "https://openvtc.org/vtn/vsc/groupRegistered/1";
