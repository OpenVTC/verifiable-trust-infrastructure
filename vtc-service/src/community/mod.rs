//! VTC community state — profile, extensions, and the matching
//! `community` keyspace.
//!
//! Implements **M0.7.1** of the VTC MVP Phase 0 plan. The
//! community profile is the public-facing record describing the
//! community itself (name, description, contact, etc.). Per
//! spec §5.1 it's a singleton — one row per VTC binary, stored
//! under the stable key `community/profile`.

pub mod profile;

pub use profile::{
    CommunityProfile, CommunityProfileUpdate, MAX_EXTENSIONS_BYTES, PROFILE_STORAGE_KEY,
    PersonhoodGovernance, load_profile, store_profile,
};
