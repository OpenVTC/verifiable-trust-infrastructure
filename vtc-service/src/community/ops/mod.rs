//! The community's administrative operations: its profile, branding,
//! requested attributes, join discovery and theme, its runtime configuration,
//! and its own DID log — each the body of a signed Trust Task
//! (`trust_tasks::{surface_tasks, config_tasks, admin_tasks, policy_tasks}`).

pub(crate) mod branding;
pub(crate) mod config;
pub(crate) mod did_register;
pub(crate) mod join_discovery;
pub(crate) mod profile;
pub(crate) mod requested_attributes;
pub(crate) mod theme;
