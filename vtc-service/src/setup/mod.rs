//! VTC setup surface.
//!
//! - [`bundle`] — `VtcKeyBundle`, the secret-store payload that
//!   carries the VTA-provisioned DID + key material.
//! - [`wizard`] — interactive `vtc setup` flow (feature-gated on
//!   `setup`).
//!
//! See `tasks/vtc-mvp/vta-driven-keys.md` for the design that
//! drove this module's shape.

pub mod bundle;
#[cfg(feature = "setup")]
pub mod wizard;

pub use bundle::VtcKeyBundle;
#[cfg(feature = "setup")]
pub use wizard::run_setup_wizard;
