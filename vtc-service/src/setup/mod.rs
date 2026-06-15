//! VTC setup surface.
//!
//! - [`bundle`] — `VtcKeyBundle`, the secret-store payload that
//!   carries the VTA-provisioned DID + key material.
//! - [`wizard`] — interactive `vtc setup` flow (feature-gated on
//!   `setup`).
//! - [`from_toml`] — non-interactive `vtc setup --from <toml>`
//!   (feature-gated on `setup`). Builds the same `WizardPlan` the
//!   interactive wizard does and feeds it to the same `apply`.
//!
//! See `tasks/vtc-mvp/vta-driven-keys.md` for the design that
//! drove this module's shape.

pub mod bundle;
#[cfg(feature = "setup")]
pub mod from_toml;
#[cfg(feature = "setup")]
pub mod wizard;

pub use bundle::VtcKeyBundle;
#[cfg(feature = "setup")]
pub use from_toml::run_setup_from_file;
#[cfg(feature = "setup")]
pub use wizard::run_setup_wizard;
