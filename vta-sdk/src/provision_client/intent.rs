//! Shared VTA request / reply types for the online provisioning workflow.
//!
//! Three intents are supported:
//!
//! - [`VtaIntent::FullSetup`] — the VTA mints the integration's DID via a
//!   template render, rolls over an admin DID, and returns a
//!   [`super::result::ProvisionResult`] with keys, `did.jsonl`,
//!   authorization VC, and VTA trust bundle.
//! - [`VtaIntent::AdminOnly`] — the integration brings its own DID; the
//!   VTA only issues an admin credential and an ACL row. The setup DID
//!   *is* the long-term admin DID — no rotation. The reply carries an
//!   admin DID + matching private key.
//! - [`VtaIntent::AdminRotated`] — the integration brings its own
//!   integration DID **and** wants the admin DID rotated to a fresh
//!   VTA-minted identity. Same wire flow as `FullSetup` minus the
//!   integration mint. The setup DID authenticates the bootstrap and
//!   loses its authority at the end of the round-trip; the rotated
//!   admin DID becomes the long-term credential. The reply shape
//!   mirrors `AdminOnly` (admin DID + private key), just with a
//!   different DID.
//!
//! Each intent produces a [`VtaReply`] that downstream consumers handle
//! uniformly. The runners in this module produce these replies; the
//! consumer's UI / persistence layer consumes them.
//!
//! Offline / sealed-handoff variants are out of scope for this module —
//! see the workspace `vta bootstrap` CLI for that flow.

use super::result::ProvisionResultV2;

/// What the operator wants the VTA to do during setup.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VtaIntent {
    /// VTA mints the integration's DID via a template render, rolls over
    /// an admin DID, and returns a [`ProvisionResult`].
    FullSetup,
    /// The integration brings its own DID (out of band); the VTA only
    /// issues an admin credential and an ACL row. The setup DID *is*
    /// the long-term admin DID — no rotation. The reply carries an
    /// admin DID + matching private key.
    AdminOnly,
    /// The integration brings its own DID **and** wants the admin DID
    /// rotated. The setup did:key authenticates the bootstrap and is
    /// then dropped; the VTA mints a fresh admin DID via the
    /// `vta-admin` template, binds the authorization VC + ACL row to
    /// it, and returns the rotated DID + key material. Use this when
    /// a short-lived setup ACL grant should be replaced with a
    /// long-term VTA-minted admin identity in one round-trip.
    AdminRotated,
}

/// Unified reply from the online runners.
///
/// Downstream consumers switch on the variant instead of branching on
/// intent separately. `Full` is boxed so the enum's stack footprint
/// stays uniform regardless of which variant is in play (the underlying
/// `ProvisionResult` is ~528 bytes vs `AdminCredentialReply`'s ~48).
#[derive(Clone, Debug)]
pub enum VtaReply {
    /// Full template-bootstrap reply. The VTA minted the integration's
    /// DID, (optionally) rolled over an admin DID, and returned the
    /// complete trust bundle.
    ///
    /// Carries [`ProvisionResultV2`] so **one reply shape covers both sealed
    /// variants**: a `TemplateBootstrap` bundle lifts into it losslessly, and a
    /// `TemplateBootstrapV2` one arrives with its extra signing keys intact.
    /// A second variant here would have meant two names for the same event, and
    /// every consumer branching on which bundle the VTA happened to seal — a
    /// question none of them actually has.
    Full(Box<ProvisionResultV2>),
    /// Admin-credential-only reply. The integration keeps its own DID;
    /// the VTA supplied an admin identity it authenticates as against
    /// the VTA's admin APIs.
    AdminOnly(AdminCredentialReply),
}

/// Payload of [`VtaReply::AdminOnly`] — an admin DID and its private key.
#[derive(Clone)]
pub struct AdminCredentialReply {
    /// Admin DID the integration authenticates as.
    pub admin_did: String,
    /// Private key (multibase) paired with `admin_did`.
    pub admin_private_key_mb: String,
}

/// Written by hand so the private key never reaches a log: a derived `Debug` would print it.
impl std::fmt::Debug for AdminCredentialReply {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AdminCredentialReply")
            .field("admin_did", &self.admin_did)
            .field("admin_private_key_mb", &"<redacted>")
            .finish()
    }
}
