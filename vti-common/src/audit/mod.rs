//! Audit log infrastructure — versioned envelope with HMAC-hashed
//! actor / target identifiers and an in-store key history that
//! survives right-to-be-forgotten rotations.
//!
//! See spec §11 of `docs/05-design-notes/vtc-mvp.md` for the design
//! rationale.
//!
//! ## Module layout
//!
//! - [`event`] — the tagged [`AuditEvent`] enum and its per-variant
//!   data structs. Ships the Phase-0 vocabulary
//!   (`CommunityInstalled`, `EmergencyBootstrapInvoked`,
//!   `AdminPasskey{Registered,Revoked}`, `Config{Changed,Reloaded}`,
//!   `RestartRequested`, `CommunityProfileUpdated`,
//!   `AuditKeyRotated`). Phase-1+ variants land alongside their
//!   owning features.
//! - [`envelope`] — the [`AuditEnvelope`] wire shape (event id,
//!   version, timestamps, HMAC-hashed + plaintext identifier pairs).
//! - [`key_store`] — the [`AuditKeyStore`] managing per-community
//!   `audit_key` history: HKDF-derived initial, fresh-random
//!   rotations, indefinite retention so pre-rotation hashes stay
//!   verifiable during compliance investigations.
//! - [`writer`] — [`AuditWriter`] takes events + identifiers, hashes
//!   the identifiers with the active key, and persists the envelope
//!   into an `audit` keyspace.

pub mod envelope;
pub mod event;
pub mod key_store;
pub mod writer;

pub use envelope::{AuditEnvelope, EVENT_VERSION, SCHEMA_VERSION};
pub use event::{
    AclChangeData, AclRevokedData, AdminInviteData, AdminPasskeyData, AdminPromotedData,
    AdminUiServedData, AuditEvent, AuditKeyRotatedData, BackupData, CommunityInstalledData,
    CommunityProfileUpdatedData, ConfigChange, ConfigChangedData, ConfigReloadedData, ConfigSource,
    CredentialIssuedData, CrossCommunitySessionMintedData, CustomEndorsementIssuedData,
    CustomEndorsementRevokedData, DidRotatedData, EmergencyBootstrapData,
    EndorsementTypeDeletedData, EndorsementTypeRegisteredData, InvitationIssuedData,
    InvitationRevokedData, JoinRequestData, JoinRequestRejectedData, MemberAddedData,
    MemberRemovedData, MemberUpdatedData, MembershipReciprocatedData, MembershipRenewedData,
    PersonhoodAssertedData, PersonhoodRevokedData, PolicyActivatedData, PolicyUploadedData,
    REDACTED_MARKER, RegistryRecordPolicyOverrideData, RegistryStatusChangedData,
    RegistrySyncOutcomeData, RestartRequestedData, RoleChangedData, SessionRevokedData,
    StatusListFlippedData, VrcPublishedData, VrcRevokedData, WebsiteBundleDeployedData,
    WebsiteFileDeletedData, WebsiteFileWrittenData, WebsiteGenerationRolledBackData,
};
pub use key_store::{AuditKey, AuditKeyStore, KeyId, RotationReason};
pub use writer::AuditWriter;
