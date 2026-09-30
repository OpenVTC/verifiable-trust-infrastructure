//! Credentials issued by the VTC — Phase 2 M2.9.
//!
//! Spec §6.1's DTG catalog. This module covers the two
//! credentials Phase 2 mints from a member-side action:
//!
//! - **VMC** ([`vmc`]) — Verifiable Membership Credential. One per
//!   member, re-minted on join + every renewal. Bounded
//!   `validUntil` per spec §3-F.
//! - **Role VAC** ([`vac`]) — Verifiable Authority Credential conferring
//!   `role:<name>` at the community's DID. Re-issued on every role change.
//!
//! Beside them: community statements ([`statement`], a VSC under a
//! registered predicate — what `vtc/endorsements/issue` mints), invitations,
//! and the identity-verification credential ([`idvc`]), which is deliberately
//! a plain W3C VC rather than a DTG credential.
//!
//! Both are signed locally via [`LocalSigner`] — plan §D1's
//! "cached-locally, VTA-controlled" model. The VTC's `#key-0`
//! Ed25519 secret already lives in the secret store; no per-call
//! VTA round-trip.
//!
//! ## Why M2.9 is one PR-sized module
//!
//! The two credential builders share their signing path,
//! validity-window plumbing, and `@context`-URL handling. They
//! also share their test-fixture pattern (deterministic seed →
//! known issuer DID + verify the proof with the matching
//! public key). Keeping the surface together means the M2.12
//! issuance step (VMC + VAC on approve) and the M2.13 renewal
//! step both reach for one canonical module.
//!
//! Every DTG credential here carries the v1 context
//! (`dtg_credentials::DTG_CONTEXT_V1`) and `issuerScope` `public` — see
//! [`dtg`].
//!
//! ## Shape parity with `vta-sdk::provision_integration::credential`
//!
//! The reference implementation in the VTA SDK signs a
//! `VtaAuthorizationCredential` the same way: `CredentialBuilder`
//! → `DataIntegrityProof::sign(&vc, &secret, …)` → attach proof.
//! We follow that pattern verbatim so the workspace has exactly
//! one canonical way to sign a VC.
//!
//! ## Status-list credentialStatus
//!
//! The VMC builder accepts an optional [`CredentialStatusRef`].
//! When present, the VMC carries a `credentialStatus` block
//! pointing at the relevant BitstringStatusList entry. M2.9
//! lands the *shape*; M2.10 + M2.11 populate the URL +
//! index from a live status-list registry. M2.9 alone can be
//! exercised with the optional left as `None` — the resulting
//! VMC has no `credentialStatus`, which is the expected
//! pre-status-list state in tests.

pub mod delivery;
pub mod dtg;
pub mod exchange;
pub mod idvc;
pub mod ingress;
pub mod invitation;
pub mod invitation_registry;
pub mod invitation_verify;
pub mod lifecycle;
pub mod present_challenge;
pub(crate) mod proof_set;
pub mod signer;
pub mod statement;
pub mod task_context;
pub mod vac;
pub mod vm_resolver;
pub mod vmc;
pub mod witness;

pub use exchange::{
    DEFAULT_OFFER_TTL, ProvenHolderProof, VerifiedPresentation, VerifiedPresentationSet,
    credential_offer, issue_on_request, make_offer, redeem, verify_oid4vci_proof,
    verify_presentation, verify_vp_token,
};
pub use signer::LocalSigner;
pub use statement::{StatementParams, build_statement};
pub use vac::{RoleVacParams, build_role_vac};
pub use vmc::{CredentialStatusRef, VmcParams, build_vmc};

/// Default validity for a freshly-minted VMC when the caller
/// doesn't override. Mirrors spec §3-F's "default 30d" — short
/// enough that a leaked credential expires in a useful window,
/// long enough that legitimate verifiers don't trip over expiry
/// on a casual cadence. Operators tighten via configuration.
pub const DEFAULT_VMC_VALIDITY: chrono::Duration = chrono::Duration::days(30);
