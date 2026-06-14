//! VTC credential-exchange (Phase 3, spec §6) — the issuer answering an OID4VCI
//! `credential-exchange/request` by issuing a credential, and the verifier
//! checking a `credential-exchange/present` [`verify_presentation`].
//!
//! The [`vta_sdk::protocols::credential_exchange`] Trust Tasks carry OID4VCI on
//! the wire; the `affinidi-openid4vci` crate gives us the offer/response
//! builders and *structural* request validation. What it does **not** give us
//! — and what gates issuance — is the **cryptographic verification of the
//! holder's key-binding proof**. That gate lives here:
//! [`verify_oid4vci_proof`] proves the requester controls a key, and
//! [`issue_on_request`] only releases the credential when that proven key is
//! the credential's intended subject.
//!
//! This is the issuer mirror of the VTA holder-receive
//! (`vta-service/src/operations/credential_exchange.rs`, task 3.3). The core
//! [`issue_on_request`] gate is a pure operation; [`make_offer`] + [`redeem`]
//! add the persisted single-use pending-offer store, and the VTC DIDComm
//! `credential-exchange/request` handler (`messaging.rs`) drives `redeem` to
//! complete the `offer → request → issue` loop with the VTA holder side.
//!
//! ## Scope of this slice
//! - **`did:key` holders** — fully wired (the proof `kid` is a `did:key`,
//!   resolved locally, and must equal the credential's bound subject).
//! - A **`did:webvh` / `did:web`** holder proof needs resolver-based key
//!   resolution — a follow-up slice (symmetric with the receive side, which
//!   defers the same resolver path).
//! - **Sealed** issuance to an *unknown* holder (the invite / air-gap case) is
//!   the `sealed_transfer` slice (3.6); this operation is the cleartext,
//!   known-holder path.

mod issue;
mod jwt;
mod pending;
#[cfg(test)]
mod tests;
mod verify;

// Re-export the full public surface so every existing `exchange::*` path
// (credentials/mod.rs, join::retention, routes::recognise, tests) is unchanged.
pub use issue::{ProvenHolderProof, credential_offer, issue_on_request, verify_oid4vci_proof};
pub use pending::{DEFAULT_OFFER_TTL, make_offer, redeem, sweep_expired_pending};
pub use verify::{
    ParsedSdJwtPresentation, VerifiedPresentation, VerifiedPresentationSet, flatten_vp_token,
    parse_sd_jwt_presentation, verify_presentation, verify_vp_token,
};
