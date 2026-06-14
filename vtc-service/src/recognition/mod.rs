//! Cross-community foreign-credential recognition — Phase 3 M3.9 + M3.10.
//!
//! Spec §8.4. The `MembershipSyncer` publishes our community's
//! members to the trust registry; this module is the **inverse**
//! path — taking a foreign community's
//! `VerifiableEndorsementCredential` +
//! `VerifiableMembershipCredential` and deciding whether the
//! local VTC should mint a session for the bearer.
//!
//! ## Session-mint hardening (fail-closed)
//!
//! [`verify::verify_foreign_vec`] runs four checks **in order**;
//! the first failure short-circuits with a typed
//! [`RecognitionError`]. Order matters — proof verification is
//! cheap (one signature + JCS canonicalisation), while the
//! status-list fetch + registry recognition query both hit the
//! network. We want the most disqualifying check (a malformed
//! credential) to surface before any HTTP call lands.
//!
//! 1. **Proof verification.** Both VEC + VMC carry
//!    `DataIntegrityProof::eddsa-jcs-2022` signatures over the
//!    foreign issuer's `#key-0`. Verified through the DI
//!    library's `proof.verify` with the shared
//!    `credentials::vm_resolver::DidVmResolver`
//!    (`VerificationMethodResolver`) — production wires
//!    `DIDCacheClient`, tests inject a stub resolver.
//! 2. **StatusList revocation.** Fetches the credential's
//!    `credentialStatus.statusListCredential` URL, decodes the
//!    bitstring, and checks `statusListIndex`. A set bit
//!    rejects the credential. Production wires
//!    `HttpStatusListFetcher`; tests inject a stub.
//! 3. **Registry recognition.** Calls the
//!    `TrustRegistryClient`'s `recognise()` query for the
//!    foreign issuer DID. A negative result rejects regardless
//!    of how the credentials verify. This is the "operator
//!    forgot to add the foreign community to the recognition
//!    graph" failsafe.
//! 4. **Validity window.** Both `validFrom` ≤ now ≤ `validUntil`
//!    must hold for both credentials. The returned
//!    `VerifiedForeignCredential` carries the **earliest**
//!    `validUntil` across the pair, which the route layer
//!    clamps the session TTL to (spec §8.4).
//!
//! ## No caching
//!
//! Plan D5. Every mint and every refresh re-runs the full
//! check — a peer community removed from the recognition graph
//! mid-session loses access on the next refresh, not on a TTL
//! boundary. The latency tax is acceptable because the
//! cross-community session lifetime is intentionally short
//! (min of three TTLs) and refresh paths are rare relative to
//! "regular member" sessions.

pub mod challenge;
pub mod verify;

pub use verify::{
    HttpStatusListFetcher, RecognitionError, StatusListFetcher, VerifiedForeignCredential,
    verify_foreign_vec,
};
