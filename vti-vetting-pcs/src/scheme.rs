//! The instantiation and the labels (design §13 C1).
//!
//! - ONE deployment label per community, with no epoch in it: `pp`, and so every applicant's
//!   `id`, is fixed for the life of the community.
//! - ONE long-lived helper key `hvk`; it rotates only on compromise.
//! - The epoch is in the CLASS label of the vetter root predicate, `vetter/<period>`. The
//!   helper's AllowList holds the live labels, so one proof may mix epochs.
//! - Tokens use a separate deployment label and key (never `hvk`), with the period in the token
//!   label `token/<period>` or `token/event/<id>`.

use ark_bls12_381::{Bls12_381, G1Projective};
use predicate_credential_system::{
    cred::PS,
    hash::bls12_381::G1Hasher,
    kiprf::DDH,
    pcs::{AllowList, PCS, Predicate},
    serialization::{from_bytes, from_multibase, to_bytes, to_multibase},
};

use crate::ProtoError;

pub type E = Bls12_381;
pub type G1 = G1Projective;
pub type Fr = ark_bls12_381::Fr;
/// `Σ-PS`: the paper's main instantiation, and the base the tokens reuse.
pub type Base = PS<E>;
pub type Tag = DDH<G1, G1Hasher>;
/// The scheme with the default policy: for users, and for deriving `pp`.
pub type Open = PCS<E, Base, Tag>;
/// The scheme as the helper runs it: never with the default policy.
pub type Helper = PCS<E, Base, Tag, AllowList<Fr>>;
/// The helper's verification key, published in the manifest.
pub type Hvk = <Base as predicate_credential_system::cred::CredentialBase>::VerificationKey;

pub fn deployment_label(community: &str) -> Vec<u8> {
    format!("{community}#vetting-pcs").into_bytes()
}

pub fn token_deployment_label(community: &str) -> Vec<u8> {
    format!("{community}#vetting-token").into_bytes()
}

/// The vetter root predicate for one epoch.
pub fn vetter_predicate(period: &str) -> Predicate {
    Predicate::root(format!("vetter/{period}").into_bytes())
}

/// The verify-only applicant predicate: `n` distinct vetters (§13 C4: any `n`, because the VTC
/// never issues under it).
pub fn hidden_vetting_predicate(n: u32) -> Predicate {
    Predicate::new(n, b"hidden-vetting".to_vec())
}

pub fn monthly_token_label(period: &str) -> String {
    format!("token/{period}")
}

pub fn event_token_label(event_id: &str) -> String {
    format!("token/event/{event_id}")
}

/// Multibase text of a group element (identifiers, tags).
pub fn point_text(p: &G1) -> Result<String, ProtoError> {
    Ok(to_multibase(&to_bytes(p)?))
}

/// Multibase text of any canonically-encodable value.
///
/// # Errors
/// [`ProtoError::Pcs`] if the value cannot be encoded.
pub fn enc<T: ark_serialize::CanonicalSerialize>(v: &T) -> Result<String, ProtoError> {
    Ok(to_multibase(&to_bytes(v)?))
}

/// The inverse of [`enc`], with validated decoding.
///
/// # Errors
/// [`ProtoError::Pcs`] if the text is not multibase base58btc, or the bytes are not a valid
/// encoding of `T`.
pub fn dec<T: ark_serialize::CanonicalDeserialize>(s: &str) -> Result<T, ProtoError> {
    Ok(from_bytes(&from_multibase(s)?)?)
}

/// Multibase text of a verification key (`hvk`, `tvk`), as a manifest publishes it.
///
/// # Errors
/// [`ProtoError::Pcs`] if the key cannot be encoded.
pub fn key_text<T: ark_serialize::CanonicalSerialize>(key: &T) -> Result<String, ProtoError> {
    Ok(to_multibase(&to_bytes(key)?))
}

/// A group element from its multibase text; the inverse of [`point_text`].
///
/// # Errors
/// [`ProtoError::Pcs`] if the text is not multibase base58btc, or the bytes are not a point in
/// the prime-order subgroup (decoding is validated).
pub fn point_from_text(text: &str) -> Result<G1, ProtoError> {
    Ok(from_bytes(&from_multibase(text)?)?)
}

/// Multibase text of a scalar (serials).
pub fn scalar_text(s: &Fr) -> Result<String, ProtoError> {
    Ok(to_multibase(&to_bytes(s)?))
}

/// A deterministic stream for deriving a member's PCS key pair from a 32-byte seed.
///
/// The VTA derives the seed from the context's derivation base (VTI-KEY-030) and feeds this to
/// the scheme's own key generation, so the same seed always yields the same `usk` and `id`,
/// restarts included. ChaCha20, as [`crate::issuer`] uses for the community's keys: the stream
/// is fixed by the seed on any build.
#[must_use]
pub fn seeded_rng(seed: &[u8; 32]) -> rand_chacha::ChaCha20Rng {
    use rand::SeedableRng;
    rand_chacha::ChaCha20Rng::from_seed(*seed)
}

/// A member's PCS key pair for `community`, derived from `seed` — the same pair
/// [`crate::vetter::VetterEngine::enrol_from_seed`] and
/// [`crate::applicant::ApplicantEngine::from_seed`] make, since the scheme instance is a function
/// of the community alone ([`deployment_label`]).
///
/// What a VTA calls to rebuild a stored engine's key on every use, so the key itself is never
/// stored (design §13 C7).
///
/// # Errors
/// [`ProtoError::Pcs`] if the scheme instance cannot be set up or the key cannot be generated.
pub fn member_key_from_seed(
    community: &str,
    seed: &[u8; 32],
) -> Result<(G1, predicate_credential_system::pcs::UserSecretKey<E>), ProtoError> {
    use predicate_credential_system::pcs::{PredicateCredentialSystem, SetupParams};
    let open = Open::setup(SetupParams::new(deployment_label(community)))?;
    Ok(open.user_keygen(&mut seeded_rng(seed))?)
}
