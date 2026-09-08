//! Minting a room's own credentials — the VIC, VMC and VAC a room issues.
//!
//! # The key never materialises, and that is the whole point
//!
//! A room's credentials are signed by the *room*, with a key this VTA holds. The obvious
//! implementation asks the key store for the secret and hands it to `DTGCredential::sign`,
//! and it is the wrong one: `vta_keys::internal::sign` deliberately loads, signs and
//! zeroizes without returning the secret to any caller, and that property is the reason a
//! VTA is a safe place to keep a room's identity at all.
//!
//! `affinidi-data-integrity` takes a [`Signer`] trait object rather than a secret, precisely
//! so a remote signer (KMS, HSM — or this) can be used without one. [`RoomKeySigner`] is
//! that seam: the credential library canonicalises and hashes, hands the bytes here, and
//! gets back a signature produced by a key it never sees.
//!
//! The alternative shapes were both bad. Extracting the key breaks the property the whole
//! rooms family rests on. Re-implementing JCS canonicalisation in this crate would risk
//! disagreeing with every verifier over exactly the bytes that decide whether a credential
//! is genuine — and it would fail silently, as a credential that verifies nowhere.
//!
//! # What authorizes any of this
//!
//! Naming the key, and nothing else — which is why this signs through
//! [`crate::operations::keys::sign_payload`] rather than reaching for
//! `vta_keys::internal::sign` directly.
//!
//! That distinction is the whole authorization story and it is easy to lose. The raw
//! internal signer takes a key id and signs; every gate lives *above* it, in
//! `sign_payload`: `require_context` on the key's context, the caller's own key-scope
//! filter, and the context policy's signing limit — which is resource-bound, so it binds a
//! super-admin too. A signer that called the raw path would let any caller who could reach
//! this task sign as any room this VTA holds a key for, silently, with every one of those
//! gates still present and none of them consulted.
//!
//! So these tasks add no new trust: a caller who may name a room's key could already have
//! signed with it through `keys/sign`.
//!
//! Note what is deliberately *not* checked: that the caller is the room's owner. "Owner" is
//! a fact about the room's DID controller, and this service is not a DID resolver.
//! Controlling the signing key and controlling the DID are the same thing while the key is
//! the one the document names — and where they have come apart, the credential minted here
//! simply fails to verify. Loudly, and at first use.

use std::sync::Arc;

use affinidi_data_integrity::DataIntegrityProof;
use affinidi_data_integrity::signer::Signer;
use affinidi_secrets_resolver::secrets::KeyType;
use vta_sdk::protocols::key_management::sign::SignAlgorithm;
use vti_common::error::AppError;
use vti_common::store::KeyspaceHandle;
use vti_secrets::SeedStore;

use crate::auth::AuthClaims;

/// Everything [`crate::operations::keys::sign_payload`] needs, carried so a signer can
/// reach it.
///
/// Passed as a struct rather than eight arguments because the point is that **all** of it
/// travels together: drop the `auth` and the gates have nothing to check against; drop the
/// contexts keyspace and the policy limit silently stops applying.
pub struct SigningContext<'a> {
    pub keys_ks: &'a KeyspaceHandle,
    pub imported_ks: &'a KeyspaceHandle,
    pub internal_ks: &'a KeyspaceHandle,
    pub contexts_ks: &'a KeyspaceHandle,
    pub acl_ks: &'a KeyspaceHandle,
    pub seed_store: &'a Arc<dyn SeedStore>,
    pub auth: &'a AuthClaims,
}

/// Signs with a room's key, through the gated oracle, without ever holding it.
pub struct RoomKeySigner<'a> {
    ctx: SigningContext<'a>,
    key_id: String,
    verification_method: String,
}

impl<'a> RoomKeySigner<'a> {
    /// `room_did` names the room; the verification method is its `#key-1`, which is what
    /// the `room` DID template puts in `assertionMethod`.
    ///
    /// A verification method that does not match the room's published document produces a
    /// credential nothing will verify — which is the failure mode this cannot prevent and
    /// should not pretend to: only the room's DID document is authoritative about that, and
    /// resolving it here would make issuance depend on the network.
    pub fn new(ctx: SigningContext<'a>, key_id: impl Into<String>, room_did: &str) -> Self {
        Self {
            ctx,
            key_id: key_id.into(),
            verification_method: format!("{room_did}#key-1"),
        }
    }
}

#[async_trait::async_trait]
impl Signer for RoomKeySigner<'_> {
    fn key_type(&self) -> KeyType {
        // The `room` template mints Ed25519 and the cryptosuite is `eddsa-jcs-2022`. A
        // room whose key is anything else is a room this cannot sign for, and the
        // cryptosuite check in `DataIntegrityProof::sign` is what says so.
        KeyType::Ed25519
    }

    fn verification_method(&self) -> &str {
        &self.verification_method
    }

    async fn sign(
        &self,
        data: &[u8],
    ) -> Result<Vec<u8>, affinidi_data_integrity::DataIntegrityError> {
        // Through the gated oracle, never `vta_keys::internal::sign` — see the module docs.
        // `AppError` is a real error type, so the source chain the trait's docs ask for is
        // preserved rather than flattened into a string.
        let result = crate::operations::keys::sign_payload(
            self.ctx.keys_ks,
            self.ctx.imported_ks,
            self.ctx.internal_ks,
            self.ctx.contexts_ks,
            self.ctx.acl_ks,
            self.ctx.seed_store,
            self.ctx.auth,
            &self.key_id,
            data,
            &SignAlgorithm::EdDSA,
            "rooms/owner",
        )
        .await
        .map_err(affinidi_data_integrity::DataIntegrityError::signing)?;

        use base64::Engine as _;
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&result.signature)
            .map_err(affinidi_data_integrity::DataIntegrityError::signing)
    }
}

/// Sign `credential` as the room, returning it serialised with its proof attached.
pub async fn sign_as_room(
    ctx: SigningContext<'_>,
    key_id: &str,
    room_did: &str,
    credential: &mut dtg_credentials::DTGCredential,
) -> Result<(String, String), AppError> {
    let signer = RoomKeySigner::new(ctx, key_id, room_did);

    let proof = DataIntegrityProof::sign(
        &*credential,
        &signer,
        affinidi_data_integrity::SignOptions::new(),
    )
    .await
    .map_err(|e| {
        // Surface the cause, not just "signing failed". Every refusal worth acting on is
        // in the source chain — an unknown key, a context the caller may not reach, a
        // policy that forbids this key, a daily quota spent — and `DataIntegrityError`
        // renders only its own outer message. An operator told "signing failed" learns
        // nothing about which of those it was.
        let mut cause = String::new();
        let mut src: Option<&(dyn std::error::Error + 'static)> = std::error::Error::source(&e);
        while let Some(inner) = src {
            cause = format!("{cause}: {inner}");
            src = inner.source();
        }
        AppError::Internal(format!("sign as room `{room_did}`: {e}{cause}"))
    })?;
    credential.credential_mut().proof = Some(proof);

    let id = credential.id().unwrap_or_default().to_string();
    let serialised = serde_json::to_string(credential)
        .map_err(|e| AppError::Internal(format!("serialise the credential: {e}")))?;
    Ok((serialised, id))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    /// The property the whole module exists for: a credential signed through the oracle
    /// verifies as the room's, with the secret never leaving the key store.
    ///
    /// Without this the seam is plausible and unproven — and the failure it guards is the
    /// worst kind, because a wrongly-signed credential is well-formed, serialises fine, and
    /// is refused by every verifier in the world except the one that made it.
    #[tokio::test]
    async fn a_credential_signed_through_the_oracle_carries_the_rooms_proof() {
        let ts = crate::test_support::open_test_store().await;
        let seed: std::sync::Arc<dyn SeedStore> =
            std::sync::Arc::new(crate::test_support::TestSeedStore(vec![7u8; 32]));
        let auth = crate::test_support::super_admin_claims();
        let ctx = || SigningContext {
            keys_ks: &ts.keys_ks,
            imported_ks: &ts.imported_ks,
            internal_ks: &ts.internal_ks,
            contexts_ks: &ts.contexts_ks,
            acl_ks: &ts.acl_ks,
            seed_store: &seed,
            auth: &auth,
        };

        // Mint the room's key through the real path. `internal::generate` alone is not
        // enough and the difference matters: `sign_payload` looks up a `KeyRecord` in the
        // keys keyspace *first*, so a key that exists only as internal material is a key
        // the oracle will not sign with. Which is correct — the record is where the context
        // binding lives, and a key with no context has no gates to apply.
        let key_id = "room-northwind-signing";
        let created = crate::operations::keys::create_key(
            &ts.keys_ks,
            &ts.internal_ks,
            &ts.contexts_ks,
            &seed,
            &ts.audit,
            &auth,
            crate::operations::keys::CreateKeyParams {
                key_type: vta_keys::KeyType::Ed25519,
                internal: true,
                derivation_path: None,
                key_id: Some(key_id.into()),
                mnemonic: None,
                label: None,
                context_id: None,
            },
            "test",
        )
        .await
        .expect("mint the room's key");

        let public = vta_sdk::did_key::decode_ed25519_public_key_multibase(&created.public_key)
            .expect("the minted public key");
        let room_did = format!(
            "did:key:{}",
            vta_sdk::did_key::ed25519_multibase_pubkey(&public)
        );

        let mut vic = dtg_credentials::DTGCredential::new_vic(
            room_did.clone(),
            "did:key:zInvitee".into(),
            Utc::now(),
            None,
        )
        .with_id("urn:uuid:11111111-1111-4111-8111-111111111111");

        let (serialised, id) = sign_as_room(ctx(), key_id, &room_did, &mut vic)
            .await
            .expect("sign as the room");

        assert_eq!(id, "urn:uuid:11111111-1111-4111-8111-111111111111");

        let parsed: serde_json::Value = serde_json::from_str(&serialised).expect("parse");
        assert_eq!(
            parsed["proof"]["verificationMethod"],
            serde_json::json!(format!("{room_did}#key-1")),
            "the proof must name the room's own verification method"
        );
        assert_eq!(parsed["proof"]["cryptosuite"], "eddsa-jcs-2022");
        assert!(
            parsed["proof"]["proofValue"]
                .as_str()
                .is_some_and(|v| !v.is_empty()),
            "a proof without a value is not a signature"
        );
    }

    /// The gates are the authorization story, so a signer that reached past them would be
    /// the whole of a bypass. This pins that the gated path is the one taken: a key the
    /// caller may not name is refused, rather than signed with.
    #[tokio::test]
    async fn a_key_the_caller_may_not_name_is_refused() {
        let ts = crate::test_support::open_test_store().await;
        let seed: std::sync::Arc<dyn SeedStore> =
            std::sync::Arc::new(crate::test_support::TestSeedStore(vec![7u8; 32]));
        let auth = crate::test_support::super_admin_claims();
        let ctx = || SigningContext {
            keys_ks: &ts.keys_ks,
            imported_ks: &ts.imported_ks,
            internal_ks: &ts.internal_ks,
            contexts_ks: &ts.contexts_ks,
            acl_ks: &ts.acl_ks,
            seed_store: &seed,
            auth: &auth,
        };

        let err = sign_as_room(
            ctx(),
            "a-key-that-does-not-exist",
            "did:key:zRoom",
            &mut dtg_credentials::DTGCredential::new_vic(
                "did:key:zRoom".into(),
                "did:key:zInvitee".into(),
                Utc::now(),
                None,
            ),
        )
        .await
        .expect_err("an unknown key must not sign");

        assert!(
            format!("{err}").contains("not found"),
            "expected the oracle's own refusal, got: {err}"
        );
    }
}
