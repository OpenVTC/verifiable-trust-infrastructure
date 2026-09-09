//! The member's own signing identity, held in wasm.
//!
//! Everything a member signs — the authority presentation's leaf, and the Trust-Task
//! documents a host authenticates them by — is signed here, so the private key never
//! crosses into JavaScript at all.
//!
//! That is a change from where this started. The first cut minted the key with WebCrypto
//! and kept the JWK in `localStorage`, which put a raw private key in a page's heap and in
//! a string store any script on the origin can read — and contradicted this crate's own
//! rule that secrets do not cross the boundary. Minting it here costs nothing (the crate
//! already links `ed25519-dalek` through OpenMLS) and means one place owns every secret the
//! member has.
//!
//! The snapshot is the one exception, and the same exception the group snapshot is: it *is*
//! key material, and the caller's job is to put it somewhere per-origin and per-device and
//! nowhere else.
//!
//! # Why `did:key`
//!
//! Self-certifying: the verification key is the identifier, so a counterparty verifies a
//! signature without resolving anything. A member who is a stranger with a link has no
//! infrastructure to be reachable at, and needs none — which is exactly the case this whole
//! demo exists for. It is also what lets `room-host` run its conservative `did:key`-only
//! verifier, where no unauthenticated request can trigger a network lookup.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use chrono::{Duration, Utc};
use dtg_credentials::DTGCredential;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// How long a minted presentation is good for.
///
/// Deliberately not a parameter. A caller that could ask for a year would be asking for the
/// standing credential a presentation exists not to be — "the page needed longer" is a
/// reason to mint again, not to mint longer. Matches `vta-service`'s oracle.
const PRESENTATION_LIFETIME: Duration = Duration::hours(4);

/// A member's signing identity: an Ed25519 key and the `did:key` it names.
///
/// `Debug` is hand-written rather than derived, and deliberately: a derived one prints the
/// signing key, and the places a `Debug` reaches — a log line, a panic message, a test
/// failure — are exactly the places key material must not turn up.
pub struct MemberIdentity {
    did: String,
    signing: ed25519_dalek::SigningKey,
}

/// The stored form. **Key material** — see the module docs.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct IdentityFile {
    did: String,
    /// The Ed25519 seed, base64url.
    seed: String,
}

impl MemberIdentity {
    /// Mint a fresh identity.
    pub fn mint() -> Result<Self, String> {
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed).map_err(|e| format!("no randomness available: {e}"))?;
        Ok(Self::from_seed(seed))
    }

    fn from_seed(seed: [u8; 32]) -> Self {
        let signing = ed25519_dalek::SigningKey::from_bytes(&seed);
        let mut multicodec = vec![0xed, 0x01];
        multicodec.extend_from_slice(signing.verifying_key().as_bytes());
        let did = format!(
            "did:key:{}",
            multibase::encode(multibase::Base::Base58Btc, &multicodec)
        );
        Self { did, signing }
    }

    pub fn restore(snapshot: &str) -> Result<Self, String> {
        let file: IdentityFile =
            serde_json::from_str(snapshot).map_err(|e| format!("identity snapshot: {e}"))?;
        let bytes = B64
            .decode(file.seed.as_bytes())
            .map_err(|e| format!("identity seed: {e}"))?;
        let seed: [u8; 32] = bytes
            .try_into()
            .map_err(|_| "identity seed is not 32 bytes".to_string())?;
        let restored = Self::from_seed(seed);
        // A `did:key` is derived from its key, so a snapshot whose DID does not match its
        // seed was edited or swapped. Cheap to check and it fails here rather than as an
        // unexplained refusal from a host later.
        if restored.did != file.did {
            return Err("the identity snapshot's DID does not match its key".into());
        }
        Ok(restored)
    }

    pub fn snapshot(&self) -> Result<String, String> {
        serde_json::to_string(&IdentityFile {
            did: self.did.clone(),
            seed: B64.encode(self.signing.to_bytes()),
        })
        .map_err(|e| e.to_string())
    }

    pub fn did(&self) -> &str {
        &self.did
    }

    /// The `did:key` verification method: the multibase tag IS the fragment, by convention.
    fn verification_method(&self) -> String {
        format!("{}#{}", self.did, &self.did["did:key:".len()..])
    }

    fn secret(&self) -> Result<affinidi_secrets_resolver::secrets::Secret, String> {
        affinidi_secrets_resolver::secrets::Secret::from_str(
            &self.verification_method(),
            &serde_json::json!({
                "crv": "Ed25519",
                "d": B64.encode(self.signing.to_bytes()),
                "kty": "OKP",
                "x": B64.encode(self.signing.verifying_key().as_bytes()),
            }),
        )
        .map_err(|e| format!("build the signing secret: {e}"))
    }

    /// Attach this member's `eddsa-jcs-2022` proof to a JSON document.
    ///
    /// What a host authenticates a request by: it takes the presenter from the document's
    /// own proof and never from a payload field, because a presentation says what may be
    /// done and not who is doing it — an unbound one is a bearer token anyone observing it
    /// inherits.
    pub fn sign_document(&self, document: &str) -> Result<String, String> {
        let mut doc: Value =
            serde_json::from_str(document).map_err(|e| format!("document is not JSON: {e}"))?;
        // A proof never covers itself.
        doc.as_object_mut()
            .ok_or("a signable document must be a JSON object")?
            .remove("proof");

        let secret = self.secret()?;
        let proof =
            futures_lite::future::block_on(affinidi_data_integrity::DataIntegrityProof::sign(
                &doc,
                &secret,
                affinidi_data_integrity::SignOptions::new(),
            ))
            .map_err(|e| format!("sign the document: {e}"))?;

        doc.as_object_mut()
            .ok_or("a signable document must be a JSON object")?
            .insert(
                "proof".into(),
                serde_json::to_value(&proof).map_err(|e| e.to_string())?,
            );
        serde_json::to_string(&doc).map_err(|e| e.to_string())
    }

    /// Mint an authority presentation for one action on one room.
    ///
    /// `vac` is the authority credential the room issued this member; `vmc` its membership
    /// credential. The result is `{ membership, authority: [leaf, root], nonce }` — the
    /// shape every host task takes and nothing else produces.
    ///
    /// # Attenuation, not issuance
    ///
    /// The leaf is derived from the root by `attenuate`, which refuses to widen. So asking
    /// for an action this member does not hold fails in the credential library rather than
    /// at a check here that somebody could forget to write — and it fails on *this* side,
    /// where the member can be told why, rather than as a refusal from the host.
    ///
    /// # The subject is us, and that is the unusual part
    ///
    /// Server-side this attenuates to a separate agent, so the leaf's subject and the
    /// chain root's differ. A browser member is its own agent, so here they are the same
    /// DID — a shape the VTA's path never produces. The pooling defence compares the
    /// chain's **root** subject rather than its leaf, so it holds either way; it is
    /// asserted in the tests rather than assumed.
    ///
    /// # There is no `audience` parameter, and that is deliberate
    ///
    /// `audience` is not "who this is addressed to". `verify_chain` compares it to the
    /// **presenter** — "the leaf must be presentable by whoever is presenting it" — so it is
    /// holder binding, and its whole job is to make a captured presentation worthless to
    /// anyone else. A browser member always presents its own, so the only correct value is
    /// this member's DID, and offering the choice is offering a way to get it wrong.
    ///
    /// Which is not hypothetical. `vta-cli-common`'s `RoomTarget` passes the **host's** DID
    /// as the audience, so `pnm-cli rooms --host-did …` mints a leaf bound to an audience
    /// no presenter can ever match: the host refuses it as `WrongAudience` every time, while
    /// omitting the flag leaves the presentation bearer-shaped for its four-hour life. Its
    /// doc comment states the intent exactly — "with it, a captured presentation is
    /// worthless to anyone else" — and names the wrong party to bind to.
    ///
    /// The `nonce` is the verifier's, echoed rather than interpreted: its value to them is
    /// that it came back unchanged.
    pub fn present(
        &self,
        vac: &str,
        vmc: &str,
        action: &str,
        nonce: Option<&str>,
    ) -> Result<String, String> {
        let root: DTGCredential =
            serde_json::from_str(vac).map_err(|e| format!("authority credential: {e}"))?;
        // Parsed only to fail early on something malformed — the *string* is what travels.
        serde_json::from_str::<Value>(vmc).map_err(|e| format!("membership credential: {e}"))?;

        let now = Utc::now();
        let expires = now + PRESENTATION_LIFETIME;
        let mut leaf = root
            .attenuate(
                self.did.clone(),
                vec![action.to_string()],
                now,
                expires,
                // Bound to us: the leaf may be presented by this member and nobody else.
                Some(self.did.clone()),
            )
            .map_err(|e| {
                format!("cannot narrow your authority for this room to `{action}`: {e}")
            })?;

        let secret = self.secret()?;
        futures_lite::future::block_on(leaf.sign(&secret, None))
            .map_err(|e| format!("sign the attenuated credential: {e}"))?;

        let leaf_json = serde_json::to_string(leaf.credential())
            .map_err(|e| format!("serialise the attenuated credential: {e}"))?;

        // **Strings, not objects.** `AuthorityPresentation` types `membership` as a
        // `String` and `authority` as `Vec<String>`; a host handed objects refuses the
        // whole request as "invalid type: map, expected a string", which reads as a
        // malformed payload rather than as a shape mismatch. The credential text is the
        // wire form — `vti-rooms-dtg` decodes base64url or bare JSON — and the root is
        // passed through exactly as received rather than re-serialised, so nothing this
        // side can do to its bytes can affect whether its proof still verifies.
        //
        // Leaf first, then the credential the room issued. Every link the host will rely
        // on is present, because the host will not fetch one.
        let mut presentation = serde_json::json!({
            "membership": vmc,
            "authority": [leaf_json, vac],
        });
        if let Some(nonce) = nonce {
            presentation["nonce"] = Value::String(nonce.to_string());
        }
        serde_json::to_string(&presentation).map_err(|e| e.to_string())
    }
}

impl std::fmt::Debug for MemberIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MemberIdentity")
            .field("did", &self.did)
            .field("signing", &"<redacted>")
            .finish()
    }
}
