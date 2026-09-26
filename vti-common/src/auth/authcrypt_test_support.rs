//! Test-only builders for authcrypt (ECDH-1PU) JWEs whose protected header is
//! chosen by the test, so the sender-binding guard in [`super::didcomm`] can be
//! exercised against envelopes a conforming packer would never emit.
//!
//! A conforming packer always writes `skid` and `apu = BASE64URL(skid)` from one
//! key id. [`authcrypt_with_header`] lets a test set them independently — in
//! particular `skid` naming the key actually used for the key agreement while
//! `apu` names somebody else's — and still produce a JWE that decrypts.
//!
//! Compiled only under `cfg(test)` or the `test-support` feature. Never enable
//! that feature in a production build.

use affinidi_secrets_resolver::secrets::Secret;
use affinidi_tdk::affinidi_crypto::jose::key_agreement::{
    Curve, EphemeralKeyPair, PrivateKeyAgreement, PublicKeyAgreement,
};
use affinidi_tdk::affinidi_crypto::jose::{aes_kw, content_encryption, ecdh};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sha2::{Digest, Sha256};

/// A `did:key` party (Ed25519, with its derived X25519 key-agreement key) for
/// building authcrypt envelopes in tests.
pub struct DidKeyParty {
    /// The `did:key:z6Mk…` DID.
    pub did: String,
    /// The key-agreement verification method id, `did:key:z6Mk…#z6LS…` — the
    /// value a conforming packer writes as `skid`.
    pub kid: String,
    /// The X25519 key-agreement secret, with `id` set to [`Self::kid`] — hand it
    /// to a secrets resolver so an ATM can decrypt envelopes addressed to it.
    pub key_agreement: Secret,
}

impl DidKeyParty {
    /// Derive the party from a 32-byte Ed25519 seed.
    pub fn from_seed(seed: [u8; 32]) -> Self {
        let signing = Secret::generate_ed25519(None, Some(&seed));
        let ed_mb = signing
            .get_public_keymultibase()
            .expect("ed25519 public multibase");
        let did = format!("did:key:{ed_mb}");
        let mut key_agreement = signing.to_x25519().expect("ed25519 -> x25519");
        let x_mb = key_agreement
            .get_public_keymultibase()
            .expect("x25519 public multibase");
        let kid = format!("{did}#{x_mb}");
        key_agreement.id = kid.clone();
        DidKeyParty {
            did,
            kid,
            key_agreement,
        }
    }

    /// The X25519 private key, for use as an authcrypt sender.
    pub fn private(&self) -> PrivateKeyAgreement {
        PrivateKeyAgreement::from_raw_bytes(Curve::X25519, self.key_agreement.get_private_bytes())
            .expect("x25519 private key")
    }

    /// The X25519 public key, for use as an authcrypt recipient.
    pub fn public(&self) -> PublicKeyAgreement {
        PublicKeyAgreement::from_raw_bytes(Curve::X25519, self.key_agreement.get_public_bytes())
            .expect("x25519 public key")
    }
}

/// How the protected header's `skid` is written.
pub enum Skid<'a> {
    /// Omit `skid`.
    Absent,
    /// A JSON string.
    Str(&'a str),
    /// An arbitrary JSON value (e.g. a number), for type-confusion cases.
    Raw(serde_json::Value),
}

/// Authcrypt (`ECDH-1PU+A256KW`, `A256CBC-HS512`) `plaintext` from
/// `sender_private` to `recipient` (`(kid, public key)`), writing `skid` and
/// `apu` into the protected header exactly as given.
///
/// `apu` is the raw PartyUInfo bytes: it is both what the header carries
/// (base64url-encoded) and what the key derivation is bound to, so the result
/// decrypts for a recipient that resolves the sender public key named by
/// `skid`. `None` omits `apu`, binding the derivation to empty PartyUInfo.
pub fn authcrypt_with_header(
    plaintext: &[u8],
    skid: Skid<'_>,
    apu: Option<&[u8]>,
    sender_private: &PrivateKeyAgreement,
    recipient: (&str, &PublicKeyAgreement),
) -> String {
    let (recipient_kid, recipient_pub) = recipient;
    let ephemeral = EphemeralKeyPair::generate(recipient_pub.curve());
    let apu_raw = apu.unwrap_or_default();
    let apv_raw = Sha256::digest(recipient_kid.as_bytes()).to_vec();

    let mut header = serde_json::json!({
        "typ": "application/didcomm-encrypted+json",
        "alg": "ECDH-1PU+A256KW",
        "enc": "A256CBC-HS512",
        "apv": URL_SAFE_NO_PAD.encode(&apv_raw),
        "epk": ephemeral.public.to_jwk(),
    });
    match skid {
        Skid::Absent => {}
        Skid::Str(s) => header["skid"] = serde_json::Value::String(s.to_string()),
        Skid::Raw(v) => header["skid"] = v,
    }
    if let Some(apu) = apu {
        header["apu"] = serde_json::Value::String(URL_SAFE_NO_PAD.encode(apu));
    }
    let protected_b64 = URL_SAFE_NO_PAD.encode(header.to_string());

    let cek = content_encryption::generate_cek();
    let iv = content_encryption::generate_iv();
    let (ciphertext, tag) =
        content_encryption::encrypt(plaintext, &cek, &iv, protected_b64.as_bytes())
            .expect("content encryption");
    let kek = ecdh::derive_sender_key_1pu(
        &ephemeral,
        sender_private,
        recipient_pub,
        apu_raw,
        &apv_raw,
        &tag,
    )
    .expect("ECDH-1PU key derivation");
    let wrapped = aes_kw::wrap(&kek, &cek).expect("key wrap");

    serde_json::json!({
        "protected": protected_b64,
        "recipients": [{
            "header": { "kid": recipient_kid },
            "encrypted_key": URL_SAFE_NO_PAD.encode(&wrapped),
        }],
        "iv": URL_SAFE_NO_PAD.encode(iv),
        "ciphertext": URL_SAFE_NO_PAD.encode(&ciphertext),
        "tag": URL_SAFE_NO_PAD.encode(tag),
    })
    .to_string()
}

/// The forged-sender envelope: authcrypt with the **attacker's** key (named
/// honestly in `skid`) while `apu` and the plaintext `from` name the victim.
pub fn forge_authcrypt(
    plaintext: &[u8],
    attacker: &DidKeyParty,
    victim_kid: &str,
    recipient: (&str, &PublicKeyAgreement),
) -> String {
    authcrypt_with_header(
        plaintext,
        Skid::Str(&attacker.kid),
        Some(victim_kid.as_bytes()),
        &attacker.private(),
        recipient,
    )
}

/// A conforming authcrypt envelope from `sender` (`skid` and `apu` both name
/// `sender.kid`), built with the messaging library's own packer.
pub fn genuine_authcrypt(
    plaintext: &[u8],
    sender: &DidKeyParty,
    recipient: (&str, &PublicKeyAgreement),
) -> String {
    affinidi_tdk::didcomm::jwe::encrypt::authcrypt(
        plaintext,
        &sender.kid,
        &sender.private(),
        &[recipient],
    )
    .expect("authcrypt")
}

/// An offline ATM (no mediator, no network) whose secrets resolver holds
/// `secrets` — enough for `atm.unpack` to decrypt an envelope addressed to one
/// of them and to resolve a `did:key` sender locally.
pub async fn offline_atm_with(secrets: &[Secret]) -> affinidi_tdk::messaging::ATM {
    use affinidi_secrets_resolver::SecretsResolver;
    use affinidi_tdk::common::TDKSharedState;
    use affinidi_tdk::common::config::TDKConfig;
    use affinidi_tdk::messaging::config::ATMConfig;

    let tdk = TDKSharedState::new(TDKConfig::builder().build().expect("TDK config"))
        .await
        .expect("TDK shared state");
    tdk.secrets_resolver().insert_vec(secrets).await;
    affinidi_tdk::messaging::ATM::new(
        ATMConfig::builder().build().expect("ATM config"),
        std::sync::Arc::new(tdk),
    )
    .await
    .expect("offline ATM")
}

/// A DIDComm `auth/authenticate/0.1` plaintext answering `challenge` for
/// `session_id`, claiming `from`, stamped now — ready to be authcrypted.
pub fn authenticate_plaintext(from: &str, to: &str, challenge: &str, session_id: &str) -> Vec<u8> {
    plaintext_message(
        "https://trusttasks.org/spec/auth/authenticate/0.1",
        from,
        to,
        serde_json::json!({ "challenge": challenge, "session_id": session_id }),
    )
}

/// Wrap `inner` (an already-packed JWE) in an anoncrypt (ECDH-ES) layer to
/// `recipient` — `anoncrypt(authcrypt(plaintext))`.
pub fn anoncrypt_wrap(inner: &str, recipient: (&str, &PublicKeyAgreement)) -> String {
    affinidi_tdk::didcomm::jwe::encrypt::anoncrypt(inner.as_bytes(), &[recipient])
        .expect("anoncrypt")
}

/// A DIDComm plaintext of `type_uri` with `body`, claiming `from`, stamped now.
pub fn plaintext_message(type_uri: &str, from: &str, to: &str, body: serde_json::Value) -> Vec<u8> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_secs();
    let msg = affinidi_tdk::didcomm::Message::build(
        format!("urn:uuid:{}", uuid::Uuid::new_v4()),
        type_uri.to_string(),
        body,
    )
    .from(from.to_string())
    .to(to.to_string())
    .created_time(now)
    .finalize();
    serde_json::to_vec(&msg).expect("serialize message")
}

/// A DIDComm `auth/refresh/0.1` plaintext carrying `refresh_token`.
pub fn refresh_plaintext(from: &str, to: &str, refresh_token: &str) -> Vec<u8> {
    plaintext_message(
        "https://trusttasks.org/spec/auth/refresh/0.1",
        from,
        to,
        serde_json::json!({ "refresh_token": refresh_token }),
    )
}
