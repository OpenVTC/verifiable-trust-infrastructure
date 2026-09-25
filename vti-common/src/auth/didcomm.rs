//! Shared authentication guard for just-unpacked DIDComm envelopes.
//!
//! `ATM::unpack` (affinidi-messaging-sdk) authenticates an authcrypt envelope
//! and surfaces the sender key id as `encrypted_from_kid`, but it does **not**
//! compare that key's DID to the inner plaintext `from` header on every path,
//! nor does it reject plaintext / anoncrypt envelopes on every path. Any handler
//! that consumes `atm.unpack` directly and then trusts `msg.from` as a proven
//! signer is therefore open to the authentication-bypass class: an attacker
//! authcrypts with their *own* key while claiming a victim's `from`, and the
//! handler mistakes them for the victim.
//!
//! [`bind_authcrypt_sender`] gives the direct-`unpack` callers (the REST
//! `/auth/*` handlers, vault unseal) one call that establishes the sender:
//!
//! 1. [`verify_authcrypt_header`] reads the **raw** outer JWE and requires an
//!    ECDH-1PU (authcrypt) layer whose sender key id `skid` is a DID URL and
//!    whose `apu` (the PartyUInfo the key agreement is bound to) is exactly
//!    `BASE64URL(skid)`. `skid` names the key used for the key agreement and
//!    `apu` the key the unpack metadata reports, so the two must be one key.
//! 2. The unpack metadata must be authcrypt, with a wrapping in which that outer
//!    authcrypt layer is the sender binding (`authcrypt(plaintext)` or
//!    `authcrypt(sign(plaintext))`), and its `encrypted_from_kid` must equal the
//!    header `skid` exactly.
//! 3. The plaintext `from` DID must equal the DID of that key.
//!
//! It returns the proven sender or a typed [`AuthcryptError`]. It takes the raw
//! envelope and the just-unpacked `(message, metadata)` pair directly, so a
//! caller never re-derives `from`, the flags or the key id by hand.
//!
//! Paths that only see an already-unpacked message (the DIDComm inbound
//! stream) cannot use this guard, because the raw envelope is gone by then;
//! they must not authorise on the transport sender alone.

use affinidi_tdk::didcomm::Message;
use affinidi_tdk::messaging::config::MessageWrappingType;
use affinidi_tdk::messaging::messages::compat::UnpackMetadata;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

/// Why binding an authcrypt sender failed. Auth handlers render it with
/// [`AuthcryptError::message`]; the vault path matches specific variants to map
/// onto its own error type.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum AuthcryptError {
    /// Not a sender-authenticated encrypted (authcrypt) envelope — the message
    /// was plaintext or anoncrypt, so its `from` is unauthenticated.
    NotAuthcrypt,
    /// The raw envelope is not a parseable JWE (JSON or compact serialization)
    /// with a decodable protected header.
    MalformedEnvelope(String),
    /// The authcrypt protected header carries no usable sender key id: `skid`
    /// is absent, not a string, or not a DID URL with a `#fragment`.
    InvalidSenderKeyId(String),
    /// The authcrypt protected header carries no `apu`.
    MissingApu,
    /// The authcrypt protected header's `apu` does not encode its `skid`.
    ApuMismatch { skid: String, apu: String },
    /// The envelope's wrapping is not one where the outer authcrypt layer is
    /// the sender binding (for example authcrypt nested inside anoncrypt).
    UnsupportedWrapping(String),
    /// Authcrypt, but the unpack metadata carried no authenticated sender key.
    NoSenderKey,
    /// The unpack metadata's authenticated sender key id is not the protected
    /// header's `skid`.
    SenderKeyMismatch { header: String, metadata: String },
    /// The inner message carried no `from` header.
    NoFrom,
    /// The inner `from` did not match the DID of the authenticated sender key —
    /// the core forged-sender case (attacker authcrypts with their own key while
    /// claiming a victim's `from`).
    Mismatch {
        claimed: String,
        authenticated: String,
    },
}

impl AuthcryptError {
    /// A one-line human message for `subject` (e.g. `"authenticate message"`,
    /// `"sealed secret"`).
    pub fn message(&self, subject: &str) -> String {
        match self {
            AuthcryptError::NotAuthcrypt => {
                format!("{subject} must be an authenticated (authcrypt) DIDComm envelope")
            }
            AuthcryptError::MalformedEnvelope(why) => {
                format!("{subject} is not a well-formed DIDComm encrypted envelope: {why}")
            }
            AuthcryptError::InvalidSenderKeyId(why) => {
                format!("{subject} authcrypt header has no usable sender key id: {why}")
            }
            AuthcryptError::MissingApu => {
                format!("{subject} authcrypt header has no apu")
            }
            AuthcryptError::ApuMismatch { skid, apu } => format!(
                "{subject} authcrypt header is inconsistent: apu `{apu}` does not encode skid `{skid}`"
            ),
            AuthcryptError::UnsupportedWrapping(wrapping) => format!(
                "{subject} must be authcrypt(plaintext) or authcrypt(sign(plaintext)), got {wrapping}"
            ),
            AuthcryptError::NoSenderKey => {
                format!("{subject} is authcrypt but carries no authenticated sender key")
            }
            AuthcryptError::SenderKeyMismatch { header, metadata } => format!(
                "{subject} sender key mismatch: header skid `{header}` is not the authenticated key `{metadata}`"
            ),
            AuthcryptError::NoFrom => format!("{subject} has no sender (from)"),
            AuthcryptError::Mismatch {
                claimed,
                authenticated,
            } => format!(
                "{subject} sender mismatch: plaintext from `{claimed}` does not match the authenticated sender `{authenticated}`"
            ),
        }
    }
}

/// Read the protected header of the outer JWE in `raw_jwe` and, for an
/// authcrypt (ECDH-1PU) layer, require that its sender key id is bound to the
/// key agreement: `skid` is a string DID URL carrying a `#fragment`, `apu` is
/// present, and `BASE64URL-decode(apu)` is byte-for-byte `skid` (with `apu`
/// canonically encoded). Returns the verified `skid`.
///
/// Accepts the JWE JSON serialization (general or flattened) and the compact
/// serialization. Any other `alg` — anoncrypt, or authcrypt wrapped inside an
/// anoncrypt layer, whose outer header is ECDH-ES — is [`AuthcryptError::NotAuthcrypt`]:
/// the callers of this function require the sender binding on the outer layer.
pub fn verify_authcrypt_header(raw_jwe: &str) -> Result<String, AuthcryptError> {
    let raw = raw_jwe.trim();
    let protected_b64 = if raw.starts_with('{') {
        let value: serde_json::Value = serde_json::from_str(raw)
            .map_err(|e| AuthcryptError::MalformedEnvelope(format!("not JSON: {e}")))?;
        if value.get("ciphertext").is_none() {
            // Plaintext DIDComm, or a JWS: not an encrypted envelope at all.
            return Err(AuthcryptError::NotAuthcrypt);
        }
        value
            .get("protected")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| AuthcryptError::MalformedEnvelope("JWE has no protected header".into()))?
            .to_string()
    } else {
        let parts: Vec<&str> = raw.split('.').collect();
        if parts.len() != 5 {
            return Err(AuthcryptError::MalformedEnvelope(
                "neither JWE JSON nor JWE compact serialization".into(),
            ));
        }
        parts[0].to_string()
    };

    let protected = URL_SAFE_NO_PAD
        .decode(protected_b64.as_bytes())
        .map_err(|e| AuthcryptError::MalformedEnvelope(format!("protected header: {e}")))?;
    let header: serde_json::Value = serde_json::from_slice(&protected)
        .map_err(|e| AuthcryptError::MalformedEnvelope(format!("protected header: {e}")))?;
    let header = header.as_object().ok_or_else(|| {
        AuthcryptError::MalformedEnvelope("protected header is not a JSON object".into())
    })?;

    let alg = header
        .get("alg")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| AuthcryptError::MalformedEnvelope("protected header has no alg".into()))?;
    if !alg.contains("1PU") {
        return Err(AuthcryptError::NotAuthcrypt);
    }

    let skid = match header.get("skid") {
        Some(serde_json::Value::String(s)) => s.clone(),
        Some(_) => {
            return Err(AuthcryptError::InvalidSenderKeyId(
                "skid is not a string".into(),
            ));
        }
        None => return Err(AuthcryptError::InvalidSenderKeyId("skid is absent".into())),
    };
    match skid.split_once('#') {
        Some((did, fragment)) if did.starts_with("did:") && !fragment.is_empty() => {}
        _ => {
            return Err(AuthcryptError::InvalidSenderKeyId(format!(
                "skid `{skid}` is not a DID URL with a key fragment"
            )));
        }
    }

    let apu = match header.get("apu") {
        Some(serde_json::Value::String(s)) => s.as_str(),
        Some(_) => {
            return Err(AuthcryptError::ApuMismatch {
                skid,
                apu: "<not a string>".into(),
            });
        }
        None => return Err(AuthcryptError::MissingApu),
    };
    let decoded = URL_SAFE_NO_PAD.decode(apu.as_bytes()).ok();
    // Exact bytes, and the canonical encoding: two spellings of one `apu` must
    // not exist for a verifier with a laxer decoder to disagree over.
    if decoded.as_deref() != Some(skid.as_bytes()) || URL_SAFE_NO_PAD.encode(&skid) != apu {
        let apu = decoded
            .map(|b| String::from_utf8_lossy(&b).into_owned())
            .unwrap_or_else(|| apu.to_string());
        return Err(AuthcryptError::ApuMismatch { skid, apu });
    }

    Ok(skid)
}

/// Bind an unpacked envelope's sender, returning the cryptographically-bound
/// sender DID (with any `#fragment` stripped).
///
/// `raw_jwe` is the envelope exactly as received and handed to `atm.unpack`;
/// `(message, metadata)` is what that call returned. Requires, in order:
///
/// - [`verify_authcrypt_header`] passes on `raw_jwe`, yielding its `skid`;
/// - `metadata` is authcrypt, with wrapping `authcrypt(plaintext)` or
///   `authcrypt(sign(plaintext))` — never authcrypt hidden inside anoncrypt;
/// - `metadata.encrypted_from_kid == Some(skid)`;
/// - the DID of `message.from` equals the DID of `skid`.
///
/// Callers pass the returned (proven) sender on to authorization; they must
/// **not** trust `message.from` on their own. See the module docs.
pub fn bind_authcrypt_sender(
    raw_jwe: &str,
    message: &Message,
    metadata: &UnpackMetadata,
) -> Result<String, AuthcryptError> {
    if !(metadata.encrypted && metadata.authenticated) {
        return Err(AuthcryptError::NotAuthcrypt);
    }
    let skid = verify_authcrypt_header(raw_jwe)?;
    match metadata.wrapping {
        MessageWrappingType::AuthcryptPlaintext | MessageWrappingType::AuthcryptSignPlaintext => {}
        other => return Err(AuthcryptError::UnsupportedWrapping(format!("{other:?}"))),
    }
    let kid = metadata
        .encrypted_from_kid
        .as_deref()
        .ok_or(AuthcryptError::NoSenderKey)?;
    if kid != skid {
        return Err(AuthcryptError::SenderKeyMismatch {
            header: skid,
            metadata: kid.to_string(),
        });
    }
    let key_did = base_did(&skid);

    match message.from.as_deref().map(base_did) {
        Some(from_did) if from_did == key_did => Ok(key_did.to_string()),
        Some(from_did) => Err(AuthcryptError::Mismatch {
            claimed: from_did.to_string(),
            authenticated: key_did.to_string(),
        }),
        None => Err(AuthcryptError::NoFrom),
    }
}

/// Strip a `#fragment` from a DID / kid, returning the base DID.
fn base_did(did: &str) -> &str {
    did.split_once('#').map(|(base, _)| base).unwrap_or(did)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const DID: &str = "did:key:z6MkSender";
    const KID: &str = "did:key:z6MkSender#z6LSSender";
    const VICTIM_KID: &str = "did:key:z6MkAdminVictim#z6LSAdminVictim";

    /// A minimal unpacked `Message` carrying (or omitting) a `from` header.
    fn msg(from: Option<&str>) -> Message {
        let builder = Message::build(
            "urn:uuid:test".to_string(),
            "https://example.org/test/1.0".to_string(),
            json!({}),
        );
        match from {
            Some(f) => builder.from(f.to_string()).finalize(),
            None => builder.finalize(),
        }
    }

    /// Unpack metadata with the given authcrypt flags + sender key id.
    ///
    /// Built by mutating a `Default` rather than with a struct expression:
    /// `UnpackMetadata` is `#[non_exhaustive]` as of affinidi-messaging-didcomm
    /// 0.15.8, which bars the literal form from outside its own crate — `..`
    /// does not exempt it. Field-at-a-time is also the shape that survives the
    /// upstream adding another field, which is the point of the attribute.
    fn meta(encrypted: bool, authenticated: bool, kid: Option<&str>) -> UnpackMetadata {
        let mut meta = UnpackMetadata::default();
        meta.encrypted = encrypted;
        meta.authenticated = authenticated;
        meta.encrypted_from_kid = kid.map(str::to_string);
        meta.wrapping = match (encrypted, authenticated) {
            (true, true) => MessageWrappingType::AuthcryptPlaintext,
            (true, false) => MessageWrappingType::AnoncryptPlaintext,
            _ => MessageWrappingType::Plaintext,
        };
        meta
    }

    /// A JWE (JSON serialization) whose protected header is exactly `header`.
    /// Only the header is read by the guard, so the other members are filler.
    fn jwe(header: serde_json::Value) -> String {
        json!({
            "protected": URL_SAFE_NO_PAD.encode(header.to_string()),
            "recipients": [{ "header": { "kid": "did:key:z6MkVta#z6LSVta" }, "encrypted_key": "AA" }],
            "iv": "AA",
            "ciphertext": "AA",
            "tag": "AA",
        })
        .to_string()
    }

    /// An authcrypt header with `skid` and `apu` written independently.
    fn authcrypt_header(skid: Option<&str>, apu: Option<&str>) -> serde_json::Value {
        let mut h =
            json!({ "alg": "ECDH-1PU+A256KW", "enc": "A256CBC-HS512", "apv": "AA", "epk": {} });
        if let Some(s) = skid {
            h["skid"] = json!(s);
        }
        if let Some(a) = apu {
            h["apu"] = json!(URL_SAFE_NO_PAD.encode(a));
        }
        h
    }

    /// A consistent authcrypt JWE for `kid`.
    fn good_jwe(kid: &str) -> String {
        jwe(authcrypt_header(Some(kid), Some(kid)))
    }

    /// Happy path: a consistent header, metadata naming the same key, and a
    /// `from` matching its DID returns the bound base DID.
    #[test]
    fn binds_matching_sender() {
        assert_eq!(
            bind_authcrypt_sender(
                &good_jwe(KID),
                &msg(Some(DID)),
                &meta(true, true, Some(KID))
            ),
            Ok(DID.to_string()),
        );
        // `from` may itself carry a fragment; still binds to the base DID.
        assert_eq!(
            bind_authcrypt_sender(
                &good_jwe(KID),
                &msg(Some(KID)),
                &meta(true, true, Some(KID))
            ),
            Ok(DID.to_string()),
        );
        // authcrypt(sign(plaintext)) is also accepted.
        let mut m = meta(true, true, Some(KID));
        m.wrapping = MessageWrappingType::AuthcryptSignPlaintext;
        assert_eq!(
            bind_authcrypt_sender(&good_jwe(KID), &msg(Some(DID)), &m),
            Ok(DID.to_string()),
        );
    }

    /// The forged-sender envelope: the key agreement used the attacker's key
    /// (`skid`), while `apu` — and so the unpack metadata — and `from` name the
    /// victim. Refused by the header check, before the metadata is believed.
    #[test]
    fn rejects_skid_apu_split() {
        const ATTACKER_KID: &str = "did:key:z6MkAttacker#z6LSAttacker";
        let raw = jwe(authcrypt_header(Some(ATTACKER_KID), Some(VICTIM_KID)));
        let err = bind_authcrypt_sender(
            &raw,
            &msg(Some("did:key:z6MkAdminVictim")),
            &meta(true, true, Some(VICTIM_KID)),
        )
        .expect_err("skid/apu split must be refused");
        assert_eq!(
            err,
            AuthcryptError::ApuMismatch {
                skid: ATTACKER_KID.to_string(),
                apu: VICTIM_KID.to_string(),
            }
        );
        assert_eq!(verify_authcrypt_header(&raw), Err(err));
    }

    /// A consistent header whose key is not the one the metadata reports.
    #[test]
    fn rejects_metadata_key_other_than_header_skid() {
        assert_eq!(
            bind_authcrypt_sender(
                &good_jwe(KID),
                &msg(Some("did:key:z6MkAdminVictim")),
                &meta(true, true, Some(VICTIM_KID)),
            ),
            Err(AuthcryptError::SenderKeyMismatch {
                header: KID.to_string(),
                metadata: VICTIM_KID.to_string(),
            }),
        );
    }

    /// Authenticated by the attacker's own consistent key, but the plaintext
    /// `from` claims a different DID → `Mismatch`, never bound to the claimed DID.
    #[test]
    fn rejects_sender_mismatch() {
        const ATTACKER_KID: &str = "did:key:z6MkAttacker#z6MkAttacker";
        let err = bind_authcrypt_sender(
            &good_jwe(ATTACKER_KID),
            &msg(Some("did:key:z6MkAdminVictim")),
            &meta(true, true, Some(ATTACKER_KID)),
        )
        .expect_err("forged from must be rejected");
        assert_eq!(
            err,
            AuthcryptError::Mismatch {
                claimed: "did:key:z6MkAdminVictim".to_string(),
                authenticated: "did:key:z6MkAttacker".to_string(),
            }
        );
        // And the rendered message names both DIDs.
        let msg = err.message("authenticate message");
        assert!(
            msg.contains("z6MkAdminVictim") && msg.contains("z6MkAttacker"),
            "got: {msg}"
        );
    }

    #[test]
    fn rejects_missing_skid() {
        let raw = jwe(authcrypt_header(None, Some(KID)));
        assert!(matches!(
            verify_authcrypt_header(&raw),
            Err(AuthcryptError::InvalidSenderKeyId(_))
        ));
    }

    #[test]
    fn rejects_non_string_skid() {
        let mut h = authcrypt_header(None, Some(KID));
        h["skid"] = json!(42);
        assert!(matches!(
            verify_authcrypt_header(&jwe(h)),
            Err(AuthcryptError::InvalidSenderKeyId(_))
        ));
    }

    /// A bare-DID `skid` would let the resolver pick "the first key-agreement
    /// key", so it names no specific key: refused.
    #[test]
    fn rejects_bare_did_skid() {
        for bare in [DID, "did:key:z6MkSender#", "z6LSNotADid#frag"] {
            let raw = jwe(authcrypt_header(Some(bare), Some(bare)));
            assert!(
                matches!(
                    verify_authcrypt_header(&raw),
                    Err(AuthcryptError::InvalidSenderKeyId(_))
                ),
                "{bare} must be refused"
            );
        }
    }

    #[test]
    fn rejects_missing_apu() {
        let raw = jwe(authcrypt_header(Some(KID), None));
        assert_eq!(
            verify_authcrypt_header(&raw),
            Err(AuthcryptError::MissingApu)
        );
    }

    /// `apu` must decode to *exactly* the `skid` bytes — not a prefix, not a
    /// superset, not a padded or non-canonical spelling of it.
    #[test]
    fn rejects_near_miss_apu() {
        for apu in [&KID[..KID.len() - 1], &format!("{KID}x"), DID] {
            let raw = jwe(authcrypt_header(Some(KID), Some(apu)));
            assert!(
                matches!(
                    verify_authcrypt_header(&raw),
                    Err(AuthcryptError::ApuMismatch { .. })
                ),
                "apu {apu} must be refused"
            );
        }
        // Padded spelling of the right bytes.
        let mut h = authcrypt_header(Some(KID), None);
        h["apu"] = json!(base64::engine::general_purpose::URL_SAFE.encode(KID));
        if h["apu"].as_str().unwrap().ends_with('=') {
            assert!(matches!(
                verify_authcrypt_header(&jwe(h)),
                Err(AuthcryptError::ApuMismatch { .. })
            ));
        }
        // Non-string apu.
        let mut h = authcrypt_header(Some(KID), None);
        h["apu"] = json!(["x"]);
        assert!(matches!(
            verify_authcrypt_header(&jwe(h)),
            Err(AuthcryptError::ApuMismatch { .. })
        ));
    }

    /// The compact serialization is read from its first segment.
    #[test]
    fn reads_compact_serialization() {
        let h = URL_SAFE_NO_PAD.encode(authcrypt_header(Some(KID), Some(KID)).to_string());
        assert_eq!(
            verify_authcrypt_header(&format!("{h}.AA.AA.AA.AA")),
            Ok(KID.to_string())
        );
        let bad = URL_SAFE_NO_PAD.encode(authcrypt_header(Some(KID), Some(VICTIM_KID)).to_string());
        assert!(verify_authcrypt_header(&format!("{bad}.AA.AA.AA.AA")).is_err());
    }

    /// Anoncrypt on the outer layer — including authcrypt hidden inside it — is
    /// not accepted on these paths, whatever the metadata says.
    #[test]
    fn rejects_anoncrypt_outer_and_nested_authcrypt() {
        let raw =
            jwe(json!({ "alg": "ECDH-ES+A256KW", "enc": "A256CBC-HS512", "apv": "AA", "epk": {} }));
        assert_eq!(
            verify_authcrypt_header(&raw),
            Err(AuthcryptError::NotAuthcrypt)
        );
        let mut m = meta(true, true, Some(KID));
        m.wrapping = MessageWrappingType::AnoncryptAuthcryptPlaintext;
        assert_eq!(
            bind_authcrypt_sender(&raw, &msg(Some(DID)), &m),
            Err(AuthcryptError::NotAuthcrypt),
        );
        // Even with an authcrypt-looking outer header, the nested wrapping is
        // refused.
        assert!(matches!(
            bind_authcrypt_sender(&good_jwe(KID), &msg(Some(DID)), &m),
            Err(AuthcryptError::UnsupportedWrapping(_))
        ));
    }

    #[test]
    fn rejects_malformed_envelopes() {
        for raw in ["", "not a jwe", "{", "a.b.c", "!!!.AA.AA.AA.AA"] {
            assert!(verify_authcrypt_header(raw).is_err(), "{raw:?}");
        }
        let no_protected = json!({ "recipients": [], "ciphertext": "AA" }).to_string();
        assert!(matches!(
            verify_authcrypt_header(&no_protected),
            Err(AuthcryptError::MalformedEnvelope(_))
        ));
    }

    /// A plaintext envelope (both flags false) is `NotAuthcrypt`, before the
    /// sender is even considered.
    #[test]
    fn rejects_plaintext() {
        let plaintext = json!({ "type": "x", "from": DID, "body": {} }).to_string();
        assert_eq!(
            bind_authcrypt_sender(&plaintext, &msg(Some(DID)), &meta(false, false, Some(KID))),
            Err(AuthcryptError::NotAuthcrypt),
        );
        assert_eq!(
            verify_authcrypt_header(&plaintext),
            Err(AuthcryptError::NotAuthcrypt)
        );
    }

    /// Anoncrypt (encrypted but not authenticated) is `NotAuthcrypt`: no proven
    /// sender.
    #[test]
    fn rejects_anoncrypt() {
        assert_eq!(
            bind_authcrypt_sender(&good_jwe(KID), &msg(None), &meta(true, false, None)),
            Err(AuthcryptError::NotAuthcrypt),
        );
    }

    /// Authcrypt but the metadata carries no sender key id — `NoSenderKey`,
    /// rather than falling back to trusting `from`.
    #[test]
    fn rejects_missing_sender_key() {
        assert_eq!(
            bind_authcrypt_sender(&good_jwe(KID), &msg(Some(DID)), &meta(true, true, None)),
            Err(AuthcryptError::NoSenderKey),
        );
    }

    /// Authcrypt with a proven key but no `from` header — `NoFrom`.
    #[test]
    fn rejects_missing_from() {
        assert_eq!(
            bind_authcrypt_sender(&good_jwe(KID), &msg(None), &meta(true, true, Some(KID))),
            Err(AuthcryptError::NoFrom),
        );
    }

    /// End to end against the messaging library's own decryptor: a forged
    /// envelope really decrypts (so the library alone would accept it, reporting
    /// the victim's key id from `apu`), and the header check refuses it; the
    /// library's own packer output passes.
    #[test]
    fn real_envelopes() {
        use super::super::authcrypt_test_support::{
            DidKeyParty, forge_authcrypt, genuine_authcrypt,
        };
        let attacker = DidKeyParty::from_seed([1; 32]);
        let victim = DidKeyParty::from_seed([2; 32]);
        let vta = DidKeyParty::from_seed([3; 32]);
        let vta_pub = vta.public();

        let forged = forge_authcrypt(b"{}", &attacker, &victim.kid, (&vta.kid, &vta_pub));
        let decrypted = affinidi_tdk::didcomm::jwe::decrypt::decrypt(
            &forged,
            &vta.kid,
            &vta.private(),
            Some(&attacker.public()),
        )
        .expect("the forged envelope decrypts with the attacker's key");
        assert_eq!(decrypted.sender_kid.as_deref(), Some(victim.kid.as_str()));
        assert!(matches!(
            verify_authcrypt_header(&forged),
            Err(AuthcryptError::ApuMismatch { .. })
        ));

        let genuine = genuine_authcrypt(b"{}", &victim, (&vta.kid, &vta_pub));
        assert_eq!(verify_authcrypt_header(&genuine), Ok(victim.kid.clone()));
    }

    /// Each variant renders a distinct, subject-tagged message.
    #[test]
    fn messages_are_subject_tagged() {
        assert!(
            AuthcryptError::NotAuthcrypt
                .message("sealed secret")
                .starts_with("sealed secret must be an authenticated")
        );
        assert!(
            AuthcryptError::NoFrom
                .message("refresh message")
                .contains("no sender")
        );
    }
}
