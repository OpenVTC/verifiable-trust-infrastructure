//! Which key may sign as which DID, for `keys/sign-document/0.1`.
//!
//! Pure functions over a DID document: the DID a document names as its signer,
//! and the Ed25519 verification methods a signer DID's document lists. Fetching
//! the document is the caller's: a VTA reads its own persona or resolves, a
//! service that signs with its own keys reads its own DID document.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::{Map, Value};

use crate::FormatRefusal;
use crate::canonical::{canonicalize, check_i_json};
use crate::key::decode_ed25519_public_key_multibase;

/// A DID as `keys/sign-document` admits one: `did:<method>:<id>`, never a DID
/// URL with a path, query or fragment.
fn is_bare_did(s: &str) -> bool {
    let mut parts = s.splitn(3, ':');
    matches!(
        (parts.next(), parts.next(), parts.next()),
        (Some("did"), Some(method), Some(id))
            if !method.is_empty()
                && method.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
                && !id.is_empty()
    ) && !s.contains(['/', '?', '#'])
}

/// The DID a document names as its signer, after the checks that need nothing
/// but the document (`keys/sign-document` items 3 and 4, and the issuer
/// binding's rule that `issuer` and `controller` agree).
pub fn document_signer(document: &Value) -> Result<String, FormatRefusal> {
    let Some(obj) = document.as_object() else {
        return Err(FormatRefusal::DocumentInvalid("noSigner"));
    };
    if obj.contains_key("proof") {
        return Err(FormatRefusal::ProofPresent);
    }
    let issuer = match obj.get("issuer") {
        None => None,
        Some(Value::String(did)) => Some(did.as_str()),
        Some(Value::Object(o)) => match o.get("id") {
            Some(Value::String(did)) => Some(did.as_str()),
            _ => return Err(FormatRefusal::DocumentInvalid("signerMalformed")),
        },
        Some(_) => return Err(FormatRefusal::DocumentInvalid("signerMalformed")),
    };
    let controller = match obj.get("controller") {
        None => None,
        Some(Value::String(did)) => Some(did.as_str()),
        Some(Value::Array(items)) => match items.as_slice() {
            [Value::String(did)] => Some(did.as_str()),
            _ => return Err(FormatRefusal::DocumentInvalid("signerMalformed")),
        },
        Some(_) => return Err(FormatRefusal::DocumentInvalid("signerMalformed")),
    };
    let signer = match (issuer, controller) {
        (None, None) => return Err(FormatRefusal::DocumentInvalid("noSigner")),
        (Some(i), Some(c)) if i != c => return Err(FormatRefusal::IssuerMismatch("controller")),
        (Some(did), _) | (None, Some(did)) => did,
    };
    if issuer.is_some_and(|d| !is_bare_did(d)) || controller.is_some_and(|d| !is_bare_did(d)) {
        return Err(FormatRefusal::DocumentInvalid("signerMalformed"));
    }
    // RFC 8785 serialises every number as a double; one beyond 2^53 would be
    // signed as a different value, and is refused rather than repaired.
    if check_i_json(document).is_err() || canonicalize(document).is_err() {
        return Err(FormatRefusal::DocumentInvalid("notCanonicalizable"));
    }
    Ok(signer.to_string())
}

/// One verification method of a signer DID: its identifier, its Ed25519 key,
/// and the relationships its document lists it under.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignerMethod {
    pub id: String,
    pub key: [u8; 32],
    pub purposes: Vec<&'static str>,
}

/// The relationships a Data Integrity proof made here may be listed under.
pub const DOCUMENT_PROOF_PURPOSES: [&str; 2] = ["assertionMethod", "authentication"];

/// The Ed25519 key a verification method object publishes, if it publishes one.
fn method_key(vm: &Map<String, Value>) -> Option<[u8; 32]> {
    if let Some(mb) = vm.get("publicKeyMultibase").and_then(Value::as_str) {
        return decode_ed25519_public_key_multibase(mb).ok();
    }
    let jwk = vm.get("publicKeyJwk")?.as_object()?;
    if jwk.get("kty")?.as_str()? != "OKP" || jwk.get("crv")?.as_str()? != "Ed25519" {
        return None;
    }
    URL_SAFE_NO_PAD
        .decode(jwk.get("x")?.as_str()?)
        .ok()?
        .try_into()
        .ok()
}

/// The Ed25519 verification methods `did`'s document lists, in the order it
/// lists them — in `verificationMethod` or embedded in a relationship — each
/// with the signing relationships that name it. A relative identifier
/// (`#key-1`) is read against `did`.
pub fn signer_methods(did: &str, document: &Value) -> Vec<SignerMethod> {
    let absolute = |id: &str| {
        if id.starts_with('#') {
            format!("{did}{id}")
        } else {
            id.to_string()
        }
    };
    let mut methods: Vec<SignerMethod> = Vec::new();
    let mut push = |vm: &Map<String, Value>| {
        let (Some(id), Some(key)) = (vm.get("id").and_then(Value::as_str), method_key(vm)) else {
            return;
        };
        let id = absolute(id);
        if !methods.iter().any(|m| m.id == id) {
            methods.push(SignerMethod {
                id,
                key,
                purposes: vec![],
            });
        }
    };
    for vm in document
        .get("verificationMethod")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_object)
    {
        push(vm);
    }
    for purpose in DOCUMENT_PROOF_PURPOSES {
        for entry in document
            .get(purpose)
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            if let Some(vm) = entry.as_object() {
                push(vm);
            }
        }
    }
    for purpose in DOCUMENT_PROOF_PURPOSES {
        for entry in document
            .get(purpose)
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let id = match entry {
                Value::String(id) => absolute(id),
                Value::Object(vm) => match vm.get("id").and_then(Value::as_str) {
                    Some(id) => absolute(id),
                    None => continue,
                },
                _ => continue,
            };
            if let Some(m) = methods.iter_mut().find(|m| m.id == id)
                && !m.purposes.contains(&purpose)
            {
                m.purposes.push(purpose);
            }
        }
    }
    methods
}

/// The methods of a `did:key`, read from the identifier itself: one Ed25519
/// key, listed under every signing relationship.
pub fn did_key_methods(did: &str) -> Option<Vec<SignerMethod>> {
    let mb = did.strip_prefix("did:key:")?;
    let key = decode_ed25519_public_key_multibase(mb).ok()?;
    // An X25519 did:key decodes to 32 bytes too; only the Ed25519 codec signs.
    let (_, raw) = multibase::decode(mb).ok()?;
    if raw.get(..2) != Some(&[0xed, 0x01]) {
        return None;
    }
    Some(vec![SignerMethod {
        id: format!("{did}#{mb}"),
        key,
        purposes: DOCUMENT_PROOF_PURPOSES.to_vec(),
    }])
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::{Signer, SigningSecret};

    fn key_text(seed: u8) -> (String, [u8; 32]) {
        let public = SigningSecret::ed25519([seed; 32]).public_key();
        let key: [u8; 32] = public.as_bytes().try_into().unwrap();
        (public.to_multibase(), key)
    }

    #[test]
    fn the_signer_is_the_issuer_or_the_controller_and_must_be_a_bare_did() {
        assert_eq!(
            document_signer(&json!({ "issuer": "did:key:z6MkA" })).unwrap(),
            "did:key:z6MkA"
        );
        assert_eq!(
            document_signer(&json!({ "issuer": { "id": "did:key:z6MkA" } })).unwrap(),
            "did:key:z6MkA"
        );
        assert_eq!(
            document_signer(&json!({ "controller": ["did:key:z6MkA"] })).unwrap(),
            "did:key:z6MkA"
        );
        assert_eq!(
            document_signer(&json!({ "issuer": "did:key:z6MkA", "controller": "did:key:z6MkA" }))
                .unwrap(),
            "did:key:z6MkA"
        );
    }

    #[test]
    fn a_document_that_names_no_signer_or_a_malformed_one_is_refused() {
        for (document, expected) in [
            (json!([]), FormatRefusal::DocumentInvalid("noSigner")),
            (
                json!({ "a": 1 }),
                FormatRefusal::DocumentInvalid("noSigner"),
            ),
            (
                json!({ "issuer": 5 }),
                FormatRefusal::DocumentInvalid("signerMalformed"),
            ),
            (
                json!({ "issuer": { "id": 5 } }),
                FormatRefusal::DocumentInvalid("signerMalformed"),
            ),
            (
                json!({ "controller": ["did:key:a", "did:key:b"] }),
                FormatRefusal::DocumentInvalid("signerMalformed"),
            ),
            (
                json!({ "issuer": "did:key:z6MkA#frag" }),
                FormatRefusal::DocumentInvalid("signerMalformed"),
            ),
            (
                json!({ "issuer": "https://example.com/issuer" }),
                FormatRefusal::DocumentInvalid("signerMalformed"),
            ),
            (
                json!({ "issuer": "did:key:z6MkA", "controller": "did:key:z6MkB" }),
                FormatRefusal::IssuerMismatch("controller"),
            ),
            (
                json!({ "issuer": "did:key:z6MkA", "proof": {} }),
                FormatRefusal::ProofPresent,
            ),
            (
                json!({ "issuer": "did:key:z6MkA", "n": 9_007_199_254_740_993u64 }),
                FormatRefusal::DocumentInvalid("notCanonicalizable"),
            ),
        ] {
            assert_eq!(document_signer(&document), Err(expected), "{document}");
        }
    }

    #[test]
    fn a_did_key_has_one_method_listed_under_every_signing_relationship() {
        let (mb, key) = key_text(1);
        let did = format!("did:key:{mb}");

        assert_eq!(
            did_key_methods(&did),
            Some(vec![SignerMethod {
                id: format!("{did}#{mb}"),
                key,
                purposes: DOCUMENT_PROOF_PURPOSES.to_vec(),
            }])
        );
        assert_eq!(
            did_key_methods("did:key:z6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc"),
            None,
            "X25519 signs nothing"
        );
        assert_eq!(did_key_methods("did:web:example.com"), None);
    }

    #[test]
    fn a_document_lists_its_methods_in_order_with_their_relationships() {
        let (mb1, key1) = key_text(1);
        let (mb2, key2) = key_text(2);
        let did = "did:web:example.com";
        let document = json!({
            "id": did,
            "verificationMethod": [
                { "id": "#key-1", "type": "Multikey", "publicKeyMultibase": mb1 },
                { "id": format!("{did}#key-2"), "type": "Multikey", "publicKeyMultibase": mb2 },
                { "id": "#not-a-key", "type": "Multikey" },
            ],
            "assertionMethod": ["#key-1", { "id": "#key-2", "type": "Multikey", "publicKeyMultibase": mb2 }],
            "authentication": ["#key-2"],
        });

        assert_eq!(
            signer_methods(did, &document),
            vec![
                SignerMethod {
                    id: format!("{did}#key-1"),
                    key: key1,
                    purposes: vec!["assertionMethod"]
                },
                SignerMethod {
                    id: format!("{did}#key-2"),
                    key: key2,
                    purposes: vec!["assertionMethod", "authentication"]
                },
            ]
        );
    }

    #[test]
    fn a_jwk_method_is_read_when_it_is_ed25519_and_ignored_otherwise() {
        let (_, key) = key_text(3);
        let x = URL_SAFE_NO_PAD.encode(key);
        let document = json!({
            "verificationMethod": [
                { "id": "did:web:e#a", "publicKeyJwk": { "kty": "OKP", "crv": "Ed25519", "x": x } },
                { "id": "did:web:e#b", "publicKeyJwk": { "kty": "OKP", "crv": "X25519", "x": x } },
                { "id": "did:web:e#c", "publicKeyJwk": { "kty": "EC", "crv": "P-256" } },
            ],
        });

        let methods = signer_methods("did:web:e", &document);

        assert_eq!(methods.len(), 1);
        assert_eq!(
            (methods[0].id.as_str(), methods[0].key),
            ("did:web:e#a", key)
        );
    }
}
