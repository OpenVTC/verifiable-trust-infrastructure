//! Verification-method resolution for Trust Task Data-Integrity proofs — the
//! one place a proof's `verificationMethod` becomes public-key bytes.
//!
//! A Trust Task proof may be made by **any DID that can name a key**:
//! `did:key:z6Mk…#z6Mk…`, `did:webvh:<scid>:example.com:glenn#key-0`,
//! `did:web:example.com#key-1`. The DID method is not the authorization —
//! resolving the verification method and checking the signature is.
//!
//! Before this existed, both services verified with `DidKeyResolver`, which
//! refuses everything but `did:key`. That is a smaller rule than it looks:
//! every DID this workspace provisions for an integration is a `did:webvh`, so
//! "`did:key` only" meant a provisioned integration could not sign a Trust
//! Task at all — and 210 of the 344 published request payloads declare a proof
//! REQUIRED.
//!
//! # `did:key` stays local; everything else needs a resolver
//!
//! `did:key` is self-describing: the key is *in* the identifier, so it resolves
//! with no I/O. Every other method requires a DID document, which means the
//! configured [`DIDCacheClient`] — and therefore network I/O, on a path that on
//! the login routes is reachable before the caller is anybody.
//!
//! That widening is deliberate but not free, so it is bounded rather than
//! assumed away:
//!
//! - The `did:key` fast path is checked **first**, so the common case never
//!   touches the network however the resolver is configured.
//! - Resolution goes through the shared [`DIDCacheClient`], which caches and
//!   carries its own timeouts — a flood of repeats costs one resolution.
//! - The unauthenticated routes that verify proofs are already behind the
//!   per-source-IP rate limiter.
//! - A resolver is **optional**. Construct with `None` and this is exactly the
//!   old `did:key`-only verifier, which is what a deployment that wants no
//!   outbound resolution on an unauthenticated route should configure.
//!
//! The alternative to accepting that surface is that no `did:webvh` holder can
//! ever authenticate, which is not a security property — it is the absence of a
//! feature the rest of the stack already assumes.

use crate::did_refresh::{evict_for_fresh_resolve, resolve_for_vm};
use affinidi_data_integrity::did_vm::resolve_did_key;
use affinidi_data_integrity::{DataIntegrityError, ResolvedKey, VerificationMethodResolver};
use affinidi_did_resolver_cache_sdk::DIDCacheClient;
use affinidi_secrets_resolver::secrets::KeyType;
use std::collections::HashSet;
use std::sync::{Arc, Mutex};

/// Resolves a Trust Task proof's `verificationMethod` to its public key.
///
/// `did:key` resolves locally through the upstream multicodec decoder, so every
/// key type that build supports is covered without listing them here. Any other
/// method resolves its DID document through the cache and pulls the named
/// verification method's key with the upstream extractor, which handles
/// `Multikey`, `Ed25519VerificationKey2020` and `publicKeyJwk` uniformly.
///
/// Cheap to clone — [`DIDCacheClient`] is `Arc`-backed.
#[derive(Clone, Default)]
pub struct TrustTaskVmResolver {
    resolver: Option<DIDCacheClient>,
    relationship: Option<ProofRelationship>,
    /// DIDs whose document this resolver was handed **from the cache**, so a
    /// verification that fails against one can ask for it fresh
    /// ([`Self::refresh_if_cached`]). A document just fetched is not refetched:
    /// it is as current as a second fetch would be.
    served_from_cache: Arc<Mutex<HashSet<String>>>,
}

/// A verification relationship a proof's method must be listed under in its
/// controller's DID document.
///
/// The resolver otherwise finds a key wherever the document declares it, so a
/// proof that says `assertionMethod` made with a key listed only under
/// `authentication` would verify. What a proof's purpose claims is only true
/// when the DID's controller put the key under that relationship.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProofRelationship {
    /// `authentication`: the DID's own operational messages.
    Authentication,
    /// `assertionMethod`: an attestation, such as a human approver's decision.
    AssertionMethod,
}

impl ProofRelationship {
    /// The relationship's name in a DID document, and the matching
    /// `proofPurpose`.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Authentication => "authentication",
            Self::AssertionMethod => "assertionMethod",
        }
    }

    fn lists(self, doc: &affinidi_did_common::Document, vm: &str) -> bool {
        let relative = vm
            .split_once('#')
            .map(|(_, fragment)| format!("#{fragment}"))
            .unwrap_or_default();
        let entries = match self {
            Self::Authentication => &doc.authentication,
            Self::AssertionMethod => &doc.assertion_method,
        };
        entries.iter().any(|e| {
            let id = e.get_id();
            id == vm || (!relative.is_empty() && id == relative)
        })
    }

    fn require(
        self,
        doc: &affinidi_did_common::Document,
        vm: &str,
    ) -> Result<(), DataIntegrityError> {
        if self.lists(doc, vm) {
            Ok(())
        } else {
            Err(DataIntegrityError::Resolver(format!(
                "verificationMethod `{vm}` is not listed under `{}` in its DID document",
                self.as_str()
            )))
        }
    }
}

impl std::fmt::Debug for TrustTaskVmResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TrustTaskVmResolver")
            .field("network_resolution", &self.resolver.is_some())
            .field("relationship", &self.relationship)
            .finish()
    }
}

impl TrustTaskVmResolver {
    /// A resolver that can reach DID documents over the network for methods
    /// that need one. `did:key` still resolves locally.
    #[must_use]
    pub fn new(resolver: DIDCacheClient) -> Self {
        Self {
            resolver: Some(resolver),
            relationship: None,
            served_from_cache: Arc::default(),
        }
    }

    /// A resolver that performs **no I/O**: `did:key` and `did:peer`, both of which carry
    /// their keys in the identifier.
    ///
    /// The guarantee is about the network, not about the method — a caller choosing this is
    /// saying no unauthenticated request may make it fetch. `did:peer` satisfies that as
    /// fully as `did:key` does, and excluding it only refused credentials this could have
    /// checked.
    #[must_use]
    pub fn did_key_only() -> Self {
        Self::default()
    }

    /// A resolver from an optional cache client — network resolution when
    /// `Some`, `did:key`-only when `None`.
    #[must_use]
    pub fn from_optional(resolver: Option<DIDCacheClient>) -> Self {
        Self {
            resolver,
            relationship: None,
            served_from_cache: Arc::default(),
        }
    }

    /// This resolver, resolving only a verification method its DID document
    /// lists under `relationship`.
    ///
    /// `did:key` needs no check: its document lists its signing key under both
    /// `authentication` and `assertionMethod` by definition.
    #[must_use]
    pub fn requiring(mut self, relationship: ProofRelationship) -> Self {
        self.relationship = Some(relationship);
        self
    }

    /// Evict `did` for a fresh resolution if — and only if — this resolver was
    /// handed its document from the cache. Returns whether it did, i.e. whether
    /// a retry could see a different document.
    ///
    /// For a verification that failed against a listed key: the key id is
    /// unchanged but its material was replaced, which [`resolve_for_vm`]
    /// cannot notice because the method is still listed.
    pub async fn refresh_if_cached(&self, did: &str) -> bool {
        let Some(resolver) = self.resolver.as_ref() else {
            return false;
        };
        let was_cached = self
            .served_from_cache
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(did);
        was_cached && evict_for_fresh_resolve(resolver, did).await
    }

    /// Whether this resolver can resolve a method other than `did:key`.
    #[must_use]
    pub fn resolves_over_the_network(&self) -> bool {
        self.resolver.is_some()
    }

    async fn resolve(&self, vm: &str) -> Result<ResolvedKey, DataIntegrityError> {
        let base_did = vm.split('#').next().unwrap_or(vm);

        // First, and unconditionally: the key is in the identifier.
        if base_did.starts_with("did:key:") {
            return resolve_did_key(vm);
        }

        // So is a `did:peer`'s, and that matters more than it looks.
        //
        // A `did:peer:2` encodes its keys and its services inline, so resolving one is —
        // in `PeerResolver`'s own words — "pure computation (no IO)". Treating it as
        // needing a network resolver made `did_key_only()` mean "did:key only" when what
        // it exists to promise is that **no unauthenticated request can make this verifier
        // fetch**. Those are different guarantees, and the narrower one refuses credentials
        // it could have checked without touching the network.
        //
        // Concretely: a room identified by `did:peer:2` can advertise a mediator, which is
        // how a member reaches its owner — a `did:key` cannot, having no service block. So
        // a host wanting to serve such a room had to enable network resolution it does not
        // need, and accept the exposure that flag exists to gate.
        if base_did.starts_with("did:peer:") {
            return resolve_did_peer(vm, base_did, self.relationship);
        }

        let resolver = self.resolver.as_ref().ok_or_else(|| {
            DataIntegrityError::Resolver(format!(
                "resolving `{base_did}` needs a DID resolver, but this verifier is configured \
                 for did:key only"
            ))
        })?;
        let resolved = resolve_for_vm(resolver, base_did, vm).await.map_err(|e| {
            DataIntegrityError::Resolver(format!("`{base_did}` did not resolve: {e}"))
        })?;
        // Recorded before the relationship check: a cached document may predate
        // the signer listing this key under the relationship, and a retry after
        // `refresh_if_cached` must be able to see the current one.
        if resolved.cache_hit {
            self.served_from_cache
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .insert(base_did.to_string());
        }
        if let Some(relationship) = self.relationship {
            relationship.require(&resolved.doc, vm)?;
        }

        // A DID document may name its verification methods absolutely
        // (`did:webvh:…:glenn#key-0`) or relatively (`#key-0`); the proof
        // always names them absolutely. Accept both spellings of the same
        // method rather than requiring the document to have chosen ours.
        let relative = vm
            .split_once('#')
            .map(|(_, fragment)| format!("#{fragment}"))
            .unwrap_or_default();
        let entry = resolved
            .doc
            .verification_method
            .iter()
            .find(|m| m.id.as_str() == vm || m.id.as_str() == relative)
            .ok_or_else(|| {
                DataIntegrityError::Resolver(format!(
                    "verificationMethod `{vm}` is not in the DID document for `{base_did}`"
                ))
            })?;

        let bytes = entry.get_public_key_bytes().map_err(|e| {
            DataIntegrityError::Resolver(format!(
                "verificationMethod `{vm}` public key could not be extracted: {e}"
            ))
        })?;
        Ok(ResolvedKey::new(declared_key_type(entry, vm)?, bytes))
    }
}

/// Resolve a `did:peer` verification method with no I/O.
///
/// The document is derived from the identifier and its keys expanded, then the method is
/// looked up exactly as the network path looks one up — including accepting both the
/// absolute and relative spellings of the same id, because a proof always names a method
/// absolutely while a document may not.
fn resolve_did_peer(
    vm: &str,
    base_did: &str,
    relationship: Option<ProofRelationship>,
) -> Result<ResolvedKey, DataIntegrityError> {
    use affinidi_did_common::DID;
    use affinidi_did_resolver_traits::{PeerResolver, Resolver};

    let did = DID::try_from(base_did).map_err(|e| {
        DataIntegrityError::Resolver(format!("`{base_did}` is not a well-formed DID: {e}"))
    })?;
    let doc = PeerResolver
        .resolve(&did)
        .ok_or_else(|| {
            DataIntegrityError::Resolver(format!(
                "`{base_did}` is not a did:peer this build resolves"
            ))
        })?
        .map_err(|e| DataIntegrityError::Resolver(format!("`{base_did}` did not resolve: {e}")))?;
    if let Some(relationship) = relationship {
        relationship.require(&doc, vm)?;
    }

    let relative = vm
        .split_once('#')
        .map(|(_, fragment)| format!("#{fragment}"))
        .unwrap_or_default();
    let entry = doc
        .verification_method
        .iter()
        .find(|m| m.id.as_str() == vm || m.id.as_str() == relative)
        .ok_or_else(|| {
            DataIntegrityError::Resolver(format!(
                "verificationMethod `{vm}` is not in the DID document for `{base_did}`"
            ))
        })?;

    let bytes = entry.get_public_key_bytes().map_err(|e| {
        DataIntegrityError::Resolver(format!(
            "verificationMethod `{vm}` public key could not be extracted: {e}"
        ))
    })?;
    Ok(ResolvedKey::new(declared_key_type(entry, vm)?, bytes))
}

/// The key type a verification method actually declares, read from its
/// `publicKeyMultibase` multicodec prefix.
///
/// # Why this is not `KeyType::Ed25519`
///
/// It was. Both resolution paths ended `ResolvedKey::new(KeyType::Ed25519,
/// bytes)` regardless of what the document said, because every key this stack
/// minted was Ed25519 and the type was therefore never wrong.
///
/// That stops being true the moment a DID carries an ML-DSA key, and the
/// failure is the bad kind: the key is extracted successfully and handed to the
/// verifier **labelled Ed25519**, so what should be "this proof uses a suite I
/// must check differently" becomes "this Ed25519 signature does not verify".
/// A hardcoded type cannot be wrong in a way anyone notices until it is wrong
/// in a way nobody can debug.
///
/// `get_public_key_bytes` cannot answer this — it decodes the multikey and
/// returns the payload, dropping the prefix that names the algorithm — so the
/// multibase string is read directly.
fn declared_key_type(
    entry: &affinidi_did_common::verification_method::VerificationMethod,
    vm: &str,
) -> Result<KeyType, DataIntegrityError> {
    let multibase = entry
        .property_set
        .get("publicKeyMultibase")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            DataIntegrityError::Resolver(format!(
                "verificationMethod `{vm}` has no `publicKeyMultibase`, so its algorithm cannot \
                 be read; a PQC key must be published as a Multikey (the JWK path does not \
                 express ML-DSA)"
            ))
        })?;

    let (_base, bytes) = multibase::decode(multibase).map_err(|e| {
        DataIntegrityError::Resolver(format!(
            "verificationMethod `{vm}` public key is not valid multibase: {e}"
        ))
    })?;

    // Matched against this workspace's own codec table rather than a second
    // copy of the prefixes. `multicodec_public()` is the one place these bytes
    // are written down, and `affinidi-tdk-rs#798` pins it against a named
    // revision of the multicodec registry — so a prefix that is wrong here is
    // wrong in exactly one place, and a test already says so.
    for candidate in [
        crate::keys::KeyType::Ed25519,
        crate::keys::KeyType::X25519,
        crate::keys::KeyType::P256,
        crate::keys::KeyType::MlDsa44,
        crate::keys::KeyType::MlDsa65,
    ] {
        if bytes.starts_with(candidate.multicodec_public()) {
            return Ok(match candidate {
                crate::keys::KeyType::Ed25519 => KeyType::Ed25519,
                crate::keys::KeyType::X25519 => KeyType::X25519,
                crate::keys::KeyType::P256 => KeyType::P256,
                crate::keys::KeyType::MlDsa44 => KeyType::MlDsa44,
                crate::keys::KeyType::MlDsa65 => KeyType::MlDsa65,
                // No wildcard: `#[non_exhaustive]` binds other crates, not the
                // one that defines the type, and this module is inside it. So
                // adding a `KeyType` variant breaks this match on purpose —
                // whoever adds a key type is made to say how a verifier should
                // read it, rather than having it silently fall to a default.
            });
        }
    }

    // Named rather than silently defaulted. A verifier that cannot check a
    // suite must say so, because the operator's next step is to publish a key
    // this build understands — and "signature did not verify" does not lead
    // there.
    Err(DataIntegrityError::Resolver(format!(
        "verificationMethod `{vm}` carries a key whose multicodec prefix this build does not \
         recognise, so its signature suite cannot be determined"
    )))
}

#[async_trait::async_trait]
impl VerificationMethodResolver for TrustTaskVmResolver {
    async fn resolve_vm(&self, vm: &str) -> Result<ResolvedKey, DataIntegrityError> {
        self.resolve(vm).await
    }
}

#[cfg(test)]
mod tests {
    use super::declared_key_type;
    use crate::keys::KeyType as LocalKeyType;
    use affinidi_did_common::verification_method::VerificationMethod;
    use affinidi_secrets_resolver::secrets::KeyType;

    /// A verification method carrying `key_type`'s public multicodec prefix.
    fn vm_with(key_type: LocalKeyType, payload_len: usize) -> VerificationMethod {
        let mut bytes = key_type.multicodec_public().to_vec();
        bytes.extend(std::iter::repeat_n(0x42u8, payload_len));
        let mb = multibase::encode(multibase::Base::Base58Btc, &bytes);

        let mut vm: VerificationMethod = serde_json::from_value(serde_json::json!({
            "id": "did:example:alice#key-0",
            "type": "Multikey",
            "controller": "did:example:alice",
        }))
        .expect("a Multikey verification method");
        vm.property_set
            .insert("publicKeyMultibase".to_string(), serde_json::json!(mb));
        vm
    }

    /// **The regression this exists for.** An ML-DSA key must not come back
    /// labelled Ed25519.
    ///
    /// Both resolution paths used to end `ResolvedKey::new(KeyType::Ed25519,
    /// bytes)` unconditionally. That is not a rejection — the key is extracted
    /// successfully and handed to the verifier under the wrong algorithm, so a
    /// "this suite needs different checking" problem presents as "this Ed25519
    /// signature is invalid", which points at the signature rather than the
    /// key.
    #[test]
    fn an_ml_dsa_key_is_not_reported_as_ed25519() {
        // FIPS 204 public key sizes, so the fixture is the real shape.
        let vm44 = vm_with(LocalKeyType::MlDsa44, 1312);
        assert_eq!(
            declared_key_type(&vm44, "did:example:alice#key-0").expect("ML-DSA-44 is recognised"),
            KeyType::MlDsa44,
        );

        let vm65 = vm_with(LocalKeyType::MlDsa65, 1952);
        assert_eq!(
            declared_key_type(&vm65, "did:example:alice#key-0").expect("ML-DSA-65 is recognised"),
            KeyType::MlDsa65,
        );
    }

    /// The common case still reads as it always did.
    #[test]
    fn an_ed25519_key_is_still_ed25519() {
        let vm = vm_with(LocalKeyType::Ed25519, 32);
        assert_eq!(
            declared_key_type(&vm, "did:example:alice#key-0").expect("Ed25519 is recognised"),
            KeyType::Ed25519,
        );
    }

    /// An unrecognised suite is named, not defaulted.
    ///
    /// Defaulting is what produced the original defect. The operator's next
    /// step is to publish a key this build understands, and only an error that
    /// says "I cannot determine the suite" leads there.
    #[test]
    fn an_unknown_prefix_is_refused_rather_than_assumed() {
        let mut vm = vm_with(LocalKeyType::Ed25519, 32);
        // A prefix belonging to no key type this build knows.
        let mb = multibase::encode(multibase::Base::Base58Btc, [0xff, 0xfe, 0x01, 0x02]);
        vm.property_set
            .insert("publicKeyMultibase".to_string(), serde_json::json!(mb));

        let err = declared_key_type(&vm, "did:example:alice#key-0")
            .expect_err("an unknown suite must not resolve");
        let text = err.to_string();
        assert!(
            text.contains("suite cannot be determined") || text.contains("does not recognise"),
            "the error must say the suite is undetermined, not blame the signature: {text}"
        );
    }

    use super::*;

    /// `did:key` never needs the network, so the `did:key`-only resolver and a
    /// network-capable one must agree on it — and the fast path must come
    /// first, or a misconfigured resolver would break the common case.
    #[tokio::test]
    async fn did_key_resolves_with_no_resolver_configured() {
        // did:key for the all-0x11 Ed25519 seed.
        let sk = ed25519_dalek::SigningKey::from_bytes(&[0x11; 32]);
        let mb = multibase::encode(
            multibase::Base::Base58Btc,
            [&[0xed, 0x01][..], &sk.verifying_key().to_bytes()[..]].concat(),
        );
        let vm = format!("did:key:{mb}#{mb}");

        let key = TrustTaskVmResolver::did_key_only()
            .resolve_vm(&vm)
            .await
            .expect("did:key resolves with no cache client");
        assert_eq!(key.public_key_bytes, sk.verifying_key().to_bytes().to_vec());
    }

    /// A `did:peer` resolves with **no resolver configured**, which is the point.
    ///
    /// Its keys are in its identifier, so this needs no network — and a verifier configured
    /// to do no I/O should therefore accept it. Before this it did not, and a host wanting
    /// to serve a `did:peer` room had to turn on network resolution it never used.
    ///
    /// A `did:peer:2` is used rather than a `did:peer:0` because that is the shape a room
    /// needs: only numalgo 2 carries a service block, which is how a room advertises the
    /// mediator its members reach its owner through.
    #[tokio::test]
    async fn did_peer_resolves_with_no_resolver_configured() {
        use affinidi_tdk::dids::{DID, KeyType};

        let (did, secrets) = DID::generate_did_peer(
            vec![
                (
                    affinidi_tdk::dids::PeerKeyRole::Verification,
                    KeyType::Ed25519,
                ),
                (affinidi_tdk::dids::PeerKeyRole::Encryption, KeyType::X25519),
            ],
            None,
        )
        .expect("mint a did:peer");

        let vm = format!("{did}#key-1");
        let resolved = TrustTaskVmResolver::did_key_only()
            .resolve_vm(&vm)
            .await
            .expect("a did:peer carries its keys in its identifier, so this needs no network");

        // The same key the minting side holds — resolution is not merely succeeding, it is
        // returning the right bytes.
        let expected = secrets
            .iter()
            .find(|s| s.id.ends_with("#key-1"))
            .expect("the verification secret");
        assert_eq!(
            resolved.public_key_bytes,
            expected.get_public_bytes(),
            "the resolved key must be the one the DID names"
        );
    }

    /// The refusal has to say *why* it refused, because "did not resolve" and
    /// "this verifier will not resolve that method" send an operator to
    /// completely different places.
    #[tokio::test]
    async fn a_did_key_only_resolver_names_its_own_limit() {
        let err = TrustTaskVmResolver::did_key_only()
            .resolve_vm("did:webvh:QmScid:example.com:glenn#key-0")
            .await
            .expect_err("did:webvh needs a resolver");
        let msg = err.to_string();
        assert!(
            msg.contains("did:key only"),
            "the error must name the configuration, got: {msg}"
        );
    }

    /// The resolver is what decides which methods may sign, so a Trust Task
    /// proof naming a `did:webvh` key must be *refused for that reason* by the
    /// narrow verifier — not quietly accepted, and not refused as a bad
    /// signature. Those are three different operator problems.
    #[tokio::test]
    async fn a_did_webvh_proof_is_refused_by_the_narrow_verifier_for_the_right_reason() {
        use trust_tasks_rs::TrustTask;

        let doc: TrustTask<serde_json::Value> = serde_json::from_value(serde_json::json!({
            "id": "urn:uuid:11111111-1111-4111-8111-111111111111",
            "type": "https://trusttasks.org/spec/vta/contexts/create/1.0",
            "issuer": "did:webvh:QmScid:example.com:glenn",
            "recipient": "did:key:z6MkVta",
            "payload": {},
            "proof": {
                "type": "DataIntegrityProof",
                "cryptosuite": "eddsa-jcs-2022",
                "proofPurpose": "assertionMethod",
                "verificationMethod": "did:webvh:QmScid:example.com:glenn#key-0",
                "created": "2026-08-29T00:00:00Z",
                "proofValue": "z2aBcD"
            }
        }))
        .expect("a well-formed Trust Task");

        let err = crate::trust_task_proof::verify::verify_trust_task_proof(&doc)
            .await
            .expect_err("did:key-only cannot resolve a did:webvh key");
        let cause = err.cause().unwrap_or_default();
        assert!(
            cause.contains("did:key only"),
            "the operator-facing cause must name the resolver's configuration, not the \
             signature, got: {cause}"
        );
    }

    #[test]
    fn the_debug_rendering_says_whether_it_can_reach_the_network() {
        let s = format!("{:?}", TrustTaskVmResolver::did_key_only());
        assert!(s.contains("network_resolution: false"), "got {s}");
    }
}
