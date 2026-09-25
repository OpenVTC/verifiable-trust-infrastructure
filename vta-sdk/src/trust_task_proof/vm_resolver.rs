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

use affinidi_data_integrity::did_vm::resolve_did_key;
use affinidi_data_integrity::{DataIntegrityError, ResolvedKey};

use super::purpose::{
    ProofPurpose, PurposeVmResolver, authorised_method, check_did_key_method, split_vm,
};
use affinidi_did_resolver_cache_sdk::DIDCacheClient;
use affinidi_secrets_resolver::secrets::KeyType;

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
}

impl std::fmt::Debug for TrustTaskVmResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TrustTaskVmResolver")
            .field("network_resolution", &self.resolver.is_some())
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
        Self { resolver: None }
    }

    /// A resolver from an optional cache client — network resolution when
    /// `Some`, `did:key`-only when `None`.
    #[must_use]
    pub fn from_optional(resolver: Option<DIDCacheClient>) -> Self {
        Self { resolver }
    }

    /// Whether this resolver can resolve a method other than `did:key`.
    #[must_use]
    pub fn resolves_over_the_network(&self) -> bool {
        self.resolver.is_some()
    }

    async fn resolve(
        &self,
        vm: &str,
        purpose: ProofPurpose,
    ) -> Result<ResolvedKey, DataIntegrityError> {
        let (base_did, _) = split_vm(vm)?;

        // First, and unconditionally: the key is in the identifier. did:key's
        // relationships are implicit — its one method signs for every purpose
        // (VTI-KEY-022 is met by naming that method exactly) — and an X25519
        // did:key is a key-agreement key that signs for nothing.
        if base_did.starts_with("did:key:") {
            check_did_key_method(vm)?;
            let key = resolve_did_key(vm)?;
            if key.key_type == KeyType::X25519 {
                return Err(DataIntegrityError::Resolver(
                    "a did:key X25519 key is authorised for keyAgreement only".to_string(),
                ));
            }
            return Ok(key);
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
            return resolve_did_peer(vm, base_did, purpose);
        }

        let resolver = self.resolver.as_ref().ok_or_else(|| {
            DataIntegrityError::Resolver(
                "resolving this verificationMethod needs a DID resolver, but this verifier is \
                 configured for did:key only"
                    .to_string(),
            )
        })?;
        let resolved = resolver.resolve(base_did).await.map_err(|e| {
            DataIntegrityError::Resolver(format!(
                "the verificationMethod's DID did not resolve: {e}"
            ))
        })?;
        key_of(&resolved.doc, base_did, vm, purpose)
    }
}

/// Resolve a `did:peer` verification method with no I/O.
///
/// The document is derived from the identifier and its keys expanded, then the method is
/// checked exactly as the network path checks one.
fn resolve_did_peer(
    vm: &str,
    base_did: &str,
    purpose: ProofPurpose,
) -> Result<ResolvedKey, DataIntegrityError> {
    use affinidi_did_common::DID;
    use affinidi_did_resolver_traits::{PeerResolver, Resolver};

    let did = DID::try_from(base_did).map_err(|e| {
        DataIntegrityError::Resolver(format!(
            "the verificationMethod's DID is not well-formed: {e}"
        ))
    })?;
    let doc = PeerResolver
        .resolve(&did)
        .ok_or_else(|| {
            DataIntegrityError::Resolver(
                "the verificationMethod's did:peer is not one this build resolves".to_string(),
            )
        })?
        .map_err(|e| {
            DataIntegrityError::Resolver(format!(
                "the verificationMethod's DID did not resolve: {e}"
            ))
        })?;
    key_of(&doc, base_did, vm, purpose)
}

/// The key of the method `vm` names in `doc`, once [`authorised_method`] has
/// established it is `did`'s own and listed under `purpose`.
pub(crate) fn key_of(
    doc: &affinidi_did_common::Document,
    did: &str,
    vm: &str,
    purpose: ProofPurpose,
) -> Result<ResolvedKey, DataIntegrityError> {
    let entry = authorised_method(doc, did, vm, purpose)?;
    let bytes = entry.get_public_key_bytes().map_err(|e| {
        DataIntegrityError::Resolver(format!(
            "the verificationMethod's public key could not be extracted: {e}"
        ))
    })?;
    Ok(ResolvedKey::new(declared_key_type(&entry, vm)?, bytes))
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
    _vm: &str,
) -> Result<KeyType, DataIntegrityError> {
    let multibase = entry
        .property_set
        .get("publicKeyMultibase")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            DataIntegrityError::Resolver(
                "the verificationMethod has no `publicKeyMultibase`, so its algorithm cannot \
                 be read; a PQC key must be published as a Multikey (the JWK path does not \
                 express ML-DSA)"
                    .to_string(),
            )
        })?;

    let (_base, bytes) = multibase::decode(multibase).map_err(|e| {
        DataIntegrityError::Resolver(format!(
            "the verificationMethod's public key is not valid multibase: {e}"
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
    Err(DataIntegrityError::Resolver(
        "the verificationMethod carries a key whose multicodec prefix this build does not \
         recognise, so its signature suite cannot be determined"
            .to_string(),
    ))
}

/// Deliberately **not** the upstream `VerificationMethodResolver`, which has no
/// purpose to check: verify through [`PurposeBound`](super::purpose::PurposeBound).
#[async_trait::async_trait]
impl PurposeVmResolver for TrustTaskVmResolver {
    async fn resolve_vm_for_purpose(
        &self,
        vm: &str,
        purpose: ProofPurpose,
    ) -> Result<ResolvedKey, DataIntegrityError> {
        self.resolve(vm, purpose).await
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
            .resolve_vm_for_purpose(&vm, ProofPurpose::AssertionMethod)
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
            .resolve_vm_for_purpose(&vm, ProofPurpose::AssertionMethod)
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
            .resolve_vm_for_purpose(
                "did:webvh:QmScid:example.com:glenn#key-0",
                ProofPurpose::AssertionMethod,
            )
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

    fn ed25519_did_key(seed: u8) -> String {
        let sk = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
        let mb = multibase::encode(
            multibase::Base::Base58Btc,
            [&[0xed, 0x01][..], &sk.verifying_key().to_bytes()[..]].concat(),
        );
        format!("did:key:{mb}")
    }

    /// VTI-KEY-022, did:key: its one key is authorised for every signing
    /// purpose, and only that method URI names it.
    #[tokio::test]
    async fn a_did_key_resolves_for_every_signing_purpose_and_only_as_itself() {
        let did = ed25519_did_key(0x21);
        let id = did.strip_prefix("did:key:").unwrap();
        let vm = format!("{did}#{id}");
        let r = TrustTaskVmResolver::did_key_only();
        for purpose in ProofPurpose::ALL {
            r.resolve_vm_for_purpose(&vm, purpose)
                .await
                .unwrap_or_else(|e| panic!("did:key for {purpose}: {e}"));
        }
        let err = r
            .resolve_vm_for_purpose(&format!("{did}#key-0"), ProofPurpose::Authentication)
            .await
            .expect_err("a did:key has no #key-0");
        assert!(err.to_string().contains("fragment must repeat"), "{err}");
    }

    /// VTI-KEY-022, did:peer: a V key is listed under authentication and
    /// assertionMethod only, and an E key under keyAgreement only — so the
    /// E key signs for nothing and the V key cannot invoke a capability.
    #[tokio::test]
    async fn a_did_peer_key_resolves_only_for_its_relationships() {
        use affinidi_tdk::dids::{DID, KeyType, PeerKeyRole};
        let (did, _) = DID::generate_did_peer(
            vec![
                (PeerKeyRole::Verification, KeyType::Ed25519),
                (PeerKeyRole::Encryption, KeyType::X25519),
            ],
            None,
        )
        .expect("mint a did:peer");
        let r = TrustTaskVmResolver::did_key_only();
        let v = format!("{did}#key-1");
        let e = format!("{did}#key-2");

        for purpose in [ProofPurpose::Authentication, ProofPurpose::AssertionMethod] {
            r.resolve_vm_for_purpose(&v, purpose)
                .await
                .unwrap_or_else(|err| panic!("V key for {purpose}: {err}"));
        }
        let err = r
            .resolve_vm_for_purpose(&v, ProofPurpose::CapabilityInvocation)
            .await
            .expect_err("a V key is not a capabilityInvocation key");
        assert!(
            err.to_string()
                .contains("not listed under capabilityInvocation"),
            "{err}"
        );

        for purpose in ProofPurpose::ALL {
            let err = r
                .resolve_vm_for_purpose(&e, purpose)
                .await
                .expect_err("a key-agreement key signs for nothing");
            assert!(err.to_string().contains("not listed under"), "{err}");
            assert!(
                !err.to_string().contains(&did),
                "no DID in the refusal: {err}"
            );
        }
    }

    /// End to end: a Trust Task proof declaring a purpose its key is not
    /// listed under is refused, although the signature itself is genuine.
    #[tokio::test]
    async fn a_trust_task_proof_for_the_wrong_purpose_is_refused() {
        use affinidi_data_integrity::{DataIntegrityProof, SignOptions};
        use affinidi_tdk::dids::{DID, KeyType, PeerKeyRole};
        use trust_tasks_rs::TrustTask;

        let (did, secrets) =
            DID::generate_did_peer(vec![(PeerKeyRole::Verification, KeyType::Ed25519)], None)
                .expect("mint a did:peer");
        let secret = secrets.into_iter().next().expect("the V key");
        let unsigned = serde_json::json!({
            "id": "urn:uuid:11111111-1111-4111-8111-111111111112",
            "type": "https://trusttasks.org/spec/vta/contexts/create/1.0",
            "issuer": did,
            "recipient": "did:key:z6MkVta",
            "payload": {},
        });
        let verify = |purpose: &'static str| {
            let unsigned = unsigned.clone();
            let secret = secret.clone();
            async move {
                let proof = DataIntegrityProof::sign(
                    &unsigned,
                    &secret,
                    SignOptions::new().with_proof_purpose(purpose),
                )
                .await
                .expect("sign");
                let mut doc = unsigned;
                doc["proof"] = serde_json::to_value(proof).unwrap();
                let doc: TrustTask<serde_json::Value> = serde_json::from_value(doc).unwrap();
                crate::trust_task_proof::verify::verify_trust_task_proof_with(
                    &doc,
                    &TrustTaskVmResolver::did_key_only(),
                )
                .await
            }
        };
        verify("authentication")
            .await
            .expect("listed under authentication");
        verify("assertionMethod")
            .await
            .expect("listed under assertionMethod");
        assert!(verify("capabilityInvocation").await.is_err());
        assert!(verify("keyAgreement").await.is_err());
    }

    #[test]
    fn the_debug_rendering_says_whether_it_can_reach_the_network() {
        let s = format!("{:?}", TrustTaskVmResolver::did_key_only());
        assert!(s.contains("network_resolution: false"), "got {s}");
    }
}
