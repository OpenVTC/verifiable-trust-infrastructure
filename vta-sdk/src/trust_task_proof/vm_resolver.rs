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
use affinidi_data_integrity::{DataIntegrityError, ResolvedKey, VerificationMethodResolver};
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
            return resolve_did_peer(vm, base_did);
        }

        let resolver = self.resolver.as_ref().ok_or_else(|| {
            DataIntegrityError::Resolver(format!(
                "resolving `{base_did}` needs a DID resolver, but this verifier is configured \
                 for did:key only"
            ))
        })?;
        let resolved = resolver.resolve(base_did).await.map_err(|e| {
            DataIntegrityError::Resolver(format!("`{base_did}` did not resolve: {e}"))
        })?;

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
        Ok(ResolvedKey::new(KeyType::Ed25519, bytes))
    }
}

/// Resolve a `did:peer` verification method with no I/O.
///
/// The document is derived from the identifier and its keys expanded, then the method is
/// looked up exactly as the network path looks one up — including accepting both the
/// absolute and relative spellings of the same id, because a proof always names a method
/// absolutely while a document may not.
fn resolve_did_peer(vm: &str, base_did: &str) -> Result<ResolvedKey, DataIntegrityError> {
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
    Ok(ResolvedKey::new(KeyType::Ed25519, bytes))
}

#[async_trait::async_trait]
impl VerificationMethodResolver for TrustTaskVmResolver {
    async fn resolve_vm(&self, vm: &str) -> Result<ResolvedKey, DataIntegrityError> {
        self.resolve(vm).await
    }
}

#[cfg(test)]
mod tests {
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
