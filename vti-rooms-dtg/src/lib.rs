//! The cryptographic half of room authorization.
//!
//! [`vti_rooms::authz`] decides whether a presentation is *shaped* right and then asks a
//! [`ChainVerifier`] whether it is *true*. This crate is that verifier, over the DTG
//! credentials the rooms design uses: a VMC for membership and a chain of VACs for
//! authority.
//!
//! # Why this is a separate crate
//!
//! `vti-rooms` is published and depends on nothing but `vti-common`, so a room host can
//! reuse its storage without dragging in a credential library and a DID resolver. Verifying
//! needs both. Keeping them apart is also what lets `vti-rooms` stay honest about the
//! seam — a host that has configured no verifier gets `RefusesEverything` and serves
//! nothing, rather than a permissive default nobody notices.
//!
//! # What verification actually consists of
//!
//! Two independent checks, and neither substitutes for the other:
//!
//! - **Are these credentials genuine?** Each one's data-integrity proof must verify against
//!   the key its `verificationMethod` names. That is what [`VerificationKeys`] resolves.
//! - **Do genuine credentials add up to the authority claimed?** That is
//!   `dtg_credentials::authority::verify_chain`, and it is the part that matters: anyone can
//!   mint a well-formed VAC naming any scope and any action, and it will verify perfectly as
//!   a credential. What makes it worthless is that its chain does not reach the party
//!   governing the scope — here, the room.
//!
//! Doing only the first is the classic mistake. A valid signature on a self-issued grant is
//! still a self-issued grant.
//!
//! # The room governs its own scope
//!
//! `governing_party` and `requested_scope` are both the room's DID. That is the whole of
//! invariant I5 in one line: a chain is worth something here **because it reaches the room**,
//! not because a host recognises the issuer. A chain rooted at the community that the room
//! belongs to, or at the host, or at anyone else, confers nothing — which is what lets the
//! room move to a different host without reissuing a single credential.
//!
//! # Nothing is fetched
//!
//! `verify_chain` takes the chain as a slice and never dereferences a `parent`, and this
//! crate never fetches a credential either. Resolving over the network would make
//! verification depend on availability, turn an identifier into a request the host can be
//! induced to make against an address the *holder* chooses, and signal credential use to
//! whoever hosts that identifier. [`VerificationKeys`] resolves **keys**, which is a
//! different thing: a key is named by the credential's own proof, and a host that cannot
//! resolve it refuses rather than proceeding.

use affinidi_data_integrity::VerificationMethodResolver;
use affinidi_secrets_resolver::secrets::KeyType;
use base64::Engine as _;
use dtg_credentials::authority::{AuthorityError, verify_chain};
use dtg_credentials::{DTGCredential, DTGCredentialType};
use vti_common::error::AppError;
use vti_rooms::authz::{Action, ChainVerifier, VerifiedChain};
use vti_rooms::wire::AuthorityPresentation;
use vti_rooms::{Room, Visibility};

pub mod nomination;

pub use vti_rooms::authz::ACTION_SUCCEED;

/// Resolve a credential's `verificationMethod` to the public key that signed it.
///
/// One implementation per host, because a VTC resolves DIDs through its own resolver and a
/// standalone room host through whatever it was configured with. Both answer the same
/// question, and both must **fail** rather than guess: a verifier that treats an
/// unresolvable method as "probably fine" has stopped checking signatures.
#[async_trait::async_trait]
pub trait VerificationKeys: Send + Sync {
    /// The Ed25519 public key bytes for `verification_method`.
    async fn public_key(&self, verification_method: &str) -> Result<Vec<u8>, AppError>;
}

/// [`VerificationKeys`] over any resolver the host already has.
///
/// Both a VTC and a room host carry an `affinidi_data_integrity::VerificationMethodResolver`
/// — `vti_common::auth::TrustTaskVmResolver` is one — so wrapping it beats making each host
/// write its own lookup and get the key-type check subtly different.
pub struct DataIntegrityKeys<R>(pub R);

#[async_trait::async_trait]
impl<R: VerificationMethodResolver + Send + Sync> VerificationKeys for DataIntegrityKeys<R> {
    async fn public_key(&self, verification_method: &str) -> Result<Vec<u8>, AppError> {
        let resolved = self
            .0
            .resolve_vm(verification_method)
            .await
            .map_err(|e| AppError::NotFound(format!("resolve `{verification_method}`: {e}")))?;

        // Room credentials are signed `eddsa-jcs-2022`. Handing a P-256 key to an Ed25519
        // verifier is not a type error anywhere in the stack — the bytes are the same
        // length — so the algorithm is checked here rather than assumed.
        if !matches!(resolved.key_type, KeyType::Ed25519) {
            return Err(AppError::NotFound(format!(
                "`{verification_method}` is a {:?} key; room credentials are eddsa-jcs-2022",
                resolved.key_type
            )));
        }
        Ok(resolved.public_key_bytes)
    }
}

/// Verify a `private` room's subject binding.
///
/// Split out because it is the one part of this that the specification does not yet settle.
/// On the disclosing tiers the pooling defence is a comparison — the VMC's subject against
/// the chain's — and [`DtgChainVerifier`] does it inline. On a `private` room the subject is
/// withheld by design, so the same property has to be proved in zero knowledge, and *which*
/// proof is a profile question: the DTG cred-spec puts ZK protocols and registry-ZK
/// interactions explicitly out of scope, and the working group has not chosen one.
///
/// So this is a seam with no default implementation shipped, and
/// [`DtgChainVerifier::without_zk`] refuses every private-room presentation with a message
/// saying exactly that. That is the honest position: a private room whose pooling defence
/// nobody checked is worse than a private room that will not open, because two parties can
/// combine one's membership with the other's authority and present as a single party
/// holding both.
#[async_trait::async_trait]
pub trait SubjectBindingVerifier: Send + Sync {
    /// Prove that `binding` shows the membership presentation and the chain leaf describe
    /// one subject, and return that subject's identifier for the room's purposes.
    async fn verify_same_subject(
        &self,
        room: &Room,
        membership: &str,
        binding: &str,
        chain_leaf_subject: &str,
    ) -> Result<(), AppError>;
}

/// The verifier that refuses every private room, and says why.
struct NoZkProfile;

#[async_trait::async_trait]
impl SubjectBindingVerifier for NoZkProfile {
    async fn verify_same_subject(
        &self,
        room: &Room,
        _membership: &str,
        _binding: &str,
        _chain_leaf_subject: &str,
    ) -> Result<(), AppError> {
        Err(AppError::Forbidden(format!(
            "room `{}` is private, and this host has no zero-knowledge profile configured \
             to verify its subject binding; serving it would mean accepting a pooling \
             defence nobody checked",
            room.room_id
        )))
    }
}

/// Verifies room presentations against DTG credentials.
pub struct DtgChainVerifier {
    keys: Box<dyn VerificationKeys>,
    zk: Box<dyn SubjectBindingVerifier>,
}

impl DtgChainVerifier {
    /// A verifier for the `open` and `attributed` tiers.
    ///
    /// Private rooms are refused, with a message naming the missing profile — see
    /// [`SubjectBindingVerifier`] for why that is the honest default rather than a gap.
    pub fn without_zk(keys: Box<dyn VerificationKeys>) -> Self {
        Self {
            keys,
            zk: Box::new(NoZkProfile),
        }
    }

    /// A verifier for every tier, once a zero-knowledge profile exists.
    pub fn with_zk(keys: Box<dyn VerificationKeys>, zk: Box<dyn SubjectBindingVerifier>) -> Self {
        Self { keys, zk }
    }

    /// Decode one presented credential and verify its proof.
    async fn open_credential(&self, encoded: &str, what: &str) -> Result<DTGCredential, AppError> {
        open_credential(encoded, what, self.keys.as_ref())
            .await
            // Everything this verifier refuses is a `Forbidden`; the shared opener is also
            // used by a path where a bad credential is a malformed request rather than a
            // denied one, so it reports `Validation` and this maps it back.
            .map_err(|e| AppError::Forbidden(e.to_string()))
    }
}

/// Decode one credential and verify its proof against the key its own proof names.
///
/// Shared because the alternative is two decoders that agree today. They would not stay
/// agreed: the serialization is a profile question the schema leaves open, and a second copy
/// is a second place to accept a form the first does not — which is how one path ends up
/// verifying something another would refuse.
///
/// Accepts base64url or bare JSON. Both are unambiguous — a JSON document starts with `{`
/// and base64url has no `{` in its alphabet — and accepting both means a caller
/// hand-building a request for a demo or a test does not have to encode by hand.
pub async fn open_credential(
    encoded: &str,
    what: &str,
    keys: &dyn VerificationKeys,
) -> Result<DTGCredential, AppError> {
    let bytes = if encoded.trim_start().starts_with('{') {
        encoded.as_bytes().to_vec()
    } else {
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(encoded.trim())
            .map_err(|_| {
                AppError::Validation(format!(
                    "{what} is neither base64url nor JSON; a credential that cannot be \
                     read cannot be verified"
                ))
            })?
    };

    let credential: DTGCredential = serde_json::from_slice(&bytes)
        .map_err(|e| AppError::Validation(format!("{what} is not a DTG credential: {e}")))?;

    let proof = credential
        .credential()
        .proof
        .as_ref()
        .ok_or_else(|| AppError::Validation(format!("{what} carries no proof")))?;

    let key = keys
        .public_key(&proof.verification_method)
        .await
        .map_err(|e| {
            // The resolver's own error is for the operator; the caller learns only that it
            // did not verify, so an unresolvable method is not an oracle for which DIDs this
            // host can reach.
            tracing::warn!(
                verification_method = %proof.verification_method,
                error = %e,
                "could not resolve a room credential's verification method"
            );
            AppError::Validation(format!("{what} could not be verified"))
        })?;

    credential.verify_proof_with_public_key(&key).map_err(|e| {
        tracing::warn!(error = %e, "room credential proof did not verify");
        AppError::Validation(format!("{what} could not be verified"))
    })?;

    Ok(credential)
}

/// An [`AuthorityError`] as a refusal.
///
/// Every variant becomes the same `Forbidden`, with the specifics in the message for an
/// operator reading logs. A caller learns that the chain did not carry the authority — not
/// which link to adjust, which would make the verifier a tool for assembling one.
pub(crate) fn chain_refusal(room_id: &str, e: AuthorityError) -> AppError {
    AppError::Forbidden(format!(
        "the authority chain does not confer this on room `{room_id}`: {e}"
    ))
}

#[async_trait::async_trait]
impl ChainVerifier for DtgChainVerifier {
    async fn verify(
        &self,
        room: &Room,
        presentation: &AuthorityPresentation,
        action: Action,
        presenter: &str,
    ) -> Result<VerifiedChain, AppError> {
        // The chain, leaf first, every link's proof checked before any of them is trusted to
        // say anything about the others.
        let mut chain = Vec::with_capacity(presentation.authority.len());
        for (index, encoded) in presentation.authority.iter().enumerate() {
            chain.push(
                self.open_credential(encoded, &format!("authority credential {index}"))
                    .await?,
            );
        }

        // `verify_chain` answers the question the signatures do not: does this add up to the
        // authority claimed? Both the governing party and the scope are the room itself —
        // a chain rooted anywhere else confers nothing here, however valid.
        let verified = verify_chain(
            &chain,
            &room.room_id,
            &room.room_id,
            action.as_str(),
            presenter,
            chrono::Utc::now(),
        )
        .map_err(|e| chain_refusal(&room.room_id, e))?;

        // `verify_chain` takes `presenter` but uses it for **one** thing: the `audience`
        // check, where a link that names an audience must be presented by that audience. It
        // does not require the leaf to grant to the presenter, and that is deliberate on
        // its side — the leaf's subject is "who may act", and binding that to the party the
        // *transport* authenticated is a question about this request, not about the chain.
        //
        // Which makes it ours, and it is not optional: without it a presentation is a
        // bearer token, and anyone who observes one inherits everything it confers. A test
        // above presents an agent's chain as the agent's human and expects a refusal.
        if verified.subject != presenter {
            return Err(AppError::Forbidden(format!(
                "the chain's leaf grants to `{}`, not to the party that signed this \
                 request; a presentation is bound to its presenter, not bearer",
                verified.subject
            )));
        }

        // The pooling defence: membership and authority must describe one subject.
        match room.visibility {
            // The subject is withheld, so it is proved rather than compared. `authorize`
            // has already refused a presentation with no binding at all; this is whether
            // the one present actually proves it.
            Visibility::Private => {
                let binding = presentation.subject_binding.as_deref().ok_or_else(|| {
                    AppError::Forbidden("a private room requires a subject binding".into())
                })?;
                self.zk
                    .verify_same_subject(room, &presentation.membership, binding, &verified.subject)
                    .await?;
            }
            // The subject is disclosed, so it is compared.
            Visibility::Open | Visibility::Attributed => {
                let membership = self
                    .open_credential(&presentation.membership, "membership credential")
                    .await?;

                if !matches!(membership.type_(), DTGCredentialType::Membership) {
                    return Err(AppError::Forbidden(format!(
                        "the presented membership credential is a {}, not a VMC",
                        membership.type_()
                    )));
                }

                // A VMC for some other room says nothing about this one.
                if membership.issuer() != room.room_id {
                    return Err(AppError::Forbidden(format!(
                        "the membership credential was issued by `{}`, not by room `{}`",
                        membership.issuer(),
                        room.room_id
                    )));
                }

                // The subject to compare is the **root's**, not the leaf's.
                //
                // The leaf says who may act, and that is frequently not a member: the case
                // this design exists for is a member equipping their agent with a narrower
                // chain, and an agent is not a member of anything. Comparing the leaf
                // would refuse exactly the arrangement the rooms design is for.
                //
                // The root's subject is the party the *room* granted to, and every
                // attenuation below it descends from them — `verify_chain` has already
                // established that each link's issuer is its parent's subject. So the root
                // is which member's standing this authority descends from, and requiring
                // the VMC to be theirs is what closes the pooling attack: a chain rooted at
                // Bob cannot be presented with Alice's membership, whoever holds the leaf.
                let root = chain.last().expect("verify_chain rejects an empty chain");
                if membership.subject() != root.subject() {
                    return Err(AppError::Forbidden(format!(
                        "the membership credential describes `{}` but the authority chain \
                         descends from `{}`; two parties cannot pool credentials into one",
                        membership.subject(),
                        root.subject()
                    )));
                }
            }
        }

        Ok(VerifiedChain {
            subject: verified.subject,
            actions: verified.actions,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A resolver that resolves nothing.
    struct NoKeys;

    #[async_trait::async_trait]
    impl VerificationKeys for NoKeys {
        async fn public_key(&self, _vm: &str) -> Result<Vec<u8>, AppError> {
            Err(AppError::NotFound("no keys here".into()))
        }
    }

    fn room(visibility: Visibility) -> Room {
        Room {
            room_id: "did:webvh:example.com:rooms:northwind".into(),
            owner_did: "did:key:z6MkOwner".into(),
            visibility,
            epoch: 1,
            next_version: 1,
            retention_days: 90,
            epoch_expires_at: None,
            created_at: 0,
            updated_at: 0,
        }
    }

    fn presentation(authority: Vec<String>, binding: Option<&str>) -> AuthorityPresentation {
        AuthorityPresentation {
            membership: "{}".into(),
            authority,
            subject_binding: binding.map(str::to_string),
        }
    }

    /// A real, well-formed VAC — built by the library that verifies it, so this test
    /// exercises the shape the implementation actually produces rather than one hand-typed
    /// beside it.
    ///
    /// Deliberately **unsigned in effect**: it carries a proof block whose value is
    /// nonsense. Everything about it is right except the one thing that matters.
    fn a_vac(issuer: &str, subject: &str, scope: &str, actions: &[&str]) -> String {
        let mut vac = DTGCredential::new_vac(
            issuer.into(),
            subject.into(),
            scope.into(),
            actions.iter().map(|s| s.to_string()).collect(),
            chrono::Utc::now() - chrono::Duration::hours(1),
            Some(chrono::Utc::now() + chrono::Duration::hours(1)),
        )
        .expect("build a VAC");

        let mut doc = serde_json::to_value(vac.credential()).expect("serialise");
        doc["proof"] = serde_json::json!({
            "type": "DataIntegrityProof",
            "cryptosuite": "eddsa-jcs-2022",
            "created": "2026-09-01T00:00:00Z",
            "verificationMethod": format!("{issuer}#key-0"),
            "proofPurpose": "assertionMethod",
            "proofValue": "z2LJhFyBmRcqMKZbdgVBb9nQpjhTjcMwCsSYRfPqk5bZ",
        });
        let _ = &mut vac;
        doc.to_string()
    }

    /// A credential this host cannot resolve a key for does not verify — it does not get
    /// the benefit of the doubt, and the refusal does not say which DIDs are reachable.
    #[tokio::test]
    async fn an_unresolvable_verification_method_refuses() {
        let v = DtgChainVerifier::without_zk(Box::new(NoKeys));
        let err = v
            .verify(
                &room(Visibility::Open),
                &presentation(
                    vec![a_vac(
                        "did:webvh:example.com:rooms:northwind",
                        "did:key:zAgent",
                        "did:webvh:example.com:rooms:northwind",
                        &["read"],
                    )],
                    None,
                ),
                Action::Read,
                "did:key:zAgent",
            )
            .await
            .unwrap_err();
        let text = format!("{err}");
        assert!(text.contains("could not be verified"), "{text}");
        assert!(
            !text.contains("no keys here"),
            "the resolver's reason is for the operator's log, not the caller: {text}"
        );
    }

    /// The check that carries the weight. A chain of perfectly valid credentials, rooted
    /// at a party that is not the room, confers nothing here — that is invariant I5, and it
    /// is what lets a room move host without reissuing anything.
    #[tokio::test]
    async fn a_chain_rooted_anywhere_but_the_room_confers_nothing() {
        struct AnyKey;
        #[async_trait::async_trait]
        impl VerificationKeys for AnyKey {
            async fn public_key(&self, _vm: &str) -> Result<Vec<u8>, AppError> {
                Ok(vec![0u8; 32])
            }
        }

        // Mallory issues herself full authority over someone else's room. Every field is
        // well-formed; the chain simply does not reach the room.
        let v = DtgChainVerifier::without_zk(Box::new(AnyKey));
        let err = v
            .verify(
                &room(Visibility::Open),
                &presentation(
                    vec![a_vac(
                        "did:key:zMallory",
                        "did:key:zMallory",
                        "did:webvh:example.com:rooms:northwind",
                        &["read", "write", "admin"],
                    )],
                    None,
                ),
                Action::Admin,
                "did:key:zMallory",
            )
            .await
            .unwrap_err();
        // It fails at the signature with this stub resolver, and would fail at the chain
        // with a real one. Either way it does not authorize, which is the property.
        assert!(format!("{err}").contains("could not be verified"), "{err}");
    }

    #[tokio::test]
    async fn a_credential_that_is_neither_base64url_nor_json_refuses() {
        let v = DtgChainVerifier::without_zk(Box::new(NoKeys));
        let err = v
            .verify(
                &room(Visibility::Open),
                &presentation(vec!["not a credential !!!".into()], None),
                Action::Read,
                "did:key:zAgent",
            )
            .await
            .unwrap_err();
        assert!(
            format!("{err}").contains("neither base64url nor JSON"),
            "{err}"
        );
    }

    /// A private room without a zero-knowledge profile is refused by the verifier, not
    /// quietly served. The message names what is missing.
    #[tokio::test]
    async fn a_private_room_refuses_without_a_zk_profile() {
        struct OneKey;
        #[async_trait::async_trait]
        impl VerificationKeys for OneKey {
            async fn public_key(&self, _vm: &str) -> Result<Vec<u8>, AppError> {
                Ok(vec![0u8; 32])
            }
        }

        // The chain never gets far enough for the ZK check here — the point of the test is
        // that `without_zk` carries a refusing binding verifier at all, which
        // `NoZkProfile` asserts directly.
        let refusal = NoZkProfile
            .verify_same_subject(&room(Visibility::Private), "vmc", "binding", "did:key:zA")
            .await
            .unwrap_err();
        assert!(
            format!("{refusal}").contains("no zero-knowledge profile configured"),
            "{refusal}"
        );

        let _ = DtgChainVerifier::without_zk(Box::new(OneKey));
    }
}

/// The end-to-end tests: real keys, real signatures, real chains.
///
/// Separated from the unit tests above because these are the ones that matter. Every test
/// up there asserts a refusal, and a verifier that refused everything would pass all of
/// them — these are what say it admits a good chain, and only a good one.
#[cfg(test)]
mod signed {
    use super::*;
    use affinidi_tdk::dids::{DID, KeyType};
    use chrono::{Duration, Utc};

    /// Resolves a `did:key`'s verification method to its own public key, which is what a
    /// `did:key` is. No network, and no opportunity to resolve to the wrong key.
    pub(crate) struct DidKeyResolver;

    #[async_trait::async_trait]
    impl VerificationKeys for DidKeyResolver {
        async fn public_key(&self, vm: &str) -> Result<Vec<u8>, AppError> {
            let did = vm.split('#').next().unwrap_or_default();
            let multibase = did
                .strip_prefix("did:key:")
                .ok_or_else(|| AppError::NotFound(format!("not a did:key: {did}")))?;
            vta_sdk::did_key::decode_ed25519_public_key_multibase(multibase)
                .map(|k| k.to_vec())
                .map_err(|e| AppError::NotFound(format!("decode {did}: {e}")))
        }
    }

    /// A room, its owner, and that owner's agent — the shape the whole design exists for.
    struct Fixture {
        room: Room,
        /// The owner's chain: one link, straight from the room.
        owner_chain: Vec<String>,
        owner_did: String,
        /// The agent's chain: the owner's, with a narrower leaf on top.
        agent_chain: Vec<String>,
        agent_did: String,
        /// The owner's membership credential, issued by the room.
        membership: String,
    }

    async fn fixture() -> Fixture {
        let (room_did, room_secret) = DID::generate_did_key(KeyType::Ed25519).expect("room key");
        let (owner_did, owner_secret) = DID::generate_did_key(KeyType::Ed25519).expect("owner key");
        let (agent_did, _) = DID::generate_did_key(KeyType::Ed25519).expect("agent key");
        let now = Utc::now();

        // The room grants its owner read and write. This is the chain root: it is worth
        // something because the *room* issued it.
        let mut owner_vac = DTGCredential::new_vac(
            room_did.clone(),
            owner_did.clone(),
            room_did.clone(),
            vec!["read".into(), "write".into()],
            now - Duration::minutes(1),
            Some(now + Duration::days(30)),
        )
        .expect("owner VAC")
        .with_id("urn:uuid:vac-owner");
        owner_vac.sign(&room_secret, None).await.expect("sign");

        // The owner narrows it for their agent — four hours, read only, no involvement
        // from the room. That is the whole point of attenuation.
        let mut agent_vac = owner_vac
            .attenuate(
                agent_did.clone(),
                vec!["read".into()],
                now - Duration::minutes(1),
                Some(now + Duration::hours(4)),
                None,
            )
            .expect("attenuate")
            .with_id("urn:uuid:vac-agent");
        agent_vac.sign(&owner_secret, None).await.expect("sign");

        let mut vmc = DTGCredential::new_vmc(
            room_did.clone(),
            owner_did.clone(),
            now - Duration::minutes(1),
            Some(now + Duration::days(30)),
            false,
        );
        vmc.sign(&room_secret, None).await.expect("sign");

        let enc = |c: &DTGCredential| serde_json::to_string(c).expect("serialise");

        Fixture {
            room: Room {
                room_id: room_did,
                owner_did: owner_did.clone(),
                visibility: Visibility::Attributed,
                epoch: 1,
                next_version: 1,
                retention_days: 90,
                epoch_expires_at: None,
                created_at: 0,
                updated_at: 0,
            },
            owner_chain: vec![enc(&owner_vac)],
            owner_did,
            agent_chain: vec![enc(&agent_vac), enc(&owner_vac)],
            agent_did,
            membership: enc(&vmc),
        }
    }

    fn present(f: &Fixture, chain: &[String]) -> AuthorityPresentation {
        AuthorityPresentation {
            membership: f.membership.clone(),
            authority: chain.to_vec(),
            subject_binding: None,
        }
    }

    fn verifier() -> DtgChainVerifier {
        DtgChainVerifier::without_zk(Box::new(DidKeyResolver))
    }

    #[tokio::test]
    async fn a_signed_chain_from_the_room_authorizes_its_owner() {
        let f = fixture().await;
        let v = verifier()
            .verify(
                &f.room,
                &present(&f, &f.owner_chain),
                Action::Write,
                &f.owner_did,
            )
            .await
            .expect("a chain the room issued, to the party presenting it, must verify");
        assert_eq!(v.subject, f.owner_did);
        assert!(v.actions.contains(&"write".to_string()));
    }

    /// The feature the design exists for: an agent holding strictly less than its human,
    /// with no involvement from the room in narrowing it.
    #[tokio::test]
    async fn an_attenuated_chain_authorizes_the_agent_for_less() {
        let f = fixture().await;
        let v = verifier()
            .verify(
                &f.room,
                &present(&f, &f.agent_chain),
                Action::Read,
                &f.agent_did,
            )
            .await
            .expect("the agent reads");
        assert_eq!(v.subject, f.agent_did);
        assert_eq!(
            v.actions,
            vec!["read".to_string()],
            "attenuation narrows; it never widens"
        );

        let err = verifier()
            .verify(
                &f.room,
                &present(&f, &f.agent_chain),
                Action::Write,
                &f.agent_did,
            )
            .await
            .unwrap_err();
        assert!(
            format!("{err}").contains("does not confer"),
            "the agent must not write: {err}"
        );
    }

    /// A captured presentation is not a bearer token. The chain grants to the agent, so
    /// the owner cannot present it and neither can anyone else.
    #[tokio::test]
    async fn a_chain_is_bound_to_the_party_presenting_it() {
        let f = fixture().await;
        let err = verifier()
            .verify(
                &f.room,
                &present(&f, &f.agent_chain),
                Action::Read,
                &f.owner_did,
            )
            .await
            .unwrap_err();
        assert!(
            format!("{err}").contains("not to the party that signed this request"),
            "{err}"
        );
    }

    /// Tampering with a credential after it was signed invalidates it, which is the whole
    /// reason the proof is checked before the chain is read.
    #[tokio::test]
    async fn a_widened_credential_does_not_verify() {
        let f = fixture().await;

        // Add `admin` to the owner's signed VAC without re-signing.
        let mut doc: serde_json::Value =
            serde_json::from_str(&f.owner_chain[0]).expect("parse the signed VAC");
        doc["credentialSubject"]["authority"]["actions"]
            .as_array_mut()
            .expect("actions is an array")
            .push(serde_json::json!("admin"));

        let err = verifier()
            .verify(
                &f.room,
                &present(&f, &[doc.to_string()]),
                Action::Admin,
                &f.owner_did,
            )
            .await
            .unwrap_err();
        assert!(format!("{err}").contains("could not be verified"), "{err}");
    }

    /// A VMC the room did not issue says nothing about membership of this room, however
    /// valid it is elsewhere.
    #[tokio::test]
    async fn a_membership_credential_from_another_room_is_refused() {
        let f = fixture().await;
        let other = fixture().await;

        let mut p = present(&f, &f.owner_chain);
        p.membership = other.membership;

        let err = verifier()
            .verify(&f.room, &p, Action::Read, &f.owner_did)
            .await
            .unwrap_err();
        assert!(format!("{err}").contains("not by room"), "{err}");
    }

    /// The pooling defence on a disclosing tier: one party's membership plus another's
    /// authority is two parties, not one.
    #[tokio::test]
    async fn membership_and_authority_must_describe_one_subject() {
        let f = fixture().await;

        // A chain rooted at a *different* room's owner, presented with this room's
        // membership. Both halves are perfectly valid; they just belong to two people.
        let other = fixture().await;
        let mut p = present(&f, &other.owner_chain);
        p.membership = f.membership.clone();

        let err = verifier()
            .verify(&f.room, &p, Action::Read, &other.owner_did)
            .await
            .unwrap_err();
        assert!(
            format!("{err}").contains("cannot pool credentials into one")
                || format!("{err}").contains("does not confer"),
            "{err}"
        );
    }

    /// The agent case, stated as its own property because getting it wrong is subtle: an
    /// agent presents its human's membership alongside a chain whose *leaf* grants to the
    /// agent. Comparing the leaf's subject to the VMC would refuse this — and refusing it
    /// would remove the entire reason the design has attenuation.
    #[tokio::test]
    async fn an_agent_presents_its_humans_membership() {
        let f = fixture().await;
        let v = verifier()
            .verify(
                &f.room,
                &present(&f, &f.agent_chain),
                Action::Read,
                &f.agent_did,
            )
            .await
            .expect("an agent is not a member; its authority descends from one");
        assert_eq!(
            v.subject, f.agent_did,
            "and it acts as itself, not as its human"
        );
    }

    /// base64url is the other accepted form, and it must reach the same conclusion.
    #[tokio::test]
    async fn base64url_and_json_verify_identically() {
        let f = fixture().await;
        let encoded: Vec<String> = f
            .owner_chain
            .iter()
            .map(|c| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(c))
            .collect();

        let mut p = present(&f, &encoded);
        p.membership = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&f.membership);

        let v = verifier()
            .verify(&f.room, &p, Action::Write, &f.owner_did)
            .await
            .expect("base64url is the same credential");
        assert_eq!(v.subject, f.owner_did);
    }
}

/// Fixtures for exercising a real room: real keys, real signatures, real chains.
///
/// Behind a feature because a permissive fixture is exactly what should not ship. It exists
/// because three places need the same setup — this crate's own tests, `room-host`'s, and the
/// `data_room` example — and three hand-rolled versions of "a signed chain rooted at the
/// room" would drift, with the drift showing up as a test that passes for the wrong reason.
#[cfg(feature = "test-support")]
pub mod test_support {
    use super::*;
    use chrono::{Duration, Utc};

    /// One party: a `did:key` in the three forms different layers want.
    pub struct Party {
        /// `did:key:z6Mk…`
        pub did: String,
        /// The multibase private key, for signing Trust Task documents.
        pub secret_multibase: String,
        /// The Affinidi secret, for signing credentials.
        pub secret: affinidi_tdk::secrets_resolver::secrets::Secret,
    }

    impl Party {
        /// Mint one.
        pub fn new() -> Self {
            let mut seed = [0u8; 32];
            getrandom::fill(&mut seed).expect("OS randomness");
            let signing = ed25519_dalek::SigningKey::from_bytes(&seed);
            let did = format!(
                "did:key:{}",
                vta_sdk::did_key::ed25519_multibase_pubkey(&signing.verifying_key().to_bytes())
            );
            Self {
                secret: vta_sdk::did_key::secrets_from_did_key(&did, &seed)
                    .expect("build secrets")
                    .signing,
                secret_multibase: multibase::encode(multibase::Base::Base58Btc, seed),
                did,
            }
        }
    }

    impl Default for Party {
        fn default() -> Self {
            Self::new()
        }
    }

    /// A room, its owner, and the owner's agent — with every credential actually signed.
    pub struct RoomFixture {
        /// The room itself. Its DID is a `did:key` so a host needs no network to verify it.
        pub room: Room,
        /// The room's own key, which issues membership and the chain root.
        pub room_key: Party,
        pub owner: Party,
        pub agent: Party,
        /// A second member — the one succession is for. Everything a claimant needs and
        /// nothing more: their own membership and their own chain from the room, at
        /// `read`. Deliberately *not* an admin, because a successor who already held
        /// `admin` would prove nothing about whether a nomination is what admitted them.
        pub successor: Party,
        /// The owner's chain: one link, from the room.
        pub owner_chain: Vec<String>,
        /// The agent's chain: the owner's, with a read-only leaf on top.
        pub agent_chain: Vec<String>,
        /// The owner's membership credential.
        pub membership: String,
        /// The successor's chain: one link from the room, conferring `read`.
        pub successor_chain: Vec<String>,
        /// The successor's own membership credential.
        pub successor_membership: String,
    }

    impl RoomFixture {
        /// Build one at `visibility`.
        pub async fn new(visibility: Visibility) -> Self {
            let room_key = Party::new();
            let owner = Party::new();
            let agent = Party::new();
            let successor = Party::new();
            let now = Utc::now();

            let mut owner_vac = DTGCredential::new_vac(
                room_key.did.clone(),
                owner.did.clone(),
                room_key.did.clone(),
                vec![
                    "read".into(),
                    "write".into(),
                    "curate".into(),
                    "admin".into(),
                ],
                now - Duration::minutes(1),
                Some(now + Duration::days(30)),
            )
            .expect("owner VAC")
            .with_id("urn:uuid:vac-owner");
            owner_vac
                .sign(&room_key.secret, None)
                .await
                .expect("sign the owner VAC");

            // Four hours, read only, and the room is not involved — which is the whole
            // reason attenuation exists.
            let mut agent_vac = owner_vac
                .attenuate(
                    agent.did.clone(),
                    vec!["read".into()],
                    now - Duration::minutes(1),
                    Some(now + Duration::hours(4)),
                    None,
                )
                .expect("attenuate to the agent")
                .with_id("urn:uuid:vac-agent");
            agent_vac
                .sign(&owner.secret, None)
                .await
                .expect("sign the agent VAC");

            let mut vmc = DTGCredential::new_vmc(
                room_key.did.clone(),
                owner.did.clone(),
                now - Duration::minutes(1),
                Some(now + Duration::days(30)),
                false,
            );
            vmc.sign(&room_key.secret, None)
                .await
                .expect("sign the VMC");

            let mut successor_vac = DTGCredential::new_vac(
                room_key.did.clone(),
                successor.did.clone(),
                room_key.did.clone(),
                vec!["read".into()],
                now - Duration::minutes(1),
                Some(now + Duration::days(30)),
            )
            .expect("successor VAC")
            .with_id("urn:uuid:vac-successor");
            successor_vac
                .sign(&room_key.secret, None)
                .await
                .expect("sign the successor VAC");

            let mut successor_vmc = DTGCredential::new_vmc(
                room_key.did.clone(),
                successor.did.clone(),
                now - Duration::minutes(1),
                Some(now + Duration::days(30)),
                false,
            );
            successor_vmc
                .sign(&room_key.secret, None)
                .await
                .expect("sign the successor VMC");

            let enc = |c: &DTGCredential| serde_json::to_string(c).expect("serialise");

            Self {
                room: Room {
                    room_id: room_key.did.clone(),
                    owner_did: owner.did.clone(),
                    visibility,
                    epoch: 1,
                    next_version: 1,
                    retention_days: 90,
                    epoch_expires_at: None,
                    created_at: 0,
                    updated_at: 0,
                },
                owner_chain: vec![enc(&owner_vac)],
                agent_chain: vec![enc(&agent_vac), enc(&owner_vac)],
                membership: enc(&vmc),
                successor_chain: vec![enc(&successor_vac)],
                successor_membership: enc(&successor_vmc),
                room_key,
                owner,
                agent,
                successor,
            }
        }

        /// The owner's presentation.
        pub fn as_owner(&self) -> AuthorityPresentation {
            AuthorityPresentation {
                membership: self.membership.clone(),
                authority: self.owner_chain.clone(),
                subject_binding: None,
            }
        }

        /// The agent's presentation — the owner's membership, a narrower chain.
        pub fn as_agent(&self) -> AuthorityPresentation {
            AuthorityPresentation {
                membership: self.membership.clone(),
                authority: self.agent_chain.clone(),
                subject_binding: None,
            }
        }

        /// The successor's presentation — their own membership, their own chain.
        pub fn as_successor(&self) -> AuthorityPresentation {
            AuthorityPresentation {
                membership: self.successor_membership.clone(),
                authority: self.successor_chain.clone(),
                subject_binding: None,
            }
        }

        /// A succession nomination: the room grants `succeed` to `successor`.
        ///
        /// Signed by the **room**, because that is the only issuer a nomination can have —
        /// an owner nominating in their own name would be a chain rooted at a person, and
        /// the whole point is that it is rooted at the room they are stepping away from.
        pub async fn nominate(&self, successor: &str, valid_until: Option<i64>) -> String {
            let now = Utc::now();
            let mut vac = DTGCredential::new_vac(
                self.room_key.did.clone(),
                successor.to_string(),
                self.room_key.did.clone(),
                vec![crate::ACTION_SUCCEED.into()],
                now - Duration::minutes(1),
                valid_until.map(|h| now + Duration::hours(h)),
            )
            .expect("nomination VAC")
            .with_id("urn:uuid:vac-nomination");
            vac.sign(&self.room_key.secret, None)
                .await
                .expect("sign the nomination");
            serde_json::to_string(&vac).expect("serialise")
        }
    }
}
