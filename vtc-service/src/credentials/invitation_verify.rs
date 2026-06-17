//! Verify a presented **Invitation Credential** (VIC) at join time — the
//! verification half of the VIC auto-join ceremony (the issuance half is
//! [`super::invitation`]).
//!
//! [`verify_presented_invitation`] pulls the `InvitationCredential` out of a
//! submitted VP, cryptographically verifies its issuer Data-Integrity proof
//! (resolving the issuer DID through the shared [`DidVmResolver`]), and resolves
//! the host-side facts the join policy decides over:
//!
//! - **holder-binding** — the VIC's `credentialSubject.id` must be the
//!   applicant presenting it (a VIC minted for someone else can't be replayed);
//! - **temporal validity** — `validFrom <= now < validUntil`;
//! - **revocation** — the VIC's status-list bit must be clear;
//! - **issuer trust** — is the issuer the community itself (M1 self-issued) or a
//!   registry-recognised third party (M2)? Surfaced as `issuer_trusted`.
//!
//! It returns a [`VerifiedInvitation`] — the workspace's verified-wire-form
//! typestate. The only way to obtain one is to pass every check above, so a call
//! site cannot feed an unverified invitation into the policy. Authenticity
//! failures (bad proof, wrong subject, expired, revoked) are a hard
//! [`AppError::Forbidden`] that never reaches policy; **consumption** is left as
//! a *policy fact* (`Invitation.consumed`) the host attaches separately, so the
//! single-use rule is the policy's call (`has_valid_invitation` rejects a
//! consumed invite) rather than a silent abort.

use std::sync::Arc;

use affinidi_data_integrity::{DataIntegrityProof, VerificationMethodResolver, VerifyOptions};
use affinidi_vc::{SubjectValue, VerifiableCredential};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use tracing::warn;

use vti_common::error::AppError;

use crate::ceremony::facts::Invitation;
use crate::credentials::vm_resolver::{DidVmResolver, check_issuer_binding};
use crate::recognition::{HttpStatusListFetcher, StatusListFetcher};
use crate::registry::TrustRegistryClient;
use crate::server::AppState;

/// The VC `type` tag identifying an Invitation Credential, as minted by the DTG
/// catalog (`dtg::issue_invitation` → `DTGCredential::new_vic`).
pub const INVITATION_CREDENTIAL_TYPE: &str = "InvitationCredential";

/// A presented invitation that passed cryptographic + binding + validity
/// verification. Only constructable via [`verify_presented_invitation`] (or its
/// testable inner), so any code holding one knows the invitation is genuine,
/// bound to the applicant, in-window, and not revoked.
///
/// Whether it has already been **consumed** is deliberately *not* part of this
/// type — consumption is a join-lifecycle fact the host looks up against the
/// `consumed_invitations` keyspace and hands to the policy via
/// [`Self::to_fact`], so the single-use rule stays a policy decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedInvitation {
    /// The VIC's top-level `id` (a `urn:uuid:…`). The consumption key.
    pub id: String,
    /// The DID that issued the VIC (`issuer`).
    pub issuer: String,
    /// The applicant the VIC is bound to (`credentialSubject.id`), already
    /// checked to equal the presenter.
    pub subject: String,
    /// Host verdict: does the community trust this issuer for invitations.
    /// `true` when the issuer is the community itself (M1), or a
    /// registry-recognised third party (M2).
    pub issuer_trusted: bool,
    /// Scopes the invitation authorizes (e.g. role bounds), if the VIC carries a
    /// `credentialSubject.scopes` array. Empty otherwise.
    pub scopes: Vec<String>,
    /// The VIC's `validUntil`, surfaced for the policy / audit.
    pub valid_until: DateTime<Utc>,
}

impl VerifiedInvitation {
    /// Project into the policy-facing [`Invitation`] fact. `consumed` is the
    /// host's single-use lookup against the `consumed_invitations` keyspace —
    /// `verified` is always `true` here because the value only exists once
    /// verification passed.
    pub fn to_fact(&self, consumed: bool) -> Invitation {
        Invitation {
            verified: true,
            issuer: self.issuer.clone(),
            issuer_role: None,
            issuer_trusted: self.issuer_trusted,
            scopes: self.scopes.clone(),
            consumed,
        }
    }
}

/// A consumed-invitation record (single-use enforcement). Stored in the
/// `consumed_invitations` keyspace keyed by the VIC `id`; written when a join
/// admit succeeds, read at verify time to set `Invitation.consumed`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsumedInvitation {
    /// The applicant that redeemed the invitation.
    pub applicant: String,
    /// When it was consumed.
    pub consumed_at: DateTime<Utc>,
    /// The join request that consumed it (audit trail).
    pub via_join_request_id: String,
}

/// Has the invitation `vic_id` already been consumed?
pub async fn is_consumed(
    ks: &vti_common::store::KeyspaceHandle,
    vic_id: &str,
) -> Result<bool, AppError> {
    Ok(ks
        .get::<ConsumedInvitation>(vic_id.as_bytes().to_vec())
        .await?
        .is_some())
}

/// Mark `vic_id` consumed. Uses `insert_if_absent` so a concurrent redeem can't
/// double-consume — returns `true` if this call recorded the consumption,
/// `false` if it was already consumed.
pub async fn mark_consumed(
    ks: &vti_common::store::KeyspaceHandle,
    vic_id: &str,
    record: &ConsumedInvitation,
) -> Result<bool, AppError> {
    ks.insert_if_absent(vic_id.as_bytes().to_vec(), record)
        .await
}

/// Verify a VIC presented inside `vp`, if one is present.
///
/// - `Ok(None)` — the VP carried no `InvitationCredential`; the join proceeds
///   on its other evidence (no invitation fact).
/// - `Ok(Some(_))` — a VIC was present and verified (proof + holder-binding +
///   validity + revocation).
/// - `Err(Forbidden)` — a VIC was present but failed verification; the join is
///   refused before policy.
pub async fn verify_presented_invitation(
    state: &AppState,
    applicant_did: &str,
    vp: &JsonValue,
) -> Result<Option<VerifiedInvitation>, AppError> {
    let Some(vic_json) = extract_invitation(vp) else {
        return Ok(None);
    };

    let own_did = state.config.read().await.vtc_did.clone();
    let resolver = DidVmResolver::new(state.did_resolver.clone());
    // Revocation is checked against the issuer's status list (its own URL): the
    // same fetcher + SSRF guard + issuer-signature verification the recognition
    // and credential-exchange paths use.
    let fetcher = match state.did_resolver.clone() {
        Some(r) => {
            let key_resolver: Arc<dyn VerificationMethodResolver> =
                Arc::new(DidVmResolver::new(Some(r)));
            HttpStatusListFetcher::with_issuer_verification(key_resolver)
        }
        None => HttpStatusListFetcher::new(),
    };

    // Subject-linkage (#1b): when the presenter is not the DID the VIC was
    // minted for, the VP must carry a `subjectLinkage` proof in which the VIC
    // subject authorizes this presenter. Verified here (where the concrete
    // resolver lives) and the verdict threaded into the binding check.
    let subject = vic_json
        .pointer("/credentialSubject/id")
        .and_then(JsonValue::as_str);
    let vic_id = vic_json.get("id").and_then(JsonValue::as_str);
    let linkage_authorized = match (subject, vic_id) {
        (Some(subject), Some(vic_id)) if subject != applicant_did => {
            verify_subject_linkage(vp, subject, vic_id, applicant_did, &resolver).await?;
            true
        }
        _ => false,
    };

    let verified = verify_invitation_inner(
        &vic_json,
        applicant_did,
        own_did.as_deref(),
        state.registry_client.as_deref(),
        &resolver,
        &fetcher,
        Utc::now(),
        linkage_authorized,
    )
    .await?;
    Ok(Some(verified))
}

/// Domain tag the VIC subject signs over for a subject-linkage proof — binds
/// the proof to this protocol so it can't be cross-protocol replayed.
pub const SUBJECT_LINKAGE_DOMAIN_TAG: &[u8] = b"vtc-invitation-subject-linkage/v1\0";

/// Verify a **subject-linkage proof**: the VIC subject (`subject`) signed
/// `TAG || vic_id || presenter` with a key under their DID, authorizing
/// `presenter` to redeem this specific invitation. Lets a holder redeem under a
/// different / freshly-minted DID without re-issuing the VIC (#1b), at the cost
/// of linking the two DIDs at this community.
///
/// The proof rides in the VP as
/// `subjectLinkage: { verificationMethod, signature }` (hex Ed25519).
async fn verify_subject_linkage(
    vp: &JsonValue,
    subject: &str,
    vic_id: &str,
    presenter: &str,
    resolver: &DidVmResolver,
) -> Result<(), AppError> {
    let linkage = vp
        .get("subjectLinkage")
        .and_then(JsonValue::as_object)
        .ok_or_else(|| {
            forbidden(format!(
                "invitation subject `{subject}` differs from the presenter `{presenter}` \
             and the VP carries no `subjectLinkage` proof"
            ))
        })?;
    let vm = linkage
        .get("verificationMethod")
        .and_then(JsonValue::as_str)
        .ok_or_else(|| forbidden("subjectLinkage is missing `verificationMethod`".into()))?;
    let signature_hex = linkage
        .get("signature")
        .and_then(JsonValue::as_str)
        .ok_or_else(|| forbidden("subjectLinkage is missing `signature`".into()))?;

    // The linkage MUST be signed by a key under the VIC subject — a key
    // controlled by some other DID cannot authorize a presenter.
    if vm.split('#').next().unwrap_or(vm) != subject {
        return Err(forbidden(format!(
            "subjectLinkage verificationMethod `{vm}` is not under the invitation subject `{subject}`"
        )));
    }

    let key = resolver.resolve_ed25519(vm).await?;
    let key: [u8; 32] = key
        .as_slice()
        .try_into()
        .map_err(|_| forbidden("subject-linkage key is not a 32-byte Ed25519 key".into()))?;
    let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&key)
        .map_err(|e| forbidden(format!("subject-linkage key is invalid: {e}")))?;
    let sig_bytes = hex::decode(signature_hex)
        .map_err(|e| forbidden(format!("subjectLinkage signature is not hex: {e}")))?;
    let signature = ed25519_dalek::Signature::from_slice(&sig_bytes)
        .map_err(|e| forbidden(format!("subjectLinkage signature is malformed: {e}")))?;

    // Signed payload: TAG || vic_id || NUL || presenter — binds the proof to
    // this exact invitation and presenter.
    let mut signed = SUBJECT_LINKAGE_DOMAIN_TAG.to_vec();
    signed.extend_from_slice(vic_id.as_bytes());
    signed.push(0);
    signed.extend_from_slice(presenter.as_bytes());

    use ed25519_dalek::Verifier;
    verifying_key
        .verify(&signed, &signature)
        .map_err(|_| forbidden("subjectLinkage signature did not verify".into()))
}

/// Pull the first `InvitationCredential` out of a VP's `verifiableCredential`
/// array. Object-form VCs only (a bare JWT string VIC isn't supported on this
/// raw-VP path — VICs are Data-Integrity VCs).
fn extract_invitation(vp: &JsonValue) -> Option<JsonValue> {
    vp.get("verifiableCredential")?
        .as_array()?
        .iter()
        .find(|vc| {
            vc.get("type")
                .and_then(JsonValue::as_array)
                .is_some_and(|types| {
                    types
                        .iter()
                        .any(|t| t.as_str() == Some(INVITATION_CREDENTIAL_TYPE))
                })
        })
        .cloned()
}

/// The testable core: verify one extracted VIC against injected resolver +
/// fetcher + trust registry. Split out so unit tests can drive it with stubs and
/// a pinned `now`, without a running `AppState`.
#[allow(clippy::too_many_arguments)]
async fn verify_invitation_inner(
    vic_json: &JsonValue,
    applicant_did: &str,
    own_did: Option<&str>,
    registry: Option<&dyn TrustRegistryClient>,
    resolver: &dyn VerificationMethodResolver,
    fetcher: &dyn StatusListFetcher,
    now: DateTime<Utc>,
    // True when the presenter is not the VIC subject but a verified subject
    // linkage proof authorized them (the dual-control / fresh-DID path, #1b).
    linkage_authorized: bool,
) -> Result<VerifiedInvitation, AppError> {
    let vic: VerifiableCredential = serde_json::from_value(vic_json.clone())
        .map_err(|e| forbidden(format!("invitation is not a Verifiable Credential: {e}")))?;

    // Type guard (defensive — extract_invitation already matched on it).
    if !vic.types.iter().any(|t| t == INVITATION_CREDENTIAL_TYPE) {
        return Err(forbidden(
            "credential is not an InvitationCredential".into(),
        ));
    }

    let id = vic_json
        .get("id")
        .and_then(JsonValue::as_str)
        .ok_or_else(|| forbidden("invitation has no top-level `id`".into()))?
        .to_string();
    let issuer = vic.issuer.id().to_string();
    let subject = subject_id(&vic)?;

    // 1. Holder-binding: the presenter must be the DID the VIC was minted for,
    // OR a verified subject-linkage proof authorized this presenter (#1b — the
    // invited DID consented to a different/fresh presenting DID).
    if subject != applicant_did && !linkage_authorized {
        return Err(forbidden(format!(
            "invitation is bound to `{subject}`, not the applicant `{applicant_did}` \
             (and no valid subject-linkage proof was provided)"
        )));
    }

    // 2. Temporal validity (cheap; before any network call).
    let valid_until = parse_required_time(vic.valid_until.as_deref(), "validUntil")?;
    if let Some(vf) = vic.valid_from.as_deref() {
        let valid_from = parse_required_time(Some(vf), "validFrom")?;
        if valid_from > now {
            return Err(forbidden(format!(
                "invitation validFrom {valid_from} is in the future"
            )));
        }
    }
    if valid_until <= now {
        return Err(forbidden(format!("invitation expired at {valid_until}")));
    }

    // 3. Issuer Data-Integrity proof: the verificationMethod must sit under the
    //    issuer, and the signature must verify against the resolved key.
    verify_invitation_proof(vic_json, &issuer, resolver).await?;

    // 4. Revocation: a VIC always carries a credentialStatus (issuance burns a
    //    revocation slot). The bit must be clear; an unresolvable status fails
    //    closed — we will not auto-admit on an invitation we can't check.
    check_not_revoked(&vic, &issuer, fetcher).await?;

    // 5. Issuer trust (a policy fact, not an abort): community self-issued (M1)
    //    or registry-recognised third party (M2).
    let issuer_trusted = invitation_issuer_trusted(own_did, registry, &issuer).await;

    let scopes = extract_scopes(&vic);

    Ok(VerifiedInvitation {
        id,
        issuer,
        subject,
        issuer_trusted,
        scopes,
        valid_until,
    })
}

/// Verify the VIC's issuer Data-Integrity proof — mirrors
/// `recognition::verify::verify_proof`: parse the proof, bind its
/// `verificationMethod` to the issuer, then let the library resolve the key +
/// check the signature over the proof-stripped document.
async fn verify_invitation_proof(
    vic_json: &JsonValue,
    issuer_did: &str,
    resolver: &dyn VerificationMethodResolver,
) -> Result<(), AppError> {
    let proof_value = vic_json
        .get("proof")
        .ok_or_else(|| forbidden("invitation has no proof".into()))?;
    let proof: DataIntegrityProof = serde_json::from_value(proof_value.clone())
        .map_err(|e| forbidden(format!("invitation proof did not parse: {e}")))?;
    let vm = proof_value
        .get("verificationMethod")
        .and_then(JsonValue::as_str)
        .ok_or_else(|| forbidden("invitation proof missing verificationMethod".into()))?;
    check_issuer_binding(vm, issuer_did).map_err(|e| forbidden(e.to_string()))?;

    let mut unsigned = vic_json.clone();
    unsigned
        .as_object_mut()
        .ok_or_else(|| forbidden("invitation is not a JSON object".into()))?
        .remove("proof");

    proof
        .verify(&unsigned, resolver, VerifyOptions::new())
        .await
        .map_err(|e| forbidden(format!("invitation signature did not verify: {e}")))?;
    Ok(())
}

/// Fail-closed revocation check. A missing `credentialStatus` is treated as
/// "not revocable" (the issuer opted out), matching the recognition path; a
/// present-but-set or unresolvable status is a hard fail.
async fn check_not_revoked(
    vic: &VerifiableCredential,
    issuer_did: &str,
    fetcher: &dyn StatusListFetcher,
) -> Result<(), AppError> {
    let Some(status) = vic.credential_status.as_ref() else {
        return Ok(());
    };
    let url = status.status_list_credential.as_deref().ok_or_else(|| {
        forbidden("invitation credentialStatus has no statusListCredential URL".into())
    })?;
    let index_str = status
        .status_list_index
        .as_deref()
        .ok_or_else(|| forbidden("invitation credentialStatus has no statusListIndex".into()))?;
    let index: usize = index_str
        .parse()
        .map_err(|e| forbidden(format!("invitation statusListIndex {index_str}: {e}")))?;

    match fetcher.check_status_bit(url, index, Some(issuer_did)).await {
        Ok(false) => Ok(()),
        Ok(true) => Err(forbidden("invitation has been revoked".into())),
        Err(e) => {
            warn!(url = %url, error = %e, "invitation status list did not resolve — failing closed");
            Err(forbidden(
                "invitation revocation status could not be verified".into(),
            ))
        }
    }
}

/// Whether the community trusts `issuer_did` to issue invitations. The
/// community's own DID is always trusted (M1 self-issued). Any other issuer is
/// resolved via TRQP `recognise` (M2 third-party). Fail-soft: a flaky registry
/// yields `false` (untrusted) + a warning rather than erroring the whole join —
/// the policy decides over the `false`.
async fn invitation_issuer_trusted(
    own_did: Option<&str>,
    registry: Option<&dyn TrustRegistryClient>,
    issuer_did: &str,
) -> bool {
    if own_did == Some(issuer_did) {
        return true;
    }
    let Some(registry) = registry else {
        return false;
    };
    match registry.recognise(issuer_did).await {
        Ok(trusted) => trusted,
        Err(e) => {
            warn!(
                issuer = %issuer_did,
                error = %e,
                "trust-registry recognise failed for invitation issuer — treating as untrusted"
            );
            false
        }
    }
}

/// `credentialSubject.id` of the (first) subject.
fn subject_id(vic: &VerifiableCredential) -> Result<String, AppError> {
    let subject_map = match &vic.credential_subject {
        SubjectValue::Single(m) => m.clone(),
        SubjectValue::Multiple(v) => v
            .first()
            .cloned()
            .ok_or_else(|| forbidden("invitation credentialSubject is empty".into()))?,
    };
    subject_map
        .get("id")
        .and_then(|v| v.as_str())
        .map(str::to_string)
        .ok_or_else(|| forbidden("invitation credentialSubject.id missing".into()))
}

/// Optional `credentialSubject.scopes` string array (forward-compat; the
/// catalog VIC subject is `{id}` today, so this is usually empty).
fn extract_scopes(vic: &VerifiableCredential) -> Vec<String> {
    let subject_map = match &vic.credential_subject {
        SubjectValue::Single(m) => m,
        SubjectValue::Multiple(v) => match v.first() {
            Some(m) => m,
            None => return Vec::new(),
        },
    };
    subject_map
        .get("scopes")
        .and_then(JsonValue::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(|s| s.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

fn parse_required_time(raw: Option<&str>, field: &str) -> Result<DateTime<Utc>, AppError> {
    let raw = raw.ok_or_else(|| forbidden(format!("invitation has no {field}")))?;
    DateTime::parse_from_rfc3339(raw)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|e| forbidden(format!("invitation {field} `{raw}`: {e}")))
}

/// Authenticity failures are `Forbidden` (the evidence didn't check out), never
/// `Validation` — the request was well-formed, its cryptographic claims false.
fn forbidden(msg: String) -> AppError {
    AppError::Forbidden(format!("invitation verification failed: {msg}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credentials::dtg;
    use crate::credentials::signer::LocalSigner;
    use crate::credentials::vmc::CredentialStatusRef;
    use crate::recognition::{RecognitionError, StatusListFetcher};
    use async_trait::async_trait;
    use chrono::Duration;
    use ed25519_dalek::SigningKey;

    const APPLICANT_SEED: [u8; 32] = [0x11; 32];
    const ISSUER_SEED: [u8; 32] = [0x22; 32];
    const OTHER_SEED: [u8; 32] = [0x33; 32];

    /// A `did:key` for a seed (so [`DidVmResolver`] resolves it locally, no I/O).
    /// Used for subject DIDs that don't sign in these tests.
    fn did_key(seed: &[u8; 32]) -> String {
        let sk = SigningKey::from_bytes(seed);
        affinidi_crypto::did_key::ed25519_pub_to_did_key(&sk.verifying_key().to_bytes())
    }

    /// A `LocalSigner` whose issuer DID is the `did:key` encoding *its own*
    /// public key, so the proof's `verificationMethod` resolves (via
    /// [`DidVmResolver`]) to exactly the signing key — independent of how the
    /// secret derives its pubkey from the seed.
    fn signer(seed: &[u8; 32]) -> LocalSigner {
        let tmp = LocalSigner::from_ed25519_seed("did:key:placeholder".into(), seed);
        let pub_bytes: [u8; 32] = tmp
            .public_bytes()
            .try_into()
            .expect("ed25519 pub is 32 bytes");
        let dk = affinidi_crypto::did_key::ed25519_pub_to_did_key(&pub_bytes);
        LocalSigner::from_ed25519_seed(dk, seed)
    }

    /// Issue a VIC to `subject`, optionally revocable, valid for `validity`.
    async fn issue_vic(
        signer: &LocalSigner,
        subject: &str,
        status: Option<&CredentialStatusRef>,
        validity: Duration,
    ) -> JsonValue {
        dtg::issue_invitation(
            signer,
            subject,
            Some(&format!("urn:uuid:{}", uuid::Uuid::new_v4())),
            status,
            validity,
            &[],
        )
        .await
        .expect("issue VIC")
    }

    struct StubFetcher {
        revoked: bool,
    }
    #[async_trait]
    impl StatusListFetcher for StubFetcher {
        async fn check_status_bit(
            &self,
            _url: &str,
            _index: usize,
            _expected_issuer: Option<&str>,
        ) -> Result<bool, RecognitionError> {
            Ok(self.revoked)
        }
    }

    /// A fetcher that always errors — exercises the fail-closed path.
    struct ErrFetcher;
    #[async_trait]
    impl StatusListFetcher for ErrFetcher {
        async fn check_status_bit(
            &self,
            _url: &str,
            _index: usize,
            _expected_issuer: Option<&str>,
        ) -> Result<bool, RecognitionError> {
            Err(RecognitionError::StatusListFailed("boom".into()))
        }
    }

    fn resolver() -> DidVmResolver {
        DidVmResolver::new(None) // did:key resolves locally
    }

    #[test]
    fn extract_invitation_finds_the_vic() {
        let vp = serde_json::json!({
            "verifiableCredential": [
                { "type": ["VerifiableCredential", "EmailCredential"] },
                { "type": ["VerifiableCredential", "InvitationCredential"], "id": "x" },
            ]
        });
        let vic = extract_invitation(&vp).expect("finds the VIC");
        assert_eq!(vic["id"], "x");
    }

    #[test]
    fn extract_invitation_absent_is_none() {
        let vp = serde_json::json!({
            "verifiableCredential": [{ "type": ["VerifiableCredential", "EmailCredential"] }]
        });
        assert!(extract_invitation(&vp).is_none());
        assert!(extract_invitation(&serde_json::json!({})).is_none());
    }

    #[tokio::test]
    async fn self_issued_vic_verifies_and_is_trusted() {
        let issuer = signer(&ISSUER_SEED);
        let applicant = did_key(&APPLICANT_SEED);
        let vic = issue_vic(&issuer, &applicant, None, Duration::days(7)).await;

        let v = verify_invitation_inner(
            &vic,
            &applicant,
            Some(issuer.issuer_did()), // own_did == issuer → M1 self-trust
            None,
            &resolver(),
            &StubFetcher { revoked: false },
            Utc::now(),
            false,
        )
        .await
        .expect("self-issued VIC verifies");

        assert_eq!(v.issuer, issuer.issuer_did());
        assert_eq!(v.subject, applicant);
        assert!(v.issuer_trusted, "community self-issued is trusted");
        let fact = v.to_fact(false);
        assert!(fact.verified && fact.issuer_trusted && !fact.consumed);
    }

    #[tokio::test]
    async fn third_party_issuer_is_untrusted_without_registry() {
        // A genuinely-signed VIC from an issuer that is NOT the community and not
        // registry-recognised verifies cryptographically but is untrusted — the
        // policy (has_valid_invitation) will refuse it.
        let issuer = signer(&ISSUER_SEED);
        let applicant = did_key(&APPLICANT_SEED);
        let vic = issue_vic(&issuer, &applicant, None, Duration::days(7)).await;

        let v = verify_invitation_inner(
            &vic,
            &applicant,
            Some(&did_key(&OTHER_SEED)), // own_did != issuer
            None,                        // no registry → untrusted
            &resolver(),
            &StubFetcher { revoked: false },
            Utc::now(),
            false,
        )
        .await
        .expect("verifies cryptographically");
        assert!(
            !v.issuer_trusted,
            "3rd-party issuer untrusted without registry"
        );
    }

    #[tokio::test]
    async fn third_party_issuer_trusted_via_registry() {
        // M2: a VIC from a third-party issuer the community recognises (in its
        // trust registry / recognition graph) is trusted — so the default policy
        // auto-admits exactly as for a self-issued invite.
        use crate::registry::{MockRegistryClient, TrustRegistryClient};

        let issuer = signer(&ISSUER_SEED);
        let applicant = did_key(&APPLICANT_SEED);
        let vic = issue_vic(&issuer, &applicant, None, Duration::days(7)).await;

        let registry = MockRegistryClient::new();
        registry.set_recognised(issuer.issuer_did()).await;
        let registry: &dyn TrustRegistryClient = &registry;

        let v = verify_invitation_inner(
            &vic,
            &applicant,
            Some(&did_key(&OTHER_SEED)), // own_did != issuer (a genuine third party)
            Some(registry),              // …but the registry recognises the issuer
            &resolver(),
            &StubFetcher { revoked: false },
            Utc::now(),
            false,
        )
        .await
        .expect("verifies cryptographically");
        assert!(
            v.issuer_trusted,
            "a registry-recognised 3rd-party issuer is trusted (M2)"
        );
    }

    #[tokio::test]
    async fn rejects_wrong_subject_binding() {
        let issuer = signer(&ISSUER_SEED);
        let vic = issue_vic(&issuer, &did_key(&APPLICANT_SEED), None, Duration::days(7)).await;
        // A different applicant presents a VIC minted for someone else.
        let err = verify_invitation_inner(
            &vic,
            &did_key(&OTHER_SEED),
            Some(issuer.issuer_did()),
            None,
            &resolver(),
            &StubFetcher { revoked: false },
            Utc::now(),
            false,
        )
        .await
        .expect_err("wrong subject must fail");
        assert!(matches!(err, AppError::Forbidden(_)), "{err:?}");
    }

    #[tokio::test]
    async fn rejects_expired_vic() {
        let issuer = signer(&ISSUER_SEED);
        let applicant = did_key(&APPLICANT_SEED);
        let vic = issue_vic(&issuer, &applicant, None, Duration::days(7)).await;
        // Evaluate "now" 8 days in the future → expired.
        let err = verify_invitation_inner(
            &vic,
            &applicant,
            Some(issuer.issuer_did()),
            None,
            &resolver(),
            &StubFetcher { revoked: false },
            Utc::now() + Duration::days(8),
            false,
        )
        .await
        .expect_err("expired VIC must fail");
        assert!(matches!(err, AppError::Forbidden(_)), "{err:?}");
    }

    #[tokio::test]
    async fn rejects_tampered_signature() {
        let issuer = signer(&ISSUER_SEED);
        let applicant = did_key(&APPLICANT_SEED);
        let mut vic = issue_vic(&issuer, &applicant, None, Duration::days(7)).await;
        // Tamper with a signed field after signing → proof must fail.
        vic["credentialSubject"]["id"] = serde_json::json!(applicant); // keep subject
        vic["validUntil"] = serde_json::json!("2099-01-01T00:00:00Z"); // covered by proof
        let err = verify_invitation_inner(
            &vic,
            &applicant,
            Some(issuer.issuer_did()),
            None,
            &resolver(),
            &StubFetcher { revoked: false },
            Utc::now(),
            false,
        )
        .await
        .expect_err("tampered VIC must fail");
        assert!(matches!(err, AppError::Forbidden(_)), "{err:?}");
    }

    #[tokio::test]
    async fn rejects_revoked_vic() {
        let issuer = signer(&ISSUER_SEED);
        let applicant = did_key(&APPLICANT_SEED);
        let status = CredentialStatusRef::revocation("https://vtc.example/status/revocation", 7);
        let vic = issue_vic(&issuer, &applicant, Some(&status), Duration::days(7)).await;
        let err = verify_invitation_inner(
            &vic,
            &applicant,
            Some(issuer.issuer_did()),
            None,
            &resolver(),
            &StubFetcher { revoked: true },
            Utc::now(),
            false,
        )
        .await
        .expect_err("revoked VIC must fail");
        assert!(matches!(err, AppError::Forbidden(_)), "{err:?}");
    }

    #[tokio::test]
    async fn unresolvable_status_fails_closed() {
        let issuer = signer(&ISSUER_SEED);
        let applicant = did_key(&APPLICANT_SEED);
        let status = CredentialStatusRef::revocation("https://vtc.example/status/revocation", 7);
        let vic = issue_vic(&issuer, &applicant, Some(&status), Duration::days(7)).await;
        let err = verify_invitation_inner(
            &vic,
            &applicant,
            Some(issuer.issuer_did()),
            None,
            &resolver(),
            &ErrFetcher,
            Utc::now(),
            false,
        )
        .await
        .expect_err("unresolvable status must fail closed");
        assert!(matches!(err, AppError::Forbidden(_)), "{err:?}");
    }

    // ── #1b subject-linkage proof ─────────────────────────────────────────

    /// Build a `subjectLinkage` proof: the VIC subject (`a_seed`) signs
    /// `TAG || vic_id || NUL || presenter`. Returns `(subject_did, vp)`.
    fn linkage_vp(a_seed: &[u8; 32], vic_id: &str, presenter: &str) -> (String, JsonValue) {
        use ed25519_dalek::{Signer, SigningKey};
        let sk = SigningKey::from_bytes(a_seed);
        let a_did =
            affinidi_crypto::did_key::ed25519_pub_to_did_key(&sk.verifying_key().to_bytes());
        let mut signed = SUBJECT_LINKAGE_DOMAIN_TAG.to_vec();
        signed.extend_from_slice(vic_id.as_bytes());
        signed.push(0);
        signed.extend_from_slice(presenter.as_bytes());
        let sig = sk.sign(&signed);
        let vp = serde_json::json!({
            "subjectLinkage": {
                "verificationMethod": a_did,
                "signature": hex::encode(sig.to_bytes()),
            }
        });
        (a_did, vp)
    }

    #[tokio::test]
    async fn subject_linkage_authorizes_a_different_presenter() {
        let presenter = did_key(&OTHER_SEED);
        let (a_did, vp) = linkage_vp(&APPLICANT_SEED, "urn:uuid:vic-1", &presenter);
        verify_subject_linkage(&vp, &a_did, "urn:uuid:vic-1", &presenter, &resolver())
            .await
            .expect("a valid subject-linkage proof authorizes the presenter");
    }

    #[tokio::test]
    async fn subject_linkage_rejects_a_different_presenter_than_signed() {
        // The proof binds OUTSIDER, but someone else tries to use it.
        let signed_presenter = did_key(&OTHER_SEED);
        let (a_did, vp) = linkage_vp(&APPLICANT_SEED, "urn:uuid:vic-1", &signed_presenter);
        let err = verify_subject_linkage(
            &vp,
            &a_did,
            "urn:uuid:vic-1",
            "did:key:zSomeoneElse",
            &resolver(),
        )
        .await
        .expect_err("a linkage bound to another presenter must not verify");
        assert!(matches!(err, AppError::Forbidden(_)), "{err:?}");
    }

    #[tokio::test]
    async fn subject_linkage_absent_is_rejected() {
        let err = verify_subject_linkage(
            &serde_json::json!({}),
            "did:key:zSubject",
            "urn:uuid:vic-1",
            "did:key:zPresenter",
            &resolver(),
        )
        .await
        .expect_err("missing subjectLinkage must fail");
        assert!(matches!(err, AppError::Forbidden(_)), "{err:?}");
    }
}
