//! The receive pipeline every Trust Task document goes through.
//!
//! In order ([`Spine::receive`]):
//!
//! 1. **Size** ([`SizeGate`]), before anything in the body is parsed.
//! 2. **Parse** the envelope, keeping the received JSON verbatim for the proof.
//! 3. **Freshness**: SPEC §7.2 item 13 and VTI-OPS-024's acceptance window
//!    over `issuedAt`. Decided from the document alone, before any resolution.
//! 4. **Expiry and recipient binding**: §7.2 items 4 and 5, against
//!    [`SpineHooks::recipient`] (skipped while the service has no DID).
//! 5. **Spec policy**: the flag-driven rules the task's own specification
//!    declares (`proof`, `recipient`, `issuedAt` REQUIRED; audience binding),
//!    read from [`SpecPolicySource`], never from a list kept here.
//! 6. [`SpineHooks::before_proof`]: the service's own pre-verification gate.
//! 7. **Proof** ([`ProofVerifier`]) over the document as received, bound to
//!    the document's `issuer` (§4.7). [`SpineHooks::after_proof`] runs on the
//!    proven signer.
//! 8. **Sender binding**: over DIDComm and TSP every document must carry a
//!    proof, and its issuer must be the transport-reported sender
//!    (VTI-OPS-021/093).
//! 9. **Admission** ([`VerifiedAdmission`]) of the verified signer.
//! 10. **Duplicate-id record** ([`AcceptedIdStore`]), claimed before
//!     execution (§7.2 item 11, VTI-OPS-025…027).
//! 11. **Dispatch** ([`Dispatcher`]), then **sign** the answer
//!     ([`ResponseSigner`]) and settle the claim: record a success, release a
//!     failure.
//!
//! Every answer is signed, refusals included. None of these checks can be
//! relaxed by configuration: VTI-OPS-093 forbids a binding weakening a
//! document requirement on a transport property.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use axum::http::StatusCode;
use chrono::{DateTime, Utc};
use serde_json::Value;
use trust_tasks_rs::{FreshnessPolicy, RejectReason, SpecPolicy, TrustTask};

use crate::TrustTaskOutcome;
use crate::accepted::{Acceptance, AcceptedIdStore};
use crate::context::ArrivalCtx;
use crate::reject::{app_error_to_reject, body_parse_error_response, reject_with};
use crate::sign::{ResponseSigner, sign_response};
use crate::size::{SizeCharge, SizeGate, default_size_table};
use crate::verify::ProofVerifier;

/// A boxed, `Send` future — what a [`Dispatcher`] returns.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// The document requirements a task's published specification declares (SPEC
/// §7.2 items 5b, 7a, 8; §7.3 item 17), by Type URI.
///
/// A service answers from its own generated spec crate's schema index. `None`
/// means the service knows no specification for the URI; the dispatcher then
/// refuses an unrouted URI, so nothing is silently unchecked.
pub trait SpecPolicySource: Send + Sync {
    /// The policy `type_uri`'s specification declares.
    fn spec_policy_for(&self, type_uri: &str) -> Option<SpecPolicy>;
}

impl<F> SpecPolicySource for F
where
    F: Fn(&str) -> Option<SpecPolicy> + Send + Sync,
{
    fn spec_policy_for(&self, type_uri: &str) -> Option<SpecPolicy> {
        self(type_uri)
    }
}

/// A transport's say in whether a document whose proof has verified may go on
/// to execute — a per-signer rate limit, typically.
///
/// Asked once, after the proof has verified against the document's `issuer`
/// and before the duplicate-id record is claimed, so a refusal spends neither
/// the document's `id` nor any work past verification.
pub trait VerifiedAdmission: Sync {
    /// `false` refuses the document. The spine then stops and answers an empty
    /// `429` outcome, which the transport replaces with its own refusal.
    fn admit_verified(&self, signer: &str) -> bool;
}

/// The service's routing table: the `match type_uri` behind the spine.
pub trait Dispatcher: Send + Sync {
    /// Run the handler for `type_uri`. `ctx.verified_signer` is the proven
    /// signer, if the document carried a proof; `received` is the document
    /// exactly as it arrived (for a handler that must store or forward what its
    /// requester signed). An unrouted URI is the dispatcher's to refuse
    /// ([`crate::reject::unsupported_type_or_version`]).
    ///
    /// The future is boxed so the spine's frame does not hold every handler's
    /// future at once.
    fn dispatch<'a>(
        &'a self,
        ctx: &'a ArrivalCtx,
        doc: TrustTask<Value>,
        type_uri: &'a str,
        received: Arc<Value>,
    ) -> BoxFuture<'a, TrustTaskOutcome>;

    /// Whether a successful response to `type_uri` is recorded for a
    /// redelivery. `false` for a response carrying a bearer secret (an invite's
    /// claim code) or one that is meaningless to replay (a stream grant): the
    /// claim is then completed with no body, and a redelivery is answered
    /// `204`.
    fn records_response(&self, _type_uri: &str) -> bool {
        true
    }
}

/// The service-specific points in the pipeline.
#[async_trait::async_trait]
pub trait SpineHooks: Send + Sync {
    /// This service's DID — the `recipient` every document must name (§7.2
    /// item 5). `None` while the service has none (setup), which skips the
    /// binding.
    async fn recipient(&self) -> Option<String>;

    /// After the spec policy, before the proof is read: a refusal decided from
    /// the document alone, or work the verification depends on (refreshing a
    /// cached DID document). `Some` stops the pipeline with that answer.
    async fn before_proof(
        &self,
        _doc: &TrustTask<Value>,
        _type_uri: &str,
    ) -> Option<TrustTaskOutcome> {
        None
    }

    /// Once the proof has verified as `signer` and been bound to the issuer.
    /// `Some` stops the pipeline with that answer.
    async fn after_proof(
        &self,
        _doc: &TrustTask<Value>,
        _type_uri: &str,
        _signer: &str,
    ) -> Option<TrustTaskOutcome> {
        None
    }
}

/// The acceptance window every VTI node applies (VTI-OPS-024: ten minutes, 60
/// seconds of skew, or a stated `expiresAt` up to the thirty-day horizon of
/// VTI-OPS-028), **requiring `issuedAt`**.
///
/// Requiring `issuedAt` is what lets the horizon bound anything: a document
/// with only an `expiresAt` has no time of issue to count thirty days from, so
/// it would be accepted, and remembered, for as long as its producer chose.
pub fn default_freshness_policy() -> FreshnessPolicy {
    vti_common::trust_task::acceptance::VTI_ACCEPTANCE_WINDOW
        .freshness_policy()
        .requiring_issued_at()
}

/// How long the duplicate-id record for `doc` must be kept under `policy`
/// (**VTI-OPS-029**): the document's acceptance end, plus the clock-skew
/// tolerance — up to thirty days with a stated `expiresAt` (VTI-OPS-028). See
/// [`vti_common::trust_task::acceptance::retain_until`].
pub fn retain_until(
    policy: &FreshnessPolicy,
    doc: &TrustTask<Value>,
    now: DateTime<Utc>,
) -> Option<DateTime<Utc>> {
    vti_common::trust_task::acceptance::retain_until(policy, doc, now)
}

/// One service's pipeline: the pieces it injects, borrowed for one call (or
/// for as long as the service holds them).
pub struct Spine<'a> {
    size: &'a dyn SizeGate,
    freshness: FreshnessPolicy,
    policy: &'a dyn SpecPolicySource,
    verifier: &'a dyn ProofVerifier,
    hooks: &'a dyn SpineHooks,
    admission: Option<&'a dyn VerifiedAdmission>,
    accepted_ids: &'a dyn AcceptedIdStore,
    dispatcher: &'a dyn Dispatcher,
    signer: Option<&'a dyn ResponseSigner>,
}

static DEFAULT_SIZE: std::sync::LazyLock<crate::size::SizeTable<fn(&str) -> Option<usize>>> =
    std::sync::LazyLock::new(default_size_table);

impl<'a> Spine<'a> {
    /// A pipeline with the required pieces, every document held to
    /// [`crate::size::DEFAULT_MAX_DOCUMENT_BYTES`] and
    /// [`default_freshness_policy`], no admission and no response signer.
    pub fn new(
        policy: &'a dyn SpecPolicySource,
        verifier: &'a dyn ProofVerifier,
        hooks: &'a dyn SpineHooks,
        accepted_ids: &'a dyn AcceptedIdStore,
        dispatcher: &'a dyn Dispatcher,
    ) -> Self {
        Self {
            size: &*DEFAULT_SIZE,
            freshness: default_freshness_policy(),
            policy,
            verifier,
            hooks,
            admission: None,
            accepted_ids,
            dispatcher,
            signer: None,
        }
    }

    /// Hold documents to `size` (step 0).
    pub fn with_size_gate(mut self, size: &'a dyn SizeGate) -> Self {
        self.size = size;
        self
    }

    /// Apply `freshness` (step 2) and derive the record's retention from it.
    pub fn with_freshness(mut self, freshness: FreshnessPolicy) -> Self {
        self.freshness = freshness;
        self
    }

    /// Ask `admission` about each verified signer (step 3a').
    pub fn with_admission(mut self, admission: Option<&'a dyn VerifiedAdmission>) -> Self {
        self.admission = admission;
        self
    }

    /// Sign every answer with `signer`; `None` answers unsigned.
    pub fn with_signer(mut self, signer: Option<&'a dyn ResponseSigner>) -> Self {
        self.signer = signer;
        self
    }

    /// The freshness policy in force.
    pub fn freshness(&self) -> &FreshnessPolicy {
        &self.freshness
    }

    /// Run `body` through the whole pipeline and answer it, signed.
    pub async fn receive(&self, ctx: &ArrivalCtx, body: &[u8]) -> TrustTaskOutcome {
        let outcome = self.receive_unsigned(ctx, body).await;
        sign_response(self.signer, outcome).await
    }

    /// Sign `outcome` with this pipeline's signer — for an answer produced
    /// outside [`Self::receive`] (a parked operation executed later).
    pub async fn sign(&self, outcome: TrustTaskOutcome) -> TrustTaskOutcome {
        sign_response(self.signer, outcome).await
    }

    fn settle(&self, charge: Option<&SizeCharge>, verified: Option<&str>) {
        if let Some(charge) = charge {
            self.size.settle(charge, verified);
        }
    }

    /// [`Self::receive`] up to, and including, signing the dispatched answer;
    /// the early refusals come back unsigned.
    async fn receive_unsigned(&self, ctx: &ArrivalCtx, body: &[u8]) -> TrustTaskOutcome {
        // 0. Size, before anything in the body is parsed.
        let charge = match self.size.admit(body).await {
            Ok(charge) => charge,
            Err(refused) => return refused,
        };

        // 1. Parse the envelope, and keep the same bytes as JSON verbatim: the
        //    proof is verified over what was received, never over a
        //    re-serialisation (VTI-45).
        let doc: TrustTask<Value> = match serde_json::from_slice(body) {
            Ok(d) => d,
            Err(e) => return body_parse_error_response(&e.to_string()),
        };
        let received: Value = match serde_json::from_slice(body) {
            Ok(v) => v,
            Err(e) => return body_parse_error_response(&e.to_string()),
        };

        // One instant for every temporal decision: the acceptance window and
        // the record's retention are the same bound.
        let now = chrono::Utc::now();

        // 2. Timestamp bounds and the acceptance window.
        if let Err(reason) = doc.validate_freshness(now, &self.freshness) {
            return reject_with(&doc, reason);
        }

        // 2b. Expiry and the recipient binding.
        if let Some(me) = self.hooks.recipient().await
            && let Err(reason) = doc.validate_basic(now, &me)
        {
            return reject_with(&doc, reason);
        }

        let type_uri = doc.type_uri.for_routing().to_string();

        // 2c. The specification's own flag-driven rules, as it states them.
        if let Some(policy) = self.policy.spec_policy_for(&type_uri)
            && let Err(reason) = policy.enforce(&doc)
        {
            tracing::info!(
                type_uri,
                ?reason,
                "document refused by its specification's own policy"
            );
            return reject_with(&doc, reason);
        }

        // 2d. The service's own pre-verification gate.
        if let Some(refused) = self.hooks.before_proof(&doc, &type_uri).await {
            return refused;
        }

        // 3. The proof, against the document as received, bound to `issuer`.
        let verified_ctx;
        let ctx = if doc.proof.is_some() {
            match self.verifier.verify(&received, &type_uri).await {
                Ok(signer) => {
                    if doc.issuer.as_deref() != Some(signer.as_str()) {
                        tracing::warn!(
                            type_uri,
                            issuer = ?doc.issuer,
                            %signer,
                            "proof verifies under a key the document's issuer does not control"
                        );
                        self.settle(charge.as_ref(), Some(signer.as_str()));
                        return reject_with(
                            &doc,
                            RejectReason::ProofInvalid {
                                reason: "the proof's verificationMethod does not belong to the \
                                         document's issuer (SPEC §4.7)"
                                    .to_string(),
                            },
                        );
                    }
                    self.settle(charge.as_ref(), Some(signer.as_str()));
                    if let Some(refused) = self.hooks.after_proof(&doc, &type_uri, &signer).await {
                        return refused;
                    }
                    verified_ctx = ctx.with_verified_signer(Some(signer));
                    &verified_ctx
                }
                // A proof that is present and does not verify is always fatal.
                Err(e) => {
                    self.settle(charge.as_ref(), None);
                    return app_error_to_reject(&doc, &e);
                }
            }
        } else {
            // No proof: whatever `issuer` claimed was never checked.
            self.settle(charge.as_ref(), None);
            ctx
        };

        // 3a. Over DIDComm and TSP the transport-reported sender is a claim:
        //     the document must carry a proof, and its issuer must be the
        //     sender (compared by identity: a did:scid's `src` is not part of
        //     it, VTI-KEY-160).
        if ctx.transport.reports_sender() {
            let base = vta_sdk::did_scid::identity;
            match (ctx.verified_signer.as_deref(), ctx.sender_did.as_deref()) {
                (Some(signer), Some(sender)) if base(signer) == base(sender) => {}
                (None, _) => {
                    tracing::warn!(type_uri, "messaging document carries no proof — refused");
                    return reject_with(&doc, RejectReason::ProofRequired);
                }
                (Some(signer), sender) => {
                    tracing::warn!(
                        type_uri,
                        %signer,
                        sender = ?sender,
                        "messaging document is signed by a DID other than its sender — refused"
                    );
                    return reject_with(
                        &doc,
                        RejectReason::IdentityMismatch(
                            trust_tasks_rs::ConsistencyError::IssuerMismatch {
                                in_band: signer.to_string(),
                                transport: sender.unwrap_or_default().to_string(),
                            },
                        ),
                    );
                }
            }
        }

        // 3a'. The transport's admission of the verified signer — after
        //      verification, before the claim, so a refused document keeps its
        //      `id` for the retry.
        if let (Some(admit), Some(signer)) = (self.admission, ctx.verified_signer.as_deref())
            && !admit.admit_verified(signer)
        {
            return TrustTaskOutcome::empty(StatusCode::TOO_MANY_REQUESTS);
        }

        // 3b. The duplicate-execution record, claimed before dispatch and after
        //     the proof, so an unauthenticated flood cannot spend another
        //     sender's ids.
        let claim = match self
            .accepted_ids
            .claim(&doc, retain_until(&self.freshness, &doc, now), now)
            .await
        {
            Ok(Acceptance::Fresh(claim)) => claim,
            Ok(Acceptance::Duplicate {
                prior_response,
                in_flight,
            }) => {
                // "In no case is a duplicate reported as `taskFailed`."
                return match prior_response {
                    Some(v) => match serde_json::to_vec(&v) {
                        Ok(body) => TrustTaskOutcome {
                            status: StatusCode::OK,
                            body,
                        },
                        Err(e) => reject_with(
                            &doc,
                            RejectReason::InternalError {
                                reason: format!("prior response is unserialisable: {e}"),
                            },
                        ),
                    },
                    // Still running: `202` is the only honest code.
                    None if in_flight => TrustTaskOutcome::empty(StatusCode::ACCEPTED),
                    None => TrustTaskOutcome::empty(StatusCode::NO_CONTENT),
                };
            }
            Ok(Acceptance::Conflict) => {
                return reject_with(&doc, RejectReason::IdConflict);
            }
            // Fail closed.
            Err(e) => return reject_with(&doc, e.reject_reason()),
        };

        // 4. Dispatch, sign, and settle the claim: record a success (so a
        //    redelivery is answered with the result), release a failure (so a
        //    corrected resend under the same `id` is not a conflict).
        let outcome = self
            .dispatcher
            .dispatch(ctx, doc, &type_uri, Arc::new(received))
            .await;
        let outcome = sign_response(self.signer, outcome).await;

        if outcome.status.is_success() {
            let recorded = if self.dispatcher.records_response(&type_uri) {
                serde_json::from_slice::<Value>(&outcome.body).ok()
            } else {
                None
            };
            claim.completed(recorded.as_ref()).await;
        } else {
            claim.release().await;
        }

        outcome
    }
}
