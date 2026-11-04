//! What a service supplies: [`OobHost`].
//!
//! The handlers ([`crate::tasks`]) own the check order, the record and every
//! refusal the family defines. The host owns its identity, its keys, its
//! gates and what an approval turns into. Every host method is called at a
//! fixed point in that order, documented on the method, so a host cannot
//! move a check by implementing it.

use std::net::IpAddr;

use serde_json::Value;
use trust_tasks_rs::{FreshnessPolicy, TrustTask};
use vti_common::error::AppError;
use vti_common::store::KeyspaceHandle;
use vti_trust_task_server::{AcceptedIdStore, TrustTaskOutcome};

use crate::audience::Audience;
use crate::http::HttpContext;
use crate::record::OobRequest;
use crate::types::GRANT_TYPE;

/// Where in the flow [`OobHost::gate`] is asked about the identity that is
/// signing in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Gate {
    /// `prove`, step 3: the carried `identify`'s issuer, **before** its proof
    /// is verified or its DID resolved (T15). Answer from local records only:
    /// a DID the service does not know at all is refused here, unresolved.
    /// Nothing about the refusal reaches the wallet beyond the vague
    /// `notAuthorized`, so [`Eligibility::RefusedTelling`] is read as
    /// [`Eligibility::Refused`] at this gate.
    Known,
    /// `prove`, step 5a: after the identify's proof verified and the number
    /// matched. The DID has proved it is the approver's, so a refusal here
    /// may say why ([`Eligibility::RefusedTelling`]).
    Proved,
    /// `respond`, step 5: an approving grant's issuer, again, now. Not asked
    /// for a declining grant.
    Decided,
}

/// A gate's answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Eligibility {
    /// Let the sign-in through this gate.
    Eligible,
    /// Decline the request with the family's vague `notAuthorized` (T15).
    /// `reason` reaches the audit row and the service log only.
    Refused { reason: String },
    /// Decline the request and say why, to the wallet now and to the starter
    /// at `redeem` (`details.reason`). Only for a reason the identity has
    /// already proved it holds ([`Gate::Proved`], [`Gate::Decided`]), never
    /// one that tells a bystander anything about someone else's DID (T15).
    RefusedTelling {
        /// For the audit row and the service log.
        reason: String,
        /// The `details.reason` both sides receive, recorded on the request.
        told: String,
        /// The message the wallet receives.
        message: String,
    },
}

/// One audited step of a sign-in. The host writes it to its audit sink;
/// `record.audience` says which audience it was for.
#[derive(Debug)]
pub struct SignInEvent<'a, A: Audience> {
    /// The key or DID that took the step.
    pub actor: &'a str,
    /// `requested`, `claimed`, `proved`, `approved`, `declined`, `redeemed`,
    /// `cancelled`, `expired` or `proofFailed`.
    pub stage: &'a str,
    pub record: &'a OobRequest<A>,
    /// The approver's DID, once known.
    pub member: Option<&'a str>,
    pub reason: Option<&'a str>,
    /// The signed grant, on `approved` and `declined`.
    pub grant: Option<Value>,
}

/// An approved request `redeem` has just consumed (`approved → consumed`,
/// once), handed to [`OobHost::complete`].
///
/// By the time a host sees this, the crate has checked that the holder of
/// `K_b` sent the `redeem`, that the stored audience is the one signed into
/// step 1 (so covered by the grant's `contextDigest`, T19), and that the
/// grant's `sessionEndsAt` has not passed. The request is spent whatever the
/// host answers.
#[derive(Debug)]
pub struct Approved<'a, A: Audience> {
    /// The `redeem` document.
    pub doc: &'a TrustTask<Value>,
    /// The HTTPS connection it arrived on: the place to set cookies, if the
    /// host issues any.
    pub http: &'a HttpContext,
    /// The consumed record. `record.start_key` is `K_b`.
    pub record: &'a OobRequest<A>,
    /// The DID that signed the grant.
    pub subject: &'a str,
    /// The grant's `sessionEndsAt`, epoch seconds, in the future. Whatever
    /// the host issues must end by it.
    pub not_after: u64,
}

impl<A: Audience> Approved<'_, A> {
    /// The `signingScope` of the approved grant, when it carries one —
    /// `respond` already held it equal to what step 2 offered. `None` for a
    /// grant with none, or an empty one.
    pub fn signing_scope(&self) -> Option<Vec<String>> {
        let grant = self.record.grant.as_ref()?;
        if grant.get("type").and_then(Value::as_str) != Some(GRANT_TYPE) {
            return None;
        }
        let scope: Vec<String> = grant
            .get("payload")?
            .get("signingScope")?
            .as_array()?
            .iter()
            .filter_map(|f| f.as_str().map(str::to_string))
            .collect();
        (!scope.is_empty()).then_some(scope)
    }

    /// The grant's `id`: the authority anything the host arms is recorded
    /// under.
    pub fn grant_id(&self) -> Option<String> {
        self.record
            .grant
            .as_ref()
            .and_then(|g| g.get("id"))
            .and_then(Value::as_str)
            .map(str::to_string)
    }
}

/// What [`OobHost::complete`] made of an approval.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Completion {
    /// Issued. The crate audits `redeemed` and answers `redeem` with
    /// `subject`, this `displayName`, `sessionEndsAt` (from `ends_at`), the
    /// `amr` ([`crate::AMR`]) and the audience's `ext`.
    Issued {
        display_name: String,
        /// When what was issued ends, epoch seconds: no later than
        /// [`Approved::not_after`].
        ends_at: u64,
    },
    /// Refused with the family's vague `notAuthorized`: the subject no longer
    /// qualifies, and is not told why (T18).
    NotAuthorized,
    /// Refused as `redeem`'s `declined`, with `details.reason: told` and the
    /// message [`OobHost::told_message`] gives. The host audits it, if it
    /// should be.
    Declined { told: String },
}

/// The wire messages that name the host's own surface. Every other message
/// is the family's own.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OobMessages {
    /// `request` off the HTTPS door.
    pub request_https_only: &'static str,
    /// `request` from an origin other than the service's own (T19).
    pub request_wrong_origin: &'static str,
    /// `redeem` off the HTTPS door.
    pub redeem_https_only: &'static str,
    /// `request` before the service has a DID.
    pub not_set_up: &'static str,
}

impl Default for OobMessages {
    fn default() -> Self {
        Self {
            request_https_only: "auth/oob/request is accepted only over HTTPS",
            request_wrong_origin: "auth/oob/request is accepted only from this service's own origin",
            redeem_https_only: "auth/oob/redeem is served only over HTTPS",
            not_set_up: "this service has not finished setting up",
        }
    }
}

/// A service that approves browser keys with `auth/oob/*`.
#[async_trait::async_trait]
pub trait OobHost: Send + Sync {
    /// What a request may ask for, and what each one stores and signs.
    type Audience: Audience;

    /// The keyspace the request rows (`oob_req:*`) live in. The host sweeps
    /// it with [`crate::sweep`].
    fn records(&self) -> &KeyspaceHandle;

    /// This service's DID: the `recipient` every carried document must name,
    /// and `service.did` in step 1. `None` while it has none: `request` is
    /// then refused as `unavailable`.
    async fn service_did(&self) -> Option<String>;

    /// The configured public URL, whose origin is the only one `request` is
    /// accepted from (T19). `None`: the same-origin call to the `Host` the
    /// request was sent to ([`crate::portal_origin`]).
    async fn public_url(&self) -> Option<String>;

    /// The name step 1 shows the wallet, if the service has a non-empty one.
    /// Without one the DID itself is shown (its first 128 characters).
    async fn service_name(&self) -> Option<String>;

    /// Where the starter is, from a local database only (base design §12.6),
    /// never a third-party call. `None` is shown as `"unknown"`, which the
    /// wallet treats as a warning.
    fn locate(&self, _address: IpAddr) -> Option<String> {
        None
    }

    /// Sign a response document in place as this service's attestation
    /// (`assertionMethod`): steps 1 and 2, and the `respond` and `cancel`
    /// answers. `Err` is the internal-error reason.
    async fn sign_step(&self, response: &mut Value) -> Result<(), String>;

    /// Verify a carried document's proof **as received**, made for
    /// `authentication` by its issuer (the `identify` inside `prove`, contract
    /// C5). Returns the proven signer DID.
    async fn verify_authentication(&self, received: &Value) -> Result<String, AppError>;

    /// Verify a carried document's proof **as received**, made for
    /// `assertionMethod` by a key its issuer lists there (the `grant` inside
    /// `respond`). Returns the proven signer DID.
    async fn verify_assertion(&self, received: &Value, type_uri: &str) -> Result<String, AppError>;

    /// The acceptance window carried documents are held to. The spine's
    /// default unless the host's own differs.
    fn freshness_policy(&self) -> FreshnessPolicy {
        vti_trust_task_server::default_freshness_policy()
    }

    /// The accepted-id record the spine keeps for outer documents: a carried
    /// document's own `id` is claimed in it too, so it cannot be replayed
    /// (T7).
    fn accepted_ids(&self) -> &dyn AcceptedIdStore;

    /// Whether `did` may go on signing in for `audience` at `gate`. Read from
    /// the live records each time, never from a session.
    async fn gate(
        &self,
        gate: Gate,
        audience: Self::Audience,
        did: &str,
    ) -> Result<Eligibility, AppError>;

    /// The message `redeem`'s `declined` carries for a request declined with
    /// `told` ([`Eligibility::RefusedTelling`], [`Completion::Declined`]).
    /// `None`: the generic "the sign-in was declined".
    fn told_message(&self, _told: &str) -> Option<String> {
        None
    }

    /// The task families step 2 offers to let `K_b` sign for as the approver
    /// (`auth/oob/prove/0.3` `signingScope`), fixed per audience as the
    /// specification requires. `None` offers none. Whatever the grant then
    /// carries is held equal to it at `respond`.
    fn signing_scope(&self, audience: Self::Audience) -> Option<Vec<String>>;

    /// Write one step to the audit sink. A failure is the host's to log; the
    /// step stands.
    async fn audit(&self, event: SignInEvent<'_, Self::Audience>);

    /// Turn a consumed approval into what this service issues for `K_b` —
    /// re-checking the subject now (T18) — and say how `redeem` answers.
    /// `Err` is rendered by [`OobHost::reject_app_error`].
    async fn complete(
        &self,
        approved: Approved<'_, Self::Audience>,
    ) -> Result<Completion, AppError>;

    /// Render an `AppError` as a refusal of `doc`.
    fn reject_app_error(&self, doc: &TrustTask<Value>, err: &AppError) -> TrustTaskOutcome {
        vti_trust_task_server::reject::app_error_to_reject(doc, err)
    }

    /// The wire messages that name this service's surface.
    fn messages(&self) -> OobMessages {
        OobMessages::default()
    }
}
