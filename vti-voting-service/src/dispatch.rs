//! The dispatch core: one inbound `voting/*` document in, one signed answer out. No transport —
//! the HTTPS door ([`crate::http`]) and the mediator session ([`crate::messaging`]) hand it the
//! bytes as received and, where the transport proved one, the sender, and carry back what it
//! returns.
//!
//! Every document goes through the workspace's one receive pipeline,
//! [`vti_trust_task_server::Spine`] (#2576): size, freshness, expiry and recipient, the task's
//! own published policy (`vti_specs::schema_index::spec_policy_for` — which tasks need a proof,
//! a recipient and an `issuedAt` is the specification's to say, never a list kept here), the
//! proof bound to the issuer, the transport sender bound to the proof, the duplicate-id record
//! (VTI-OPS-025 … 029), and the signed answer. What is this service's own sits in the pieces it
//! hands the pipeline:
//!
//! - [`Gate`] (`SpineHooks::before_proof`): the issuer is the transport-proven sender, the task
//!   is one served here, and a cast is signed by a `did:key` (VTI-VOT-003) — all decided from
//!   the document alone, before anything is resolved.
//! - [`Verifier`]: which DIDs this service resolves on which binding ([`resolver_for`]), with a
//!   deadline on verification.
//! - [`freshness_for`]: the acceptance window, which a cast is not held to (VTI-VOT-004).
//! - [`Ballots`]: the routing table, over the ballot box.

use std::sync::Arc;

use axum::http::StatusCode;
use chrono::Utc;
use serde_json::Value;
use trust_tasks_rs::{FreshnessPolicy, RejectReason, StandardCode, TrustTask, TrustTaskCode};
use uuid::Uuid;
use vti_common::error::AppError;
use vti_trust_task_server::reject::{app_error_to_reject, reject_with, reject_with_code};
use vti_trust_task_server::{
    ArrivalCtx, BoxFuture, Dispatcher, ProofVerifier, ResponseSigner, SizeTable, SpineHooks,
    StoreAcceptedIds, TrustTaskOutcome,
};
use vti_voting::service::{Caller, ElectionVersion, Failure, VerifiedCast};

use crate::boxes::{Boxes, Shard};
use crate::config::CommunitiesConfig;
use crate::identity::Identity;

const SPEC: &str = "https://trusttasks.org/spec/";

/// The keyspace the accepted-document-id record lives in (VTI-OPS-025 … 029), under
/// `<data_dir>/store`. In the store rather than in the process: a document stating an
/// `expiresAt` is acceptable for up to thirty days (VTI-OPS-028), so a restart inside its
/// window is routine, and a record held only in memory would let its replay execute again.
pub const ACCEPTED_IDS_KEYSPACE: &str = "accepted_ids";

/// The largest document this service reads: axum's default body limit, which is what bounded
/// the HTTPS door before the pipeline did. A task whose specification declares a larger bound
/// is held to that instead.
const MAX_DOCUMENT_BYTES: usize = 2 * 1024 * 1024;

pub struct AppState {
    /// Every election, each under a lock of its own ([`crate::boxes`]): held only for what
    /// reads or changes that election, on a blocking thread, and a cast's costly checks run
    /// without it.
    pub ballot_boxes: Arc<Boxes>,
    pub identity: Identity,
    /// Resolves any DID method the operator configured — used only for a signer this service
    /// has a reason to know ([`resolver_for`]).
    pub resolver: vti_common::auth::TrustTaskVmResolver,
    /// Resolves `did:key` and `did:peer` only, with no I/O: every other signer on a binding that
    /// proves nobody.
    local_resolver: vti_common::auth::TrustTaskVmResolver,
    /// Whose elections are registered, and how many each may hold open.
    pub communities: CommunitiesConfig,
    /// One permit per cast being checked: the checks run on blocking threads, never more at
    /// once than the machine has cores.
    pub cast_checks: tokio::sync::Semaphore,
    /// Whether the identity's mediator session is connected right now, as its supervisor
    /// reports it; `None` without a provisioned identity (the HTTPS-only test `did:key`).
    pub messaging: Option<tokio::sync::watch::Receiver<bool>>,
    /// The accepted-document-id record, shared by every binding (VTI-OPS-027).
    accepted_ids: StoreAcceptedIds,
    /// The keyspace behind [`Self::accepted_ids`], for [`Self::sweep_accepted_ids`].
    accepted_ids_ks: vti_common::store::KeyspaceHandle,
}

impl AppState {
    /// `accepted_ids` is the keyspace the duplicate-id record is kept in
    /// ([`ACCEPTED_IDS_KEYSPACE`] in the service's store).
    #[must_use]
    pub fn new(
        ballot_boxes: Boxes,
        identity: Identity,
        resolver: vti_common::auth::TrustTaskVmResolver,
        communities: CommunitiesConfig,
        accepted_ids: vti_common::store::KeyspaceHandle,
    ) -> Self {
        let cores = std::thread::available_parallelism().map_or(1, std::num::NonZero::get);
        Self {
            ballot_boxes: Arc::new(ballot_boxes),
            identity,
            resolver,
            local_resolver: vti_common::auth::TrustTaskVmResolver::did_key_only(),
            communities,
            cast_checks: tokio::sync::Semaphore::new(cores),
            messaging: None,
            accepted_ids: StoreAcceptedIds::new(accepted_ids.clone()),
            accepted_ids_ks: accepted_ids,
        }
    }

    /// The state of a service that reaches its mediator: `connected` is
    /// [`vti_common::host_session::supervise_reporting`]'s report.
    #[must_use]
    pub fn with_messaging(mut self, connected: tokio::sync::watch::Receiver<bool>) -> Self {
        self.messaging = Some(connected);
        self
    }

    /// Drop every accepted-id record whose retention has passed, returning how many. Run on a
    /// timer: the record is read-through-expiry, so this only bounds the keyspace.
    ///
    /// # Errors
    /// If the keyspace cannot be read or written.
    pub async fn sweep_accepted_ids(&self) -> Result<usize, AppError> {
        vti_trust_task_server::accepted_store::sweep_expired(&self.accepted_ids_ks, Utc::now())
            .await
    }
}

impl std::fmt::Debug for AppState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppState")
            .field("did", &self.identity.did)
            .finish_non_exhaustive()
    }
}

/// One answer: the signed document, and the HTTP status the HTTPS binding gives it. `doc` is
/// `None` when nothing could be answered — bytes that are not a document, an answer that could
/// not be signed, or a duplicate with no recorded answer (`202` still running, `204` a read).
#[derive(Debug)]
pub struct Answer {
    pub status: StatusCode,
    pub doc: Option<Value>,
}

impl Answer {
    fn none(status: StatusCode) -> Self {
        Self { status, doc: None }
    }
}

/// What a request's type names: one of this service's tasks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Task {
    Register,
    Show,
    Close,
    Cancel,
    Cast,
    Head,
    Read,
    Inclusion,
    Consistency,
    Result,
    CastEncrypted,
    Enrol,
    Deal,
    Confirm,
    Justify,
    Decrypt,
    TrusteeStatus,
    Authorize,
}

/// A generated payload type's Type URI — the version pinned in `vti-specs-core`, never a
/// literal.
macro_rules! uri {
    ($($path:ident)::+) => {
        <vti_specs::voting::$($path)::+::Payload as trust_tasks_rs::Payload>::TYPE_URI
    };
}

/// **The routing table**: every Type URI this service serves, and the task it names. One
/// entry per served version, each named by its generated payload type, so a version is served
/// exactly when it is pinned and routed here — the slug and version are read off the URI
/// ([`slug_of`]) rather than kept in a second and third table.
///
/// `voting/election/{register,show}` at 0.4, whose manifest admits the `credential` roll
/// (voting/_shared/0.4, VTI-VOT-025), at 0.3, whose manifest admits a `textReleaseThreshold`
/// as low as 1 (voting/_shared/0.3, VTI-VOT-065), and at 0.2, whose manifest admits 10 or
/// more; `voting/board/read` at 0.2, whose lifecycle entries name their instants `…At`
/// (voting/_shared/0.2); every other task at 0.1.
#[allow(deprecated)] // older election versions stay served to communities that send them
const SERVED: &[(&str, Task, Option<ElectionVersion>)] = &[
    (
        uri!(election::register::v0_4),
        Task::Register,
        Some(ElectionVersion::V0_4),
    ),
    (
        uri!(election::register::v0_3),
        Task::Register,
        Some(ElectionVersion::V0_3),
    ),
    (
        uri!(election::register::v0_2),
        Task::Register,
        Some(ElectionVersion::V0_2),
    ),
    (
        uri!(election::show::v0_4),
        Task::Show,
        Some(ElectionVersion::V0_4),
    ),
    (
        uri!(election::show::v0_3),
        Task::Show,
        Some(ElectionVersion::V0_3),
    ),
    (
        uri!(election::show::v0_2),
        Task::Show,
        Some(ElectionVersion::V0_2),
    ),
    (uri!(election::close::v0_1), Task::Close, None),
    (uri!(election::cancel::v0_1), Task::Cancel, None),
    (uri!(ballot::cast::v0_1), Task::Cast, None),
    (
        uri!(ballot::cast_encrypted::v0_1),
        Task::CastEncrypted,
        None,
    ),
    (uri!(board::head::v0_1), Task::Head, None),
    (uri!(board::read::v0_2), Task::Read, None),
    (uri!(board::inclusion::v0_1), Task::Inclusion, None),
    (uri!(board::consistency::v0_1), Task::Consistency, None),
    (uri!(result::show::v0_1), Task::Result, None),
    (uri!(trustees::enrol::v0_1), Task::Enrol, None),
    (uri!(trustees::deal::v0_1), Task::Deal, None),
    (uri!(trustees::confirm::v0_1), Task::Confirm, None),
    (uri!(trustees::justify::v0_1), Task::Justify, None),
    (uri!(trustees::decrypt::v0_1), Task::Decrypt, None),
    (uri!(trustees::status::v0_1), Task::TrusteeStatus, None),
    (uri!(trustees::authorize::v0_1), Task::Authorize, None),
];

/// Every Type URI this service serves.
pub fn served_uris() -> impl Iterator<Item = &'static str> {
    SERVED.iter().map(|(uri, _, _)| *uri)
}

/// A Type URI without its `#request` fragment, which is optional (framework SPEC §4.4.1): the
/// generated payload types, and so every peer sending through them, use the bare form.
fn bare(type_uri: &str) -> &str {
    type_uri.strip_suffix("#request").unwrap_or(type_uri)
}

/// A Type URI's slug — `voting/ballot/cast` — read off the URI itself.
fn slug_of(type_uri: &str) -> Option<&str> {
    bare(type_uri)
        .strip_prefix(SPEC)
        .and_then(|path| path.rsplit_once('/'))
        .map(|(slug, _)| slug)
}

/// The task `type_uri` names, when it is a version served here.
fn served(type_uri: &str) -> Option<(Task, Option<ElectionVersion>)> {
    let bare = bare(type_uri);
    SERVED
        .iter()
        .find(|(uri, _, _)| *uri == bare)
        .map(|(_, task, version)| (*task, *version))
}

impl Task {
    /// Tasks a community or a trustee signs: consequential, and signed by a DID that keeps its
    /// key.
    fn consequential(self) -> bool {
        !matches!(
            self,
            Task::Show
                | Task::Head
                | Task::Read
                | Task::Inclusion
                | Task::Consistency
                | Task::Result
                | Task::TrusteeStatus
        )
    }
}

/// The acceptance window `task` is held to.
///
/// - A community's or a trustee's request: the window every VTI node applies (VTI-OPS-024),
///   `issuedAt` required, so a copy of one is not a standing instruction.
/// - A cast: never older than voting allows, but not this window. Its key is made for that one
///   cast and its sender may resend it until voting closes (VTI-VOT-003, VTI-VOT-004), and the
///   ballot box answers a resend as it did; `issuedAt` is still required and may not be in the
///   future. (A cast the voter's agent signs carries `expiresAt` = voting close, which bounds
///   it under either policy.)
/// - A read: no age bound, as before — it changes nothing, and its answer is what the board
///   holds now. A future-dated `issuedAt` is still refused.
fn freshness_for(task: Option<Task>) -> FreshnessPolicy {
    let window = vti_trust_task_server::default_freshness_policy();
    match task {
        Some(Task::Cast | Task::CastEncrypted) => {
            let mut cast = window;
            cast.max_age = None;
            cast
        }
        Some(t) if !t.consequential() => {
            let mut read = window;
            read.max_age = None;
            read.require_issued_at = false;
            read
        }
        _ => window,
    }
}

/// A received proof's `verificationMethod`: verifying it resolves the DID it names.
fn proof_method(received: &Value) -> Option<&str> {
    received
        .pointer("/proof/verificationMethod")
        .and_then(Value::as_str)
}

/// How long verifying one request's proof may take, resolution included. Past it the request
/// is refused `unavailable`, never left holding a connection on a slow DID host.
const PROOF_VERIFY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

/// A DID that carries its keys in itself: resolving it fetches nothing.
fn resolves_locally(did: &str) -> bool {
    did.starts_with("did:key:") || did.starts_with("did:peer:")
}

/// The election a request names: `(community, electionId)` — at the top of the payload, or in
/// a registration's manifest.
fn named_election(task: Task, payload: &Value) -> (&str, &str) {
    let at = if task == Task::Register {
        &payload["manifest"]
    } else {
        payload
    };
    (
        at["community"].as_str().unwrap_or_default(),
        at["electionId"].as_str().unwrap_or_default(),
    )
}

/// The resolver for `signer`'s proof, or `None` where this service will not resolve it.
///
/// A `did:key` or `did:peer` resolves with no I/O, on any binding. Any other DID needs a fetch
/// the sender chose, so it is resolved only where the service has a reason to know the signer:
/// a transport proved it (TSP, DIDComm — the sender is the issuer, checked by [`Gate`]); or, on
/// the HTTPS binding, which proves nobody, it is a community named in `[communities] allowed`,
/// or a party the election the request names, held here, names (its community, auditors or
/// trustees) — and then only where that election's parties are themselves vouched for
/// ([`parties_vouched_for`]). An open box (`allow_any`) names no community, so a stranger's
/// DID is never fetched on its HTTPS door.
async fn resolver_for<'a>(
    state: &'a AppState,
    transport_sender: Option<&str>,
    task: Task,
    signer: &str,
    payload: &Value,
) -> Option<&'a vti_common::auth::TrustTaskVmResolver> {
    if resolves_locally(signer) {
        return Some(&state.local_resolver);
    }
    if transport_sender.is_some() {
        return Some(&state.resolver);
    }
    if state.communities.allowed.iter().any(|c| c == signer) {
        return Some(&state.resolver);
    }
    let (community, election_id) = named_election(task, payload);
    if !parties_vouched_for(state, community) {
        return None;
    }
    let shard = state.ballot_boxes.get(community, election_id)?;
    let (community, election_id, signer) = (
        community.to_string(),
        election_id.to_string(),
        signer.to_string(),
    );
    // On a blocking thread: the election's lock may be held across a journal write.
    let named = tokio::task::spawn_blocking(move || {
        shard
            .lock()
            .is_ok_and(|bb| bb.names_party(&community, &election_id, &signer))
    })
    .await
    .unwrap_or(false);
    named.then_some(&state.resolver)
}

/// Whether the parties an election of `community` names may be resolved on the HTTPS door.
///
/// Its manifest's auditors and trustees are whoever the registering community wrote there, so
/// they are no better known than the community: one named in `[communities] allowed`, or one
/// whose own DID had to be resolved and proven to register — over TSP or DIDComm, because on
/// this door an unlisted community's DID is not resolved. A `did:key` or `did:peer` community
/// is neither: on an open box (`allow_any`) anyone can mint one and register over HTTPS, naming
/// any DID as an auditor or a trustee. Its parties sign with a `did:key` or `did:peer` on this
/// door, or reach the box over TSP or DIDComm.
fn parties_vouched_for(state: &AppState, community: &str) -> bool {
    state.communities.allowed.iter().any(|c| c == community) || !resolves_locally(community)
}

fn standard(code: StandardCode) -> TrustTaskCode {
    TrustTaskCode::Standard(code)
}

/// Answer one document, `body` exactly as received.
///
/// `transport_sender` is the sender a transport proved (TSP, DIDComm authcrypt); `None` on a
/// binding that proves nobody (HTTPS). Where there is one, the document must carry a proof and
/// its `issuer` must be the sender (framework §7.2 item 6, VTI-OPS-021, VTI-VOT-005) — a party
/// cannot relay another's request as its own.
pub async fn answer(state: &AppState, body: &[u8], transport_sender: Option<&str>) -> Answer {
    // Bytes that are not a document are answered with nothing: there is nobody to address a
    // signed refusal to.
    let Ok(doc) = serde_json::from_slice::<TrustTask<Value>>(body) else {
        return Answer::none(StatusCode::BAD_REQUEST);
    };
    // A reply or an error is never answered: answering an error with an error is the loop only
    // a rate limiter ends. This service sends no requests, so nothing waits for one either.
    let type_uri = doc.type_uri.to_string();
    if type_uri.ends_with("#response") || type_uri.contains("/trust-task-error/") {
        return Answer::none(StatusCode::BAD_REQUEST);
    }
    let task = served(&type_uri).map(|(task, _)| task);

    let ctx = match transport_sender {
        // TSP and DIDComm alike report a sender the pipeline binds to the proof.
        Some(sender) => ArrivalCtx::didcomm(sender.to_string()),
        None => ArrivalCtx::rest(),
    };
    let size = SizeTable::new(
        MAX_DOCUMENT_BYTES,
        vti_specs::schema_index::max_document_bytes_for,
    );
    let gate = Gate {
        state,
        transport_sender,
    };
    let verifier = Verifier {
        state,
        transport_sender,
    };
    let signer = AnswerSigner(&state.identity);
    let ballots = Ballots { state };
    // The policy of a task this service serves: an unserved type is `unsupportedType` or
    // `unsupportedVersion` ([`Gate`]), never refused for what another version requires.
    let policy = |type_uri: &str| {
        served(type_uri)
            .is_some()
            .then(|| vti_specs::schema_index::spec_policy_for(type_uri))
            .flatten()
    };
    let outcome =
        vti_trust_task_server::Spine::new(&policy, &verifier, &gate, &state.accepted_ids, &ballots)
            .with_size_gate(&size)
            .with_freshness(freshness_for(task))
            .with_signer(Some(&signer))
            // A public read (a board, a result) is asked unsigned over TSP or DIDComm as over HTTPS;
            // a task whose proof is REQUIRED is still refused unsigned on every transport.
            .accepting_unsigned_optional_over_messaging()
            .receive(&ctx, body)
            .await;

    if outcome.body.is_empty() {
        return Answer::none(outcome.status);
    }
    match serde_json::from_slice::<Value>(&outcome.body) {
        // An answer that could not be signed is not sent: an unsigned receipt or head is
        // evidence of nothing.
        Ok(doc) if doc.get("proof").is_some() => Answer {
            status: outcome.status,
            doc: Some(doc),
        },
        _ => {
            tracing::error!(status = %outcome.status, "an answer could not be signed; not sending it");
            Answer::none(outcome.status)
        }
    }
}

/// This service's own checks before any proof is read (`SpineHooks`), decided from the
/// document alone so nothing is resolved for a request refused anyway.
struct Gate<'a> {
    state: &'a AppState,
    transport_sender: Option<&'a str>,
}

#[async_trait::async_trait]
impl SpineHooks for Gate<'_> {
    async fn recipient(&self) -> Option<String> {
        Some(self.state.identity.did.clone())
    }

    async fn before_proof(
        &self,
        doc: &TrustTask<Value>,
        type_uri: &str,
    ) -> Option<TrustTaskOutcome> {
        // Over TSP or DIDComm the issuer must be the transport-proven sender. The pipeline
        // binds the proof to the sender too; refusing here first keeps a relayed request from
        // having anything resolved on its behalf.
        if let Some(sender) = self.transport_sender
            && doc.issuer.as_deref() != Some(sender)
        {
            return Some(reject_with_code(
                doc,
                standard(StandardCode::PermissionDenied),
                "the issuer is not the sender",
                None,
            ));
        }
        let Some((task, _)) = served(type_uri) else {
            let slug = slug_of(type_uri);
            let versions: Vec<&str> = SERVED
                .iter()
                .filter(|(uri, _, _)| slug.is_some() && slug_of(uri) == slug)
                .filter_map(|(uri, _, _)| uri.rsplit_once('/').map(|(_, v)| v))
                .collect();
            return Some(match slug {
                Some(slug) if !versions.is_empty() => reject_with_code(
                    doc,
                    standard(StandardCode::UnsupportedVersion),
                    format!(
                        "this ballot box serves {slug} at {} only",
                        versions.join(" and ")
                    ),
                    None,
                ),
                _ => reject_with_code(
                    doc,
                    standard(StandardCode::UnsupportedType),
                    "not a task this service serves",
                    None,
                ),
            });
        };
        // A cast is signed by a key made for it alone (VTI-VOT-003): a did:key, which resolves
        // without fetching anything an anonymous sender chose.
        if matches!(task, Task::Cast | Task::CastEncrypted)
            && !doc
                .issuer
                .as_deref()
                .is_some_and(|i| i.starts_with("did:key:"))
        {
            return Some(reject_with_code(
                doc,
                standard(StandardCode::ProofInvalid),
                "a cast is signed by a did:key made for it",
                None,
            ));
        }
        None
    }
}

/// The marker [`Verifier::verify`] answers a verification that ran out of time with, so
/// [`Verifier::refusal`] can answer it `unavailable`.
const VERIFY_TIMED_OUT: &str = "the signer's verification method did not resolve in time";

/// The proof, verified over the document as received — by a resolver this service is willing
/// to use for that signer on that binding ([`resolver_for`]), within [`PROOF_VERIFY_TIMEOUT`].
struct Verifier<'a> {
    state: &'a AppState,
    transport_sender: Option<&'a str>,
}

#[async_trait::async_trait]
impl ProofVerifier for Verifier<'_> {
    async fn verify(&self, received: &Value, type_uri: &str) -> Result<String, AppError> {
        // [`Gate`] refused anything not served before the proof was read.
        let Some((task, _)) = served(type_uri) else {
            return Err(AppError::Unauthorized(
                "not a task this service serves".into(),
            ));
        };
        // Verifying resolves the proof's verification method, so both checks come first: the
        // method must be the issuer's, and the issuer one this service will resolve.
        let Some(issuer) = received["issuer"].as_str().filter(|i| {
            proof_method(received)
                .is_some_and(|vm| vti_common::auth::check_issuer_binding(vm, i).is_ok())
        }) else {
            return Err(AppError::Unauthorized(
                "the proof is not the issuer's".into(),
            ));
        };
        let Some(resolver) = resolver_for(
            self.state,
            self.transport_sender,
            task,
            issuer,
            &received["payload"],
        )
        .await
        else {
            return Err(AppError::Forbidden(
                "on this binding a request is signed by a did:key, by a community this ballot \
                 box serves, or by a party the election it names lists"
                    .into(),
            ));
        };
        let verified = tokio::time::timeout(
            PROOF_VERIFY_TIMEOUT,
            vti_common::auth::verify_trust_task_proof_value(received, resolver),
        )
        .await;
        let Ok(verified) = verified else {
            tracing::debug!("a request proof did not verify in time");
            return Err(AppError::Internal(VERIFY_TIMED_OUT.into()));
        };
        verified.map_err(|e| {
            // The resolver's own words stay in the log: they can name what it fetched.
            tracing::debug!(error = %e, "a request proof did not verify");
            AppError::Unauthorized("the proof does not verify".into())
        })
    }

    /// `proofInvalid` for a proof that is not the issuer's or does not verify, `permissionDenied`
    /// for a signer this binding does not resolve, and `unavailable` for a verification that
    /// ran out of time — each with this service's own words, never the resolver's.
    fn refusal(&self, doc: &TrustTask<Value>, err: &AppError) -> TrustTaskOutcome {
        match err {
            AppError::Unauthorized(m) => {
                reject_with_code(doc, standard(StandardCode::ProofInvalid), m.clone(), None)
            }
            AppError::Forbidden(m) => reject_with_code(
                doc,
                standard(StandardCode::PermissionDenied),
                m.clone(),
                None,
            ),
            AppError::Internal(m) if m == VERIFY_TIMED_OUT => {
                reject_with_code(doc, standard(StandardCode::Unavailable), m.clone(), None)
            }
            other => app_error_to_reject(doc, other),
        }
    }
}

/// Signs every answer as this service's DID.
struct AnswerSigner<'a>(&'a Identity);

#[async_trait::async_trait]
impl ResponseSigner for AnswerSigner<'_> {
    async fn sign_response_document(&self, doc: &mut Value) -> Result<(), AppError> {
        let mut typed: TrustTask<Value> = serde_json::from_value(doc.clone())
            .map_err(|e| AppError::Internal(format!("an answer is not a document: {e}")))?;
        vta_sdk::trust_task_sign::sign_in_place_with(&mut typed, &self.0.key)
            .await
            .map_err(|e| AppError::Internal(format!("could not sign the answer: {e}")))?;
        *doc = serde_json::to_value(&typed)?;
        Ok(())
    }
}

/// The routing table behind the pipeline: [`SERVED`], over the ballot box.
struct Ballots<'a> {
    state: &'a AppState,
}

impl Dispatcher for Ballots<'_> {
    fn dispatch<'a>(
        &'a self,
        ctx: &'a ArrivalCtx,
        doc: TrustTask<Value>,
        type_uri: &'a str,
        received: Arc<Value>,
    ) -> BoxFuture<'a, TrustTaskOutcome> {
        Box::pin(run(
            self.state,
            ctx.verified_signer.clone(),
            doc,
            type_uri,
            received,
        ))
    }

    /// A consequential task's answer is kept, so its redelivery is answered with it — a cast's
    /// receipt included. A read's is not: its answer is the board as it stands, and a replay
    /// is owed nothing (`204`).
    fn records_response(&self, type_uri: &str) -> bool {
        served(type_uri).is_none_or(|(task, _)| task.consequential())
    }
}

/// Run one task the pipeline admitted. `signer` is the proven signer, if the document carried
/// a proof (its specification's policy has already required one where it must).
async fn run(
    state: &AppState,
    signer: Option<String>,
    doc: TrustTask<Value>,
    type_uri: &str,
    received: Arc<Value>,
) -> TrustTaskOutcome {
    let Some((task, version)) = served(type_uri) else {
        return reject_with(
            &doc,
            RejectReason::UnsupportedType {
                type_uri: type_uri.to_string(),
            },
        );
    };
    let now = Utc::now();

    // A cast's costly checks — the pairing, a tallied ballot's proofs — run without the ballot
    // box, so one sender's casts never hold up every other community's tasks (VTI-VOT-045).
    let verified = match task {
        Task::Cast | Task::CastEncrypted => {
            match check_cast(state, task, &doc.payload, now).await {
                Ok(v) => v,
                Err(f) => return refuse_failure(&doc, type_uri, f),
            }
        }
        _ => None,
    };

    // The ballot box is synchronous, and journals what it accepts before it answers: hold the
    // election's lock for the call, on a blocking thread so a journal write never stalls the
    // runtime, and never across an await (#2604).
    let (community, election_id) = named_election(task, &doc.payload);
    let (community, election_id) = (community.to_string(), election_id.to_string());
    let boxes = Arc::clone(&state.ballot_boxes);
    let communities = state.communities.clone();
    let payload = doc.payload.clone();
    let version = version.unwrap_or(ElectionVersion::V0_4);
    let locked = tokio::task::spawn_blocking(move || {
        let caller = signer.as_deref().map_or(Caller::Anonymous, Caller::Did);
        let signer_did = signer.as_deref().unwrap_or_default();
        let p = &payload;
        if task == Task::Register {
            return boxes.register(
                &community,
                &election_id,
                |held, unfinished| registration_refused(&communities, signer_did, held, unfinished),
                |bb| bb.register_at(version, signer_did, p, now),
            );
        }
        let shard: Shard = boxes.for_task(&community, &election_id);
        let Ok(mut bb) = shard.lock() else {
            return Err(box_unavailable());
        };
        match task {
            Task::Register => unreachable!("answered above"),
            Task::Show => bb.show_at(version, caller, p, now),
            Task::Close => bb.close(signer_did, p, now),
            Task::Cancel => bb.cancel(signer_did, p, now),
            Task::Cast => match &verified {
                Some(v) => bb.cast_verified(p, v, now),
                None => bb.cast(p, now),
            },
            Task::Head => bb.board_head(caller, p, now),
            Task::Read => bb.board_read(caller, p, now),
            Task::Inclusion => bb.board_inclusion(caller, p, now),
            Task::Consistency => bb.board_consistency(caller, p, now),
            Task::Result => bb.result(caller, p, now),
            Task::CastEncrypted => match &verified {
                Some(v) => bb.cast_encrypted_verified(p, v, now),
                None => bb.cast_encrypted(p, now),
            },
            // A trustee's step goes on the board as the request received, proof included
            // (CONVENTIONS §9.6).
            Task::Enrol => bb.trustees_enrol(signer_did, &received, now),
            Task::Deal => bb.trustees_deal(signer_did, &received, now),
            Task::Confirm => bb.trustees_confirm(signer_did, &received, now),
            Task::Justify => bb.trustees_justify(signer_did, &received, now),
            Task::Decrypt => bb.trustees_decrypt(signer_did, &received, now),
            Task::TrusteeStatus => bb.trustees_status(caller, p, now),
            // The community's authorization goes on the board as received (CONVENTIONS §9.7).
            Task::Authorize => bb.trustees_authorize(signer_did, &received, now),
        }
    })
    .await;
    let outcome = locked.unwrap_or_else(|_| Err(box_unavailable()));

    match outcome {
        Ok(payload) => {
            let response = doc.respond_with(format!("urn:uuid:{}", Uuid::new_v4()), payload);
            match serde_json::to_vec(&response) {
                Ok(body) => TrustTaskOutcome {
                    status: StatusCode::OK,
                    body,
                },
                Err(e) => reject_with(
                    &doc,
                    RejectReason::InternalError {
                        reason: format!("the answer is unserialisable: {e}"),
                    },
                ),
            }
        }
        Err(f) => refuse_failure(&doc, type_uri, f),
    }
}

/// Answer a refusal the ballot box reported, under the task's own code where it is not
/// standard — the extended code's slug read off the request's Type URI.
fn refuse_failure(
    doc: &TrustTask<Value>,
    type_uri: &str,
    Failure {
        local,
        standard: is_standard,
        reason,
        ..
    }: Failure,
) -> TrustTaskOutcome {
    let slug = slug_of(type_uri).unwrap_or_default();
    let code = if is_standard {
        local
            .parse()
            .unwrap_or(TrustTaskCode::Standard(StandardCode::InternalError))
    } else {
        TrustTaskCode::new_extended(slug, local)
            .unwrap_or(TrustTaskCode::Standard(StandardCode::TaskFailed))
    };
    tracing::info!(task = slug, code = %code, %reason, "refused");
    reject_with_code(doc, code, reason, None)
}

fn box_unavailable() -> Failure {
    Failure {
        local: "internalError",
        standard: true,
        reason: "ballot box unavailable".into(),
    }
}

/// A cast's cheap checks under the lock, then its costly ones on a blocking thread without it.
/// `None` when the cast needs none (a resend), and the ballot box answers it as it is.
async fn check_cast(
    state: &AppState,
    task: Task,
    payload: &Value,
    now: chrono::DateTime<Utc>,
) -> Result<Option<VerifiedCast>, Failure> {
    let (community, election_id) = named_election(task, payload);
    let shard = state.ballot_boxes.for_task(community, election_id);
    let payload = payload.clone();
    // On a blocking thread: running the election's clock may journal an entry.
    let check = tokio::task::spawn_blocking(move || {
        let mut bb = shard.lock().map_err(|_| box_unavailable())?;
        if task == Task::Cast {
            bb.cast_check(&payload, now)
        } else {
            bb.cast_encrypted_check(&payload, now)
        }
    })
    .await
    .map_err(|_| box_unavailable())??;
    let Some(check) = check else {
        return Ok(None);
    };
    let _permit = state
        .cast_checks
        .acquire()
        .await
        .map_err(|_| box_unavailable())?;
    tokio::task::spawn_blocking(move || check.run())
        .await
        .map_err(|_| box_unavailable())?
        .map(Some)
}

/// Why a registration is refused before the ballot box looks at it: a community this box does
/// not serve (`permissionDenied`), or one already holding its quota of unfinished elections
/// (`unavailable`: it succeeds once one finishes). A repeat of a registration already held is
/// never refused here — it answers as it did.
fn registration_refused(
    communities: &CommunitiesConfig,
    signer: &str,
    held: bool,
    unfinished: usize,
) -> Option<Failure> {
    if !communities.admits(signer) {
        return Some(Failure {
            local: "permissionDenied",
            standard: true,
            reason: "this ballot box does not register this community's elections".into(),
        });
    }
    if !held && unfinished >= communities.max_unfinished {
        return Some(Failure {
            local: "unavailable",
            standard: true,
            reason: "this community holds as many unfinished elections here as it may".into(),
        });
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every served Type URI is a version VTI pins (so its policy comes from its own
    /// specification, never "nothing to check"), and every pinned `voting/*` version is served
    /// here — the routing table and the pin cannot drift apart.
    #[test]
    fn the_served_versions_are_exactly_the_pinned_voting_versions() {
        for uri in served_uris() {
            assert!(
                vti_specs::schema_index::spec_policy_for(uri).is_some(),
                "{uri} is served but not pinned"
            );
        }
        let pinned: std::collections::BTreeSet<&str> = vti_specs::schema_index::type_uris()
            .filter(|u| u.starts_with("https://trusttasks.org/spec/voting/"))
            .filter(|u| !u.ends_with("#response"))
            .collect();
        let routed: std::collections::BTreeSet<&str> = served_uris().collect();
        assert_eq!(pinned, routed);
    }

    #[test]
    fn a_slug_is_read_off_the_uri() {
        assert_eq!(
            slug_of("https://trusttasks.org/spec/voting/ballot/cast/0.1#request"),
            Some("voting/ballot/cast")
        );
        assert_eq!(slug_of("https://example.com/x/0.1"), None);
    }
}
