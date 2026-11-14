//! A room host: it stores data-room records and serves them back.
//!
//! # What this is, and what it deliberately is not
//!
//! A room host is a **delivery service**. It holds records — ciphertext, on any tier but
//! `open` — and answers `rooms/*` Trust Tasks against them. It is not a community: it has no
//! member roster, no policy engine, no credential issuance, no admin surface, and no opinion
//! about who belongs to any room it stores.
//!
//! That is not minimalism for its own sake. **A room is authorized by credentials the room
//! itself issued**, so a host that kept its own record of who belongs would become part of
//! that room's membership, and the room could no longer move to a different host without
//! reissuing credentials. The absence of a roster here is the portability guarantee, made
//! structural: there is nothing in this binary that could consult one.
//!
//! # Why it exists as its own binary
//!
//! Topology T1 of the data-rooms design is a person hosting their own rooms on
//! infrastructure they control. Before `vti-rooms` was extracted, doing that meant running a
//! whole community service — member lifecycle, policy, credentials, a website, an admin SPA
//! — to store some ciphertext. This is the same room protocol with none of that.
//!
//! It is also deliberately **not** part of the VTA. The process guarding a master seed
//! should not also terminate presentations from arbitrary DIDs, which is why the design
//! makes a room host an ordinary provisioned integration with its own DID (the `room-host`
//! DID template) rather than a new surface on the agent.
//!
//! # How a request is authorized
//!
//! Two things this host takes from a request and nothing else:
//!
//! - the **presenter**, from the document's own `eddsa-jcs-2022` proof. Not from a payload
//!   field — a presentation says what may be done, not who is doing it, so an unbound one
//!   is a bearer token anyone observing it inherits.
//! - the **chain**, verified by [`vti_rooms_dtg`] against credentials the room issued.
//!
//! Neither is a lookup in anything this host stores, which is the whole of invariant I5.
//!
//! # Status
//!
//! `open` and `attributed` rooms serve. A `private` room is refused, because its subject
//! binding has to be proved in zero knowledge and the working group has not settled the
//! profile — the refusal comes from `vti-rooms-dtg`, which is also what a VTC uses, so the
//! two cannot disagree about what is safe to serve.

pub mod creation;
pub mod mirror;

/// Room files: `rooms/blobs/*`, `rooms/records/put` 0.2 and `rooms/info`.
mod files;

/// Being reachable at a mediator, as well as at a URL.
#[cfg(feature = "didcomm")]
pub mod didcomm;

/// Enrolling with a VTA, so a host can serve rooms that VTA governs.
#[cfg(feature = "onboarding")]
pub mod onboarding;

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::State;
use axum::http::StatusCode;

use axum::routing::post;
use axum::{Json, Router};
use serde_json::Value;
use trust_tasks_rs::{RejectReason, TrustTask};
use vti_common::config::StoreConfig;
use vti_common::error::AppError;
use vti_common::store::{KeyspaceHandle, Store};
use vti_rooms::audit as rooms_audit;
use vti_rooms::{ROOM_RECORDS_KEYSPACE, ROOMS_KEYSPACE, Room, storage};
use vti_trust_task_server::ArrivalCtx;

/// Everything this host holds. Two keyspaces and a verifier — and note what is not here.
#[derive(Clone)]
pub struct HostState {
    rooms: KeyspaceHandle,
    records: KeyspaceHandle,
    /// The rooms' epoch key chains. Wrapped key material this host cannot read.
    epoch_links: KeyspaceHandle,
    /// Each room's revocation list (`rooms/revocations/put`): the one thing this host
    /// consults beyond a presentation, and room state rather than its own — signed by the
    /// room, moving with it.
    revocations: KeyspaceHandle,
    /// Room files: the blob index, transfers, limits and usage, and the store
    /// the ciphertext lives in. Ciphertext this host cannot read, again.
    files: Arc<vti_rooms::blobs::BlobHost>,
    /// The record of accepted document identifiers (SPEC §7.2 item 11,
    /// VTI-OPS-025 … 029): in the store, so it survives a restart and is shared
    /// by every carrier that reaches [`dispatch`].
    accepted_ids: KeyspaceHandle,
    /// The watches members armed (`rooms/watch/0.1`): this host's own state, never the
    /// room's, consulted to authorize nothing, and signalled over the mediator session
    /// when this host has one ([`HostState::set_signals`]).
    watches: Arc<vti_rooms::watch::RoomWatches>,
    /// How a DID resolves to the key that signed a credential.
    ///
    /// A room's credentials are issued by the room, which is normally a `did:webvh`, so a
    /// host restricted to `did:key` can serve almost nothing. It is still the default when
    /// no resolver is configured: refusing what it cannot verify is correct, and quietly
    /// resolving over the network for an unauthenticated caller is not.
    resolver: vti_common::auth::TrustTaskVmResolver,
    /// This host's own DID, once it has one — the `recipient` a document addressed to it
    /// must carry (framework SPEC §7.2 items 4–5). Set when the host becomes reachable by
    /// DID ([`HostState::set_host_did`]); an HTTP-only host with no identity has nothing to
    /// compare against, exactly as a VTC with no DID configured skips the check.
    host_did: Arc<std::sync::OnceLock<String>>,
    /// Whether an `open` room's `message` or `reaction` takes a new version only from its
    /// original author (`rooms/records/put/0.5` Host item 15, a MAY). On unless the operator
    /// turns it off ([`HostState::set_refuse_rewrites_by_others`]).
    refuse_rewrites_by_others: Arc<std::sync::atomic::AtomicBool>,
    /// What signs every answer [`dispatch`] gives, once this host has a key to sign with
    /// ([`HostState::set_answer_signer`]). A party acting on an answer — a member's VTA
    /// arming a watch or advancing a room's group — believes only one signed by the host
    /// it addressed (SPEC §7.3 item 7, VTI-KEY-106), so without this every success this
    /// host returned was refused at the caller as unsigned.
    answer_signer: Arc<std::sync::OnceLock<Arc<dyn vti_trust_task_server::ResponseSigner>>>,
    /// Who may register a room here, and how many ([`HostState::set_room_creation`]).
    creation: Arc<std::sync::RwLock<creation::RoomCreation>>,
    /// The room counts registration is held to, kept rather than recounted per create
    /// ([`RoomCounts`]). The lock is held across a registration's check and its write,
    /// so two concurrent creates cannot both pass a ceiling that has room for one.
    room_counts: Arc<tokio::sync::Mutex<Option<RoomCounts>>>,
    /// Bumped whenever rooms may have been added, removed or moved between owners other
    /// than by a registration here ([`HostState::rooms_changed`]). Kept counts taken at
    /// an older value are recounted before they are relied on.
    rooms_generation: Arc<std::sync::atomic::AtomicU64>,
    /// When a refused registration was last logged, and how many were refused since
    /// ([`HostState::log_refused_registration`]).
    refusal_log: Arc<std::sync::Mutex<RefusalLog>>,
}

impl HostState {
    /// Set who may register rooms on this host and how many each may hold
    /// ([`creation::RoomCreation`]). Applies to registrations from here on; rooms already
    /// registered are kept and served.
    pub fn set_room_creation(&self, policy: creation::RoomCreation) {
        *self
            .creation
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = policy;
    }

    /// See [`Self::set_room_creation`].
    pub fn room_creation(&self) -> creation::RoomCreation {
        self.creation
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// Sign every answer from here on with `signer`, which signs as this host's DID. First
    /// call wins, as [`Self::set_host_did`]'s does: a host answers as one identity.
    ///
    /// An HTTP-only host with no identity has no key, and answers unsigned — exactly as a
    /// service before provisioning does (`vti_trust_task_server::sign_response`).
    pub fn set_answer_signer(&self, signer: Arc<dyn vti_trust_task_server::ResponseSigner>) {
        let _ = self.answer_signer.set(signer);
    }

    /// Whether this host refuses, on an `open` room, a new version of a `message` or a
    /// `reaction` by anyone but its original author (`rooms/records/put/0.5` Host item 15).
    ///
    /// **On by default.** The specification makes it a MAY, and its readers defend against
    /// such a rewrite whatever the host does (`SealedRecordBody`, *What a new version
    /// keeps*); refusing it at the host is cheap on the one tier where the host reads `kind`
    /// anyway, and stops a member rewriting someone else's words for every reader that
    /// predates those rules. An operator whose room's readers want otherwise turns it off.
    pub fn set_refuse_rewrites_by_others(&self, on: bool) {
        self.refuse_rewrites_by_others
            .store(on, std::sync::atomic::Ordering::Relaxed);
    }

    /// See [`Self::set_refuse_rewrites_by_others`].
    pub fn refuses_rewrites_by_others(&self) -> bool {
        self.refuse_rewrites_by_others
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Bind this host to its DID, so a document addressed to anyone else is refused as
    /// `wrongRecipient`. First call wins: a host has one identity for its lifetime, and a
    /// second, different one is refused rather than silently swapped in.
    pub fn set_host_did(&self, did: &str) -> Result<(), AppError> {
        let set = self.host_did.get_or_init(|| did.to_string());
        if set == did {
            Ok(())
        } else {
            Err(AppError::Conflict(format!(
                "this host already serves as `{set}`; it cannot also be `{did}`"
            )))
        }
    }

    /// This host's DID, when it has one.
    pub fn host_did(&self) -> Option<&str> {
        self.host_did.get().map(String::as_str)
    }

    /// Drop every accepted-id record whose retention has passed, returning how
    /// many. Run on a timer: the record is read-through-expiry, so this only
    /// bounds the keyspace.
    pub async fn sweep_accepted_ids(&self) -> Result<usize, AppError> {
        vti_trust_task_server::accepted_store::sweep_expired(&self.accepted_ids, chrono::Utc::now())
            .await
    }

    /// Lend the watches this host's outbound transport (`rooms/changed/0.1`). Until a host
    /// has one — it is not reachable at a mediator — every watch is refused
    /// `addressUnreachable`: there is no transport it could signal over.
    pub fn set_signals(&self, signals: Arc<dyn vti_rooms::watch::Signals>) {
        self.watches.set_signals(signals);
    }

    /// Signal a fired watch after a delay drawn from `from..=to` milliseconds rather than
    /// the default 2–6 s (`rooms/changed/0.1` Producer item 4). For a test driving a watch
    /// end to end; a host serving members keeps the default.
    #[cfg(any(test, feature = "test-support"))]
    pub fn set_watch_signal_delay_ms(&self, from: u64, to: u64) {
        self.watches.set_signal_delay_ms(from, to);
    }

    /// Space a live watch's signals `spacing` apart rather than the default second
    /// (`rooms/watch/0.2` Host item 5). For a test; a host serving members keeps at least a
    /// second.
    #[cfg(any(test, feature = "test-support"))]
    pub fn set_live_watch_spacing(&self, spacing: std::time::Duration) {
        self.watches.set_live_spacing(spacing);
    }

    /// Set `room_id`'s signal delay directly, as `rooms/signal-delay/set` records it — and,
    /// back to `randomised`, end its live watches as that task does. For a test that needs a
    /// room's setting without an `admin` chain.
    #[cfg(any(test, feature = "test-support"))]
    pub async fn set_room_signal_delay(
        &self,
        room_id: &str,
        delay: vti_rooms::signal_delay::SignalDelay,
    ) -> Result<(), AppError> {
        storage::set_signal_delay(&self.rooms, room_id, delay, 0).await?;
        if delay.is_randomised() {
            self.watches.end_live_watches(room_id).await;
        }
        Ok(())
    }

    /// Forget the watches whose lease ran out, returning how many. Run on a timer beside
    /// [`Self::sweep_accepted_ids`]; a room's own watches are also swept when it moves.
    pub async fn sweep_watches(&self) -> Result<usize, AppError> {
        self.watches.sweep(chrono::Utc::now()).await
    }

    /// A task may have moved `room_id`: fire the watches it put past their watermark.
    pub(crate) async fn room_moved(&self, room_id: &str) {
        self.watches.room_moved(room_id).await;
    }

    /// The room keyspace.
    ///
    /// This crate already exports `open_state` and `router` so a host can be embedded; this
    /// is the third thing an embedder needs — placing a room in a state no wire call can
    /// produce. Restoring from a backup is one such case. Ageing a room past its epoch, so
    /// succession can be demonstrated without waiting a year, is the one the `data_room`
    /// example uses it for.
    ///
    /// It is deliberately the *rooms* keyspace and not the records one: seeding rooms is a
    /// legitimate administrative act, and handing out the record store would let an embedder
    /// write records around every authorization check in this file.
    ///
    /// Handing it out counts as a change to the rooms ([`Self::rooms_changed`]): whatever
    /// the caller adds or removes, registration recounts before it next relies on the
    /// rooms it holds, so a removed room never holds a slot it no longer fills.
    pub fn rooms(&self) -> &KeyspaceHandle {
        self.rooms_changed();
        &self.rooms
    }

    /// Say the rooms may have changed other than by a registration here — added,
    /// removed, or moved between owners — so the counts registration is held to are
    /// recounted before they are next relied on.
    pub fn rooms_changed(&self) {
        self.rooms_generation
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    /// The record keyspace, for the mirror puller.
    ///
    /// Deliberately *not* the general-purpose escape hatch `rooms()` is careful
    /// not to be: a mirror writes records this host did not authorize, which is
    /// exactly what a copy is, and `storage::store_mirrored_record` refuses to
    /// do it on a room this host primaries. An embedder reaching for this to
    /// write records around the authorization checks would be writing them into
    /// a room whose version counter disagrees.
    pub fn records(&self) -> &KeyspaceHandle {
        &self.records
    }
}

/// This host's half of the shared `rooms/*` handlers ([`vti_rooms_host`]): its keyspaces and
/// verifier, its creator rules and ceilings, and a log line for an audit trail.
#[async_trait::async_trait]
impl vti_rooms_host::RoomHost for HostState {
    fn rooms(&self) -> &KeyspaceHandle {
        &self.rooms
    }

    fn records(&self) -> &KeyspaceHandle {
        &self.records
    }

    fn epoch_links(&self) -> &KeyspaceHandle {
        &self.epoch_links
    }

    fn revocations(&self) -> &KeyspaceHandle {
        &self.revocations
    }

    fn files(&self) -> &vti_rooms::blobs::BlobHost {
        &self.files
    }

    fn watches(&self) -> &vti_rooms::watch::RoomWatches {
        &self.watches
    }

    fn resolver(&self) -> vti_common::auth::TrustTaskVmResolver {
        self.resolver.clone()
    }

    fn host_limits(&self) -> vti_rooms::signal_delay::HostLimits {
        files::HOST_LIMITS
    }

    async fn refuses_rewrites_by_others(&self) -> bool {
        HostState::refuses_rewrites_by_others(self)
    }

    /// The host's own bound on registration (`authorize_create` leaves it to whoever hosts):
    /// who may register, and how many rooms one owner and the host may hold. Checked and
    /// written under one lock, so concurrent creates cannot overshoot.
    async fn register(
        &self,
        registration: vti_rooms_host::Registration<'_>,
    ) -> Result<(), vti_rooms_host::RegisterRefused> {
        let (presenter, room) = (registration.presenter, registration.room);
        let mut counts = self.room_counts.lock().await;
        if let Err(refusal) = admit_registration(self, &mut counts, presenter, room).await {
            if let RegistrationRefused::Policy(why) = &refusal {
                self.log_refused_registration(presenter, why);
            }
            return Err(refusal_reason(refusal));
        }
        storage::create_room(&self.rooms, room).await?;
        if let Some(c) = counts.as_mut() {
            c.add(&room.owner_did);
        }
        Ok(())
    }

    /// Ownership moved: the counts registration is held to are recounted before they are
    /// next relied on.
    fn owner_changed(&self, _room_id: &str) {
        self.rooms_changed();
    }

    /// Record a room operation — §8, with the tier decision made by `vti_rooms::audit`.
    ///
    /// This host has no audit chain: it is a delivery service, and standing up an HMAC key
    /// store and a hash chain here would be most of a community service again, which is the
    /// thing it exists not to be. So the trail goes to `tracing`, where an operator's own log
    /// pipeline collects it.
    ///
    /// What is **not** different from a VTC is *what may be recorded*. The actor comes from
    /// [`vti_rooms::audit::for_operation`], so a `private` room logs that a member acted and
    /// never who — a host that logged the DID because its own logging happened to be simpler
    /// would have handed itself the membership by the back door.
    async fn audit(
        &self,
        room: &Room,
        authorized: &vti_rooms::authz::AuthorizedAction,
        event: vti_rooms_host::RoomAudit<'_>,
    ) {
        use vti_rooms_host::RoomAudit;
        let operation = event.operation();
        #[cfg(test)]
        AUDITED.with(|audited| audited.borrow_mut().push(operation.action_name()));
        match event {
            RoomAudit::Operation {
                record_key,
                purpose,
                ..
            } => {
                let entry = rooms_audit::for_operation(room.visibility, authorized, record_key);
                tracing::info!(
                    action = operation.action_name(),
                    room = %entry.room_id,
                    actor = %entry.actor.as_str(),
                    record = entry.record_key.as_deref().unwrap_or("-"),
                    visibility = ?room.visibility,
                    purpose = purpose.unwrap_or("-"),
                    "room operation"
                );
            }
            // A retention act or a signal-delay change, with what the specification asks a
            // host to keep — never anything a removed record said.
            other => {
                let detail = match other {
                    RoomAudit::Retention { detail, .. } => detail.detail(),
                    RoomAudit::SignalDelay(audit) => audit.detail(),
                    _ => Value::Null,
                };
                let entry = rooms_audit::for_operation(room.visibility, authorized, None);
                tracing::info!(
                    action = operation.action_name(),
                    room = %entry.room_id,
                    actor = %entry.actor.as_str(),
                    visibility = ?room.visibility,
                    detail = %detail,
                    "room operation"
                );
            }
        }
    }
}

// What `audit` recorded on this thread, so a test can assert on the trail without
// capturing log output. A thread-local `tracing` subscriber is not reliable for that when
// other tests share the process (`cargo test`): a callsite's cached interest can be settled
// by another thread before the subscriber exists, and the event is then never delivered.
#[cfg(test)]
thread_local! {
    static AUDITED: std::cell::RefCell<Vec<&'static str>> = const { std::cell::RefCell::new(Vec::new()) };
}

/// What `audit` recorded on this thread, for a test in any
/// module of this crate.
#[cfg(test)]
pub(crate) fn tests_audited() -> Vec<&'static str> {
    AUDITED.with(|audited| audited.borrow().clone())
}

/// Seconds since the Unix epoch, for a test placing a room in time.
#[cfg(test)]
pub(crate) fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// What answering a request produces: **the document, and separately a status.**
///
/// The document is the answer. It is a routed Trust-Task `#response` or `trust-task-error`,
/// self-describing — it carries its own `type` and, when it refuses, a framework `code` — so
/// a caller switches on what is *in* it and never on how it arrived.
///
/// The status is the same fact restated for one carrier that insists on having it out of
/// band. HTTP does; DIDComm and TSP do not, and on those wires it is simply dropped. Keeping
/// them as two fields rather than one `Response` is what lets one dispatch serve all three:
/// the moment a handler builds an HTTP response, every other carrier has to take it apart
/// again to find the answer inside.
pub struct Answer {
    /// The HTTP status this answer would be, derived from the document's own code.
    pub status: u16,
    /// The routed Trust-Task document. **This is the answer.**
    pub document: Value,
}

impl axum::response::IntoResponse for Answer {
    fn into_response(self) -> axum::response::Response {
        (
            StatusCode::from_u16(self.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
            Json(self.document),
        )
            .into_response()
    }
}

/// The HTTP mount. Everything it does is [`dispatch`]; this only says which carrier asked.
async fn trust_task(State(state): State<Arc<HostState>>, body: Bytes) -> Answer {
    dispatch(&state, &body).await
}

/// **The one entry point** for a document that arrived over HTTP: a `rooms/*` document,
/// routed by its own `type`.
///
/// One mount rather than five routes, because the document's `type` is its identity — the
/// same shape the VTC's holder-facing surface uses. And one pipeline for every carrier
/// ([`dispatch_from`]), because a host that routed or authorized differently depending on
/// how a request arrived would have as many authorization models as it has wires.
///
/// Nothing about *who* is asking comes from the carrier. The presenter is taken from the
/// document's own `eddsa-jcs-2022` proof and the authority from the chain it carries, so a
/// request is exactly as authorized over a socket as over a POST.
pub async fn dispatch(state: &Arc<HostState>, body: &[u8]) -> Answer {
    dispatch_from(state, &ArrivalCtx::rest(), body).await
}

/// [`dispatch`], for a document a carrier delivered: `ctx` says which, and over DIDComm and
/// TSP the sender it authenticated, which the spine requires the document's proof to bind
/// (VTI-OPS-021/093).
///
/// This is the workspace's receive pipeline ([`vti_trust_task_server::Spine`]), the one the
/// VTC runs, in its order: size, freshness and the acceptance window, expiry and the
/// recipient binding, the task's own specification policy, the proof bound to `issuer`, the
/// sender binding, the duplicate-id record, dispatch, and every answer signed — refusals too.
pub async fn dispatch_from(state: &Arc<HostState>, ctx: &ArrivalCtx, body: &[u8]) -> Answer {
    let size = DeclaredSizes;
    let policy = vti_specs::schema_index::spec_policy_for;
    let verifier =
        vti_trust_task_server::ResolverProofVerifier::operational(state.resolver.clone());
    let hooks = Hooks(state);
    let accepted = vti_trust_task_server::StoreAcceptedIds::new(state.accepted_ids.clone());
    let dispatcher = RoomDispatcher(Arc::clone(state));
    let signer = state
        .answer_signer
        .get()
        .map(|s| &**s as &dyn vti_trust_task_server::ResponseSigner);
    let outcome =
        vti_trust_task_server::Spine::new(&policy, &verifier, &hooks, &accepted, &dispatcher)
            .with_size_gate(&size)
            .with_signer(signer)
            .receive(ctx, body)
            .await;
    Answer::from(outcome)
}

impl From<vti_trust_task_server::TrustTaskOutcome> for Answer {
    fn from(outcome: vti_trust_task_server::TrustTaskOutcome) -> Self {
        Self {
            status: outcome.status.as_u16(),
            // An empty body is an answer with no document: a duplicate still in flight
            // (`202`) or one completed without a kept answer (`204`).
            document: serde_json::from_slice(&outcome.body).unwrap_or(Value::Null),
        }
    }
}

/// Sign `doc` as this host, when it has a signer ([`HostState::set_answer_signer`]) and the
/// document carries no proof yet. A signing failure leaves it unsigned and logs. For an
/// answer produced outside [`dispatch`] (a carrier's own refusal).
#[cfg(feature = "didcomm")]
pub(crate) async fn sign_answer(state: &HostState, doc: &mut Value) {
    if let Some(signer) = state.answer_signer.get()
        && doc.is_object()
        && doc.get("proof").is_none()
        && let Err(e) = signer.sign_response_document(doc).await
    {
        tracing::error!(error = %e, "could not sign an answer; returning it unsigned");
    }
}

/// The size gate: SPEC §12.4 and each task's `maxDocumentBytes`. A document larger than its
/// specification declares is refused, measured over the document as received, before it is
/// parsed. Tasks that declare no bound keep the transport's own limit, so the large-document
/// tasks are exactly the ones that may be large — a chunk document is admitted at its bound,
/// and nothing else is.
struct DeclaredSizes;

#[async_trait::async_trait]
impl vti_trust_task_server::SizeGate for DeclaredSizes {
    async fn admit(
        &self,
        body: &[u8],
    ) -> Result<Option<vti_trust_task_server::SizeCharge>, vti_trust_task_server::TrustTaskOutcome>
    {
        let Some(type_uri) = vti_trust_task_server::size::peek_type(body) else {
            // Not a document of any readable type: the parse refuses it next.
            return Ok(None);
        };
        let bare = type_uri.split('#').next().unwrap_or(&type_uri);
        if let Some(max) = vti_specs::schema_index::max_document_bytes_for(bare) {
            vti_trust_task_server::size::check_size(body, max, |_| max)?;
        }
        Ok(None)
    }
}

/// This host's points in the pipeline: its DID, once it has one.
struct Hooks<'a>(&'a HostState);

#[async_trait::async_trait]
impl vti_trust_task_server::SpineHooks for Hooks<'_> {
    async fn recipient(&self) -> Option<String> {
        self.0.host_did().map(str::to_string)
    }

    /// A host with no DID yet has nothing to compare a `recipient` against, so the spine
    /// skips the binding — and with it the expiry half of SPEC §7.2 item 4. Applied here
    /// instead, as the same check against the document's own recipient, which it trivially
    /// matches: an expired document is refused by a host with or without an identity.
    async fn before_proof(
        &self,
        doc: &TrustTask<Value>,
        _type_uri: &str,
    ) -> Option<vti_trust_task_server::TrustTaskOutcome> {
        if self.0.host_did().is_some() {
            return None;
        }
        let own = doc.recipient.clone().unwrap_or_default();
        doc.validate_basic(chrono::Utc::now(), &own)
            .err()
            .map(|reason| vti_trust_task_server::reject::reject_with(doc, reason))
    }
}

/// The routing table behind the spine.
struct RoomDispatcher(Arc<HostState>);

impl vti_trust_task_server::Dispatcher for RoomDispatcher {
    fn dispatch<'a>(
        &'a self,
        ctx: &'a ArrivalCtx,
        doc: TrustTask<Value>,
        type_uri: &'a str,
        _received: Arc<Value>,
    ) -> vti_trust_task_server::BoxFuture<'a, vti_trust_task_server::TrustTaskOutcome> {
        Box::pin(async move {
            if !vti_rooms_host::serves(type_uri) {
                // The framework's own codes for this: a host that does not implement a task
                // says so by naming the type — or the versions it serves of one it does — and
                // a client can tell that from a task it implements but refused.
                return vti_trust_task_server::reject::unsupported_type_or_version(
                    &doc,
                    type_uri,
                    vti_rooms_host::served_uris(),
                    "room host",
                );
            }
            // A room operation is authorized against the DID that signed the request, so an
            // unsigned one has nothing to authorize. Every `rooms/*` specification declares
            // the proof REQUIRED, so the spine has normally refused this already.
            let Some(presenter) = ctx.verified_signer.as_deref() else {
                return vti_trust_task_server::reject::reject_with(
                    &doc,
                    trust_tasks_rs::RejectReason::ProofRequired,
                );
            };
            let host: Arc<dyn vti_rooms_host::RoomHost> = self.0.clone();
            vti_rooms_host::dispatch(host, doc, presenter).await
        })
    }

    /// A read's answer is not kept in the duplicate-execution record (a chunk download is
    /// large, and a replay is owed nothing), so a duplicate read is answered `204`; a write's
    /// is, so a redelivered write is answered with the result it already had. Read off the
    /// shared registrations ([`vti_rooms_host::is_consequential`]).
    fn records_response(&self, type_uri: &str) -> bool {
        vti_rooms_host::is_consequential(type_uri)
    }
}

/// The keyspace the accepted-document-id record lives in (SPEC §7.2 item 11).
///
/// In the store rather than in the process, as the VTA's and the VTC's are: a document
/// stating an `expiresAt` is acceptable for up to thirty days (VTI-OPS-028), so a restart
/// inside its window is routine, and a record held only in memory would let its replay
/// after the restart execute again (VTI-OPS-029). One host process owns its store; a
/// replicated host would still need the record shared between replicas.
pub const ACCEPTED_IDS_KEYSPACE: &str = "accepted_ids";

/// Why a registration was refused before the room was written.
enum RegistrationRefused {
    Policy(creation::CreationRefused),
    Store(AppError),
}

/// How long kept room counts are trusted before they are recounted. Registration keeps
/// them current itself; this catches what changes rooms without it — an ownership
/// transfer, a mirror, an embedder writing the rooms keyspace, a removal — so a count is
/// at most this stale.
const ROOM_COUNTS_MAX_AGE: std::time::Duration = std::time::Duration::from_secs(300);

/// Rooms held, in total and per owner, as of `counted_at`.
struct RoomCounts {
    total: u64,
    per_owner: std::collections::HashMap<String, u64>,
    counted_at: std::time::Instant,
    /// [`HostState::rooms_generation`] when counted.
    generation: u64,
}

impl RoomCounts {
    async fn count(rooms: &KeyspaceHandle, generation: u64) -> Result<Self, AppError> {
        let all = storage::list_rooms(rooms).await?;
        let mut per_owner = std::collections::HashMap::new();
        for r in &all {
            *per_owner
                .entry(creation::bare_did(&r.owner_did).to_string())
                .or_insert(0) += 1;
        }
        Ok(Self {
            total: all.len() as u64,
            per_owner,
            counted_at: std::time::Instant::now(),
            generation,
        })
    }

    fn owned_by(&self, owner: &str) -> u64 {
        self.per_owner
            .get(creation::bare_did(owner))
            .copied()
            .unwrap_or(0)
    }

    fn add(&mut self, owner: &str) {
        self.total += 1;
        *self
            .per_owner
            .entry(creation::bare_did(owner).to_string())
            .or_insert(0) += 1;
    }
}

/// Hold a registration of `room` by `presenter` to the host's
/// [`creation::RoomCreation`], recounting `counts` when absent or stale. The caller
/// holds the `room_counts` lock.
async fn admit_registration(
    state: &HostState,
    counts: &mut Option<RoomCounts>,
    presenter: &str,
    room: &Room,
) -> Result<(), RegistrationRefused> {
    let policy = state.room_creation();
    // Refuse a party this host does not register for before reading anything.
    if !policy.admits(presenter) {
        return Err(RegistrationRefused::Policy(
            creation::CreationRefused::NotACreator,
        ));
    }
    // A repeat of a registration that already happened is answered as that, not as a
    // ceiling the room already counts toward.
    if storage::get_room(&state.rooms, &room.room_id).await.is_ok() {
        return Err(RegistrationRefused::Store(AppError::Conflict(format!(
            "room `{}` is already registered here",
            room.room_id
        ))));
    }
    let generation = state
        .rooms_generation
        .load(std::sync::atomic::Ordering::Relaxed);
    if counts
        .as_ref()
        .is_none_or(|c| c.generation != generation || c.counted_at.elapsed() > ROOM_COUNTS_MAX_AGE)
    {
        *counts = Some(
            RoomCounts::count(&state.rooms, generation)
                .await
                .map_err(RegistrationRefused::Store)?,
        );
    }
    let c = counts.as_ref().expect("counted above");
    policy
        .check(presenter, c.total, c.owned_by(&room.owner_did))
        .map_err(RegistrationRefused::Policy)
}

/// The refused-registration log's state: when one was last written, and how many were
/// refused without a line since.
#[derive(Default)]
struct RefusalLog {
    last: Option<std::time::Instant>,
    unlogged: u64,
}

/// At most one refused-registration line per this long; the line counts the rest.
const REFUSAL_LOG_INTERVAL: std::time::Duration = std::time::Duration::from_secs(60);

impl HostState {
    /// Log a refused registration for the operator, at most once per
    /// [`REFUSAL_LOG_INTERVAL`], counting those not logged in between. A refusal is
    /// usually a creator the operator has not named yet, or a limit reached; either is
    /// something they act on, and an unbounded line per refusal is not.
    fn log_refused_registration(&self, presenter: &str, refusal: &creation::CreationRefused) {
        let mut log = self
            .refusal_log
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let due = log.last.is_none_or(|t| t.elapsed() >= REFUSAL_LOG_INTERVAL);
        if !due {
            log.unlogged += 1;
            return;
        }
        let also = std::mem::take(&mut log.unlogged);
        log.last = Some(std::time::Instant::now());
        drop(log);
        match refusal {
            creation::CreationRefused::NotACreator => tracing::warn!(
                presenter,
                also_refused_since_last_line = also,
                "refused rooms/create: the signer is not a creator this host was given \
                 (--room-creator)"
            ),
            creation::CreationRefused::OwnerAtLimit { max } => tracing::warn!(
                presenter,
                max_rooms_per_owner = max,
                also_refused_since_last_line = also,
                "refused rooms/create: the owner holds its limit of rooms on this host"
            ),
            creation::CreationRefused::HostAtLimit { max } => tracing::warn!(
                presenter,
                max_rooms = max,
                also_refused_since_last_line = also,
                "refused rooms/create: this host holds its limit of rooms (--max-rooms)"
            ),
        }
    }
}

/// A refused registration, worded as this host words it.
fn refusal_reason(refusal: RegistrationRefused) -> vti_rooms_host::RegisterRefused {
    use creation::CreationRefused as R;
    use vti_rooms_host::RegisterRefused as Out;
    match refusal {
        RegistrationRefused::Store(e) => Out::App(e),
        RegistrationRefused::Policy(R::NotACreator) => {
            Out::Reject(RejectReason::PermissionDenied {
                reason: "this host registers rooms only for the parties its operator named".into(),
            })
        }
        RegistrationRefused::Policy(R::OwnerAtLimit { max }) => {
            Out::Reject(RejectReason::TaskFailed {
                reason: format!("the owner already holds {max} rooms on this host, its limit"),
                details: Some(serde_json::json!({ "limit": "roomsPerOwner", "max": max })),
            })
        }
        RegistrationRefused::Policy(R::HostAtLimit { max }) => {
            Out::Reject(RejectReason::TaskFailed {
                reason: format!("this host already holds {max} rooms, its limit"),
                details: Some(serde_json::json!({ "limit": "rooms", "max": max })),
            })
        }
    }
}

/// Build the router. Separated from `main` so tests can drive it without a socket.
pub fn router(state: Arc<HostState>) -> Router {
    Router::new()
        .route("/trust-tasks", post(trust_task))
        .route("/health", axum::routing::get(|| async { "ok" }))
        .with_state(state)
}

/// [`router`], reachable from a browser at the named origins.
///
/// A room's own client may be a web page — a member is a party holding credentials, not a
/// party running a server, and increasingly that means a tab. Without a CORS layer a
/// browser cannot reach this host at all: the request is made and the response is discarded
/// before any script sees it, so the failure surfaces as a network error with nothing in it
/// about origins, and the page's author goes looking at the wrong end.
///
/// Off unless asked for, and by explicit origin rather than `*`. This host stores rooms it
/// does not govern; which sites may talk to it from a user's browser is an operator's
/// decision, and a wildcard is the one answer that cannot be reviewed. Mirrors
/// `vta-service`'s layer, including its refusal to partially apply: a half-configured CORS
/// surface is worse than none, because it looks configured.
///
/// Note this changes nothing about **authorization**. A browser reaching this host is still
/// a request carrying a proof and a chain, refused exactly as any other would be. CORS
/// decides who may ask, never what the answer is.
pub fn router_with_origins(state: Arc<HostState>, allowed_origins: &[String]) -> Router {
    let router = router(state);
    match cors_layer(allowed_origins) {
        Some(layer) => router.layer(layer),
        None => router,
    }
}

/// The CORS layer for `allowed_origins`, or `None` when there is nothing usable to apply.
fn cors_layer(allowed_origins: &[String]) -> Option<tower_http::cors::CorsLayer> {
    use axum::http::{HeaderName, HeaderValue, Method};
    use tower_http::cors::{AllowOrigin, CorsLayer};

    if allowed_origins.is_empty() {
        return None;
    }
    // `AllowOrigin::list` panics on a wildcard, and falling through to `any()` is not the
    // intent — an operator who wants every origin can say so in a proxy, where it is
    // visible. Malformed entries are dropped for the same reason a typo should show up in
    // the startup log rather than silently widen anything.
    let parsed: Vec<HeaderValue> = allowed_origins
        .iter()
        .filter(|o| !o.is_empty() && *o != "*")
        .filter_map(|o| HeaderValue::from_str(o).ok())
        .collect();
    if parsed.is_empty() {
        tracing::warn!(
            "every --allow-origin value was empty, a wildcard, or unparseable; serving with \
             no CORS layer rather than a partial one"
        );
        return None;
    }
    Some(
        CorsLayer::new()
            .allow_origin(AllowOrigin::list(parsed))
            // One route takes a body, and it is a POST. Nothing here is a GET a browser
            // would send credentials with.
            .allow_methods([Method::GET, Method::POST])
            .allow_headers([HeaderName::from_static("content-type")])
            .max_age(std::time::Duration::from_secs(60)),
    )
}

/// How many rooms `state` holds, mirrors included.
pub async fn rooms_held(state: &HostState) -> Result<usize, AppError> {
    Ok(storage::list_rooms(&state.rooms).await?.len())
}

/// Open the store with a `did:key`-only verifier.
///
/// The conservative construction, and what a test or the example wants: no network
/// resolution can be triggered by an unauthenticated request. A deployment serving a
/// `did:webvh` room wants [`open_state_with_resolver`].
pub fn open_state(data_dir: &std::path::Path) -> anyhow::Result<Arc<HostState>> {
    open_state_with_resolver(
        data_dir,
        vti_common::auth::TrustTaskVmResolver::did_key_only(),
    )
}

/// Open the store with a specific verification-method resolver, and room files
/// in a local directory under `data_dir` with the default limits.
pub fn open_state_with_resolver(
    data_dir: &std::path::Path,
    resolver: vti_common::auth::TrustTaskVmResolver,
) -> anyhow::Result<Arc<HostState>> {
    open_state_with_files(data_dir, resolver, FilesConfig::default())
}

/// How this host stores room files: one storage config, as a standalone host has.
#[derive(Clone, Default)]
pub struct FilesConfig {
    /// The limits applied to every room this host serves.
    pub limits: vti_rooms::blobs::HostLimits,
    /// Where committed blobs go. `None` is a local directory, `<data_dir>/blobs`.
    pub store: Option<Arc<dyn vti_common::blob_store::BlobStore>>,
    /// The storage config's name, recorded on every blob. `local` when unset.
    pub config_id: Option<String>,
}

/// Open the store with a resolver and an explicit room-file configuration.
pub fn open_state_with_files(
    data_dir: &std::path::Path,
    resolver: vti_common::auth::TrustTaskVmResolver,
    files: FilesConfig,
) -> anyhow::Result<Arc<HostState>> {
    let store = Store::open(&StoreConfig {
        data_dir: data_dir.to_path_buf(),
    })?;
    let blob_store = files.store.unwrap_or_else(|| {
        Arc::new(vti_common::blob_store::local::LocalDirStore::new(
            data_dir.join("blobs"),
        ))
    });
    Ok(Arc::new(HostState {
        rooms: store.keyspace(ROOMS_KEYSPACE)?,
        records: store.keyspace(ROOM_RECORDS_KEYSPACE)?,
        epoch_links: store.keyspace(vti_rooms::ROOM_EPOCH_LINKS_KEYSPACE)?,
        revocations: store.keyspace(vti_rooms::ROOM_REVOCATIONS_KEYSPACE)?,
        files: Arc::new(vti_rooms::blobs::BlobHost::new(
            store.keyspace(vti_rooms::blobs::ROOM_BLOBS_KEYSPACE)?,
            store.keyspace(vti_rooms::blobs::ROOM_BLOB_TRANSFERS_KEYSPACE)?,
            data_dir.join("blob-staging"),
            Arc::new(vti_rooms::blobs::FixedStore::new(
                files.config_id.unwrap_or_else(|| "local".into()),
                blob_store,
            )),
            files.limits,
        )),
        accepted_ids: store.keyspace(ACCEPTED_IDS_KEYSPACE)?,
        watches: Arc::new(vti_rooms::watch::RoomWatches::new(
            store.keyspace(vti_rooms::watch::ROOM_WATCHES_KEYSPACE)?,
            store.keyspace(ROOMS_KEYSPACE)?,
            store.keyspace(vti_rooms::ROOM_REVOCATIONS_KEYSPACE)?,
        )),
        resolver,
        host_did: Arc::new(std::sync::OnceLock::new()),
        refuse_rewrites_by_others: Arc::new(std::sync::atomic::AtomicBool::new(true)),
        answer_signer: Arc::new(std::sync::OnceLock::new()),
        creation: Arc::new(std::sync::RwLock::new(creation::RoomCreation::default())),
        room_counts: Arc::new(tokio::sync::Mutex::new(None)),
        rooms_generation: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        refusal_log: Arc::new(std::sync::Mutex::new(RefusalLog::default())),
    }))
}

impl HostState {
    /// Move room rows still in the earlier key layout, whose keys could name two rooms at
    /// once (#2382), to the current one ([`vti_rooms::storage::migrate_room_keys`]). Run
    /// at boot, before a room is served. A row that cannot be attributed to one room is
    /// left where it is and logged; nothing reads it.
    pub async fn migrate_room_keys(&self) -> anyhow::Result<()> {
        let out = vti_rooms::storage::migrate_room_keys(&self.records, &self.epoch_links).await?;
        if out.records + out.epoch_links + out.commits > 0 {
            tracing::info!(
                records = out.records,
                epoch_links = out.epoch_links,
                commits = out.commits,
                "room rows moved to the current key layout"
            );
        }
        for row in &out.left {
            tracing::warn!(
                row,
                "a room row in the earlier key layout was left in place"
            );
        }
        Ok(())
    }

    /// Room files, for the collection task an embedder runs
    /// ([`vti_rooms::blobs::BlobHost::sweep`]).
    pub fn files(&self) -> &Arc<vti_rooms::blobs::BlobHost> {
        &self.files
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use serde_json::json;
    use tower::ServiceExt;
    use vti_rooms::Visibility;
    use vti_rooms::wire::{
        ROOMS_EPOCH_MINT_TYPE, ROOMS_OWNER_CLAIM_TYPE, ROOMS_OWNER_TRANSFER_TYPE,
    };
    use vti_rooms_dtg::test_support::{Party, RoomFixture};

    /// A host over a temporary store.
    ///
    /// `did:key`-only resolution is not a limitation being worked around here: the fixture's
    /// room, owner and agent are all `did:key`, so every credential in these tests verifies
    /// with no network at all. That is deliberate — a test that reached the network would be
    /// testing the network.
    fn state() -> (tempfile::TempDir, Arc<HostState>) {
        let dir = tempfile::tempdir().unwrap();
        let state = open_state(dir.path()).expect("open store");
        // These tests register rooms as whoever they mint.
        state.set_room_creation(crate::creation::RoomCreation::any_creator());
        (dir, state)
    }

    /// The `did:key` for a one-byte test seed, plus the private-key
    /// multibase `vta_sdk::trust_task_sign::build_signed` accepts.
    fn did_key_from_seed(seed_byte: u8) -> (String, String) {
        use ed25519_dalek::SigningKey;
        let seed = [seed_byte; 32];
        let sk = SigningKey::from_bytes(&seed);
        let did = format!(
            "did:key:{}",
            vta_sdk::did_key::ed25519_multibase_pubkey(&sk.verifying_key().to_bytes())
        );
        let mut buf = vec![0x80, 0x26];
        buf.extend_from_slice(&seed);
        (did, multibase::encode(multibase::Base::Base58Btc, &buf))
    }

    /// `presenter` runs on every request reaching this host, including from a
    /// party this host has no relationship with — so it is one of the ~12
    /// inbound routes FTL-29595 fix direction 3 must leave byte-identical: a
    /// resolver failure and an actual bad signature must render the same
    /// `AppError::Forbidden`, never letting a caller learn which occurred.
    #[tokio::test]
    async fn a_resolver_failure_and_a_bad_signature_render_identically() {
        let (_dir, state) = state();

        // Resolver failure: a `did:webvh` verification method against this
        // did:key-only host — refused before any signature check runs.
        let resolver_fail_doc: TrustTask<Value> = serde_json::from_value(json!({
            "id": "urn:uuid:00000000-0000-4000-8000-000000000030",
            "type": vti_rooms::wire::ROOMS_RECORDS_PUT_V3_TYPE,
            "issuer": "did:webvh:QmScid:example.com:glenn",
            "recipient": "did:key:zHost",
            "payload": {},
            "proof": {
                "type": "DataIntegrityProof",
                "cryptosuite": "eddsa-jcs-2022",
                "proofPurpose": "assertionMethod",
                "verificationMethod": "did:webvh:QmScid:example.com:glenn#key-0",
                "created": "2026-01-01T00:00:00Z",
                "proofValue": "z2aBcD"
            }
        }))
        .expect("well-formed document");

        // Bad signature: a real did:key, signed, then corrupted.
        let (signer_did, secret_mb) = did_key_from_seed(41);
        let signed = vta_sdk::trust_task_sign::build_signed(
            vti_rooms::wire::ROOMS_RECORDS_PUT_V3_TYPE,
            json!({}),
            &signer_did,
            &secret_mb,
            "did:key:zHost",
        )
        .await
        .expect("build a validly-signed document");
        let mut bad_sig_doc: TrustTask<Value> =
            serde_json::from_str(&signed).expect("signed doc parses");
        let proof = bad_sig_doc.proof.as_mut().expect("document is signed");
        let last = proof.proof_value.pop().expect("non-empty proofValue");
        proof.proof_value.push(if last == '1' { '2' } else { '1' });

        // The spine's proof step, as this host runs it: verified over the document as
        // received, through this host's resolver.
        use vti_trust_task_server::ProofVerifier as _;
        let verifier =
            vti_trust_task_server::ResolverProofVerifier::operational(state.resolver.clone());
        let as_received = |d: &TrustTask<Value>| serde_json::to_value(d).expect("a document");
        let resolver_failure = verifier.verify(&as_received(&resolver_fail_doc), "x").await;
        let bad_signature = verifier.verify(&as_received(&bad_sig_doc), "x").await;

        match (resolver_failure, bad_signature) {
            (Err(AppError::Unauthorized(a)), Err(AppError::Unauthorized(b))) => {
                assert_eq!(
                    a, b,
                    "a resolver failure must render exactly as a bad signature does"
                );
            }
            other => panic!("expected both to be Unauthorized errors, got {other:?}"),
        }
    }

    /// Send a **signed** document and return the status plus the response payload.
    ///
    /// Signing is not ceremony: the host reads the presenter from this proof, and an
    /// unsigned request is refused before any chain is looked at.
    async fn call(
        app: &Router,
        type_uri: &str,
        payload: Value,
        signer: &Party,
    ) -> (StatusCode, Value) {
        let doc = vta_sdk::trust_task_sign::build_signed(
            type_uri,
            payload,
            &signer.did,
            &signer.secret_multibase,
            "did:key:zHost",
        )
        .await
        .expect("sign the request");

        let resp = app
            .clone()
            .oneshot(
                Request::post("/trust-tasks")
                    .header("content-type", "application/json")
                    .body(Body::from(doc))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let doc: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        assert!(
            doc.get("id").is_some(),
            "every reply must be a Trust Task document: {doc}"
        );
        (status, doc.get("payload").cloned().unwrap_or(Value::Null))
    }

    // ── read mirrors, end to end (§7.3) ─────────────────────────────────────

    /// Serve `app` on an ephemeral port and hand back its base URL.
    ///
    /// A mirror reaches its primary over HTTP like any other client, so the
    /// primary in these tests is a real socket rather than a direct call: a
    /// mirror that only worked in-process would prove nothing about the pull.
    async fn serve(app: Router) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        format!("http://{addr}")
    }

    /// The whole point of a mirror: records written at the primary become
    /// readable at the copy, under the primary's own version numbers.
    #[tokio::test]
    async fn a_mirror_serves_what_its_primary_wrote() {
        let (_pd, primary_state) = state();
        let (_md, mirror_state) = state();
        let f = RoomFixture::new(Visibility::Open).await;

        // The primary: an ordinary room with two records in it.
        let primary_app = router(primary_state.clone());
        register(&primary_app, &f).await;
        for (key, body) in [("decision/one", "first"), ("decision/two", "second")] {
            let (status, out) = call(
                &primary_app,
                vti_rooms::wire::ROOMS_RECORDS_PUT_V3_TYPE,
                serde_json::json!({
                    "roomId": f.room.room_id,
                    "key": key,
                    "presentation": f.as_owner(),
                    "cleartext": { "body": body },
                }),
                &f.owner,
            )
            .await;
            assert_eq!(status, StatusCode::OK, "{out}");
        }
        let primary_url = serve(primary_app).await;

        // The mirror: the same room id, registered as a copy of that primary.
        vti_rooms::storage::create_room(
            mirror_state.rooms(),
            &vti_rooms::Room {
                mirror_of: Some(primary_url.clone()),
                record_retention: None,
                last_prune: None,
                signal_delay: Default::default(),
                epoch_floor: None,
                frozen_at: None,
                next_version: 1,
                ..f.room.clone()
            },
        )
        .await
        .unwrap();

        let outcome = crate::mirror::pull_once(
            &mirror_state,
            &crate::mirror::MirroredRoom {
                room_id: f.room.room_id.clone(),
                primary_url,
                primary_did: Some("did:key:zHost".into()),
                membership: f.membership.clone(),
                authority: f.owner_chain.clone(),
                signer_did: f.owner.did.clone(),
                signer_key_multibase: f.owner.secret_multibase.clone(),
            },
        )
        .await
        .expect("the mirror pulls from its primary");
        assert_eq!(outcome.copied, 2, "both records copied");

        // Readable from the copy, with the primary's numbering intact — which is
        // what makes a sealed record openable and a watermark comparable.
        let mirror_app = router(mirror_state.clone());
        let (status, body) = call(
            &mirror_app,
            vti_rooms::wire::ROOMS_RECORDS_GET_V2_TYPE,
            serde_json::json!({
                "roomId": f.room.room_id,
                "key": "decision/one",
                "presentation": f.as_owner(),
            }),
            &f.owner,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["cleartext"]["body"], "first");
        assert_eq!(
            body["version"], 1,
            "the primary's version, not the mirror's"
        );

        // A second pull is a no-op: the watermark resumed where the first left off.
        let again = crate::mirror::pull_once(
            &mirror_state,
            &crate::mirror::MirroredRoom {
                room_id: f.room.room_id.clone(),
                // Deliberately unreachable: an unreachable primary must leave
                // the mirror serving what it has rather than losing it.
                primary_url: "http://127.0.0.1:1".to_string(),
                primary_did: None,
                membership: f.membership.clone(),
                authority: f.owner_chain.clone(),
                signer_did: f.owner.did.clone(),
                signer_key_multibase: f.owner.secret_multibase.clone(),
            },
        )
        .await;
        assert!(again.is_err(), "an unreachable primary is an error");
        let (status, body) = call(
            &mirror_app,
            vti_rooms::wire::ROOMS_RECORDS_GET_V2_TYPE,
            serde_json::json!({
                "roomId": f.room.room_id,
                "key": "decision/one",
                "presentation": f.as_owner(),
            }),
            &f.owner,
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "still serving the copy it has: {body}"
        );
    }

    /// The refusal that makes a mirror a mirror, over the wire — and it names
    /// the primary, so an operator knows where the write belongs.
    #[tokio::test]
    async fn a_mirror_refuses_a_write_and_says_where_it_goes() {
        let (_d, st) = state();
        let f = RoomFixture::new(Visibility::Open).await;
        vti_rooms::storage::create_room(
            st.rooms(),
            &vti_rooms::Room {
                mirror_of: Some("https://primary.example.org".into()),
                record_retention: None,
                last_prune: None,
                signal_delay: Default::default(),
                epoch_floor: None,
                frozen_at: None,
                ..f.room.clone()
            },
        )
        .await
        .unwrap();

        let app = router(st);
        let (status, body) = call(
            &app,
            vti_rooms::wire::ROOMS_RECORDS_PUT_V3_TYPE,
            serde_json::json!({
                "roomId": f.room.room_id,
                "key": "decision/three",
                "presentation": f.as_owner(),
                "cleartext": { "body": "not here" },
            }),
            &f.owner,
        )
        .await;
        assert_ne!(status, StatusCode::OK, "a mirror performs no writes");
        assert!(
            body.to_string().contains("primary.example.org"),
            "the refusal must name the primary: {body}"
        );
    }

    /// Register `f`'s room with the host.
    async fn register(app: &Router, f: &RoomFixture) {
        let (status, body) = call(
            app,
            vti_rooms::wire::ROOMS_CREATE_V2_TYPE,
            serde_json::json!({
                "roomId": f.room.room_id,
                "ownerDid": f.room.owner_did,
                "visibility": f.room.visibility,
            }),
            &f.owner,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
    }

    /// **The same bytes, answered identically, whichever carrier brought them.**
    ///
    /// This is the property the whole carrier-neutral split exists for, and it is asserted
    /// rather than assumed: a host that routed or authorized differently depending on how a
    /// request arrived would have as many authorization models as it has wires, and the
    /// difference would show up as "it works over HTTP but not over DIDComm" — a report with
    /// nowhere to start looking.
    ///
    /// A DIDComm or TSP listener calls `dispatch` with exactly these bytes; only the framing
    /// around them differs, and none of it reaches here. So driving `dispatch` directly is
    /// driving what those carriers drive.
    #[tokio::test]
    async fn one_dispatch_answers_the_same_over_any_carrier() {
        let (_dir, st) = state();
        let app = router(st.clone());
        let f = RoomFixture::new(Visibility::Open).await;
        register(&app, &f).await;

        // One request, as two documents. Not the same bytes twice: those are spent on first
        // delivery, and a replay is refused whichever carrier brings it
        // (`a_replayed_read_is_refused`). Everything a reply is derived from is shared,
        // the thread included; only the per-document `id` differs.
        let request = async || {
            let mut doc = vta_sdk::trust_task_sign::build_unsigned(
                vti_rooms::wire::ROOMS_RECORDS_LIST_V5_TYPE,
                serde_json::json!({
                    "roomId": f.room.room_id,
                    "presentation": f.as_owner(),
                }),
                &f.owner.did,
                "did:key:zHost",
            )
            .expect("build the request");
            doc.thread_id = Some("urn:uuid:00000000-0000-4000-8000-0000000000aa".into());
            vta_sdk::trust_task_sign::sign_in_place(
                &mut doc,
                &f.owner.did,
                &f.owner.secret_multibase,
            )
            .await
            .expect("sign the request");
            serde_json::to_string(&doc).expect("serialise")
        };
        let document = request().await;

        // Over HTTP, through the router.
        let http = app
            .clone()
            .oneshot(
                Request::post("/trust-tasks")
                    .header("content-type", "application/json")
                    .body(Body::from(document.clone()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let http_status = http.status();
        let http_body: Value = serde_json::from_slice(
            &axum::body::to_bytes(http.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();

        // Straight into `dispatch`, which is what a mediator listener does.
        let document = request().await;
        let carried = dispatch(&st, document.as_bytes()).await;

        assert_eq!(http_status, StatusCode::OK, "{http_body}");
        assert_eq!(
            carried.status, 200,
            "the status is derived from the document, so both carriers agree on it"
        );
        // Guard the guard: comparing fields neither document has would pass while asserting
        // nothing, and the framework's field names are not this crate's to choose.
        // Everything that says *what happened* and *to whom*. `id` and `issuedAt` are
        // per-answer and correctly differ between two dispatches of one request.
        let says_what_happened = ["type", "payload", "threadId", "recipient", "issuer"];
        for field in says_what_happened {
            assert!(
                http_body.get(field).is_some(),
                "the response document has no `{field}` to compare — this test would pass \
                 vacuously: {http_body}"
            );
        }
        for field in says_what_happened {
            assert_eq!(
                http_body.get(field),
                carried.document.get(field),
                "`{field}` must not depend on the carrier"
            );
        }
    }

    /// **A TSP reply is the document, with nothing around it.**
    ///
    /// This host used to wrap it as `{ thid, document }`, on the reasoning that TSP has no
    /// headers so correlation had to be added. It does not: a routed response carries its own
    /// `threadId`, set to the request's `id`. The wrapper said the same thing twice and made
    /// this host's replies unreadable to a client written against `vtc-service`, which sends
    /// the document bare — two hosts of one protocol disagreeing about the wire.
    ///
    /// Asserted as a property of `dispatch` rather than of a framing function, because there
    /// is no longer a framing function and that is the point.
    #[tokio::test]
    async fn a_tsp_answer_is_the_document_and_threads_on_the_request() {
        let (_dir, st) = state();
        let app = router(st.clone());
        let f = RoomFixture::new(Visibility::Open).await;
        register(&app, &f).await;

        let document = vta_sdk::trust_task_sign::build_signed(
            vti_rooms::wire::ROOMS_RECORDS_LIST_V5_TYPE,
            serde_json::json!({ "roomId": f.room.room_id, "presentation": f.as_owner() }),
            &f.owner.did,
            &f.owner.secret_multibase,
            "did:key:zHost",
        )
        .await
        .unwrap();
        let request_id: Value = serde_json::from_str(&document).unwrap();
        let request_id = request_id["id"].as_str().unwrap().to_string();

        // What the TSP arm sends is exactly this — `send_tsp` serialises it unchanged.
        let answer = dispatch(&st, document.as_bytes()).await.document;

        assert_eq!(
            answer["threadId"], request_id,
            "the document threads itself, which is why nothing needs to wrap it"
        );
        assert!(
            answer.get("thid").is_none(),
            "and it carries no second, disagreeing copy of that: {answer}"
        );
    }

    /// `rooms/create/0.2` declares `retentionPolicy`, and `rooms/owner/register/0.2`
    /// passes it on. A host that refused the member as unknown refused every room an
    /// owner asked to keep from-join — and one that ignored it would store epoch links the
    /// room said it would not have.
    #[tokio::test]
    async fn a_room_registered_from_join_is_stored_so() {
        let (_d, st) = state();
        let app = router(st.clone());
        let f = RoomFixture::new(Visibility::Attributed).await;
        let (status, body) = call(
            &app,
            vti_rooms::wire::ROOMS_CREATE_V2_TYPE,
            serde_json::json!({
                "roomId": f.room.room_id,
                "ownerDid": f.room.owner_did,
                "visibility": f.room.visibility,
                "retentionPolicy": "fromJoin",
                "ext": { "org.example": { "note": "ignored" } },
            }),
            &f.owner,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let room = vti_rooms::storage::get_room(st.rooms(), &f.room.room_id)
            .await
            .unwrap();
        assert_eq!(room.retention_policy, vti_rooms::RetentionPolicy::FromJoin);
        assert!(!room.retention_policy.links_epochs());
    }

    /// Registration is the one verb no chain can authorize, so the proof on the request
    /// is the whole of its defence — and `ownerDid` is a payload field until something
    /// checks it against the signer.
    #[tokio::test]
    async fn a_room_cannot_be_registered_in_somebody_elses_name() {
        let (_d, st) = state();
        let app = router(st.clone());
        let f = RoomFixture::new(Visibility::Open).await;
        let mallory = Party::new();

        let (status, body) = call(
            &app,
            vti_rooms::wire::ROOMS_CREATE_V2_TYPE,
            serde_json::json!({
                "roomId": f.room.room_id,
                "ownerDid": f.room.owner_did,
                "visibility": f.room.visibility,
            }),
            &mallory,
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");

        // And nothing was stored: a refused registration must not leave the id taken,
        // or refusing it would still deny the room to its owner.
        assert!(
            vti_rooms::storage::get_room(st.rooms(), &f.room.room_id)
                .await
                .is_err(),
            "a refused registration must not create the room"
        );

        // The owner's own registration still works, which is what makes the check a gate
        // rather than a wall.
        register(&app, &f).await;
    }

    /// Register `room_id` for `owner`, signed by `owner`.
    async fn create_as(app: &Router, room_id: &str, owner: &Party) -> (StatusCode, Value) {
        call(
            app,
            vti_rooms::wire::ROOMS_CREATE_V2_TYPE,
            serde_json::json!({
                "roomId": room_id,
                "ownerDid": owner.did,
                "visibility": "open",
            }),
            owner,
        )
        .await
    }

    #[tokio::test]
    async fn a_host_that_names_no_creator_registers_no_room() {
        let (_d, st) = state();
        st.set_room_creation(creation::RoomCreation {
            creators: creation::Creators::None,
            ..Default::default()
        });
        let app = router(st.clone());
        let f = RoomFixture::new(Visibility::Open).await;
        let (status, body) = create_as(&app, &f.room.room_id, &f.owner).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
        assert!(
            vti_rooms::storage::get_room(st.rooms(), &f.room.room_id)
                .await
                .is_err(),
            "a refused registration must not create the room"
        );
    }

    #[tokio::test]
    async fn only_a_named_creator_registers_rooms() {
        let (_d, st) = state();
        let f = RoomFixture::new(Visibility::Open).await;
        st.set_room_creation(creation::RoomCreation {
            creators: creation::Creators::Only([f.owner.did.clone()].into_iter().collect()),
            ..Default::default()
        });
        let app = router(st.clone());
        register(&app, &f).await;

        let other = RoomFixture::new(Visibility::Open).await;
        let (status, body) = create_as(&app, &other.room.room_id, &other.owner).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    }

    #[tokio::test]
    async fn an_owner_holds_at_most_its_ceiling_of_rooms() {
        let (_d, st) = state();
        st.set_room_creation(creation::RoomCreation {
            creators: creation::Creators::Any,
            max_rooms_per_owner: 1,
            max_rooms: 100,
        });
        let app = router(st.clone());
        let f = RoomFixture::new(Visibility::Open).await;
        register(&app, &f).await;

        let second = RoomFixture::new(Visibility::Open).await;
        let (status, body) = create_as(&app, &second.room.room_id, &f.owner).await;
        assert_ne!(status, StatusCode::OK, "{body}");
        assert!(body.to_string().contains("roomsPerOwner"), "{body}");
        assert!(
            vti_rooms::storage::get_room(st.rooms(), &second.room.room_id)
                .await
                .is_err()
        );

        // Another owner is not held to the first one's count.
        register(&app, &second).await;
    }

    #[tokio::test]
    async fn the_host_holds_at_most_its_ceiling_of_rooms() {
        let (_d, st) = state();
        st.set_room_creation(creation::RoomCreation {
            creators: creation::Creators::Any,
            max_rooms_per_owner: 10,
            max_rooms: 1,
        });
        let app = router(st.clone());
        let f = RoomFixture::new(Visibility::Open).await;
        register(&app, &f).await;

        let second = RoomFixture::new(Visibility::Open).await;
        let (status, body) = create_as(&app, &second.room.room_id, &second.owner).await;
        assert_ne!(status, StatusCode::OK, "{body}");
        assert!(body.to_string().contains("\"rooms\""), "{body}");
    }

    /// A repeat of a registration is answered as already registered, not as a
    /// ceiling the room already counts toward.
    #[tokio::test]
    async fn a_repeat_registration_is_already_registered_even_at_the_ceiling() {
        let (_d, st) = state();
        st.set_room_creation(creation::RoomCreation {
            creators: creation::Creators::Any,
            max_rooms_per_owner: 1,
            max_rooms: 1,
        });
        let app = router(st.clone());
        let f = RoomFixture::new(Visibility::Open).await;
        register(&app, &f).await;
        let (status, body) = create_as(&app, &f.room.room_id, &f.owner).await;
        assert_ne!(status, StatusCode::OK, "{body}");
        assert!(body.to_string().contains("already registered"), "{body}");
    }

    /// Two registrations racing for the last slot: exactly one gets it.
    #[tokio::test]
    async fn concurrent_registrations_never_overshoot_the_ceiling() {
        let (_d, st) = state();
        st.set_room_creation(creation::RoomCreation {
            creators: creation::Creators::Any,
            max_rooms_per_owner: 10,
            max_rooms: 1,
        });
        let app = router(st.clone());
        let (a, b) = (
            RoomFixture::new(Visibility::Open).await,
            RoomFixture::new(Visibility::Open).await,
        );
        let ((sa, _), (sb, _)) = tokio::join!(
            create_as(&app, &a.room.room_id, &a.owner),
            create_as(&app, &b.room.room_id, &b.owner)
        );
        assert_eq!(
            [sa, sb].iter().filter(|s| **s == StatusCode::OK).count(),
            1,
            "{sa} {sb}"
        );
        assert_eq!(
            vti_rooms::storage::list_rooms(st.rooms())
                .await
                .unwrap()
                .len(),
            1
        );
    }

    /// A room removed through [`HostState::rooms`] frees its slot at once: the kept
    /// counts are not relied on past a change made there.
    #[tokio::test]
    async fn a_room_removed_by_the_embedder_frees_its_slot_at_once() {
        let (_d, st) = state();
        st.set_room_creation(creation::RoomCreation {
            creators: creation::Creators::Any,
            max_rooms_per_owner: 10,
            max_rooms: 1,
        });
        let app = router(st.clone());
        let (a, b) = (
            RoomFixture::new(Visibility::Open).await,
            RoomFixture::new(Visibility::Open).await,
        );
        register(&app, &a).await;
        let (status, body) = create_as(&app, &b.room.room_id, &b.owner).await;
        assert_ne!(status, StatusCode::OK, "at the ceiling: {body}");

        vti_rooms::storage::purge_room_rows(
            st.rooms(),
            &st.records,
            &st.epoch_links,
            &st.revocations,
            &a.room.room_id,
        )
        .await
        .unwrap();
        register(&app, &b).await;
    }

    /// Refused registrations are logged at most once a minute, the rest counted.
    #[test]
    fn refused_registrations_are_logged_at_a_bounded_rate() {
        let (_d, st) = state();
        let refused = creation::CreationRefused::NotACreator;
        st.log_refused_registration("did:key:zA", &refused);
        st.log_refused_registration("did:key:zB", &refused);
        st.log_refused_registration("did:key:zC", &refused);
        let log = st.refusal_log.lock().unwrap();
        assert!(log.last.is_some());
        assert_eq!(log.unlogged, 2);
    }

    /// `open_state` registers nothing until its embedder says who may (R5.1).
    #[tokio::test]
    async fn a_host_registers_no_room_until_told_who_may() {
        let dir = tempfile::tempdir().unwrap();
        let st = open_state(dir.path()).expect("open store");
        let app = router(st.clone());
        let f = RoomFixture::new(Visibility::Open).await;
        let (status, body) = create_as(&app, &f.room.room_id, &f.owner).await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "the default is closed: {body}"
        );
    }

    /// A document with no proof has no presenter, and a registration nobody signed
    /// records an owner nobody proved.
    #[tokio::test]
    async fn an_unsigned_registration_is_refused() {
        let (_d, st) = state();
        let app = router(st);
        let f = RoomFixture::new(Visibility::Open).await;

        let doc = serde_json::json!({
            "id": "urn:uuid:unsigned",
            "type": vti_rooms::wire::ROOMS_CREATE_V2_TYPE,
            "issuer": f.room.owner_did,
            "recipient": "did:key:zHost",
            "payload": {
                "roomId": f.room.room_id,
                "ownerDid": f.room.owner_did,
                "visibility": f.room.visibility,
            },
        });
        let resp = app
            .oneshot(
                Request::post("/trust-tasks")
                    .header("content-type", "application/json")
                    .body(Body::from(doc.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_ne!(
            resp.status(),
            StatusCode::OK,
            "an unsigned registration must not be accepted"
        );
    }

    #[tokio::test]
    async fn a_record_round_trips_under_a_chain_the_room_issued() {
        let (_d, st) = state();
        let app = router(st);
        let f = RoomFixture::new(Visibility::Open).await;
        register(&app, &f).await;

        let (status, body) = call(
            &app,
            vti_rooms::wire::ROOMS_RECORDS_PUT_V3_TYPE,
            serde_json::json!({
                "roomId": f.room.room_id,
                "key": "decision/pricing",
                "presentation": f.as_owner(),
                "cleartext": { "body": "a decision" },
            }),
            &f.owner,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["version"], 1);

        let (status, body) = call(
            &app,
            vti_rooms::wire::ROOMS_RECORDS_GET_V2_TYPE,
            serde_json::json!({
                "roomId": f.room.room_id,
                "key": "decision/pricing",
                "presentation": f.as_owner(),
            }),
            &f.owner,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["cleartext"]["body"], "a decision");
        assert_eq!(
            body["author"], f.owner.did,
            "the author is the verified subject, not the room's owner field"
        );
    }

    /// POST bytes verbatim, so the *same* document can be delivered twice.
    ///
    /// `call` re-signs, which mints a fresh `id` each time and so can never express a
    /// redelivery — the thing every carrier here actually does.
    async fn post_raw(app: &Router, doc: &[u8]) -> (StatusCode, Value) {
        let resp = app
            .clone()
            .oneshot(
                Request::post("/trust-tasks")
                    .header("content-type", "application/json")
                    .body(Body::from(doc.to_vec()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        // The routed document's `payload`, as `call` returns — the reply's own `id` is a
        // fresh uuid per answer, so comparing whole documents would never match.
        let doc: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        (status, doc.get("payload").cloned().unwrap_or(Value::Null))
    }

    /// SPEC §7.2 item 11. Live delivery is at-least-once — the mediator re-pushes an
    /// undelivered inbox on every live-delivery activation and every socket replacement —
    /// so the same signed `put` arrives twice as routine traffic. It must be written once.
    ///
    /// The proof does not catch this: the redelivered copy carries the same valid proof,
    /// because it is the same document.
    #[tokio::test]
    async fn a_redelivered_write_is_executed_once() {
        let (_d, st) = state();
        let app = router(st);
        let f = RoomFixture::new(Visibility::Open).await;
        register(&app, &f).await;

        let doc = vta_sdk::trust_task_sign::build_signed(
            vti_rooms::wire::ROOMS_RECORDS_PUT_V3_TYPE,
            serde_json::json!({
                "roomId": f.room.room_id,
                "key": "decision/pricing",
                "presentation": f.as_owner(),
                "cleartext": { "body": "a decision" },
            }),
            &f.owner.did,
            &f.owner.secret_multibase,
            "did:key:zHost",
        )
        .await
        .expect("sign the request");

        let (status, first) = post_raw(&app, doc.as_bytes()).await;
        assert_eq!(status, StatusCode::OK, "{first}");
        assert_eq!(first["version"], 1);

        let (status, second) = post_raw(&app, doc.as_bytes()).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "a duplicate is never a failure — the task did not fail, it already happened: \
             {second}"
        );
        assert_eq!(
            second, first,
            "the duplicate must be answered with the original result, not re-executed"
        );

        // The claim is what proves it: a second execution would have made version 2.
        let (status, body) = call(
            &app,
            vti_rooms::wire::ROOMS_RECORDS_GET_V2_TYPE,
            serde_json::json!({
                "roomId": f.room.room_id,
                "key": "decision/pricing",
                "presentation": f.as_owner(),
            }),
            &f.owner,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["version"], 1, "the record was written twice");
    }

    /// **VTI-OPS-029.** The record survives a restart. A write accepted before the host
    /// restarts is still inside its acceptance window after it, and a redelivery then must
    /// be answered from the record, not written again. With the record in memory the
    /// second process had never seen the document and wrote version 2.
    #[tokio::test]
    async fn a_write_redelivered_after_a_restart_is_executed_once() {
        let dir = tempfile::tempdir().unwrap();
        let f = RoomFixture::new(Visibility::Open).await;
        let doc = vta_sdk::trust_task_sign::build_signed(
            vti_rooms::wire::ROOMS_RECORDS_PUT_V3_TYPE,
            serde_json::json!({
                "roomId": f.room.room_id,
                "key": "decision/pricing",
                "presentation": f.as_owner(),
                "cleartext": { "body": "a decision" },
            }),
            &f.owner.did,
            &f.owner.secret_multibase,
            "did:key:zHost",
        )
        .await
        .expect("sign the request");

        let first = {
            let st = open_state(dir.path()).expect("open store");
            st.set_room_creation(crate::creation::RoomCreation::any_creator());
            let app = router(st.clone());
            register(&app, &f).await;
            let (status, first) = post_raw(&app, doc.as_bytes()).await;
            assert_eq!(status, StatusCode::OK, "{first}");
            assert_eq!(first["version"], 1);
            // In the store, not the process: a static map would also pass the rest of
            // this test, which runs both "processes" in one.
            let id = serde_json::from_str::<Value>(&doc).unwrap()["id"]
                .as_str()
                .unwrap()
                .to_string();
            assert!(
                st.accepted_ids
                    .get_raw(format!("accepted:{id}").into_bytes())
                    .await
                    .unwrap()
                    .is_some(),
                "the accepted id is recorded in the host's store"
            );
            first
        };

        // The first process is gone; its store is all that remains.
        let app = router(open_state(dir.path()).expect("reopen store"));
        let (status, second) = post_raw(&app, doc.as_bytes()).await;
        assert_eq!(status, StatusCode::OK, "{second}");
        assert_eq!(
            second, first,
            "answered with the original result, not executed again"
        );
        let (status, body) = call(
            &app,
            vti_rooms::wire::ROOMS_RECORDS_GET_V2_TYPE,
            serde_json::json!({
                "roomId": f.room.room_id,
                "key": "decision/pricing",
                "presentation": f.as_owner(),
            }),
            &f.owner,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(
            body["version"], 1,
            "the record was written twice across the restart"
        );
    }

    /// A *different* document under an already-spent `id` is a conflict, not a retry.
    /// Digest-keyed precisely so the two are distinguishable; absorbing the second as a
    /// duplicate is the one outcome §7.2 rules out.
    #[tokio::test]
    async fn a_different_document_reusing_an_id_is_refused() {
        let (_d, st) = state();
        let app = router(st);
        let f = RoomFixture::new(Visibility::Open).await;
        register(&app, &f).await;

        let sign = async |body: &str| {
            vta_sdk::trust_task_sign::build_signed(
                vti_rooms::wire::ROOMS_RECORDS_PUT_V3_TYPE,
                serde_json::json!({
                    "roomId": f.room.room_id,
                    "key": "decision/pricing",
                    "presentation": f.as_owner(),
                    "cleartext": { "body": body },
                }),
                &f.owner.did,
                &f.owner.secret_multibase,
                "did:key:zHost",
            )
            .await
            .expect("sign the request")
        };

        let first = sign("a decision").await;
        let (status, _) = post_raw(&app, first.as_bytes()).await;
        assert_eq!(status, StatusCode::OK);

        // Same id, different content.
        let id = serde_json::from_str::<Value>(&first).unwrap()["id"]
            .as_str()
            .unwrap()
            .to_string();
        let mut second: Value = serde_json::from_str(&sign("a different decision").await).unwrap();
        second["id"] = Value::String(id);
        let (status, body) = post_raw(&app, serde_json::to_vec(&second).unwrap().as_slice()).await;

        assert_ne!(
            status,
            StatusCode::OK,
            "a different document under a spent id must not be served: {body}"
        );
    }

    /// Every document is recorded, reads included (SPEC §7.2 item 11, as the VTC's spine
    /// applies it). A captured read replayed inside its window is not answered again — with
    /// the room as it is *now*, to whoever replays it — and its first answer is not kept to
    /// be handed back either: a duplicate read is `204`, with nothing in it.
    #[tokio::test]
    async fn a_replayed_read_is_refused() {
        let (_d, st) = state();
        let app = router(st);
        let f = RoomFixture::new(Visibility::Open).await;
        register(&app, &f).await;

        let doc = vta_sdk::trust_task_sign::build_signed(
            vti_rooms::wire::ROOMS_RECORDS_LIST_V5_TYPE,
            serde_json::json!({ "roomId": f.room.room_id, "presentation": f.as_owner() }),
            &f.owner.did,
            &f.owner.secret_multibase,
            "did:key:zHost",
        )
        .await
        .expect("sign the request");

        let (first_status, first) = post_raw(&app, doc.as_bytes()).await;
        let (second_status, second) = post_raw(&app, doc.as_bytes()).await;

        assert_eq!(first_status, StatusCode::OK, "{first}");
        assert_eq!(
            second_status,
            StatusCode::NO_CONTENT,
            "a replayed read must not be answered: {second}"
        );
        assert_eq!(second, Value::Null, "and must carry nothing: {second}");

        // A fresh document for the same read is answered: the record is per document,
        // not per question.
        let (status, again) = call(
            &app,
            vti_rooms::wire::ROOMS_RECORDS_LIST_V5_TYPE,
            serde_json::json!({ "roomId": f.room.room_id, "presentation": f.as_owner() }),
            &f.owner,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{again}");
    }

    /// A list request from the owner, built unsigned so a test can set what `build_signed`
    /// fixes, then signed as `signer`.
    async fn list_doc(
        f: &RoomFixture,
        signer: &Party,
        edit: impl FnOnce(&mut TrustTask<Value>),
    ) -> Vec<u8> {
        let mut doc = vta_sdk::trust_task_sign::build_unsigned(
            vti_rooms::wire::ROOMS_RECORDS_LIST_V5_TYPE,
            serde_json::json!({ "roomId": f.room.room_id, "presentation": f.as_owner() }),
            &f.owner.did,
            "did:key:zHost",
        )
        .expect("build");
        edit(&mut doc);
        vta_sdk::trust_task_sign::sign_in_place(&mut doc, &signer.did, &signer.secret_multibase)
            .await
            .expect("sign");
        serde_json::to_vec(&doc).expect("serialise")
    }

    /// The spine checks the VTC applies to every document, applied here too (framework
    /// SPEC §7.2 items 4, 5 and 13). Each document is otherwise one the host answers.
    #[tokio::test]
    async fn stale_expired_and_misaddressed_documents_are_refused() {
        let (_d, st) = state();
        st.set_host_did("did:key:zHost").expect("bind the host DID");
        let app = router(st);
        let f = RoomFixture::new(Visibility::Open).await;
        register(&app, &f).await;
        let now = chrono::Utc::now();

        // The control: in its window, addressed to this host.
        let ok = list_doc(&f, &f.owner, |_| {}).await;
        let (status, body) = post_raw(&app, &ok).await;
        assert_eq!(status, StatusCode::OK, "{body}");

        type Edit = Box<dyn FnOnce(&mut TrustTask<Value>)>;
        let cases: [(&str, Edit); 4] = [
            (
                "stale: issued an hour ago",
                Box::new(move |d| d.issued_at = Some(now - chrono::Duration::hours(1))),
            ),
            (
                "expired",
                Box::new(move |d| {
                    d.issued_at = Some(now - chrono::Duration::minutes(1));
                    d.expires_at = Some(now - chrono::Duration::seconds(10));
                }),
            ),
            ("no issuedAt", Box::new(|d| d.issued_at = None)),
            (
                "addressed to another host",
                Box::new(|d| d.recipient = Some("did:key:zSomeOtherHost".into())),
            ),
        ];
        for (why, edit) in cases {
            let doc = list_doc(&f, &f.owner, edit).await;
            let (status, body) = post_raw(&app, &doc).await;
            assert!(
                status.is_client_error(),
                "{why}: must be refused, got {status}: {body}"
            );
            assert!(
                body.get("code").is_some(),
                "{why}: a routed refusal: {body}"
            );
        }
    }

    /// A document whose proof verifies under a key its `issuer` does not control is
    /// refused (SPEC §4.7): the agent signs a document that names the owner as issuer.
    #[tokio::test]
    async fn a_document_signed_by_anyone_but_its_issuer_is_refused() {
        let (_d, st) = state();
        let app = router(st);
        let f = RoomFixture::new(Visibility::Open).await;
        register(&app, &f).await;

        let doc = list_doc(&f, &f.agent, |d| {
            if let Value::Object(p) = &mut d.payload {
                p.insert(
                    "presentation".into(),
                    serde_json::to_value(f.as_agent()).unwrap(),
                );
            }
        })
        .await;
        let (status, body) = post_raw(&app, &doc).await;
        // The spine's refusal, as the VTC gives it: the proof is not the issuer's, so it
        // proves nothing about the document (`proofInvalid`).
        assert!(status.is_client_error(), "{status}: {body}");
        assert_eq!(body["code"], "proofInvalid", "{body}");
    }

    /// The arrangement the whole design exists for, end to end through a host.
    #[tokio::test]
    async fn an_agent_reads_under_a_narrower_chain_and_cannot_write() {
        let (_d, st) = state();
        let app = router(st);
        let f = RoomFixture::new(Visibility::Open).await;
        register(&app, &f).await;
        call(
            &app,
            vti_rooms::wire::ROOMS_RECORDS_PUT_V3_TYPE,
            serde_json::json!({
                "roomId": f.room.room_id,
                "key": "k",
                "presentation": f.as_owner(),
                "cleartext": { "body": "for the agent to read" },
            }),
            &f.owner,
        )
        .await;

        let (status, body) = call(
            &app,
            vti_rooms::wire::ROOMS_RECORDS_GET_V2_TYPE,
            serde_json::json!({
                "roomId": f.room.room_id,
                "key": "k",
                "presentation": f.as_agent(),
            }),
            &f.agent,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "the agent reads: {body}");

        let (status, body) = call(
            &app,
            vti_rooms::wire::ROOMS_RECORDS_PUT_V3_TYPE,
            serde_json::json!({
                "roomId": f.room.room_id,
                "key": "k2",
                "presentation": f.as_agent(),
                "cleartext": { "body": "but it must not write" },
            }),
            &f.agent,
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    }

    /// VTI-ACL-110: a chain stating purposes is held to them on every read. get/0.4 names
    /// the purpose; a purpose the chain does not grant is `purposeNotGranted`, and an earlier
    /// version — which cannot name one — is refused where the chain lists more than one.
    #[tokio::test]
    async fn vti_acl_110_a_read_is_held_to_the_purposes_its_chain_grants() {
        use dtg_credentials::purposes::PurposeScope;
        let (_d, st) = state();
        let app = router(st);
        let f = RoomFixture::new(Visibility::Open).await;
        register(&app, &f).await;
        call(
            &app,
            vti_rooms::wire::ROOMS_RECORDS_PUT_V3_TYPE,
            serde_json::json!({
                "roomId": f.room.room_id,
                "key": "k",
                "presentation": f.as_owner(),
                "cleartext": { "body": "for one purpose only" },
            }),
            &f.owner,
        )
        .await;
        let get = |uri: &'static str,
                   presentation: vti_rooms::wire::AuthorityPresentation,
                   purpose: Option<&str>| {
            let mut payload = serde_json::json!({
                "roomId": f.room.room_id,
                "key": "k",
                "presentation": presentation,
            });
            if let Some(p) = purpose {
                payload["purpose"] = serde_json::json!(p);
            }
            let app = app.clone();
            let agent = &f.agent;
            async move { call(&app, uri, payload, agent).await }
        };
        const V4: &str = vti_rooms::wire::ROOMS_RECORDS_GET_V4_TYPE;
        const V3: &str = vti_rooms::wire::ROOMS_RECORDS_GET_V3_TYPE;

        let one = f
            .as_agent_for(PurposeScope::listed(["taskExecution"]))
            .await;
        let (status, body) = get(V4, one.clone(), Some("taskExecution")).await;
        assert_eq!(status, StatusCode::OK, "the granted purpose: {body}");
        let (status, body) = get(V4, one.clone(), None).await;
        assert_eq!(status, StatusCode::OK, "the only purpose applies: {body}");
        let (status, body) = get(V3, one.clone(), None).await;
        assert_eq!(status, StatusCode::OK, "so it does to get/0.3: {body}");
        let (_, body) = get(V4, one, Some("analytics")).await;
        assert_eq!(
            body["code"], "rooms/records/get:purposeNotGranted",
            "{body}"
        );
        assert_eq!(
            body["details"],
            serde_json::json!({ "purposeNamed": true, "purpose": "analytics" }),
            "{body}"
        );
        assert!(body.get("cleartext").is_none(), "no content: {body}");

        let two = f
            .as_agent_for(PurposeScope::listed(["taskExecution", "personalisation"]))
            .await;
        let (_, body) = get(V4, two.clone(), None).await;
        assert_eq!(
            body["code"], "rooms/records/get:purposeNotGranted",
            "{body}"
        );
        assert_eq!(
            body["details"],
            serde_json::json!({ "purposeNamed": false })
        );
        let (_, body) = get(V3, two.clone(), None).await;
        assert_eq!(
            body["code"], "permissionDenied",
            "get/0.3 cannot name one: {body}"
        );
        let (status, body) = get(V4, two, Some("personalisation")).await;
        assert_eq!(status, StatusCode::OK, "{body}");

        // A chain stating none grants `any`, which never grants model training.
        let (status, body) = get(V4, f.as_agent(), Some("analytics")).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let (_, body) = get(V4, f.as_agent(), Some("modelTraining")).await;
        assert_eq!(
            body["code"], "rooms/records/get:purposeNotGranted",
            "{body}"
        );
    }

    /// A presentation is not a bearer token: the agent's chain, presented by its human.
    #[tokio::test]
    async fn a_captured_presentation_does_not_work_for_someone_else() {
        let (_d, st) = state();
        let app = router(st);
        let f = RoomFixture::new(Visibility::Open).await;
        register(&app, &f).await;

        let (status, body) = call(
            &app,
            vti_rooms::wire::ROOMS_RECORDS_GET_V2_TYPE,
            serde_json::json!({
                "roomId": f.room.room_id,
                "key": "k",
                "presentation": f.as_agent(),
            }),
            &f.owner,
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    }

    /// A stranger with a perfectly valid chain of their own gets nothing here — because the
    /// chain does not reach *this* room.
    #[tokio::test]
    async fn a_chain_from_another_room_confers_nothing() {
        let (_d, st) = state();
        let app = router(st);
        let f = RoomFixture::new(Visibility::Open).await;
        let elsewhere = RoomFixture::new(Visibility::Open).await;
        register(&app, &f).await;

        let (status, body) = call(
            &app,
            vti_rooms::wire::ROOMS_RECORDS_GET_V2_TYPE,
            serde_json::json!({
                "roomId": f.room.room_id,
                "key": "k",
                "presentation": elsewhere.as_owner(),
            }),
            &elsewhere.owner,
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    }

    #[tokio::test]
    async fn an_operation_with_no_chain_is_refused() {
        let (_d, st) = state();
        let app = router(st);
        let f = RoomFixture::new(Visibility::Open).await;
        register(&app, &f).await;

        let (status, _) = call(
            &app,
            vti_rooms::wire::ROOMS_RECORDS_PUT_V3_TYPE,
            serde_json::json!({
                "roomId": f.room.room_id,
                "key": "k",
                "presentation": { "membership": f.membership, "authority": [] },
                "cleartext": { "body": "x" },
            }),
            &f.owner,
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    }

    /// A private room is refused with the message `vti-rooms-dtg` gives it, which is the
    /// same message a VTC gives — the two cannot disagree about what is safe to serve.
    #[tokio::test]
    async fn a_private_room_is_refused_for_want_of_a_zk_profile() {
        let (_d, st) = state();
        let app = router(st);
        let f = RoomFixture::new(Visibility::Private).await;
        register(&app, &f).await;

        let mut p = f.as_owner();
        p.subject_binding = Some("a-binding-nobody-can-check".into());

        let (status, body) = call(
            &app,
            vti_rooms::wire::ROOMS_RECORDS_GET_V2_TYPE,
            serde_json::json!({
                "roomId": f.room.room_id,
                "key": "k",
                "presentation": p,
            }),
            &f.owner,
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert!(
            body["message"]
                .as_str()
                .unwrap_or_default()
                .contains("zero-knowledge profile"),
            "{body}"
        );
    }

    #[tokio::test]
    async fn a_listing_returns_metadata_and_never_bodies() {
        let (_d, st) = state();
        let app = router(st);
        let f = RoomFixture::new(Visibility::Open).await;
        register(&app, &f).await;
        call(
            &app,
            vti_rooms::wire::ROOMS_RECORDS_PUT_V3_TYPE,
            serde_json::json!({
                "roomId": f.room.room_id,
                "key": "a",
                "presentation": f.as_owner(),
                "cleartext": { "body": "secret-body-text" },
            }),
            &f.owner,
        )
        .await;

        let (status, body) = call(
            &app,
            vti_rooms::wire::ROOMS_RECORDS_LIST_V5_TYPE,
            serde_json::json!({
                "roomId": f.room.room_id,
                "presentation": f.as_owner(),
            }),
            &f.owner,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let text = body.to_string();
        assert!(text.contains("\"key\""));
        assert!(
            !text.contains("secret-body-text"),
            "a listing must never carry bodies: {text}"
        );
    }

    #[tokio::test]
    async fn an_unknown_task_is_not_served() {
        let (_d, st) = state();
        let (status, body) = call(
            &router(st),
            "https://trusttasks.org/spec/vtc/members/list/0.2",
            serde_json::json!({}),
            &Party::new(),
        )
        .await;
        assert!(
            !status.is_success(),
            "a room host serves rooms and nothing else"
        );
        assert_eq!(
            body["code"], "unsupportedType",
            "and says so with the framework's own code: {body}"
        );
    }

    /// Register `f`'s room with a chosen epoch expiry, bypassing the create handler.
    ///
    /// Succession is entirely about the passage of time, and the only honest way to test it
    /// without waiting a year is to write the room in the state a year would produce.
    async fn register_expiring(
        st: &Arc<HostState>,
        f: &RoomFixture,
        epoch_expires_at: Option<u64>,
    ) {
        let room = Room {
            epoch_expires_at,
            ..f.room.clone()
        };
        storage::create_room(&st.rooms, &room)
            .await
            .expect("register the room");
    }

    /// Take what `audit_room` recorded on this thread since the last call.
    fn take_audited() -> Vec<&'static str> {
        AUDITED.with(|audited| std::mem::take(&mut *audited.borrow_mut()))
    }

    /// `rooms/epoch/prune/0.2`: `admin` only (a `read` chain is `permissionDenied`), a floor
    /// at or above the current epoch is refused (`notAhead`), and a prune that runs is
    /// audited as `room.epoch.prune` — never as the mint it used to be logged as.
    #[tokio::test]
    async fn a_prune_needs_admin_and_is_audited_as_a_prune() {
        // The test runtime is current-thread, so the host's handlers run on this thread
        // and record to this thread's trail.
        let (_d, st) = state();
        let app = router(st);
        let f = RoomFixture::new(Visibility::Open).await;
        register(&app, &f).await;

        // Advance once, so there is an epoch below the current one to prune to.
        let (status, minted) = call(
            &app,
            ROOMS_EPOCH_MINT_TYPE,
            serde_json::json!({
                "roomId": f.room.room_id,
                "epoch": f.room.epoch + 1,
                "presentation": f.as_owner(),
            }),
            &f.owner,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{minted}");
        let current = minted["epoch"].as_u64().unwrap();
        take_audited();

        // The agent's chain confers `read` only: refused, and nothing audited.
        let (status, body) = call(
            &app,
            vti_rooms::wire::ROOMS_EPOCH_PRUNE_V2_TYPE,
            serde_json::json!({
                "roomId": f.room.room_id,
                "beforeEpoch": current - 1,
                "presentation": f.as_agent(),
                "reason": "not mine to decide",
            }),
            &f.agent,
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
        assert!(
            !take_audited().contains(&"room.epoch.prune"),
            "a refused prune must not be audited as one"
        );

        // The owner, at the current epoch: the whole chain would go, so it is refused.
        let (status, body) = call(
            &app,
            vti_rooms::wire::ROOMS_EPOCH_PRUNE_V2_TYPE,
            serde_json::json!({
                "roomId": f.room.room_id,
                "beforeEpoch": current,
                "presentation": f.as_owner(),
            }),
            &f.owner,
        )
        .await;
        assert_ne!(
            status,
            StatusCode::OK,
            "pruning to the current epoch: {body}"
        );
        assert_eq!(body["code"], "rooms/epoch/prune:notAhead", "{body}");
        assert_eq!(body["details"]["epoch"].as_u64(), Some(current), "{body}");

        // The owner, below it: performed, and audited as what it was.
        take_audited();
        let (status, body) = call(
            &app,
            vti_rooms::wire::ROOMS_EPOCH_PRUNE_V2_TYPE,
            serde_json::json!({
                "roomId": f.room.room_id,
                "beforeEpoch": current - 1,
                "presentation": f.as_owner(),
                "reason": "retention: past the agreed window",
            }),
            &f.owner,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["roomId"], f.room.room_id);
        assert!(
            body["pruned"].is_u64() && body["earliestRung"].is_u64(),
            "{body}"
        );
        let logged = take_audited();
        assert!(
            logged.contains(&"room.epoch.prune"),
            "the prune must be audited as a prune: {logged:?}"
        );
        assert!(
            !logged.contains(&"room.epoch.mint"),
            "a prune is not a mint: {logged:?}"
        );
    }

    /// `rooms/epoch/prune/0.2` and `rooms/epoch/chain/0.2` (trust-tasks-tf #869): the host
    /// keeps the room's epoch floor — `beforeEpoch − 1`, raised by either version, never
    /// lowered — returns it, serves it on every chain response (an empty one included),
    /// and never serves a rung at or below it, at 0.1 either.
    #[tokio::test]
    async fn the_host_keeps_the_epoch_floor_and_never_serves_below_it() {
        let (_d, st) = state();
        let app = router(st.clone());
        let f = RoomFixture::new(Visibility::Open).await;
        register(&app, &f).await;
        for epoch in 2..=5u32 {
            let (status, out) = call(
                &app,
                ROOMS_EPOCH_MINT_TYPE,
                serde_json::json!({
                    "roomId": f.room.room_id, "epoch": epoch, "presentation": f.as_owner(),
                    "link": { "epoch": epoch, "wrapped": format!("d3JhcHBlZA{epoch}"), "nonce": "bm9uY2U" },
                }),
                &f.owner,
            )
            .await;
            assert_eq!(status, StatusCode::OK, "{out}");
        }
        let prune = |version: &str, before: u32| {
            (
                format!("https://trusttasks.org/spec/rooms/epoch/prune/{version}"),
                serde_json::json!({
                    "roomId": f.room.room_id, "beforeEpoch": before,
                    "presentation": f.as_owner(), "reason": "the agreed window",
                }),
            )
        };
        // The table's middle row: `beforeEpoch: 4` drops rungs 2 and 3, rung 4 still
        // yields epoch 3, so the floor is 3.
        let (uri, p) = prune("0.2", 4);
        let (status, out) = call(&app, &uri, p, &f.owner).await;
        assert_eq!(status, StatusCode::OK, "{out}");
        assert_eq!(out["pruned"], 2, "{out}");
        assert_eq!(out["earliestRung"], 4);
        assert_eq!(out["epochFloor"], 3);

        let chain = |version: &str, from: Option<u32>| {
            let mut p =
                serde_json::json!({ "roomId": f.room.room_id, "presentation": f.as_owner() });
            if let Some(e) = from {
                p["fromEpoch"] = serde_json::json!(e);
            }
            (
                format!("https://trusttasks.org/spec/rooms/epoch/chain/{version}"),
                p,
            )
        };
        let epochs = |v: &Value| -> Vec<u64> {
            v["links"]
                .as_array()
                .unwrap()
                .iter()
                .map(|l| l["epoch"].as_u64().unwrap())
                .collect()
        };
        let (uri, p) = chain("0.2", None);
        let (_, out) = call(&app, &uri, p, &f.owner).await;
        assert_eq!(epochs(&out), [5, 4], "{out}");
        assert_eq!(out["epochFloor"], 3);
        // A request for nothing above the floor still learns the floor.
        let (uri, p) = chain("0.2", Some(3));
        let (_, out) = call(&app, &uri, p, &f.owner).await;
        assert!(epochs(&out).is_empty(), "{out}");
        assert_eq!(out["epochFloor"], 3);

        // Monotonic: a lower prune changes nothing.
        let (uri, p) = prune("0.2", 2);
        let (_, out) = call(&app, &uri, p, &f.owner).await;
        assert_eq!(out["epochFloor"], 3, "{out}");
        // A rung above the floor is still taken, at the next mint.
        let (status, out) = call(
            &app,
            ROOMS_EPOCH_MINT_TYPE,
            serde_json::json!({
                "roomId": f.room.room_id, "epoch": 6, "presentation": f.as_owner(),
                "link": { "epoch": 6, "wrapped": "d3JhcHBlZA6", "nonce": "bm9uY2U" },
            }),
            &f.owner,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{out}");
        let (uri, p) = prune("0.2", 5);
        let (status, out) = call(&app, &uri, p, &f.owner).await;
        assert_eq!(status, StatusCode::OK, "{out}");
        let room = storage::get_room(&st.rooms, &f.room.room_id).await.unwrap();
        assert_eq!(room.epoch_floor, Some(4), "the floor is the room's");

        // And a rung at or below the floor is never stored again.
        let refused = storage::put_epoch_link_above_floor(
            &st.epoch_links,
            &room,
            &vti_rooms::wire::EpochLink {
                epoch: 4,
                wrapped: "x".into(),
                nonce: "y".into(),
            },
        )
        .await;
        assert!(refused.is_err());
    }

    /// A room that does not chain refuses a rung, rather than storing one it said it would
    /// not have.
    ///
    /// Written straight to the store because `FromJoin` is not reachable over the wire —
    /// `rooms/create` has no member for it yet. That is the same reason this guard is worth
    /// a test now: an unreachable branch is exactly the kind that rots, and the policy it
    /// enforces was inert code until this test existed.
    #[tokio::test]
    async fn a_room_that_does_not_chain_refuses_an_epoch_link() {
        let (_d, st) = state();
        let app = router(st.clone());
        let f = RoomFixture::new(Visibility::Attributed).await;

        let room = Room {
            retention_policy: vti_rooms::RetentionPolicy::FromJoin,
            anchor_cadence: Default::default(),
            ..f.room.clone()
        };
        storage::create_room(&st.rooms, &room)
            .await
            .expect("register the room");

        let (status, body) = call(
            &app,
            ROOMS_EPOCH_MINT_TYPE,
            serde_json::json!({
                "roomId": f.room.room_id,
                "epoch": f.room.epoch + 1,
                "presentation": f.as_owner(),
                "link": {
                    "epoch": f.room.epoch + 1,
                    "wrapped": "9jK2_QhV1sVvR0m5xAqZ7A",
                    "nonce": "b0Zt8Qm2Yq1sVvR0"
                }
            }),
            &f.owner,
        )
        .await;

        assert_ne!(status, StatusCode::OK, "a rung must be refused: {body}");
        assert!(
            body.to_string()
                .contains("does not keep an epoch key chain"),
            "expected a policy refusal, got: {body}"
        );

        // And the same mint without a rung is fine: the policy refuses the link, not the
        // advance. A room that does not chain still advances its epochs.
        let (status, body) = call(
            &app,
            ROOMS_EPOCH_MINT_TYPE,
            serde_json::json!({
                "roomId": f.room.room_id,
                "epoch": f.room.epoch + 1,
                "presentation": f.as_owner(),
            }),
            &f.owner,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(
            body["epoch"].as_u64(),
            Some(u64::from(f.room.epoch + 1)),
            "an unlinked advance must still work: {body}"
        );
    }

    /// A record sealed under an epoch the room has moved past is the declared
    /// `epochMismatch` — the code a writer's client turns into "apply the commit you
    /// missed" — and is not stored.
    #[tokio::test]
    async fn a_record_sealed_under_a_superseded_epoch_is_epoch_mismatch() {
        let (_d, st) = state();
        let app = router(st.clone());
        let f = RoomFixture::new(Visibility::Attributed).await;
        register(&app, &f).await;
        let current = storage::get_room(&st.rooms, &f.room.room_id)
            .await
            .unwrap()
            .epoch;

        let (status, body) = call(
            &app,
            vti_rooms::wire::ROOMS_RECORDS_PUT_V3_TYPE,
            serde_json::json!({
                "roomId": f.room.room_id,
                "key": "k",
                "presentation": f.as_owner(),
                "sealed": {
                    "ciphertext": "9jK2_QhV1sVvR0m5xAqZ7A",
                    "nonce": "b0Zt8Qm2Yq1sVvR0",
                    "epoch": current + 1
                }
            }),
            &f.owner,
        )
        .await;
        assert_ne!(status, StatusCode::OK, "{body}");
        assert_eq!(body["code"], "rooms/records/put:epochMismatch", "{body}");
        assert!(
            storage::get_record(&st.records, &f.room.room_id, "k")
                .await
                .is_err()
        );
    }

    fn days_ago(n: u64) -> Option<u64> {
        Some(now() - n * 24 * 60 * 60)
    }

    #[tokio::test]
    async fn an_owner_transfers_the_room_to_another_member() {
        let (_d, st) = state();
        let app = router(st);
        let f = RoomFixture::new(Visibility::Open).await;
        register(&app, &f).await;

        let (status, body) = call(
            &app,
            ROOMS_OWNER_TRANSFER_TYPE,
            serde_json::json!({
                "roomId": f.room.room_id,
                "newOwnerDid": f.successor.did,
                "presentation": f.as_owner(),
                "reason": "stepping back from this project",
            }),
            &f.owner,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["ownerDid"], f.successor.did);
    }

    /// `admin`, not `read`. The agent's chain is the narrower one a member hands their
    /// agent, and an agent that could give the room away would make attenuation pointless.
    #[tokio::test]
    async fn read_may_not_transfer_the_room() {
        let (_d, st) = state();
        let app = router(st);
        let f = RoomFixture::new(Visibility::Open).await;
        register(&app, &f).await;

        let (status, _) = call(
            &app,
            ROOMS_OWNER_TRANSFER_TYPE,
            serde_json::json!({
                "roomId": f.room.room_id,
                "newOwnerDid": f.agent.did,
                "presentation": f.as_agent(),
            }),
            &f.agent,
        )
        .await;
        assert!(!status.is_success(), "an agent may not hand away the room");
    }

    /// The whole point: a room outlives one person's availability.
    #[tokio::test]
    async fn a_nominated_successor_claims_a_dormant_room() {
        let (_d, st) = state();
        let f = RoomFixture::new(Visibility::Open).await;
        register_expiring(&st, &f, days_ago(60)).await;
        let app = router(st.clone());

        let (status, body) = call(
            &app,
            ROOMS_OWNER_CLAIM_TYPE,
            serde_json::json!({
                "roomId": f.room.room_id,
                "nomination": f.nominate(&f.successor.did, 24).await,
                "presentation": f.as_successor(),
                "reason": "the owner has been unreachable since March",
            }),
            &f.successor,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["ownerDid"], f.successor.did);

        // And the claim did not renew it. The new owner's first act should be the one that
        // proves they can perform it.
        let room = storage::get_room(&st.rooms, &f.room.room_id).await.unwrap();
        assert!(
            !room.lifecycle(now()).accepts_writes(),
            "a claim hands over a dormant room, it does not revive one"
        );
    }

    /// The defence against a hostile claim, and it is the same act as ordinary use: an
    /// owner who was merely away renews, and every pending claim stops working.
    #[tokio::test]
    async fn a_live_room_cannot_be_claimed() {
        let (_d, st) = state();
        let f = RoomFixture::new(Visibility::Open).await;
        register_expiring(&st, &f, Some(now() + 30 * 24 * 60 * 60)).await;
        let app = router(st);

        let (status, body) = call(
            &app,
            ROOMS_OWNER_CLAIM_TYPE,
            serde_json::json!({
                "roomId": f.room.room_id,
                "nomination": f.nominate(&f.successor.did, 24).await,
                "presentation": f.as_successor(),
            }),
            &f.successor,
        )
        .await;
        assert!(!status.is_success(), "the owner is still here: {body}");
    }

    /// A lapse is not dormancy. An epoch expiring is frequently somebody on holiday, and a
    /// takeover window that opened the moment one expired would make every holiday one.
    #[tokio::test]
    async fn a_merely_lapsed_room_is_not_yet_claimable() {
        let (_d, st) = state();
        let f = RoomFixture::new(Visibility::Open).await;
        register_expiring(&st, &f, days_ago(3)).await;
        let app = router(st);

        let (status, body) = call(
            &app,
            ROOMS_OWNER_CLAIM_TYPE,
            serde_json::json!({
                "roomId": f.room.room_id,
                "nomination": f.nominate(&f.successor.did, 24).await,
                "presentation": f.as_successor(),
            }),
            &f.successor,
        )
        .await;
        assert!(
            !status.is_success(),
            "three days is a holiday, not an abandonment: {body}"
        );
    }

    /// Dormancy alone confers nothing. Otherwise any member of any quiet room could take it.
    #[tokio::test]
    async fn a_member_without_a_nomination_cannot_claim() {
        let (_d, st) = state();
        let f = RoomFixture::new(Visibility::Open).await;
        register_expiring(&st, &f, days_ago(60)).await;
        let app = router(st);

        // A real nomination — for somebody else.
        let (status, body) = call(
            &app,
            ROOMS_OWNER_CLAIM_TYPE,
            serde_json::json!({
                "roomId": f.room.room_id,
                "nomination": f.nominate(&f.agent.did, 24).await,
                "presentation": f.as_successor(),
            }),
            &f.successor,
        )
        .await;
        assert!(
            !status.is_success(),
            "a nomination is bound to the party it names: {body}"
        );
    }

    /// Every URI `vti_rooms::wire` says is dispatched must actually route here.
    ///
    /// The failure this catches is adding a handler to the wire crate's list and forgetting
    /// the `match` arm — which does not fail to compile, and shows up as `unsupportedType`
    /// on a verb the host claims to serve.
    #[tokio::test]
    async fn every_dispatched_uri_routes() {
        let (_d, st) = state();
        let app = router(st);
        let signer = Party::new();

        for uri in vti_rooms::wire::ROOMS_DISPATCHED_URIS {
            // An empty payload, so every one of these fails — the question is only *how*.
            let (_, body) = call(&app, uri, serde_json::json!({}), &signer).await;
            assert_ne!(
                body["code"], "unsupportedType",
                "{uri} is declared dispatched but has no route"
            );
        }
    }
}
