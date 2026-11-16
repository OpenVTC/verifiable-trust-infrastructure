//! `rooms/keys/read` 0.1 and 0.2 — fetch records from a room's host as the member, check
//! what the host asserted about each, and open them.
//!
//! One reader serves both versions, so 0.1 and a 0.2 request naming `key` cannot answer a
//! record differently: 0.2 adds only what the host's `rooms/records/get/0.3` serves
//! (`createdAt`, `createdBy`, `bodyStoredAt`, passed through exactly as served) and the
//! batch form.
//!
//! # The batch form (`rooms/keys/read/0.2`, *Reading several records*)
//!
//! - **Each key is read as it would be alone**: its own `rooms/records/get` to the same
//!   host under the same `read` grant, its own checks and verdict, and its own refusal —
//!   the code and `details` it would have been refused with alone, which is why a key's
//!   `error` is taken from the refusal document a single read would have answered.
//! - **What concerns the request as a whole** is one `trust-task-error`: both or neither of
//!   `key` and `keys`, more than 32, a repeated key, a caller who is not a member.
//! - **`notAttempted`** answers each key not come to before the response's size or time
//!   budget ran out ([`Budget`]); a key that was read is never answered with it.
//! - **Repairs are per batch.** Every key is fetched and opened first; the keys whose epoch
//!   key is missing are then repaired at most once each way — one catch-up to the highest
//!   epoch any of them needs, one chain extension to the lowest — under the per-member lock
//!   ([`super::room_catch_up`]), and opened again.
//!
//! Keys are read one after another, in the request's order. Concurrent fetches would be
//! faster, but a key in flight when the budget runs out has been read and then has to be
//! answered, so the bounds could only be kept approximately.

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use serde_json::{Map, Value, json};
use trust_tasks_rs::{DeclaredErrorCode, RejectReason, TrustTask};
use vti_common::acl::Capability;

use crate::auth::AuthClaims;
use crate::operations::room_groups::{self, OpenError};
use crate::operations::room_host::RoomTaskError;
use crate::operations::room_member;
use crate::server::AppState;

use super::helpers::{TrustTaskOutcome, app_error_to_reject, parse_payload, success_response};
use super::room_group::{
    MemberSendError, PresentingMember, compare_anchor, compare_head, declared, head_of,
    is_profile_location, named_member, outbound_resolver, presenting_member, send_as_member_typed,
    verify_trace,
};

/// The most keys one `rooms/keys/read/0.2` request may name (*Why 32*).
pub(super) const MAX_KEYS: usize = 32;

/// When a batch stops starting new keys.
///
/// - **Bytes**: 512 KiB of answered entries. A key is begun only while the entries so far
///   are under this, so a response is at most this plus one record — and one record is
///   what a single read already returns. A screen of a busy conversation is a few KiB a
///   record, so 32 of them fit many times over; what this stops is 32 one-mebibyte
///   documents (up to ~43 MiB of base64url) in one answer, which no transport this VTA
///   speaks carries well and which the 1 MiB request cap (`MAX_BODY_SIZE`) puts in
///   proportion.
/// - **Time**: 15 seconds. A key already begun finishes (its fetch is bounded by the
///   outbound timeout, a repair by `REPAIR_WAIT`), so a caller waiting on a batch should
///   allow this plus one key and one repair; the SDK waits 60 seconds. Past this, the
///   member is better served by the records read so far and a second request than by a
///   reply that arrives after its client gave up.
#[derive(Debug, Clone, Copy)]
pub(super) struct Budget {
    pub bytes: usize,
    pub time: Duration,
}

impl Budget {
    pub(super) const DEFAULT: Self = Self {
        bytes: 512 * 1024,
        time: Duration::from_secs(15),
    };
}

/// Which `rooms/keys/read` is being answered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Version {
    V0_1,
    V0_2,
    V0_3,
}

impl Version {
    fn codes(self) -> Codes {
        #[allow(deprecated)] // read/0.1 is still served beside 0.2
        match self {
            Self::V0_1 => {
                use vti_specs::rooms::keys::read::v0_1::error_codes as c;
                Codes {
                    unreachable: c::HOST_UNREACHABLE,
                    refused: c::HOST_REFUSED,
                    cannot_open: c::CANNOT_OPEN,
                    not_a_member: c::NOT_A_MEMBER,
                }
            }
            Self::V0_2 => {
                use vti_specs::rooms::keys::read::v0_2::error_codes as c;
                Codes {
                    unreachable: c::HOST_UNREACHABLE,
                    refused: c::HOST_REFUSED,
                    cannot_open: c::CANNOT_OPEN,
                    not_a_member: c::NOT_A_MEMBER,
                }
            }
            Self::V0_3 => {
                use vti_specs::rooms::keys::read::v0_3::error_codes as c;
                Codes {
                    unreachable: c::HOST_UNREACHABLE,
                    refused: c::HOST_REFUSED,
                    cannot_open: c::CANNOT_OPEN,
                    not_a_member: c::NOT_A_MEMBER,
                }
            }
        }
    }

    /// The code refusing a purpose, where this version declares one.
    fn purpose_code(self) -> Option<DeclaredErrorCode> {
        match self {
            Self::V0_3 => {
                Some(vti_specs::rooms::keys::read::v0_3::error_codes::PURPOSE_NOT_GRANTED)
            }
            _ => None,
        }
    }
}

#[derive(Clone, Copy)]
struct Codes {
    unreachable: DeclaredErrorCode,
    refused: DeclaredErrorCode,
    cannot_open: DeclaredErrorCode,
    not_a_member: DeclaredErrorCode,
}

/// `rooms/keys/read/0.1`: one record, fetched with `rooms/records/get/0.2`.
#[allow(deprecated)] // read/0.1 is still served beside 0.2
pub(super) async fn handle_read_v0_1(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    #[allow(deprecated)] // read/0.1 is still served beside 0.2
    let req: vti_specs::rooms::keys::read::v0_1::Payload = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    let room_id = req.room_id.to_string();
    let host = req.host.to_string();
    let key = req.key.to_string();
    read(
        state,
        auth,
        &doc,
        Version::V0_1,
        &room_id,
        &host,
        Keys::One(key),
        Budget::DEFAULT,
        None,
    )
    .await
}

/// `rooms/keys/read/0.2`: one record (`key`) or up to 32 (`keys`), fetched with
/// `rooms/records/get/0.3` where the host serves it. Purpose-bound, naming none.
pub(super) async fn handle_read_v0_2(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    read_v0_2_within(state, auth, doc, Budget::DEFAULT).await
}

/// `rooms/keys/read/0.3`: 0.2's read, for the `purpose` the caller names (VTI-ACL-103),
/// which is passed on to the host as `rooms/records/get/0.4`'s where the host serves it.
pub(super) async fn handle_read_v0_3(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    if let Err(resp) = parse_payload::<vti_specs::rooms::keys::read::v0_3::Payload>(&doc) {
        return resp;
    }
    let mut doc = doc;
    let requested = doc
        .payload
        .as_object_mut()
        .and_then(|m| m.remove("purpose"))
        .and_then(|v| v.as_str().map(str::to_string));
    read_within(state, auth, doc, Budget::DEFAULT, Version::V0_3, requested).await
}

/// [`handle_read_v0_2`] under `budget` — the tests' way to reach `notAttempted`.
pub(super) async fn read_v0_2_within(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
    budget: Budget,
) -> TrustTaskOutcome {
    read_within(state, auth, doc, budget, Version::V0_2, None).await
}

/// 0.2 and 0.3, the latter's payload read as the former's (`extends`).
#[allow(deprecated)] // the 0.2 payload type reads 0.3's too
async fn read_within(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
    budget: Budget,
    version: Version,
    requested: Option<String>,
) -> TrustTaskOutcome {
    let req: vti_specs::rooms::keys::read::v0_2::Payload = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    let keys = match (req.key, req.keys) {
        (Some(key), None) => Keys::One(key.to_string()),
        (None, Some(keys)) => {
            let keys: Vec<String> = keys.into_iter().map(|k| k.to_string()).collect();
            if keys.is_empty() || keys.len() > MAX_KEYS {
                return malformed(
                    &doc,
                    format!(
                        "`keys` names {} records; a request names from 1 to {MAX_KEYS}",
                        keys.len()
                    ),
                );
            }
            let mut seen = std::collections::HashSet::new();
            if let Some(dup) = keys.iter().find(|k| !seen.insert(k.as_str())) {
                return malformed(&doc, format!("`keys` names `{dup}` more than once"));
            }
            if let Some(bad) = keys.iter().find(|k| k.is_empty() || k.len() > 512) {
                return malformed(
                    &doc,
                    format!("`keys` holds a key of {} characters; 1 to 512", bad.len()),
                );
            }
            Keys::Many(keys)
        }
        (Some(_), Some(_)) => {
            return malformed(
                &doc,
                "a request names exactly one of `key` and `keys`".into(),
            );
        }
        (None, None) => {
            return malformed(&doc, "a request names one of `key` and `keys`".into());
        }
    };
    let room_id = req.room_id.to_string();
    let host = req.host.to_string();
    read(
        state, auth, &doc, version, &room_id, &host, keys, budget, requested,
    )
    .await
}

fn malformed(doc: &TrustTask<Value>, reason: String) -> TrustTaskOutcome {
    super::helpers::reject_with(doc, RejectReason::MalformedRequest { reason })
}

enum Keys {
    One(String),
    Many(Vec<String>),
}

#[allow(clippy::too_many_arguments)]
async fn read(
    state: &AppState,
    auth: &AuthClaims,
    doc: &TrustTask<Value>,
    version: Version,
    room_id: &str,
    host: &str,
    keys: Keys,
    budget: Budget,
    requested: Option<String>,
) -> TrustTaskOutcome {
    if let Err(r) = super::helpers::require_capability(
        state,
        auth,
        doc,
        Capability::RoomOpen,
        "reading a room record",
    )
    .await
    {
        return r;
    }
    let resolver = match outbound_resolver(state, doc) {
        Ok(v) => v,
        Err(resp) => return resp,
    };

    // `read`, and only `read`, granted to the principal and sent as the principal
    // (*What the recipient presents, and to whom*). The caller-named host is not bound into
    // the presentation: what makes naming one safe is that the leaf grants to the principal,
    // usable only by a party that can sign as the principal. What it gains is sight of the
    // credentials, which is a disclosure rather than an escalation.
    let named = match named_member(doc) {
        Ok(n) => n,
        Err(resp) => return resp,
    };
    let codes = version.codes();
    let presenting = match presenting_member(state, auth, room_id, named.as_deref()).await {
        Ok(v) => v,
        // 0.2 answers a principal holding nothing this room issued with its own declared
        // code; 0.1 keeps the refusal it has always given.
        Err(vti_common::error::AppError::NotFound(why)) if version != Version::V0_1 => {
            return super::helpers::reject_declared(doc, codes.not_a_member, why);
        }
        Err(e) => return app_error_to_reject(doc, e),
    };
    // Reading a record discloses it to the caller (VTI-ACL-102): held to the caller's
    // purposes before the host is asked for anything.
    let decision = match super::room_group::admit_room_purpose(
        state,
        auth,
        doc,
        "rooms.keys.read",
        room_id,
        requested.as_deref(),
        version.purpose_code(),
    )
    .await
    {
        Ok(d) => d,
        Err(r) => return r,
    };

    let reader = Reader {
        state,
        auth,
        doc,
        presenting: &presenting,
        resolver: &resolver,
        host,
        room_id,
        codes,
        ask_v3: AtomicBool::new(version != Version::V0_1),
        // The host holds the read to the purposes its authority chain states, where it
        // serves get/0.4 (`rooms/keys/read/0.3`); only a purpose that was named is passed.
        purpose: requested.clone(),
        ask_v4: AtomicBool::new(version == Version::V0_3 && requested.is_some()),
    };

    match keys {
        Keys::One(key) => {
            let mut results = reader.read_all(&[key], None).await;
            match results.pop() {
                Some(Answer::Read { mut fields, ext }) => {
                    super::room_group::record_purpose(
                        state,
                        "rooms.keys.read",
                        auth,
                        room_id,
                        &decision,
                        "success",
                    )
                    .await;
                    let mut payload = Map::new();
                    payload.insert("roomId".into(), json!(room_id));
                    payload.append(&mut fields);
                    if let Some(ext) = ext.single() {
                        payload.insert("ext".into(), ext);
                    }
                    success_response(doc, Value::Object(payload))
                }
                Some(Answer::Refused(outcome)) => outcome,
                // One key is always begun: there is no budget to run out of before it.
                Some(Answer::NotAttempted) | None => app_error_to_reject(
                    doc,
                    vti_common::error::AppError::Internal(
                        "a single read produced no answer".into(),
                    ),
                ),
            }
        }
        Keys::Many(keys) => {
            let answers = reader.read_all(&keys, Some(budget)).await;
            let not_attempted = {
                use vti_specs::rooms::keys::read::v0_2::error_codes::NOT_ATTEMPTED;
                json!({
                    "code": wire(NOT_ATTEMPTED),
                    "message": "not read in this request: the response reached the size or \
                                time this agent allows one batch before this key; ask for it \
                                again",
                    "retryable": true,
                })
            };
            let mut results = Vec::with_capacity(keys.len());
            let mut profile_keys = Vec::new();
            let mut sealed_at = Map::new();
            for (key, answer) in keys.iter().zip(answers) {
                let mut entry = Map::new();
                entry.insert("key".into(), json!(key));
                match answer {
                    Answer::Read { mut fields, ext } => {
                        fields.remove("key");
                        entry.append(&mut fields);
                        if ext.room_profile {
                            profile_keys.push(json!(key));
                        }
                        if let Some(v) = ext.sealed_at {
                            sealed_at.insert(key.clone(), json!(v));
                        }
                    }
                    Answer::Refused(outcome) => {
                        entry.insert("error".into(), key_error(&outcome));
                    }
                    Answer::NotAttempted => {
                        entry.insert("error".into(), not_attempted.clone());
                    }
                }
                results.push(Value::Object(entry));
            }
            super::room_group::record_purpose(
                state,
                "rooms.keys.read",
                auth,
                room_id,
                &decision,
                "success",
            )
            .await;
            let mut payload = json!({ "roomId": room_id, "results": results });
            // `ReadResult` is closed and carries no `ext`, so what a single read says in its
            // own `ext` is said here once, by key.
            let mut ours = Map::new();
            if !profile_keys.is_empty() {
                ours.insert("roomProfile".into(), Value::Array(profile_keys));
            }
            if !sealed_at.is_empty() {
                ours.insert("sealedAt".into(), Value::Object(sealed_at));
            }
            if !ours.is_empty() {
                payload["ext"] = json!({ room_member::MEMBER_EXT: ours });
            }
            success_response(doc, payload)
        }
    }
}

/// A declared code as the wire spells it.
fn wire(code: DeclaredErrorCode) -> String {
    code.code.to_string()
}

/// A key's `error` in a batch: exactly the refusal it would have been answered with alone
/// — read back from that refusal's own document, so the two cannot drift — in `KeyError`'s
/// bounds.
fn key_error(outcome: &TrustTaskOutcome) -> Value {
    let doc: Value = serde_json::from_slice(&outcome.body).unwrap_or(Value::Null);
    let p = &doc["payload"];
    let mut e = Map::new();
    let code = p["code"].as_str().unwrap_or("taskFailed");
    e.insert(
        "code".into(),
        json!(code.chars().take(256).collect::<String>()),
    );
    if let Some(m) = p["message"].as_str() {
        e.insert(
            "message".into(),
            json!(m.chars().take(1024).collect::<String>()),
        );
    }
    // The value the specification declares for the code, where it declares it (SPEC §8.4:
    // what an emitter SHOULD send) — `hostUnreachable` is retryable, `hostRefused` is not.
    let declared =
        vti_specs::schema_index::error_codes_for(vta_sdk::trust_tasks::TASK_ROOMS_KEYS_READ_0_2)
            .and_then(|codes| codes.iter().find(|c| c.code == code));
    let retryable = match declared {
        Some(c) => c.retryable,
        None => p["retryable"].as_bool().unwrap_or(false),
    };
    e.insert("retryable".into(), json!(retryable));
    if let Some(d) = p.get("details").filter(|d| d.is_object()) {
        e.insert("details".into(), d.clone());
    }
    Value::Object(e)
}

/// What a single read would put in its `ext`.
#[derive(Default)]
struct ReadExt {
    /// The record sits at the room's profile location, so it is not opened here.
    room_profile: bool,
    /// The body opened at this version, not the record's own.
    sealed_at: Option<u64>,
}

impl ReadExt {
    fn single(&self) -> Option<Value> {
        let mut ours = Map::new();
        if self.room_profile {
            ours.insert("roomProfile".into(), json!(true));
        }
        if let Some(v) = self.sealed_at {
            ours.insert("sealedAt".into(), json!(v));
        }
        (!ours.is_empty()).then(|| json!({ room_member::MEMBER_EXT: ours }))
    }
}

/// One key's answer.
enum Answer {
    /// The record: its response members (the key among them) and what goes in `ext`.
    Read {
        fields: Map<String, Value>,
        ext: ReadExt,
    },
    /// The refusal a request naming this key alone would have been answered with.
    Refused(TrustTaskOutcome),
    /// Not begun within the budget.
    NotAttempted,
}

/// A record fetched and checked whose epoch key is missing — waiting for the batch's repair.
struct Pending {
    fields: Map<String, Value>,
    served: vti_rooms::wire::GetRecordResponse,
    sealed_at: u64,
    search: room_groups::Search,
    refused: OpenError,
}

enum Stage {
    Done(Answer),
    Pending(Box<Pending>),
}

struct Reader<'a> {
    state: &'a AppState,
    auth: &'a AuthClaims,
    doc: &'a TrustTask<Value>,
    presenting: &'a PresentingMember,
    resolver: &'a affinidi_did_resolver_cache_sdk::DIDCacheClient,
    host: &'a str,
    room_id: &'a str,
    codes: Codes,
    /// Whether to ask `rooms/records/get/0.3` first. Cleared, for the rest of the request,
    /// by a host that answers it `unsupportedType`.
    ask_v3: AtomicBool,
    /// The purpose the caller named, passed to a host serving `rooms/records/get/0.4`.
    purpose: Option<String>,
    /// Ask get/0.4 first: a purpose was named and the host has not refused the version.
    ask_v4: AtomicBool,
}

impl Reader<'_> {
    /// Read `keys` in order. `budget` `None` begins every key (a single read).
    async fn read_all(&self, keys: &[String], budget: Option<Budget>) -> Vec<Answer> {
        let started = Instant::now();
        let mut answered_bytes = 0usize;
        let mut stages: Vec<Stage> = Vec::with_capacity(keys.len());
        for key in keys {
            if let Some(b) = budget
                && (answered_bytes >= b.bytes || started.elapsed() >= b.time)
            {
                stages.push(Stage::Done(Answer::NotAttempted));
                continue;
            }
            let stage = self.first_pass(key).await;
            answered_bytes += match &stage {
                Stage::Done(Answer::Read { fields, .. }) => {
                    serde_json::to_vec(fields).map_or(0, |b| b.len())
                }
                Stage::Done(Answer::Refused(o)) => o.body.len(),
                Stage::Done(Answer::NotAttempted) => 0,
                // About what the opened body will be, base64url-encoded.
                Stage::Pending(p) => p
                    .served
                    .record
                    .sealed
                    .as_ref()
                    .map_or(0, |s| s.ciphertext.len()),
            };
            stages.push(stage);
        }

        // Repairs, at most once each per request (*Repairs are per batch*): one catch-up to
        // the highest epoch any record needs, one chain extension down to the lowest.
        let behind = stages
            .iter()
            .filter_map(|s| match s {
                Stage::Pending(p) => match p.refused {
                    OpenError::NotDelivered { epoch, .. } => Some((epoch, &p.refused)),
                    _ => None,
                },
                _ => None,
            })
            .max_by_key(|(e, _)| *e)
            .map(|(_, r)| r);
        let early = stages
            .iter()
            .filter_map(|s| match s {
                Stage::Pending(p) => match p.refused {
                    OpenError::BeyondChain { epoch, .. } => Some((epoch, &p.refused)),
                    _ => None,
                },
                _ => None,
            })
            .min_by_key(|(e, _)| *e)
            .map(|(_, r)| r);
        let caught_up = match behind {
            Some(r) => Some(self.repair(r).await),
            None => None,
        };
        let extended = match early {
            Some(r) => Some(self.repair(r).await),
            None => None,
        };

        let mut answers = Vec::with_capacity(stages.len());
        for stage in stages {
            answers.push(match stage {
                Stage::Done(a) => a,
                Stage::Pending(p) => {
                    let repaired = match p.refused {
                        OpenError::NotDelivered { .. } => caught_up.clone(),
                        _ => extended.clone(),
                    };
                    self.second_pass(*p, repaired).await
                }
            });
        }
        answers
    }

    async fn repair(&self, refused: &OpenError) -> Result<(), String> {
        let outcome = super::room_catch_up::repair(
            self.state,
            self.auth,
            self.presenting,
            self.resolver,
            self.host,
            refused,
        )
        .await;
        if let Err(why) = &outcome {
            tracing::warn!(
                room = %self.room_id,
                reason = %why,
                "could not repair this member's epoch state before opening a record"
            );
        }
        outcome
    }

    /// Fetch `key`, check it, and open it if this agent holds its epoch key.
    async fn first_pass(&self, key: &str) -> Stage {
        let (served, times) = match self.fetch(key).await {
            Ok(v) => v,
            Err(outcome) => return Stage::Done(Answer::Refused(outcome)),
        };
        let fields = self.checked(&served, times).await;
        let member = &self.presenting.member;

        // The room's own profile is how the room describes itself, not a record a member
        // wrote into it (`SealedRecordBody`, *A profile record*): it is not opened here, and
        // the answer says where to read it.
        if is_profile_location(self.state, member, &served.record).await {
            return Stage::Done(Answer::Read {
                fields,
                ext: ReadExt {
                    room_profile: true,
                    sealed_at: None,
                },
            });
        }

        let Some(sealed) = &served.record.sealed else {
            // Open tier, or a tombstone: nothing to open, and a tombstone is an answer.
            let mut fields = fields;
            if let Some(cleartext) = &served.record.cleartext {
                fields.insert("cleartext".into(), cleartext.clone());
            }
            return Stage::Done(Answer::Read {
                fields,
                ext: ReadExt::default(),
            });
        };
        // Opened at the version the body was sealed at, which a curation moves the record
        // past (rooms `_shared/0.1` `SealedRecord.version`). A record curated by a host that
        // predates that member carries none, and is searched for.
        let sealed_at = match sealed.sealed_at(served.record.version) {
            Ok(v) => v,
            Err(why) => {
                return Stage::Done(Answer::Refused(app_error_to_reject(
                    self.doc,
                    vti_common::error::AppError::Validation(format!(
                        "room host `{}` {why}",
                        self.host
                    )),
                )));
            }
        };
        let search = if sealed.version.is_some() {
            room_groups::Search::Exact
        } else {
            room_groups::Search::Earlier
        };
        match self.open(&served, sealed_at, search).await {
            Ok(opened) => Stage::Done(self.opened(fields, &served, opened)),
            // Repair before refusing (*Opening, and when it cannot*): a member who is behind
            // applies the commits the host relays, one who joined late fetches the links; a
            // removed member is never repaired.
            Err(e @ (OpenError::NotDelivered { .. } | OpenError::BeyondChain { .. })) => {
                Stage::Pending(Box::new(Pending {
                    fields,
                    served,
                    sealed_at,
                    search,
                    refused: e,
                }))
            }
            Err(e) => Stage::Done(Answer::Refused(self.cannot_open(e, sealed.epoch, None))),
        }
    }

    /// Open a record again after the batch's repair.
    async fn second_pass(&self, p: Pending, repaired: Option<Result<(), String>>) -> Answer {
        let Pending {
            fields,
            served,
            sealed_at,
            search,
            ..
        } = p;
        let epoch = served.record.sealed.as_ref().map_or(0, |s| s.epoch);
        match self.open(&served, sealed_at, search).await {
            Ok(opened) => {
                // A record this agent could not place before the repair may be the room's
                // own profile, which is not opened here.
                if is_profile_location(self.state, &self.presenting.member, &served.record).await {
                    return Answer::Read {
                        fields,
                        ext: ReadExt {
                            room_profile: true,
                            sealed_at: None,
                        },
                    };
                }
                self.opened(fields, &served, opened)
            }
            Err(e) => Answer::Refused(self.cannot_open(e, epoch, repaired.and_then(Result::err))),
        }
    }

    async fn open(
        &self,
        served: &vti_rooms::wire::GetRecordResponse,
        sealed_at: u64,
        search: room_groups::Search,
    ) -> Result<(Vec<u8>, u64), OpenError> {
        let Some(sealed) = &served.record.sealed else {
            return Err(OpenError::App(vti_common::error::AppError::Internal(
                "no sealed body to open".into(),
            )));
        };
        room_groups::open_record_at(
            &self.state.room_groups_ks,
            &self.presenting.member,
            &served.record.key,
            sealed_at,
            &sealed.ciphertext,
            &sealed.nonce,
            sealed.epoch,
            search,
        )
        .await
    }

    fn opened(
        &self,
        mut fields: Map<String, Value>,
        served: &vti_rooms::wire::GetRecordResponse,
        (plaintext, opened_at): (Vec<u8>, u64),
    ) -> Answer {
        // base64url, as the spec gives it — not the bytes, which serialize as an array.
        fields.insert(
            "plaintext".into(),
            json!(base64::Engine::encode(
                &base64::engine::general_purpose::URL_SAFE_NO_PAD,
                plaintext
            )),
        );
        // A reader checks the author's signed location against the version the body was
        // sealed at; where that is not the record's own, say which it is.
        Answer::Read {
            fields,
            ext: ReadExt {
                room_profile: false,
                sealed_at: (opened_at != served.record.version).then_some(opened_at),
            },
        }
    }

    /// The record from the host, and the members `rooms/records/get/0.3` adds to it.
    ///
    /// Asked at 0.3 where this request reads it, and again at 0.2 when the host answers
    /// `unsupportedType` — after which the rest of the request asks 0.2 straight away.
    async fn fetch(
        &self,
        key: &str,
    ) -> Result<(vti_rooms::wire::GetRecordResponse, Map<String, Value>), TrustTaskOutcome> {
        let payload = json!({ "roomId": self.room_id, "key": key });
        let mut reply = None;
        if self.ask_v4.load(Ordering::Relaxed)
            && let Some(purpose) = &self.purpose
        {
            let mut with_purpose = payload.clone();
            with_purpose["purpose"] = json!(purpose);
            match self
                .send(vti_rooms::wire::ROOMS_RECORDS_GET_V4_TYPE, with_purpose)
                .await
            {
                Ok(v) => reply = Some(v),
                // A host that predates get/0.4 reads its chain as granting `any`, and no
                // credential states purposes yet, so 0.3 loses nothing.
                Err(MemberSendError::Host(RoomTaskError::Refused { code, .. }))
                    if code == "unsupportedType" =>
                {
                    self.ask_v4.store(false, Ordering::Relaxed);
                }
                Err(e) => return Err(self.host_failure(e)),
            }
        }
        if reply.is_none() && self.ask_v3.load(Ordering::Relaxed) {
            match self
                .send(vti_rooms::wire::ROOMS_RECORDS_GET_V3_TYPE, payload.clone())
                .await
            {
                Ok(v) => reply = Some(v),
                Err(MemberSendError::Host(RoomTaskError::Refused { code, .. }))
                    if code == "unsupportedType" =>
                {
                    self.ask_v3.store(false, Ordering::Relaxed);
                }
                Err(e) => return Err(self.host_failure(e)),
            }
        }
        let reply = match reply {
            Some(v) => v,
            None => {
                #[allow(deprecated)] // get/0.2 is read from hosts that predate get/0.3
                let task = vti_rooms::wire::ROOMS_RECORDS_GET_V2_TYPE;
                self.send(task, payload)
                    .await
                    .map_err(|e| self.host_failure(e))?
            }
        };
        // Exactly as served, and only what get/0.3 defines: a 0.2 host serves none of them.
        let mut times = Map::new();
        for member in ["createdAt", "createdBy", "bodyStoredAt"] {
            if let Some(v) = reply.get(member) {
                times.insert(member.into(), v.clone());
            }
        }
        // `send_room_task` has already verified the reply's proof AND bound the proven
        // signer to the host that was addressed — a proof that verifies against some other
        // party is a reply from somebody else.
        let served: vti_rooms::wire::GetRecordResponse =
            serde_json::from_value(reply).map_err(|e| {
                app_error_to_reject(
                    self.doc,
                    vti_common::error::AppError::Internal(format!(
                        "room host `{}` served a record this agent cannot read: {e}",
                        self.host
                    )),
                )
            })?;
        Ok((served, times))
    }

    async fn send(&self, task: &str, payload: Value) -> Result<Value, MemberSendError> {
        send_as_member_typed(
            self.state,
            self.auth,
            self.presenting,
            self.resolver,
            self.host,
            task,
            payload,
        )
        .await
    }

    fn host_failure(&self, e: MemberSendError) -> TrustTaskOutcome {
        super::room_group::host_failure(
            self.doc,
            e,
            self.host,
            self.codes.unreachable,
            self.codes.refused,
        )
    }

    /// The record's members and its `verification`.
    async fn checked(
        &self,
        served: &vti_rooms::wire::GetRecordResponse,
        mut times: Map<String, Value>,
    ) -> Map<String, Value> {
        let trace = verify_trace(served);
        let mut fields = Map::new();
        fields.insert("key".into(), json!(served.record.key));
        fields.insert("version".into(), json!(served.record.version));
        fields.insert("status".into(), json!(served.record.status));
        fields.insert("updatedAt".into(), json!(served.record.updated_at));
        fields.append(&mut times);
        if let Some(author) = &served.record.author {
            fields.insert("author".into(), json!(author));
        }
        let head = head_of(
            served.data_commitment.as_ref(),
            served.record_count,
            served.head_version,
        );
        let mut verification = json!({
            "trace": trace,
            "priorRoots": compare_head(self.state, &self.presenting.member, head.as_ref()).await,
            "anchor": compare_anchor(self.state, self.room_id, head.as_ref()).await,
        });
        if let Some(head) = head {
            verification["head"] = head;
        }
        fields.insert("verification".into(), verification);
        fields
    }

    /// `cannotOpen`: the record was fetched and its epoch key is not held, after the repair
    /// its reason admits. `details` carries the epoch and the reason in
    /// `rooms/keys/open/0.2`'s words, and the repair's failure where it failed, so a member is
    /// told which party has to act. Anything else that stopped the open is not an epoch case.
    fn cannot_open(
        &self,
        e: OpenError,
        epoch: u32,
        repair_failed: Option<String>,
    ) -> TrustTaskOutcome {
        let mut message = e.to_string();
        let mut details = match e {
            OpenError::NotDelivered { held, .. } => {
                json!({ "reason": "notDelivered", "heldEpoch": held })
            }
            OpenError::BeyondChain { earliest, .. } => {
                json!({ "reason": "beyondChain", "earliestEpoch": earliest })
            }
            OpenError::Removed { removed_at, .. } => {
                json!({ "reason": "removed", "removedAtEpoch": removed_at })
            }
            OpenError::App(e) => return app_error_to_reject(self.doc, e),
        };
        details["epoch"] = json!(epoch);
        if let Some(why) = repair_failed {
            message = format!("{message} (fetching what was missing from the host: {why})");
        }
        super::helpers::reject_with_code(
            self.doc,
            declared(self.codes.cannot_open),
            message,
            Some(details),
        )
    }
}

/// The keys a batch read answered, by outcome — for the tests' assertions.
#[cfg(test)]
pub(super) fn outcomes(results: &Value) -> std::collections::BTreeMap<String, String> {
    results
        .as_array()
        .into_iter()
        .flatten()
        .map(|r| {
            let key = r["key"].as_str().unwrap_or_default().to_string();
            let what = r["error"]["code"]
                .as_str()
                .map_or_else(|| "read".to_string(), str::to_string);
            (key, what)
        })
        .collect()
}
