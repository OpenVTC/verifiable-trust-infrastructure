//! Acting **as** the member — `rooms/keys/act/{0.1,0.2,0.3,0.4}` and `rooms/keys/seal/0.2`.
//!
//! The member's own client (a `pnm` session, a wallet extension, a phone) holds no key of
//! the persona the room admitted. These two tasks are how it writes and reads as that
//! persona anyway: `act` completes a host-bound room request as the member and hands it
//! back to send; `seal` 0.2 under `signAsPrincipal` signs a record body as the member
//! before sealing it. The orchestration is [`crate::operations::room_act`].
//!
//! # Who may ask
//!
//! **The entitlement is acting as the member** — being, or being the client of, this VTA's
//! own principal. Three gates, in order:
//!
//! 1. **Capability**: [`Capability::RoomPresent`] for `act` (it mints a presentation),
//!    [`Capability::RoomOpen`] for `seal` (as 0.1).
//! 2. **Not a delegate** ([`is_delegate`]). Both specifications refuse, with the standard
//!    `permissionDenied`, a caller to which the member delegated narrower standing: an
//!    agent presents under its own identifier (`rooms/keys/present`) and signs its own
//!    bodies. This VTA's marker for such a party is the consumer kind its ACL entry
//!    records — an AI agent or a mediator is a service acting *for* the principal, never
//!    the principal's own client.
//! 3. **Persona**: the member acted as is a persona the caller may act as
//!    ([`crate::operations::persona`]) — a DID this VTA holds in a context the caller acts
//!    in — holding the room's credentials.
//!
//! # The subject (`rooms/keys/act/0.2`)
//!
//! 0.2's `subjectPath` is `/document/issuer`: the member, never the room. Where `issuer`
//! is absent (a type that names a room, a caller who may act as exactly one of its
//! members) the subject is the member recipient item 2 resolves — [`act_subject`] for the
//! policy gate, which runs before this handler, and the completed document's `issuer` for
//! the audit row. 0.1 keeps the room as its row's resource, as it always has.
//!
//! # A community's offer (`rooms/keys/act/0.3`)
//!
//! 0.3 adds `vtc/rooms/offers/{list,accept}/0.1`: a member's reply to a community's offer of
//! a room, signed as the DID the offer is addressed to. No presentation is inserted and no
//! room credential is required — the member is not in the room yet — so the member is the
//! named `issuer`, acted as only where this VTA holds a key its DID document lists for
//! `authentication` and the caller may act as it (recipient item 2b). An acceptance's
//! `keyPackage` is completed only when this VTA minted it for that room and member and still
//! holds its private half (item 10, `keyPackageNotHeld`): a KeyPackage minted anywhere else
//! would become the member's leaf with keys somebody else holds.
//!
//! # The offer listing with descriptions (`rooms/keys/act/0.4`)
//!
//! 0.4 adds `vtc/rooms/offers/list/0.2` — the listing that shows each offered room's
//! description — in the same row as `0.1` and on the same terms
//! ([`room_act::OFFER_TYPES_0_4`]). Nothing else changes. 0.3's table stays closed: a 0.3
//! request wrapping a `0.2` listing is `typeNotActable`, as 0.3 recipient item 1 requires.

use chrono::Utc;
use serde_json::Value;
use trust_tasks_rs::TrustTask;
use vti_common::acl::{Capability, ConsumerKind, ServiceKind};
use vti_common::error::AppError;

use crate::audit;
use crate::auth::AuthClaims;
use crate::operations::room_act;
use crate::operations::{room_groups, room_member, room_oracle};
use crate::server::AppState;

use super::helpers::{
    TRANSPORT_TRUST_TASK, TrustTaskOutcome, app_error_to_reject, malformed_request_response,
    parse_payload, reject_declared, reject_with, reject_with_code, success_response,
};
use super::room_group::declared;

/// How old a document's `issuedAt` may be when it is completed. A document is signed to be
/// sent now (`rooms/keys/act/0.2` recipient item 8), and a host applies its own window on
/// top of this one.
const MAX_AGE: chrono::Duration = chrono::Duration::minutes(5);

/// How far ahead of this VTA's clock an `issuedAt` may be — clock skew, not scheduling.
const MAX_SKEW: chrono::Duration = chrono::Duration::minutes(2);

/// Whether the caller is a party the member delegated to, rather than the member's own
/// client.
///
/// A delegate is recorded by its ACL entry's consumer kind: a registered AI agent or a
/// mediator is a service acting for the principal. A row with no kind defaults to
/// `Service { Daemon }`, which every pre-existing client row (a `pnm` session among them)
/// carries — so that one is not read as a delegate. A store error refuses: being unable to
/// tell is not evidence of being the member.
pub(super) async fn is_delegate(state: &AppState, auth: &AuthClaims) -> Result<bool, AppError> {
    let entry = vti_common::acl::get_acl_entry(&state.acl_ks, &auth.did).await?;
    Ok(matches!(
        entry.map(|e| e.kind),
        Some(ConsumerKind::Service {
            service_kind: ServiceKind::AiAgent | ServiceKind::Mediator
        })
    ))
}

/// `permissionDenied` for a delegate, in the words both specifications use.
fn refuse_delegate(doc: &TrustTask<Value>) -> TrustTaskOutcome {
    reject_with(
        doc,
        trust_tasks_rs::RejectReason::PermissionDenied {
            reason: "a delegate presents under its own identifier: use rooms/keys/present, \
                     and sign your own record bodies"
                .into(),
        },
    )
}

/// The delegate gate as an outcome.
pub(super) async fn require_not_delegate(
    state: &AppState,
    auth: &AuthClaims,
    doc: &TrustTask<Value>,
) -> Result<(), TrustTaskOutcome> {
    match is_delegate(state, auth).await {
        Ok(false) => Ok(()),
        Ok(true) => Err(refuse_delegate(doc)),
        Err(e) => {
            tracing::error!(error = %e, did = %auth.did, "could not read the caller's ACL entry; refusing");
            Err(refuse_delegate(doc))
        }
    }
}

/// Whether this VTA holds group state for `room_id` for any member it serves — including a
/// row from before per-member keying.
async fn holds_any_group(state: &AppState, room_id: &str) -> Result<bool, AppError> {
    let groups = &state.room_groups_ks;
    Ok(!room_groups::holders(groups, room_id).await?.is_empty()
        || room_groups::legacy_group(groups, room_id).await?.is_some())
}

/// The subject of a `rooms/keys/act/0.2` request, for a policy evaluated before the
/// handler runs: the value at `subjectPath` (`/document/issuer`) when it is set, and
/// otherwise the member recipient item 2 resolves — the one member of the document's room
/// the caller may act as (act 0.2 *The subject*).
///
/// `None` only where item 2 resolves no member, and so the handler refuses the request
/// (`notAMember`, `principalAmbiguous`) before anything is completed: nothing is done as
/// a subject-less request.
pub(super) async fn act_subject(
    state: &AppState,
    auth: &AuthClaims,
    payload: &Value,
) -> Option<String> {
    let document = payload.get("document")?;
    if let Some(issuer) = document.get("issuer").and_then(Value::as_str) {
        return Some(issuer.to_string());
    }
    let room_id = document
        .get("payload")
        .and_then(|p| p.get("roomId"))
        .and_then(Value::as_str)?;
    match room_oracle::principals(state, auth, room_id).await {
        Ok(candidates) if candidates.len() == 1 => candidates.into_iter().next().map(|p| p.did),
        Ok(_) => None,
        Err(e) => {
            tracing::warn!(error = %e, "could not resolve the rooms/keys/act subject for the policy gate");
            None
        }
    }
}

/// Which `rooms/keys/act` is being answered. 0.2 names the member as the subject, which
/// this VTA records as the audit row's resource; 0.3 also completes the offer types
/// ([`room_act::OFFER_TYPES`]), which 0.1 and 0.2's schema refuses; 0.4 also
/// `vtc/rooms/offers/list/0.2` ([`room_act::OFFER_TYPES_0_4`]), which 0.3's table refuses.
#[derive(Clone, Copy, PartialEq, Eq)]
enum ActVersion {
    V0_1,
    V0_2,
    V0_3,
    V0_4,
}

impl ActVersion {
    /// Whether `type_uri` is an offer type this version's table lists.
    fn completes_offer(self, type_uri: &str) -> bool {
        match self {
            Self::V0_1 | Self::V0_2 => false,
            Self::V0_3 => room_act::is_offer_type(type_uri),
            Self::V0_4 => room_act::is_offer_type_0_4(type_uri),
        }
    }
}

/// `rooms/keys/act/0.1`.
pub(super) async fn handle_act(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    act_at(state, auth, doc, ActVersion::V0_1).await
}

/// `rooms/keys/act/0.2`: 0.1, with the member as the task's subject. For a type that
/// names no room the member is `issuer`, required and never picked here (recipient item
/// 2a) — which 0.1 already did in this VTA.
pub(super) async fn handle_act_v0_2(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    act_at(state, auth, doc, ActVersion::V0_2).await
}

/// `rooms/keys/act/0.3`: 0.2, and a member's reply to a community's offer of a room —
/// `vtc/rooms/offers/{list,accept}/0.1` — completed as the DID the offer is addressed to
/// (recipient item 2b), an acceptance only with a KeyPackage this VTA minted (item 10).
pub(super) async fn handle_act_v0_3(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    act_at(state, auth, doc, ActVersion::V0_3).await
}

/// `rooms/keys/act/0.4`: 0.3, with `vtc/rooms/offers/list/0.2` in the offer row beside
/// `0.1` — the listing that shows each offered room's description, completed on the same
/// terms (trust-tasks-tf #810).
pub(super) async fn handle_act_v0_4(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    act_at(state, auth, doc, ActVersion::V0_4).await
}

/// `rooms/keys/act`, at any version. The request is checked against the asked version's
/// schema — 0.1 and 0.2 share one, which refuses the offer types — and read through 0.4's
/// generated type, whose schema is 0.3's (it differs from 0.2's only in admitting the offer
/// types). Which offer types are completed is the asked version's table
/// ([`ActVersion::completes_offer`]). The answer is checked against the asked version's
/// response type.
async fn act_at(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
    at: ActVersion,
) -> TrustTaskOutcome {
    use trust_tasks_rs::specs::rooms::keys::act::v0_4 as spec;

    if let Err(r) = super::helpers::require_capability(
        state,
        auth,
        &doc,
        Capability::RoomPresent,
        "completing a room request as its member",
    )
    .await
    {
        return r;
    }
    if let Err(r) = require_not_delegate(state, auth, &doc).await {
        return r;
    }

    if matches!(at, ActVersion::V0_1 | ActVersion::V0_2)
        && let Err(resp) =
            parse_payload::<trust_tasks_rs::specs::rooms::keys::act::v0_2::Payload>(&doc)
    {
        return resp;
    }
    if at == ActVersion::V0_3
        && let Err(resp) =
            parse_payload::<trust_tasks_rs::specs::rooms::keys::act::v0_3::Payload>(&doc)
    {
        return resp;
    }
    let req: spec::Payload = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    // The document as the client sent it. Every member but `issuer`, `payload.presentation`
    // and `proof` goes back byte for byte (item 6) — re-serialising the typed form would
    // rewrite the timestamps the client chose.
    let mut document = doc.payload.get("document").cloned().unwrap_or(Value::Null);

    // Item 1: the closed table, before anything is resolved. At 0.3 the offer types are in
    // it too, with no action: they take no presentation. Each version's table is its own —
    // `vtc/rooms/offers/list/0.2` only from 0.4, so 0.3 refuses it here.
    let type_uri = req.document.type_.as_str();
    let offer = at.completes_offer(type_uri);
    let Some(action) = (if offer {
        Some(None)
    } else {
        room_act::actable(type_uri)
    }) else {
        return reject_with_code(
            &doc,
            declared(spec::error_codes::TYPE_NOT_ACTABLE),
            format!("`{type_uri}` is not a room request this VTA completes as a member"),
            Some(serde_json::json!({ "type": type_uri })),
        );
    };

    // Item 8: signed to be sent now, and never over a presentation somebody else chose.
    let now = Utc::now();
    if req.document.issued_at < now - MAX_AGE || req.document.issued_at > now + MAX_SKEW {
        return malformed_request_response(format!(
            "the document was issued at {}; a document is completed to be sent now",
            req.document.issued_at.to_rfc3339()
        ));
    }
    if req.document.expires_at.is_some_and(|t| t <= now) {
        return malformed_request_response("the document has already expired".into());
    }
    if req.document.payload.contains_key("presentation") {
        return malformed_request_response(
            "the document already carries a presentation; the member's own is inserted here".into(),
        );
    }

    let issuer = req.document.issuer.as_ref().map(|i| i.as_str().to_string());
    let room_id = req
        .document
        .payload
        .get("roomId")
        .and_then(Value::as_str)
        .map(str::to_string);

    // Item 9: a mint for a room whose group this VTA holds — for ANY member it serves — is
    // refused before anyone is resolved. On a sealed room the epoch advances only with a
    // group commit, which the caller cannot make, and a host that minted anyway would leave
    // every member's key holder an epoch behind. Open rooms (no group) still mint.
    if room_act::bare_type(type_uri)
        == <trust_tasks_rs::specs::rooms::epoch::mint::v0_1::Payload as trust_tasks_rs::Payload>::TYPE_URI
        && let Some(room_id) = &room_id
    {
        let held = match holds_any_group(state, room_id).await {
            Ok(h) => h,
            Err(e) => return app_error_to_reject(&doc, e),
        };
        if held {
            return reject_declared(
                &doc,
                spec::error_codes::SEALED_ROOM_MINT,
                format!(
                    "room `{room_id}` is sealed here: its epoch advances only with a group \
                     commit. Renew it from the owner's key holder with `pnm rooms owner \
                     group-renew` (rooms/owner/group/renew)"
                ),
            );
        }
    }

    // Item 2: whom to act as.
    let completed = match &room_id {
        // Item 2b: the offer types, before any room credential is looked for — the member
        // is not in the room yet.
        _ if offer => {
            match complete_offer(
                state,
                auth,
                &doc,
                type_uri,
                issuer,
                room_id.as_deref(),
                document,
            )
            .await
            {
                Ok(c) => Ok(c),
                Err(refused) => return refused,
            }
        }
        Some(room_id) => {
            let candidates = match room_oracle::principals(state, auth, room_id).await {
                Ok(c) => c,
                Err(e) => return app_error_to_reject(&doc, e),
            };
            let principal = match (&issuer, candidates.len()) {
                (Some(named), _) => match candidates.into_iter().find(|p| &p.did == named) {
                    Some(p) => p,
                    None => {
                        return reject_with_code(
                            &doc,
                            declared(spec::error_codes::ISSUER_NOT_PRINCIPAL),
                            format!("`{named}` is not a member of room `{room_id}` you may act as"),
                            Some(serde_json::json!({ "issuer": named })),
                        );
                    }
                },
                (None, 0) => {
                    return reject_declared(
                        &doc,
                        spec::error_codes::NOT_A_MEMBER,
                        format!(
                            "this VTA holds no credential issued by room `{room_id}` to a member \
                             you may act as"
                        ),
                    );
                }
                (None, 1) => candidates.into_iter().next().expect("one candidate"),
                (None, n) => {
                    return reject_declared(
                        &doc,
                        spec::error_codes::PRINCIPAL_AMBIGUOUS,
                        format!(
                            "you may act as {n} members of room `{room_id}`; name the one you \
                             mean in the document's `issuer`"
                        ),
                    );
                }
            };

            // Item 4: exactly the table's action, and only if the member holds it.
            if let Some(action) = action {
                match principal.confers(action) {
                    Ok(true) => {}
                    Ok(false) => {
                        return reject_with_code(
                            &doc,
                            declared(spec::error_codes::ACTION_NOT_HELD),
                            format!(
                                "the member's credentials for room `{room_id}` do not confer \
                                 `{action}`"
                            ),
                            Some(serde_json::json!({ "action": action })),
                        );
                    }
                    Err(e) => return app_error_to_reject(&doc, e),
                }
            }
            room_act::complete_as(state, auth, &principal, room_id, document, action).await
        }
        // A document that names no room — a download chunk, an upload's commit or abort —
        // takes no presentation; its authority is the transfer the member's own request
        // opened. With no room to resolve against, the member must be named (0.2 recipient
        // item 2a): `issuer` if this VTA holds its keys and the caller may act as it, and
        // never a member picked here — not the only one held, not one inferred from the
        // transfer id. The transfer belongs to whoever opened it, which only the client
        // knows.
        None => {
            if action.is_some() {
                return malformed_request_response(format!(
                    "a `{type_uri}` request names its `roomId`"
                ));
            }
            let Some(named) = issuer else {
                return reject_declared(
                    &doc,
                    spec::error_codes::PRINCIPAL_AMBIGUOUS,
                    "the document names no room, so the member to act as cannot be resolved \
                     from it; name the member in the document's `issuer`",
                );
            };
            if crate::operations::persona::persona_key_for(
                crate::operations::persona::PersonaStores::from_state(state),
                auth,
                &named,
                crate::operations::persona::Relationship::Authentication,
            )
            .await
            .map(|k| k.is_none())
            .unwrap_or(true)
            {
                return reject_with_code(
                    &doc,
                    declared(spec::error_codes::ISSUER_NOT_PRINCIPAL),
                    format!("`{named}` is not a member you may act as"),
                    Some(serde_json::json!({ "issuer": named })),
                );
            }
            if let Err(e) = room_act::check_schema(&document) {
                return app_error_to_reject(&doc, e);
            }
            room_act::sign_as(state, auth, &named, std::mem::take(&mut document))
                .await
                .map(|document| room_act::Completed {
                    document,
                    expires_at: None,
                })
        }
    };
    let completed = match completed {
        Ok(c) => c,
        Err(e) => return app_error_to_reject(&doc, e),
    };
    let principal = completed.document["issuer"]
        .as_str()
        .unwrap_or_default()
        .to_string();

    // The type and room, never the payload (spec *Retention*). At 0.2 the row's resource
    // is the subject — the member item 2 resolved, whom the completed document names as
    // `issuer` — and the room, where the type names one, goes beside the type.
    let bare = room_act::bare_type(type_uri);
    let (resource, detail) = match at {
        ActVersion::V0_1 => (room_id.clone(), format!("type={bare}")),
        ActVersion::V0_2 | ActVersion::V0_3 | ActVersion::V0_4 => (
            Some(principal.clone()),
            match &room_id {
                Some(room) => format!("type={bare} roomId={room}"),
                None => format!("type={bare}"),
            },
        ),
    };
    if let Err(e) = audit::record_with_detail(
        &state.audit_sink,
        "rooms.keys.act",
        &auth.did,
        resource.as_deref(),
        "success",
        Some(TRANSPORT_TRUST_TASK),
        None,
        Some(&detail),
    )
    .await
    {
        tracing::error!(error = %e, "failed to record a rooms/keys/act audit entry");
    }

    let mut response = serde_json::json!({
        "principal": principal,
        "document": completed.document,
    });
    if let Some(expires) = completed.expires_at {
        response["expiresAt"] = Value::String(expires);
    }
    let checked = match at {
        ActVersion::V0_1 => serde_json::from_value::<
            trust_tasks_rs::specs::rooms::keys::act::v0_1::Response,
        >(response)
        .and_then(serde_json::to_value),
        ActVersion::V0_2 => serde_json::from_value::<
            trust_tasks_rs::specs::rooms::keys::act::v0_2::Response,
        >(response)
        .and_then(serde_json::to_value),
        ActVersion::V0_3 => serde_json::from_value::<
            trust_tasks_rs::specs::rooms::keys::act::v0_3::Response,
        >(response)
        .and_then(serde_json::to_value),
        ActVersion::V0_4 => {
            serde_json::from_value::<spec::Response>(response).and_then(serde_json::to_value)
        }
    };
    match checked {
        Ok(r) => success_response(&doc, r),
        Err(e) => app_error_to_reject(
            &doc,
            AppError::Internal(format!(
                "the completed response does not fit its schema: {e}"
            )),
        ),
    }
}

/// Complete one of the offer types as its `issuer` — `rooms/keys/act/0.3` (and 0.4)
/// recipient items 2b and 10. `Err` is the refusal to answer with.
async fn complete_offer(
    state: &AppState,
    auth: &AuthClaims,
    doc: &TrustTask<Value>,
    type_uri: &str,
    issuer: Option<String>,
    room_id: Option<&str>,
    document: Value,
) -> Result<room_act::Completed, TrustTaskOutcome> {
    use trust_tasks_rs::specs::rooms::keys::act::v0_4::error_codes as codes;

    // Item 2b: the named `issuer`, never one picked for the caller — not the only persona
    // held, not one inferred from the offer.
    let Some(named) = issuer else {
        return Err(reject_declared(
            doc,
            codes::PRINCIPAL_AMBIGUOUS,
            "a reply to a community's offer is signed as the DID the offer is addressed to: \
             name it in the document's `issuer`",
        ));
    };
    // A key `issuer`'s DID document lists for `authentication`, which the caller may act as.
    // No room credential is asked for: whether `issuer` is the party the offer names is the
    // community's check, against the proof.
    let held = crate::operations::persona::persona_key_for(
        crate::operations::persona::PersonaStores::from_state(state),
        auth,
        &named,
        crate::operations::persona::Relationship::Authentication,
    )
    .await
    .map(|k| k.is_some())
    .unwrap_or(false);
    if !held {
        return Err(reject_with_code(
            doc,
            declared(codes::ISSUER_NOT_PRINCIPAL),
            format!(
                "this VTA holds no key `{named}` lists for `authentication` that you may act as, \
                 so it cannot reply to an offer as that DID"
            ),
            Some(serde_json::json!({ "issuer": named })),
        ));
    }

    // Item 10: an acceptance's KeyPackage is completed only when this VTA minted it, for
    // this room and this member, and still holds its unused, unexpired private half —
    // compared by KeyPackageRef, never by what its leaf credential claims.
    if room_act::is_offer_accept(type_uri)
        && let Some(kp) = document
            .get("payload")
            .and_then(|p| p.get("keyPackage"))
            .and_then(Value::as_str)
    {
        let held = match (decode_b64(kp), room_id) {
            (Ok(bytes), Some(room_id)) => {
                let member = room_groups::Member::new(room_id, &named)
                    .map_err(|e| app_error_to_reject(doc, e))?;
                room_groups::holds_key_package(
                    &state.room_groups_ks,
                    &member,
                    &bytes,
                    u64::try_from(Utc::now().timestamp()).unwrap_or(0),
                )
                .await
                .map_err(|e| app_error_to_reject(doc, e))?
            }
            _ => false,
        };
        if !held {
            return Err(reject_declared(
                doc,
                codes::KEY_PACKAGE_NOT_HELD,
                "this KeyPackage was not minted here for this room and member, or its private \
                 half is no longer held (used, or expired): mint one with \
                 rooms/keys/key-package and build the acceptance with it",
            ));
        }
    }

    room_act::check_schema(&document).map_err(|e| app_error_to_reject(doc, e))?;
    room_act::sign_as(state, auth, &named, document)
        .await
        .map(|document| room_act::Completed {
            document,
            expires_at: None,
        })
        .map_err(|e| app_error_to_reject(doc, e))
}

fn decode_b64(s: &str) -> Result<Vec<u8>, base64::DecodeError> {
    use base64::Engine as _;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(s.trim())
}

/// `rooms/keys/seal/0.2`. Without `signAsPrincipal` it is 0.1; with it, the body is signed
/// as its `author` — a member the caller acts as — before it is sealed.
pub(super) async fn handle_seal_v0_2(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    use trust_tasks_rs::specs::rooms::keys::seal::v0_2 as spec;

    if let Err(r) = super::helpers::require_capability(
        state,
        auth,
        &doc,
        Capability::RoomOpen,
        "sealing a room record",
    )
    .await
    {
        return r;
    }

    let req: spec::Payload = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    let sign = req.sign_as_principal.unwrap_or(false);
    if sign && let Err(r) = require_not_delegate(state, auth, &doc).await {
        return r;
    }

    let plaintext = match base64::Engine::decode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        req.plaintext.as_str(),
    ) {
        Ok(b) => b,
        Err(e) => {
            return app_error_to_reject(
                &doc,
                AppError::Validation(format!("plaintext is not base64url: {e}")),
            );
        }
    };
    let key = req.key.as_str();

    let (member, plaintext) = if sign {
        let body = match unsigned_body(&plaintext) {
            Ok(b) => b,
            Err(why) => {
                return reject_declared(&doc, spec::error_codes::BODY_INVALID, why);
            }
        };
        let author = body["author"].as_str().unwrap_or_default().to_string();
        // Item 3: a member of this room the caller may act as — the persona rule, and the
        // room's own group state for that persona. Held for someone else and held for
        // nobody answer alike.
        let member = match room_member::member_as(state, auth, &req.room_id, &author).await {
            Ok(m) => m,
            Err(e) => return app_error_to_reject(&doc, e),
        };
        let acts_as = crate::operations::persona::persona_key_for(
            crate::operations::persona::PersonaStores::from_state(state),
            auth,
            &author,
            crate::operations::persona::Relationship::AssertionMethod,
        )
        .await;
        let signing_key = match acts_as {
            Ok(Some(k)) => k,
            Ok(None) => {
                return reject_with_code(
                    &doc,
                    declared(spec::error_codes::AUTHOR_NOT_PRINCIPAL),
                    format!(
                        "the body's author is not a member of room `{}` you may act as",
                        req.room_id
                    ),
                    Some(serde_json::json!({ "author": author })),
                );
            }
            Err(e) => return app_error_to_reject(&doc, e),
        };
        // Item 1: the group state of the member the request concerns — the author's, and
        // never another member's this VTA also serves.
        match room_groups::load(&state.room_groups_ks, &member).await {
            Ok(Some(_)) => {}
            Ok(None) => {
                return reject_declared(
                    &doc,
                    spec::error_codes::NOT_A_MEMBER,
                    format!(
                        "this VTA holds no group state for room `{}` for the body's author",
                        req.room_id
                    ),
                );
            }
            Err(e) => return app_error_to_reject(&doc, e),
        }
        // ... and the location the body signs is the one it is sealed for.
        if body["roomId"].as_str() != Some(req.room_id.as_str())
            || body["key"].as_str() != Some(key)
            || body["version"].as_u64() != Some(req.version)
        {
            return reject_declared(
                &doc,
                spec::error_codes::LOCATION_MISMATCH,
                "the body's roomId, key or version differs from the payload's; a body signed \
                 for one location and sealed for another opens nowhere",
            );
        }
        // Item 4: signed for `assertionMethod` as the author, through the gated oracle.
        let signed = match sign_body(state, auth, signing_key, body).await {
            Ok(s) => s,
            Err(e) => return app_error_to_reject(&doc, e),
        };
        (member, signed)
    } else {
        // Not signing as the member, so nothing in the body names whose group seals it:
        // `ext["org.openvtc.rooms"].member` does, where the caller may act as several.
        let named = match room_member::named_member(&doc.payload) {
            Ok(n) => n,
            Err(e) => return malformed_request_response(e),
        };
        let member =
            match room_member::require_acting_as(state, auth, &req.room_id, named.as_deref()).await
            {
                Ok(m) => m,
                Err(e) => {
                    if matches!(e, AppError::NotFound(_)) {
                        return reject_declared(
                            &doc,
                            spec::error_codes::NOT_A_MEMBER,
                            e.to_string(),
                        );
                    }
                    return app_error_to_reject(&doc, e);
                }
            };
        (member, plaintext)
    };

    let sealed = match room_groups::seal_record(
        &state.room_groups_ks,
        &member,
        key,
        req.version,
        &plaintext,
    )
    .await
    {
        Ok(s) => s,
        Err(e) => {
            if matches!(e, AppError::NotFound(_)) {
                return reject_declared(&doc, spec::error_codes::NOT_A_MEMBER, e.to_string());
            }
            return app_error_to_reject(&doc, e);
        }
    };

    super::room_group::record(
        state,
        if sign {
            "rooms.keys.seal.sign-as-principal"
        } else {
            "rooms.keys.seal"
        },
        auth,
        &req.room_id,
    )
    .await;
    success_response(
        &doc,
        serde_json::json!({
            "sealed": {
                "ciphertext": sealed.ciphertext,
                "nonce": sealed.nonce,
                "epoch": sealed.epoch,
            }
        }),
    )
}

/// The members a `SealedRecordBody` may carry (`rooms/_shared/0.1/room.schema.json`), and
/// those it must.
const BODY_MEMBERS: &[&str] = &[
    "roomId",
    "key",
    "version",
    "author",
    "title",
    "description",
    "body",
    "tags",
    "file",
];
const BODY_REQUIRED: &[&str] = &["roomId", "key", "version", "author"];

/// Decode an unsigned `SealedRecordBody` (`bodyInvalid` otherwise): JSON, an object, no
/// `proof`, no unknown member, every required one present and of the right shape.
fn unsigned_body(plaintext: &[u8]) -> Result<Value, String> {
    let value: Value =
        serde_json::from_slice(plaintext).map_err(|e| format!("the body is not JSON: {e}"))?;
    let obj = value
        .as_object()
        .ok_or_else(|| "the body is not a JSON object".to_string())?;
    if obj.contains_key("proof") {
        return Err("the body already carries a proof; it is signed here".into());
    }
    if let Some(unknown) = obj.keys().find(|k| !BODY_MEMBERS.contains(&k.as_str())) {
        return Err(format!("the body carries an unknown member `{unknown}`"));
    }
    if let Some(missing) = BODY_REQUIRED.iter().find(|k| !obj.contains_key(**k)) {
        return Err(format!("the body lacks `{missing}`"));
    }
    let nonempty = |k: &str| obj[k].as_str().is_some_and(|s| !s.is_empty());
    if !nonempty("roomId") || !nonempty("key") {
        return Err("`roomId` and `key` are non-empty strings".into());
    }
    if obj["version"].as_u64().is_none_or(|v| v == 0) {
        return Err("`version` is an integer from 1".into());
    }
    if !obj["author"]
        .as_str()
        .is_some_and(|a| a.starts_with("did:"))
    {
        return Err("`author` is a DID".into());
    }
    Ok(value)
}

/// Sign `body` for `assertionMethod` with `key`, through the gated oracle, and return the
/// signed body's UTF-8 JSON — what is sealed.
pub(super) async fn sign_body(
    state: &AppState,
    auth: &AuthClaims,
    key: crate::operations::persona::PersonaKey,
    mut body: Value,
) -> Result<Vec<u8>, AppError> {
    let signer = crate::operations::room_issuance::VtaKeySigner::new(
        super::room_group::signing_context(state, auth),
        key.key_id,
        key.verification_method,
    );
    let proof = affinidi_data_integrity::DataIntegrityProof::sign(
        &body,
        &signer,
        affinidi_data_integrity::SignOptions::new().with_proof_purpose("assertionMethod"),
    )
    .await
    .map_err(|e| AppError::Internal(format!("sign the record body: {e}")))?;
    body["proof"] = serde_json::to_value(proof)
        .map_err(|e| AppError::Internal(format!("serialise the proof: {e}")))?;
    serde_json::to_vec(&body).map_err(|e| AppError::Internal(format!("serialise the body: {e}")))
}

#[cfg(test)]
mod tests {
    //! `rooms/keys/act/{0.1,0.2}` and `rooms/keys/seal/0.2`, and the in-place
    //! `rooms/keys/{read,browse,backfill}` change, against real personas held in contexts.
    //!
    //! The end-to-end case runs a real room host in process (`room_host::dispatch`): the
    //! same proof verification, chain authorization and author recording a host applies,
    //! so "the host recorded the persona" is the host's statement, not this test's.

    use std::sync::{Arc, Mutex};

    use base64::Engine as _;
    use chrono::Duration as Span;
    use dtg_credentials::DTGCredential;
    use serde_json::json;
    use trust_tasks_rs::TypeUri;
    use vti_rooms_dtg::test_support::Party;

    use super::*;
    use crate::operations::persona::test_fixture::{self as personas, Persona};
    use crate::operations::room_groups::Member;
    use crate::operations::room_oracle::{AUTHORITY_TYPE, MEMBERSHIP_TYPE};

    const ACT: &str = vta_sdk::trust_tasks::TASK_ROOMS_KEYS_ACT_0_1;
    const ACT_0_2: &str = vta_sdk::trust_tasks::TASK_ROOMS_KEYS_ACT_0_2;
    const ACT_0_3: &str = vta_sdk::trust_tasks::TASK_ROOMS_KEYS_ACT_0_3;
    const ACT_0_4: &str = vta_sdk::trust_tasks::TASK_ROOMS_KEYS_ACT_0_4;
    const OFFERS_LIST: &str = "https://trusttasks.org/spec/vtc/rooms/offers/list/0.1";
    const OFFERS_LIST_0_2: &str = "https://trusttasks.org/spec/vtc/rooms/offers/list/0.2";
    const OFFERS_ACCEPT: &str = "https://trusttasks.org/spec/vtc/rooms/offers/accept/0.1";
    const COMMUNITY: &str = "did:webvh:example.com:northwind-community";
    const SEAL: &str = vta_sdk::trust_tasks::TASK_ROOMS_KEYS_SEAL_0_2;
    const KEY: &str = "giXFLTGBdnnQJRoIsktuIg";

    fn request(uri: &str, payload: Value) -> TrustTask<Value> {
        let uri: TypeUri = uri.parse().unwrap();
        TrustTask::new(format!("urn:uuid:{}", uuid::Uuid::new_v4()), uri, payload)
    }

    fn body(outcome: TrustTaskOutcome) -> Value {
        serde_json::from_slice(&outcome.body).expect("a document")
    }

    /// The code a refusal carries, as the wire spells it.
    fn code(doc: &Value) -> String {
        doc["payload"]["code"]
            .as_str()
            .unwrap_or_default()
            .to_string()
    }

    fn b64(v: &Value) -> String {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(serde_json::to_vec(v).unwrap())
    }

    /// A VTA holding `alice`'s and `bob`'s personas in their own contexts, and a room that
    /// granted `actions` to alice's.
    struct Fx {
        state: AppState,
        _dir: tempfile::TempDir,
        room: Party,
        alice: Persona,
        bob: Persona,
    }

    async fn fixture(actions: &[&str]) -> Fx {
        let (state, dir) = crate::test_support::build_signing_test_app_state().await;
        for (id, name) in [("alice", "Alice"), ("bob", "Bob")] {
            crate::contexts::create_context(&state.contexts_ks, id, name)
                .await
                .expect("create context");
        }
        let persona = |context: &'static str, key_id: &'static str| {
            let state = &state;
            async move {
                personas::did_key_persona(
                    &state.keys_ks,
                    &state.internal_ks,
                    &state.contexts_ks,
                    &state.acl_ks,
                    &state.seed_store,
                    &state.audit_sink,
                    context,
                    key_id,
                )
                .await
            }
        };
        let alice = persona("alice", "alice-persona").await;
        let bob = persona("bob", "bob-persona").await;
        let room = Party::new();
        grant(&state, &room, &alice.did, "alice", actions).await;
        Fx {
            state,
            _dir: dir,
            room,
            alice,
            bob,
        }
    }

    /// The room's VAC (conferring `actions`) and VMC to `subject`, stored context-less.
    async fn grant(state: &AppState, room: &Party, subject: &str, tag: &str, actions: &[&str]) {
        let now = Utc::now();
        let mut vac = DTGCredential::new_vac(
            room.did.clone(),
            dtg_credentials::IssuerScope::Public,
            subject.to_string(),
            room.did.clone(),
            actions.iter().map(|a| a.to_string()).collect(),
            now - Span::minutes(1),
            now + Span::days(30),
        )
        .expect("the room's grant")
        .with_id(format!("urn:uuid:vac-{tag}"));
        vac.sign(&room.secret, None).await.expect("sign the VAC");
        let mut vmc = DTGCredential::new_vmc(
            room.did.clone(),
            subject.to_string(),
            now - Span::minutes(1),
            Some(now + Span::days(30)),
            false,
        );
        vmc.sign(&room.secret, None).await.expect("sign the VMC");
        for (id, tag_type, cred) in [
            (format!("vac-{tag}"), AUTHORITY_TYPE, &vac),
            (format!("vmc-{tag}"), MEMBERSHIP_TYPE, &vmc),
        ] {
            use crate::vault::model::{CredentialFormat, CredentialStatus, StoredCredential};
            crate::vault::storage::put(
                &state.vault_ks,
                &StoredCredential {
                    id,
                    format: CredentialFormat::EddsaJcs2022,
                    types: vec![tag_type.into()],
                    schema_id: None,
                    community_did: None,
                    context_id: None,
                    subject_did: None,
                    issuer_did: Some(room.did.clone()),
                    purpose: None,
                    status: CredentialStatus::Unknown,
                    valid_from: None,
                    valid_until: None,
                    received_at: "2026-01-01T00:00:00Z".into(),
                    source: None,
                    tags: Default::default(),
                    body: serde_json::to_vec(cred).unwrap(),
                    lifecycle: vti_common::vault::VaultStatus::Active,
                    archived_at: None,
                    deleted_at: None,
                    grace_until: None,
                },
            )
            .await
            .expect("store the credential");
        }
    }

    /// A `pnm` session acting in alice's context — its own `did:key`, which is no persona.
    fn alice_client() -> AuthClaims {
        crate::test_support::admin_claims_for_context("alice")
    }

    async fn found_group(f: &Fx, persona: &str) {
        room_groups::create_group(
            &f.state.room_groups_ks,
            &Member::new(&f.room.did, persona).unwrap(),
            0,
        )
        .await
        .expect("found the group");
    }

    /// An unsigned host-bound room request, as a member's client builds one.
    fn unsigned(type_uri: &str, host: &str, payload: Value) -> Value {
        json!({
            "id": format!("urn:uuid:{}", uuid::Uuid::new_v4()),
            "type": type_uri,
            "recipient": host,
            "issuedAt": Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            "payload": payload,
        })
    }

    async fn act(state: &AppState, auth: &AuthClaims, document: Value) -> Value {
        body(handle_act(state, auth, request(ACT, json!({ "document": document }))).await)
    }

    async fn act_v0_3(state: &AppState, auth: &AuthClaims, document: Value) -> Value {
        body(
            handle_act_v0_3(
                state,
                auth,
                request(ACT_0_3, json!({ "document": document })),
            )
            .await,
        )
    }

    async fn act_v0_4(state: &AppState, auth: &AuthClaims, document: Value) -> Value {
        body(
            handle_act_v0_4(
                state,
                auth,
                request(ACT_0_4, json!({ "document": document })),
            )
            .await,
        )
    }

    /// A reply to a community's offer, as a member's client builds one: addressed to the
    /// community, `issuer` the DID the offer names (when given).
    fn offer(type_uri: &str, issuer: Option<&str>, payload: Value) -> Value {
        let mut d = unsigned(type_uri, COMMUNITY, payload);
        if let Some(i) = issuer {
            d["issuer"] = json!(i);
        }
        d
    }

    /// A KeyPackage this VTA mints for `persona` in `room`, as `rooms/keys/key-package`
    /// does, living `lifetime` seconds from `now`.
    async fn minted(f: &Fx, room: &str, persona: &str, lifetime: u64, now: u64) -> String {
        room_groups::mint_key_package(
            &f.state.room_groups_ks,
            &Member::new(room, persona).unwrap(),
            lifetime,
            now,
        )
        .await
        .expect("mint a key package")
        .key_package
    }

    fn unix_now() -> u64 {
        u64::try_from(Utc::now().timestamp()).unwrap()
    }

    /// `rooms/keys/act/0.3`: an offer type is completed as its named `issuer`, with no
    /// presentation inserted and no room credential needed — the member is not in the room
    /// yet — signed for `authentication`. The document goes back otherwise unchanged.
    #[tokio::test]
    async fn act_0_3_completes_an_offer_type_as_its_issuer_without_a_presentation() {
        let f = fixture(&["read"]).await;
        let board = Party::new(); // a room alice holds nothing from
        for (type_uri, payload) in [
            (OFFERS_LIST, json!({})),
            (OFFERS_ACCEPT, json!({ "roomId": board.did })),
        ] {
            let document = offer(type_uri, Some(&f.alice.did), payload.clone());
            let out = act_v0_3(&f.state, &alice_client(), document.clone()).await;
            assert_eq!(
                out["payload"]["principal"], f.alice.did,
                "{type_uri}: {out}"
            );
            let completed = &out["payload"]["document"];
            assert_eq!(completed["issuer"], f.alice.did, "{out}");
            assert_eq!(completed["recipient"], COMMUNITY, "{out}");
            assert_eq!(completed["id"], document["id"], "{out}");
            assert_eq!(completed["payload"], payload, "nothing inserted: {out}");
            assert_eq!(
                completed["proof"]["proofPurpose"], "authentication",
                "{out}"
            );
            assert!(out["payload"].get("expiresAt").is_none(), "{out}");
            serde_json::from_value::<trust_tasks_rs::specs::rooms::keys::act::v0_3::Response>(
                out["payload"].clone(),
            )
            .expect("a 0.3 response");
        }
    }

    /// Producer item 2 / recipient item 2b: an offer type names its member in `issuer`, and
    /// the VTA never picks one — `principalAmbiguous` without it, even where the caller may
    /// act as exactly one persona. A DID the caller may not act as, or one this VTA holds no
    /// `authentication` key for, is `issuerNotPrincipal`.
    #[tokio::test]
    async fn act_0_3_an_offer_type_is_completed_only_as_a_named_issuer_the_caller_acts_as() {
        let f = fixture(&["read"]).await;
        for type_uri in [OFFERS_LIST, OFFERS_ACCEPT] {
            let payload = if type_uri == OFFERS_LIST {
                json!({})
            } else {
                json!({ "roomId": f.room.did })
            };
            let out = act_v0_3(
                &f.state,
                &alice_client(),
                offer(type_uri, None, payload.clone()),
            )
            .await;
            assert_eq!(code(&out), "rooms/keys/act:principalAmbiguous", "{out}");

            let out = act_v0_3(
                &f.state,
                &alice_client(),
                offer(type_uri, Some(&f.bob.did), payload.clone()),
            )
            .await;
            assert_eq!(code(&out), "rooms/keys/act:issuerNotPrincipal", "{out}");
            assert_eq!(out["payload"]["details"]["issuer"], f.bob.did, "{out}");

            let stranger = Party::new().did;
            let out = act_v0_3(
                &f.state,
                &alice_client(),
                offer(type_uri, Some(&stranger), payload),
            )
            .await;
            assert_eq!(code(&out), "rooms/keys/act:issuerNotPrincipal", "{out}");
        }
    }

    /// 0.1 and 0.2 do not complete the offer types: their schema refuses the `type`.
    #[tokio::test]
    async fn act_0_2_does_not_complete_an_offer_type() {
        let f = fixture(&["read"]).await;
        let document = offer(OFFERS_LIST, Some(&f.alice.did), json!({}));
        for out in [
            act_v0_2(&f.state, &alice_client(), document.clone()).await,
            act(&f.state, &alice_client(), document.clone()).await,
        ] {
            assert!(out["payload"].get("principal").is_none(), "{out}");
            assert!(!code(&out).is_empty(), "{out}");
        }
        // And at 0.3 an administrator's task is still not actable: only the offer types are.
        let out = act_v0_3(
            &f.state,
            &alice_client(),
            offer(
                "https://trusttasks.org/spec/vtc/rooms/community/members/add/0.1",
                Some(&f.alice.did),
                json!({ "roomId": f.room.did, "member": f.bob.did }),
            ),
        )
        .await;
        assert!(out["payload"].get("principal").is_none(), "{out}");
    }

    /// Recipient item 10: an acceptance's `keyPackage` is completed only when this VTA
    /// minted it for that room and that member and still holds its private half. A
    /// KeyPackage made anywhere else — even one whose leaf names the member — one minted
    /// for another room or another member, one already used by a Welcome, and one expired
    /// are all `keyPackageNotHeld`, and nothing is signed.
    #[tokio::test]
    async fn act_0_3_an_acceptance_carries_only_a_key_package_this_vta_minted() {
        let f = fixture(&["read"]).await;
        let board = Party::new().did;
        let accept = |kp: &str| {
            offer(
                OFFERS_ACCEPT,
                Some(&f.alice.did),
                json!({ "roomId": board, "keyPackage": kp }),
            )
        };
        let not_held = |out: &Value| {
            assert_eq!(code(out), "rooms/keys/act:keyPackageNotHeld", "{out}");
            assert!(out["payload"].get("document").is_none(), "{out}");
        };

        // Foreign: made by somebody else, its leaf naming alice.
        let (_, foreign) = vti_rooms::mls::IdentitySnapshot::mint(&f.alice.did).unwrap();
        let foreign = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(foreign);
        not_held(&act_v0_3(&f.state, &alice_client(), accept(&foreign)).await);
        // Not a KeyPackage at all.
        not_held(&act_v0_3(&f.state, &alice_client(), accept("AAEAAgADAAQ")).await);

        // Minted here, for another room.
        let other_room = minted(&f, &Party::new().did, &f.alice.did, 3600, unix_now()).await;
        not_held(&act_v0_3(&f.state, &alice_client(), accept(&other_room)).await);

        // Minted here, for this room, for another member.
        let bobs = minted(&f, &board, &f.bob.did, 3600, unix_now()).await;
        not_held(&act_v0_3(&f.state, &alice_client(), accept(&bobs)).await);

        // Expired.
        let expired = minted(&f, &board, &f.alice.did, 60, unix_now() - 120).await;
        not_held(&act_v0_3(&f.state, &alice_client(), accept(&expired)).await);

        // Held: completed — and still held, so a retry after a lost answer completes again.
        let held = minted(&f, &board, &f.alice.did, 3600, unix_now()).await;
        for _ in 0..2 {
            let out = act_v0_3(&f.state, &alice_client(), accept(&held)).await;
            assert_eq!(out["payload"]["principal"], f.alice.did, "{out}");
            assert_eq!(
                out["payload"]["document"]["payload"]["keyPackage"], held,
                "{out}"
            );
        }

        // Used: a Welcome consumed it.
        let mut owner = vti_rooms::mls::RoomGroup::create("did:example:owner").unwrap();
        let change = owner
            .add_member_from_bytes(
                &base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .decode(&held)
                    .unwrap(),
            )
            .unwrap();
        room_groups::join(
            &f.state.room_groups_ks,
            &Member::new(&board, &f.alice.did).unwrap(),
            &change.welcome.unwrap(),
            0,
        )
        .await
        .expect("joins");
        not_held(&act_v0_3(&f.state, &alice_client(), accept(&held)).await);
    }

    /// An open room's acceptance carries no KeyPackage, and item 10 has nothing to check.
    #[tokio::test]
    async fn act_0_3_an_open_rooms_acceptance_needs_no_key_package() {
        let f = fixture(&["read"]).await;
        let out = act_v0_3(
            &f.state,
            &alice_client(),
            offer(
                OFFERS_ACCEPT,
                Some(&f.alice.did),
                json!({ "roomId": Party::new().did }),
            ),
        )
        .await;
        assert_eq!(out["payload"]["principal"], f.alice.did, "{out}");
    }

    /// 0.3 completes a host-bound room request as 0.2 did.
    #[tokio::test]
    async fn act_0_3_completes_a_room_request_as_0_2_did() {
        let f = fixture(&["read"]).await;
        let out = act_v0_3(
            &f.state,
            &alice_client(),
            unsigned(
                vti_rooms::wire::ROOMS_RECORDS_GET_TYPE,
                "did:key:zHost",
                json!({ "roomId": f.room.did, "key": KEY }),
            ),
        )
        .await;
        assert_eq!(out["payload"]["principal"], f.alice.did, "{out}");
        assert!(
            out["payload"]["document"]["payload"]["presentation"].is_object(),
            "{out}"
        );
    }

    /// `rooms/keys/act/0.4` adds `vtc/rooms/offers/list/0.2` to the offer row, on 0.1's
    /// terms: completed as its named `issuer`, nothing inserted, signed for
    /// `authentication`, answered as a 0.4 response.
    #[tokio::test]
    async fn act_0_4_completes_offers_list_0_2_as_its_issuer_without_a_presentation() {
        let f = fixture(&["read"]).await;
        let document = offer(OFFERS_LIST_0_2, Some(&f.alice.did), json!({}));
        let out = act_v0_4(&f.state, &alice_client(), document.clone()).await;
        assert!(
            out["type"].as_str().is_some_and(|t| t.starts_with(ACT_0_4)),
            "{out}"
        );
        assert_eq!(out["payload"]["principal"], f.alice.did, "{out}");
        let completed = &out["payload"]["document"];
        assert_eq!(completed["type"], OFFERS_LIST_0_2, "{out}");
        assert_eq!(completed["issuer"], f.alice.did, "{out}");
        assert_eq!(completed["recipient"], COMMUNITY, "{out}");
        assert_eq!(completed["id"], document["id"], "{out}");
        assert_eq!(completed["payload"], json!({}), "nothing inserted: {out}");
        assert_eq!(
            completed["proof"]["proofPurpose"], "authentication",
            "{out}"
        );
        assert!(out["payload"].get("expiresAt").is_none(), "{out}");
        serde_json::from_value::<trust_tasks_rs::specs::rooms::keys::act::v0_4::Response>(
            out["payload"].clone(),
        )
        .expect("a 0.4 response");

        // Recipient item 2b holds for it as for 0.1: named, and only a DID the caller acts as.
        let out = act_v0_4(
            &f.state,
            &alice_client(),
            offer(OFFERS_LIST_0_2, None, json!({})),
        )
        .await;
        assert_eq!(code(&out), "rooms/keys/act:principalAmbiguous", "{out}");
        let out = act_v0_4(
            &f.state,
            &alice_client(),
            offer(OFFERS_LIST_0_2, Some(&f.bob.did), json!({})),
        )
        .await;
        assert_eq!(code(&out), "rooms/keys/act:issuerNotPrincipal", "{out}");
    }

    /// `rooms/keys/act/0.3`'s table is closed (recipient item 1): a `vtc/rooms/offers/list/0.2`
    /// it wraps is `typeNotActable`, `details.type` repeating it, and nothing is signed —
    /// although the same VTA completes it at 0.4.
    #[tokio::test]
    async fn act_0_3_refuses_offers_list_0_2_as_not_actable() {
        let f = fixture(&["read"]).await;
        let document = offer(OFFERS_LIST_0_2, Some(&f.alice.did), json!({}));
        let out = act_v0_3(&f.state, &alice_client(), document).await;
        assert_eq!(code(&out), "rooms/keys/act:typeNotActable", "{out}");
        assert_eq!(out["payload"]["details"]["type"], OFFERS_LIST_0_2, "{out}");
        assert!(out["payload"].get("document").is_none(), "{out}");
        assert!(out["payload"].get("principal").is_none(), "{out}");

        // And 0.1 / 0.2, whose schema admits no offer type at all.
        let document = offer(OFFERS_LIST_0_2, Some(&f.alice.did), json!({}));
        for out in [
            act_v0_2(&f.state, &alice_client(), document.clone()).await,
            act(&f.state, &alice_client(), document).await,
        ] {
            assert!(out["payload"].get("principal").is_none(), "{out}");
            assert!(!code(&out).is_empty(), "{out}");
        }
    }

    /// 0.4 completes everything 0.3 does: the 0.1 listing, an acceptance, and a host-bound
    /// room request with its presentation.
    #[tokio::test]
    async fn act_0_4_completes_what_0_3_does() {
        let f = fixture(&["read"]).await;
        for (type_uri, payload) in [
            (OFFERS_LIST, json!({})),
            (OFFERS_ACCEPT, json!({ "roomId": Party::new().did })),
        ] {
            let out = act_v0_4(
                &f.state,
                &alice_client(),
                offer(type_uri, Some(&f.alice.did), payload),
            )
            .await;
            assert_eq!(
                out["payload"]["principal"], f.alice.did,
                "{type_uri}: {out}"
            );
        }
        let out = act_v0_4(
            &f.state,
            &alice_client(),
            unsigned(
                vti_rooms::wire::ROOMS_RECORDS_GET_TYPE,
                "did:key:zHost",
                json!({ "roomId": f.room.did, "key": KEY }),
            ),
        )
        .await;
        assert_eq!(out["payload"]["principal"], f.alice.did, "{out}");
        assert!(
            out["payload"]["document"]["payload"]["presentation"].is_object(),
            "{out}"
        );
        // An administrator's task is still not actable at 0.4.
        let out = act_v0_4(
            &f.state,
            &alice_client(),
            offer(
                "https://trusttasks.org/spec/vtc/rooms/community/members/add/0.1",
                Some(&f.alice.did),
                json!({ "roomId": f.room.did, "member": f.bob.did }),
            ),
        )
        .await;
        assert!(out["payload"].get("principal").is_none(), "{out}");
    }

    async fn act_v0_2(state: &AppState, auth: &AuthClaims, document: Value) -> Value {
        body(
            handle_act_v0_2(
                state,
                auth,
                request(ACT_0_2, json!({ "document": document })),
            )
            .await,
        )
    }

    /// Every `rooms.keys.act` audit row as `(target, detail)`, oldest first. A DID
    /// resource is the row's target (`target_did_plain` beside its hash).
    async fn act_rows(state: &AppState) -> Vec<(Option<String>, Option<String>)> {
        let mut rows: Vec<(String, Option<String>, Option<String>)> = state
            .audit_ks
            .prefix_iter_raw("log:")
            .await
            .expect("scan the audit log")
            .iter()
            .filter_map(|(_, v)| serde_json::from_slice::<Value>(v).ok())
            .filter(|r| r["event"]["data"]["action"] == "rooms.keys.act")
            .map(|r| {
                (
                    r["timestamp"].as_str().unwrap_or_default().to_string(),
                    r["target_did_plain"].as_str().map(str::to_string),
                    r["event"]["data"]["detail"].as_str().map(str::to_string),
                )
            })
            .collect();
        rows.sort_by(|a, b| a.0.cmp(&b.0));
        rows.into_iter().map(|(_, t, d)| (t, d)).collect()
    }

    /// `rooms/keys/act/0.2` recipient item 2a: a type that names no room is completed as
    /// its `issuer` and nobody else. Absent, it is `principalAmbiguous` even where the
    /// caller may act as exactly one member — the VTA never picks one; a member the caller
    /// may not act as is `issuerNotPrincipal`.
    #[tokio::test]
    async fn act_0_2_completes_a_room_less_type_only_as_its_named_issuer() {
        let f = fixture(&["read"]).await;
        let chunk = |issuer: Option<&str>| {
            let mut d = unsigned(
                vti_rooms::wire::ROOMS_BLOBS_CHUNK_TYPE,
                "did:key:zHost",
                json!({ "downloadId": "3e0f5a7c-9b21-4d8e-a6c4-2f1b0d9e8c7a", "index": 0 }),
            );
            if let Some(i) = issuer {
                d["issuer"] = json!(i);
            }
            d
        };

        let out = act_v0_2(&f.state, &alice_client(), chunk(None)).await;
        assert_eq!(code(&out), "rooms/keys/act:principalAmbiguous", "{out}");

        let out = act_v0_2(&f.state, &alice_client(), chunk(Some(&f.bob.did))).await;
        assert_eq!(code(&out), "rooms/keys/act:issuerNotPrincipal", "{out}");
        assert_eq!(out["payload"]["details"]["issuer"], f.bob.did, "{out}");

        let out = act_v0_2(&f.state, &alice_client(), chunk(Some(&f.alice.did))).await;
        assert_eq!(out["payload"]["principal"], f.alice.did, "{out}");
        assert_eq!(out["payload"]["document"]["issuer"], f.alice.did, "{out}");
        assert!(
            out["type"].as_str().is_some_and(|t| t.starts_with(ACT_0_2)),
            "{out}"
        );
        serde_json::from_value::<trust_tasks_rs::specs::rooms::keys::act::v0_2::Response>(
            out["payload"].clone(),
        )
        .expect("a 0.2 response");

        // The subject is the member: the audit row's resource.
        let rows = act_rows(&f.state).await;
        let last = rows.last().expect("a row");
        assert_eq!(last.0.as_deref(), Some(f.alice.did.as_str()), "{rows:?}");
    }

    /// `rooms/keys/act/0.2` *The subject*: a policy and an audit row take the member item 2
    /// resolves — when `issuer` is absent, the one member of the room the caller may act as —
    /// never the room, and never "no subject". 0.1 keeps the room as its row's resource.
    #[tokio::test]
    async fn act_0_2_records_and_gates_the_resolved_member_as_the_subject() {
        let f = fixture(&["read"]).await;
        let get = || {
            unsigned(
                vti_rooms::wire::ROOMS_RECORDS_GET_TYPE,
                "did:key:zHost",
                json!({ "roomId": f.room.did, "key": KEY }),
            )
        };

        // The policy gate's subject, before the handler runs.
        let resolved = act_subject(&f.state, &alice_client(), &json!({ "document": get() })).await;
        assert_eq!(resolved.as_deref(), Some(f.alice.did.as_str()));
        let mut named = get();
        named["issuer"] = json!(f.bob.did);
        assert_eq!(
            act_subject(&f.state, &alice_client(), &json!({ "document": named }))
                .await
                .as_deref(),
            Some(f.bob.did.as_str()),
            "the value at subjectPath, when set"
        );
        let nobody = crate::test_support::admin_claims_for_context("bob");
        assert_eq!(
            act_subject(&f.state, &nobody, &json!({ "document": get() })).await,
            None,
            "no member resolves, so the handler refuses"
        );

        let out = act_v0_2(&f.state, &alice_client(), get()).await;
        assert_eq!(out["payload"]["principal"], f.alice.did, "{out}");
        let out = act(&f.state, &alice_client(), get()).await;
        assert_eq!(out["payload"]["principal"], f.alice.did, "{out}");

        let rows = act_rows(&f.state).await;
        assert_eq!(rows.len(), 2, "{rows:?}");
        let (v2_target, v2_detail) = &rows[0];
        assert_eq!(
            v2_target.as_deref(),
            Some(f.alice.did.as_str()),
            "the 0.2 row names the member: {rows:?}"
        );
        assert!(
            v2_detail
                .as_deref()
                .is_some_and(|d| d.contains(&format!("roomId={}", f.room.did))),
            "{rows:?}"
        );
        assert_eq!(
            rows[1].0.as_deref(),
            Some(f.room.did.as_str()),
            "the 0.1 row names the room, as it always has: {rows:?}"
        );
    }

    async fn seal(state: &AppState, auth: &AuthClaims, payload: Value) -> Value {
        body(handle_seal_v0_2(state, auth, request(SEAL, payload)).await)
    }

    /// **The point of the task.** A record the member's own client writes is the persona's:
    /// the host records the persona as author, the body's proof is the persona's, and the
    /// client's DID — and this VTA's — appear nowhere the host saw or stored.
    #[tokio::test]
    async fn a_record_written_by_the_members_own_client_is_the_personas() {
        let f = fixture(&["read", "write"]).await;
        found_group(&f, &f.alice.did).await;
        let client = alice_client();
        let vta_did = f.state.config.read().await.vta_did.clone().unwrap();

        // A real host, holding the room on the attributed tier.
        let host_dir = tempfile::tempdir().unwrap();
        let host = room_host::open_state(host_dir.path()).expect("a host");
        vti_rooms::storage::create_room(
            host.rooms(),
            &vti_rooms::Room {
                room_id: f.room.did.clone(),
                owner_did: f.alice.did.clone(),
                visibility: vti_rooms::Visibility::Attributed,
                retention_policy: vti_rooms::RetentionPolicy::Chained,
                anchor_cadence: Default::default(),
                epoch: 1,
                next_version: 1,
                retention_days: 90,
                epoch_expires_at: None,
                created_at: 0,
                updated_at: 0,
                mirror_of: None,
            },
        )
        .await
        .expect("seed the room");

        // seal 0.2 under `signAsPrincipal`: the body names the persona, unsigned.
        let unsigned_body = json!({
            "roomId": f.room.did, "key": KEY, "version": 1, "author": f.alice.did,
            "title": "Pricing holds", "body": "Agreed not to reprice.",
        });
        let sealed = seal(
            &f.state,
            &client,
            json!({
                "roomId": f.room.did, "key": KEY, "version": 1,
                "plaintext": b64(&unsigned_body), "signAsPrincipal": true,
            }),
        )
        .await;
        assert!(
            sealed["type"].as_str().unwrap().ends_with("#response"),
            "{sealed}"
        );

        // act: the client's unsigned put, completed as the persona.
        let out = act(
            &f.state,
            &client,
            unsigned(
                vti_rooms::wire::ROOMS_RECORDS_PUT_TYPE,
                "did:key:zHost",
                json!({
                    "roomId": f.room.did, "key": KEY, "expectedVersion": 0,
                    "sealed": sealed["payload"]["sealed"],
                }),
            ),
        )
        .await;
        assert!(
            out["type"].as_str().unwrap().ends_with("#response"),
            "{out}"
        );
        assert_eq!(out["payload"]["principal"], f.alice.did);
        let completed = out["payload"]["document"].clone();
        assert_eq!(completed["issuer"], f.alice.did);
        assert_eq!(completed["proof"]["proofPurpose"], "authentication");
        assert!(
            completed["proof"]["verificationMethod"]
                .as_str()
                .unwrap()
                .starts_with(&format!("{}#", f.alice.did)),
            "{completed}"
        );
        let sent = serde_json::to_string(&completed).unwrap();
        assert!(
            !sent.contains(&client.did),
            "the client's DID reached the host"
        );
        assert!(!sent.contains(&vta_did), "the VTA's DID reached the host");

        // The host verifies the proof, authorizes the chain and records the author.
        let answer = room_host::dispatch(&host, sent.as_bytes()).await;
        assert_eq!(answer.status, 200, "{}", answer.document);
        let stored = vti_rooms::storage::get_record(host.records(), &f.room.did, KEY)
            .await
            .expect("the record");
        assert_eq!(stored.author.as_deref(), Some(f.alice.did.as_str()));
        let stored_json = serde_json::to_string(&stored).unwrap();
        assert!(!stored_json.contains(&client.did));
        assert!(!stored_json.contains(&vta_did));

        // The body opens, and its proof is the persona's, for `assertionMethod`.
        let plaintext = room_groups::open_record(
            &f.state.room_groups_ks,
            &Member::new(&f.room.did, &f.alice.did).unwrap(),
            KEY,
            stored.version,
            stored.sealed.as_deref().unwrap(),
            stored.nonce.as_deref().unwrap(),
            stored.epoch.unwrap(),
        )
        .await
        .expect("the record opens");
        let mut signed: Value = serde_json::from_slice(&plaintext).unwrap();
        assert!(!String::from_utf8_lossy(&plaintext).contains(&client.did));
        let proof: affinidi_data_integrity::DataIntegrityProof =
            serde_json::from_value(signed.as_object_mut().unwrap().remove("proof").unwrap())
                .unwrap();
        assert_eq!(proof.proof_purpose, "assertionMethod");
        assert!(
            proof
                .verification_method
                .starts_with(&format!("{}#", f.alice.did))
        );
        assert_eq!(signed, unsigned_body, "the body is signed, not composed");
        proof
            .verify_with_public_key(
                &signed,
                &f.alice.public_key,
                affinidi_data_integrity::VerifyOptions::new(),
            )
            .expect("the body verifies against the persona's key");
    }

    /// A file moved by the member's own client is the persona's too: the begin and the
    /// direct commit are completed as the persona, the bytes go straight to storage over
    /// the host's targets, and a proxied upload's chunks are signed by a single-use key —
    /// and neither the client's DID nor the upload key is recorded anywhere.
    #[tokio::test]
    async fn a_file_moved_by_the_members_own_client_is_the_personas() {
        use sha2::{Digest, Sha256};
        use trust_tasks_rs::specs::rooms::blobs::upload as up;
        use vti_common::blob_store::sha256_digest_multibase as mb;

        let f = fixture(&["read", "write"]).await;
        let client = alice_client();
        let s3 = vti_common::blob_store::mock_s3::MockS3::start(true).await;
        let store =
            vti_common::blob_store::presigned::PresignedBlobs::new("s3", s3.presigner(), None)
                .unwrap()
                .with_plain_http();
        let host_dir = tempfile::tempdir().unwrap();
        let host = room_host::open_state_with_files(
            host_dir.path(),
            vti_common::auth::TrustTaskVmResolver::did_key_only(),
            room_host::FilesConfig {
                store: Some(std::sync::Arc::new(store)),
                config_id: Some("s3".into()),
                ..Default::default()
            },
        )
        .expect("a host");
        vti_rooms::storage::create_room(
            host.rooms(),
            &vti_rooms::Room {
                room_id: f.room.did.clone(),
                owner_did: f.alice.did.clone(),
                visibility: vti_rooms::Visibility::Attributed,
                retention_policy: vti_rooms::RetentionPolicy::Chained,
                anchor_cadence: Default::default(),
                epoch: 1,
                next_version: 1,
                retention_days: 90,
                epoch_expires_at: None,
                created_at: 0,
                updated_at: 0,
                mirror_of: None,
            },
        )
        .await
        .expect("seed the room");

        let manifest = |bytes: &[u8]| {
            let digests: Vec<String> = bytes
                .chunks(16_384)
                .map(|c| mb(&Sha256::digest(c).into()))
                .collect();
            json!({
                "size": bytes.len(),
                "chunks": { "chunkSize": 16_384, "chunkCount": digests.len(), "chunkDigests": digests },
                "digest": mb(&Sha256::digest(bytes).into()),
            })
        };
        // Act, then send the completed document to the host, checking what it carries.
        let send = |doc: Value| {
            let host = host.clone();
            let client_did = client.did.clone();
            async move {
                let sent = serde_json::to_string(&doc).unwrap();
                assert!(
                    !sent.contains(&client_did),
                    "the client's DID reached the host"
                );
                let answer = room_host::dispatch(&host, sent.as_bytes()).await;
                assert_eq!(answer.status, 200, "{}", answer.document);
                answer.document["payload"].clone()
            }
        };
        let completed = |out: Value| {
            assert!(
                out["type"].as_str().unwrap().ends_with("#response"),
                "{out}"
            );
            assert_eq!(out["payload"]["principal"], f.alice.did);
            out["payload"]["document"].clone()
        };

        // Direct: two parts straight to storage, committed as the persona.
        const PART: usize = vti_common::blob_store::MIN_MULTIPART_PART_BYTES as usize;
        let bytes: Vec<u8> = (0..PART + 70_000).map(|i| (i % 253) as u8).collect();
        let plan: Vec<String> = bytes
            .chunks(PART)
            .map(|c| mb(&Sha256::digest(c).into()))
            .collect();
        let key = vta_sdk::did_key::ed25519_multibase_pubkey(&[7; 32]);
        let begin = completed(
            act(
                &f.state,
                &client,
                unsigned(
                    <up::begin::v0_2::Payload as trust_tasks_rs::Payload>::TYPE_URI,
                    "did:key:zHost",
                    json!({
                        "roomId": f.room.did, "manifest": manifest(&bytes),
                        "uploadKey": format!("did:key:{key}"),
                        "directParts": { "partSize": PART, "partCount": 2, "partDigests": plan },
                    }),
                ),
            )
            .await,
        );
        assert_eq!(begin["issuer"], f.alice.did);
        let begun = send(begin).await;
        assert_eq!(begun["mode"], "direct", "{begun}");
        for (t, part) in begun["targets"]
            .as_array()
            .unwrap()
            .iter()
            .zip(bytes.chunks(PART))
        {
            let mut req = reqwest::Client::new().put(
                t["url"]
                    .as_str()
                    .unwrap()
                    .replacen("https://", "http://", 1),
            );
            for (k, v) in t["headers"].as_object().unwrap() {
                req = req.header(k, v.as_str().unwrap());
            }
            assert!(
                req.body(part.to_vec())
                    .send()
                    .await
                    .unwrap()
                    .status()
                    .is_success()
            );
        }
        let mut commit = unsigned(
            <up::commit::v0_2::Payload as trust_tasks_rs::Payload>::TYPE_URI,
            "did:key:zHost",
            json!({ "uploadId": begun["uploadId"] }),
        );
        // No room is named, so the member is.
        commit["issuer"] = json!(f.alice.did);
        let committed = send(completed(act(&f.state, &client, commit).await)).await;
        let blob_ref = committed["blobRef"].as_str().unwrap().to_string();
        let entry = host
            .files()
            .blob(&f.room.did, &blob_ref)
            .await
            .unwrap()
            .expect("committed after verification at storage");
        assert_eq!(entry.charged_to.as_deref(), Some(f.alice.did.as_str()));
        assert!(!serde_json::to_string(&entry).unwrap().contains(&client.did));

        // Proxied: the persona begins, a single-use key sends and commits.
        let small: Vec<u8> = (0..20_000).map(|i| (i % 7) as u8).collect();
        let (key_did, key_secret) = {
            let seed = [9u8; 32];
            let pk = ed25519_dalek::SigningKey::from_bytes(&seed)
                .verifying_key()
                .to_bytes();
            (
                format!(
                    "did:key:{}",
                    vta_sdk::did_key::ed25519_multibase_pubkey(&pk)
                ),
                multibase::encode(multibase::Base::Base58Btc, seed),
            )
        };
        let begin = completed(
            act(
                &f.state,
                &client,
                unsigned(
                    <up::begin::v0_2::Payload as trust_tasks_rs::Payload>::TYPE_URI,
                    "did:key:zHost",
                    json!({ "roomId": f.room.did, "manifest": manifest(&small), "uploadKey": key_did }),
                ),
            )
            .await,
        );
        let begun = send(begin).await;
        assert_eq!(begun["mode"], "proxied", "{begun}");
        let by_key = |type_uri: &'static str, payload: Value| {
            let (key_did, key_secret) = (key_did.clone(), key_secret.clone());
            async move {
                let doc = vta_sdk::trust_task_sign::build_signed(
                    type_uri,
                    payload,
                    &key_did,
                    &key_secret,
                    "did:key:zHost",
                )
                .await
                .unwrap();
                serde_json::from_str::<Value>(&doc).unwrap()
            }
        };
        for (i, c) in small.chunks(16_384).enumerate() {
            let doc = by_key(
                <up::chunk::v0_2::Payload as trust_tasks_rs::Payload>::TYPE_URI,
                json!({ "uploadId": begun["uploadId"], "index": i,
                        "data": base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, c),
                        "digestMultibase": mb(&Sha256::digest(c).into()) }),
            )
            .await;
            send(doc).await;
        }
        let doc = by_key(
            <up::commit::v0_2::Payload as trust_tasks_rs::Payload>::TYPE_URI,
            json!({ "uploadId": begun["uploadId"] }),
        )
        .await;
        let committed = send(doc).await;
        let entry = host
            .files()
            .blob(&f.room.did, committed["blobRef"].as_str().unwrap())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(entry.charged_to.as_deref(), Some(f.alice.did.as_str()));
        let raw = serde_json::to_string(&entry).unwrap();
        assert!(!raw.contains(&key_did) && !raw.contains(&client.did));
    }

    /// Item 1: a type outside the table is refused before anything is resolved.
    #[tokio::test]
    async fn act_refuses_a_type_outside_the_table() {
        let f = fixture(&["read", "write", "admin"]).await;
        let out = act(
            &f.state,
            &alice_client(),
            unsigned(
                vti_rooms::wire::ROOMS_EPOCH_PRUNE_TYPE,
                "did:key:zHost",
                json!({ "roomId": f.room.did, "beforeEpoch": 2 }),
            ),
        )
        .await;
        assert_eq!(code(&out), "rooms/keys/act:typeNotActable", "{out}");
        assert_eq!(
            out["payload"]["details"]["type"],
            vti_rooms::wire::ROOMS_EPOCH_PRUNE_TYPE
        );
    }

    /// Item 9: a mint for a room whose group this VTA holds — for any member, even one the
    /// caller cannot act as — is `sealedRoomMint`; an open room (no group here) still mints.
    #[tokio::test]
    async fn act_refuses_a_mint_for_a_sealed_room_and_completes_one_for_an_open_room() {
        let f = fixture(&["read", "write", "admin"]).await;
        let mint = |room: &str| {
            unsigned(
                vti_rooms::wire::ROOMS_EPOCH_MINT_TYPE,
                "did:key:zHost",
                json!({ "roomId": room, "epoch": 2 }),
            )
        };

        // Open: no group state, so the table applies.
        let out = act(&f.state, &alice_client(), mint(&f.room.did)).await;
        assert_eq!(out["payload"]["principal"], f.alice.did, "{out}");

        // Sealed: bob's persona holds the group — another member, another context.
        found_group(&f, &f.bob.did).await;
        let out = act(&f.state, &alice_client(), mint(&f.room.did)).await;
        assert_eq!(code(&out), "rooms/keys/act:sealedRoomMint", "{out}");
        assert!(
            out["payload"]["message"]
                .as_str()
                .unwrap_or_default()
                .contains("group-renew"),
            "{out}"
        );
    }

    /// Item 2: no member here the caller may act as — whether nobody holds the room, or only
    /// someone in another context does.
    #[tokio::test]
    async fn act_refuses_a_caller_who_is_not_a_member() {
        let f = fixture(&["read"]).await;
        let get = |room: &str| {
            unsigned(
                vti_rooms::wire::ROOMS_RECORDS_GET_TYPE,
                "did:key:zHost",
                json!({ "roomId": room, "key": KEY }),
            )
        };
        let nobody = act(&f.state, &alice_client(), get(&Party::new().did)).await;
        assert_eq!(code(&nobody), "rooms/keys/act:notAMember", "{nobody}");
        let bobs_caller = crate::test_support::admin_claims_for_context("bob");
        let elsewhere = act(&f.state, &bobs_caller, get(&f.room.did)).await;
        assert_eq!(code(&elsewhere), "rooms/keys/act:notAMember", "{elsewhere}");
    }

    /// Item 2: a caller acting as two members of the room must name one; naming one that is
    /// not a member it may act as is `issuerNotPrincipal`.
    #[tokio::test]
    async fn act_asks_an_ambiguous_caller_to_name_the_member() {
        let f = fixture(&["read"]).await;
        grant(&f.state, &f.room, &f.bob.did, "bob", &["read"]).await;
        let both = AuthClaims {
            allowed_contexts: vec!["alice".into(), "bob".into()],
            ..crate::test_support::super_admin_claims()
        };
        let get = |issuer: Option<&str>| {
            let mut d = unsigned(
                vti_rooms::wire::ROOMS_RECORDS_GET_TYPE,
                "did:key:zHost",
                json!({ "roomId": f.room.did, "key": KEY }),
            );
            if let Some(i) = issuer {
                d["issuer"] = json!(i);
            }
            d
        };
        let out = act(&f.state, &both, get(None)).await;
        assert_eq!(code(&out), "rooms/keys/act:principalAmbiguous", "{out}");

        let named = act(&f.state, &both, get(Some(&f.bob.did))).await;
        assert_eq!(named["payload"]["principal"], f.bob.did, "{named}");

        // Alice's caller cannot name bob — and a DID nobody holds reads the same.
        for stranger in [
            f.bob.did.as_str(),
            "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
        ] {
            let out = act(&f.state, &alice_client(), get(Some(stranger))).await;
            assert_eq!(code(&out), "rooms/keys/act:issuerNotPrincipal", "{out}");
            assert_eq!(out["payload"]["details"]["issuer"], stranger);
        }
    }

    /// Item 4: the member's credentials must confer the table's action for the type.
    #[tokio::test]
    async fn act_refuses_an_action_the_member_does_not_hold() {
        let f = fixture(&["read"]).await;
        let out = act(
            &f.state,
            &alice_client(),
            unsigned(
                vti_rooms::wire::ROOMS_RECORDS_PUT_TYPE,
                "did:key:zHost",
                json!({
                    "roomId": f.room.did, "key": KEY, "expectedVersion": 0,
                    "cleartext": { "title": "x" },
                }),
            ),
        )
        .await;
        assert_eq!(code(&out), "rooms/keys/act:actionNotHeld", "{out}");
        assert_eq!(out["payload"]["details"]["action"], "write");
    }

    /// The presentation inserted is narrowed to exactly the table's action, granted to the
    /// member.
    #[tokio::test]
    async fn act_narrows_to_exactly_the_tables_action_granted_to_the_member() {
        let f = fixture(&["read", "write", "admin"]).await;
        let out = act(
            &f.state,
            &alice_client(),
            unsigned(
                vti_rooms::wire::ROOMS_RECORDS_GET_TYPE,
                "did:key:zHost",
                json!({ "roomId": f.room.did, "key": KEY }),
            ),
        )
        .await;
        let leaf: Value = serde_json::from_str(
            out["payload"]["document"]["payload"]["presentation"]["authority"][0]
                .as_str()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(leaf["credentialSubject"]["id"], f.alice.did);
        assert_eq!(
            leaf["credentialSubject"]["authority"]["actions"],
            json!(["read"])
        );
        assert!(out["payload"]["expiresAt"].is_string());
    }

    /// Item 3: a delegate — an agent the member equipped — is refused with the standard
    /// `permissionDenied`, on `act` and on `seal` under `signAsPrincipal`.
    #[tokio::test]
    async fn a_delegate_is_refused() {
        let f = fixture(&["read", "write"]).await;
        found_group(&f, &f.alice.did).await;
        let agent = Party::new();
        let entry: vti_common::acl::AclEntry = serde_json::from_value(json!({
            "did": agent.did, "role": "application", "label": null,
            "allowed_contexts": ["alice"], "created_at": 0, "created_by": "test",
            "kind": { "kind": "service", "serviceKind": "ai-agent" },
        }))
        .unwrap();
        vti_common::acl::store_acl_entry(&f.state.acl_ks, &entry)
            .await
            .unwrap();
        let auth = AuthClaims {
            did: agent.did.clone(),
            role: vti_common::acl::Role::Application,
            allowed_contexts: vec!["alice".into()],
            ..crate::test_support::super_admin_claims()
        };
        let out = act(
            &f.state,
            &auth,
            unsigned(
                vti_rooms::wire::ROOMS_RECORDS_GET_TYPE,
                "did:key:zHost",
                json!({ "roomId": f.room.did, "key": KEY }),
            ),
        )
        .await;
        assert_eq!(code(&out), "permissionDenied", "{out}");

        let body = json!({ "roomId": f.room.did, "key": KEY, "version": 1, "author": f.alice.did });
        let out = seal(
            &f.state,
            &auth,
            json!({
                "roomId": f.room.did, "key": KEY, "version": 1,
                "plaintext": b64(&body), "signAsPrincipal": true,
            }),
        )
        .await;
        assert_eq!(code(&out), "permissionDenied", "{out}");
    }

    /// Item 8: a document already carrying a presentation, or not fresh, is malformed.
    #[tokio::test]
    async fn act_refuses_a_stale_or_pre_presented_document() {
        let f = fixture(&["read"]).await;
        let mut stale = unsigned(
            vti_rooms::wire::ROOMS_RECORDS_GET_TYPE,
            "did:key:zHost",
            json!({ "roomId": f.room.did, "key": KEY }),
        );
        stale["issuedAt"] = json!("2020-01-01T00:00:00Z");
        assert_eq!(
            code(&act(&f.state, &alice_client(), stale).await),
            "malformedRequest"
        );
        let presented = unsigned(
            vti_rooms::wire::ROOMS_RECORDS_GET_TYPE,
            "did:key:zHost",
            json!({ "roomId": f.room.did, "key": KEY, "presentation": {} }),
        );
        assert_eq!(
            code(&act(&f.state, &alice_client(), presented).await),
            "malformedRequest"
        );
    }

    /// seal 0.2's author checks, in the specification's words.
    #[tokio::test]
    async fn seal_v0_2_checks_the_author_and_the_location() {
        let f = fixture(&["read", "write"]).await;
        let client = alice_client();
        let payload = |body: &Value, version: u64| {
            json!({
                "roomId": f.room.did, "key": KEY, "version": version,
                "plaintext": b64(body), "signAsPrincipal": true,
            })
        };
        let good = json!({ "roomId": f.room.did, "key": KEY, "version": 1, "author": f.alice.did });

        // No group state for alice's persona yet.
        let out = seal(&f.state, &client, payload(&good, 1)).await;
        assert_eq!(code(&out), "rooms/keys/seal:notAMember", "{out}");
        found_group(&f, &f.alice.did).await;

        // An unknown member, and a proof already present.
        let mut unknown = good.clone();
        unknown["colour"] = json!("blue");
        let out = seal(&f.state, &client, payload(&unknown, 1)).await;
        assert_eq!(code(&out), "rooms/keys/seal:bodyInvalid", "{out}");
        let mut proofed = good.clone();
        proofed["proof"] = json!({});
        let out = seal(&f.state, &client, payload(&proofed, 1)).await;
        assert_eq!(code(&out), "rooms/keys/seal:bodyInvalid", "{out}");

        // An author the caller does not act as.
        let mut bobs = good.clone();
        bobs["author"] = json!(f.bob.did);
        let out = seal(&f.state, &client, payload(&bobs, 1)).await;
        assert_eq!(code(&out), "rooms/keys/seal:authorNotPrincipal", "{out}");
        assert_eq!(out["payload"]["details"]["author"], f.bob.did);

        // A body signed for one version and sealed for another.
        let out = seal(&f.state, &client, payload(&good, 2)).await;
        assert_eq!(code(&out), "rooms/keys/seal:locationMismatch", "{out}");

        // And the good one seals.
        let out = seal(&f.state, &client, payload(&good, 1)).await;
        assert!(out["payload"]["sealed"]["ciphertext"].is_string(), "{out}");
    }

    /// Without `signAsPrincipal`, 0.2 is 0.1: the bytes are sealed exactly as given.
    #[tokio::test]
    async fn seal_v0_2_without_the_flag_seals_the_bytes_given() {
        let f = fixture(&["read", "write"]).await;
        found_group(&f, &f.alice.did).await;
        let bytes = json!({ "anything": "the writer signed" });
        let out = seal(
            &f.state,
            &alice_client(),
            json!({ "roomId": f.room.did, "key": KEY, "version": 1, "plaintext": b64(&bytes) }),
        )
        .await;
        let sealed = &out["payload"]["sealed"];
        let opened = room_groups::open_record(
            &f.state.room_groups_ks,
            &Member::new(&f.room.did, &f.alice.did).unwrap(),
            KEY,
            1,
            sealed["ciphertext"].as_str().unwrap(),
            sealed["nonce"].as_str().unwrap(),
            sealed["epoch"].as_u64().unwrap() as u32,
        )
        .await
        .unwrap();
        assert_eq!(opened, serde_json::to_vec(&bytes).unwrap());
    }

    // ─── read / browse / backfill: as the principal, never as this VTA ──────

    /// A stand-in host on loopback that records every document it receives and answers
    /// `rooms/records/{get,list}` and `rooms/epoch/chain` signed as itself.
    async fn recording_host() -> (Party, Value, Arc<Mutex<Vec<Value>>>) {
        recording_host_serving(json!({ "cleartext": { "title": "t" } })).await
    }

    /// [`recording_host`], answering `rooms/records/get` with `content` (`cleartext` or
    /// `sealed`) for the requested key at version 1.
    async fn recording_host_serving(content: Value) -> (Party, Value, Arc<Mutex<Vec<Value>>>) {
        let party = Party::new();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let host_did = party.did.clone();
        let secret = party.secret_multibase.clone();
        let log = seen.clone();
        let app = axum::Router::new().route(
            "/trust-tasks",
            axum::routing::post(move |axum::Json(req): axum::Json<Value>| {
                let host_did = host_did.clone();
                let secret = secret.clone();
                let log = log.clone();
                let content = content.clone();
                async move {
                    log.lock().unwrap().push(req.clone());
                    let task = req["type"].as_str().unwrap_or_default().to_string();
                    let room_id = req["payload"]["roomId"].clone();
                    let payload = if task == vti_rooms::wire::ROOMS_RECORDS_GET_TYPE {
                        let mut record = json!({
                            "key": req["payload"]["key"], "version": 1, "status": "active",
                            "updatedAt": "2026-01-01T00:00:00Z",
                        });
                        for (k, v) in content.as_object().unwrap() {
                            record[k] = v.clone();
                        }
                        record
                    } else if task == vti_rooms::wire::ROOMS_RECORDS_LIST_TYPE {
                        json!({ "records": [] })
                    } else {
                        json!({ "roomId": room_id, "links": [] })
                    };
                    let mut doc: TrustTask<Value> = serde_json::from_value(json!({
                        "id": format!("urn:uuid:{}", uuid::Uuid::new_v4()),
                        "type": format!("{task}#response"),
                        "issuer": host_did,
                        "recipient": req["issuer"],
                        "issuedAt": Utc::now().to_rfc3339(),
                        "threadId": req["id"],
                        "payload": payload,
                    }))
                    .unwrap();
                    vta_sdk::trust_task_sign::sign_in_place(&mut doc, &host_did, &secret)
                        .await
                        .unwrap();
                    (
                        axum::http::StatusCode::OK,
                        serde_json::to_string(&doc).unwrap(),
                    )
                }
            }),
        );
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let mb = party.did.strip_prefix("did:key:").unwrap().to_string();
        let vm = format!("{}#{mb}", party.did);
        let doc = json!({
            "@context": ["https://www.w3.org/ns/did/v1"],
            "id": party.did,
            "verificationMethod": [{
                "id": vm, "type": "Multikey", "controller": party.did, "publicKeyMultibase": mb,
            }],
            "authentication": [vm],
            "assertionMethod": [vm],
            "service": [{
                "id": format!("{}#rest", party.did), "type": "TrustTaskHTTPS",
                "serviceEndpoint": format!("http://127.0.0.1:{port}"),
            }],
        });
        (party, doc, seen)
    }

    /// **The defect, found live**: a context-scoped caller's `read` / `browse` / `backfill`
    /// presented to, and signed as, this VTA's own DID — and failed, because the caller may
    /// not sign with the VTA's `#key-0`. Now each document the host receives is the
    /// persona's: issuer, signer and leaf subject, and the VTA's DID is in none of them.
    #[tokio::test]
    async fn read_browse_and_backfill_act_as_the_principal_for_a_context_scoped_caller() {
        let mut f = fixture(&["read", "write"]).await;
        found_group(&f, &f.alice.did).await;
        let (host, host_doc, seen) = recording_host().await;
        let mut resolver = affinidi_did_resolver_cache_sdk::DIDCacheClient::new(
            affinidi_did_resolver_cache_sdk::config::DIDCacheConfigBuilder::default().build(),
        )
        .await
        .unwrap();
        resolver
            .add_did_document(&host.did, serde_json::from_value(host_doc).unwrap())
            .await;
        f.state.did_resolver = Some(resolver);
        let vta_did = f.state.config.read().await.vta_did.clone().unwrap();
        let client = alice_client();
        assert!(!client.is_super_admin(), "the caller the defect hit");

        let read = body(
            super::super::room_group::handle_read(
                &f.state,
                &client,
                request(
                    vta_sdk::trust_tasks::TASK_ROOMS_KEYS_READ_0_1,
                    json!({ "roomId": f.room.did, "key": KEY, "host": host.did }),
                ),
            )
            .await,
        );
        assert!(
            read["type"].as_str().unwrap().ends_with("#response"),
            "{read}"
        );
        let browse = body(
            super::super::room_group::handle_browse(
                &f.state,
                &client,
                request(
                    vta_sdk::trust_tasks::TASK_ROOMS_KEYS_BROWSE_0_1,
                    json!({ "roomId": f.room.did, "host": host.did }),
                ),
            )
            .await,
        );
        assert!(
            browse["type"].as_str().unwrap().ends_with("#response"),
            "{browse}"
        );
        let backfill = body(
            super::super::room_group::handle_backfill(
                &f.state,
                &client,
                request(
                    vta_sdk::trust_tasks::TASK_ROOMS_KEYS_BACKFILL_0_1,
                    json!({ "roomId": f.room.did, "host": host.did }),
                ),
            )
            .await,
        );
        assert!(
            backfill["type"].as_str().unwrap().ends_with("#response"),
            "{backfill}"
        );

        let received = seen.lock().unwrap().clone();
        assert_eq!(received.len(), 3);
        for doc in &received {
            let text = doc.to_string();
            assert!(
                !text.contains(&vta_did),
                "the VTA's DID reached the host: {text}"
            );
            assert!(
                !text.contains(&client.did),
                "the client's DID reached the host"
            );
            assert_eq!(doc["issuer"], f.alice.did);
            assert!(
                doc["proof"]["verificationMethod"]
                    .as_str()
                    .unwrap()
                    .starts_with(&format!("{}#", f.alice.did))
            );
            let leaf: Value = serde_json::from_str(
                doc["payload"]["presentation"]["authority"][0]
                    .as_str()
                    .unwrap(),
            )
            .unwrap();
            assert_eq!(leaf["credentialSubject"]["id"], f.alice.did);
            assert_eq!(
                leaf["credentialSubject"]["authority"]["actions"],
                json!(["read"])
            );
        }
    }

    /// **Found live**: `read` answered a sealed record's `plaintext` as a JSON array of
    /// numbers, which a client decoding the spec's base64url string refused
    /// (`rooms/keys/read/0.1`: `plaintext` is the opened record, base64url).
    #[tokio::test]
    async fn read_answers_a_sealed_records_plaintext_as_base64url() {
        let mut f = fixture(&["read", "write"]).await;
        found_group(&f, &f.alice.did).await;
        let sealed = room_groups::seal_record(
            &f.state.room_groups_ks,
            &Member::new(&f.room.did, &f.alice.did).unwrap(),
            KEY,
            1,
            b"a note",
        )
        .await
        .unwrap();
        let (host, host_doc, _seen) =
            recording_host_serving(json!({ "sealed": serde_json::to_value(&sealed).unwrap() }))
                .await;
        let mut resolver = affinidi_did_resolver_cache_sdk::DIDCacheClient::new(
            affinidi_did_resolver_cache_sdk::config::DIDCacheConfigBuilder::default().build(),
        )
        .await
        .unwrap();
        resolver
            .add_did_document(&host.did, serde_json::from_value(host_doc).unwrap())
            .await;
        f.state.did_resolver = Some(resolver);

        let read = body(
            super::super::room_group::handle_read(
                &f.state,
                &alice_client(),
                request(
                    vta_sdk::trust_tasks::TASK_ROOMS_KEYS_READ_0_1,
                    json!({ "roomId": f.room.did, "key": KEY, "host": host.did }),
                ),
            )
            .await,
        );
        let plaintext = read["payload"]["plaintext"]
            .as_str()
            .unwrap_or_else(|| panic!("plaintext is not a string: {read}"));
        assert_eq!(
            base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, plaintext)
                .unwrap(),
            b"a note"
        );
    }

    // ─── transport: the binding whose authenticated sender can be the signer ───

    /// The recording host's document, also advertising DIDComm through a mediator —
    /// a VTC on messaging, which serves its Trust-Task HTTPS door as well. DIDComm is
    /// listed first, as the canonical service order puts it.
    fn advertising_didcomm_too(mut doc: Value) -> Value {
        let did = doc["id"].as_str().unwrap().to_string();
        doc["service"].as_array_mut().unwrap().insert(
            0,
            json!({
                "id": format!("{did}#didcomm"),
                "type": "DIDCommMessaging",
                "serviceEndpoint": [{ "uri": "did:example:mediator", "accept": ["didcomm/v2"] }],
            }),
        );
        doc
    }

    /// `keys backfill` as alice's client asks it, against `host`.
    async fn backfill_as_alice(f: &Fx, host: &str) -> Value {
        body(
            super::super::room_group::handle_backfill(
                &f.state,
                &alice_client(),
                request(
                    vta_sdk::trust_tasks::TASK_ROOMS_KEYS_BACKFILL_0_1,
                    json!({ "roomId": f.room.did, "host": host }),
                ),
            )
            .await,
        )
    }

    async fn resolver_with(
        did: &str,
        doc: Value,
    ) -> affinidi_did_resolver_cache_sdk::DIDCacheClient {
        let mut resolver = affinidi_did_resolver_cache_sdk::DIDCacheClient::new(
            affinidi_did_resolver_cache_sdk::config::DIDCacheConfigBuilder::default().build(),
        )
        .await
        .unwrap();
        resolver
            .add_did_document(did, serde_json::from_value(doc).unwrap())
            .await;
        resolver
    }

    /// **Found live**: a REST-only VTA (`[messaging] kind = "skip"`) sending a member's
    /// room request to a VTC that advertises DIDComm and HTTPS picked DIDComm — the
    /// higher preference — and failed *"DIDComm messaging not initialized"*. A transport
    /// this VTA cannot start is not in its set, so the request goes over the HTTPS both
    /// sides can use, and the host answers it.
    #[tokio::test]
    async fn a_rest_only_vta_reaches_a_host_advertising_didcomm_over_https() {
        let mut f = fixture(&["read", "write"]).await;
        found_group(&f, &f.alice.did).await;
        let (host, host_doc, seen) = recording_host().await;
        f.state.did_resolver =
            Some(resolver_with(&host.did, advertising_didcomm_too(host_doc)).await);
        assert!(
            f.state.didcomm_bridge.vta_did().is_none(),
            "the fixture is the REST-only VTA: no mediator session"
        );

        let reply = backfill_as_alice(&f, &host.did).await;
        assert!(
            reply["type"].as_str().unwrap().ends_with("#response"),
            "the host must be reached and answer: {reply}"
        );
        assert_eq!(seen.lock().unwrap().len(), 1, "one request, over HTTPS");
    }

    /// **Found live**: a VTA on a mediator sent the persona-signed request over DIDComm,
    /// authenticated as **itself**, and the VTC refused it `identityMismatch` — the
    /// DIDComm and TSP bindings make the in-band `issuer` a cross-check against the
    /// transport's authenticated sender. It must go over HTTPS, where no bearer is sent
    /// and the persona's proof is the authentication, and be accepted.
    ///
    /// The bridge reports a live session as the VTA without a mediator, so a DIDComm
    /// selection would fail here *"not initialized"* rather than reach the host.
    #[cfg(feature = "didcomm")]
    #[tokio::test]
    async fn a_persona_signed_request_from_a_vta_on_a_mediator_goes_over_https() {
        let mut f = fixture(&["read", "write"]).await;
        found_group(&f, &f.alice.did).await;
        let (host, host_doc, seen) = recording_host().await;
        let resolver = resolver_with(&host.did, advertising_didcomm_too(host_doc)).await;
        f.state.did_resolver = Some(resolver.clone());
        let vta_did = f.state.config.read().await.vta_did.clone().unwrap();
        f.state.didcomm_bridge.pretend_live_as(&vta_did);

        // DIDComm is wired: this VTA's own documents would still take it.
        let out = crate::operations::outbound::Outbound::from_app_state(&f.state, &resolver);
        assert!(
            out.initiable_protocols(Some(&vta_did))
                .contains(&vta_sdk::protocol::matching::Protocol::Didcomm),
            "the VTA's own documents keep DIDComm"
        );
        assert_eq!(
            out.initiable_protocols(Some(&f.alice.did)),
            vec![vta_sdk::protocol::matching::Protocol::Rest],
            "a persona's document rides only the binding whose sender can be the persona"
        );

        let reply = backfill_as_alice(&f, &host.did).await;
        assert!(
            reply["type"].as_str().unwrap().ends_with("#response"),
            "the persona-signed request must reach the host and be answered: {reply}"
        );
        let received = seen.lock().unwrap().clone();
        assert_eq!(received.len(), 1);
        assert_eq!(received[0]["issuer"], f.alice.did);
        assert!(
            !received[0].to_string().contains(&vta_did),
            "the VTA's DID must not reach the host"
        );
    }
}
