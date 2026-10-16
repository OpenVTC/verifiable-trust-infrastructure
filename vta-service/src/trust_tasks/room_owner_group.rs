//! The owner's half of a sealed room's MLS group — `rooms/owner/group/create/0.1`,
//! `rooms/owner/group/add/0.1`, `rooms/owner/group/remove/0.1` and
//! `rooms/owner/group/renew/0.1`.
//!
//! Every member reaches a room's group by a Welcome (`rooms/keys/welcome`), except the
//! owner, whom nobody can welcome: `create` founds the group with the owner as its only
//! leaf. `add` admits a member — it builds the commit and the Welcome, advances the room's
//! epoch at its host, and returns the Welcome for the caller to deliver. `remove` is its
//! mirror: it drops a member's leaf and advances the room, so nothing sealed from then on
//! is readable to them. It recalls nothing they already read, and on a `chained` room they
//! keep the epochs they were in. `renew` advances the room with a commit that changes no
//! membership — the only correct renewal of a sealed room, whose epoch is its group's epoch
//! plus one, so a bare `rooms/epoch/mint` would move the host and leave every member behind.
//!
//! # Remote first (items 2–6 of `add`, `remove` and `renew`)
//!
//! The host is advanced **before** this agent's own group, never after. The change is
//! built on a copy and kept durably as the room's one pending advance
//! ([`room_groups::PendingAdvance`], an admission, a removal or a renewal) while the live
//! group stays
//! where it is; `rooms/epoch/mint` goes to the host; only an accepted advance replaces the
//! live group. A refusal discards the pending advance. An unknown outcome — a host that
//! could not be reached, or an answer that could not be read — keeps it: the host may have
//! accepted, and a key holder cannot process its own commit from the wire, so the pending
//! group is the only way to follow it there. The next `add`, `remove` or `renew` for the
//! room asks
//! the host which epoch it is at and settles the pending advance first, whichever kind it
//! is: a room holds at most one.

use serde_json::Value;
use trust_tasks_rs::specs::rooms::owner::group::{
    add as spec_add, create as spec_create, remove as spec_remove, renew as spec_renew,
};
use trust_tasks_rs::{DeclaredErrorCode, TrustTask};
use vti_common::acl::Capability;
use vti_common::error::AppError;

use crate::auth::AuthClaims;
use crate::operations::room_groups::{
    self, CreateGroupError, Member, PendingAdvance, PrepareAddError, PrepareRemoveError, Reconciled,
};
use crate::operations::room_host::{RoomTaskError, send_room_task_typed};
use crate::operations::room_member;
use crate::server::AppState;

use super::TrustTaskOutcome;
use super::helpers::{app_error_to_reject, parse_payload, reject_with_code, success_response};
use super::room_group::{declared, now, outbound_identity, record, signing_context};

/// `rooms/owner/group/create/0.1` — found a room's group, with the owner as its only leaf.
pub(super) async fn handle_create(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    use spec_create::v0_1::error_codes as codes;
    if let Err(r) = super::helpers::require_capability(
        state,
        auth,
        &doc,
        Capability::CredentialWrite,
        "founding a room's group",
    )
    .await
    {
        return r;
    }
    let req: spec_create::v0_1::Payload = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    let room_id = req.room_id.as_str();

    // Item 1: control of the room's signing key, the gate issuing its credentials uses —
    // checked without signing anything, since founding produces no signature.
    if let Err(e) = crate::operations::keys::require_key_nameable(
        &state.keys_ks,
        &state.acl_ks,
        auth,
        req.signing_key_id.as_str(),
    )
    .await
    {
        return reject_with_code(
            &doc,
            declared(codes::NO_SIGNING_KEY),
            format!(
                "this agent will not found room `{room_id}`'s group on key `{}`: {e}",
                req.signing_key_id.as_str()
            ),
            None,
        );
    }

    // Item 3: the leaf identifies the owner's **persona** — the subject of their membership
    // and authority credentials — and never the interface client that sent this.
    let member = match founding_member(
        state,
        auth,
        room_id,
        req.member.as_ref().map(|m| m.as_str()),
    )
    .await
    {
        Ok(m) => m,
        Err(e) => return app_error_to_reject(&doc, e),
    };
    // Founded under that persona. Another persona on this VTA holding a group for the same
    // room is another member, and its group is not this one's to refuse over.
    let member = match room_member::member_as(state, auth, room_id, &member).await {
        Ok(m) => m,
        Err(e) => return app_error_to_reject(&doc, e),
    };
    match room_groups::create_group(&state.room_groups_ks, &member, now()).await {
        Ok(epoch) => {
            record(state, "rooms.owner.group.create", auth, room_id).await;
            success_response(
                &doc,
                serde_json::json!({ "roomId": room_id, "epoch": epoch }),
            )
        }
        // Item 2: never replace a group.
        Err(CreateGroupError::AlreadyExists { epoch }) => reject_with_code(
            &doc,
            declared(codes::ALREADY_EXISTS),
            format!(
                "this agent already holds room `{room_id}`'s group, at epoch {epoch}; founding \
                 over it would discard the key schedule its sealed records depend on"
            ),
            Some(serde_json::json!({ "epoch": epoch })),
        ),
        Err(CreateGroupError::App(e)) => app_error_to_reject(&doc, e),
    }
}

/// Which `rooms/owner/group/add` is being answered. The request and response schemas are
/// the same; 0.2 answers a repeated admission with its Welcome (item 8) where 0.1 refused it
/// `alreadyMember`.
#[derive(Clone, Copy, PartialEq, Eq)]
enum AddVersion {
    V0_1,
    V0_2,
}

/// `rooms/owner/group/add/0.1` — admit a member, advancing the room at its host first.
pub(super) async fn handle_add(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    add_at(state, auth, doc, AddVersion::V0_1).await
}

/// `rooms/owner/group/add/0.2` — 0.1, and a request that repeats the admission this agent
/// last applied for the room (same `member`, a KeyPackage with the same `KeyPackageRef`) is
/// answered with that admission's epoch and Welcome, changing nothing (item 8).
pub(super) async fn handle_add_v0_2(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    add_at(state, auth, doc, AddVersion::V0_2).await
}

/// `rooms/owner/group/add`, at either version. The error codes are the same at both (the
/// slug carries no version), so 0.2's generated constants serve both.
async fn add_at(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
    at: AddVersion,
) -> TrustTaskOutcome {
    use spec_add::v0_2::error_codes as codes;
    const ADVANCE: AdvanceCodes = AdvanceCodes {
        no_authority: codes::NO_AUTHORITY,
        epoch_conflict: codes::EPOCH_CONFLICT,
        host_unreachable: codes::HOST_UNREACHABLE,
        host_refused: codes::HOST_REFUSED,
        staged: false,
    };
    if let Err(r) = super::helpers::require_capability(
        state,
        auth,
        &doc,
        Capability::CredentialWrite,
        "admitting a member to a room's group",
    )
    .await
    {
        return r;
    }
    let req: spec_add::v0_2::Payload = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    let room_id = req.room_id.as_str().to_string();
    let host = req.host.as_str().to_string();
    let member = req.member.as_str().to_string();

    if let Err(r) = require_group(state, auth, &doc, &room_id, codes::NO_GROUP).await {
        return r;
    }

    let (_, resolver) = match outbound_identity(state, &doc).await {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    let host_call = match HostCall::as_owner(
        state,
        auth,
        &resolver,
        &room_id,
        &doc,
        ADVANCE.no_authority,
    )
    .await
    {
        Ok(h) => h,
        Err(r) => return r,
    };

    // Item 6: an advance left pending by an earlier request is settled first.
    if let Err(r) = host_call.settle_pending(&doc, &ADVANCE).await {
        return r;
    }
    // The owner's `admin` authority, minted before anything is built: a caller without it
    // learns so without leaving a pending admission behind.
    let presentation = match host_call
        .admin_presentation(&doc, ADVANCE.no_authority)
        .await
    {
        Ok(p) => p,
        Err(r) => return r,
    };

    let key_package = match decode_b64(req.key_package.as_str()) {
        Ok(k) => k,
        Err(e) => {
            return reject_with_code(
                &doc,
                declared(codes::KEY_PACKAGE_INVALID),
                format!("the KeyPackage is not base64url: {e}"),
                None,
            );
        }
    };

    // 0.2 item 8: a repeat of the admission last applied — after item 1 and the checks of
    // *Authorization* above, and after item 6 settled a pending admission into the retained
    // one — is answered with that admission, without contacting the host, advancing or
    // building a new Welcome.
    if at == AddVersion::V0_2 {
        let key_package_ref = match vti_rooms::mls::key_package_ref(&key_package) {
            Ok(r) => r,
            Err(e) => {
                return reject_with_code(
                    &doc,
                    declared(codes::KEY_PACKAGE_INVALID),
                    format!("the KeyPackage cannot admit `{member}`: {e}"),
                    None,
                );
            }
        };
        match room_groups::retained_admission(&state.room_groups_ks, &host_call.owner_member, now())
            .await
        {
            Ok(Some(kept)) if kept.repeated_by(&member, &key_package_ref) => {
                // A repeat changes nothing, so it is recorded as one: no second admission.
                record(state, "rooms.owner.group.add.repeated", auth, &room_id).await;
                let mut body = serde_json::json!({
                    "roomId": room_id,
                    "member": member,
                    "epoch": kept.epoch,
                    "welcome": kept.welcome,
                });
                if let Some(tree) = kept.ratchet_tree {
                    body["ratchetTree"] = Value::String(tree);
                }
                return success_response(&doc, body);
            }
            Ok(_) => {}
            Err(e) => return app_error_to_reject(&doc, e),
        }
    }

    // The room's profile, read before the advance: after it, a key holder of a `fromJoin`
    // room can no longer open what was sealed under the epoch it left
    // (`rooms/keys/profile/write/0.1`, *Keeping the profile readable across epochs*).
    let profile = host_call.profile_speaker(&host);
    let carried = super::room_profile::carry_before_advance(&profile).await;

    // Items 2 and 3: built on a copy and retained durably before the host is contacted.
    let pending = match room_groups::prepare_add(
        &state.room_groups_ks,
        &host_call.owner_member,
        &host,
        &member,
        &key_package,
        now(),
    )
    .await
    {
        Ok(p) => p,
        Err(PrepareAddError::NoGroup) => {
            return reject_with_code(
                &doc,
                declared(codes::NO_GROUP),
                format!("this agent holds no group for room `{room_id}`"),
                None,
            );
        }
        Err(PrepareAddError::AlreadyMember) => {
            return reject_with_code(
                &doc,
                declared(codes::ALREADY_MEMBER),
                match at {
                    AddVersion::V0_1 => {
                        format!("`{member}` already has a leaf in room `{room_id}`'s group")
                    }
                    // 0.2: and this is not a repeat this agent can answer (item 8).
                    AddVersion::V0_2 => format!(
                        "`{member}` already has a leaf in room `{room_id}`'s group, and this \
                         is not a repeat of an admission whose Welcome is still kept here — \
                         another KeyPackage, or one admitted before this agent's last advance \
                         of the room or more than 24 hours ago. Remove them \
                         (rooms/owner/group/remove) and admit them again with a fresh \
                         KeyPackage"
                    ),
                },
                None,
            );
        }
        Err(PrepareAddError::KeyPackageInvalid(why)) => {
            return reject_with_code(
                &doc,
                declared(codes::KEY_PACKAGE_INVALID),
                format!("the KeyPackage cannot admit `{member}`: {why}"),
                None,
            );
        }
        Err(PrepareAddError::App(e)) => return app_error_to_reject(&doc, e),
    };

    // Items 4 and 5.
    if let Err(r) = host_call
        .advance(
            &doc,
            &ADVANCE,
            &host,
            &pending,
            presentation,
            req.reason.as_ref().map(|r| r.as_str()),
        )
        .await
    {
        return r;
    }

    // ... and written again under the new epoch, as the owner. Never the advance's to fail.
    super::room_profile::rewrite_after_advance(&profile, carried).await;

    // The member's DID and the room, never the Welcome or the KeyPackage.
    record(state, "rooms.owner.group.add", auth, &room_id).await;
    success_response(
        &doc,
        serde_json::json!({
            "roomId": room_id,
            "member": member,
            "epoch": pending.epoch,
            "welcome": pending.welcome,
        }),
    )
}

/// `rooms/owner/group/remove/0.1` — remove a member's leaf, advancing the room at its host
/// first. The mirror of [`handle_add`], on the same machinery.
pub(super) async fn handle_remove(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    use spec_remove::v0_1::error_codes as codes;
    const ADVANCE: AdvanceCodes = AdvanceCodes {
        no_authority: codes::NO_AUTHORITY,
        epoch_conflict: codes::EPOCH_CONFLICT,
        host_unreachable: codes::HOST_UNREACHABLE,
        host_refused: codes::HOST_REFUSED,
        staged: false,
    };
    if let Err(r) = super::helpers::require_capability(
        state,
        auth,
        &doc,
        Capability::CredentialWrite,
        "removing a member from a room's group",
    )
    .await
    {
        return r;
    }
    let req: spec_remove::v0_1::Payload = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    let room_id = req.room_id.as_str().to_string();
    let host = req.host.as_str().to_string();
    let member = req.member.as_str().to_string();

    // Item 1, the parts that need nobody else: no group, and this agent's own leaf. A key
    // holder never removes itself — an owner leaving hands the room on with
    // rooms/owner/transfer — and that answer does not wait on a host.
    match require_group(state, auth, &doc, &room_id, codes::NO_GROUP).await {
        Err(r) => return r,
        // The leaf of the persona the caller holds the group as — never another persona's
        // this VTA holds for somebody else, who is a member like any other.
        Ok(Some(held)) if held.persona() == member => return own_leaf(&doc, &room_id, &member),
        Ok(_) => {}
    }

    let (_, resolver) = match outbound_identity(state, &doc).await {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    let host_call = match HostCall::as_owner(
        state,
        auth,
        &resolver,
        &room_id,
        &doc,
        ADVANCE.no_authority,
    )
    .await
    {
        Ok(h) => h,
        Err(r) => return r,
    };

    // Item 3/6: a pending advance — an admission as readily as a removal — is settled
    // before this one is built. Membership is read after it, so removing a member whose
    // admission was pending sees the admission the host actually took.
    if let Err(r) = host_call.settle_pending(&doc, &ADVANCE).await {
        return r;
    }
    let presentation = match host_call
        .admin_presentation(&doc, ADVANCE.no_authority)
        .await
    {
        Ok(p) => p,
        Err(r) => return r,
    };

    // The profile, read before the advance, to write again after it.
    let profile = host_call.profile_speaker(&host);
    let carried = super::room_profile::carry_before_advance(&profile).await;

    // Items 1 to 3: refused, or built on a copy and retained durably before the host is
    // contacted.
    let pending = match room_groups::prepare_remove(
        &state.room_groups_ks,
        &host_call.owner_member,
        &host,
        &member,
        now(),
    )
    .await
    {
        Ok(p) => p,
        Err(PrepareRemoveError::NoGroup) => {
            return reject_with_code(
                &doc,
                declared(codes::NO_GROUP),
                format!("this agent holds no group for room `{room_id}`"),
                None,
            );
        }
        Err(PrepareRemoveError::NotMember) => {
            return reject_with_code(
                &doc,
                declared(codes::NOT_MEMBER),
                format!("`{member}` has no leaf in room `{room_id}`'s group"),
                None,
            );
        }
        Err(PrepareRemoveError::OwnLeaf) => return own_leaf(&doc, &room_id, &member),
        Err(PrepareRemoveError::App(e)) => return app_error_to_reject(&doc, e),
    };

    // Items 4 and 5.
    if let Err(r) = host_call
        .advance(
            &doc,
            &ADVANCE,
            &host,
            &pending,
            presentation,
            req.reason.as_ref().map(|r| r.as_str()),
        )
        .await
    {
        return r;
    }

    // The removed member cannot open what is sealed from here on, the profile included —
    // and the re-write supersedes whatever they wrote under the epoch they left.
    super::room_profile::rewrite_after_advance(&profile, carried).await;

    // The room only. The audit row is this agent's; who left is the owner's business and
    // the host never learns it either (it sees an opaque commit).
    record(state, "rooms.owner.group.remove", auth, &room_id).await;
    success_response(
        &doc,
        serde_json::json!({
            "roomId": room_id,
            "member": member,
            "epoch": pending.epoch,
        }),
    )
}

/// `rooms/owner/group/renew/0.1` — advance a sealed room's group with a commit that adds
/// and removes nobody, advancing the room at its host first. The third advance beside
/// [`handle_add`] and [`handle_remove`], on the same machinery.
pub(super) async fn handle_renew(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    use spec_renew::v0_1::error_codes as codes;
    const ADVANCE: AdvanceCodes = AdvanceCodes {
        no_authority: codes::NO_AUTHORITY,
        epoch_conflict: codes::EPOCH_CONFLICT,
        host_unreachable: codes::HOST_UNREACHABLE,
        host_refused: codes::HOST_REFUSED,
        staged: false,
    };
    if let Err(r) = super::helpers::require_capability(
        state,
        auth,
        &doc,
        Capability::CredentialWrite,
        "renewing a room's group",
    )
    .await
    {
        return r;
    }
    let req: spec_renew::v0_1::Payload = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    let room_id = req.room_id.as_str().to_string();
    let host = req.host.as_str().to_string();

    // Item 1: `noGroup` — an `open` room has none and renews with rooms/epoch/mint.
    if let Err(r) = require_group(state, auth, &doc, &room_id, codes::NO_GROUP).await {
        return r;
    }

    let (_, resolver) = match outbound_identity(state, &doc).await {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    // Item 1: `noAuthority`, before anything is settled or built.
    let host_call = match HostCall::as_owner(
        state,
        auth,
        &resolver,
        &room_id,
        &doc,
        ADVANCE.no_authority,
    )
    .await
    {
        Ok(h) => h,
        Err(r) => return r,
    };

    // Items 3 and 6: one pending advance per room — an admission or a removal as readily
    // as a renewal — settled before this one is built.
    if let Err(r) = host_call.settle_pending(&doc, &ADVANCE).await {
        return r;
    }
    let presentation = match host_call
        .admin_presentation(&doc, ADVANCE.no_authority)
        .await
    {
        Ok(p) => p,
        Err(r) => return r,
    };

    // The profile, read before the advance, to write again after it.
    let profile = host_call.profile_speaker(&host);
    let carried = super::room_profile::carry_before_advance(&profile).await;

    // Items 2, 3 and 7: a commit that adds and removes nobody, and its link, built on a
    // copy and retained durably before the host is contacted.
    let pending = match room_groups::prepare_renew(
        &state.room_groups_ks,
        &host_call.owner_member,
        &host,
        now(),
    )
    .await
    {
        Ok(Some(p)) => p,
        Ok(None) => {
            return reject_with_code(
                &doc,
                declared(codes::NO_GROUP),
                format!("this agent holds no group for room `{room_id}`"),
                None,
            );
        }
        Err(e) => return app_error_to_reject(&doc, e),
    };

    // Items 4 and 5.
    if let Err(r) = host_call
        .advance(
            &doc,
            &ADVANCE,
            &host,
            &pending,
            presentation,
            req.reason.as_ref().map(|r| r.as_str()),
        )
        .await
    {
        return r;
    }

    super::room_profile::rewrite_after_advance(&profile, carried).await;

    record(state, "rooms.owner.group.renew", auth, &room_id).await;
    success_response(
        &doc,
        serde_json::json!({ "roomId": room_id, "epoch": pending.epoch }),
    )
}

fn own_leaf(doc: &TrustTask<Value>, room_id: &str, member: &str) -> TrustTaskOutcome {
    reject_with_code(
        doc,
        declared(spec_remove::v0_1::error_codes::OWN_LEAF),
        format!(
            "`{member}` is this agent's own leaf in room `{room_id}`'s group; a key holder \
             does not remove itself — hand the room on with rooms/owner/transfer"
        ),
        None,
    )
}

/// `noGroup` unless this agent holds the room's group for a persona the caller acts as.
///
/// The member it is held as, where there is exactly one; `None` where the caller acts as
/// several holding the room — which persona owns it is then the owner credentials' answer
/// ([`HostCall::as_owner`]), not a guess here. A persona in another context is not one the
/// caller acts as, and its group answers `noGroup` like a room nobody here holds.
async fn require_group(
    state: &AppState,
    auth: &AuthClaims,
    doc: &TrustTask<Value>,
    room_id: &str,
    no_group: DeclaredErrorCode,
) -> Result<Option<Member>, TrustTaskOutcome> {
    match room_member::acting(state, auth, room_id).await {
        Ok(Some(m)) => Ok(Some(m)),
        Err(AppError::Conflict(_)) => Ok(None),
        Ok(None) => Err(reject_with_code(
            doc,
            declared(no_group),
            format!(
                "this agent holds no group for room `{room_id}`: found one with \
                 rooms/owner/group/create, or join by a Welcome"
            ),
            None,
        )),
        Err(e) => Err(app_error_to_reject(doc, e)),
    }
}

/// The codes an epoch advance answers with, in the namespace of the task that asked for
/// it. `add`, `remove` and `renew` declare the same four, each under its own slug.
pub(super) struct AdvanceCodes {
    pub(super) no_authority: DeclaredErrorCode,
    pub(super) epoch_conflict: DeclaredErrorCode,
    pub(super) host_unreachable: DeclaredErrorCode,
    pub(super) host_refused: DeclaredErrorCode,
    /// `rooms/owner/group/remove/0.2`: `hostUnreachable` and `hostRefused` carry
    /// `details.stage` (`revocation` or `advance`), and `hostRefused` the host's `code`
    /// beside it and nothing else.
    pub(super) staged: bool,
}

/// `noAuthority`: the caller acts as no persona holding the room's `admin` authority.
pub(super) fn no_authority(
    doc: &TrustTask<Value>,
    code: DeclaredErrorCode,
    room_id: &str,
    e: AppError,
) -> TrustTaskOutcome {
    reject_with_code(
        doc,
        declared(code),
        format!(
            "this agent holds no authority credential conferring `admin` on room `{room_id}` \
             for a persona you act as, so it cannot advance the room's epoch: {e}"
        ),
        None,
    )
}

/// The DID `create`'s one leaf identifies.
///
/// The specification: `member`, "absent means the caller", and "the subject of the owner's
/// membership and authority credentials". The caller here is the owner acting through an
/// interface client, so "the caller" is read as the owner's **persona** — never the client's
/// own `did:key`, which this agent holds no key for and which would make the owner a
/// different member from every other client they use:
///
/// - `member` named: it must be a persona the caller may act as. Refused otherwise, the same
///   way whether it is unknown or held in another context.
/// - absent: the persona the room's credentials name, where this agent holds them for a
///   persona the caller acts as; else the caller's own DID only if it *is* a persona (a
///   `did:key` this agent holds in a context the caller acts in); else a refusal asking for
///   `member`, rather than a leaf carrying a client key.
async fn founding_member(
    state: &AppState,
    auth: &AuthClaims,
    room_id: &str,
    named: Option<&str>,
) -> Result<String, AppError> {
    let stores = crate::operations::persona::PersonaStores::from_state(state);
    if let Some(member) = named {
        return match crate::operations::persona::persona_signing_key(stores, auth, member).await? {
            Some(_) => Ok(member.to_string()),
            None => Err(AppError::Forbidden(format!(
                "`{member}` is not a persona you may act as, so it cannot be the owner's leaf \
                 in room `{room_id}`. Name a DID this agent minted for you in a context you \
                 act in"
            ))),
        };
    }
    match crate::operations::room_oracle::principal(state, auth, room_id).await {
        Ok(p) => return Ok(p.did),
        Err(AppError::NotFound(_)) => {}
        Err(e) => return Err(e),
    }
    if crate::operations::persona::persona_signing_key(stores, auth, &auth.did)
        .await?
        .is_some()
    {
        return Ok(auth.did.clone());
    }
    Err(AppError::Validation(format!(
        "name the owner's persona as `member`: this agent holds no credential from room \
         `{room_id}` naming one you act as, and your own DID is a client key it does not hold, \
         which cannot be a member's identity"
    )))
}

/// What `add`, `remove` and `renew` need to speak to a host **as the owner's persona**.
///
/// `rooms/owner/group/{add,remove,renew}` have the key holder speak "to the host as its
/// principal", presenting the owner's `admin` authority; `rooms/epoch/mint`'s producer is
/// the owner (or a holder of `admin`). So every request is signed as the persona the room's
/// credentials name — the same identity `rooms/owner/register` registered — and never as
/// this agent, whose DID is shared by every principal it serves and would attribute the
/// advance to none of them.
pub(super) struct HostCall<'a> {
    state: &'a AppState,
    auth: &'a AuthClaims,
    owner: crate::operations::room_oracle::Principal,
    /// The owner persona as a member of the room: whose group is advanced, whose one
    /// pending advance is settled, and whose root memory gates the write.
    pub(super) owner_member: Member,
    resolver: &'a affinidi_did_resolver_cache_sdk::DIDCacheClient,
    room_id: &'a str,
}

impl<'a> HostCall<'a> {
    /// Resolve the owner persona the caller acts as in `room_id`, or `noAuthority` — before
    /// anything is settled or built, so a caller without it leaves nothing behind.
    pub(super) async fn as_owner(
        state: &'a AppState,
        auth: &'a AuthClaims,
        resolver: &'a affinidi_did_resolver_cache_sdk::DIDCacheClient,
        room_id: &'a str,
        doc: &TrustTask<Value>,
        no_authority_code: DeclaredErrorCode,
    ) -> Result<Self, TrustTaskOutcome> {
        let owner = match crate::operations::room_oracle::principal(state, auth, room_id).await {
            Ok(p) => p,
            Err(e @ (AppError::NotFound(_) | AppError::Forbidden(_) | AppError::Validation(_))) => {
                return Err(no_authority(doc, no_authority_code, room_id, e));
            }
            Err(e) => return Err(app_error_to_reject(doc, e)),
        };
        let owner_member = match room_member::member_as(state, auth, room_id, &owner.did).await {
            Ok(m) => m,
            Err(e) => return Err(app_error_to_reject(doc, e)),
        };
        Ok(Self {
            state,
            auth,
            owner,
            owner_member,
            resolver,
            room_id,
        })
    }

    /// The owner persona as `rooms/keys/profile/*` speaks for it: the profile read before an
    /// advance and written again after it go to `host` as the owner, under the owner's own
    /// `read` and `write` grants.
    fn profile_speaker<'h>(&'h self, host: &'h str) -> super::room_profile::Speaker<'h> {
        super::room_profile::Speaker::for_owner(
            self.state,
            self.auth,
            self.resolver,
            host,
            self.owner.clone(),
            self.owner_member.clone(),
        )
    }

    pub(super) async fn send(
        &self,
        host: &str,
        task: &str,
        payload: Value,
    ) -> Result<Value, RoomTaskError> {
        send_room_task_typed(
            signing_context(self.state, self.auth),
            &self.state.room_groups_ks,
            &self.owner_member,
            &crate::operations::outbound::Outbound::from_app_state(self.state, self.resolver),
            host,
            &self.owner.key.key_id,
            &self.owner.did,
            &self.owner.key.verification_method,
            task,
            &format!("{task}#response"),
            payload,
        )
        .await
    }

    /// The room's epoch at `host`, from `rooms/info` under the owner's `read` grant.
    async fn epoch(&self, host: &str) -> Result<u32, RoomTaskError> {
        let minted = crate::operations::room_oracle::present_as(
            self.state,
            self.auth,
            &self.owner,
            &self.owner.did,
            self.room_id,
            "read",
        )
        .await
        .map_err(RoomTaskError::Unknown)?;
        let info = self
            .send(
                host,
                vti_rooms::wire::ROOMS_INFO_TYPE,
                serde_json::json!({ "roomId": self.room_id, "presentation": minted.presentation }),
            )
            .await?;
        info.get("epoch")
            .and_then(Value::as_u64)
            .and_then(|e| u32::try_from(e).ok())
            .ok_or_else(|| {
                RoomTaskError::Unknown(AppError::Internal(format!(
                    "host `{host}` described room `{}` without an epoch",
                    self.room_id
                )))
            })
    }

    /// Item 6: settle the room's pending advance, if it has one, against the host it was
    /// sent to — whichever kind it is, so an admission found at a removal is settled as
    /// surely as a removal found at an admission.
    pub(super) async fn settle_pending(
        &self,
        doc: &TrustTask<Value>,
        codes: &AdvanceCodes,
    ) -> Result<(), TrustTaskOutcome> {
        let room_id = self.room_id;
        let pending = match room_groups::pending_advance(
            &self.state.room_groups_ks,
            &self.owner_member,
        )
        .await
        {
            Ok(Some(p)) => p,
            Ok(None) => return Ok(()),
            Err(e) => return Err(app_error_to_reject(doc, e)),
        };
        // `rooms/owner/group/remove/0.2` item 8: a removal whose list the host has not
        // confirmed delivers it again first (a repeat is answered as accepted). Until it is
        // confirmed the advance was never sent, so the epoch check below discards it —
        // and the list, once accepted, is the room's and stays.
        let mut pending = pending;
        if let Some(rev) = pending.revocation.clone().filter(|r| !r.confirmed) {
            let list = vti_rooms::revocation::RevocationList::parse(&rev.list, room_id)
                .map_err(|e| app_error_to_reject(doc, AppError::Internal(e.to_string())))?;
            let presentation = self.admin_presentation(doc, codes.no_authority).await?;
            match self.deliver_list(&pending.host, &list, &presentation).await {
                Delivery::Accepted { .. } => {
                    if let Some(r) = pending.revocation.as_mut() {
                        r.confirmed = true;
                    }
                    room_groups::update_pending_advance(
                        &self.state.room_groups_ks,
                        &self.owner_member,
                        &pending,
                    )
                    .await
                    .map_err(|e| app_error_to_reject(doc, e))?;
                }
                // Refused: no host took the list, so the removal it was for never
                // happened — discarded whole, list included (item 6).
                Delivery::Refused { code, .. } => {
                    tracing::warn!(room = %room_id, %code,
                        "a pending removal's revocation list was refused; the removal is discarded");
                    let _lock = crate::operations::room_revocation::signing_lock(room_id).await;
                    crate::operations::room_revocation::discard_unaccepted(
                        &self.state.room_groups_ks,
                        &list,
                        rev.previous.as_ref(),
                    )
                    .await
                    .map_err(|e| app_error_to_reject(doc, e))?;
                    room_groups::discard_pending_advance(
                        &self.state.room_groups_ks,
                        &self.owner_member,
                    )
                    .await
                    .map_err(|e| app_error_to_reject(doc, e))?;
                    return Ok(());
                }
                Delivery::Unreachable(why) => {
                    return Err(reject_with_code(
                        doc,
                        declared(codes.host_unreachable),
                        format!(
                            "an earlier removal in room `{room_id}` is waiting on host `{}` to \
                             accept its withdrawal, and it did not answer: {why}",
                            pending.host
                        ),
                        codes
                            .staged
                            .then(|| serde_json::json!({ "stage": "revocation" })),
                    ));
                }
            }
        }
        let host_epoch = self.epoch(&pending.host).await.map_err(|e| {
            reject_with_code(
                doc,
                declared(codes.host_unreachable),
                format!(
                    "an earlier {} in room `{room_id}` is waiting on host `{}`, and asking it \
                     which epoch it is at failed: {}",
                    pending.kind.noun(),
                    pending.host,
                    e.into_app_error()
                ),
                None,
            )
        })?;
        match room_groups::reconcile_pending_advance(
            &self.state.room_groups_ks,
            &self.owner_member,
            &pending,
            host_epoch,
            now(),
        )
        .await
        {
            Ok(Reconciled::Applied | Reconciled::Discarded) => Ok(()),
            Ok(Reconciled::Conflict) => Err(reject_with_code(
                doc,
                declared(codes.epoch_conflict),
                format!(
                    "room `{room_id}` is at epoch {host_epoch} at its host, which this agent's \
                     group has not reached; catch up with rooms/epoch/commits and try again"
                ),
                Some(serde_json::json!({ "hostEpoch": host_epoch })),
            )),
            Err(e) => Err(app_error_to_reject(doc, e)),
        }
    }

    /// The owner persona's `admin` presentation for the room, or `noAuthority` — minted as
    /// `rooms/keys/present` mints it, the leaf granted to the party that signs the request
    /// carrying it, which is the owner persona itself.
    pub(super) async fn admin_presentation(
        &self,
        doc: &TrustTask<Value>,
        no_authority_code: DeclaredErrorCode,
    ) -> Result<Value, TrustTaskOutcome> {
        let room_id = self.room_id;
        match crate::operations::room_oracle::present_as(
            self.state,
            self.auth,
            &self.owner,
            &self.owner.did,
            room_id,
            "admin",
        )
        .await
        {
            Ok(m) => Ok(m.presentation),
            Err(e @ (AppError::NotFound(_) | AppError::Forbidden(_) | AppError::Validation(_))) => {
                Err(no_authority(doc, no_authority_code, room_id, e))
            }
            Err(e) => Err(app_error_to_reject(doc, e)),
        }
    }

    /// Items 4 and 5: advance the room at `host` with `rooms/epoch/mint`, then follow the
    /// host's answer — promote the pending advance on acceptance, discard it on refusal,
    /// keep it on an unknown outcome.
    pub(super) async fn advance(
        &self,
        doc: &TrustTask<Value>,
        codes: &AdvanceCodes,
        host: &str,
        pending: &PendingAdvance,
        presentation: Value,
        reason: Option<&str>,
    ) -> Result<(), TrustTaskOutcome> {
        let room_id = self.room_id;
        let groups = &self.state.room_groups_ks;
        let mut mint = serde_json::json!({
            "roomId": room_id,
            "epoch": pending.epoch,
            "presentation": presentation,
            "commit": pending.commit,
        });
        if let Some(link) = &pending.link {
            mint["link"] = serde_json::to_value(link).unwrap_or(Value::Null);
        }
        if let Some(reason) = reason {
            mint["reason"] = serde_json::json!(reason);
        }
        match self
            .send(host, vti_rooms::wire::ROOMS_EPOCH_MINT_TYPE, mint)
            .await
        {
            Ok(_) => {}
            // A refusal is the host's answer — the advance did not happen — so the pending
            // advance is discarded and the live group never moved.
            Err(RoomTaskError::Refused { code, reason, .. }) => {
                if let Err(e) =
                    room_groups::discard_pending_advance(groups, &self.owner_member).await
                {
                    return Err(app_error_to_reject(doc, e));
                }
                if code == "rooms/epoch/mint:nonSequential" {
                    let host_epoch = self.epoch(host).await.ok();
                    return Err(reject_with_code(
                        doc,
                        declared(codes.epoch_conflict),
                        format!(
                            "host `{host}` is not at epoch {} for room `{room_id}`: another \
                             admin advanced it. Catch up with rooms/epoch/commits and try again.",
                            pending.epoch - 1
                        ),
                        host_epoch.map(|e| serde_json::json!({ "hostEpoch": e })),
                    ));
                }
                return Err(reject_with_code(
                    doc,
                    declared(codes.host_refused),
                    format!("host `{host}` declined to advance room `{room_id}`: {code}: {reason}"),
                    Some(if codes.staged {
                        // 0.2: the withdrawal is in force at the host, and stays.
                        serde_json::json!({ "stage": "advance", "code": code })
                    } else {
                        serde_json::json!({ "code": code, "reason": reason })
                    }),
                ));
            }
            // An unknown outcome keeps the pending advance: the host may have accepted, and
            // the next request settles it (item 6). Discarding here could strand this agent
            // an epoch behind a room that did advance, with no way to follow.
            Err(RoomTaskError::Unknown(e)) => {
                return Err(reject_with_code(
                    doc,
                    declared(codes.host_unreachable),
                    format!(
                        "the epoch advance for room `{room_id}` did not get an answer from host \
                         `{host}`: {e}. Whether it took effect is unknown; the next admission, \
                         removal or renewal in this room settles it with the host first."
                    ),
                    codes
                        .staged
                        .then(|| serde_json::json!({ "stage": "advance" })),
                ));
            }
        }

        room_groups::promote_pending_advance(groups, &self.owner_member, pending, now())
            .await
            // The host advanced and this agent could not record it. The pending row
            // survives, and the next request promotes it (item 6): a delay, not a loss.
            .map_err(|e| app_error_to_reject(doc, e))
    }
}

/// What one host did with a delivered revocation list (`rooms/owner/revoke`, `Delivery`).
pub(super) enum Delivery {
    /// The host holds the list and enforces it from `in_force_at`: it answered with the
    /// list's own head (`rooms/owner/revoke` item 5).
    Accepted { head: Value, in_force_at: String },
    /// The host answered and declined.
    Refused { code: String, reason: String },
    /// No answer this agent can rely on: the outcome is unknown.
    Unreachable(String),
}

impl HostCall<'_> {
    /// Deliver `list` to `host` with `rooms/revocations/put`, presenting the owner
    /// persona's `admin` authority in a document addressed to that host.
    pub(super) async fn deliver_list(
        &self,
        host: &str,
        list: &vti_rooms::revocation::RevocationList,
        presentation: &Value,
    ) -> Delivery {
        let payload = serde_json::json!({
            "roomId": self.room_id,
            "presentation": presentation,
            "list": list.raw(),
        });
        match self
            .send(host, vti_rooms::wire::ROOMS_REVOCATIONS_PUT_TYPE, payload)
            .await
        {
            Ok(answer) => {
                let head = answer.get("head").cloned().unwrap_or(Value::Null);
                if head == list.head().to_wire() {
                    Delivery::Accepted {
                        head,
                        in_force_at: answer
                            .get("inForceAt")
                            .and_then(Value::as_str)
                            .unwrap_or_default()
                            .to_string(),
                    }
                } else {
                    // Never reported as accepted unless the host named this list.
                    Delivery::Unreachable(format!(
                        "host `{host}` answered with a head that is not this list's"
                    ))
                }
            }
            Err(RoomTaskError::Refused { code, reason, .. }) => {
                if code == "rooms/revocations/put:stale" {
                    // A host ahead of this agent holds a list this agent did not sign —
                    // or was restored past. Either way the room's key may be in more than
                    // one party's hands (`rooms/owner/revoke` item 6).
                    tracing::warn!(room = %self.room_id, %host, security_alert = true,
                        "a host holds a later revocation list than this key holder");
                }
                Delivery::Refused { code, reason }
            }
            Err(RoomTaskError::Unknown(e)) => Delivery::Unreachable(e.to_string()),
        }
    }

    /// The room's tier: as this agent registered it, else from `rooms/info` at `host`
    /// under the owner persona's `read` grant (`rooms/owner/revoke` item 2,
    /// `rooms/owner/group/remove/0.2` item 2).
    pub(super) async fn tier(&self, host: &str) -> Result<String, AppError> {
        if let Some(t) =
            crate::operations::room_revocation::known_tier(&self.state.room_groups_ks, self.room_id)
                .await?
        {
            return Ok(t);
        }
        let minted = crate::operations::room_oracle::present_as(
            self.state,
            self.auth,
            &self.owner,
            &self.owner.did,
            self.room_id,
            "read",
        )
        .await?;
        let info = self
            .send(
                host,
                vti_rooms::wire::ROOMS_INFO_TYPE,
                serde_json::json!({ "roomId": self.room_id, "presentation": minted.presentation }),
            )
            .await
            .map_err(RoomTaskError::into_app_error)?;
        info.get("visibility")
            .and_then(Value::as_str)
            .map(str::to_string)
            .ok_or_else(|| {
                AppError::Internal(format!(
                    "host `{host}` described room `{}` without its tier",
                    self.room_id
                ))
            })
    }

    /// The list a host holds for the room, from `rooms/revocations/get`, if it answers with
    /// one.
    pub(super) async fn fetch_list(&self, host: &str, presentation: &Value) -> Option<Value> {
        match self
            .send(
                host,
                vti_rooms::wire::ROOMS_REVOCATIONS_GET_TYPE,
                serde_json::json!({ "roomId": self.room_id, "presentation": presentation }),
            )
            .await
        {
            Ok(answer) => answer.get("list").cloned(),
            Err(e) => {
                tracing::debug!(room = %self.room_id, %host, error = %e.into_app_error(),
                    "could not read a host's revocation list");
                None
            }
        }
    }
}

/// `rooms/owner/group/remove/0.2` — withdraw the member's credentials at the host, then
/// remove their leaf and advance the room: there is no instant where they are outside the
/// group but still credentialed (trust-tasks-tf #804).
pub(super) async fn handle_remove_v0_2(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    use crate::operations::room_revocation as revocation;
    use spec_remove::v0_2::error_codes as codes;
    const ADVANCE: AdvanceCodes = AdvanceCodes {
        no_authority: codes::NO_AUTHORITY,
        epoch_conflict: codes::EPOCH_CONFLICT,
        host_unreachable: codes::HOST_UNREACHABLE,
        host_refused: codes::HOST_REFUSED,
        staged: true,
    };
    if let Err(r) = super::helpers::require_capability(
        state,
        auth,
        &doc,
        Capability::CredentialWrite,
        "removing a member from a room",
    )
    .await
    {
        return r;
    }
    let req: spec_remove::v0_2::Payload = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    let room_id = req.room_id.as_str().to_string();
    let host = req.host.as_str().to_string();
    let member = req.member.as_str().to_string();
    let signing_key_id = req.signing_key_id.as_str().to_string();
    let mirrors: Vec<String> = req
        .mirrors
        .iter()
        .flatten()
        .map(|m| m.as_str().to_string())
        .collect();

    // Item 1: noGroup, ownLeaf, noSigningKey, noAuthority — before anything else.
    match require_group(state, auth, &doc, &room_id, codes::NO_GROUP).await {
        Err(r) => return r,
        Ok(Some(held)) if held.persona() == member => return own_leaf(&doc, &room_id, &member),
        Ok(_) => {}
    }
    if let Err(e) = crate::operations::keys::require_key_nameable(
        &state.keys_ks,
        &state.acl_ks,
        auth,
        &signing_key_id,
    )
    .await
    {
        return reject_with_code(
            &doc,
            declared(codes::NO_SIGNING_KEY),
            format!(
                "this agent will not sign as room `{room_id}` with key `{signing_key_id}`: {e}"
            ),
            None,
        );
    }
    let (_, resolver) = match outbound_identity(state, &doc).await {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    let host_call = match HostCall::as_owner(
        state,
        auth,
        &resolver,
        &room_id,
        &doc,
        ADVANCE.no_authority,
    )
    .await
    {
        Ok(h) => h,
        Err(r) => return r,
    };
    let presentation = match host_call
        .admin_presentation(&doc, ADVANCE.no_authority)
        .await
    {
        Ok(p) => p,
        Err(r) => return r,
    };
    // Item 8: an earlier advance is settled first, whatever its kind.
    if let Err(r) = host_call.settle_pending(&doc, &ADVANCE).await {
        return r;
    }

    // Item 2: never a private room — its host could not be told whom to refuse without
    // being told who was a member. Nothing has changed.
    match host_call.tier(&host).await {
        Ok(t) if t == "private" => {
            return reject_with_code(
                &doc,
                declared(codes::PRIVATE_ROOM),
                format!(
                    "room `{room_id}` is private: a member cannot be withdrawn one at a time \
                     there. Remove them with rooms/owner/group/remove 0.1, and reset every \
                     credential with rooms/owner/revoke if the room needs that too"
                ),
                None,
            );
        }
        Ok(_) => {}
        Err(e) => {
            return reject_with_code(
                &doc,
                declared(codes::HOST_UNREACHABLE),
                format!("could not establish room `{room_id}`'s tier from host `{host}`: {e}"),
                Some(serde_json::json!({ "stage": "revocation" })),
            );
        }
    }

    // The room's profile, read before the advance, to write again after it — as every
    // advance does (`rooms/keys/profile/write/0.1`, *Keeping the profile readable across
    // epochs*).
    let profile = host_call.profile_speaker(&host);
    let carried = super::room_profile::carry_before_advance(&profile).await;

    // Item 3, and item 5's first half: the commit and link, built on a copy and retained
    // before anything is sent.
    let mut pending = match room_groups::prepare_remove(
        &state.room_groups_ks,
        &host_call.owner_member,
        &host,
        &member,
        now(),
    )
    .await
    {
        Ok(p) => p,
        Err(PrepareRemoveError::NoGroup) => {
            return reject_with_code(
                &doc,
                declared(codes::NO_GROUP),
                format!("this agent holds no group for room `{room_id}`"),
                None,
            );
        }
        Err(PrepareRemoveError::NotMember) => {
            return reject_with_code(
                &doc,
                declared(codes::NOT_MEMBER),
                format!("`{member}` has no leaf in room `{room_id}`'s group"),
                None,
            );
        }
        Err(PrepareRemoveError::OwnLeaf) => return own_leaf(&doc, &room_id, &member),
        Err(PrepareRemoveError::App(e)) => return app_error_to_reject(&doc, e),
    };

    // Item 4, and item 5's second half: the room's next list, one `subject` entry for the
    // member stamped with the time it is signed, kept and retained with the advance.
    let list = {
        let _lock = revocation::signing_lock(&room_id).await;
        let held = match revocation::held(&state.room_groups_ks, &room_id).await {
            Ok(h) => h,
            Err(e) => {
                let _ = room_groups::discard_pending_advance(
                    &state.room_groups_ks,
                    &host_call.owner_member,
                )
                .await;
                return app_error_to_reject(&doc, e);
            }
        };
        let signed_at = chrono::Utc::now();
        let entry = vti_rooms::revocation::Entry::Subject {
            subject: member.clone(),
            revoked_at: signed_at,
            until: req.until,
        };
        let signed = match revocation::sign_next(
            signing_context(state, auth),
            &signing_key_id,
            &room_id,
            held.as_ref(),
            std::slice::from_ref(&entry),
            signed_at,
        )
        .await
        {
            Ok(l) => l,
            Err(e) => {
                let _ = room_groups::discard_pending_advance(
                    &state.room_groups_ks,
                    &host_call.owner_member,
                )
                .await;
                return reject_with_code(
                    &doc,
                    declared(codes::NO_SIGNING_KEY),
                    format!("this agent could not sign as room `{room_id}`: {e}"),
                    None,
                );
            }
        };
        if let Err(e) = revocation::keep(&state.room_groups_ks, &signed).await {
            let _ = room_groups::discard_pending_advance(
                &state.room_groups_ks,
                &host_call.owner_member,
            )
            .await;
            return app_error_to_reject(&doc, e);
        }
        pending.revocation = Some(room_groups::PendingRevocation {
            list: signed.raw().clone(),
            previous: held.map(|h| h.raw().clone()),
            // As the entry writes it, sub-second part included.
            revoked_at: signed_at.to_rfc3339_opts(chrono::SecondsFormat::AutoSi, true),
            confirmed: false,
        });
        if let Err(e) = room_groups::update_pending_advance(
            &state.room_groups_ks,
            &host_call.owner_member,
            &pending,
        )
        .await
        {
            return app_error_to_reject(&doc, e);
        }
        signed
    };
    let revoked_at = pending
        .revocation
        .as_ref()
        .map(|r| r.revoked_at.clone())
        .unwrap_or_default();

    // Item 6: the withdrawal reaches the host before the advance, and nothing advances
    // until the host has accepted it.
    let head = match host_call.deliver_list(&host, &list, &presentation).await {
        Delivery::Accepted { head, .. } => head,
        Delivery::Refused { code, reason } => {
            // No host took it: the whole pending removal goes, list included.
            {
                let _lock = revocation::signing_lock(&room_id).await;
                let previous = pending.revocation.as_ref().and_then(|r| r.previous.clone());
                if let Err(e) =
                    revocation::discard_unaccepted(&state.room_groups_ks, &list, previous.as_ref())
                        .await
                {
                    return app_error_to_reject(&doc, e);
                }
            }
            if let Err(e) =
                room_groups::discard_pending_advance(&state.room_groups_ks, &host_call.owner_member)
                    .await
            {
                return app_error_to_reject(&doc, e);
            }
            return reject_with_code(
                &doc,
                declared(codes::HOST_REFUSED),
                format!(
                    "host `{host}` declined room `{room_id}`'s revocation list: {code}: {reason}. \
                     Nothing changed"
                ),
                Some(serde_json::json!({ "stage": "revocation", "code": code })),
            );
        }
        Delivery::Unreachable(why) => {
            return reject_with_code(
                &doc,
                declared(codes::HOST_UNREACHABLE),
                format!(
                    "host `{host}` did not answer the withdrawal for room `{room_id}`: {why}. \
                     Whether it took effect is unknown; the next request for this room \
                     delivers it again first"
                ),
                Some(serde_json::json!({ "stage": "revocation" })),
            );
        }
    };
    if let Some(r) = pending.revocation.as_mut() {
        r.confirmed = true;
    }
    if let Err(e) = room_groups::update_pending_advance(
        &state.room_groups_ks,
        &host_call.owner_member,
        &pending,
    )
    .await
    {
        return app_error_to_reject(&doc, e);
    }

    // Item 7: then the advance. A refusal discards the advance and leaves the withdrawal,
    // which is the room's and in force.
    if let Err(r) = host_call
        .advance(
            &doc,
            &ADVANCE,
            &host,
            &pending,
            presentation.clone(),
            req.reason.as_ref().map(|r| r.as_str()),
        )
        .await
    {
        return r;
    }

    // The removed member cannot open what is sealed from here on, the profile included.
    super::room_profile::rewrite_after_advance(&profile, carried).await;

    // Item 9: every mirror is delivered the list too; one that does not confirm is named,
    // not waited for.
    let mut mirrors_pending = Vec::new();
    for mirror in &mirrors {
        if !matches!(
            host_call.deliver_list(mirror, &list, &presentation).await,
            Delivery::Accepted { .. }
        ) {
            mirrors_pending.push(mirror.clone());
        }
    }

    // The room only: who left is the owner's business.
    record(state, "rooms.owner.group.remove", auth, &room_id).await;
    let mut body = serde_json::json!({
        "roomId": room_id,
        "member": member,
        "revocation": head,
        "revokedAt": revoked_at,
        "epoch": pending.epoch,
    });
    if !mirrors_pending.is_empty() {
        body["mirrorsPending"] = serde_json::json!(mirrors_pending);
    }
    success_response(&doc, body)
}

fn decode_b64(s: &str) -> Result<Vec<u8>, base64::DecodeError> {
    use base64::Engine as _;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(s.trim())
}

#[cfg(test)]
mod tests {
    //! The owner's group verbs against a stand-in room host on a loopback port.
    //!
    //! The host is a stub because what is under test is this agent's side of the
    //! conversation — what it sends, and above all what it does with each kind of
    //! answer — and a stub is the only host that can be told to accept an advance and then
    //! lose the reply. It answers `rooms/epoch/mint` and `rooms/info` with documents signed
    //! as its own DID, which this agent requires of every reply it acts on.

    use std::sync::{Arc, Mutex};

    use chrono::{Duration as Span, Utc};
    use dtg_credentials::DTGCredential;
    use trust_tasks_rs::TypeUri;
    use vti_rooms_dtg::test_support::Party;

    use super::*;
    use crate::operations::room_oracle::{AUTHORITY_TYPE, MEMBERSHIP_TYPE};

    /// What the stub host does with the next epoch advance.
    #[derive(Clone, Copy, PartialEq)]
    enum Mode {
        Accept,
        Refuse,
        /// Advance the room, then answer with something unreadable: the outcome the
        /// caller sees is unknown, while the host has in fact moved.
        AcceptThenLose,
    }

    struct Host {
        epoch: u32,
        mode: Mode,
        /// What the stub does with the next `rooms/revocations/put`.
        list_mode: Mode,
        /// The room's tier, as `rooms/info` reports it.
        visibility: &'static str,
        /// Every list the host accepted, in order.
        lists: Vec<Value>,
        /// Every task the host received, in order.
        log: Vec<String>,
        /// The last `rooms/epoch/mint` payload the host took, so a test can relay its
        /// commit to the members who remain.
        last_mint: Option<Value>,
        /// Who signed the last `rooms/epoch/mint` the host received.
        last_mint_issuer: Option<String>,
    }

    struct StubHost {
        did: String,
        state: Arc<Mutex<Host>>,
    }

    async fn start_host(vta_did: String) -> (StubHost, serde_json::Value) {
        let party = Party::new();
        let state = Arc::new(Mutex::new(Host {
            epoch: 1,
            mode: Mode::Accept,
            list_mode: Mode::Accept,
            visibility: "attributed",
            lists: Vec::new(),
            log: Vec::new(),
            last_mint: None,
            last_mint_issuer: None,
        }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let host_did = party.did.clone();
        let shared = state.clone();
        let app = axum::Router::new().route(
            "/trust-tasks",
            axum::routing::post(move |axum::Json(req): axum::Json<Value>| {
                let shared = shared.clone();
                let host_did = host_did.clone();
                let secret = party.secret_multibase.clone();
                let vta_did = vta_did.clone();
                async move {
                    let task = req["type"].as_str().unwrap_or_default().to_string();
                    let room_id = req["payload"]["roomId"].clone();
                    let answer = {
                        let mut h = shared.lock().unwrap();
                        h.log.push(task.clone());
                        if task == vti_rooms::wire::ROOMS_INFO_TYPE {
                            Ok(serde_json::json!({
                                "roomId": room_id, "visibility": h.visibility,
                                "retentionPolicy": "chained", "epoch": h.epoch,
                            }))
                        } else if task == vti_rooms::wire::ROOMS_CREATE_TYPE {
                            Ok(serde_json::json!({ "roomId": room_id, "epoch": h.epoch }))
                        } else if task == vti_rooms::wire::ROOMS_REVOCATIONS_GET_TYPE {
                            let mut body = serde_json::json!({ "roomId": room_id });
                            if let Some(last) = h.lists.last() {
                                body["list"] = last.clone();
                                body["inForceAt"] = serde_json::json!("2026-10-16T09:30:00Z");
                            }
                            Ok(body)
                        } else if task == vti_rooms::wire::ROOMS_REVOCATIONS_PUT_TYPE {
                            let list = req["payload"]["list"].clone();
                            match h.list_mode {
                                Mode::Refuse => {
                                    Err(("rooms/revocations/put:listInvalid", "not the room's"))
                                }
                                mode => {
                                    h.lists.push(list.clone());
                                    if mode == Mode::AcceptThenLose {
                                        return (
                                            axum::http::StatusCode::BAD_GATEWAY,
                                            "the reply was lost".to_string(),
                                        );
                                    }
                                    Ok(serde_json::json!({
                                        "roomId": room_id,
                                        "head": {
                                            "sequence": list["sequence"],
                                            "digest": vti_rooms::revocation::digest_multibase(&list),
                                        },
                                        "inForceAt": "2026-10-16T09:30:00Z",
                                    }))
                                }
                            }
                        } else if task == vti_rooms::wire::ROOMS_EPOCH_MINT_TYPE {
                            h.last_mint_issuer = req["issuer"].as_str().map(str::to_string);
                            let asked = req["payload"]["epoch"].as_u64().unwrap_or(0) as u32;
                            match h.mode {
                                Mode::Refuse => Err(("permissionDenied", "not today")),
                                _ if asked != h.epoch + 1 => {
                                    Err(("rooms/epoch/mint:nonSequential", "wrong epoch"))
                                }
                                mode => {
                                    h.epoch = asked;
                                    h.last_mint = Some(req["payload"].clone());
                                    if mode == Mode::AcceptThenLose {
                                        return (
                                            axum::http::StatusCode::BAD_GATEWAY,
                                            "the reply was lost".to_string(),
                                        );
                                    }
                                    Ok(serde_json::json!({ "roomId": room_id, "epoch": asked }))
                                }
                            }
                        } else {
                            Err(("unsupportedTask", "stub"))
                        }
                    };
                    let doc = match answer {
                        Err((code, msg)) => serde_json::json!({
                            "id": format!("urn:uuid:{}", uuid::Uuid::new_v4()),
                            "type": "https://trusttasks.org/spec/trust-task-error/0.5",
                            "payload": { "code": code, "message": msg },
                        }),
                        Ok(payload) => {
                            let mut doc: trust_tasks_rs::TrustTask<Value> =
                                serde_json::from_value(serde_json::json!({
                                    "id": format!("urn:uuid:{}", uuid::Uuid::new_v4()),
                                    "type": format!("{task}#response"),
                                    "issuer": host_did,
                                    "recipient": vta_did,
                                    "issuedAt": Utc::now().to_rfc3339(),
                                    "threadId": req["id"],
                                    "payload": payload,
                                }))
                                .unwrap();
                            vta_sdk::trust_task_sign::sign_in_place(&mut doc, &host_did, &secret)
                                .await
                                .unwrap();
                            serde_json::to_value(doc).unwrap()
                        }
                    };
                    (axum::http::StatusCode::OK, doc.to_string())
                }
            }),
        );
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        // The host's DID document: its own key, and the HTTPS binding on loopback.
        let mb = party.did.strip_prefix("did:key:").unwrap();
        let vm = format!("{}#{mb}", party.did);
        let doc = serde_json::json!({
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
        (
            StubHost {
                did: party.did.clone(),
                state,
            },
            doc,
        )
    }

    const OWNER_KEY_PATH: &str = "m/44'/0'/7'/0'/1'";
    const ROOM_KEY_PATH: &str = "m/44'/0'/7'/0'/2'";

    /// An owner's VTA: the room's signing key, the owner's identity, their `admin`
    /// grant and membership in the vault, and a resolver that knows the host.
    struct Owner {
        state: AppState,
        _dir: tempfile::TempDir,
        member: String,
        room: Party,
        room_key: String,
        host: StubHost,
    }

    async fn owner() -> Owner {
        let (mut state, dir) = crate::test_support::build_signing_test_app_state().await;
        let member = crate::test_support::seed_holder_key(&state, OWNER_KEY_PATH, None).await;
        let room_signing = crate::test_support::seed_holder_key(&state, ROOM_KEY_PATH, None).await;
        let room_key = format!(
            "{room_signing}#{}",
            room_signing.strip_prefix("did:key:").unwrap()
        );
        let room = Party::new();

        let now = Utc::now();
        let mut vac = DTGCredential::new_vac(
            room.did.clone(),
            dtg_credentials::IssuerScope::Public,
            member.clone(),
            room.did.clone(),
            vec!["read".into(), "write".into(), "admin".into()],
            now - Span::minutes(1),
            now + Span::days(30),
        )
        .unwrap()
        .with_id("urn:uuid:vac-owner");
        vac.sign(&room.secret, None).await.unwrap();
        let mut vmc = DTGCredential::new_vmc(
            room.did.clone(),
            member.clone(),
            now - Span::minutes(1),
            Some(now + Span::days(30)),
            false,
        );
        vmc.sign(&room.secret, None).await.unwrap();
        vault(&state, AUTHORITY_TYPE, &room.did, &vac).await;
        vault(&state, MEMBERSHIP_TYPE, &room.did, &vmc).await;

        let vta_did = state.config.read().await.vta_did.clone().unwrap();
        let (host, host_doc) = start_host(vta_did).await;
        let mut resolver = affinidi_did_resolver_cache_sdk::DIDCacheClient::new(
            affinidi_did_resolver_cache_sdk::config::DIDCacheConfigBuilder::default().build(),
        )
        .await
        .unwrap();
        resolver
            .add_did_document(&host.did, serde_json::from_value(host_doc).unwrap())
            .await;
        state.did_resolver = Some(resolver);

        Owner {
            state,
            _dir: dir,
            member,
            room,
            room_key,
            host,
        }
    }

    /// The owner persona as a member of the owner's room.
    fn om(o: &Owner) -> Member {
        Member::new(&o.room.did, &o.member).unwrap()
    }

    async fn vault(state: &AppState, type_tag: &str, issuer: &str, cred: &DTGCredential) {
        use crate::vault::model::{CredentialFormat, CredentialStatus, StoredCredential};
        use vti_common::vault::VaultStatus;
        crate::vault::storage::put(
            &state.vault_ks,
            &StoredCredential {
                id: format!("{type_tag}-{issuer}"),
                format: CredentialFormat::EddsaJcs2022,
                types: vec![type_tag.into()],
                schema_id: None,
                community_did: None,
                context_id: None,
                subject_did: None,
                issuer_did: Some(issuer.to_string()),
                purpose: None,
                status: CredentialStatus::Unknown,
                valid_from: None,
                valid_until: None,
                received_at: "2026-01-01T00:00:00Z".into(),
                source: None,
                tags: Default::default(),
                body: serde_json::to_vec(cred).unwrap(),
                lifecycle: VaultStatus::Active,
                archived_at: None,
                deleted_at: None,
                grace_until: None,
            },
        )
        .await
        .unwrap();
    }

    fn request(uri: &str, payload: Value) -> TrustTask<Value> {
        let uri: TypeUri = uri.parse().unwrap();
        TrustTask::new("urn:uuid:owner-group-test", uri, payload)
    }

    fn body(outcome: TrustTaskOutcome) -> Value {
        serde_json::from_slice(&outcome.body).expect("a document")
    }

    async fn create(o: &Owner, key: &str) -> Value {
        body(
            handle_create(
                &o.state,
                &crate::test_support::super_admin_claims(),
                request(
                    vta_sdk::trust_tasks::TASK_ROOMS_OWNER_GROUP_CREATE_0_1,
                    serde_json::json!({
                        "roomId": o.room.did, "signingKeyId": key, "member": o.member,
                    }),
                ),
            )
            .await,
        )
    }

    async fn add(o: &Owner, member: &str, key_package: &str) -> Value {
        body(
            handle_add(
                &o.state,
                &crate::test_support::super_admin_claims(),
                request(
                    vta_sdk::trust_tasks::TASK_ROOMS_OWNER_GROUP_ADD_0_1,
                    serde_json::json!({
                        "roomId": o.room.did, "host": o.host.did, "member": member,
                        "keyPackage": key_package, "reason": "joining the deal team",
                    }),
                ),
            )
            .await,
        )
    }

    async fn add_v0_2(o: &Owner, member: &str, key_package: &str) -> Value {
        body(
            handle_add_v0_2(
                &o.state,
                &crate::test_support::super_admin_claims(),
                request(
                    vta_sdk::trust_tasks::TASK_ROOMS_OWNER_GROUP_ADD_0_2,
                    serde_json::json!({
                        "roomId": o.room.did, "host": o.host.did, "member": member,
                        "keyPackage": key_package, "reason": "joining the deal team",
                    }),
                ),
            )
            .await,
        )
    }

    async fn remove(o: &Owner, member: &str) -> Value {
        body(
            handle_remove(
                &o.state,
                &crate::test_support::super_admin_claims(),
                request(
                    vta_sdk::trust_tasks::TASK_ROOMS_OWNER_GROUP_REMOVE_0_1,
                    serde_json::json!({
                        "roomId": o.room.did, "host": o.host.did, "member": member,
                        "reason": "left the deal team",
                    }),
                ),
            )
            .await,
        )
    }

    async fn remove_v0_2(o: &Owner, member: &str, mirrors: &[&str]) -> Value {
        body(
            handle_remove_v0_2(
                &o.state,
                &crate::test_support::super_admin_claims(),
                request(
                    vta_sdk::trust_tasks::TASK_ROOMS_OWNER_GROUP_REMOVE_0_2,
                    serde_json::json!({
                        "roomId": o.room.did, "host": o.host.did, "member": member,
                        "signingKeyId": o.room_key, "mirrors": mirrors,
                        "reason": "left the deal team",
                    }),
                ),
            )
            .await,
        )
    }

    async fn revoke(o: &Owner, withdraw: Value) -> Value {
        body(
            super::super::room_owner_revoke::handle_revoke(
                &o.state,
                &crate::test_support::super_admin_claims(),
                request(
                    vta_sdk::trust_tasks::TASK_ROOMS_OWNER_REVOKE_0_1,
                    serde_json::json!({
                        "roomId": o.room.did, "signingKeyId": o.room_key,
                        "hosts": [o.host.did], "withdraw": withdraw,
                    }),
                ),
            )
            .await,
        )
    }

    async fn revoke_with(o: &Owner, room: &str, key: &str, hosts: Value, withdraw: Value) -> Value {
        body(
            super::super::room_owner_revoke::handle_revoke(
                &o.state,
                &crate::test_support::super_admin_claims(),
                request(
                    vta_sdk::trust_tasks::TASK_ROOMS_OWNER_REVOKE_0_1,
                    serde_json::json!({
                        "roomId": room, "signingKeyId": key, "hosts": hosts, "withdraw": withdraw,
                    }),
                ),
            )
            .await,
        )
    }

    async fn held_list(o: &Owner) -> Option<vti_rooms::revocation::RevocationList> {
        crate::operations::room_revocation::held(&o.state.room_groups_ks, &o.room.did)
            .await
            .unwrap()
    }

    fn host_log(o: &Owner) -> Vec<String> {
        o.host.state.lock().unwrap().log.clone()
    }

    async fn renew(o: &Owner) -> Value {
        body(
            handle_renew(
                &o.state,
                &crate::test_support::super_admin_claims(),
                request(
                    vta_sdk::trust_tasks::TASK_ROOMS_OWNER_GROUP_RENEW_0_1,
                    serde_json::json!({
                        "roomId": o.room.did, "host": o.host.did, "reason": "quarterly renewal",
                    }),
                ),
            )
            .await,
        )
    }

    /// The group this agent holds for the owner's room.
    async fn live_group(o: &Owner) -> vti_rooms::mls::RoomGroup {
        let r = room_groups::load(&o.state.room_groups_ks, &om(o))
            .await
            .unwrap()
            .expect("a group");
        vti_rooms::mls::RoomGroup::restore(&r.snapshot).unwrap()
    }

    async fn pending(o: &Owner) -> Option<room_groups::PendingAdvance> {
        room_groups::pending_advance(&o.state.room_groups_ks, &om(o))
            .await
            .unwrap()
    }

    /// A member admitted end to end: the owner's VTA admits them, and their own VTA joins
    /// from the Welcome.
    async fn admitted(o: &Owner) -> (AppState, tempfile::TempDir, String) {
        let (j_state, j_dir, j_did, kp) = joiner(&o.room.did).await;
        let out = add(o, &j_did, &kp).await;
        let welcome = {
            use base64::Engine as _;
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(out["payload"]["welcome"].as_str().expect("{out}"))
                .unwrap()
        };
        room_groups::join(
            &j_state.room_groups_ks,
            &Member::new(&o.room.did, &j_did).unwrap(),
            &welcome,
            0,
        )
        .await
        .expect("joins from the Welcome");
        (j_state, j_dir, j_did)
    }

    async fn live_epoch(o: &Owner) -> u32 {
        let r = room_groups::load(&o.state.room_groups_ks, &om(o))
            .await
            .unwrap()
            .expect("a group");
        vti_rooms::sealed::SealedRoom::new(
            o.room.did.as_str(),
            vti_rooms::mls::RoomGroup::restore(&r.snapshot).unwrap(),
        )
        .room_epoch()
    }

    /// A joiner's VTA: a KeyPackage minted for the room.
    async fn joiner(room: &str) -> (AppState, tempfile::TempDir, String, String) {
        let (state, dir) = crate::test_support::build_signing_test_app_state().await;
        let did = Party::new().did;
        let pending = room_groups::mint_key_package(
            &state.room_groups_ks,
            &Member::new(room, &did).unwrap(),
            3600,
            0,
        )
        .await
        .unwrap();
        (state, dir, did, pending.key_package)
    }

    #[tokio::test]
    async fn create_founds_the_group_at_the_epoch_a_host_records_and_never_twice() {
        let o = owner().await;
        let first = create(&o, &o.room_key).await;
        assert_eq!(first["payload"]["epoch"], 1, "{first}");
        assert_eq!(live_epoch(&o).await, 1);

        let again = create(&o, &o.room_key).await;
        assert_eq!(
            again["payload"]["code"], "rooms/owner/group/create:alreadyExists",
            "{again}"
        );
        assert_eq!(again["payload"]["details"]["epoch"], 1, "{again}");
    }

    #[tokio::test]
    async fn create_refuses_a_key_the_caller_cannot_name() {
        let o = owner().await;
        let out = create(&o, "did:key:z6MkNobody#z6MkNobody").await;
        assert_eq!(
            out["payload"]["code"], "rooms/owner/group/create:noSigningKey",
            "{out}"
        );
        assert!(
            room_groups::load(&o.state.room_groups_ks, &om(&o))
                .await
                .unwrap()
                .is_none()
        );
    }

    /// The whole admission: the host advances first, the owner's group follows, and the
    /// newcomer's own VTA joins from the Welcome — after which each can open what the other
    /// sealed.
    #[tokio::test]
    async fn an_admitted_member_joins_and_both_read_each_other() {
        let o = owner().await;
        create(&o, &o.room_key).await;
        let (j_state, _j_dir, j_did, kp) = joiner(&o.room.did).await;

        let out = add(&o, &j_did, &kp).await;
        assert_eq!(out["payload"]["epoch"], 2, "{out}");
        assert_eq!(o.host.state.lock().unwrap().epoch, 2, "the host advanced");
        assert_eq!(live_epoch(&o).await, 2, "and only then the owner's group");
        assert!(
            room_groups::pending_advance(&o.state.room_groups_ks, &om(&o))
                .await
                .unwrap()
                .is_none()
        );

        let welcome = {
            use base64::Engine as _;
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(out["payload"]["welcome"].as_str().unwrap())
                .unwrap()
        };
        let joined = room_groups::join(
            &j_state.room_groups_ks,
            &Member::new(&o.room.did, &j_did).unwrap(),
            &welcome,
            0,
        )
        .await
        .expect("the newcomer's VTA joins from the Welcome");
        assert_eq!(joined + 1, 2, "at the room's new epoch");

        let from_owner = room_groups::seal_record(
            &o.state.room_groups_ks,
            &om(&o),
            "notes/1",
            1,
            b"from the owner",
        )
        .await
        .unwrap();
        let opened = room_groups::open_record(
            &j_state.room_groups_ks,
            &Member::new(&o.room.did, &j_did).unwrap(),
            "notes/1",
            1,
            &from_owner.ciphertext,
            &from_owner.nonce,
            from_owner.epoch,
        )
        .await
        .unwrap();
        assert_eq!(opened, b"from the owner");

        let from_member = room_groups::seal_record(
            &j_state.room_groups_ks,
            &Member::new(&o.room.did, &j_did).unwrap(),
            "notes/2",
            2,
            b"from the member",
        )
        .await
        .unwrap();
        let opened = room_groups::open_record(
            &o.state.room_groups_ks,
            &om(&o),
            "notes/2",
            2,
            &from_member.ciphertext,
            &from_member.nonce,
            from_member.epoch,
        )
        .await
        .unwrap();
        assert_eq!(opened, b"from the member");

        // Admitting the same member twice is refused, not a second leaf.
        let (_s2, _d2, _did2, kp2) = joiner(&o.room.did).await;
        let again = add(&o, &j_did, &kp2).await;
        assert_eq!(
            again["payload"]["code"], "rooms/owner/group/add:alreadyMember",
            "{again}"
        );
    }

    /// `rooms/owner/group/add/0.2` item 8: the identical request again — after the answer
    /// was lost on the way back to the caller — is answered with the same epoch and Welcome,
    /// and nothing moves: not the host, not the group. The Welcome still admits the member.
    /// 0.1 is unchanged and refuses the same repeat `alreadyMember`.
    #[tokio::test]
    async fn add_0_2_answers_an_identical_repeat_with_the_kept_welcome() {
        let o = owner().await;
        create(&o, &o.room_key).await;
        let (j_state, _j_dir, j_did, kp) = joiner(&o.room.did).await;

        let first = add_v0_2(&o, &j_did, &kp).await;
        assert_eq!(first["payload"]["epoch"], 2, "{first}");
        let mints_before = o.host.state.lock().unwrap().last_mint.clone();

        let again = add_v0_2(&o, &j_did, &kp).await;
        assert_eq!(again["payload"]["epoch"], 2, "{again}");
        assert_eq!(again["payload"]["member"], j_did, "{again}");
        assert_eq!(
            again["payload"]["welcome"], first["payload"]["welcome"],
            "the same Welcome, not a fresh one"
        );
        assert!(
            again["type"].as_str().is_some_and(
                |t| t.starts_with(vta_sdk::trust_tasks::TASK_ROOMS_OWNER_GROUP_ADD_0_2)
            ),
            "{again}"
        );
        serde_json::from_value::<spec_add::v0_2::Response>(again["payload"].clone())
            .expect("a 0.2 response");
        assert_eq!(
            o.host.state.lock().unwrap().epoch,
            2,
            "the host did not advance"
        );
        assert_eq!(
            o.host.state.lock().unwrap().last_mint,
            mints_before,
            "nothing was sent to the host"
        );
        assert_eq!(live_epoch(&o).await, 2, "the group did not change");
        assert!(pending(&o).await.is_none());

        // 0.1 behaviour is unchanged: the same repeat is `alreadyMember`.
        let v01 = add(&o, &j_did, &kp).await;
        assert_eq!(
            v01["payload"]["code"], "rooms/owner/group/add:alreadyMember",
            "{v01}"
        );

        // The re-served Welcome is the one that admits them.
        let welcome = {
            use base64::Engine as _;
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(again["payload"]["welcome"].as_str().unwrap())
                .unwrap()
        };
        room_groups::join(
            &j_state.room_groups_ks,
            &Member::new(&o.room.did, &j_did).unwrap(),
            &welcome,
            0,
        )
        .await
        .expect("joins from the re-served Welcome");
    }

    /// Item 8: the match is exact. Another KeyPackage for the same member, or the same
    /// KeyPackage named for another member, is no repeat — `alreadyMember` for the first,
    /// and the second is refused as `keyPackageInvalid` as any mismatched leaf is.
    #[tokio::test]
    async fn add_0_2_another_key_package_for_the_member_is_already_member() {
        let o = owner().await;
        create(&o, &o.room_key).await;
        let (_s, _d, j_did, kp) = joiner(&o.room.did).await;
        add_v0_2(&o, &j_did, &kp).await;

        let (_, other) = vti_rooms::mls::IdentitySnapshot::mint(&j_did).unwrap();
        let other = {
            use base64::Engine as _;
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(other)
        };
        let out = add_v0_2(&o, &j_did, &other).await;
        assert_eq!(
            out["payload"]["code"], "rooms/owner/group/add:alreadyMember",
            "{out}"
        );
        assert_eq!(o.host.state.lock().unwrap().epoch, 2);

        let out = add_v0_2(&o, "did:key:z6MkSomebodyElse", &kp).await;
        assert_eq!(
            out["payload"]["code"], "rooms/owner/group/add:keyPackageInvalid",
            "{out}"
        );
        assert_eq!(o.host.state.lock().unwrap().epoch, 2);
    }

    /// Item 8: kept until the owner's next advance of the room, or 24 hours — whichever is
    /// first — and `alreadyMember` after either. The sweep takes an expired one off disk.
    #[tokio::test]
    async fn add_0_2_forgets_the_welcome_at_the_next_advance_or_after_24_hours() {
        // The next advance.
        let o = owner().await;
        create(&o, &o.room_key).await;
        let (_s, _d, j_did, kp) = joiner(&o.room.did).await;
        add_v0_2(&o, &j_did, &kp).await;
        let renewed = renew(&o).await;
        assert_eq!(renewed["payload"]["epoch"], 3, "{renewed}");
        assert!(!room_groups::has_retained_admission_row(&o.state.room_groups_ks, &om(&o)).await);
        let out = add_v0_2(&o, &j_did, &kp).await;
        assert_eq!(
            out["payload"]["code"], "rooms/owner/group/add:alreadyMember",
            "{out}"
        );

        // 24 hours.
        let o = owner().await;
        create(&o, &o.room_key).await;
        let (_s, _d, j_did, kp) = joiner(&o.room.did).await;
        add_v0_2(&o, &j_did, &kp).await;
        room_groups::age_retained_admission_for_test(
            &o.state.room_groups_ks,
            &om(&o),
            room_groups::ADMISSION_RETENTION_SECS - 60,
        )
        .await;
        let out = add_v0_2(&o, &j_did, &kp).await;
        assert_eq!(
            out["payload"]["epoch"], 2,
            "still kept just inside 24 hours: {out}"
        );
        room_groups::age_retained_admission_for_test(&o.state.room_groups_ks, &om(&o), 120).await;
        let out = add_v0_2(&o, &j_did, &kp).await;
        assert_eq!(
            out["payload"]["code"], "rooms/owner/group/add:alreadyMember",
            "{out}"
        );
        assert!(
            !room_groups::has_retained_admission_row(&o.state.room_groups_ks, &om(&o)).await,
            "an expired admission read is discarded"
        );

        // The sweep, for one nobody asks about again.
        let o = owner().await;
        create(&o, &o.room_key).await;
        let (_s, _d, j_did, kp) = joiner(&o.room.did).await;
        add_v0_2(&o, &j_did, &kp).await;
        let now = u64::try_from(Utc::now().timestamp()).unwrap();
        assert_eq!(
            room_groups::sweep_retained_admissions(&o.state.room_groups_ks, now)
                .await
                .unwrap(),
            0,
            "a kept one stays"
        );
        assert_eq!(
            room_groups::sweep_retained_admissions(
                &o.state.room_groups_ks,
                now + room_groups::ADMISSION_RETENTION_SECS
            )
            .await
            .unwrap(),
            1
        );
        assert!(!room_groups::has_retained_admission_row(&o.state.room_groups_ks, &om(&o)).await);
    }

    /// Items 6 and 8: the host accepts and its answer is lost, so the admission is pending.
    /// The identical request settles it (item 6) — and, since it repeats the admission it
    /// just applied, is answered with that admission's Welcome rather than refused or
    /// advanced again.
    #[tokio::test]
    async fn add_0_2_a_repeat_after_a_lost_host_answer_settles_and_gets_the_welcome() {
        let o = owner().await;
        create(&o, &o.room_key).await;
        o.host.state.lock().unwrap().mode = Mode::AcceptThenLose;
        let (_s, _d, j_did, kp) = joiner(&o.room.did).await;

        let out = add_v0_2(&o, &j_did, &kp).await;
        assert_eq!(
            out["payload"]["code"], "rooms/owner/group/add:hostUnreachable",
            "{out}"
        );
        let kept = pending(&o).await.expect("pending").welcome;

        o.host.state.lock().unwrap().mode = Mode::Accept;
        let again = add_v0_2(&o, &j_did, &kp).await;
        assert_eq!(again["payload"]["epoch"], 2, "{again}");
        assert_eq!(
            again["payload"]["welcome"].as_str(),
            kept.as_deref(),
            "{again}"
        );
        assert_eq!(
            o.host.state.lock().unwrap().epoch,
            2,
            "settled, not advanced again"
        );
        assert_eq!(live_epoch(&o).await, 2);
        assert!(pending(&o).await.is_none());
    }

    /// A KeyPackage naming somebody else is refused: an owner admits the party they meant.
    #[tokio::test]
    async fn a_key_package_for_someone_else_is_refused() {
        let o = owner().await;
        create(&o, &o.room_key).await;
        let (_s, _d, _did, kp) = joiner(&o.room.did).await;
        let out = add(&o, "did:key:z6MkSomebodyElse", &kp).await;
        assert_eq!(
            out["payload"]["code"], "rooms/owner/group/add:keyPackageInvalid",
            "{out}"
        );
        assert_eq!(
            o.host.state.lock().unwrap().epoch,
            1,
            "nothing reached the host"
        );
        assert!(
            room_groups::pending_advance(&o.state.room_groups_ks, &om(&o))
                .await
                .unwrap()
                .is_none()
        );
    }

    /// Item 5: a refusal is the host's answer, so the owner's group does not move.
    #[tokio::test]
    async fn a_host_refusal_leaves_the_group_where_it_was() {
        let o = owner().await;
        create(&o, &o.room_key).await;
        o.host.state.lock().unwrap().mode = Mode::Refuse;
        let (_s, _d, did, kp) = joiner(&o.room.did).await;

        let out = add(&o, &did, &kp).await;
        assert_eq!(
            out["payload"]["code"], "rooms/owner/group/add:hostRefused",
            "{out}"
        );
        assert_eq!(live_epoch(&o).await, 1);
        assert!(
            room_groups::pending_advance(&o.state.room_groups_ks, &om(&o))
                .await
                .unwrap()
                .is_none(),
            "a refused admission leaves nothing pending"
        );
    }

    /// A host another admin advanced answers `nonSequential`: `epochConflict`, carrying the
    /// host's epoch, and nothing changes here.
    #[tokio::test]
    async fn a_room_advanced_elsewhere_is_an_epoch_conflict() {
        let o = owner().await;
        create(&o, &o.room_key).await;
        o.host.state.lock().unwrap().epoch = 5;
        let (_s, _d, did, kp) = joiner(&o.room.did).await;

        let out = add(&o, &did, &kp).await;
        assert_eq!(
            out["payload"]["code"], "rooms/owner/group/add:epochConflict",
            "{out}"
        );
        assert_eq!(out["payload"]["details"]["hostEpoch"], 5, "{out}");
        assert_eq!(live_epoch(&o).await, 1);
    }

    /// Items 3, 5 and 6: the host accepts and the answer is lost. The outcome is unknown,
    /// so the pending admission is kept — and the next request finds the host at its epoch
    /// and applies it, rather than leaving this agent behind a room that moved.
    #[tokio::test]
    async fn an_advance_whose_answer_was_lost_is_settled_by_the_next_request() {
        let o = owner().await;
        create(&o, &o.room_key).await;
        o.host.state.lock().unwrap().mode = Mode::AcceptThenLose;
        let (_s, _d, did, kp) = joiner(&o.room.did).await;

        let out = add(&o, &did, &kp).await;
        assert_eq!(
            out["payload"]["code"], "rooms/owner/group/add:hostUnreachable",
            "{out}"
        );
        assert_eq!(
            o.host.state.lock().unwrap().epoch,
            2,
            "the host did advance"
        );
        assert_eq!(live_epoch(&o).await, 1, "this agent does not know that yet");
        assert!(
            room_groups::pending_advance(&o.state.room_groups_ks, &om(&o))
                .await
                .unwrap()
                .is_some(),
            "an unknown outcome keeps the pending admission"
        );

        // The next admission settles the first against the host before anything else.
        o.host.state.lock().unwrap().mode = Mode::Accept;
        let (_s2, _d2, did2, kp2) = joiner(&o.room.did).await;
        let out = add(&o, &did2, &kp2).await;
        assert_eq!(out["payload"]["epoch"], 3, "{out}");
        assert_eq!(live_epoch(&o).await, 3);
        let group = room_groups::load(&o.state.room_groups_ks, &om(&o))
            .await
            .unwrap()
            .unwrap();
        let group = vti_rooms::mls::RoomGroup::restore(&group.snapshot).unwrap();
        assert!(
            group.leaf_of(&did).is_some(),
            "the first admission was applied"
        );
        assert!(group.leaf_of(&did2).is_some());
    }

    /// A pending admission the host never took is discarded, and the room carries on.
    #[tokio::test]
    async fn a_pending_admission_the_host_never_took_is_discarded() {
        let o = owner().await;
        create(&o, &o.room_key).await;
        let (_s, _d, did, kp) = joiner(&o.room.did).await;
        let key_package = {
            use base64::Engine as _;
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(&kp)
                .unwrap()
        };
        // As if the process died between storing the pending admission and sending it.
        room_groups::prepare_add(
            &o.state.room_groups_ks,
            &om(&o),
            &o.host.did,
            &did,
            &key_package,
            0,
        )
        .await
        .unwrap();

        let (_s2, _d2, did2, kp2) = joiner(&o.room.did).await;
        let out = add(&o, &did2, &kp2).await;
        assert_eq!(out["payload"]["epoch"], 2, "{out}");
        let group = room_groups::load(&o.state.room_groups_ks, &om(&o))
            .await
            .unwrap()
            .unwrap();
        let group = vti_rooms::mls::RoomGroup::restore(&group.snapshot).unwrap();
        assert!(group.leaf_of(&did).is_none(), "never admitted");
        assert!(group.leaf_of(&did2).is_some());
    }

    /// Without the owner's `admin` grant nothing is built and nothing is sent.
    #[tokio::test]
    async fn no_admin_authority_is_refused_before_anything_is_built() {
        let o = owner().await;
        create(&o, &o.room_key).await;
        crate::vault::storage::delete(
            &o.state.vault_ks,
            &format!("{AUTHORITY_TYPE}-{}", o.room.did),
        )
        .await
        .unwrap();
        let (_s, _d, did, kp) = joiner(&o.room.did).await;
        let out = add(&o, &did, &kp).await;
        assert_eq!(
            out["payload"]["code"], "rooms/owner/group/add:noAuthority",
            "{out}"
        );
        assert!(
            room_groups::pending_advance(&o.state.room_groups_ks, &om(&o))
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn add_without_a_group_says_so() {
        let o = owner().await;
        let (_s, _d, did, kp) = joiner(&o.room.did).await;
        let out = add(&o, &did, &kp).await;
        assert_eq!(
            out["payload"]["code"], "rooms/owner/group/add:noGroup",
            "{out}"
        );
    }

    // ─── rooms/owner/group/remove/0.1 ────────────────────────────────────────────────

    /// Item 1: no group.
    #[tokio::test]
    async fn remove_without_a_group_is_no_group() {
        let o = owner().await;
        let out = remove(&o, "did:key:z6MkSomebody").await;
        assert_eq!(
            out["payload"]["code"], "rooms/owner/group/remove:noGroup",
            "{out}"
        );
    }

    /// Item 1: a DID with no leaf is refused, and nothing is built or sent.
    #[tokio::test]
    async fn removing_a_non_member_is_not_member_and_sends_nothing() {
        let o = owner().await;
        create(&o, &o.room_key).await;
        let out = remove(&o, "did:key:z6MkNeverAdmitted").await;
        assert_eq!(
            out["payload"]["code"], "rooms/owner/group/remove:notMember",
            "{out}"
        );
        assert_eq!(
            o.host.state.lock().unwrap().epoch,
            1,
            "nothing reached the host"
        );
        assert!(o.host.state.lock().unwrap().last_mint.is_none());
        assert!(pending(&o).await.is_none());
        assert_eq!(live_epoch(&o).await, 1);
    }

    /// Item 1: the key holder's own leaf is `ownLeaf` — refused before the host is asked
    /// anything, and the group keeps its owner.
    #[tokio::test]
    async fn removing_the_own_leaf_is_refused() {
        let o = owner().await;
        create(&o, &o.room_key).await;
        // A host that would refuse proves the refusal never needed it.
        o.host.state.lock().unwrap().mode = Mode::Refuse;
        let out = remove(&o, &o.member).await;
        assert_eq!(
            out["payload"]["code"], "rooms/owner/group/remove:ownLeaf",
            "{out}"
        );
        assert!(live_group(&o).await.leaf_of(&o.member).is_some());
        assert!(pending(&o).await.is_none());
    }

    /// Items 2, 4 and 5 end to end: the host advances first and only then the owner's
    /// group; the member who remains follows from the commit the host took and reads what
    /// the owner seals next; the member removed cannot — while both still read what was
    /// sealed before.
    #[tokio::test]
    async fn a_removed_member_reads_nothing_sealed_after_and_the_rest_carry_on() {
        let o = owner().await;
        create(&o, &o.room_key).await;
        let (stay_state, _stay_dir, stay_did) = admitted(&o).await; // epoch 2
        let (gone_state, _gone_dir, gone_did) = admitted(&o).await; // epoch 3

        // The member who stays applies the second admission, as the host would relay it.
        let commit_3 = commit_of_last_mint(&o);
        room_groups::apply_commit(
            &stay_state.room_groups_ks,
            &Member::new(&o.room.did, &stay_did).unwrap(),
            &commit_3,
            2,
            0,
        )
        .await
        .expect("the remaining member follows the admission");

        let before =
            room_groups::seal_record(&o.state.room_groups_ks, &om(&o), "notes/1", 1, b"before")
                .await
                .unwrap();

        let out = remove(&o, &gone_did).await;
        assert_eq!(out["payload"]["epoch"], 4, "{out}");
        assert_eq!(out["payload"]["member"], gone_did, "{out}");
        assert_eq!(o.host.state.lock().unwrap().epoch, 4, "the host advanced");
        assert_eq!(live_epoch(&o).await, 4, "and only then the owner's group");
        assert!(pending(&o).await.is_none());
        let group = live_group(&o).await;
        assert!(group.leaf_of(&gone_did).is_none(), "the leaf is gone");
        assert!(group.leaf_of(&stay_did).is_some());
        let mint = o.host.state.lock().unwrap().last_mint.clone().unwrap();
        assert!(
            mint.get("link").is_some(),
            "the advance carries its epoch link: {mint}"
        );
        assert_eq!(mint["reason"], "left the deal team");
        assert!(
            !mint.to_string().contains(&gone_did),
            "the host is not told who left"
        );

        let commit_4 = commit_of_last_mint(&o);
        room_groups::apply_commit(
            &stay_state.room_groups_ks,
            &Member::new(&o.room.did, &stay_did).unwrap(),
            &commit_4,
            3,
            0,
        )
        .await
        .expect("the remaining member follows the removal");
        let after =
            room_groups::seal_record(&o.state.room_groups_ks, &om(&o), "notes/2", 1, b"after")
                .await
                .unwrap();
        assert_eq!(after.epoch, 4);
        let open = |state: &AppState,
                    did: &str,
                    rec: &vti_rooms::wire::SealedContent,
                    key: &'static str| {
            let ks = state.room_groups_ks.clone();
            let member = Member::new(&o.room.did, did).unwrap();
            let rec = rec.clone();
            async move {
                room_groups::open_record(
                    &ks,
                    &member,
                    key,
                    1,
                    &rec.ciphertext,
                    &rec.nonce,
                    rec.epoch,
                )
                .await
            }
        };
        assert_eq!(
            open(&stay_state, &stay_did, &after, "notes/2")
                .await
                .unwrap(),
            b"after"
        );
        assert!(
            open(&gone_state, &gone_did, &after, "notes/2")
                .await
                .is_err(),
            "removal is forward: nothing sealed after it opens for the member removed"
        );
        assert_eq!(
            open(&stay_state, &stay_did, &before, "notes/1")
                .await
                .unwrap(),
            b"before"
        );
        assert_eq!(
            open(&gone_state, &gone_did, &before, "notes/1")
                .await
                .unwrap(),
            b"before",
            "and it recalls nothing: what they could read, they still can"
        );
    }

    fn commit_of_last_mint(o: &Owner) -> Vec<u8> {
        use base64::Engine as _;
        let mint = o
            .host
            .state
            .lock()
            .unwrap()
            .last_mint
            .clone()
            .expect("a mint");
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(mint["commit"].as_str().unwrap())
            .unwrap()
    }

    /// Item 5: a refusal is the host's answer — `hostRefused`, the pending removal is
    /// discarded and the member keeps their leaf.
    #[tokio::test]
    async fn a_refused_removal_leaves_the_group_unchanged() {
        let o = owner().await;
        create(&o, &o.room_key).await;
        let (_s, _d, did) = admitted(&o).await;
        o.host.state.lock().unwrap().mode = Mode::Refuse;

        let out = remove(&o, &did).await;
        assert_eq!(
            out["payload"]["code"], "rooms/owner/group/remove:hostRefused",
            "{out}"
        );
        assert_eq!(
            out["payload"]["details"]["code"], "permissionDenied",
            "{out}"
        );
        assert_eq!(live_epoch(&o).await, 2);
        assert!(live_group(&o).await.leaf_of(&did).is_some());
        assert!(
            pending(&o).await.is_none(),
            "a refused removal leaves nothing pending"
        );
    }

    /// A host another admin advanced answers `nonSequential`: `epochConflict` with
    /// `hostEpoch`, and nothing changes here.
    #[tokio::test]
    async fn a_removal_in_a_room_advanced_elsewhere_is_an_epoch_conflict() {
        let o = owner().await;
        create(&o, &o.room_key).await;
        let (_s, _d, did) = admitted(&o).await;
        o.host.state.lock().unwrap().epoch = 7;

        let out = remove(&o, &did).await;
        assert_eq!(
            out["payload"]["code"], "rooms/owner/group/remove:epochConflict",
            "{out}"
        );
        assert_eq!(out["payload"]["details"]["hostEpoch"], 7, "{out}");
        assert_eq!(live_epoch(&o).await, 2);
        assert!(live_group(&o).await.leaf_of(&did).is_some());
        assert!(pending(&o).await.is_none());
    }

    /// Items 3, 5 and 6: the host takes the removal and the answer is lost —
    /// `hostUnreachable`, the pending removal is KEPT, the live group has not moved, and the
    /// next request (here, another removal) finds the host at its epoch and applies it.
    #[tokio::test]
    async fn a_removal_whose_answer_was_lost_is_applied_by_the_next_request() {
        let o = owner().await;
        create(&o, &o.room_key).await;
        let (_s1, _d1, first) = admitted(&o).await; // 2
        let (_s2, _d2, second) = admitted(&o).await; // 3
        o.host.state.lock().unwrap().mode = Mode::AcceptThenLose;

        let out = remove(&o, &first).await;
        assert_eq!(
            out["payload"]["code"], "rooms/owner/group/remove:hostUnreachable",
            "{out}"
        );
        assert_eq!(
            o.host.state.lock().unwrap().epoch,
            4,
            "the host did advance"
        );
        assert_eq!(live_epoch(&o).await, 3, "this agent does not know that yet");
        let kept = pending(&o)
            .await
            .expect("an unknown outcome keeps the pending removal");
        assert_eq!(kept.kind, room_groups::AdvanceKind::Removal);
        assert_eq!(kept.epoch, 4);
        assert!(kept.welcome.is_none(), "a removal welcomes nobody");

        o.host.state.lock().unwrap().mode = Mode::Accept;
        let out = remove(&o, &second).await;
        assert_eq!(out["payload"]["epoch"], 5, "{out}");
        let group = live_group(&o).await;
        assert!(
            group.leaf_of(&first).is_none(),
            "the first removal was applied"
        );
        assert!(group.leaf_of(&second).is_none());
        assert!(pending(&o).await.is_none());
    }

    /// Item 6: a pending removal the host never took is discarded — the member keeps their
    /// leaf — and the request carries on from the live group.
    #[tokio::test]
    async fn a_pending_removal_the_host_never_took_is_discarded() {
        let o = owner().await;
        create(&o, &o.room_key).await;
        let (_s1, _d1, first) = admitted(&o).await; // 2
        let (_s2, _d2, second) = admitted(&o).await; // 3
        // As if the process died between storing the pending removal and sending it.
        room_groups::prepare_remove(&o.state.room_groups_ks, &om(&o), &o.host.did, &first, 0)
            .await
            .unwrap();

        let out = remove(&o, &second).await;
        assert_eq!(out["payload"]["epoch"], 4, "{out}");
        let group = live_group(&o).await;
        assert!(group.leaf_of(&first).is_some(), "never removed");
        assert!(group.leaf_of(&second).is_none());
    }

    /// Item 6, third case: the host is neither at the pending epoch nor the one before it.
    /// The pending removal is discarded and the request refused `epochConflict`.
    #[tokio::test]
    async fn a_pending_removal_overtaken_at_the_host_is_discarded_as_a_conflict() {
        let o = owner().await;
        create(&o, &o.room_key).await;
        let (_s1, _d1, first) = admitted(&o).await; // 2
        room_groups::prepare_remove(&o.state.room_groups_ks, &om(&o), &o.host.did, &first, 0)
            .await
            .unwrap();
        o.host.state.lock().unwrap().epoch = 9;

        let out = remove(&o, &first).await;
        assert_eq!(
            out["payload"]["code"], "rooms/owner/group/remove:epochConflict",
            "{out}"
        );
        assert_eq!(out["payload"]["details"]["hostEpoch"], 9, "{out}");
        assert!(pending(&o).await.is_none(), "discarded");
        assert_eq!(live_epoch(&o).await, 2);
    }

    /// Item 3: one pending advance per room, of either kind. An admission whose answer was
    /// lost is settled by a removal — and since membership is read after settling, the
    /// member it admitted can be the one removed.
    #[tokio::test]
    async fn a_pending_admission_is_settled_before_a_removal_is_built() {
        let o = owner().await;
        create(&o, &o.room_key).await;
        o.host.state.lock().unwrap().mode = Mode::AcceptThenLose;
        let (_s, _d, did, kp) = joiner(&o.room.did).await;
        let out = add(&o, &did, &kp).await;
        assert_eq!(
            out["payload"]["code"], "rooms/owner/group/add:hostUnreachable",
            "{out}"
        );
        assert_eq!(
            pending(&o).await.unwrap().kind,
            room_groups::AdvanceKind::Admission
        );

        o.host.state.lock().unwrap().mode = Mode::Accept;
        let out = remove(&o, &did).await;
        assert_eq!(out["payload"]["epoch"], 3, "{out}");
        assert!(live_group(&o).await.leaf_of(&did).is_none());
        assert!(pending(&o).await.is_none());
    }

    /// And the other way: a removal whose answer was lost is settled by an admission.
    #[tokio::test]
    async fn a_pending_removal_is_settled_before_an_admission_is_built() {
        let o = owner().await;
        create(&o, &o.room_key).await;
        let (_s, _d, gone) = admitted(&o).await; // 2
        o.host.state.lock().unwrap().mode = Mode::AcceptThenLose;
        remove(&o, &gone).await; // host at 3, answer lost

        o.host.state.lock().unwrap().mode = Mode::Accept;
        let (_s2, _d2, newcomer, kp) = joiner(&o.room.did).await;
        let out = add(&o, &newcomer, &kp).await;
        assert_eq!(out["payload"]["epoch"], 4, "{out}");
        let group = live_group(&o).await;
        assert!(
            group.leaf_of(&gone).is_none(),
            "the removal was applied first"
        );
        assert!(group.leaf_of(&newcomer).is_some());
    }

    /// The slot holds one advance: a second cannot be retained over a first, whichever
    /// kinds they are. The handlers never reach this (they settle first); a request racing
    /// another for the same room does.
    #[tokio::test]
    async fn a_room_holds_at_most_one_pending_advance() {
        let o = owner().await;
        create(&o, &o.room_key).await;
        let (_s, _d, did) = admitted(&o).await;
        room_groups::prepare_remove(&o.state.room_groups_ks, &om(&o), &o.host.did, &did, 0)
            .await
            .unwrap();
        let (_s2, _d2, other, kp) = joiner(&o.room.did).await;
        let kp = {
            use base64::Engine as _;
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(&kp)
                .unwrap()
        };
        let second = room_groups::prepare_add(
            &o.state.room_groups_ks,
            &om(&o),
            &o.host.did,
            &other,
            &kp,
            0,
        )
        .await;
        assert!(
            matches!(second, Err(PrepareAddError::App(AppError::Conflict(_)))),
            "{second:?}"
        );
        assert_eq!(
            pending(&o).await.unwrap().kind,
            room_groups::AdvanceKind::Removal,
            "the first is untouched"
        );
    }

    /// **An upgraded store.** The group and a pending admission as the per-room build left
    /// them — `room-group:<room>`, and the admission at `room-add:<room>` in its shape from
    /// before removal existed, with no `kind` — are moved under the owner persona on first
    /// touch (the persona the group's own leaf identifies), the admission is read as one and
    /// settled, and nothing is left at the old keys to be found again.
    #[tokio::test]
    async fn a_legacy_group_and_pending_admission_are_migrated_and_settled() {
        let o = owner().await;
        create(&o, &o.room_key).await;
        o.host.state.lock().unwrap().mode = Mode::AcceptThenLose;
        let (_s, _d, did, kp) = joiner(&o.room.did).await;
        add(&o, &did, &kp).await; // host at 2, answer lost

        // Put both rows back where, and as, the per-room build wrote them.
        let groups = &o.state.room_groups_ks;
        let record = room_groups::load(groups, &om(&o)).await.unwrap().unwrap();
        let mut legacy = serde_json::to_value(pending(&o).await.unwrap()).unwrap();
        legacy.as_object_mut().unwrap().remove("kind");
        room_groups::forget(groups, &om(&o)).await.unwrap();
        room_groups::legacy_for_test::store_group(groups, &o.room.did, &record).await;
        room_groups::legacy_for_test::store_pending_add(groups, &o.room.did, &legacy).await;
        assert!(pending(&o).await.is_none(), "nothing under the member yet");

        o.host.state.lock().unwrap().mode = Mode::Accept;
        let out = remove(&o, &did).await;
        assert_eq!(out["payload"]["epoch"], 3, "{out}");
        assert!(pending(&o).await.is_none(), "the slot is clear");
        assert!(
            room_groups::legacy_rooms(groups).await.unwrap().is_empty(),
            "the legacy group row was moved, not copied"
        );
        assert!(
            groups
                .get_raw(format!("room-add:{}", o.room.did))
                .await
                .unwrap()
                .is_none(),
            "the legacy admission slot is empty"
        );
        assert_eq!(live_epoch(&o).await, 3);
    }

    /// Without the owner's `admin` grant nothing is built and nothing is sent.
    #[tokio::test]
    async fn remove_without_admin_authority_is_refused_before_anything_is_built() {
        let o = owner().await;
        create(&o, &o.room_key).await;
        let (_s, _d, did) = admitted(&o).await;
        crate::vault::storage::delete(
            &o.state.vault_ks,
            &format!("{AUTHORITY_TYPE}-{}", o.room.did),
        )
        .await
        .unwrap();
        let out = remove(&o, &did).await;
        assert_eq!(
            out["payload"]["code"], "rooms/owner/group/remove:noAuthority",
            "{out}"
        );
        assert!(pending(&o).await.is_none());
        assert!(live_group(&o).await.leaf_of(&did).is_some());
    }
    // ─── Personas ────────────────────────────────────────────────────────────

    async fn create_as(o: &Owner, auth: &AuthClaims, member: Option<&str>) -> Value {
        let mut payload = serde_json::json!({ "roomId": o.room.did, "signingKeyId": o.room_key });
        if let Some(m) = member {
            payload["member"] = serde_json::json!(m);
        }
        body(
            handle_create(
                &o.state,
                auth,
                request(
                    vta_sdk::trust_tasks::TASK_ROOMS_OWNER_GROUP_CREATE_0_1,
                    payload,
                ),
            )
            .await,
        )
    }

    async fn leaf_of(o: &Owner, did: &str) -> bool {
        let r = room_groups::load(&o.state.room_groups_ks, &om(o))
            .await
            .unwrap()
            .expect("a group");
        vti_rooms::mls::RoomGroup::restore(&r.snapshot)
            .unwrap()
            .leaf_of(did)
            .is_some()
    }

    /// With no `member`, the owner's leaf is the persona the room's credentials name — not
    /// the caller, whose DID is a client key.
    #[tokio::test]
    async fn create_without_a_member_founds_on_the_owners_persona() {
        let o = owner().await;
        let caller = crate::test_support::super_admin_claims();
        let out = create_as(&o, &caller, None).await;
        assert_eq!(out["payload"]["epoch"], 1, "{out}");
        assert!(leaf_of(&o, &o.member).await, "the persona's leaf");
        assert!(!leaf_of(&o, &caller.did).await, "never the client's");
    }

    /// A `member` that is not a persona the caller may act as is refused — another
    /// context's persona and the caller's own client key alike — and nothing is founded.
    #[tokio::test]
    async fn create_refuses_a_member_that_is_not_the_callers_persona() {
        let o = owner().await;
        crate::contexts::create_context(&o.state.contexts_ks, "bob", "Bob")
            .await
            .unwrap();
        let bob = crate::operations::persona::test_fixture::did_key_persona(
            &o.state.keys_ks,
            &o.state.internal_ks,
            &o.state.contexts_ks,
            &o.state.acl_ks,
            &o.state.seed_store,
            &o.state.audit_sink,
            "bob",
            "bob-persona",
        )
        .await;
        let caller = crate::test_support::super_admin_claims();
        let nobody = Party::new().did;

        // A super-admin acts everywhere, so bob's persona is theirs to name; a caller
        // scoped elsewhere is not, and is told so as for a DID nobody holds. (Asked of the
        // rule directly: such a caller could not name the room's key either.)
        let scoped = crate::test_support::admin_claims_for_context("carol");
        let to_bob = founding_member(&o.state, &scoped, &o.room.did, Some(&bob.did))
            .await
            .expect_err("bob's persona is not carol's caller's");
        let to_nobody = founding_member(&o.state, &scoped, &o.room.did, Some(&nobody))
            .await
            .expect_err("nobody's");
        assert!(matches!(to_bob, AppError::Forbidden(_)), "{to_bob}");
        assert_eq!(
            to_bob.to_string(),
            to_nobody.to_string().replace(&nobody, &bob.did)
        );
        let msg = |d: &Value| {
            d["payload"]["message"]
                .as_str()
                .unwrap_or_default()
                .to_string()
        };

        let to_client = create_as(&o, &caller, Some(&caller.did)).await;
        assert!(
            msg(&to_client).contains("not a persona you may act as"),
            "{to_client}"
        );
        assert!(
            room_groups::load(&o.state.room_groups_ks, &om(&o))
                .await
                .unwrap()
                .is_none(),
            "nothing founded"
        );

        // Named explicitly, a persona the caller acts as is accepted.
        let ok = create_as(&o, &caller, Some(&o.member)).await;
        assert_eq!(ok["payload"]["epoch"], 1, "{ok}");
    }

    /// No `member`, no credentials naming a persona, and a caller whose DID is a client key:
    /// asked for `member`, never founded on the client key.
    #[tokio::test]
    async fn create_with_nothing_to_name_the_owner_asks_for_member() {
        let o = owner().await;
        for tag in [AUTHORITY_TYPE, MEMBERSHIP_TYPE] {
            crate::vault::storage::delete(&o.state.vault_ks, &format!("{tag}-{}", o.room.did))
                .await
                .unwrap();
        }
        let out = create_as(&o, &crate::test_support::super_admin_claims(), None).await;
        assert!(
            out["payload"]["message"]
                .as_str()
                .unwrap_or_default()
                .contains("`member`"),
            "{out}"
        );
        assert!(
            room_groups::load(&o.state.room_groups_ks, &om(&o))
                .await
                .unwrap()
                .is_none()
        );
    }

    /// `rooms/epoch/mint` goes to the host signed as the owner's persona, with the `admin`
    /// leaf granted to that same persona — the presenter the host authenticates — and not
    /// as this agent, whose DID every principal it serves shares. Admission, removal and
    /// renewal alike.
    #[tokio::test]
    async fn add_remove_and_renew_speak_to_the_host_as_the_owners_persona() {
        let o = owner().await;
        create(&o, &o.room_key).await;
        let vta_did = o.state.config.read().await.vta_did.clone().unwrap();
        let check = |what: &str| {
            let h = o.host.state.lock().unwrap();
            let issuer = h.last_mint_issuer.clone().expect("a mint was signed");
            assert_eq!(issuer, o.member, "{what}: signed as the owner persona");
            assert_ne!(issuer, vta_did, "{what}");
            let leaf: Value = serde_json::from_str(
                h.last_mint.as_ref().expect("a mint")["presentation"]["authority"][0]
                    .as_str()
                    .unwrap(),
            )
            .unwrap();
            assert_eq!(leaf["credentialSubject"]["id"], o.member, "{what}: {leaf}");
            assert_eq!(
                leaf["issuer"], o.member,
                "{what}: narrowed by the persona: {leaf}"
            );
        };

        let (_s, _d, did, kp) = joiner(&o.room.did).await;
        let out = add(&o, &did, &kp).await;
        assert_eq!(out["payload"]["epoch"], 2, "{out}");
        check("add");

        let out = remove(&o, &did).await;
        assert_eq!(out["payload"]["epoch"], 3, "{out}");
        check("remove");

        let out = renew(&o).await;
        assert_eq!(out["payload"]["epoch"], 4, "{out}");
        check("renew");
    }

    // ─── rooms/owner/group/renew/0.1 ─────────────────────────────────────────────────

    /// Item 1: no group — an `open` room renews with rooms/epoch/mint, not here.
    #[tokio::test]
    async fn renew_without_a_group_is_no_group() {
        let o = owner().await;
        let out = renew(&o).await;
        assert_eq!(
            out["payload"]["code"], "rooms/owner/group/renew:noGroup",
            "{out}"
        );
        assert!(o.host.state.lock().unwrap().last_mint.is_none());
    }

    /// Item 1: without the owner's `admin` grant nothing is built and nothing is sent.
    #[tokio::test]
    async fn renew_without_admin_authority_is_refused_before_anything_is_built() {
        let o = owner().await;
        create(&o, &o.room_key).await;
        crate::vault::storage::delete(
            &o.state.vault_ks,
            &format!("{AUTHORITY_TYPE}-{}", o.room.did),
        )
        .await
        .unwrap();
        let out = renew(&o).await;
        assert_eq!(
            out["payload"]["code"], "rooms/owner/group/renew:noAuthority",
            "{out}"
        );
        assert!(pending(&o).await.is_none());
        assert!(o.host.state.lock().unwrap().last_mint.is_none());
        assert_eq!(live_epoch(&o).await, 1);
    }

    /// Items 2, 4, 5 and 7 end to end: the host advances first and only then the owner's
    /// group; nobody joins or leaves; the member who remains follows from the commit the
    /// host took and reads what the owner seals next; and what was sealed before still
    /// opens, through the link.
    #[tokio::test]
    async fn a_renewal_advances_the_host_then_the_group_and_members_follow() {
        let o = owner().await;
        create(&o, &o.room_key).await;
        let (m_state, _m_dir, m_did) = admitted(&o).await; // epoch 2
        let member = Member::new(&o.room.did, &m_did).unwrap();

        let before =
            room_groups::seal_record(&o.state.room_groups_ks, &om(&o), "notes/1", 1, b"before")
                .await
                .unwrap();
        assert_eq!(before.epoch, 2);

        let out = renew(&o).await;
        assert_eq!(out["payload"]["epoch"], 3, "{out}");
        assert_eq!(out["payload"]["roomId"], o.room.did, "{out}");
        assert_eq!(o.host.state.lock().unwrap().epoch, 3, "the host advanced");
        assert_eq!(live_epoch(&o).await, 3, "and only then the owner's group");
        assert!(pending(&o).await.is_none());
        let group = live_group(&o).await;
        assert_eq!(group.member_count(), 2, "nobody joined or left");
        assert!(group.leaf_of(&o.member).is_some());
        assert!(group.leaf_of(&m_did).is_some());
        let mint = o.host.state.lock().unwrap().last_mint.clone().unwrap();
        assert!(
            mint.get("link").is_some(),
            "the advance carries its link: {mint}"
        );
        assert!(mint.get("commit").is_some(), "and its commit: {mint}");
        assert_eq!(mint["reason"], "quarterly renewal");

        // The remaining member's key holder applies the commit the host relays.
        let commit = commit_of_last_mint(&o);
        room_groups::apply_commit(&m_state.room_groups_ks, &member, &commit, 2, 0)
            .await
            .expect("the remaining member follows the renewal");

        let after =
            room_groups::seal_record(&o.state.room_groups_ks, &om(&o), "notes/2", 1, b"after")
                .await
                .unwrap();
        assert_eq!(after.epoch, 3);
        let open = |rec: &vti_rooms::wire::SealedContent, key: &'static str| {
            let ks = m_state.room_groups_ks.clone();
            let member = member.clone();
            let rec = rec.clone();
            async move {
                room_groups::open_record(
                    &ks,
                    &member,
                    key,
                    1,
                    &rec.ciphertext,
                    &rec.nonce,
                    rec.epoch,
                )
                .await
            }
        };
        assert_eq!(open(&after, "notes/2").await.unwrap(), b"after");
        assert_eq!(
            open(&before, "notes/1").await.unwrap(),
            b"before",
            "an earlier epoch still opens through the link"
        );
        // And the member's writes reach the owner at the new epoch.
        let from_member =
            room_groups::seal_record(&m_state.room_groups_ks, &member, "notes/3", 1, b"reply")
                .await
                .unwrap();
        assert_eq!(from_member.epoch, 3);
        let opened = room_groups::open_record(
            &o.state.room_groups_ks,
            &om(&o),
            "notes/3",
            1,
            &from_member.ciphertext,
            &from_member.nonce,
            from_member.epoch,
        )
        .await
        .unwrap();
        assert_eq!(opened, b"reply");
    }

    /// Item 5: a refusal is the host's answer — `hostRefused`, the pending renewal is
    /// discarded and the group does not move.
    #[tokio::test]
    async fn a_refused_renewal_leaves_the_group_unchanged() {
        let o = owner().await;
        create(&o, &o.room_key).await;
        let before = live_group(&o).await.epoch_authenticator();
        o.host.state.lock().unwrap().mode = Mode::Refuse;

        let out = renew(&o).await;
        assert_eq!(
            out["payload"]["code"], "rooms/owner/group/renew:hostRefused",
            "{out}"
        );
        assert_eq!(
            out["payload"]["details"]["code"], "permissionDenied",
            "{out}"
        );
        assert_eq!(live_epoch(&o).await, 1);
        assert_eq!(
            live_group(&o).await.epoch_authenticator(),
            before,
            "the very same group state"
        );
        assert!(
            pending(&o).await.is_none(),
            "a refused renewal leaves nothing pending"
        );
    }

    /// Another admin advanced the room: `epochConflict` carrying `hostEpoch`, and nothing
    /// changes here.
    #[tokio::test]
    async fn a_renewal_in_a_room_advanced_elsewhere_is_an_epoch_conflict() {
        let o = owner().await;
        create(&o, &o.room_key).await;
        o.host.state.lock().unwrap().epoch = 6;

        let out = renew(&o).await;
        assert_eq!(
            out["payload"]["code"], "rooms/owner/group/renew:epochConflict",
            "{out}"
        );
        assert_eq!(out["payload"]["details"]["hostEpoch"], 6, "{out}");
        assert_eq!(live_epoch(&o).await, 1);
        assert!(pending(&o).await.is_none());
    }

    /// Items 3, 5 and 6: the host takes the renewal and the answer is lost —
    /// `hostUnreachable`, the pending renewal is KEPT, and the next renewal finds the host
    /// at its epoch, applies it, and renews again from there.
    #[tokio::test]
    async fn a_renewal_whose_answer_was_lost_is_kept_and_settled() {
        let o = owner().await;
        create(&o, &o.room_key).await;
        o.host.state.lock().unwrap().mode = Mode::AcceptThenLose;

        let out = renew(&o).await;
        assert_eq!(
            out["payload"]["code"], "rooms/owner/group/renew:hostUnreachable",
            "{out}"
        );
        assert_eq!(
            o.host.state.lock().unwrap().epoch,
            2,
            "the host did advance"
        );
        assert_eq!(live_epoch(&o).await, 1, "this agent does not know that yet");
        let kept = pending(&o)
            .await
            .expect("an unknown outcome keeps the pending renewal");
        assert_eq!(kept.kind, room_groups::AdvanceKind::Renewal);
        assert_eq!(kept.epoch, 2);
        assert_eq!(kept.member, o.member, "the committer, not anybody changed");
        assert!(kept.welcome.is_none());

        o.host.state.lock().unwrap().mode = Mode::Accept;
        let out = renew(&o).await;
        assert_eq!(out["payload"]["epoch"], 3, "{out}");
        assert_eq!(live_epoch(&o).await, 3);
        assert!(pending(&o).await.is_none());
    }

    /// Item 6: a pending renewal the host never took is discarded, and the request carries
    /// on from the live group.
    #[tokio::test]
    async fn a_pending_renewal_the_host_never_took_is_discarded() {
        let o = owner().await;
        create(&o, &o.room_key).await;
        // As if the process died between storing the pending renewal and sending it.
        room_groups::prepare_renew(&o.state.room_groups_ks, &om(&o), &o.host.did, 0)
            .await
            .unwrap()
            .unwrap();

        let out = renew(&o).await;
        assert_eq!(out["payload"]["epoch"], 2, "{out}");
        assert_eq!(live_epoch(&o).await, 2);
        assert!(pending(&o).await.is_none());
    }

    /// Item 3: one pending advance per room across admission, removal and renewal. A lost
    /// admission is settled by a renewal, a lost renewal by a removal and by an admission,
    /// and a second advance cannot be retained over a pending renewal.
    #[tokio::test]
    async fn one_pending_advance_per_room_across_add_remove_and_renew() {
        let o = owner().await;
        create(&o, &o.room_key).await;

        // A lost admission, settled by a renewal.
        o.host.state.lock().unwrap().mode = Mode::AcceptThenLose;
        let (_s, _d, did, kp) = joiner(&o.room.did).await;
        add(&o, &did, &kp).await; // host at 2
        assert_eq!(
            pending(&o).await.unwrap().kind,
            room_groups::AdvanceKind::Admission
        );
        o.host.state.lock().unwrap().mode = Mode::Accept;
        let out = renew(&o).await;
        assert_eq!(out["payload"]["epoch"], 3, "{out}");
        assert!(
            live_group(&o).await.leaf_of(&did).is_some(),
            "the admission applied first"
        );

        // A lost renewal, settled by a removal.
        o.host.state.lock().unwrap().mode = Mode::AcceptThenLose;
        renew(&o).await; // host at 4
        assert_eq!(
            pending(&o).await.unwrap().kind,
            room_groups::AdvanceKind::Renewal
        );
        o.host.state.lock().unwrap().mode = Mode::Accept;
        let out = remove(&o, &did).await;
        assert_eq!(out["payload"]["epoch"], 5, "{out}");
        assert!(live_group(&o).await.leaf_of(&did).is_none());

        // A lost renewal, settled by an admission.
        o.host.state.lock().unwrap().mode = Mode::AcceptThenLose;
        renew(&o).await; // host at 6
        o.host.state.lock().unwrap().mode = Mode::Accept;
        let (_s2, _d2, did2, kp2) = joiner(&o.room.did).await;
        let out = add(&o, &did2, &kp2).await;
        assert_eq!(out["payload"]["epoch"], 7, "{out}");
        assert_eq!(live_epoch(&o).await, 7);

        // The slot holds one: nothing is retained over a pending renewal.
        room_groups::prepare_renew(&o.state.room_groups_ks, &om(&o), &o.host.did, 0)
            .await
            .unwrap()
            .unwrap();
        let second =
            room_groups::prepare_remove(&o.state.room_groups_ks, &om(&o), &o.host.did, &did2, 0)
                .await;
        assert!(
            matches!(second, Err(PrepareRemoveError::App(AppError::Conflict(_)))),
            "{second:?}"
        );
        let third =
            room_groups::prepare_renew(&o.state.room_groups_ks, &om(&o), &o.host.did, 0).await;
        assert!(matches!(third, Err(AppError::Conflict(_))), "{third:?}");
        assert_eq!(
            pending(&o).await.unwrap().kind,
            room_groups::AdvanceKind::Renewal,
            "the first is untouched"
        );
    }

    /// Per-persona state: another persona on this same VTA, a member of the owner's room,
    /// holds its own group. The owner's renewal advances the owner's group and leaves the
    /// other persona's alone — it follows by applying the commit, like any member.
    #[tokio::test]
    async fn a_renewal_advances_only_the_owner_personas_group() {
        let o = owner().await;
        create(&o, &o.room_key).await;
        // A second persona on the owner's own VTA, admitted to the room.
        let other_did = Party::new().did;
        let other = Member::new(&o.room.did, &other_did).unwrap();
        let kp = room_groups::mint_key_package(&o.state.room_groups_ks, &other, 3600, 0)
            .await
            .unwrap()
            .key_package;
        let out = add(&o, &other_did, &kp).await;
        let welcome = {
            use base64::Engine as _;
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(out["payload"]["welcome"].as_str().expect("{out}"))
                .unwrap()
        };
        room_groups::join(&o.state.room_groups_ks, &other, &welcome, 0)
            .await
            .unwrap();
        let other_epoch = |state: &AppState| {
            let ks = state.room_groups_ks.clone();
            let other = other.clone();
            let room = o.room.did.clone();
            async move {
                let r = room_groups::load(&ks, &other).await.unwrap().unwrap();
                vti_rooms::sealed::SealedRoom::new(
                    room,
                    vti_rooms::mls::RoomGroup::restore(&r.snapshot).unwrap(),
                )
                .room_epoch()
            }
        };
        assert_eq!(other_epoch(&o.state).await, 2);

        let out = renew(&o).await;
        assert_eq!(out["payload"]["epoch"], 3, "{out}");
        assert_eq!(live_epoch(&o).await, 3);
        assert_eq!(
            other_epoch(&o.state).await,
            2,
            "the other persona's group is its own"
        );
        assert!(
            room_groups::pending_advance(&o.state.room_groups_ks, &other)
                .await
                .unwrap()
                .is_none()
        );
        room_groups::apply_commit(
            &o.state.room_groups_ks,
            &other,
            &commit_of_last_mint(&o),
            2,
            0,
        )
        .await
        .expect("and follows the renewal like any member");
        assert_eq!(other_epoch(&o.state).await, 3);
    }

    // ─── rooms/owner/group/remove/0.2 (trust-tasks-tf #804) ──────────────────────────

    /// Items 4–7: the member is withdrawn at the host first — one `subject` entry, signed as
    /// the room and kept — and only then does the room advance; the answer carries the
    /// list's head and the withdrawal's time.
    #[tokio::test]
    async fn remove_0_2_withdraws_at_the_host_first_then_advances() {
        let o = owner().await;
        create(&o, &o.room_key).await;
        let (_s, _d, did) = admitted(&o).await;
        o.host.state.lock().unwrap().log.clear();

        let out = remove_v0_2(&o, &did, &[]).await;
        assert_eq!(out["payload"]["epoch"], 3, "{out}");
        assert_eq!(out["payload"]["revocation"]["sequence"], 1, "{out}");
        assert!(out["payload"]["revokedAt"].is_string(), "{out}");

        let log = host_log(&o);
        let put = log
            .iter()
            .position(|t| t == vti_rooms::wire::ROOMS_REVOCATIONS_PUT_TYPE)
            .expect("the withdrawal was delivered");
        let mint = log
            .iter()
            .position(|t| t == vti_rooms::wire::ROOMS_EPOCH_MINT_TYPE)
            .expect("the room advanced");
        assert!(put < mint, "withdraw first, then advance: {log:?}");

        let held = held_list(&o).await.expect("the list is kept");
        assert_eq!(held.sequence(), 1);
        assert!(matches!(
            &held.entries()[0],
            vti_rooms::revocation::Entry::Subject { subject, .. } if *subject == did
        ));
        assert_eq!(
            o.host.state.lock().unwrap().lists.last(),
            Some(held.raw()),
            "the host was given exactly the list kept here"
        );
        assert!(pending(&o).await.is_none());
        assert!(live_group(&o).await.leaf_of(&did).is_none());
    }

    /// Item 6: a host that refuses the list refuses the removal — nothing advanced, the
    /// whole pending removal discarded, the list included.
    #[tokio::test]
    async fn remove_0_2_a_refused_withdrawal_changes_nothing() {
        let o = owner().await;
        create(&o, &o.room_key).await;
        let (_s, _d, did) = admitted(&o).await;
        o.host.state.lock().unwrap().list_mode = Mode::Refuse;
        o.host.state.lock().unwrap().log.clear();

        let out = remove_v0_2(&o, &did, &[]).await;
        assert_eq!(
            out["payload"]["code"], "rooms/owner/group/remove:hostRefused",
            "{out}"
        );
        assert_eq!(out["payload"]["details"]["stage"], "revocation", "{out}");
        assert!(held_list(&o).await.is_none(), "no host took the list");
        assert!(pending(&o).await.is_none());
        assert!(live_group(&o).await.leaf_of(&did).is_some());
        assert!(
            !host_log(&o)
                .iter()
                .any(|t| t == vti_rooms::wire::ROOMS_EPOCH_MINT_TYPE),
            "nothing advances until the host accepts the withdrawal"
        );
    }

    /// Items 6 and 8: an unanswered withdrawal keeps the pending removal; the next request
    /// delivers the list again first (a repeat is accepted), and the advance that was never
    /// sent is discarded — the member stays withdrawn, and a repeated removal advances.
    #[tokio::test]
    async fn remove_0_2_an_unanswered_withdrawal_is_delivered_again_by_the_next_request() {
        let o = owner().await;
        create(&o, &o.room_key).await;
        let (_s, _d, did) = admitted(&o).await;
        o.host.state.lock().unwrap().list_mode = Mode::AcceptThenLose;

        let out = remove_v0_2(&o, &did, &[]).await;
        assert_eq!(
            out["payload"]["code"], "rooms/owner/group/remove:hostUnreachable",
            "{out}"
        );
        assert_eq!(out["payload"]["details"]["stage"], "revocation", "{out}");
        let p = pending(&o).await.expect("kept");
        assert!(!p.revocation.as_ref().unwrap().confirmed);

        o.host.state.lock().unwrap().list_mode = Mode::Accept;
        let out = remove_v0_2(&o, &did, &[]).await;
        assert_eq!(out["payload"]["epoch"], 3, "{out}");
        assert_eq!(
            out["payload"]["revocation"]["sequence"], 2,
            "the first list stayed the room's, and the repeat built on it: {out}"
        );
        assert_eq!(held_list(&o).await.unwrap().entries().len(), 2);
        assert!(live_group(&o).await.leaf_of(&did).is_none());
    }

    /// Item 7: an advance the host refuses discards the advance, never the withdrawal,
    /// which is in force at the host and is the room's.
    #[tokio::test]
    async fn remove_0_2_a_refused_advance_keeps_the_withdrawal() {
        let o = owner().await;
        create(&o, &o.room_key).await;
        let (_s, _d, did) = admitted(&o).await;
        o.host.state.lock().unwrap().mode = Mode::Refuse;

        let out = remove_v0_2(&o, &did, &[]).await;
        assert_eq!(
            out["payload"]["code"], "rooms/owner/group/remove:hostRefused",
            "{out}"
        );
        assert_eq!(out["payload"]["details"]["stage"], "advance", "{out}");
        assert_eq!(held_list(&o).await.unwrap().sequence(), 1);
        assert!(pending(&o).await.is_none());
        assert!(live_group(&o).await.leaf_of(&did).is_some());
    }

    /// Item 2: a private room is refused, changing nothing.
    #[tokio::test]
    async fn remove_0_2_refuses_a_private_room() {
        let o = owner().await;
        create(&o, &o.room_key).await;
        let (_s, _d, did) = admitted(&o).await;
        o.host.state.lock().unwrap().visibility = "private";

        let out = remove_v0_2(&o, &did, &[]).await;
        assert_eq!(
            out["payload"]["code"], "rooms/owner/group/remove:privateRoom",
            "{out}"
        );
        assert!(held_list(&o).await.is_none());
        assert!(pending(&o).await.is_none());
        assert!(live_group(&o).await.leaf_of(&did).is_some());
    }

    /// Item 9: a mirror that does not confirm is named in `mirrorsPending`, not waited for.
    #[tokio::test]
    async fn remove_0_2_names_a_mirror_that_did_not_confirm() {
        let o = owner().await;
        create(&o, &o.room_key).await;
        let (_s, _d, did) = admitted(&o).await;
        let mirror = Party::new().did;
        let out = remove_v0_2(&o, &did, &[&mirror]).await;
        assert_eq!(
            out["payload"]["mirrorsPending"],
            serde_json::json!([mirror]),
            "{out}"
        );
        assert_eq!(out["payload"]["epoch"], 3);
    }

    // ─── rooms/owner/revoke/0.1 (trust-tasks-tf #804) ────────────────────────────────

    /// Items 3–6: the next list is signed, kept and delivered; an empty `withdraw`
    /// re-delivers it without signing anything new.
    #[tokio::test]
    async fn revoke_signs_keeps_and_delivers_and_an_empty_withdraw_redelivers() {
        let o = owner().await;
        let gone = Party::new().did;
        let out = revoke(
            &o,
            serde_json::json!([{ "kind": "subject", "subject": gone }]),
        )
        .await;
        let p = &out["payload"];
        assert_eq!(p["head"]["sequence"], 1, "{out}");
        assert_eq!(p["deliveries"][0]["outcome"], "accepted", "{out}");
        assert_eq!(p["deliveries"][0]["head"], p["head"]);
        let held = held_list(&o).await.expect("kept");
        assert_eq!(&p["list"], held.raw());

        let again = revoke(&o, serde_json::json!([])).await;
        assert_eq!(
            again["payload"]["head"], p["head"],
            "nothing new signed: {again}"
        );
        assert_eq!(o.host.state.lock().unwrap().lists.len(), 2);
    }

    /// Item 1: `noList`, `roomSubject`; item 2: `entryNotPermitted` on a private room.
    #[tokio::test]
    async fn revoke_refuses_before_signing_anything() {
        let o = owner().await;
        let out = revoke(&o, serde_json::json!([])).await;
        assert_eq!(out["payload"]["code"], "rooms/owner/revoke:noList", "{out}");
        let out = revoke(
            &o,
            serde_json::json!([{ "kind": "subject", "subject": o.room.did }]),
        )
        .await;
        assert_eq!(
            out["payload"]["code"], "rooms/owner/revoke:roomSubject",
            "{out}"
        );
        o.host.state.lock().unwrap().visibility = "private";
        let out = revoke(
            &o,
            serde_json::json!([{ "kind": "credential", "credentialId": "urn:uuid:x" }]),
        )
        .await;
        assert_eq!(
            out["payload"]["code"], "rooms/owner/revoke:entryNotPermitted",
            "{out}"
        );
        assert!(held_list(&o).await.is_none());
        // A reset is the one withdrawal a private room takes.
        let out = revoke(&o, serde_json::json!([{ "kind": "room" }])).await;
        assert_eq!(out["payload"]["head"]["sequence"], 1, "{out}");
    }

    /// Item 6: a host that refuses is reported `refused` with its code; the list is kept
    /// and the request succeeds.
    #[tokio::test]
    async fn revoke_reports_a_refusing_host_and_still_keeps_the_list() {
        let o = owner().await;
        o.host.state.lock().unwrap().list_mode = Mode::Refuse;
        let out = revoke(&o, serde_json::json!([{ "kind": "room" }])).await;
        assert_eq!(
            out["payload"]["deliveries"][0]["outcome"], "refused",
            "{out}"
        );
        assert_eq!(
            out["payload"]["deliveries"][0]["code"],
            "rooms/revocations/put:listInvalid"
        );
        assert!(held_list(&o).await.is_some());
    }

    /// Item 4: a key holder that lost its list (restored from an old backup) recovers the
    /// host's, signed by the room, and the next list keeps its entries.
    #[tokio::test]
    async fn revoke_recovers_a_lost_list_from_a_host() {
        let o = owner().await;
        let first = Party::new().did;
        revoke(
            &o,
            serde_json::json!([{ "kind": "subject", "subject": first }]),
        )
        .await;
        // Restored from before the list existed.
        o.state
            .room_groups_ks
            .remove(format!("room-revocations/{}", o.room.did))
            .await
            .unwrap();

        let second = Party::new().did;
        let out = revoke(
            &o,
            serde_json::json!([{ "kind": "subject", "subject": second }]),
        )
        .await;
        assert_eq!(out["payload"]["head"]["sequence"], 2, "{out}");
        assert_eq!(
            out["payload"]["list"]["entries"].as_array().unwrap().len(),
            2
        );
    }

    /// `rooms/owner/revoke`: registering a room with a host delivers the list held for it
    /// there before answering — a room moving hosts arrives with its withdrawals.
    #[tokio::test]
    async fn registering_a_room_delivers_its_list_before_answering() {
        let o = owner().await;
        revoke(&o, serde_json::json!([{ "kind": "room" }])).await;
        o.host.state.lock().unwrap().log.clear();

        let out = body(
            super::super::room_owner::handle_register(
                &o.state,
                &crate::test_support::super_admin_claims(),
                request(
                    vta_sdk::trust_tasks::TASK_ROOMS_OWNER_REGISTER_0_1,
                    serde_json::json!({
                        "roomId": o.room.did, "host": o.host.did,
                        "visibility": "attributed", "ownerDid": o.member,
                    }),
                ),
            )
            .await,
        );
        assert_eq!(out["payload"]["epoch"], 1, "{out}");
        assert_eq!(
            host_log(&o),
            vec![
                vti_rooms::wire::ROOMS_CREATE_TYPE.to_string(),
                vti_rooms::wire::ROOMS_REVOCATIONS_PUT_TYPE.to_string(),
            ]
        );
    }

    /// `rooms/owner/group/remove/0.2` item 1: a key the caller may not name is
    /// `noSigningKey`, before anything is built or sent.
    #[tokio::test]
    async fn remove_0_2_refuses_a_key_the_caller_cannot_name() {
        let o = owner().await;
        create(&o, &o.room_key).await;
        let (_s, _d, did) = admitted(&o).await;
        o.host.state.lock().unwrap().log.clear();
        let out = body(
            handle_remove_v0_2(
                &o.state,
                &crate::test_support::super_admin_claims(),
                request(
                    vta_sdk::trust_tasks::TASK_ROOMS_OWNER_GROUP_REMOVE_0_2,
                    serde_json::json!({
                        "roomId": o.room.did, "host": o.host.did, "member": did,
                        "signingKeyId": "no-such-key",
                    }),
                ),
            )
            .await,
        );
        assert_eq!(
            out["payload"]["code"], "rooms/owner/group/remove:noSigningKey",
            "{out}"
        );
        assert!(host_log(&o).is_empty(), "nothing reaches the host");
        assert!(pending(&o).await.is_none());
        assert!(held_list(&o).await.is_none());
    }

    /// `rooms/owner/revoke/0.1` item 1: an unknown key is `noSigningKey`.
    #[tokio::test]
    async fn revoke_refuses_a_key_the_caller_cannot_name() {
        let o = owner().await;
        let out = revoke_with(
            &o,
            &o.room.did,
            "no-such-key",
            serde_json::json!([o.host.did]),
            serde_json::json!([{ "kind": "room" }]),
        )
        .await;
        assert_eq!(
            out["payload"]["code"], "rooms/owner/revoke:noSigningKey",
            "{out}"
        );
        assert!(held_list(&o).await.is_none());
    }

    /// `rooms/owner/revoke/0.1` item 1: a room this agent holds no `admin` grant of, for a
    /// persona the caller acts as, is `noAuthority` — before anything is signed.
    #[tokio::test]
    async fn revoke_without_admin_authority_is_no_authority() {
        let o = owner().await;
        let elsewhere = Party::new().did;
        let out = revoke_with(
            &o,
            &elsewhere,
            &o.room_key,
            serde_json::json!([o.host.did]),
            serde_json::json!([{ "kind": "room" }]),
        )
        .await;
        assert_eq!(
            out["payload"]["code"], "rooms/owner/revoke:noAuthority",
            "{out}"
        );
        assert!(
            crate::operations::room_revocation::held(&o.state.room_groups_ks, &elsewhere)
                .await
                .unwrap()
                .is_none()
        );
    }

    /// `rooms/owner/revoke/0.1` item 2: a withdrawal naming a party needs the tier, and a
    /// first host that cannot be reached leaves it unknown — `tierUnknown`, nothing signed.
    #[tokio::test]
    async fn revoke_naming_a_party_without_a_reachable_host_is_tier_unknown() {
        let o = owner().await;
        let unreachable = Party::new().did;
        let out = revoke_with(
            &o,
            &o.room.did,
            &o.room_key,
            serde_json::json!([unreachable]),
            serde_json::json!([{ "kind": "subject", "subject": Party::new().did }]),
        )
        .await;
        assert_eq!(
            out["payload"]["code"], "rooms/owner/revoke:tierUnknown",
            "{out}"
        );
        assert!(held_list(&o).await.is_none(), "nothing was signed");
    }
}
