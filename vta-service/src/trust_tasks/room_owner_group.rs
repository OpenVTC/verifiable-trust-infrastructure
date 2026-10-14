//! The owner's half of a sealed room's MLS group — `rooms/owner/group/create/0.1`,
//! `rooms/owner/group/add/0.1` and `rooms/owner/group/remove/0.1`.
//!
//! Every member reaches a room's group by a Welcome (`rooms/keys/welcome`), except the
//! owner, whom nobody can welcome: `create` founds the group with the owner as its only
//! leaf. `add` admits a member — it builds the commit and the Welcome, advances the room's
//! epoch at its host, and returns the Welcome for the caller to deliver. `remove` is its
//! mirror: it drops a member's leaf and advances the room, so nothing sealed from then on
//! is readable to them. It recalls nothing they already read, and on a `chained` room they
//! keep the epochs they were in.
//!
//! # Remote first (items 2–6 of `add` and `remove`)
//!
//! The host is advanced **before** this agent's own group, never after. The change is
//! built on a copy and kept durably as the room's one pending advance
//! ([`room_groups::PendingAdvance`], an admission or a removal) while the live group stays
//! where it is; `rooms/epoch/mint` goes to the host; only an accepted advance replaces the
//! live group. A refusal discards the pending advance. An unknown outcome — a host that
//! could not be reached, or an answer that could not be read — keeps it: the host may have
//! accepted, and a key holder cannot process its own commit from the wire, so the pending
//! group is the only way to follow it there. The next `add` or `remove` for the room asks
//! the host which epoch it is at and settles the pending advance first, whichever kind it
//! is: a room holds at most one.

use serde_json::Value;
use trust_tasks_rs::specs::rooms::owner::group::{
    add as spec_add, create as spec_create, remove as spec_remove,
};
use trust_tasks_rs::{DeclaredErrorCode, TrustTask};
use vti_common::acl::Capability;
use vti_common::error::AppError;

use crate::auth::AuthClaims;
use crate::operations::room_groups::{
    self, CreateGroupError, PendingAdvance, PrepareAddError, PrepareRemoveError, Reconciled,
};
use crate::operations::room_host::{RoomTaskError, send_room_task_typed};
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
    match room_groups::create_group(&state.room_groups_ks, room_id, &member, now()).await {
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

/// `rooms/owner/group/add/0.1` — admit a member, advancing the room at its host first.
pub(super) async fn handle_add(
    state: &AppState,
    auth: &AuthClaims,
    doc: TrustTask<Value>,
) -> TrustTaskOutcome {
    use spec_add::v0_1::error_codes as codes;
    const ADVANCE: AdvanceCodes = AdvanceCodes {
        no_authority: codes::NO_AUTHORITY,
        epoch_conflict: codes::EPOCH_CONFLICT,
        host_unreachable: codes::HOST_UNREACHABLE,
        host_refused: codes::HOST_REFUSED,
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
    let req: spec_add::v0_1::Payload = match parse_payload(&doc) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    let room_id = req.room_id.as_str().to_string();
    let host = req.host.as_str().to_string();
    let member = req.member.as_str().to_string();

    if let Err(r) = require_group(state, &doc, &room_id, codes::NO_GROUP).await {
        return r;
    }

    let (_, resolver) = match outbound_identity(state, &doc).await {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    let host_call = match HostCall::as_owner(state, auth, &resolver, &room_id, &doc, &ADVANCE).await
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
    let presentation = match host_call.admin_presentation(&doc, &ADVANCE).await {
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

    // Items 2 and 3: built on a copy and retained durably before the host is contacted.
    let pending = match room_groups::prepare_add(
        &state.room_groups_ks,
        &room_id,
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
                format!("`{member}` already has a leaf in room `{room_id}`'s group"),
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
    if let Err(r) = require_group(state, &doc, &room_id, codes::NO_GROUP).await {
        return r;
    }
    match room_groups::is_own_leaf(&state.room_groups_ks, &room_id, &member).await {
        Ok(true) => return own_leaf(&doc, &room_id, &member),
        Ok(false) => {}
        Err(e) => return app_error_to_reject(&doc, e),
    }

    let (_, resolver) = match outbound_identity(state, &doc).await {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    let host_call = match HostCall::as_owner(state, auth, &resolver, &room_id, &doc, &ADVANCE).await
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
    let presentation = match host_call.admin_presentation(&doc, &ADVANCE).await {
        Ok(p) => p,
        Err(r) => return r,
    };

    // Items 1 to 3: refused, or built on a copy and retained durably before the host is
    // contacted.
    let pending =
        match room_groups::prepare_remove(&state.room_groups_ks, &room_id, &host, &member, now())
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

/// `noGroup` unless this agent holds the room's group.
async fn require_group(
    state: &AppState,
    doc: &TrustTask<Value>,
    room_id: &str,
    no_group: DeclaredErrorCode,
) -> Result<(), TrustTaskOutcome> {
    match room_groups::load(&state.room_groups_ks, room_id).await {
        Ok(Some(_)) => Ok(()),
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
/// it. `add` and `remove` declare the same four, each under its own slug.
struct AdvanceCodes {
    no_authority: DeclaredErrorCode,
    epoch_conflict: DeclaredErrorCode,
    host_unreachable: DeclaredErrorCode,
    host_refused: DeclaredErrorCode,
}

/// `noAuthority`: the caller acts as no persona holding the room's `admin` authority.
fn no_authority(
    doc: &TrustTask<Value>,
    codes: &AdvanceCodes,
    room_id: &str,
    e: AppError,
) -> TrustTaskOutcome {
    reject_with_code(
        doc,
        declared(codes.no_authority),
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

/// What `add` and `remove` need to speak to a host **as the owner's persona**.
///
/// `rooms/owner/group/{add,remove}` have the key holder speak "to the host as its
/// principal", presenting the owner's `admin` authority; `rooms/epoch/mint`'s producer is
/// the owner (or a holder of `admin`). So every request is signed as the persona the room's
/// credentials name — the same identity `rooms/owner/register` registered — and never as
/// this agent, whose DID is shared by every principal it serves and would attribute the
/// advance to none of them.
struct HostCall<'a> {
    state: &'a AppState,
    auth: &'a AuthClaims,
    owner: crate::operations::room_oracle::Principal,
    resolver: &'a affinidi_did_resolver_cache_sdk::DIDCacheClient,
    room_id: &'a str,
}

impl<'a> HostCall<'a> {
    /// Resolve the owner persona the caller acts as in `room_id`, or `noAuthority` — before
    /// anything is settled or built, so a caller without it leaves nothing behind.
    async fn as_owner(
        state: &'a AppState,
        auth: &'a AuthClaims,
        resolver: &'a affinidi_did_resolver_cache_sdk::DIDCacheClient,
        room_id: &'a str,
        doc: &TrustTask<Value>,
        codes: &AdvanceCodes,
    ) -> Result<Self, TrustTaskOutcome> {
        let owner = match crate::operations::room_oracle::principal(state, auth, room_id).await {
            Ok(p) => p,
            Err(e @ (AppError::NotFound(_) | AppError::Forbidden(_) | AppError::Validation(_))) => {
                return Err(no_authority(doc, codes, room_id, e));
            }
            Err(e) => return Err(app_error_to_reject(doc, e)),
        };
        Ok(Self {
            state,
            auth,
            owner,
            resolver,
            room_id,
        })
    }

    async fn send(&self, host: &str, task: &str, payload: Value) -> Result<Value, RoomTaskError> {
        send_room_task_typed(
            signing_context(self.state, self.auth),
            &self.state.room_groups_ks,
            self.room_id,
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
    async fn settle_pending(
        &self,
        doc: &TrustTask<Value>,
        codes: &AdvanceCodes,
    ) -> Result<(), TrustTaskOutcome> {
        let room_id = self.room_id;
        let pending = match room_groups::pending_advance(&self.state.room_groups_ks, room_id).await
        {
            Ok(Some(p)) => p,
            Ok(None) => return Ok(()),
            Err(e) => return Err(app_error_to_reject(doc, e)),
        };
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
            room_id,
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
    async fn admin_presentation(
        &self,
        doc: &TrustTask<Value>,
        codes: &AdvanceCodes,
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
                Err(no_authority(doc, codes, room_id, e))
            }
            Err(e) => Err(app_error_to_reject(doc, e)),
        }
    }

    /// Items 4 and 5: advance the room at `host` with `rooms/epoch/mint`, then follow the
    /// host's answer — promote the pending advance on acceptance, discard it on refusal,
    /// keep it on an unknown outcome.
    async fn advance(
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
                if let Err(e) = room_groups::discard_pending_advance(groups, room_id).await {
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
                    Some(serde_json::json!({ "code": code, "reason": reason })),
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
                         `{host}`: {e}. Whether it took effect is unknown; the next admission or \
                         removal in this room settles it with the host first."
                    ),
                    None,
                ));
            }
        }

        room_groups::promote_pending_advance(groups, room_id, pending, now())
            .await
            // The host advanced and this agent could not record it. The pending row
            // survives, and the next request promotes it (item 6): a delay, not a loss.
            .map_err(|e| app_error_to_reject(doc, e))
    }
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
                        if task == vti_rooms::wire::ROOMS_INFO_TYPE {
                            Ok(serde_json::json!({
                                "roomId": room_id, "visibility": "attributed",
                                "retentionPolicy": "chained", "epoch": h.epoch,
                            }))
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

    /// The group this agent holds for the owner's room.
    async fn live_group(o: &Owner) -> vti_rooms::mls::RoomGroup {
        let r = room_groups::load(&o.state.room_groups_ks, &o.room.did)
            .await
            .unwrap()
            .expect("a group");
        vti_rooms::mls::RoomGroup::restore(&r.snapshot).unwrap()
    }

    async fn pending(o: &Owner) -> Option<room_groups::PendingAdvance> {
        room_groups::pending_advance(&o.state.room_groups_ks, &o.room.did)
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
        room_groups::join(&j_state.room_groups_ks, &o.room.did, &j_did, &welcome, 0)
            .await
            .expect("joins from the Welcome");
        (j_state, j_dir, j_did)
    }

    async fn live_epoch(o: &Owner) -> u32 {
        let r = room_groups::load(&o.state.room_groups_ks, &o.room.did)
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
        let pending = room_groups::mint_key_package(&state.room_groups_ks, room, &did, 3600, 0)
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
            room_groups::load(&o.state.room_groups_ks, &o.room.did)
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
            room_groups::pending_advance(&o.state.room_groups_ks, &o.room.did)
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
        let joined = room_groups::join(&j_state.room_groups_ks, &o.room.did, &j_did, &welcome, 0)
            .await
            .expect("the newcomer's VTA joins from the Welcome");
        assert_eq!(joined + 1, 2, "at the room's new epoch");

        let from_owner = room_groups::seal_record(
            &o.state.room_groups_ks,
            &o.room.did,
            "notes/1",
            1,
            b"from the owner",
        )
        .await
        .unwrap();
        let opened = room_groups::open_record(
            &j_state.room_groups_ks,
            &o.room.did,
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
            &o.room.did,
            "notes/2",
            2,
            b"from the member",
        )
        .await
        .unwrap();
        let opened = room_groups::open_record(
            &o.state.room_groups_ks,
            &o.room.did,
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
            room_groups::pending_advance(&o.state.room_groups_ks, &o.room.did)
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
            room_groups::pending_advance(&o.state.room_groups_ks, &o.room.did)
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
            room_groups::pending_advance(&o.state.room_groups_ks, &o.room.did)
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
        let group = room_groups::load(&o.state.room_groups_ks, &o.room.did)
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
            &o.room.did,
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
        let group = room_groups::load(&o.state.room_groups_ks, &o.room.did)
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
            room_groups::pending_advance(&o.state.room_groups_ks, &o.room.did)
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
        room_groups::apply_commit(&stay_state.room_groups_ks, &o.room.did, &commit_3, 2, 0)
            .await
            .expect("the remaining member follows the admission");

        let before = room_groups::seal_record(
            &o.state.room_groups_ks,
            &o.room.did,
            "notes/1",
            1,
            b"before",
        )
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
        room_groups::apply_commit(&stay_state.room_groups_ks, &o.room.did, &commit_4, 3, 0)
            .await
            .expect("the remaining member follows the removal");
        let after =
            room_groups::seal_record(&o.state.room_groups_ks, &o.room.did, "notes/2", 1, b"after")
                .await
                .unwrap();
        assert_eq!(after.epoch, 4);
        let open = |state: &AppState, rec: &vti_rooms::wire::SealedContent, key: &'static str| {
            let ks = state.room_groups_ks.clone();
            let room = o.room.did.clone();
            let rec = rec.clone();
            async move {
                room_groups::open_record(&ks, &room, key, 1, &rec.ciphertext, &rec.nonce, rec.epoch)
                    .await
            }
        };
        assert_eq!(
            open(&stay_state, &after, "notes/2").await.unwrap(),
            b"after"
        );
        assert!(
            open(&gone_state, &after, "notes/2").await.is_err(),
            "removal is forward: nothing sealed after it opens for the member removed"
        );
        assert_eq!(
            open(&stay_state, &before, "notes/1").await.unwrap(),
            b"before"
        );
        assert_eq!(
            open(&gone_state, &before, "notes/1").await.unwrap(),
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
        room_groups::prepare_remove(&o.state.room_groups_ks, &o.room.did, &o.host.did, &first, 0)
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
        room_groups::prepare_remove(&o.state.room_groups_ks, &o.room.did, &o.host.did, &first, 0)
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
        room_groups::prepare_remove(&o.state.room_groups_ks, &o.room.did, &o.host.did, &did, 0)
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
            &o.room.did,
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

    /// A pending admission an earlier build left at `room-add:<room>` — the row's shape
    /// before removal existed, with no `kind` — is read as an admission and settled, then
    /// cleared, not left to be found again.
    #[tokio::test]
    async fn a_legacy_pending_admission_is_settled_and_cleared() {
        let o = owner().await;
        create(&o, &o.room_key).await;
        o.host.state.lock().unwrap().mode = Mode::AcceptThenLose;
        let (_s, _d, did, kp) = joiner(&o.room.did).await;
        add(&o, &did, &kp).await; // host at 2, answer lost
        // Move the row to where, and as, the admission-only build wrote it.
        let mut legacy = serde_json::to_value(pending(&o).await.unwrap()).unwrap();
        legacy.as_object_mut().unwrap().remove("kind");
        room_groups::discard_pending_advance(&o.state.room_groups_ks, &o.room.did)
            .await
            .unwrap();
        room_groups::store_legacy_pending_add_for_test(
            &o.state.room_groups_ks,
            &o.room.did,
            &legacy,
        )
        .await
        .unwrap();
        let found = pending(&o).await.expect("the legacy row is found");
        assert_eq!(found.kind, room_groups::AdvanceKind::Admission);
        assert!(found.welcome.is_some());

        o.host.state.lock().unwrap().mode = Mode::Accept;
        let out = remove(&o, &did).await;
        assert_eq!(out["payload"]["epoch"], 3, "{out}");
        assert!(pending(&o).await.is_none(), "both slots are clear");
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
        let r = room_groups::load(&o.state.room_groups_ks, &o.room.did)
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
            room_groups::load(&o.state.room_groups_ks, &o.room.did)
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
            room_groups::load(&o.state.room_groups_ks, &o.room.did)
                .await
                .unwrap()
                .is_none()
        );
    }

    /// `rooms/epoch/mint` goes to the host signed as the owner's persona, with the `admin`
    /// leaf granted to that same persona — the presenter the host authenticates — and not
    /// as this agent, whose DID every principal it serves shares. Admission and removal
    /// alike.
    #[tokio::test]
    async fn add_and_remove_speak_to_the_host_as_the_owners_persona() {
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
    }
}
