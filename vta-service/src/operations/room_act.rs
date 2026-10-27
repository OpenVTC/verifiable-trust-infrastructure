//! Completing a host-bound room request **as the member** — `rooms/keys/act/{0.1,…,0.5}`,
//! and the documents `rooms/keys/{read,browse,backfill}` send on the member's behalf. At 0.3
//! also a member's reply to a community's offer of a room ([`OFFER_TYPES`]), at 0.4 the
//! listing that shows each offered room's description too ([`OFFER_TYPES_0_4`]), and at 0.5
//! the community's record of the member's admissions ([`COMMUNITY_TYPES`]).
//!
//! # Why this exists
//!
//! A member of a room is the persona the room admitted ([`crate::operations::persona`]).
//! The member's own client — a `pnm` session, a wallet extension, a phone — holds none of
//! that persona's keys. Until this, the client asked for a presentation with
//! `rooms/keys/present`, which grants the leaf to the **caller**, and signed the request
//! with its own key: the host recorded the client's `did:key` as the actor and, on an
//! `attributed` room, as the author of every record. And the three tasks in which this VTA
//! itself spoke to the host presented to, and signed as, **this VTA's own DID** — an
//! identity no room admitted, and one shared by everyone the VTA serves.
//!
//! Both are the same mistake, and this module is the one place it is not made: the
//! document a host receives names the member as `issuer`, carries the member's own
//! authority narrowed to the one action it needs **and granted to the member**, and is
//! signed by a key of the member's DID for `authentication`. Nothing in it names the
//! client, and nothing names this VTA.
//!
//! # Not a signing oracle
//!
//! [`ACT_TABLE`] is the specification's closed table: only those types are completed, and
//! each is narrowed to the one action the table fixes for it. A caller cannot ask for a
//! presentation wider than its document's type needs, nor have anything but a room request
//! signed as the member. The key is reached only through the gated oracle
//! ([`crate::operations::room_issuance::VtaKeySigner`] → `keys::sign_payload`), which
//! re-checks the key's context, the caller's key scope and the context's signing policy.

use serde_json::Value;
use vti_common::error::AppError;

use crate::auth::AuthClaims;
use crate::operations::persona::{PersonaKey, PersonaStores, Relationship, persona_key_for};
use crate::operations::room_issuance::VtaKeySigner;
use crate::operations::room_oracle::{self, Principal};
use crate::server::AppState;

use trust_tasks_rs::Payload as _;
use trust_tasks_rs::specs::rooms as spec;

/// One row of `rooms/keys/act`'s table: a request type, and the action its inserted
/// presentation is narrowed to — `None` for the types that take no presentation.
pub type ActRow = (&'static str, Option<&'static str>);

/// The table, exactly as `rooms/keys/act/0.1` states it — and 0.2, which leaves it
/// unchanged and adds only that its three room-less types (`rooms/blobs/chunk/0.1`,
/// `rooms/blobs/upload/{commit,abort}/0.2`) name their member in `issuer`. Type URIs come
/// from the generated payload types, never a literal.
///
/// `rooms/epoch/mint/0.1` is in the table, and refused for any room this VTA holds group
/// state for (`sealedRoomMint`, recipient item 9, checked in the handler): a mint carries
/// no group commit, so on a sealed room it would leave the room's epoch ahead of its MLS
/// epoch. A sealed room is renewed with `rooms/owner/group/renew`.
pub const ACT_TABLE: &[ActRow] = &[
    (spec::records::put::v0_1::Payload::TYPE_URI, Some("write")),
    (spec::records::put::v0_2::Payload::TYPE_URI, Some("write")),
    (spec::records::get::v0_1::Payload::TYPE_URI, Some("read")),
    (spec::records::get::v0_2::Payload::TYPE_URI, Some("read")),
    (spec::records::list::v0_1::Payload::TYPE_URI, Some("read")),
    (spec::records::list::v0_2::Payload::TYPE_URI, Some("read")),
    (
        spec::records::curate::v0_1::Payload::TYPE_URI,
        Some("curate"),
    ),
    (spec::info::v0_1::Payload::TYPE_URI, Some("read")),
    (spec::usage::v0_1::Payload::TYPE_URI, Some("admin")),
    (spec::epoch::chain::v0_1::Payload::TYPE_URI, Some("read")),
    (spec::epoch::commits::v0_1::Payload::TYPE_URI, Some("read")),
    (spec::epoch::mint::v0_1::Payload::TYPE_URI, Some("admin")),
    (spec::blobs::get::v0_1::Payload::TYPE_URI, Some("read")),
    (spec::blobs::get::v0_2::Payload::TYPE_URI, Some("read")),
    // A download chunk's authority is the open download the member's `blobs/get` opened.
    (spec::blobs::chunk::v0_1::Payload::TYPE_URI, None),
    (
        spec::blobs::upload::begin::v0_2::Payload::TYPE_URI,
        Some("write"),
    ),
    // Their authority is the open upload the member's begin opened. Signed as the member
    // only for a direct-mode upload; a host refuses the member's on a proxied one.
    (spec::blobs::upload::commit::v0_2::Payload::TYPE_URI, None),
    (spec::blobs::upload::abort::v0_2::Payload::TYPE_URI, None),
];

/// The two offer types `rooms/keys/act/0.3` adds to the table: a member's reply to a
/// community's offer of a room, addressed to the community rather than to a room's host,
/// by a party the room has not yet admitted. Neither takes a presentation — there is no
/// room credential to insert — and the member is the document's `issuer`, required
/// (producer item 2) and resolved by recipient item 2b. Not in [`ACT_TABLE`]: 0.1 and 0.2
/// do not complete them, and nothing else of the `vtc` family is actable at any version.
///
/// 0.3's table is closed at exactly these two: a 0.3 request wrapping
/// `vtc/rooms/offers/list/0.2` is `typeNotActable` (0.3 recipient item 1). 0.4 admits that
/// one too ([`OFFER_TYPES_0_4`]).
pub const OFFER_TYPES: &[&str] = &[OFFERS_LIST_0_1, OFFERS_ACCEPT_0_1];

/// The offer types `rooms/keys/act/0.4` completes: 0.3's, and `vtc/rooms/offers/list/0.2`
/// in the same row as `0.1` and on the same terms — no presentation, `issuer` required and
/// resolved without a room credential (0.4 *What changed from 0.3*). 0.2 changes only what
/// the community answers (each room's description); its request is the same empty payload.
pub const OFFER_TYPES_0_4: &[&str] = &[OFFERS_LIST_0_1, OFFERS_LIST_0_2, OFFERS_ACCEPT_0_1];

const OFFERS_LIST_0_1: &str =
    <trust_tasks_rs::specs::vtc::rooms::offers::list::v0_1::Payload as trust_tasks_rs::Payload>::TYPE_URI;
const OFFERS_LIST_0_2: &str =
    <trust_tasks_rs::specs::vtc::rooms::offers::list::v0_2::Payload as trust_tasks_rs::Payload>::TYPE_URI;
const OFFERS_ACCEPT_0_1: &str =
    <trust_tasks_rs::specs::vtc::rooms::offers::accept::v0_1::Payload as trust_tasks_rs::Payload>::TYPE_URI;

/// Whether `type_uri` is one of [`OFFER_TYPES`] — an offer type `rooms/keys/act/0.3`
/// completes.
pub fn is_offer_type(type_uri: &str) -> bool {
    OFFER_TYPES.contains(&bare_type(type_uri))
}

/// Whether `type_uri` is one of [`OFFER_TYPES_0_4`] — an offer type `rooms/keys/act/0.4`
/// completes.
pub fn is_offer_type_0_4(type_uri: &str) -> bool {
    OFFER_TYPES_0_4.contains(&bare_type(type_uri))
}

/// The community types `rooms/keys/act/0.5` completes: 0.4's [`OFFER_TYPES_0_4`], and
/// `vtc/rooms/memberships/list/0.1` — the community's record of the member's admissions,
/// which every surface reads. All are made to the community as the DID it addresses its
/// offers to, with no presentation, and resolved by recipient item 2b.
pub const COMMUNITY_TYPES: &[&str] = &[
    OFFERS_LIST_0_1,
    OFFERS_LIST_0_2,
    OFFERS_ACCEPT_0_1,
    MEMBERSHIPS_LIST_0_1,
];

const MEMBERSHIPS_LIST_0_1: &str =
    <trust_tasks_rs::specs::vtc::rooms::memberships::list::v0_1::Payload as trust_tasks_rs::Payload>::TYPE_URI;

/// Whether `type_uri` is one of [`COMMUNITY_TYPES`].
pub fn is_community_type(type_uri: &str) -> bool {
    COMMUNITY_TYPES.contains(&bare_type(type_uri))
}

/// The community types `rooms/keys/act/0.6` completes: 0.5's [`COMMUNITY_TYPES`], and
/// `vtc/rooms/offers/list/0.3` in the offer types' row and on their terms (0.6 *What
/// changed from 0.5*). 0.3 also returns the renewals of the admissions a member holds;
/// its request is the same empty payload.
pub const COMMUNITY_TYPES_0_6: &[&str] = &[
    OFFERS_LIST_0_1,
    OFFERS_LIST_0_2,
    OFFERS_LIST_0_3,
    OFFERS_ACCEPT_0_1,
    MEMBERSHIPS_LIST_0_1,
];

const OFFERS_LIST_0_3: &str =
    <trust_tasks_rs::specs::vtc::rooms::offers::list::v0_3::Payload as trust_tasks_rs::Payload>::TYPE_URI;

/// Whether `type_uri` is one of [`COMMUNITY_TYPES_0_6`].
pub fn is_community_type_0_6(type_uri: &str) -> bool {
    COMMUNITY_TYPES_0_6.contains(&bare_type(type_uri))
}

/// Whether `type_uri` is `vtc/rooms/offers/accept/0.1` — the one offer type that can carry
/// key material, and so the one `rooms/keys/act/0.3` recipient item 10 checks.
pub fn is_offer_accept(type_uri: &str) -> bool {
    bare_type(type_uri) == OFFERS_ACCEPT_0_1
}

/// The bare type URI a document names — `#request` is the same type.
pub fn bare_type(type_uri: &str) -> &str {
    type_uri.strip_suffix("#request").unwrap_or(type_uri)
}

/// The table's row for `type_uri`: `Some(action)` where the type is actable (`action` is
/// `None` for one that takes no presentation), `None` where it is not.
pub fn actable(type_uri: &str) -> Option<Option<&'static str>> {
    let bare = bare_type(type_uri);
    ACT_TABLE
        .iter()
        .find(|(t, _)| *t == bare)
        .map(|(_, action)| *action)
}

/// The key this VTA signs a room request with as `did`, for `authentication`.
///
/// The persona rule is [`persona_key_for`]'s; a persona whose document lists no key it
/// holds under `authentication` cannot send a room request as itself, and is refused
/// rather than signed for under a key a host will not accept for the purpose.
pub async fn authentication_key(
    state: &AppState,
    auth: &AuthClaims,
    did: &str,
) -> Result<PersonaKey, AppError> {
    persona_key_for(
        PersonaStores::from_state(state),
        auth,
        did,
        Relationship::Authentication,
    )
    .await?
    .ok_or_else(|| {
        AppError::Forbidden(format!(
            "this agent holds no key that `{did}` lists for `authentication` and that you may \
             use, so it cannot send a room request as that member"
        ))
    })
}

/// Sign `document` as `did` for `authentication`, through the gated oracle, and set its
/// `issuer` to `did` first — the proof covers every member, `recipient` included.
pub async fn sign_as(
    state: &AppState,
    auth: &AuthClaims,
    did: &str,
    mut document: Value,
) -> Result<Value, AppError> {
    let key = authentication_key(state, auth, did).await?;
    let obj = document
        .as_object_mut()
        .ok_or_else(|| AppError::Validation("a room request is a JSON object".into()))?;
    obj.remove("proof");
    obj.insert("issuer".into(), Value::String(did.to_string()));

    let signer = VtaKeySigner::new(
        crate::operations::room_issuance::SigningContext {
            keys_ks: &state.keys_ks,
            imported_ks: &state.imported_ks,
            internal_ks: &state.internal_ks,
            contexts_ks: &state.contexts_ks,
            acl_ks: &state.acl_ks,
            seed_store: &state.seed_store,
            audit: &state.audit_sink,
            auth,
        },
        key.key_id,
        key.verification_method,
    );
    let proof = affinidi_data_integrity::DataIntegrityProof::sign(
        &document,
        &signer,
        affinidi_data_integrity::SignOptions::new()
            .with_proof_purpose(Relationship::Authentication.as_str()),
    )
    .await
    .map_err(|e| {
        let mut cause = String::new();
        let mut src: Option<&(dyn std::error::Error + 'static)> = std::error::Error::source(&e);
        while let Some(inner) = src {
            cause = format!("{cause}: {inner}");
            src = inner.source();
        }
        AppError::Internal(format!("sign the room request as `{did}`: {e}{cause}"))
    })?;
    document["proof"] = serde_json::to_value(proof)
        .map_err(|e| AppError::Internal(format!("serialise the proof: {e}")))?;
    Ok(document)
}

/// Validate a room request's payload against its type's own schema — what a host will do,
/// done before this VTA signs anything as the member (`rooms/keys/act` recipient item
/// 8). A type the registry carries no schema for is refused: signing a document nobody
/// can check is not a default worth having.
pub fn check_schema(document: &Value) -> Result<(), AppError> {
    let type_uri = document
        .get("type")
        .and_then(Value::as_str)
        .ok_or_else(|| AppError::Validation("a room request names its `type`".into()))?;
    let bare = bare_type(type_uri);
    let schema = trust_tasks_rs::schema_index::schema_for(bare).ok_or_else(|| {
        AppError::Validation(format!(
            "`{bare}` has no schema to validate the request against"
        ))
    })?;
    let payload = document.get("payload").cloned().unwrap_or(Value::Null);
    trust_tasks_rs::validate::against_schema(schema, &payload).map_err(|e| {
        AppError::Validation(format!(
            "the `{bare}` payload does not validate against its schema: {}",
            e.messages().join("; ")
        ))
    })
}

/// A room request completed as its member.
#[derive(Debug, Clone)]
pub struct Completed {
    /// The signed document, ready to send to its `recipient` unaltered.
    pub document: Value,
    /// When the inserted presentation's leaf lapses; `None` where none was inserted.
    pub expires_at: Option<String>,
}

/// Complete `document` as `principal`: insert the principal's own authority narrowed to
/// `action` and granted to the principal (where `action` is `Some`), set `issuer`, and sign
/// for `authentication`.
///
/// The caller has established that `principal` holds `action`; the credential library
/// refuses to widen regardless.
pub async fn complete_as(
    state: &AppState,
    auth: &AuthClaims,
    principal: &Principal,
    room_id: &str,
    mut document: Value,
    action: Option<&str>,
) -> Result<Completed, AppError> {
    let mut expires_at = None;
    if let Some(action) = action {
        // Granted to the member itself (`agent_did` = the principal): the presenter a host
        // authenticates is the member, which is what makes the host record the member.
        let minted =
            room_oracle::present_as(state, auth, principal, &principal.did, room_id, action)
                .await?;
        let payload = document
            .get_mut("payload")
            .and_then(Value::as_object_mut)
            .ok_or_else(|| AppError::Validation("a room request carries a payload".into()))?;
        payload.insert("presentation".into(), minted.presentation);
        expires_at = Some(minted.expires_at);
    }
    check_schema(&document)?;
    let document = sign_as(state, auth, &principal.did, document).await?;
    Ok(Completed {
        document,
        expires_at,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every row of the table names a type the registry carries a schema for — the check a
    /// completed document is validated against.
    #[test]
    fn every_actable_type_has_a_schema() {
        for (t, _) in ACT_TABLE {
            assert!(
                trust_tasks_rs::schema_index::schema_for(t).is_some(),
                "{t} has no schema"
            );
        }
    }

    /// The offer types are actable at 0.3 and later only, apart from the host-bound table,
    /// and they are the only `vtc` types that are: an administrator's `members/add` is not.
    #[test]
    fn the_offer_types_are_apart_from_the_host_bound_table() {
        for t in OFFER_TYPES_0_4 {
            assert!(is_offer_type_0_4(t), "{t}");
            assert_eq!(actable(t), None, "{t} is not in the 0.1/0.2 table");
            assert!(
                trust_tasks_rs::schema_index::schema_for(t).is_some(),
                "{t} has no schema"
            );
        }
        for t in OFFER_TYPES {
            assert!(is_offer_type(t) && is_offer_type_0_4(t), "{t}");
        }
        assert!(is_offer_accept(&format!("{OFFERS_ACCEPT_0_1}#request")));
        assert!(!is_offer_accept(OFFERS_LIST_0_1));
        assert!(!is_offer_accept(OFFERS_LIST_0_2));
        let members_add = "https://trusttasks.org/spec/vtc/rooms/community/members/add/0.1";
        assert!(!is_offer_type(members_add) && !is_offer_type_0_4(members_add));
    }

    /// `rooms/keys/act/0.4` widens the table by exactly `vtc/rooms/offers/list/0.2`, and
    /// 0.3's closed table still refuses it (0.3 recipient item 1).
    #[test]
    fn rooms_keys_act_0_4_adds_only_offers_list_0_2() {
        assert!(!is_offer_type(OFFERS_LIST_0_2));
        assert!(is_offer_type_0_4(&format!("{OFFERS_LIST_0_2}#request")));
        let added: Vec<_> = OFFER_TYPES_0_4
            .iter()
            .filter(|t| !OFFER_TYPES.contains(t))
            .collect();
        assert_eq!(added, [&OFFERS_LIST_0_2]);
    }

    /// `rooms/keys/act/0.5` widens 0.4's table by exactly `vtc/rooms/memberships/list/0.1`,
    /// and 0.4's table still refuses it; still no administrator's task, and only one of them
    /// can carry key material.
    #[test]
    fn rooms_keys_act_0_5_adds_only_memberships_list() {
        for t in COMMUNITY_TYPES {
            assert!(is_community_type(t), "{t}");
            assert_eq!(actable(t), None, "{t} is not in the 0.1/0.2 table");
            assert!(
                trust_tasks_rs::schema_index::schema_for(t).is_some(),
                "{t} has no schema"
            );
        }
        let added: Vec<_> = COMMUNITY_TYPES
            .iter()
            .filter(|t| !OFFER_TYPES_0_4.contains(t))
            .collect();
        assert_eq!(added, [&MEMBERSHIPS_LIST_0_1]);
        assert!(is_community_type(&format!(
            "{MEMBERSHIPS_LIST_0_1}#request"
        )));
        assert!(!is_offer_type_0_4(MEMBERSHIPS_LIST_0_1));
        assert_eq!(
            COMMUNITY_TYPES
                .iter()
                .filter(|t| is_offer_accept(t))
                .count(),
            1
        );
        assert!(!is_community_type(
            "https://trusttasks.org/spec/vtc/rooms/community/members/list/0.1"
        ));
    }

    /// `rooms/keys/act/0.6` widens 0.5's table by exactly `vtc/rooms/offers/list/0.3`, and
    /// 0.5's closed table still refuses it.
    #[test]
    fn rooms_keys_act_0_6_adds_only_offers_list_0_3() {
        for t in COMMUNITY_TYPES_0_6 {
            assert!(is_community_type_0_6(t), "{t}");
            assert_eq!(actable(t), None, "{t} is not in the 0.1/0.2 table");
            assert!(
                trust_tasks_rs::schema_index::schema_for(t).is_some(),
                "{t} has no schema"
            );
        }
        let added: Vec<_> = COMMUNITY_TYPES_0_6
            .iter()
            .filter(|t| !COMMUNITY_TYPES.contains(t))
            .collect();
        assert_eq!(added, [&OFFERS_LIST_0_3]);
        assert!(is_community_type_0_6(&format!("{OFFERS_LIST_0_3}#request")));
        assert!(!is_community_type(OFFERS_LIST_0_3));
        assert!(!is_offer_type_0_4(OFFERS_LIST_0_3));
    }

    /// The deliberate absences: chunk uploads (bytes never pass through the key holder),
    /// the 0.1 uploads that bind every chunk to the member, and the operations that prune
    /// or change ownership.
    #[test]
    fn the_absent_types_are_not_actable() {
        for t in [
            spec::blobs::upload::chunk::v0_2::Payload::TYPE_URI,
            spec::blobs::upload::chunk::v0_1::Payload::TYPE_URI,
            spec::blobs::upload::begin::v0_1::Payload::TYPE_URI,
            spec::blobs::upload::commit::v0_1::Payload::TYPE_URI,
            spec::blobs::upload::abort::v0_1::Payload::TYPE_URI,
            spec::epoch::prune::v0_1::Payload::TYPE_URI,
            spec::owner::transfer::v0_1::Payload::TYPE_URI,
            spec::owner::claim::v0_1::Payload::TYPE_URI,
            spec::create::v0_1::Payload::TYPE_URI,
            "https://trusttasks.org/spec/keys/sign/0.1",
        ] {
            assert_eq!(actable(t), None, "{t}");
        }
        assert_eq!(
            actable(&format!(
                "{}#request",
                spec::records::put::v0_2::Payload::TYPE_URI
            )),
            Some(Some("write"))
        );
    }
}
