//! The room presentation oracle — `rooms/keys/present/0.1`.
//!
//! An agent asks the VTA holding its principal's room credentials to produce a presentation
//! for **one** room operation. The credentials never cross to the agent; only the
//! presentation does, and it is bound to the operation it was asked for.
//!
//! # Why this exists at all
//!
//! The data-rooms design turns on a member equipping their agent with strictly less than
//! they hold — a chain one link longer, conferring `read` for four hours, bound to one host.
//! Until now nothing *minted* one. A member wanting to give an agent access had two options:
//! hand over their own credentials, which is the outcome attenuation exists to prevent, or
//! mint an attenuation by hand, which nobody does.
//!
//! So the agent asks, and the VTA — which already holds the member's keys and is already in
//! their trusted computing base — mints it. A host is not in that base, which is why the
//! host sees only the result.
//!
//! # What a caller cannot obtain by asking
//!
//! **More than the principal holds.** [`present`] attenuates from the member's own VAC, and
//! `dtg_credentials::attenuate` refuses to widen. A request for `admin` against a chain
//! conferring `read` fails at the credential library, not at a policy check here.
//!
//! **A presentation covering everything.** `action` is a required member of the request and
//! exactly one action is conferred. An oracle that minted one covering every action would
//! have handed the caller its principal's whole standing in the room, which is precisely the
//! outcome attenuation exists to prevent.
//!
//! **A presentation somebody else can use.** The leaf grants to the DID this VTA
//! authenticated for the request, and a host refuses a chain whose leaf grants to anyone but
//! the party that signed what it received. So a presentation minted here is usable by the
//! caller and by nobody else — and the caller cannot ask for one made out to a third party,
//! because it never gets to name the subject.
//!
//! **A presentation bound to a host.** Deliberately not offered, because it would not mean
//! anything. The chain is scoped to the *room*; a chain rooted in one room confers nothing
//! anywhere else, and any host serving that room would honour it — a room may have more than
//! one host, and moving between them without reissuing credentials is the point. Binding a
//! *request* to its destination is the job of the `recipient` member on the document that
//! carries the presentation, which its `proof` covers (SPEC.md §4.8.2).
//!
//! Both of those are the library's rules now rather than this module's hopes:
//! dtg-credentials 0.8 requires the presenter to be the leaf's subject, refusing anyone else
//! with `NotThePresenter`, and removes the `audience` field that used to stand in for it
//! badly — optional, so a leaf without one was accepted from anybody, and read as the
//! *destination* by the Trust Tasks registry while the library compared it to the presenter
//! (`trustoverip/dtgwg-cred-spec#41`, `trustoverip/dtgwg-trust-tasks-tf#414`).
//!
//! **The keys.** Nothing in the response carries key material in either direction. An oracle
//! that returned the principal's VAC itself would be a credential-release call wearing a
//! different name.
//!
//! # The lifetime is short and not negotiable
//!
//! [`PRESENTATION_LIFETIME`] bounds every leaf this mints. A caller cannot ask for longer:
//! the whole value of an oracle over a credential hand-off is that withdrawing access is
//! withdrawing it *here*, and a long-lived leaf reintroduces exactly the standing credential
//! the oracle exists to avoid handing over.

use chrono::{Duration, Utc};
use dtg_credentials::DTGCredential;
use serde_json::Value;
use vti_common::acl::ActScope;
use vti_common::error::AppError;
use vti_common::store::KeyspaceHandle;

use crate::auth::AuthClaims;
use crate::server::AppState;

/// How long a minted presentation is good for.
///
/// Deliberately not a request parameter. A caller that could ask for a year would be asking
/// for the standing credential this task exists not to hand over, and "the agent needed
/// longer" is a reason to ask again, not a reason to mint longer.
pub const PRESENTATION_LIFETIME: Duration = Duration::hours(4);

/// The VC `type` tag a room's authority credential carries.
const AUTHORITY_TYPE: &str = "AuthorityCredential";
/// The VC `type` tag a room's membership credential carries.
const MEMBERSHIP_TYPE: &str = "MembershipCredential";

/// What the oracle produces.
#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MintedPresentation {
    /// The presentation to send to the host: membership, an authority chain leaf-first, and
    /// — on a room that withholds the subject — a same-subject binding.
    pub presentation: Value,
    /// When it stops being accepted, so a caller can avoid presenting a stale one.
    pub expires_at: String,
}

/// Mint a presentation for `agent_did` to perform `action` on `room_id`.
///
/// `agent_did` is the party the *transport* authenticated — the caller's own DID, from the
/// request's proof. It is what the minted leaf grants to, which is what makes the result
/// unusable by anyone else: `authorize` on the far side refuses a chain whose leaf grants to
/// somebody other than the party that signed the request.
pub async fn present(
    state: &AppState,
    auth: &AuthClaims,
    agent_did: &str,
    room_id: &str,
    action: &str,
) -> Result<MintedPresentation, AppError> {
    let scope = auth.act_scope();

    // The principal's own credentials for this room. Found by issuer, because a room issues
    // its own — which is the same property the host verifies against, so a credential that
    // would not verify there is not one this will present.
    let vac = find_room_credential(&state.vault_ks, room_id, AUTHORITY_TYPE, &scope).await?;
    let vmc = find_room_credential(&state.vault_ks, room_id, MEMBERSHIP_TYPE, &scope).await?;

    let root: DTGCredential = serde_json::from_value(vac.clone()).map_err(|e| {
        AppError::Internal(format!("stored authority credential for `{room_id}`: {e}"))
    })?;

    // Attenuation, not issuance. `attenuate` refuses to widen, so a caller asking for more
    // than the principal holds fails in the credential library rather than at a check here
    // that somebody could forget to write.
    let now = Utc::now();
    let expires = now + PRESENTATION_LIFETIME;
    // There is no audience argument any more. The leaf is bound to its subject —
    // `agent_did`, the caller this VTA authenticated — and a verifier requires the presenter
    // to be that subject. A second field naming who may present could only repeat the
    // subject or contradict it, which is why dtg-credentials 0.8 removed it.
    let mut leaf = root
        .attenuate(
            agent_did.to_string(),
            vec![action.to_string()],
            now,
            expires,
        )
        .map_err(|e| {
            // The common case is asking for an action the principal does not hold, and
            // saying so plainly is better than a generic refusal the caller cannot act on.
            AppError::Validation(format!(
                "cannot attenuate the principal's authority for `{room_id}` to `{action}`: {e}"
            ))
        })?;

    // Signed by the **principal**, whose key this VTA holds. The subject of the root VAC is
    // who the room granted to, so that is the key that may narrow it.
    let keys = crate::operations::holder_keys::resolve_holder_keys(
        &state.keys_ks,
        &state.seed_store,
        auth,
        root.subject(),
    )
    .await?;

    leaf.sign(&keys.consent_secret, None)
        .await
        .map_err(|e| AppError::Internal(format!("sign the attenuated credential: {e}")))?;

    let leaf_json = serde_json::to_value(leaf.credential())
        .map_err(|e| AppError::Internal(format!("serialise the attenuated credential: {e}")))?;

    // Leaf first, then the credential the room issued. Every link the host will rely on is
    // present, because the host will not fetch one.
    // No nonce. A presentation is a bundle of credentials signed by their *issuers*, never
    // by the party presenting it, so a challenge placed inside it is unauthenticated — an
    // attacker replaying a captured presentation copies the challenge with everything else.
    // Freshness belongs to the request: the room task document carrying this is signed by
    // the presenter and carries `id` and `issuedAt`, which is what SPEC.md §7.2 item 11
    // keys duplicate-execution protection on.
    // Credentials cross as JSON **strings**, not as objects. `AuthorityPresentation` types
    // both members as strings — the host's opener accepts base64url or bare JSON text and
    // selects on a leading `{` — so an object here is not a presentation a host can even
    // deserialize, let alone verify. It emitted objects until this task moved to `0.2`,
    // whose response schema names the shared component and made the disagreement a type
    // error instead of a runtime refusal nothing in this workspace exercised.
    let as_text = |v: &Value, what: &str| -> Result<Value, AppError> {
        serde_json::to_string(v)
            .map(Value::String)
            .map_err(|e| AppError::Internal(format!("serialise the {what}: {e}")))
    };
    let presentation = serde_json::json!({
        "membership": as_text(&vmc, "membership credential")?,
        "authority": [
            as_text(&leaf_json, "attenuated credential")?,
            as_text(&vac, "room-issued credential")?,
        ],
    });

    Ok(MintedPresentation {
        presentation,
        expires_at: expires.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
    })
}

/// The principal's credential of `type_tag` issued by `room_id`.
///
/// Refuses ambiguity rather than picking. Two authority credentials from one room is a state
/// this code cannot resolve correctly — choosing the broader one hands out more than
/// necessary, choosing the narrower one produces a presentation that fails at the host for
/// reasons the caller cannot see — so it says so and stops.
async fn find_room_credential(
    vault: &KeyspaceHandle,
    room_id: &str,
    type_tag: &str,
    scope: &ActScope,
) -> Result<Value, AppError> {
    let query = crate::vault::query::CredentialQuery {
        r#type: Some(type_tag.to_string()),
        issuer_did: Some(room_id.to_string()),
        ..Default::default()
    };

    let found = crate::vault::query::search(vault, &query, scope).await?;
    match found.len() {
        0 => Err(AppError::NotFound(format!(
            "this VTA holds no {type_tag} issued by room `{room_id}`"
        ))),
        1 => {
            let stored = crate::vault::storage::get(vault, &found[0].id)
                .await?
                .ok_or_else(|| {
                    AppError::Internal(format!("credential `{}` vanished mid-read", found[0].id))
                })?;
            // `body` is **opaque bytes** — the vault never parses what it holds. So it is
            // PARSED here, not converted: `to_value` on a `Vec<u8>` yields a JSON array of
            // byte values, which then fails to deserialise as a credential with "invalid
            // type: sequence, expected struct DTGCommon". That is what it did until the
            // round-trip test below was written.
            serde_json::from_slice(&stored.body)
                .map_err(|e| AppError::Internal(format!("stored {type_tag} for `{room_id}`: {e}")))
        }
        n => Err(AppError::Conflict(format!(
            "this VTA holds {n} {type_tag}s issued by room `{room_id}`; which one to \
             attenuate from is not a question this can answer safely"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration as Span;
    use dtg_credentials::DTGCredential;
    use vti_rooms::authz::{Action, ChainVerifier};
    use vti_rooms::wire::AuthorityPresentation;
    use vti_rooms::{RetentionPolicy, Room, Visibility};
    use vti_rooms_dtg::test_support::Party;
    use vti_rooms_dtg::{DataIntegrityKeys, DtgChainVerifier};

    /// Put a signed credential in the vault the way the receive path would.
    async fn vault(state: &AppState, type_tag: &str, issuer: &str, cred: &DTGCredential) {
        use crate::vault::model::{CredentialFormat, CredentialStatus, StoredCredential};
        use vti_common::vault::VaultStatus;
        let stored = StoredCredential {
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
            body: serde_json::to_vec(cred).expect("serialise the credential"),
            lifecycle: VaultStatus::Active,
            archived_at: None,
            deleted_at: None,
            grace_until: None,
        };
        crate::vault::storage::put(&state.vault_ks, &stored)
            .await
            .expect("store the credential");
    }

    /// **The seam this whole task turns on, and the one nothing exercised.**
    ///
    /// Mint through [`present`], then hand the result to the verifier a host actually runs.
    /// Every defect this test would have caught was found by hand instead, months apart:
    ///
    /// - the request carried an `audience` no presenter could satisfy, so a host refused
    ///   every presentation minted with one (dtgwg-trust-tasks-tf#414);
    /// - it carried a `nonce` written into a closed object, so a host refused the
    ///   presentation as malformed;
    /// - the credentials crossed as JSON *objects* where the wire form is a *string*, so
    ///   the presentation never deserialised at all;
    /// - and the vault body — opaque bytes — was handed to `serde_json::to_value`, which
    ///   turns `Vec<u8>` into an array of numbers rather than reading the credential.
    ///
    /// Each side was internally consistent and well tested. The seam between them was not
    /// tested at all, which is why "green" said nothing about whether this worked.
    #[tokio::test]
    async fn a_minted_presentation_verifies_at_a_host() {
        let (state, _dir) = crate::test_support::build_signing_test_app_state().await;

        // The member's key is one this VTA manages — presenting means signing as the
        // subject, so a key it does not hold cannot attenuate.
        let member_did =
            crate::test_support::seed_holder_key(&state, "m/44'/0'/7'/0'/1'", None).await;
        let room = Party::new();
        let agent = Party::new();
        let now = Utc::now();

        let mut vac = DTGCredential::new_vac(
            room.did.clone(),
            member_did.clone(),
            room.did.clone(),
            vec!["read".into(), "write".into()],
            now - Span::minutes(1),
            now + Span::days(30),
        )
        .expect("the room's grant to the member")
        .with_id("urn:uuid:vac-member");
        vac.sign(&room.secret, None).await.expect("sign the VAC");

        let mut vmc = DTGCredential::new_vmc(
            room.did.clone(),
            member_did.clone(),
            now - Span::minutes(1),
            Some(now + Span::days(30)),
            false,
        );
        vmc.sign(&room.secret, None).await.expect("sign the VMC");

        vault(&state, AUTHORITY_TYPE, &room.did, &vac).await;
        vault(&state, MEMBERSHIP_TYPE, &room.did, &vmc).await;

        let minted = present(
            &state,
            &crate::test_support::super_admin_claims(),
            &agent.did,
            &room.did,
            "read",
        )
        .await
        .expect("the oracle mints a presentation");

        // A host receives this as a document member and deserialises it. An object where
        // the schema says string does not get that far.
        let presentation: AuthorityPresentation =
            serde_json::from_value(minted.presentation.clone()).unwrap_or_else(|e| {
                panic!(
                    "a host cannot read the minted presentation: {e}\n{:#}",
                    minted.presentation
                )
            });

        let verifier = DtgChainVerifier::without_zk(Box::new(DataIntegrityKeys(
            state.trust_task_vm_resolver(),
        )));
        let room_row = Room {
            room_id: room.did.clone(),
            owner_did: member_did.clone(),
            visibility: Visibility::Open,
            retention_policy: RetentionPolicy::Chained,
            anchor_cadence: Default::default(),
            epoch: 1,
            next_version: 1,
            retention_days: 90,
            epoch_expires_at: None,
            created_at: 0,
            updated_at: 0,
            mirror_of: None,
        };

        // The presenter is the agent: the leaf was granted to it, and a VAC is not a bearer
        // credential, so nobody else can present this.
        let verified = verifier
            .verify(&room_row, &presentation, Action::Read, &agent.did)
            .await
            .expect("the host verifies the chain the oracle minted");

        assert_eq!(verified.subject, agent.did);
        assert!(verified.actions.iter().any(|a| a == "read"));
    }

    /// The other half of the same property: the oracle cannot mint something a *third*
    /// party could use. Attenuation narrows to the caller, so the member who owns the
    /// credentials cannot present the chain minted for their own agent.
    #[tokio::test]
    async fn a_minted_presentation_is_useless_to_anyone_else() {
        let (state, _dir) = crate::test_support::build_signing_test_app_state().await;
        let member_did =
            crate::test_support::seed_holder_key(&state, "m/44'/0'/7'/0'/2'", None).await;
        let room = Party::new();
        let agent = Party::new();
        let now = Utc::now();

        let mut vac = DTGCredential::new_vac(
            room.did.clone(),
            member_did.clone(),
            room.did.clone(),
            vec!["read".into()],
            now - Span::minutes(1),
            now + Span::days(30),
        )
        .expect("the room's grant")
        .with_id("urn:uuid:vac-member-2");
        vac.sign(&room.secret, None).await.expect("sign the VAC");

        let mut vmc = DTGCredential::new_vmc(
            room.did.clone(),
            member_did.clone(),
            now - Span::minutes(1),
            Some(now + Span::days(30)),
            false,
        );
        vmc.sign(&room.secret, None).await.expect("sign the VMC");

        vault(&state, AUTHORITY_TYPE, &room.did, &vac).await;
        vault(&state, MEMBERSHIP_TYPE, &room.did, &vmc).await;

        let minted = present(
            &state,
            &crate::test_support::super_admin_claims(),
            &agent.did,
            &room.did,
            "read",
        )
        .await
        .expect("mint");
        let presentation: AuthorityPresentation =
            serde_json::from_value(minted.presentation).expect("readable presentation");

        let verifier = DtgChainVerifier::without_zk(Box::new(DataIntegrityKeys(
            state.trust_task_vm_resolver(),
        )));
        let room_row = Room {
            room_id: room.did.clone(),
            owner_did: member_did.clone(),
            visibility: Visibility::Open,
            retention_policy: RetentionPolicy::Chained,
            anchor_cadence: Default::default(),
            epoch: 1,
            next_version: 1,
            retention_days: 90,
            epoch_expires_at: None,
            created_at: 0,
            updated_at: 0,
            mirror_of: None,
        };

        // The member holds strictly more authority than the agent, and still cannot use
        // this: the chain says the agent is acting.
        let err = verifier
            .verify(&room_row, &presentation, Action::Read, &member_did)
            .await
            .expect_err("the principal must not be able to present their agent's chain");
        assert!(
            format!("{err}").contains(&agent.did),
            "the refusal should name who the leaf grants to: {err}"
        );
    }
}
