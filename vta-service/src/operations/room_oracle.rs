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
//! **A presentation usable by whoever captured it.** The leaf grants to `agent_did` — the
//! party the transport authenticated — and since dtg-credentials 0.8 `verify_chain` REQUIRES
//! the presenter to be the leaf's subject, refusing anyone else with `NotThePresenter`. So a
//! presentation lifted off the wire authorises nothing for the party that lifted it.
//!
//! That used to be `audience`'s job and it did it badly: the field was optional, so a leaf
//! without one was accepted from anybody, and the Trust Tasks registry described it as the
//! party a presentation is *for* while the library compared it to the presenter — so an
//! implementation following the registry minted leaves the verifier refused every time.
//! 0.8 removes it and makes the subject rule normative
//! (`trustoverip/dtgwg-cred-spec#41`, `trustoverip/dtgwg-trust-tasks-tf#414`). The
//! destination question it was reaching for is answered a layer up, by the Trust Task
//! document's `recipient`, which its `proof` covers.
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
    // Accepted and ignored. `rooms/keys/present/0.1` still carries an `audience` member and
    // dtg-credentials 0.8 removed the field it fed. Taking it and doing nothing keeps every
    // existing caller working — the CLI names its host here — while the binding comes from
    // the subject rule instead. Removing it from the schema is proposed in
    // `trustoverip/dtgwg-trust-tasks-tf#414`; until that lands, accepting it is better than
    // refusing a request that is not wrong, and far better than pretending it still binds.
    _audience: Option<&str>,
    nonce: Option<&str>,
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
    let mut presentation = serde_json::json!({
        "membership": vmc,
        "authority": [leaf_json, vac],
    });
    // Echoed rather than interpreted: the verifier chose it, and its value to them is that
    // it came back unchanged.
    if let Some(nonce) = nonce {
        presentation["nonce"] = Value::String(nonce.to_string());
    }

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
            serde_json::to_value(&stored.body)
                .map_err(|e| AppError::Internal(format!("stored {type_tag} for `{room_id}`: {e}")))
        }
        n => Err(AppError::Conflict(format!(
            "this VTA holds {n} {type_tag}s issued by room `{room_id}`; which one to \
             attenuate from is not a question this can answer safely"
        ))),
    }
}
