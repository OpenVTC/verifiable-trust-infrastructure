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
//! **Another member's standing.** The credentials presented are those the room issued to a
//! **persona the caller may act as** ([`principal`]): a DID this VTA holds for the person, in
//! a context the caller acts in. The persona is the member; it signs the leaf. A credential
//! whose subject is anyone else — a persona held in another context, or a DID this VTA holds
//! no key for — is not the caller's to present, wherever it is stored.
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
pub(crate) const AUTHORITY_TYPE: &str = "AuthorityCredential";
/// The VC `type` tag a room's membership credential carries.
pub(crate) const MEMBERSHIP_TYPE: &str = "MembershipCredential";

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

/// The member a room's credentials name, as the caller may act as them: the **persona**
/// the room granted to, the key this agent signs with as that persona, and the room-issued
/// credentials themselves.
///
/// Constructible only by [`principal`], which is where the persona rule is applied.
#[derive(Debug, Clone)]
pub struct Principal {
    /// The persona DID: the subject of the room's membership and authority credentials.
    pub did: String,
    /// The key this agent signs with as [`Self::did`].
    pub key: crate::operations::persona::PersonaKey,
    vac: Value,
    vmc: Value,
}

impl Principal {
    /// Whether the room's grant to this persona confers `action` — what
    /// `rooms/keys/act` checks before narrowing to it, so a member who does not hold
    /// the action is told so in the task's own words (`actionNotHeld`) rather than in the
    /// credential library's.
    pub fn confers(&self, action: &str) -> Result<bool, AppError> {
        let root: DTGCredential = serde_json::from_value(self.vac.clone())
            .map_err(|e| AppError::Internal(format!("stored authority credential: {e}")))?;
        Ok(root
            .credential()
            .authority()
            .is_some_and(|grant| grant.actions.iter().any(|a| a == action)))
    }

    /// The actions the room's grant to this persona confers — what `rooms/keys/list`
    /// reports beside each member, so a client can say which place in the room a persona
    /// holds (one that administers it, or a member). Empty for an unreadable credential:
    /// this is a description, never a gate.
    pub fn actions(&self) -> Vec<String> {
        serde_json::from_value::<DTGCredential>(self.vac.clone())
            .ok()
            .and_then(|root| root.credential().authority().map(|g| g.actions.clone()))
            .unwrap_or_default()
    }
}

/// Every persona the caller may act as that holds credentials issued by `room_id`, with
/// those credentials.
///
/// The candidates [`principal`] chooses from, and what `rooms/keys/act` resolves its
/// `issuer` against. Empty when there are none — a room nobody here holds anything from and
/// a room only somebody the caller cannot act as holds read alike. A persona holding two
/// authority credentials, or two membership credentials, from one room is refused rather
/// than guessed between, as it always was.
pub async fn principals(
    state: &AppState,
    auth: &AuthClaims,
    room_id: &str,
) -> Result<Vec<Principal>, AppError> {
    let scope = auth.act_scope();
    let stores = crate::operations::persona::PersonaStores::from_state(state);

    let mut held: Vec<(DTGCredential, Value, crate::operations::persona::PersonaKey)> = Vec::new();
    for vac in room_credentials(&state.vault_ks, room_id, AUTHORITY_TYPE, &scope).await? {
        let parsed: DTGCredential = serde_json::from_value(vac.clone()).map_err(|e| {
            AppError::Internal(format!("stored authority credential for `{room_id}`: {e}"))
        })?;
        if let Some(key) =
            crate::operations::persona::persona_signing_key(stores, auth, parsed.subject()).await?
        {
            held.push((parsed, vac, key));
        }
    }

    // Two credentials for one persona is the ambiguity this always refused.
    let mut subjects: Vec<String> = held
        .iter()
        .map(|(c, _, _)| c.subject().to_string())
        .collect();
    subjects.sort_unstable();
    let total = subjects.len();
    subjects.dedup();
    if subjects.len() != total {
        return Err(AppError::Conflict(format!(
            "this VTA holds more than one {AUTHORITY_TYPE} issued by room `{room_id}` to one \
             persona; which one to attenuate from is not a question this can answer safely"
        )));
    }

    let vmcs = room_credentials(&state.vault_ks, room_id, MEMBERSHIP_TYPE, &scope).await?;
    let mut out = Vec::with_capacity(held.len());
    for (root, vac, key) in held {
        let did = root.subject().to_string();
        // The membership credential of the same persona — never another's, which would pair
        // one member's authority with somebody else's membership.
        let mut mine = Vec::new();
        for vmc in &vmcs {
            let parsed: DTGCredential = serde_json::from_value(vmc.clone()).map_err(|e| {
                AppError::Internal(format!("stored membership credential for `{room_id}`: {e}"))
            })?;
            if parsed.subject() == did {
                mine.push(vmc.clone());
            }
        }
        let vmc = match mine.len() {
            0 => {
                return Err(AppError::NotFound(format!(
                    "this VTA holds no {MEMBERSHIP_TYPE} issued by room `{room_id}` to the \
                     persona its {AUTHORITY_TYPE} names"
                )));
            }
            1 => mine.remove(0),
            n => {
                return Err(AppError::Conflict(format!(
                    "this VTA holds {n} {MEMBERSHIP_TYPE}s issued by room `{room_id}` to one \
                     persona; which one to present is not a question this can answer safely"
                )));
            }
        };
        out.push(Principal { did, key, vac, vmc });
    }
    Ok(out)
}

/// The persona the caller acts as in `room_id`, and the credentials the room issued it.
///
/// # Selection is by persona, never by "whatever is in the vault"
///
/// Credentials are found by issuer — a room issues its own, which is the property a host
/// verifies — and then kept only where their **subject is a persona the caller may act as**
/// ([`crate::operations::persona::persona_signing_key`]). That second filter is the
/// privilege boundary. The vault's own custody gate admits a credential stored without a
/// context to every caller, so on its own it would let a caller in context A present a
/// credential whose subject is a persona in context B; here such a credential is simply not
/// one of the caller's, and the answer is the same `NotFound` as for a room nobody holds
/// anything from.
///
/// One persona, one authority credential and one membership credential, or a refusal: a
/// caller acting in two contexts that each hold a persona in this room is asked to choose
/// by acting in one, never answered with a guess.
pub async fn principal(
    state: &AppState,
    auth: &AuthClaims,
    room_id: &str,
) -> Result<Principal, AppError> {
    principal_named(state, auth, room_id, None).await
}

/// [`principal`], or — where the request names the member
/// ([`crate::operations::room_member::named_member`]) — exactly that persona, if it is one
/// the caller may act as holding the room's credentials. Naming only narrows: a persona the
/// caller may not act as is the same `NotFound` as one nobody here holds.
pub async fn principal_named(
    state: &AppState,
    auth: &AuthClaims,
    room_id: &str,
    named: Option<&str>,
) -> Result<Principal, AppError> {
    let mut held = principals(state, auth, room_id).await?;
    if let Some(named) = named {
        return held.into_iter().find(|p| p.did == named).ok_or_else(|| {
            AppError::NotFound(format!(
                "this VTA holds no {AUTHORITY_TYPE} issued by room `{room_id}` to `{named}` \
                 as a persona you may act as"
            ))
        });
    }
    match held.len() {
        0 => Err(AppError::NotFound(format!(
            "this VTA holds no {AUTHORITY_TYPE} issued by room `{room_id}` to a persona \
             you may act as"
        ))),
        1 => Ok(held.remove(0)),
        n => Err(AppError::Conflict(format!(
            "you may act as {n} personas holding a {AUTHORITY_TYPE} issued by room \
             `{room_id}`; which one is acting is not a question this can answer \
             safely — act from the context of the one you mean"
        ))),
    }
}

/// Mint a presentation for `agent_did` to perform `action` on `room_id`.
///
/// `agent_did` is the party that will present it — for `rooms/keys/present`, the producer
/// of the request, as that specification's *Presenter binding* requires. It is what the
/// minted leaf grants to, which is what makes the result unusable by anyone else: `authorize`
/// on the far side refuses a chain whose leaf grants to somebody other than the party that
/// signed the request. The member whose authority is narrowed is the caller's
/// [`principal`] persona, and the leaf is signed as that persona.
pub async fn present(
    state: &AppState,
    auth: &AuthClaims,
    agent_did: &str,
    room_id: &str,
    action: &str,
) -> Result<MintedPresentation, AppError> {
    let principal = principal(state, auth, room_id).await?;
    present_as(state, auth, &principal, agent_did, room_id, action).await
}

/// [`present`], for a [`principal`] already resolved — so a caller that must also sign as
/// the persona (`rooms/owner/group/add`, which speaks to the host *as* the owner) uses the
/// same persona the presentation was minted from rather than resolving it twice.
pub async fn present_as(
    state: &AppState,
    auth: &AuthClaims,
    principal: &Principal,
    agent_did: &str,
    room_id: &str,
    action: &str,
) -> Result<MintedPresentation, AppError> {
    let root: DTGCredential = serde_json::from_value(principal.vac.clone()).map_err(|e| {
        AppError::Internal(format!("stored authority credential for `{room_id}`: {e}"))
    })?;

    // Attenuation, not issuance. `attenuate` refuses to widen, so a caller asking for more
    // than the principal holds fails in the credential library rather than at a check here
    // that somebody could forget to write.
    let now = Utc::now();
    let expires = now + PRESENTATION_LIFETIME;
    // There is no audience argument any more. The leaf is bound to its subject —
    // `agent_did` — and a verifier requires the presenter to be that subject. A second
    // field naming who may present could only repeat the subject or contradict it, which is
    // why dtg-credentials 0.8 removed it.
    // `issuerScope: directed`: the leaf is issued by the member under the DID the room
    // admitted — one identifier recognised by the room, its host and the agent, not a
    // per-counterparty one and not a public identity. `max_attenuation: None` takes the
    // library default under the room's bound (the parent's less one).
    let mut leaf = root
        .attenuate(
            dtg_credentials::IssuerScope::Directed,
            agent_did.to_string(),
            vec![action.to_string()],
            now,
            expires,
            None,
        )
        .map_err(|e| {
            // The common case is asking for an action the principal does not hold, and
            // saying so plainly is better than a generic refusal the caller cannot act on.
            AppError::Validation(format!(
                "cannot attenuate the principal's authority for `{room_id}` to `{action}`: {e}"
            ))
        })?;
    leaf.validate()
        .map_err(|e| AppError::Internal(format!("the attenuated credential: {e}")))?;

    // Signed by the **principal** — the persona the room granted to, whose key this VTA
    // holds — so that is the key that may narrow it. Through the gated oracle: the key never
    // leaves the key store, and its context, the caller's key scope and the context's
    // signing policy are checked again where the signature is made.
    let signer = crate::operations::room_issuance::VtaKeySigner::new(
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
        principal.key.key_id.clone(),
        principal.key.verification_method.clone(),
    );
    let proof = affinidi_data_integrity::DataIntegrityProof::sign(
        &leaf,
        &signer,
        affinidi_data_integrity::SignOptions::new(),
    )
    .await
    .map_err(|e| {
        let mut cause = String::new();
        let mut src: Option<&(dyn std::error::Error + 'static)> = std::error::Error::source(&e);
        while let Some(inner) = src {
            cause = format!("{cause}: {inner}");
            src = inner.source();
        }
        AppError::Internal(format!("sign the attenuated credential: {e}{cause}"))
    })?;
    leaf.credential_mut().proof = Some(proof);

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
        "membership": as_text(&principal.vmc, "membership credential")?,
        "authority": [
            as_text(&leaf_json, "attenuated credential")?,
            as_text(&principal.vac, "room-issued credential")?,
        ],
    });

    Ok(MintedPresentation {
        presentation,
        expires_at: expires.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
    })
}

/// Every credential of `type_tag` issued by `room_id` that the caller's custody scope
/// reaches, parsed. Whose they are is [`principal`]'s question, not this one's.
async fn room_credentials(
    vault: &KeyspaceHandle,
    room_id: &str,
    type_tag: &str,
    scope: &ActScope,
) -> Result<Vec<Value>, AppError> {
    let query = crate::vault::query::CredentialQuery {
        r#type: Some(type_tag.to_string()),
        issuer_did: Some(room_id.to_string()),
        ..Default::default()
    };

    let mut out = Vec::new();
    for found in crate::vault::query::search(vault, &query, scope).await? {
        let stored = crate::vault::storage::get(vault, &found.id)
            .await?
            .ok_or_else(|| {
                AppError::Internal(format!("credential `{}` vanished mid-read", found.id))
            })?;
        // `body` is **opaque bytes** — the vault never parses what it holds. So it is
        // PARSED here, not converted: `to_value` on a `Vec<u8>` yields a JSON array of
        // byte values, which then fails to deserialise as a credential with "invalid
        // type: sequence, expected struct DTGCommon". That is what it did until the
        // round-trip test below was written.
        out.push(
            serde_json::from_slice(&stored.body).map_err(|e| {
                AppError::Internal(format!("stored {type_tag} for `{room_id}`: {e}"))
            })?,
        );
    }
    Ok(out)
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
            dtg_credentials::IssuerScope::Public,
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
            dtg_credentials::IssuerScope::Public,
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

    // ─── Personas ────────────────────────────────────────────────────────────
    //
    // The member a room's credentials name is a persona this VTA holds for a person in one
    // of their contexts. These pin the three things that makes true: a `did:webvh` persona
    // signs (it could not, before), a caller reaches only the personas of contexts it acts
    // in, and an ambiguous caller is refused rather than guessed for.

    use crate::operations::persona::test_fixture::{self as personas, Persona};

    /// Put a credential in the vault under its own id — two from one room must not collide.
    async fn vault_as(
        state: &AppState,
        id: &str,
        type_tag: &str,
        issuer: &str,
        context_id: Option<&str>,
        cred: &DTGCredential,
    ) {
        use crate::vault::model::{CredentialFormat, CredentialStatus, StoredCredential};
        use vti_common::vault::VaultStatus;
        crate::vault::storage::put(
            &state.vault_ks,
            &StoredCredential {
                id: id.into(),
                format: CredentialFormat::EddsaJcs2022,
                types: vec![type_tag.into()],
                schema_id: None,
                community_did: None,
                context_id: context_id.map(str::to_string),
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
            },
        )
        .await
        .expect("store the credential");
    }

    /// `alice` and `bob`, two contexts of one VTA.
    async fn two_contexts(state: &AppState) {
        for (id, name) in [("alice", "Alice"), ("bob", "Bob")] {
            crate::contexts::create_context(&state.contexts_ks, id, name)
                .await
                .expect("create context");
        }
    }

    async fn did_key_persona(state: &AppState, context: &str, key_id: &str) -> Persona {
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

    #[cfg(feature = "webvh")]
    async fn webvh_persona(state: &AppState, context: &str, key_id: &str) -> Persona {
        personas::webvh_persona(
            &state.keys_ks,
            &state.internal_ks,
            &state.contexts_ks,
            &state.acl_ks,
            &state.webvh_ks,
            &state.seed_store,
            &state.audit_sink,
            context,
            key_id,
        )
        .await
    }

    /// The room's VAC (conferring `actions`) and VMC to `subject`, stored context-less — the
    /// case where the vault's own custody gate admits every caller, so only the persona rule
    /// stands between one context and another's credentials.
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
        vault_as(
            state,
            &format!("vac-{tag}"),
            AUTHORITY_TYPE,
            &room.did,
            None,
            &vac,
        )
        .await;
        vault_as(
            state,
            &format!("vmc-{tag}"),
            MEMBERSHIP_TYPE,
            &room.did,
            None,
            &vmc,
        )
        .await;
    }

    fn room_row(room: &str, owner: &str) -> Room {
        Room {
            room_id: room.to_string(),
            owner_did: owner.to_string(),
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
        }
    }

    /// A resolver that knows `docs`, so a host can resolve a `did:webvh` persona's method.
    async fn resolver_knowing(
        state: &mut AppState,
        docs: &[&Persona],
    ) -> affinidi_did_resolver_cache_sdk::DIDCacheClient {
        let mut resolver = affinidi_did_resolver_cache_sdk::DIDCacheClient::new(
            affinidi_did_resolver_cache_sdk::config::DIDCacheConfigBuilder::default().build(),
        )
        .await
        .unwrap();
        for p in docs {
            resolver
                .add_did_document(&p.did, serde_json::from_value(p.document.clone()).unwrap())
                .await;
        }
        state.did_resolver = Some(resolver.clone());
        resolver
    }

    /// **A `did:webvh` persona presents.** The leaf is signed as the persona — under the
    /// method its own log publishes — and a host verifies the chain against the persona's
    /// resolved document. Before, the oracle accepted only a `did:key` subject whose key id
    /// was `did:key:X#X`, so a room granting to a person's minted `did:webvh` could not be
    /// presented from at all.
    #[cfg(feature = "webvh")]
    #[tokio::test]
    async fn a_webvh_persona_presents_and_a_host_verifies_it() {
        let (mut state, _dir) = crate::test_support::build_signing_test_app_state().await;
        two_contexts(&state).await;
        let alice = webvh_persona(&state, "alice", "alice-persona").await;
        resolver_knowing(&mut state, &[&alice]).await;
        let room = Party::new();
        let agent = Party::new();
        grant(&state, &room, &alice.did, "alice", &["read", "write"]).await;

        let caller = crate::test_support::admin_claims_for_context("alice");
        let p = principal(&state, &caller, &room.did).await.expect("alice");
        assert_eq!(
            p.did, alice.did,
            "the member is the persona, not the caller"
        );
        assert_eq!(p.key.verification_method, format!("{}#key-1", alice.did));

        let minted = present(&state, &caller, &agent.did, &room.did, "read")
            .await
            .expect("the oracle mints as the persona");
        let presentation: AuthorityPresentation =
            serde_json::from_value(minted.presentation).expect("a readable presentation");
        let verifier = DtgChainVerifier::without_zk(Box::new(DataIntegrityKeys(
            state.trust_task_vm_resolver(),
        )));
        let verified = verifier
            .verify(
                &room_row(&room.did, &alice.did),
                &presentation,
                Action::Read,
                &agent.did,
            )
            .await
            .expect("the host verifies a chain whose leaf the persona signed");
        assert_eq!(verified.subject, agent.did);
    }

    /// **The owner presenting as itself** — what `rooms/owner/group/add` sends with
    /// `rooms/epoch/mint`: the leaf granted to the persona that signs the request, so the
    /// presenter the host authenticates is the persona the room granted `admin` to.
    #[cfg(feature = "webvh")]
    #[tokio::test]
    async fn a_persona_presenting_its_own_admin_authority_verifies() {
        let (mut state, _dir) = crate::test_support::build_signing_test_app_state().await;
        two_contexts(&state).await;
        let owner = webvh_persona(&state, "alice", "owner-persona").await;
        resolver_knowing(&mut state, &[&owner]).await;
        let room = Party::new();
        grant(
            &state,
            &room,
            &owner.did,
            "owner",
            &["read", "write", "admin"],
        )
        .await;

        let caller = crate::test_support::admin_claims_for_context("alice");
        let p = principal(&state, &caller, &room.did)
            .await
            .expect("the owner");
        let minted = present_as(&state, &caller, &p, &p.did, &room.did, "admin")
            .await
            .expect("mint");
        let presentation: AuthorityPresentation =
            serde_json::from_value(minted.presentation).expect("readable");
        let verifier = DtgChainVerifier::without_zk(Box::new(DataIntegrityKeys(
            state.trust_task_vm_resolver(),
        )));
        let verified = verifier
            .verify(
                &room_row(&room.did, &owner.did),
                &presentation,
                Action::Admin,
                &owner.did,
            )
            .await
            .expect("the owner persona presents its own admin authority");
        assert_eq!(verified.subject, owner.did);
    }

    /// **The privilege boundary.** A credential stored without a context is visible to the
    /// vault's custody gate from every context; its subject being bob's persona is what
    /// keeps it bob's. A caller acting in `alice` is told the same thing as for a room this
    /// VTA holds nothing from.
    #[tokio::test]
    async fn another_contexts_persona_is_not_presented() {
        let (state, _dir) = crate::test_support::build_signing_test_app_state().await;
        two_contexts(&state).await;
        let bob = did_key_persona(&state, "bob", "bob-persona").await;
        let room = Party::new();
        grant(&state, &room, &bob.did, "bob", &["read"]).await;
        let elsewhere = Party::new();

        let alice_caller = crate::test_support::admin_claims_for_context("alice");
        let err = present(&state, &alice_caller, &alice_caller.did, &room.did, "read")
            .await
            .expect_err("bob's credentials are not alice's caller's");
        assert!(matches!(err, AppError::NotFound(_)), "{err}");
        let unknown = present(
            &state,
            &alice_caller,
            &alice_caller.did,
            &elsewhere.did,
            "read",
        )
        .await
        .expect_err("a room nobody holds anything from");
        assert_eq!(
            err.to_string(),
            unknown.to_string().replace(&elsewhere.did, &room.did),
            "held-for-someone-else and held-for-nobody read the same"
        );

        // And bob's own caller is served.
        present(
            &state,
            &crate::test_support::admin_claims_for_context("bob"),
            &Party::new().did,
            &room.did,
            "read",
        )
        .await
        .expect("bob presents bob's");
    }

    /// A credential naming a DID this VTA holds no key for — an interface client's
    /// `did:key` — is not anybody's to present, not even a super-admin's.
    #[tokio::test]
    async fn a_credential_naming_a_client_key_is_not_presented() {
        let (state, _dir) = crate::test_support::build_signing_test_app_state().await;
        let room = Party::new();
        let client = Party::new();
        grant(&state, &room, &client.did, "client", &["read"]).await;
        let err = present(
            &state,
            &crate::test_support::super_admin_claims(),
            &client.did,
            &room.did,
            "read",
        )
        .await
        .expect_err("no persona");
        assert!(matches!(err, AppError::NotFound(_)), "{err}");
    }

    /// A caller acting as two personas that each hold credentials for one room is asked to
    /// act from one context — never answered with whichever came first.
    #[tokio::test]
    async fn two_personas_in_one_room_are_not_guessed_between() {
        let (state, _dir) = crate::test_support::build_signing_test_app_state().await;
        two_contexts(&state).await;
        let alice = did_key_persona(&state, "alice", "alice-persona").await;
        let bob = did_key_persona(&state, "bob", "bob-persona").await;
        let room = Party::new();
        grant(&state, &room, &alice.did, "alice", &["read"]).await;
        grant(&state, &room, &bob.did, "bob", &["read"]).await;

        let both = crate::auth::AuthClaims {
            allowed_contexts: vec!["alice".into(), "bob".into()],
            ..crate::test_support::super_admin_claims()
        };
        let err = principal(&state, &both, &room.did)
            .await
            .expect_err("ambiguous");
        assert!(matches!(err, AppError::Conflict(_)), "{err}");
        assert!(err.to_string().contains("2 personas"), "{err}");

        let alice_only = principal(
            &state,
            &crate::test_support::admin_claims_for_context("alice"),
            &room.did,
        )
        .await
        .expect("one persona");
        assert_eq!(alice_only.did, alice.did);
    }

    /// The membership credential presented is the persona's own, never another member's
    /// that happens to come from the same room.
    #[tokio::test]
    async fn the_membership_presented_is_the_same_personas() {
        let (state, _dir) = crate::test_support::build_signing_test_app_state().await;
        two_contexts(&state).await;
        let alice = did_key_persona(&state, "alice", "alice-persona").await;
        let room = Party::new();
        grant(&state, &room, &alice.did, "alice", &["read"]).await;
        // Somebody else's membership in the same room.
        let now = Utc::now();
        let mut other = DTGCredential::new_vmc(
            room.did.clone(),
            Party::new().did,
            now - Span::minutes(1),
            Some(now + Span::days(30)),
            false,
        );
        other.sign(&room.secret, None).await.unwrap();
        vault_as(
            &state,
            "vmc-other",
            MEMBERSHIP_TYPE,
            &room.did,
            None,
            &other,
        )
        .await;

        let p = principal(
            &state,
            &crate::test_support::admin_claims_for_context("alice"),
            &room.did,
        )
        .await
        .expect("alice's membership, unambiguously");
        let vmc: DTGCredential = serde_json::from_value(p.vmc).unwrap();
        assert_eq!(vmc.subject(), alice.did);
    }
}
