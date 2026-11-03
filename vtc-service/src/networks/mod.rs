//! The community as a member of Verifiable Trust Networks (`vtc/networks/*`).
//!
//! A Verifiable Trust Network (VTN) curates communities and networks (VTI-VTN-001 – 063).
//! It may list this community without asking (VTI-VTN-010). The listing only becomes
//! membership when the community acknowledges it (VTI-VTN-013). This module is the
//! community's side of that relationship:
//!
//! - **Join**: verify the network at the administrator's URL answers as the DID the
//!   administrator named, verify its listing, register groups for its roles, sign the
//!   acknowledgement and verify the grant. Every statement is signed **as the community**,
//!   by [`crate::credentials::LocalSigner`], so a community holding a post-quantum key signs
//!   with a proof set. A network verifies proof sets (`vti_vtn::verify`).
//! - **Repudiate** a listing, or **leave** by repudiating the grant.
//! - **Register a group** for a network role. The network learns the group's DID, never
//!   its members.
//! - **Relay**: a network delivers a broadcast for a registered group to this community's
//!   relay endpoint. The envelope is verified end to end, and the community pushes it,
//!   unchanged, to the group's active members as `vtc/networks/notice/0.1`.
//! - **Evidence**: a member gets the registration and acceptance linking a group they are
//!   in to a network, to present for a network room pass.
//!
//! Records live in `community_ks`: `network-membership:<network DID>`, plus a seen-set of
//! relayed broadcast ids, `network-broadcast-seen:<message id>`.
//!
//! **Not a capability module yet.** Enabling a capability module projects it to the trust
//! registry (`crate::capability_modules`), which has no `vtn-membership` module to accept
//! it. Until it does, these tasks are gated by the ACL alone (`vtc.config.admin`, plus the
//! requester's bound step-up for every write).

use std::sync::Arc;

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use vti_common::audit::{AuditEvent, NetworkMembershipChangedData};
use vti_common::auth::{ProofPurpose, PurposeVmResolver, TrustTaskVmResolver};
use vti_common::error::AppError;
use vti_vtn::credentials::member;
use vti_vtn::identity::{Party, SignFuture};
use vti_vtn::model::EntryKind;
use vti_vtn::relay::{self, Envelope};
use vti_vtn::verify::{KeyFuture, KeyResolver, verify_signed_by};
use vti_vtn::vocab::{GROUP_REGISTERED_V1, LISTS_V1};
use vti_vtn::{ClientError, VtnClient, VtnError, encode_did};

use crate::credentials::LocalSigner;
use crate::credentials::delivery::{Thread, push_document};
use crate::server::AppState;

const KEY_PREFIX: &str = "network-membership:";
const SEEN_PREFIX: &str = "network-broadcast-seen:";
/// Where a network delivers broadcasts for one of this community's groups, under the API
/// base: `<public URL>/v1/networks/relay/<group id>`.
pub const RELAY_PATH: &str = "/networks/relay/";
/// What the community pushes to a group member for each relayed broadcast.
pub const NOTICE_TYPE: &str =
    <vti_specs::vtc::networks::notice::v0_1::Payload as trust_tasks_rs::Payload>::TYPE_URI;

/// Where a membership stands.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum State {
    Acknowledged,
    Repudiated,
    Departed,
}

/// A community group registered for one of the network's roles.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct RegisteredGroup {
    pub role: String,
    pub group_id: String,
    pub group_did: String,
    pub endpoint: String,
    pub registration: Value,
    pub acceptance: Value,
    pub registered_at: DateTime<Utc>,
}

/// The community's membership of one network. Serialises as the shared
/// `vtc/_shared/0.6` `NetworkMembership` record the tasks answer with.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Membership {
    pub network: String,
    pub url: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub state: State,
    pub listing: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acknowledgement: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repudiation: Option<Value>,
    #[serde(default)]
    pub groups: Vec<RegisteredGroup>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub joined_at: Option<DateTime<Utc>>,
    pub updated_at: DateTime<Utc>,
}

/// Why a network operation was refused.
#[derive(Debug, thiserror::Error)]
pub enum NetError {
    #[error("the network does not list this community: {0}")]
    NotListed(String),
    #[error("{0}")]
    Mismatch(String),
    #[error("the network requires a group for role `{0}`, and none was assigned")]
    RoleUnassigned(String),
    #[error("`{0}` is not a group of this community with a DID of its own")]
    UnknownGroup(String),
    #[error("the network refused: {0}")]
    Refused(String),
    #[error("this community is not a member of that network")]
    NotMember,
    #[error("this community is already a member of that network")]
    AlreadyMember,
    #[error("this community is a member of that network; it leaves with vtc/networks/leave")]
    IsMember,
    #[error("no membership record for that network")]
    NotFound,
    #[error("{0}")]
    Unavailable(String),
    /// An inbound delivery that does not verify.
    #[error("{0}")]
    Rejected(String),
    #[error(transparent)]
    App(#[from] AppError),
}

impl From<VtnError> for NetError {
    fn from(e: VtnError) -> Self {
        NetError::Refused(e.to_string())
    }
}

fn refused(e: ClientError) -> NetError {
    NetError::Refused(e.to_string())
}

/// Allow for clock skew between the community and the network on what we sign.
fn signing_time() -> DateTime<Utc> {
    Utc::now() - Duration::seconds(30)
}

// ------------------------------------------------------------- the community

/// The community, signing as its DID through [`LocalSigner`].
pub(crate) struct Community {
    did: String,
    signer: Arc<LocalSigner>,
}

impl Party for Community {
    fn did(&self) -> &str {
        &self.did
    }

    fn sign_for<'a>(&'a self, mut document: Value, purpose: &'a str) -> SignFuture<'a> {
        Box::pin(async move {
            let signed = if purpose == "authentication" {
                self.signer.sign_authentication_doc(&mut document).await
            } else {
                self.signer.sign_doc(&mut document).await
            };
            signed.map_err(|e| VtnError::Internal(format!("sign as the community: {e}")))?;
            Ok(document)
        })
    }
}

async fn community(state: &AppState) -> Result<Community, NetError> {
    let did = state
        .config
        .read()
        .await
        .vtc_did
        .clone()
        .filter(|d| !d.is_empty())
        .ok_or_else(|| NetError::Unavailable("this community has no DID yet".into()))?;
    let signer = state
        .credential_signer
        .clone()
        .ok_or_else(|| NetError::Unavailable("this community has no signing key".into()))?;
    Ok(Community { did, signer })
}

/// Parties' keys, through the community's DID resolver, checked for the proof's purpose.
pub(crate) struct Resolver(TrustTaskVmResolver);

impl KeyResolver for Resolver {
    fn resolve<'a>(&'a self, verification_method: &'a str, purpose: &'a str) -> KeyFuture<'a> {
        Box::pin(async move {
            let purpose = ProofPurpose::parse(purpose).map_err(VtnError::from)?;
            let key = self
                .0
                .resolve_vm_for_purpose(verification_method, purpose)
                .await
                .map_err(VtnError::from)?;
            Ok(key.public_key_bytes)
        })
    }
}

fn resolver(state: &AppState) -> Resolver {
    Resolver(state.trust_task_vm_resolver())
}

/// A client for the network at `url`, over the hardened foreign-fetch client. The URL is
/// one an administrator named, so the workspace's private-endpoint opt-in applies.
fn client(url: &str) -> Result<VtnClient, NetError> {
    // Tests reach a fake network on loopback without TLS. Never in a production build: the
    // same gate as `crate::test_support`.
    #[cfg(any(test, feature = "test-support"))]
    if url.starts_with("http://127.0.0.1:") {
        return Ok(VtnClient::new(url));
    }
    let policy = vta_sdk::http::EndpointPolicy::process_default();
    vta_sdk::http::guard_foreign_url(url, policy)
        .map_err(|e| NetError::Refused(format!("{url}: {e}")))?;
    Ok(VtnClient::with_http(
        vta_sdk::http::foreign_fetch_client_for(policy),
        url,
    ))
}

async fn relay_endpoint(state: &AppState, group_id: &str) -> Result<String, NetError> {
    let base = state
        .config
        .read()
        .await
        .public_url
        .clone()
        .filter(|u| !u.is_empty())
        .ok_or_else(|| {
            NetError::Unavailable(
                "this community has no public_url, so a network cannot reach its groups".into(),
            )
        })?;
    Ok(format!(
        "{}/v1{RELAY_PATH}{}",
        base.trim_end_matches('/'),
        group_id
    ))
}

async fn group(state: &AppState, group_id: &str) -> Result<crate::groups::Group, NetError> {
    crate::groups::get(state.directory.ks(), group_id)
        .await?
        .filter(|g| !g.group_did.is_empty())
        .ok_or_else(|| NetError::UnknownGroup(group_id.to_string()))
}

/// The DIDs of a group's active members.
async fn active_members(state: &AppState, group_id: &str) -> Result<Vec<String>, AppError> {
    let ks = state.directory.ks();
    let mut out = Vec::new();
    for m in crate::groups::members_of(ks, group_id).await? {
        if m.state != "active" {
            continue;
        }
        if let Some(card) = crate::directory::cards::get(ks, &m.entry_id).await? {
            out.push(card.did);
        }
    }
    out.sort();
    out.dedup();
    Ok(out)
}

// ------------------------------------------------------------------ records

pub async fn load(state: &AppState, network: &str) -> Result<Option<Membership>, AppError> {
    state
        .community_ks
        .get(format!("{KEY_PREFIX}{network}"))
        .await
}

async fn save(state: &AppState, m: &Membership) -> Result<(), AppError> {
    state
        .community_ks
        .insert(format!("{KEY_PREFIX}{}", m.network), m)
        .await
}

/// Every membership record, by network DID.
pub async fn list(state: &AppState) -> Result<Vec<Membership>, AppError> {
    let mut out: Vec<Membership> = state
        .community_ks
        .prefix_iter_raw(KEY_PREFIX.as_bytes().to_vec())
        .await?
        .into_iter()
        .filter_map(|(_, v)| serde_json::from_slice(&v).ok())
        .collect();
    out.sort_by(|a, b| a.network.cmp(&b.network));
    Ok(out)
}

async fn audit(state: &AppState, actor: &str, data: NetworkMembershipChangedData) {
    if let Some(writer) = state.audit_writer.as_ref()
        && let Err(e) = writer
            .write(actor, None, AuditEvent::NetworkMembershipChanged(data))
            .await
    {
        tracing::warn!(error = %e, "could not audit a network membership change");
    }
}

fn audit_data(network: &str, event: &str) -> NetworkMembershipChangedData {
    NetworkMembershipChangedData {
        network: network.to_string(),
        event: event.to_string(),
        role: None,
        group_id: None,
        reason: None,
        message_id: None,
        recipients: None,
    }
}

// --------------------------------------------------------------- the network

/// Read the network's profile at `url` and check it is `network`; sign in as the community.
async fn session(
    url: &str,
    network: &str,
    community: &Community,
) -> Result<(VtnClient, Value), NetError> {
    let mut client = client(url)?;
    let profile = client.profile().await.map_err(refused)?;
    let answering = profile["did"].as_str().unwrap_or_default();
    if answering != network {
        return Err(NetError::Mismatch(format!(
            "the network at {url} answers as {answering}, not {network}"
        )));
    }
    client
        .sign_in_as(community, network, None)
        .await
        .map_err(|e| match e.status() {
            Some(401) => NetError::NotListed(format!("{network} refused the community's sign-in")),
            _ => refused(e),
        })?;
    Ok((client, profile))
}

/// The community's entry at the network, with its listing verified as the network's.
async fn own_listing(
    client: &VtnClient,
    network: &str,
    community: &Community,
    resolver: &Resolver,
) -> Result<Value, NetError> {
    let entry = client
        .get(&format!("/v1/entries/{}", encode_did(&community.did)))
        .await
        .map_err(|e| match e.status() {
            Some(404) => NetError::NotListed(format!("{network} has no entry for this community")),
            _ => refused(e),
        })?;
    let listing = entry["listing"].clone();
    let vsc = verify_signed_by(&listing, network, resolver, Utc::now())
        .await
        .map_err(|e| NetError::NotListed(format!("the listing does not verify: {e}")))?;
    if vsc.subject() != community.did || vsc.predicate() != Some(LISTS_V1) {
        return Err(NetError::NotListed(
            "the network's listing does not list this community".into(),
        ));
    }
    if listing["credentialSubject"]["object"]["value"]["nodeType"].as_str()
        != Some(EntryKind::Community.node_type())
    {
        return Err(NetError::NotListed(
            "the network's listing does not list this party as a community".into(),
        ));
    }
    Ok(listing)
}

/// Register `group` for `role` with the network, and verify the network's acceptance.
async fn register_with(
    state: &AppState,
    client: &VtnClient,
    network: &str,
    community: &Community,
    role: &str,
    group: &crate::groups::Group,
    resolver: &Resolver,
) -> Result<RegisteredGroup, NetError> {
    let endpoint = relay_endpoint(state, &group.group_id).await?;
    let registration = vti_vtn::groups::register_as(
        community,
        network,
        role,
        &group.group_did,
        &endpoint,
        signing_time(),
    )
    .await?;
    let accepted = client
        .post(
            &format!("/v1/entries/{}/groups", encode_did(&community.did)),
            &json!({ "registration": registration }),
        )
        .await
        .map_err(refused)?;
    let acceptance = accepted["acceptance"]["credential"].clone();
    let vsc = verify_signed_by(&acceptance, network, resolver, Utc::now()).await?;
    if vsc.predicate() != Some(GROUP_REGISTERED_V1) || vsc.subject() != group.group_did {
        return Err(NetError::Refused(
            "the network's acceptance does not name the group".into(),
        ));
    }
    Ok(RegisteredGroup {
        role: role.to_string(),
        group_id: group.group_id.clone(),
        group_did: group.group_did.clone(),
        endpoint,
        registration,
        acceptance,
        registered_at: Utc::now(),
    })
}

/// Accept a network's listing: register the assigned groups, acknowledge, verify the grant.
pub async fn join(
    state: &AppState,
    actor: &str,
    url: &str,
    network: &str,
    assignments: &[(String, String)],
) -> Result<Membership, NetError> {
    let community = community(state).await?;
    if load(state, network)
        .await?
        .is_some_and(|m| m.state == State::Acknowledged)
    {
        return Err(NetError::AlreadyMember);
    }
    // Every check that needs nothing from the network, before anything is sent.
    let mut groups = Vec::new();
    for (role, group_id) in assignments {
        groups.push((role.clone(), group(state, group_id).await?));
    }
    let url = url.trim_end_matches('/');
    let (client, profile) = session(url, network, &community).await?;
    for required in profile["roles"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|r| r["required"] == true)
        .filter_map(|r| r["name"].as_str())
    {
        if !assignments.iter().any(|(role, _)| role == required) {
            return Err(NetError::RoleUnassigned(required.to_string()));
        }
    }
    let resolver = resolver(state);
    let listing = own_listing(&client, network, &community, &resolver).await?;

    let mut registered = Vec::new();
    for (role, g) in &groups {
        registered
            .push(register_with(state, &client, network, &community, role, g, &resolver).await?);
    }

    let offer = client
        .get(&format!("/v1/entries/{}/offer", encode_did(&community.did)))
        .await
        .map_err(refused)?;
    if offer["issuer"].as_str() != Some(network)
        || offer["credentialSubject"]["id"].as_str() != Some(community.did.as_str())
    {
        return Err(NetError::Refused(
            "the network's offer is not a membership of this community".into(),
        ));
    }
    let ack = member::acknowledge_as(&offer, &community, signing_time(), None).await?;
    let entry = client
        .post(
            &format!("/v1/entries/{}/acknowledge", encode_did(&community.did)),
            &json!({ "acknowledgement": ack }),
        )
        .await
        .map_err(refused)?;
    let grant = entry["grant"].clone();
    let grant_vc = verify_signed_by(&grant, network, &resolver, Utc::now()).await?;
    let mut claims = ack.clone();
    if let Some(o) = claims.as_object_mut() {
        o.remove("proof");
    }
    let ack_vc: dtg_credentials::DTGCredential = serde_json::from_value(claims)
        .map_err(|e| NetError::Refused(format!("acknowledgement: {e}")))?;
    if grant_vc.subject() != community.did
        || !ack_vc
            .acknowledges(&grant_vc)
            .map_err(|e| NetError::Refused(e.to_string()))?
    {
        return Err(NetError::Refused(
            "the network's grant does not match the acknowledgement".into(),
        ));
    }

    let now = Utc::now();
    let membership = Membership {
        network: network.to_string(),
        url: url.to_string(),
        name: profile["profile"]["name"].as_str().map(str::to_string),
        state: State::Acknowledged,
        listing,
        grant: Some(grant),
        acknowledgement: Some(ack),
        repudiation: None,
        groups: registered,
        joined_at: Some(now),
        updated_at: now,
    };
    save(state, &membership).await?;
    audit(state, actor, audit_data(network, "joined")).await;
    Ok(membership)
}

/// Reject a network's listing of the community (VTI-VTN-012).
pub async fn repudiate(
    state: &AppState,
    actor: &str,
    url: &str,
    network: &str,
    reason: Option<String>,
) -> Result<Membership, NetError> {
    let community = community(state).await?;
    if load(state, network)
        .await?
        .is_some_and(|m| m.state == State::Acknowledged)
    {
        return Err(NetError::IsMember);
    }
    let url = url.trim_end_matches('/');
    let (client, profile) = session(url, network, &community).await?;
    let listing = own_listing(&client, network, &community, &resolver(state)).await?;
    let repudiation = member::repudiate_as(&listing, &community, signing_time()).await?;
    client
        .post(
            &format!("/v1/entries/{}/repudiate", encode_did(&community.did)),
            &json!({ "repudiation": repudiation }),
        )
        .await
        .map_err(refused)?;
    let membership = Membership {
        network: network.to_string(),
        url: url.to_string(),
        name: profile["profile"]["name"].as_str().map(str::to_string),
        state: State::Repudiated,
        listing,
        grant: None,
        acknowledgement: None,
        repudiation: Some(repudiation),
        groups: Vec::new(),
        joined_at: None,
        updated_at: Utc::now(),
    };
    save(state, &membership).await?;
    let mut data = audit_data(network, "repudiated");
    data.reason = reason;
    audit(state, actor, data).await;
    Ok(membership)
}

/// Leave a network by repudiating its grant (VTI-VTN-053).
pub async fn leave(
    state: &AppState,
    actor: &str,
    network: &str,
    reason: Option<String>,
) -> Result<Membership, NetError> {
    let community = community(state).await?;
    let mut membership = load(state, network)
        .await?
        .filter(|m| m.state == State::Acknowledged)
        .ok_or(NetError::NotMember)?;
    let grant = membership.grant.clone().ok_or(NetError::NotMember)?;
    let repudiation = member::repudiate_as(&grant, &community, signing_time()).await?;
    client(&membership.url)?
        .post(
            &format!("/v1/entries/{}/repudiate", encode_did(&community.did)),
            &json!({ "repudiation": repudiation }),
        )
        .await
        .map_err(refused)?;
    membership.state = State::Departed;
    membership.repudiation = Some(repudiation);
    membership.updated_at = Utc::now();
    save(state, &membership).await?;
    let mut data = audit_data(network, "left");
    data.reason = reason;
    audit(state, actor, data).await;
    Ok(membership)
}

/// Register (or re-register) a community group for one of the network's roles.
pub async fn register_group(
    state: &AppState,
    actor: &str,
    network: &str,
    role: &str,
    group_id: &str,
) -> Result<Membership, NetError> {
    let community = community(state).await?;
    let mut membership = load(state, network)
        .await?
        .filter(|m| m.state == State::Acknowledged)
        .ok_or(NetError::NotMember)?;
    let g = group(state, group_id).await?;
    let client = client(&membership.url)?;
    let registered = register_with(
        state,
        &client,
        network,
        &community,
        role,
        &g,
        &resolver(state),
    )
    .await?;
    membership.groups.retain(|r| r.role != role);
    membership.groups.push(registered);
    membership.groups.sort_by(|a, b| a.role.cmp(&b.role));
    membership.updated_at = Utc::now();
    save(state, &membership).await?;
    let mut data = audit_data(network, "groupRegistered");
    data.role = Some(role.to_string());
    data.group_id = Some(group_id.to_string());
    audit(state, actor, data).await;
    Ok(membership)
}

// -------------------------------------------------------------------- relay

/// A network delivers a broadcast for `group_id`. Verified end to end, then pushed to the
/// group's active members. Answers the network's relay receipt.
pub async fn relay(
    state: &AppState,
    group_id: &str,
    envelope: Envelope,
) -> Result<Value, NetError> {
    let g = crate::groups::get(state.directory.ks(), group_id)
        .await?
        .ok_or_else(|| NetError::Rejected(format!("no group {group_id}")))?;
    let verified = relay::verify(
        &envelope,
        &resolver(state),
        Utc::now(),
        relay::DEFAULT_MAX_HOPS,
    )
    .await
    .map_err(|e| NetError::Rejected(e.to_string()))?;
    if verified.to != g.group_did {
        return Err(NetError::Rejected(
            "the envelope is not addressed to this group".into(),
        ));
    }
    let membership = load(state, &verified.from)
        .await?
        .filter(|m| m.state == State::Acknowledged)
        .ok_or_else(|| {
            NetError::Rejected(format!(
                "{} is not a network this community is a member of",
                verified.from
            ))
        })?;
    let registered = membership
        .groups
        .iter()
        .find(|r| r.group_id == group_id)
        .ok_or_else(|| {
            NetError::Rejected(format!(
                "this community did not register {group_id} with {}",
                verified.from
            ))
        })?;
    let first = state
        .community_ks
        .insert_if_absent(format!("{SEEN_PREFIX}{}", verified.id), &Utc::now())
        .await?;
    if !first {
        return Ok(json!({ "status": "duplicate" }));
    }
    let payload = json!({
        "network": verified.from,
        "role": registered.role,
        "groupId": group_id,
        "envelope": envelope,
    });
    let members = active_members(state, group_id).await?;
    let mut queued = 0u32;
    for did in &members {
        match push_document(state, did, NOTICE_TYPE, payload.clone(), Thread::New).await {
            Ok(_) => queued += 1,
            Err(e) => tracing::warn!(member = %did, error = %e, "could not queue a network notice"),
        }
    }
    let mut data = audit_data(&verified.from, "broadcastRelayed");
    data.role = Some(registered.role.clone());
    data.group_id = Some(group_id.to_string());
    data.message_id = Some(verified.id.clone());
    data.recipients = Some(queued);
    audit(state, &verified.from, data).await;
    tracing::info!(
        network = %verified.from,
        group = group_id,
        members = members.len(),
        queued,
        "network broadcast relayed to a group"
    );
    Ok(json!({ "status": "delivered" }))
}

// ----------------------------------------------------------------- evidence

/// The chain links `caller` may present: for each group they are an active member of, and
/// each network that group is registered with.
pub async fn evidence(
    state: &AppState,
    caller: &str,
    group_filter: Option<&str>,
    network_filter: Option<&str>,
) -> Result<Vec<Value>, AppError> {
    let mut links = Vec::new();
    for m in list(state).await? {
        if m.state != State::Acknowledged || network_filter.is_some_and(|n| n != m.network) {
            continue;
        }
        for g in &m.groups {
            if group_filter.is_some_and(|f| f != g.group_id) {
                continue;
            }
            if !active_members(state, &g.group_id)
                .await?
                .iter()
                .any(|d| d == caller)
            {
                continue;
            }
            links.push(json!({
                "groupId": g.group_id,
                "groupDid": g.group_did,
                "network": m.network,
                "role": g.role,
                "registration": g.registration,
                "acceptance": g.acceptance,
            }));
        }
    }
    Ok(links)
}

#[cfg(test)]
mod tests;
