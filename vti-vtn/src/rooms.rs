//! Network room passes (design §5.4).
//!
//! A network can open rooms for a role: a "Pandemic Response" room for everyone in the
//! network's `admins` groups. A person is admitted on evidence they carry, checked at the
//! time, so the network never caches anyone's roster:
//!
//! 1. Their **membership credential** from a group (group → person).
//! 2. For each network between that group and this one, a **chain link**:
//!    - the group owner's `servesRole` registration;
//!    - the accepting network's `groupRegistered` acceptance.
//!
//!    The member community hands these to its group's members.
//! 3. The last group in the chain is registered directly with this network, for the room's
//!    role, by a current member.
//!
//! The network then issues a short-lived **room pass**: an authority credential (VAC) for
//! `room:enter`, scoped to the room.

use chrono::{DateTime, Duration, Utc};
use dtg_credentials::{DTGCredential, DTGCredentialType, IssuerScope, digests_match};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::credentials::new_credential_id;
use crate::error::{Result, VtnError};
use crate::groups::verify_registration;
use crate::verify::{KeyResolver, verify_signed_by};
use crate::vocab::GROUP_REGISTERED_V1;

/// The action a room pass grants.
pub const ROOM_ENTER: &str = "room:enter";
/// The longest chain followed.
pub const MAX_CHAIN: usize = 8;

/// One step up the chain: a group's registration with a network, and that network's
/// acceptance.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct ChainLink {
    pub registration: Value,
    pub acceptance: Value,
}

/// What a verified link establishes: `network` accepted `group` for its role `role`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedLink {
    pub network: String,
    pub group: String,
    pub role: String,
    pub owner: String,
}

/// The room scope a pass is for: a DID URL on the network's DID.
pub fn room_scope(network: &str, room: &str) -> String {
    format!("{network}#room-{room}")
}

/// Verify a chain link's signatures and binding. Status is the caller's to check.
pub async fn verify_link(
    link: &ChainLink,
    resolver: &dyn KeyResolver,
    at: DateTime<Utc>,
) -> Result<VerifiedLink> {
    let network = link
        .acceptance
        .get("issuer")
        .and_then(Value::as_str)
        .ok_or_else(|| VtnError::Rejected("acceptance has no issuer".into()))?
        .to_string();
    let acceptance = verify_signed_by(&link.acceptance, &network, resolver, at).await?;
    if !matches!(acceptance.type_(), DTGCredentialType::Statement)
        || acceptance.predicate() != Some(GROUP_REGISTERED_V1)
    {
        return Err(VtnError::Rejected(format!(
            "not a {GROUP_REGISTERED_V1} acceptance"
        )));
    }
    let digest = acceptance
        .subject_digest()
        .ok_or_else(|| VtnError::Rejected("acceptance names no registration".into()))?;
    if !digests_match(
        digest,
        &dtg_credentials::digest_multibase_json(&link.registration)?,
    )? {
        return Err(VtnError::Rejected(
            "acceptance is for another registration".into(),
        ));
    }
    let owner = link
        .registration
        .get("issuer")
        .and_then(Value::as_str)
        .ok_or_else(|| VtnError::Rejected("registration has no issuer".into()))?
        .to_string();
    let reg = verify_registration(&link.registration, &owner, &network, resolver, at).await?;
    if acceptance.subject() != reg.group {
        return Err(VtnError::Rejected("acceptance names another group".into()));
    }
    Ok(VerifiedLink {
        network,
        group: reg.group,
        role: reg.role,
        owner,
    })
}

/// Verify a person's membership credential from a group: a community-issued VMC (grant)
/// naming `holder`. Returns the group (its issuer). Status is the caller's to check.
pub async fn verify_group_membership(
    vmc: &Value,
    holder: &str,
    resolver: &dyn KeyResolver,
    at: DateTime<Utc>,
) -> Result<String> {
    let group = vmc
        .get("issuer")
        .and_then(Value::as_str)
        .ok_or_else(|| VtnError::Rejected("membership credential has no issuer".into()))?
        .to_string();
    let credential = verify_signed_by(vmc, &group, resolver, at).await?;
    if !matches!(credential.type_(), DTGCredentialType::Membership)
        || credential.subject_digest().is_some()
    {
        return Err(VtnError::Rejected(
            "not a group-issued membership credential".into(),
        ));
    }
    if credential.subject() != holder {
        return Err(VtnError::Rejected(
            "the membership credential names someone else".into(),
        ));
    }
    Ok(group)
}

/// The (unsigned) room pass.
pub fn room_pass(
    network: &str,
    holder: &str,
    room: &str,
    valid_from: DateTime<Utc>,
    lifetime: Duration,
) -> Result<DTGCredential> {
    Ok(DTGCredential::new_vac(
        network.to_string(),
        IssuerScope::Public,
        holder.to_string(),
        room_scope(network, room),
        vec![ROOM_ENTER.to_string()],
        valid_from,
        valid_from + lifetime,
    )?
    .with_id(new_credential_id()))
}
