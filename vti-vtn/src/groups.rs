//! Network roles and the groups members register for them.
//!
//! A network defines **roles**, e.g. `admins` or `notifications`. A member registers one of
//! its own groups to serve a role. The member signs a `servesRole` VSC (member → group),
//! naming the network, the role and the endpoint that accepts deliveries for the group. The
//! network answers with a `groupRegistered` VSC (network → group) bound to that
//! registration's digest.
//!
//! What a group is depends on the member:
//! - **A VTC** registers one of its groups (its own `did:webvh`). The VTC relays deliveries
//!   to that group's members.
//! - **A VTN** registers its **network group** for a role: the set of groups its own members
//!   registered. Deliveries then cascade one network at a time, and no network ever holds
//!   another's roster.
//!
//! **Assumption A14:** a network group is identified by a DID URL on the network's DID,
//! `<network DID>#role-<name>`, not a DID of its own minted by the VTA.

use chrono::{DateTime, Utc};
use dtg_credentials::statement::StatementObject;
use dtg_credentials::{DTGCredential, DTGCredentialType, IssuerScope};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::credentials::new_credential_id;
use crate::error::{Result, VtnError};
use crate::identity::Identity;
use crate::model::Issued;
use crate::verify::{KeyResolver, verify_signed_by};
use crate::vocab::{GROUP_REGISTERED_V1, SERVES_ROLE_V1};

/// A role the network defines.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RoleDef {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Admission requires the member to have registered a group for this role.
    #[serde(default)]
    pub required: bool,
}

/// The identifier of `network`'s network group for `role` (A14).
pub fn network_group_id(network: &str, role: &str) -> String {
    format!("{network}#role-{role}")
}

/// The network a network-group identifier belongs to, if it is one.
pub fn network_of_group(group: &str) -> Option<&str> {
    group
        .split_once('#')
        .filter(|(_, f)| f.starts_with("role-"))
        .map(|(did, _)| did)
}

/// Role names are short identifiers: they appear in URLs and DID fragments.
pub fn valid_role_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
}

/// What a registration says.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Registration {
    pub member: String,
    pub group: String,
    pub role: String,
    pub endpoint: String,
}

/// A group a member registered with this network, and the network's acceptance.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct RegisteredGroup {
    pub member: String,
    pub role: String,
    pub group: String,
    pub endpoint: String,
    /// The member's `servesRole` VSC.
    pub registration: Value,
    /// The network's `groupRegistered` VSC.
    pub acceptance: Issued,
    pub registered_at: DateTime<Utc>,
}

/// Member side: the (unsigned) registration of `group` to serve `role` in `network`,
/// deliveries to `endpoint`, as `member`.
pub fn registration(
    member: &str,
    network: &str,
    role: &str,
    group: &str,
    endpoint: &str,
    valid_from: DateTime<Utc>,
) -> Result<DTGCredential> {
    if !valid_role_name(role) {
        return Err(VtnError::Rejected(format!("invalid role name {role:?}")));
    }
    Ok(DTGCredential::new_vsc(
        member.to_string(),
        IssuerScope::Public,
        group.to_string(),
        SERVES_ROLE_V1,
        StatementObject::Value(json!({ "network": network, "role": role, "endpoint": endpoint })),
        valid_from,
        None,
    )?
    .with_id(new_credential_id()))
}

/// [`registration`], signed by any [`crate::identity::Party`].
pub async fn register_as(
    member: &dyn crate::identity::Party,
    network: &str,
    role: &str,
    group: &str,
    endpoint: &str,
    valid_from: DateTime<Utc>,
) -> Result<Value> {
    let vsc = registration(member.did(), network, role, group, endpoint, valid_from)?;
    crate::identity::sign_credential_as(member, &vsc).await
}

/// Member side: register `group` to serve `role` in `network`, deliveries to `endpoint`.
pub async fn register(
    member: &Identity,
    network: &str,
    role: &str,
    group: &str,
    endpoint: &str,
    valid_from: DateTime<Utc>,
) -> Result<DTGCredential> {
    if !valid_role_name(role) {
        return Err(VtnError::Rejected(format!("invalid role name {role:?}")));
    }
    let mut vsc = DTGCredential::new_vsc(
        member.did().to_string(),
        IssuerScope::Public,
        group.to_string(),
        SERVES_ROLE_V1,
        StatementObject::Value(json!({ "network": network, "role": role, "endpoint": endpoint })),
        valid_from,
        None,
    )?
    .with_id(new_credential_id());
    member.sign_credential(&mut vsc).await?;
    Ok(vsc)
}

/// Network side: verify a registration from `member` addressed to `network`.
pub async fn verify_registration(
    registration: &Value,
    member: &str,
    network: &str,
    resolver: &dyn KeyResolver,
    at: DateTime<Utc>,
) -> Result<Registration> {
    let vsc = verify_signed_by(registration, member, resolver, at).await?;
    if !matches!(vsc.type_(), DTGCredentialType::Statement)
        || vsc.predicate() != Some(SERVES_ROLE_V1)
    {
        return Err(VtnError::Rejected(format!(
            "not a {SERVES_ROLE_V1} statement"
        )));
    }
    let value = vsc
        .statement()
        .and_then(|s| s.object.value())
        .ok_or_else(|| VtnError::Rejected("registration carries no value".into()))?;
    let field = |name: &str| {
        value
            .get(name)
            .and_then(Value::as_str)
            .map(str::to_string)
            .ok_or_else(|| VtnError::Rejected(format!("registration has no `{name}`")))
    };
    if field("network")? != network {
        return Err(VtnError::Rejected(
            "registration names another network".into(),
        ));
    }
    let role = field("role")?;
    if !valid_role_name(&role) {
        return Err(VtnError::Rejected(format!("invalid role name {role:?}")));
    }
    let endpoint = field("endpoint")?;
    if !(endpoint.starts_with("https://") || endpoint.starts_with("http://")) {
        return Err(VtnError::Rejected("endpoint must be an http(s) URL".into()));
    }
    // A member may register its own network group, or a group of its own; it may not
    // register another network's network group.
    let group = vsc.subject().to_string();
    if let Some(owner) = network_of_group(&group)
        && owner != member
    {
        return Err(VtnError::Rejected(
            "a network group can only be registered by its own network".into(),
        ));
    }
    Ok(Registration {
        member: member.to_string(),
        group,
        role,
        endpoint,
    })
}

/// Network side: the (unsigned) acceptance of a verified registration.
pub fn acceptance(
    network: &str,
    group: &str,
    registration: &Value,
    valid_from: DateTime<Utc>,
    credential_status: Value,
) -> Result<DTGCredential> {
    let digest = dtg_credentials::digest_multibase_json(registration)?;
    Ok(DTGCredential::new_vsc(
        network.to_string(),
        IssuerScope::Public,
        group.to_string(),
        GROUP_REGISTERED_V1,
        StatementObject::DigestMultibase(digest),
        valid_from,
        None,
    )?
    .with_id(new_credential_id())
    .with_credential_status(credential_status))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verify::LocalDidKeyResolver;

    #[test]
    fn network_group_ids_round_trip() {
        let id = network_group_id("did:key:z6Mkx", "admins");
        assert_eq!(id, "did:key:z6Mkx#role-admins");
        assert_eq!(network_of_group(&id), Some("did:key:z6Mkx"));
        assert_eq!(network_of_group("did:webvh:abc:group"), None);
        assert!(
            valid_role_name("security-contacts")
                && !valid_role_name("Admins")
                && !valid_role_name("")
        );
    }

    #[tokio::test]
    async fn registration_round_trip_and_refusals() {
        let member = Identity::generate();
        let network = Identity::generate();
        let at = Utc::now() - chrono::Duration::seconds(5);
        let group = network_group_id(member.did(), "admins");
        let vsc = register(
            &member,
            network.did(),
            "admins",
            &group,
            "https://m.example/v1/relay/admins",
            at,
        )
        .await
        .unwrap();
        let json = serde_json::to_value(&vsc).unwrap();
        let reg = verify_registration(
            &json,
            member.did(),
            network.did(),
            &LocalDidKeyResolver,
            Utc::now(),
        )
        .await
        .unwrap();
        assert_eq!(reg.role, "admins");
        assert_eq!(reg.group, group);

        // Addressed to another network.
        assert!(
            verify_registration(
                &json,
                member.did(),
                "did:key:zOther",
                &LocalDidKeyResolver,
                Utc::now()
            )
            .await
            .is_err()
        );

        // Someone else's network group.
        let other = Identity::generate();
        let stolen = register(
            &member,
            network.did(),
            "admins",
            &network_group_id(other.did(), "admins"),
            "https://m.example/",
            at,
        )
        .await
        .unwrap();
        assert!(
            verify_registration(
                &serde_json::to_value(&stolen).unwrap(),
                member.did(),
                network.did(),
                &LocalDidKeyResolver,
                Utc::now()
            )
            .await
            .is_err()
        );
    }
}
