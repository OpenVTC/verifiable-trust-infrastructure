//! Network roles and the groups members register for them.
//!
//! A network defines **roles**, e.g. `admins` or `notifications`. A member registers one of
//! its own groups to serve a role by sending a signed `vtn/groups/register` Trust Task
//! naming the role, the group and the endpoint that accepts deliveries for it. The signed
//! request is the registration. The network answers with a `groupRegistered` VSC
//! (network → group) bound to the request's digest, revocable through the network's
//! status list: the credential is the proof, the request only asks (A19).
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
use dtg_credentials::{DTGCredential, IssuerScope};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::credentials::new_credential_id;
use crate::error::{Result, VtnError};
use crate::identity::Identity;
use crate::model::Issued;
use crate::specs::groups::register::v0_1 as register;
use crate::verify::{AUTHENTICATION, KeyResolver, verify_document};
use crate::vocab::GROUP_REGISTERED_V1;

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
    /// The member's signed `vtn/groups/register` request.
    pub registration: Value,
    /// The network's `groupRegistered` VSC.
    pub acceptance: Issued,
    pub registered_at: DateTime<Utc>,
}

/// How far a registration's `issuedAt` may run ahead of the verifier's clock.
const CLOCK_SKEW: chrono::Duration = chrono::Duration::minutes(5);

/// Member side: the payload registering `group` to serve `role`, deliveries to `endpoint`.
pub fn registration(role: &str, group: &str, endpoint: &str) -> Result<register::Payload> {
    if !valid_role_name(role) {
        return Err(VtnError::Rejected(format!("invalid role name {role:?}")));
    }
    if !endpoint.starts_with("https://") {
        return Err(VtnError::Rejected("endpoint must be an https URL".into()));
    }
    serde_json::from_value(json!({ "role": role, "group": group, "endpoint": endpoint }))
        .map_err(|e| VtnError::Rejected(format!("registration: {e}")))
}

/// Member side: `member`'s signed `vtn/groups/register` request to `network`. The signed
/// document is the registration: the network's acceptance binds its
/// [`registration_digest`], and a room-pass chain carries it.
pub async fn register_as(
    member: &dyn crate::identity::Party,
    network: &str,
    role: &str,
    group: &str,
    endpoint: &str,
) -> Result<Value> {
    let payload = registration(role, group, endpoint)?;
    crate::request::sign_request(member, network, &payload).await
}

/// [`register_as`] for a local [`Identity`].
pub async fn register(
    member: &Identity,
    network: &str,
    role: &str,
    group: &str,
    endpoint: &str,
) -> Result<Value> {
    register_as(member, network, role, group, endpoint).await
}

/// The registration digest: SHA-256 over the JCS form of the signed request **including**
/// its `proof` (`vtn/groups/register/0.1`, *Registration digest*). A re-signed or unsigned
/// copy is a different registration.
pub fn registration_digest(registration: &Value) -> Result<String> {
    use sha2::{Digest, Sha256};
    let canonical = serde_json_canonicalizer::to_vec(registration)
        .map_err(|e| VtnError::Rejected(format!("canonicalise the registration: {e}")))?;
    let digest = Sha256::digest(&canonical);
    let mut multihash = Vec::with_capacity(2 + digest.len());
    multihash.extend_from_slice(&[0x12, 0x20]);
    multihash.extend_from_slice(&digest);
    Ok(multibase::encode(multibase::Base::Base58Btc, multihash))
}

/// Verify a registration: a `vtn/groups/register` request from `member` to `network`,
/// signed by `member` for `authentication`, issued no later than `at` (allowing for clock
/// skew). Its freshness at arrival is the receiving spine's to check; a registration in a
/// room-pass chain is old by design and stands until its acceptance is revoked.
pub async fn verify_registration(
    registration: &Value,
    member: &str,
    network: &str,
    resolver: &dyn KeyResolver,
    at: DateTime<Utc>,
) -> Result<Registration> {
    let member_of = |name: &str| registration.get(name).and_then(Value::as_str);
    if member_of("type") != Some(<register::Payload as trust_tasks_rs::Payload>::TYPE_URI) {
        return Err(VtnError::Rejected(
            "not a vtn/groups/register/0.1 request".into(),
        ));
    }
    if member_of("issuer") != Some(member) {
        return Err(VtnError::Rejected(format!(
            "registration issued by {}, expected {member}",
            registration["issuer"]
        )));
    }
    if member_of("recipient") != Some(network) {
        return Err(VtnError::Rejected(
            "registration names another network".into(),
        ));
    }
    let issued_at: DateTime<Utc> = member_of("issuedAt")
        .and_then(|t| t.parse().ok())
        .ok_or_else(|| VtnError::Rejected("registration has no issuedAt".into()))?;
    if issued_at > at + CLOCK_SKEW {
        return Err(VtnError::Rejected(
            "registration is issued in the future".into(),
        ));
    }
    verify_document(registration, member, AUTHENTICATION, resolver).await?;
    let payload: register::Payload = serde_json::from_value(registration["payload"].clone())
        .map_err(|e| VtnError::Rejected(format!("registration payload: {e}")))?;
    let role = payload.role.to_string();
    let group = payload.group.to_string();
    let endpoint = payload.endpoint.to_string();
    if !valid_role_name(&role) {
        return Err(VtnError::Rejected(format!("invalid role name {role:?}")));
    }
    if !endpoint.starts_with("https://") {
        return Err(VtnError::Rejected("endpoint must be an https URL".into()));
    }
    // A member may register its own network group, or a group of its own; it may not
    // register another network's network group.
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

/// Network side: the (unsigned) acceptance of a verified registration, bound to its
/// [`registration_digest`] and revocable through `credential_status`.
pub fn acceptance(
    network: &str,
    group: &str,
    registration: &Value,
    valid_from: DateTime<Utc>,
    credential_status: Value,
) -> Result<DTGCredential> {
    let digest = registration_digest(registration)?;
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
        let group = network_group_id(member.did(), "admins");
        let json = register(
            &member,
            network.did(),
            "admins",
            &group,
            "https://m.example/v1/relay/admins",
        )
        .await
        .unwrap();
        assert_eq!(json["proof"]["proofPurpose"], AUTHENTICATION);
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

        // Tampered after signing.
        let mut tampered = json.clone();
        tampered["payload"]["endpoint"] = json!("https://evil.example/");
        assert!(
            verify_registration(
                &tampered,
                member.did(),
                network.did(),
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
        )
        .await
        .unwrap();
        assert!(
            verify_registration(
                &stolen,
                member.did(),
                network.did(),
                &LocalDidKeyResolver,
                Utc::now()
            )
            .await
            .is_err()
        );

        // Not https.
        assert!(registration("admins", &group, "http://m.example/").is_err());
    }

    #[tokio::test]
    async fn the_registration_digest_covers_the_proof() {
        let member = Identity::generate();
        let group = network_group_id(member.did(), "admins");
        let signed = register(
            &member,
            "did:key:zNet",
            "admins",
            &group,
            "https://m.example/",
        )
        .await
        .unwrap();
        let mut unsigned = signed.clone();
        unsigned.as_object_mut().unwrap().remove("proof");
        assert_ne!(
            registration_digest(&signed).unwrap(),
            registration_digest(&unsigned).unwrap()
        );
        assert_ne!(
            registration_digest(&signed).unwrap(),
            dtg_credentials::digest_multibase_json(&signed).unwrap()
        );
    }
}
