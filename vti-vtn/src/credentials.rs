//! The DTG credentials that evidence VTN relationships.
//!
//! | Relationship | Credential | Issuer → subject |
//! |---|---|---|
//! | listing | VSC [`LISTS_V1`] | network → party |
//! | membership offer / grant | VMC (no digest) | network → party |
//! | membership acknowledgement | VMC (`digestMultibase` of grant) | party → network |
//! | repudiation / departure | VSC [`REPUDIATES_V1`] | party → network |
//!
//! Network-side builders return **unsigned** credentials; the caller signs with
//! [`Identity::sign_credential`]. The `member` module holds what a listed party runs.

use chrono::{DateTime, Utc};
use dtg_credentials::statement::StatementObject;
use dtg_credentials::{DTGCredential, IssuerScope};
use serde_json::{Value, json};

use crate::error::Result;
use crate::identity::Identity;
use crate::model::{EntryKind, Framework};
use crate::vocab::{LISTS_V1, REPUDIATES_V1};

/// A fresh credential `id`.
pub fn new_credential_id() -> String {
    format!("urn:uuid:{}", uuid::Uuid::new_v4())
}

/// The listing VSC: the network attests that it lists `subject` as `kind`, under
/// `framework`. One-sided by design (VTI-VTN-010): it needs nothing from the subject and
/// establishes nothing about it (assumption A1).
pub fn listing_vsc(
    network: &str,
    subject: &str,
    kind: EntryKind,
    framework: &Framework,
    valid_from: DateTime<Utc>,
    credential_status: Value,
) -> Result<DTGCredential> {
    let object = StatementObject::Value(json!({
        "kind": kind,
        "framework": { "iri": framework.iri, "version": framework.version },
    }));
    Ok(DTGCredential::new_vsc(
        network.to_string(),
        IssuerScope::Public,
        subject.to_string(),
        LISTS_V1,
        object,
        valid_from,
        None,
    )?
    .with_id(new_credential_id())
    .with_credential_status(credential_status))
}

/// The membership offer: the network's VMC grant to `subject`, **unsigned**.
///
/// **Assumption A2.** DTG Core requires the grant to exist before the acknowledgement,
/// which carries its digest; VTI-VTN-013 forbids issuing a membership credential to a
/// party that has not acknowledged. Both hold if the network publishes the grant's claims
/// unsigned, the party signs an acknowledgement over their digest, and only then does the
/// network sign the grant. The digest excludes `proof`, so the signed grant matches the
/// acknowledgement byte for byte, and no signed membership credential ever names a party
/// that has not agreed.
pub fn membership_offer(
    network: &str,
    subject: &str,
    valid_from: DateTime<Utc>,
    valid_until: Option<DateTime<Utc>>,
    credential_status: Value,
) -> DTGCredential {
    DTGCredential::new_vmc(
        network.to_string(),
        subject.to_string(),
        valid_from,
        valid_until,
        false,
    )
    .with_id(new_credential_id())
    .with_credential_status(credential_status)
}

/// What a listed party (a VTC, or a VTN listed by another network) runs.
pub mod member {
    use super::*;

    /// Acknowledge a membership offer: the member-issued VMC, signed by `member`.
    ///
    /// A community's identifier is `public` (DTG Core, VMC), so the acknowledgement
    /// declares `public` too. `valid_until` must fall within the offer's; `None` takes the
    /// offer's own, so the acknowledgement lapses with the grant it answers.
    pub async fn acknowledge(
        offer: &Value,
        member: &Identity,
        valid_from: DateTime<Utc>,
        valid_until: Option<DateTime<Utc>>,
    ) -> Result<DTGCredential> {
        let valid_until = match valid_until {
            Some(until) => Some(until),
            None => offer
                .get("validUntil")
                .and_then(Value::as_str)
                .map(|s| {
                    DateTime::parse_from_rfc3339(s)
                        .map(|d| d.with_timezone(&Utc))
                        .map_err(|e| crate::VtnError::Rejected(format!("offer validUntil: {e}")))
                })
                .transpose()?,
        };
        let mut ack = DTGCredential::new_member_vmc_for(
            offer,
            member.did(),
            IssuerScope::Public,
            valid_from,
            valid_until,
        )?
        .with_id(new_credential_id());
        member.sign_credential(&mut ack).await?;
        Ok(ack)
    }

    /// Repudiate `target` (a listing VSC, or a membership grant to depart), signed by
    /// `member`. The subject is the network that issued `target`.
    pub async fn repudiate(
        target: &Value,
        member: &Identity,
        valid_from: DateTime<Utc>,
    ) -> Result<DTGCredential> {
        let network = target
            .get("issuer")
            .and_then(Value::as_str)
            .ok_or_else(|| crate::VtnError::Rejected("target has no issuer".into()))?;
        let digest = dtg_credentials::digest_multibase_json(target)?;
        let mut vsc = DTGCredential::new_vsc(
            member.did().to_string(),
            IssuerScope::Public,
            network.to_string(),
            REPUDIATES_V1,
            StatementObject::DigestMultibase(digest),
            valid_from,
            None,
        )?
        .with_id(new_credential_id());
        member.sign_credential(&mut vsc).await?;
        Ok(vsc)
    }
}
