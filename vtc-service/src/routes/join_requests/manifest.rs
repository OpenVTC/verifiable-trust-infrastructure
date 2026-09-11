//! Pre-submit discovery — the join manifest (`vtc/join-requests/manifest/0.1`
//! and `/0.2`) — plus a shared `manifest_inner` the Trust Task dispatcher and
//! the DIDComm handler call into.
//!
//! Returns the community's registered Accepts criteria — each a named
//! DCQL Presentation Definition — plus this VTC's DID, so a prospective
//! applicant can assemble a presentation before opening a thread. A
//! stateless, unauthenticated public read: no thread, no challenge, no
//! audit.
//!
//! ## 0.1 and 0.2
//!
//! 0.2 adds, per criterion, the peer-vetting requirements the community
//! registered and a `requirementsDigest` over the criterion. An applicant
//! records the digest when it starts gathering statements, so a change to the
//! requirements mid-application is detectable rather than a surprise at submit
//! (OpenVTC `docs/design/vetting-process.md` §6.3).
//!
//! A 0.1 answer carries neither member: the version the applicant asked for
//! decides the shape, and a 0.1 reader is not handed members its version does
//! not define.

use axum::Json;
use axum::extract::State;

use vta_sdk::protocols::join_requests::{JoinRequestManifestResponseBody, ManifestCriterion};
use vta_sdk::vetting::requirements::requirements_digest;
use vti_common::error::AppError;

use crate::schemas::accepts::{AcceptsCriterion, list_accepts};
use crate::server::AppState;

/// Which manifest version a caller asked for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManifestVersion {
    /// `vtc/join-requests/manifest/0.1` — criteria only.
    V0_1,
    /// `vtc/join-requests/manifest/0.2` — criteria with their vetting
    /// requirements and a `requirementsDigest`.
    V0_2,
}

/// GET /join-requests/manifest — pre-submit discovery of the community's
/// Accepts criteria. Public, stateless read.
#[utoipa::path(
    get, path = "/join-requests/manifest", tag = "join-requests",
    responses(
        (status = 200, description = "Community join evidence requirements", body = JoinRequestManifestResponseBody),
    ),
)]
pub async fn manifest(
    State(state): State<AppState>,
) -> Result<Json<JoinRequestManifestResponseBody>, AppError> {
    Ok(Json(manifest_inner(&state, ManifestVersion::V0_1).await?))
}

/// Shared discovery read for REST + DIDComm: the community's join
/// evidence requirements, in the shape `version` defines.
pub async fn manifest_inner(
    state: &AppState,
    version: ManifestVersion,
) -> Result<JoinRequestManifestResponseBody, AppError> {
    let community_did = state
        .config
        .read()
        .await
        .vtc_did
        .clone()
        .filter(|d| !d.is_empty())
        .ok_or_else(|| AppError::Internal("VTC DID not configured".into()))?;

    let criteria = list_accepts(&state.schemas_ks)
        .await?
        .into_iter()
        .map(|c| manifest_criterion(c, version))
        .collect::<Result<Vec<_>, _>>()?;

    Ok(JoinRequestManifestResponseBody {
        community_did,
        criteria,
    })
}

/// Project a stored criterion into the manifest shape `version` defines.
///
/// The 0.2 digest is computed over the criterion exactly as it is delivered,
/// minus the digest member, so an applicant recomputes it from what it
/// received with [`requirements_digest`] and gets the same value.
pub fn manifest_criterion(
    stored: AcceptsCriterion,
    version: ManifestVersion,
) -> Result<ManifestCriterion, AppError> {
    let mut criterion = ManifestCriterion {
        id: stored.id,
        description: stored.description,
        presentation_definition: stored.query,
        vetting: None,
        requirements_digest: None,
    };
    if version == ManifestVersion::V0_2 {
        criterion.vetting = stored.vetting;
        let delivered = serde_json::to_value(&criterion)
            .map_err(|e| AppError::Internal(format!("manifest criterion encode: {e}")))?;
        let digest = requirements_digest(&delivered)
            .map_err(|e| AppError::Internal(format!("requirements digest: {e:?}")))?;
        criterion.requirements_digest = Some(digest);
    }
    Ok(criterion)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use serde_json::json;
    use vta_sdk::protocols::vetting::VettingRequirements;

    fn requirements(min: u32) -> VettingRequirements {
        serde_json::from_value(json!({
            "version": "0.1",
            "statementType": "https://firstperson.network/endorsements/identity-vetting/0.1",
            "minStatements": min,
            "acceptedMethods": ["in-person", "video"],
            "eligibleVetters": { "role": "vetter" }
        }))
        .unwrap()
    }

    fn stored(vetting: Option<VettingRequirements>) -> AcceptsCriterion {
        AcceptsCriterion {
            id: "kernel-developer".into(),
            query: json!({ "credentials": [{ "id": "vetting", "format": "ldp_vc" }] }),
            description: Some("Two vetters".into()),
            vetting,
            created_at: Utc::now(),
            created_by_did: "did:key:zAdmin".into(),
        }
    }

    #[test]
    fn a_0_1_answer_carries_no_vetting_members() {
        let c = manifest_criterion(stored(Some(requirements(2))), ManifestVersion::V0_1).unwrap();
        let v = serde_json::to_value(&c).unwrap();
        assert!(v.get("vetting").is_none());
        assert!(v.get("requirementsDigest").is_none());
    }

    #[test]
    fn a_0_2_digest_recomputes_from_what_the_applicant_receives() {
        let c = manifest_criterion(stored(Some(requirements(2))), ManifestVersion::V0_2).unwrap();
        let received = serde_json::to_value(&c).unwrap();
        assert_eq!(received["vetting"]["minStatements"], 2);
        assert_eq!(
            received["requirementsDigest"].as_str().unwrap(),
            requirements_digest(&received).unwrap(),
            "the digest must be checkable by the applicant from the delivered criterion"
        );
    }

    #[test]
    fn changing_the_requirements_changes_the_digest() {
        let two = manifest_criterion(stored(Some(requirements(2))), ManifestVersion::V0_2).unwrap();
        let three =
            manifest_criterion(stored(Some(requirements(3))), ManifestVersion::V0_2).unwrap();
        assert_ne!(two.requirements_digest, three.requirements_digest);
    }

    #[test]
    fn a_criterion_without_vetting_still_gets_a_digest_under_0_2() {
        let c = manifest_criterion(stored(None), ManifestVersion::V0_2).unwrap();
        assert!(c.vetting.is_none());
        assert!(c.requirements_digest.is_some());
    }
}
