//! Pre-submit discovery — the join manifest (`vtc/join-requests/manifest/0.1`
//! and `/0.2`) — plus the shared reads the Trust Task dispatcher and the
//! DIDComm handler call into.
//!
//! Returns the community's registered Accepts criteria — each a named
//! DCQL Presentation Definition — plus this VTC's DID, so a prospective
//! applicant can assemble a presentation before opening a thread. A
//! stateless, unauthenticated public read: no thread, no challenge, no
//! audit.
//!
//! Both answers are the generated `manifest::v0_1::Response` and
//! `manifest::v0_2::Response`; this module only projects stored criteria onto
//! them.
//!
//! ## 0.1 and 0.2
//!
//! 0.2 adds, per criterion, the peer-vetting requirements the community
//! registered and a `requirementsDigest` over the criterion, and the
//! community's branding. An applicant records the digest when it starts
//! gathering statements, so a change to the requirements mid-application is
//! detectable rather than a surprise at submit (OpenVTC
//! `docs/design/vetting-process.md` §6.3).
//!
//! A 0.1 answer carries none of those members: the version the applicant asked
//! for decides the shape, and a 0.1 reader is not handed members its version
//! does not define.

use axum::Json;
use axum::extract::State;
use serde_json::{Map, Value};

use vta_sdk::openapi::{JoinManifest01Response, JoinManifest02Response};
use vta_sdk::protocols::join_requests::manifest::{v0_1, v0_2};
use vta_sdk::protocols::vetting::{CheckShape, read_branding};
use vta_sdk::vetting::requirements::requirements_digest;
use vti_common::auth::AdminAuth;
use vti_common::error::AppError;

use crate::community::branding;
use crate::schemas::accepts::{AcceptsCriterion, list_accepts};
use crate::server::AppState;

/// GET /join-requests/manifest — the join manifest (0.2) as applicants receive
/// it, for an admin session.
///
/// Applicants read the manifest as a Trust Task document over
/// `POST /v1/trust-tasks`. The admin console reads the same answer here, under
/// the same `vtc/join-requests/manifest/0.2` task, to show each criterion's
/// vetting requirements and `requirementsDigest` — criteria are registered
/// through `/v1/schemas/accepts`, which carries no digest.
#[utoipa::path(
    get, path = "/join-requests/manifest",
    operation_id = "joinRequestManifestShow", tag = "join-requests",
    security(("bearer_jwt" = [])),
    responses(
        (status = 200, description = "The join manifest (0.2): each criterion with its vetting requirements and requirementsDigest, and the branding", body = JoinManifest02Response),
        (status = 401, description = "Missing or invalid bearer token"),
        (status = 403, description = "Caller is not an admin"),
    ),
)]
pub async fn admin_manifest(
    _admin: AdminAuth,
    State(state): State<AppState>,
) -> Result<Json<JoinManifest02Response>, AppError> {
    Ok(Json(manifest_v0_2(&state).await?.into()))
}

/// Which manifest version a caller asked for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManifestVersion {
    /// `vtc/join-requests/manifest/0.1` — criteria only.
    V0_1,
    /// `vtc/join-requests/manifest/0.2` — criteria with their vetting
    /// requirements and a `requirementsDigest`, and the branding.
    V0_2,
}

/// GET /join-requests/manifest — pre-submit discovery of the community's
/// Accepts criteria. Public, stateless read.
#[utoipa::path(
    get, path = "/join-requests/manifest", tag = "join-requests",
    responses(
        (status = 200, description = "Community join evidence requirements", body = JoinManifest01Response),
    ),
)]
pub async fn manifest(
    State(state): State<AppState>,
) -> Result<Json<JoinManifest01Response>, AppError> {
    Ok(Json(manifest_v0_1(&state).await?.into()))
}

async fn community_did(state: &AppState) -> Result<String, AppError> {
    state
        .config
        .read()
        .await
        .vtc_did
        .clone()
        .filter(|d| !d.is_empty())
        .ok_or_else(|| AppError::Internal("VTC DID not configured".into()))
}

/// The community's `vtc/join-requests/manifest/0.1` answer.
pub async fn manifest_v0_1(state: &AppState) -> Result<v0_1::Response, AppError> {
    response_v0_1(
        community_did(state).await?,
        list_accepts(&state.schemas_ks).await?,
    )
}

/// The community's `vtc/join-requests/manifest/0.2` answer. Branding only when
/// the community has set some.
pub async fn manifest_v0_2(state: &AppState) -> Result<v0_2::Response, AppError> {
    let branding = Some(branding::load_branding(&state.community_ks).await?)
        .filter(|b| !branding::is_empty(b));
    response_v0_2(
        community_did(state).await?,
        list_accepts(&state.schemas_ks).await?,
        branding,
    )
}

/// The 0.1 answer over `stored` criteria.
pub fn response_v0_1(
    community_did: String,
    stored: Vec<AcceptsCriterion>,
) -> Result<v0_1::Response, AppError> {
    let criteria = stored
        .into_iter()
        .map(criterion_v0_1)
        .collect::<Result<Vec<_>, _>>()
        .map_err(stored_fault)?;
    v0_1::Response::try_from(
        v0_1::Response::builder()
            .community_did(community_did)
            .criteria(criteria),
    )
    .map_err(|e| AppError::Internal(format!("manifest 0.1: {e}")))
}

/// The 0.2 answer over `stored` criteria and `branding`.
///
/// Branding the manifest cannot carry — a `logoUrl` that is not an absolute
/// https URI among it — is left out, and the manifest is served without it.
/// Branding is presentation only, and the manifest is what every applicant
/// needs to join, so a bad logo address must not stop joins. Storing branding
/// refuses such a value first ([`crate::community::branding::store_branding`]),
/// so only a row written before that check can reach here; a warning names the
/// members at fault, never their values, which may be hostile.
pub fn response_v0_2(
    community_did: String,
    stored: Vec<AcceptsCriterion>,
    branding: Option<v0_2::CommunityBranding>,
) -> Result<v0_2::Response, AppError> {
    let branding = branding.filter(|branding| {
        if branding.check_shape().is_ok() {
            return true;
        }
        let members = invalid_branding_members(branding);
        tracing::warn!(
            members = %if members.is_empty() { "branding".to_string() } else { members.join(", ") },
            "the stored community branding breaks the join manifest's CommunityBranding \
             definition; serving manifest 0.2 without branding until an admin replaces it"
        );
        false
    });
    let criteria = stored
        .into_iter()
        .map(manifest_criterion)
        .collect::<Result<Vec<_>, _>>()
        .map_err(stored_fault)?;
    v0_2::Response::try_from(
        v0_2::Response::builder()
            .community_did(community_did)
            .criteria(criteria)
            .branding(branding),
    )
    .map_err(|e| AppError::Internal(format!("manifest 0.2: {e}")))
}

/// The top-level members of `branding` that fail the manifest's
/// `CommunityBranding` definition on their own. Names only: a value is what an
/// admin typed, and a log is no place to repeat a hostile one.
fn invalid_branding_members(branding: &v0_2::CommunityBranding) -> Vec<String> {
    let Ok(Value::Object(members)) = serde_json::to_value(branding) else {
        return Vec::new();
    };
    members
        .into_iter()
        .filter(|(name, value)| {
            let alone = Value::Object(Map::from_iter([(name.clone(), value.clone())]));
            read_branding(&alone).is_err()
        })
        .map(|(name, _)| name)
        .collect()
}

/// A stored criterion that does not project onto the manifest is the
/// community's fault, not the caller's. Registration refuses one
/// ([`crate::schemas::accepts::store_accepts`]), so only a row written before
/// that check can reach here.
fn stored_fault(e: AppError) -> AppError {
    AppError::Internal(format!(
        "a stored accepts criterion does not project onto the manifest: {e}"
    ))
}

/// Project a stored criterion onto `vtc/join-requests/manifest/0.1`.
///
/// # Errors
///
/// [`AppError::Validation`] naming the member the manifest schema refuses.
pub fn criterion_v0_1(stored: AcceptsCriterion) -> Result<v0_1::ResponseCriteriaItem, AppError> {
    let description = stored
        .description
        .map(v0_1::ResponseCriteriaItemDescription::try_from)
        .transpose()
        .map_err(|e| refused("description", e))?;
    v0_1::ResponseCriteriaItem::try_from(
        v0_1::ResponseCriteriaItem::builder()
            .id(stored.id)
            .description(description)
            .presentation_definition(query_object(stored.query)?),
    )
    .map_err(|e| refused("criterion", e))
}

/// Project a stored criterion onto `vtc/join-requests/manifest/0.2`, with its
/// `requirementsDigest`.
///
/// The digest is computed over the criterion exactly as it is delivered, minus
/// the digest member, so an applicant recomputes it from what it received with
/// [`requirements_digest`] and gets the same value.
///
/// # Errors
///
/// [`AppError::Validation`] naming the member the manifest schema refuses.
pub fn manifest_criterion(stored: AcceptsCriterion) -> Result<v0_2::Criterion, AppError> {
    let description = stored
        .description
        .map(v0_2::CriterionDescription::try_from)
        .transpose()
        .map_err(|e| refused("description", e))?;
    let mut criterion = v0_2::Criterion::try_from(
        v0_2::Criterion::builder()
            .id(stored.id)
            .description(description)
            .presentation_definition(query_object(stored.query)?)
            .vetting(stored.vetting),
    )
    .map_err(|e| refused("criterion", e))?;
    let delivered = serde_json::to_value(&criterion)
        .map_err(|e| AppError::Internal(format!("manifest criterion encode: {e}")))?;
    let digest = requirements_digest(&delivered)
        .map_err(|e| AppError::Internal(format!("requirements digest: {e}")))?;
    criterion.requirements_digest = Some(
        v0_2::DigestMultibase::try_from(digest)
            .map_err(|e| AppError::Internal(format!("requirements digest: {e}")))?,
    );
    Ok(criterion)
}

fn refused(member: &str, e: impl std::fmt::Display) -> AppError {
    AppError::Validation(format!(
        "the join manifest cannot carry this criterion's {member}: {e}"
    ))
}

/// A criterion's `presentationDefinition` is a JSON object.
fn query_object(query: Value) -> Result<Map<String, Value>, AppError> {
    match query {
        Value::Object(query) => Ok(query),
        _ => Err(AppError::Validation(
            "an accepts criterion's query must be a JSON object".into(),
        )),
    }
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
            "acceptedMethods": ["inPerson", "video"],
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
        let c = criterion_v0_1(stored(Some(requirements(2)))).unwrap();
        let v = serde_json::to_value(&c).unwrap();
        assert!(v.get("vetting").is_none());
        assert!(v.get("requirementsDigest").is_none());
        assert_eq!(v["id"], "kernel-developer");
    }

    #[test]
    fn a_0_2_digest_recomputes_from_what_the_applicant_receives() {
        let c = manifest_criterion(stored(Some(requirements(2)))).unwrap();
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
        let digest = |min| {
            manifest_criterion(stored(Some(requirements(min))))
                .unwrap()
                .requirements_digest
                .map(String::from)
        };
        assert_ne!(digest(2), digest(3));
    }

    #[test]
    fn a_criterion_without_vetting_still_gets_a_digest_under_0_2() {
        let c = manifest_criterion(stored(None)).unwrap();
        assert!(c.vetting.is_none());
        assert!(c.requirements_digest.is_some());
    }

    #[test]
    fn a_criterion_the_manifest_cannot_carry_is_refused() {
        // 0.2 bounds a criterion id at 128 characters; 0.1 set no upper bound.
        // Registration projects onto 0.2, so the stricter one decides.
        let mut long_id = stored(None);
        long_id.id = "x".repeat(129);
        assert!(matches!(
            manifest_criterion(long_id.clone()),
            Err(AppError::Validation(_))
        ));
        assert!(criterion_v0_1(long_id).is_ok());

        let mut not_an_object = stored(None);
        not_an_object.query = json!(["credentials"]);
        assert!(matches!(
            manifest_criterion(not_an_object),
            Err(AppError::Validation(_))
        ));

        let mut long_description = stored(None);
        long_description.description = Some("x".repeat(1025));
        assert!(matches!(
            manifest_criterion(long_description),
            Err(AppError::Validation(_))
        ));
    }

    fn branding(logo: &str) -> v0_2::CommunityBranding {
        serde_json::from_value(json!({ "displayName": "Kernel", "logoUrl": logo })).unwrap()
    }

    #[test]
    fn branding_the_manifest_cannot_carry_is_omitted_and_the_manifest_still_served() {
        let answer = |logo: &str| {
            response_v0_2(
                "did:web:vtc.example".into(),
                vec![stored(None)],
                Some(branding(logo)),
            )
            .expect("branding must never fail the manifest an applicant joins by")
        };
        let good = answer("https://kernel.example/logo.svg");
        assert_eq!(
            good.branding.and_then(|b| b.logo_url),
            Some("https://kernel.example/logo.svg".to_string())
        );
        for bad in [
            "https://kernel.example/my logo.svg",
            "https://kernel.example/logo\u{7}.svg",
            "http://kernel.example/logo.svg",
        ] {
            let manifest = answer(bad);
            assert!(manifest.branding.is_none(), "{bad:?}");
            assert_eq!(manifest.criteria.len(), 1, "{bad:?}");
        }
    }

    #[test]
    fn the_warning_names_the_member_at_fault_not_its_value() {
        assert_eq!(
            invalid_branding_members(&branding("https://kernel.example/my logo.svg")),
            vec!["logoUrl".to_string()]
        );
        assert!(invalid_branding_members(&branding("https://kernel.example/logo.svg")).is_empty());
    }
}
