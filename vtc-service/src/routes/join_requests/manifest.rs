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

use serde_json::{Map, Value};

use vta_sdk::protocols::join_requests::manifest::{v0_1, v0_2};
use vta_sdk::protocols::vetting::{CheckShape, read_branding};
use vta_sdk::vetting::requirements::{REQUIREMENTS_DIGEST_MEMBER, requirements_digest};
use vti_common::error::AppError;

use crate::community::branding;
use crate::schemas::accepts::{AcceptsCriterion, list_accepts};
use crate::server::AppState;

/// Which manifest version a caller asked for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManifestVersion {
    /// `vtc/join-requests/manifest/0.1` — criteria only.
    V0_1,
    /// `vtc/join-requests/manifest/0.2` — criteria with their vetting
    /// requirements and a `requirementsDigest`, and the branding.
    V0_2,
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
pub async fn manifest_v0_2(state: &AppState) -> Result<Value, AppError> {
    let branding = Some(branding::load_branding(&state.community_ks).await?)
        .filter(|b| !branding::is_empty(b));
    response_v0_2(
        community_did(state).await?,
        list_accepts(&state.schemas_ks).await?,
        branding,
        crate::community::requested_attributes::load_requested(&state.community_ks).await?,
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
    requested_attributes: Vec<v0_2::ResponseRequestedAttributesItem>,
) -> Result<Value, AppError> {
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
    let served = stored
        .into_iter()
        .map(manifest_criterion)
        .collect::<Result<Vec<_>, _>>()
        .map_err(stored_fault)?;
    let response = v0_2::Response::try_from(
        v0_2::Response::builder()
            .community_did(community_did)
            .criteria(
                served
                    .iter()
                    .map(|s| s.criterion.clone())
                    .collect::<Vec<_>>(),
            )
            .branding(branding)
            // Absent when the community asks for nothing: an empty array is
            // omitted by the generated type, and "asks nothing" is the answer.
            .requested_attributes(requested_attributes),
    )
    .map_err(|e| AppError::Internal(format!("manifest 0.2: {e}")))?;

    // Built typed so the whole response is validated against the generated schema, then
    // serialised and the criteria put back as they were digested. Only the criteria differ, and
    // only by the `vetting.ext` the generated type drops — so this swap is what makes the served
    // bytes and the digested bytes the same bytes.
    let mut out = serde_json::to_value(&response)
        .map_err(|e| AppError::Internal(format!("manifest 0.2 encode: {e}")))?;
    if let Some(map) = out.as_object_mut() {
        map.insert(
            "criteria".to_string(),
            Value::Array(served.into_iter().map(|s| s.json).collect()),
        );
    }
    Ok(out)
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

/// A criterion as the community both **serves** it and **digests** it.
///
/// Two forms of one thing, because the generated type cannot carry all of it. A community that
/// runs hidden vetting publishes its parameters under `vetting.ext`, and `VettingRequirements`
/// at the pinned `trust-tasks-rs` has no `ext` member — the schema on the registry does, so this
/// is a version lag rather than a disagreement. The typed form is what consumers evaluate
/// against; the JSON is what goes on the wire, and what the digest is taken over.
///
/// Keeping them beside each other is what stops the two drifting: the digest lives on both, and
/// it is computed once, over [`Self::json`].
#[derive(Debug, Clone)]
pub struct ServedCriterion {
    /// The generated type, with `requirementsDigest` set.
    pub criterion: v0_2::Criterion,
    /// The criterion as served — `vetting.ext` included, `requirementsDigest` set.
    pub json: Value,
}

/// Project a stored criterion onto `vtc/join-requests/manifest/0.2`, with its
/// `requirementsDigest`.
///
/// The digest is computed over the criterion exactly as it is delivered, minus
/// the digest member, so an applicant recomputes it from what it received with
/// [`requirements_digest`] and gets the same value. **That is why the hidden-vetting
/// parameters are injected before the digest and not after**: they are part of what the
/// applicant received, so they are part of what it digests, and a proof binds to that digest.
///
/// # Errors
///
/// [`AppError::Validation`] naming the member the manifest schema refuses.
pub fn manifest_criterion(stored: AcceptsCriterion) -> Result<ServedCriterion, AppError> {
    let description = stored
        .description
        .map(v0_2::CriterionDescription::try_from)
        .transpose()
        .map_err(|e| refused("description", e))?;
    #[cfg(feature = "vetting-pcs")]
    let hidden_vetting = stored.hidden_vetting.clone();
    let mut criterion = v0_2::Criterion::try_from(
        v0_2::Criterion::builder()
            .id(stored.id)
            .description(description)
            .presentation_definition(query_object(stored.query)?)
            .vetting(stored.vetting),
    )
    .map_err(|e| refused("criterion", e))?;
    let mut delivered = serde_json::to_value(&criterion)
        .map_err(|e| AppError::Internal(format!("manifest criterion encode: {e}")))?;

    // Hidden-vetter admission (development branch `zkp-pcs`). Only under the feature: a build
    // without the suite cannot verify a proof, and advertising a mode it would then refuse is
    // worse than not advertising it.
    //
    // `ext` and never `extCritical`. Critical means "refuse to apply if you cannot do this",
    // which would lock out every named applicant of a community that also accepts named
    // vetting — and both paths are meant to coexist (§16).
    #[cfg(feature = "vetting-pcs")]
    if let Some(raw) = hidden_vetting {
        inject_hidden_vetting(&mut delivered, &raw)?;
    }

    let digest = requirements_digest(&delivered)
        .map_err(|e| AppError::Internal(format!("requirements digest: {e}")))?;
    criterion.requirements_digest = Some(
        v0_2::DigestMultibase::try_from(digest.clone())
            .map_err(|e| AppError::Internal(format!("requirements digest: {e}")))?,
    );
    if let Some(map) = delivered.as_object_mut() {
        map.insert(
            REQUIREMENTS_DIGEST_MEMBER.to_string(),
            Value::String(digest),
        );
    }
    Ok(ServedCriterion {
        criterion,
        json: delivered,
    })
}

/// Put this community's published hidden-vetting parameters into the criterion's `vetting.ext`.
///
/// A no-op for a criterion that asks for no vetting at all: the parameters describe *how* this
/// community's vetting is carried out, so without requirements there is nothing for them to
/// qualify, and a client reading them there would have nothing to apply them to.
///
/// # Errors
///
/// [`AppError::Internal`] if what was stored is not a readable configuration. It was written by
/// an admin through a route that parses it, so an unreadable one is this service's fault, not
/// the operator's — and serving a manifest that silently omitted the parameters would make a
/// hidden community look like a named one.
#[cfg(feature = "vetting-pcs")]
fn inject_hidden_vetting(delivered: &mut Value, raw: &Value) -> Result<(), AppError> {
    let Some(vetting) = delivered.get_mut("vetting").and_then(Value::as_object_mut) else {
        return Ok(());
    };
    let config: crate::vetting::pcs::HiddenVettingConfig = serde_json::from_value(raw.clone())
        .map_err(|e| {
            AppError::Internal(format!(
                "stored hidden-vetting parameters are unreadable: {e}"
            ))
        })?;
    let ext = vetting
        .entry("ext")
        .or_insert_with(|| Value::Object(Map::new()));
    if let Some(ext) = ext.as_object_mut() {
        ext.insert(
            crate::vetting::pcs::HIDDEN_VETTING_NS.to_string(),
            config.published(),
        );
    }
    Ok(())
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
            "statementType": "https://registry.trustoverip.org/dtg/vsc/vetted/1",
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
            hidden_vetting: None,
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
        let received = manifest_criterion(stored(Some(requirements(2))))
            .unwrap()
            .json;
        assert_eq!(received["vetting"]["minStatements"], 2);
        assert_eq!(
            received["requirementsDigest"].as_str().unwrap(),
            requirements_digest(&received).unwrap(),
            "the digest must be checkable by the applicant from the delivered criterion"
        );
    }

    /// A community that runs hidden vetting publishes its parameters where a client looks for
    /// them. Without this the client reads `Mode::Named` from every manifest, and a hidden
    /// community is indistinguishable from an ordinary one — which is how this branch behaved
    /// until the parameters were put on the wire.
    #[cfg(feature = "vetting-pcs")]
    #[test]
    fn a_hidden_criterion_publishes_its_parameters_where_a_client_reads_them() {
        let mut c = stored(Some(requirements(3)));
        c.hidden_vetting = Some(serde_json::to_value(hidden_config()).unwrap());
        let served = manifest_criterion(c).unwrap().json;

        let ext = &served["vetting"]["ext"][crate::vetting::pcs::HIDDEN_VETTING_NS];
        assert_eq!(ext["suite"], vti_vetting_pcs::wire::SUITE);
        assert_eq!(ext["helperKey"], "zHvk");
        assert_eq!(ext["tokenKey"], "zTvk");
        // Whole labels, not the bare period the store keeps: the label is what a request names.
        assert_eq!(ext["vetterLabels"][0], "vetter/2026-09");
        assert_eq!(ext["tokenLabels"][0], "token/2026-09");
        assert_eq!(ext["dripPerTick"], 3);

        // `ext`, never `extCritical`: a community running both paths must not lock out the
        // applicants using the named one.
        assert!(served["vetting"].get("extCritical").is_none());
    }

    /// The digest is what a proof binds to, so it has to cover the parameters the proof was
    /// built under. Injected after the digest, a community could change its keys without the
    /// digest moving, and an applicant would bind to a criterion it never saw.
    #[cfg(feature = "vetting-pcs")]
    #[test]
    fn the_digest_covers_the_published_parameters() {
        let digest_with = |tvk: &str| {
            let mut c = stored(Some(requirements(3)));
            let mut config = hidden_config();
            config.tvk = tvk.into();
            c.hidden_vetting = Some(serde_json::to_value(config).unwrap());
            let served = manifest_criterion(c).unwrap().json;
            // And it is recomputable from what was delivered, which is the whole contract.
            assert_eq!(
                served["requirementsDigest"].as_str().unwrap(),
                requirements_digest(&served).unwrap()
            );
            served["requirementsDigest"].as_str().unwrap().to_string()
        };
        assert_ne!(digest_with("zTvk"), digest_with("zOtherTvk"));
    }

    /// Who approved an event is the community's record of its own decision. Publishing it would
    /// name a member in a document every applicant receives, for nothing a vetter could act on.
    #[cfg(feature = "vetting-pcs")]
    #[test]
    fn an_events_approver_is_never_published() {
        let mut config = hidden_config();
        config.events.push(crate::vetting::pcs::HiddenVettingEvent {
            event_id: "kernel-summit-2026".into(),
            start_date: chrono::NaiveDate::from_ymd_opt(2026, 10, 12).unwrap(),
            end_date: chrono::NaiveDate::from_ymd_opt(2026, 10, 14).unwrap(),
            grace_days: 14,
            group_floor: 3,
            tiers: vec![crate::vetting::pcs::HiddenVettingTier {
                name: "desk".into(),
                drip_per_tick: 20,
            }],
            approved_by: Some("did:key:zTheApprover".into()),
        });
        let mut c = stored(Some(requirements(3)));
        c.hidden_vetting = Some(serde_json::to_value(config).unwrap());
        let served = manifest_criterion(c).unwrap().json;

        let event = &served["vetting"]["ext"][crate::vetting::pcs::HIDDEN_VETTING_NS]["events"][0];
        assert_eq!(event["eventId"], "kernel-summit-2026");
        assert_eq!(event["groupFloor"], 3);
        assert_eq!(event["tiers"][0]["dripPerTick"], 20);
        assert!(event.get("approvedBy").is_none(), "{event}");
        assert!(event.get("graceDays").is_none(), "{event}");
        assert!(
            !serde_json::to_string(&served)
                .unwrap()
                .contains("zTheApprover"),
            "the approver's DID must not appear anywhere in what is served"
        );
    }

    /// A criterion that asks for no vetting has nothing for these parameters to qualify.
    #[cfg(feature = "vetting-pcs")]
    #[test]
    fn a_criterion_without_vetting_publishes_no_parameters() {
        let mut c = stored(None);
        c.hidden_vetting = Some(serde_json::to_value(hidden_config()).unwrap());
        let served = manifest_criterion(c).unwrap().json;
        assert!(served.get("vetting").is_none());
    }

    #[cfg(feature = "vetting-pcs")]
    fn hidden_config() -> crate::vetting::pcs::HiddenVettingConfig {
        crate::vetting::pcs::HiddenVettingConfig {
            suite: vti_vetting_pcs::wire::SUITE.into(),
            hvk: "zHvk".into(),
            tvk: "zTvk".into(),
            live_periods: vec!["2026-09".into()],
            live_token_labels: vec!["token/2026-09".into()],
            drip_per_tick: 3,
            events: Vec::new(),
        }
    }

    #[test]
    fn changing_the_requirements_changes_the_digest() {
        let digest = |min| {
            manifest_criterion(stored(Some(requirements(min))))
                .unwrap()
                .criterion
                .requirements_digest
                .map(String::from)
        };
        assert_ne!(digest(2), digest(3));
    }

    #[test]
    fn a_criterion_without_vetting_still_gets_a_digest_under_0_2() {
        let c = manifest_criterion(stored(None)).unwrap().criterion;
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
                Vec::new(),
            )
            .expect("branding must never fail the manifest an applicant joins by")
        };
        let good = answer("https://kernel.example/logo.svg");
        assert_eq!(
            good["branding"]["logoUrl"].as_str(),
            Some("https://kernel.example/logo.svg")
        );
        for bad in [
            "https://kernel.example/my logo.svg",
            "https://kernel.example/logo\u{7}.svg",
            "http://kernel.example/logo.svg",
        ] {
            let manifest = answer(bad);
            assert!(manifest.get("branding").is_none(), "{bad:?}");
            assert_eq!(
                manifest["criteria"].as_array().map(Vec::len),
                Some(1),
                "{bad:?}"
            );
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
