//! The schema store's **Accepts** half (task 2.4,
//! `docs/05-design-notes/vti-credential-architecture.md` §8): the community's
//! **join criteria**.
//!
//! Where the **Issues** registry ([`super::SchemaEntry`]) names the types the
//! community *mints*, an **Accepts criterion** is one way into the community
//! (`vtc/schemas/accepts/register/0.2`, `vtc/join-requests/manifest/0.3`): an
//! `admission` mode, and the requirements it states — any of a DCQL query over
//! the registry with the issuers whose credentials count, peer-vetting
//! requirements, and an invitation — or none. Which criteria a community has,
//! and so who it admits and how, is its administrators' decision; nothing here
//! assumes one. How a submission is decided against them is
//! [`crate::join::criteria`].
//!
//! ## Validation
//!
//! A criterion is only stored if its query, when it has one, is (a) a
//! **structurally-valid DCQL query** and (b) every credential type it
//! references (`meta.vct_values`) is a **registered** schema-store type — no
//! dangling references to types the community doesn't know about.
//!
//! ## Order
//!
//! The manifest lists criteria **in the order the community decides by**: a
//! submission naming no criterion is decided under the first it meets
//! (`vtc/join-requests/manifest/0.3` item 3). That order is registration order
//! — [`AcceptsCriterion::position`], assigned when an id is first registered and
//! kept when it is replaced — so an administrator reorders by deleting a
//! criterion and registering it again. `vtc/schemas/accepts/list/0.2` pages in
//! id order, as it specifies; [`published_criteria`] is the decision order.
//!
//! ## Versions
//!
//! A submission citing a criterion's `requirementsDigest` is decided under the
//! version that digest names while that version is within its
//! `requirementsGrace` (manifest 0.3 item 5). So replacing or deleting a
//! criterion keeps the version it supersedes, keyed by its digest
//! ([`superseded_version`]).
//!
//! Criteria live in the same `schemas` keyspace under the disjoint `accepts:`,
//! `accepts-version:` and `accepts-seeded` keys (the Issues registry uses
//! `schemas:<type-uri>`).

use affinidi_openid4vp::DcqlQuery;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use vta_sdk::protocols::vetting::{CheckShape, VettingRequirements};
use vti_common::error::AppError;
use vti_common::store::KeyspaceHandle;

use super::schema_exists;

/// Key prefix for stored Accepts criteria — disjoint from `schemas:` (the
/// per-type Issues registry).
pub const ACCEPTS_PREFIX: &[u8] = b"accepts:";

/// Key prefix for the versions a criterion's replacement or deletion
/// superseded, keyed by their `requirementsDigest`.
const VERSION_PREFIX: &str = "accepts-version:";

/// Set once the default criteria have been offered to this community, so that
/// an administrator who deletes every criterion is left with none — which the
/// manifest publishes as "accepting no applications" — rather than with the
/// defaults again on the next boot.
const SEEDED_KEY: &str = "accepts-seeded";

fn key(id: &str) -> Vec<u8> {
    let mut k = ACCEPTS_PREFIX.to_vec();
    k.extend_from_slice(id.as_bytes());
    k
}

/// How the community decides a submission that meets a criterion.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
#[derive(utoipa::ToSchema)]
pub enum Admission {
    /// It admits the applicant without a person deciding.
    Automatic,
    /// It refers the submission to an administrator, who decides. Meeting the
    /// criterion never admits by itself.
    ///
    /// The default, and so the reading of a row stored before criteria stated
    /// their admission: the restrictive one.
    #[default]
    Review,
}

impl Admission {
    pub fn as_str(self) -> &'static str {
        match self {
            Admission::Automatic => "automatic",
            Admission::Review => "review",
        }
    }
}

/// Whose credentials meet a criterion's query.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[derive(utoipa::ToSchema)]
pub enum CredentialIssuers {
    /// Any issuer whose credential verifies.
    Any,
    /// This community's own.
    Community,
    /// This community's, or a community it recognises.
    Recognised,
}

impl CredentialIssuers {
    pub fn as_str(self) -> &'static str {
        match self {
            CredentialIssuers::Any => "any",
            CredentialIssuers::Community => "community",
            CredentialIssuers::Recognised => "recognised",
        }
    }
}

/// One way into the community: its admission mode and the requirements it
/// states. Every stated requirement must be met; a criterion stating none is
/// met by every submission whose proof and presentation verify.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[derive(utoipa::ToSchema)]
pub struct AcceptsCriterion {
    /// Criterion id. Primary key.
    pub id: String,
    /// How a submission meeting this criterion is decided.
    #[serde(default)]
    pub admission: Admission,
    /// The credentials an applicant must present, as a DCQL query. Absent: the
    /// criterion requires no credential. Structurally validated and every
    /// referenced type checked against the registry when stored (see
    /// [`validate_accepts_query`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<Object>)]
    pub query: Option<Value>,
    /// Whose credentials meet [`Self::query`]. Present exactly when it is.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_issuers: Option<CredentialIssuers>,
    /// True: met only by a submission carrying a valid, unconsumed invitation
    /// this community issued to the applicant.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub invitation_required: bool,
    /// Free-form description shown to applicants and in admin UIs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Peer identity vetting this criterion requires: the manifest's own
    /// `VettingRequirements`. Every number in it is this community's policy.
    /// The register task additionally requires its `statementType` to be a
    /// registered endorsement type.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<vta_sdk::openapi::JoinManifest02VettingRequirements>)]
    pub vetting: Option<VettingRequirements>,
    /// Hidden-vetter admission (ZKP, development branch `zkp-pcs`): the published
    /// parameters an applicant proves against, and this VTC checks — `hvk`, `tvk`
    /// and the live labels (`crate::vetting::pcs::HiddenVettingConfig`).
    ///
    /// Held as raw JSON so the field costs nothing when the feature is off, and
    /// so a criterion registered by a build that has it stays readable by one
    /// that does not. It reaches the manifest under `vetting.ext` only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<Object>)]
    pub hidden_vetting: Option<serde_json::Value>,
    /// Where this criterion stands in the order the community decides by.
    /// Assigned on first registration and kept on replacement; see the module
    /// docs.
    #[serde(default)]
    pub position: u64,
    pub created_at: DateTime<Utc>,
    /// Admin DID that registered the criterion (audit correlation).
    pub created_by_did: String,
}

impl AcceptsCriterion {
    /// A criterion with no requirements, decided as `admission` says.
    pub fn new(id: impl Into<String>, admission: Admission, by: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            admission,
            query: None,
            credential_issuers: None,
            invitation_required: false,
            description: None,
            vetting: None,
            hidden_vetting: None,
            position: 0,
            created_at: Utc::now(),
            created_by_did: by.into(),
        }
    }

    /// The criterion as `vtc/schemas/accepts/{register,show,list}/0.2` carry it:
    /// the members that schema defines, and none of this store's own
    /// ([`Self::position`], [`Self::hidden_vetting`]).
    pub fn to_wire(&self) -> Value {
        let mut out = json!({
            "id": self.id,
            "admission": self.admission.as_str(),
            "createdAt": self.created_at,
            "createdByDid": self.created_by_did,
        });
        let map = out.as_object_mut().expect("object literal");
        if let Some(query) = &self.query {
            map.insert("query".into(), query.clone());
        }
        if let Some(issuers) = self.credential_issuers {
            map.insert("credentialIssuers".into(), issuers.as_str().into());
        }
        if self.invitation_required {
            map.insert("invitationRequired".into(), true.into());
        }
        if let Some(description) = &self.description {
            map.insert("description".into(), description.clone().into());
        }
        if let Some(vetting) = &self.vetting {
            map.insert(
                "vetting".into(),
                serde_json::to_value(vetting).unwrap_or(Value::Null),
            );
        }
        out
    }

    /// The DCQL query, parsed. `None` when the criterion requires no
    /// credential.
    ///
    /// # Errors
    ///
    /// [`AppError::Internal`] for a stored query that no longer parses — it was
    /// validated when stored.
    pub fn dcql(&self) -> Result<Option<DcqlQuery>, AppError> {
        self.query
            .as_ref()
            .map(|q| {
                DcqlQuery::from_json(q).map_err(|e| {
                    AppError::Internal(format!(
                        "stored Accepts criterion `{}` is not a valid DCQL query: {e}",
                        self.id
                    ))
                })
            })
            .transpose()
    }
}

/// The credential type URIs a DCQL query references via each credential query's
/// `meta.vct_values` (the type selector).
pub(crate) fn referenced_types(query: &DcqlQuery) -> Vec<String> {
    let mut out = Vec::new();
    for cq in &query.credentials {
        if let Some(meta) = &cq.meta
            && let Some(vcts) = meta.get("vct_values").and_then(|v| v.as_array())
        {
            out.extend(vcts.iter().filter_map(|v| v.as_str()).map(String::from));
        }
    }
    out
}

/// Validate a DCQL query intended as an Accepts criterion: it must be a
/// structurally-valid [`DcqlQuery`], **and** every credential type it references
/// (`meta.vct_values`) must be a registered schema-store type.
///
/// Returns the parsed [`DcqlQuery`] on success, or [`AppError::Validation`] for
/// a malformed query or a dangling type reference.
pub async fn validate_accepts_query(
    schemas_ks: &KeyspaceHandle,
    query: &Value,
) -> Result<DcqlQuery, AppError> {
    let dcql = DcqlQuery::from_json(query)
        .map_err(|e| AppError::Validation(format!("invalid DCQL query: {e}")))?;

    for type_uri in referenced_types(&dcql) {
        if !schema_exists(schemas_ks, &type_uri).await? {
            return Err(AppError::Validation(format!(
                "DCQL Accepts criterion references unregistered credential type `{type_uri}` \
                 — register it in the schema store first"
            )));
        }
    }
    Ok(dcql)
}

/// The rules the criterion's own shape states, which a JSON Schema
/// `dependentRequired` states on the wire but a stored row has to be held to
/// here: `credentialIssuers` is present exactly when the query is.
fn check_requirements_shape(criterion: &AcceptsCriterion) -> Result<(), AppError> {
    match (&criterion.query, criterion.credential_issuers) {
        (Some(_), None) => Err(AppError::Validation(
            "a criterion with a query must say whose credentials count (credentialIssuers)".into(),
        )),
        (None, Some(_)) => Err(AppError::Validation(
            "credentialIssuers says whose credentials meet the query, and this criterion has \
             no query"
                .into(),
        )),
        _ => Ok(()),
    }
}

/// Validate + store an Accepts criterion. The query is validated against the
/// registry first, any vetting requirements must be evaluable, and the
/// criterion must be one the join manifest can publish; a criterion with a
/// malformed query, a dangling type reference, requirements no applicant could
/// satisfy, or a member the manifest schema refuses is **not** stored.
///
/// Replacing a criterion keeps its [`AcceptsCriterion::position`] — the
/// decision order is the administrators', and a replacement is not a
/// reordering — and keeps the version it supersedes for the grace window.
pub async fn store_accepts(
    schemas_ks: &KeyspaceHandle,
    criterion: &AcceptsCriterion,
) -> Result<AcceptsCriterion, AppError> {
    check_requirements_shape(criterion)?;
    if let Some(query) = &criterion.query {
        validate_accepts_query(schemas_ks, query).await?;
    }
    if let Some(vetting) = &criterion.vetting {
        vetting
            .check_shape()
            .map_err(|e| AppError::Validation(format!("vetting: {e}")))?;
    }
    let mut criterion = criterion.clone();
    let existing = get_accepts(schemas_ks, &criterion.id).await?;
    criterion.position = match &existing {
        Some(old) => old.position,
        None => next_position(schemas_ks).await?,
    };
    let served = crate::routes::join_requests::manifest::manifest_criterion(criterion.clone())?;
    if let Some(old) = existing {
        supersede(schemas_ks, old, Some(&served.digest)).await?;
    }
    schemas_ks
        .insert(
            String::from_utf8(key(&criterion.id)).expect("ascii key"),
            &criterion,
        )
        .await?;
    Ok(criterion)
}

/// The position after every stored criterion's.
async fn next_position(schemas_ks: &KeyspaceHandle) -> Result<u64, AppError> {
    Ok(list_accepts(schemas_ks)
        .await?
        .iter()
        .map(|c| c.position)
        .max()
        .map_or(1, |p| p.saturating_add(1)))
}

/// A version of a criterion that a replacement or deletion superseded.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SupersededVersion {
    /// The criterion as it stood.
    pub criterion: AcceptsCriterion,
    /// When it stopped being the current version.
    pub superseded_at: DateTime<Utc>,
}

impl SupersededVersion {
    /// Whether a submission citing this version is still decided under it:
    /// only within the `requirementsGrace` that version declared. No grace
    /// declared, none applies.
    pub fn within_grace(&self, now: DateTime<Utc>) -> bool {
        self.criterion
            .vetting
            .as_ref()
            .and_then(|v| v.requirements_grace.as_ref())
            .and_then(|d| vta_sdk::protocols::vetting::parse_iso8601_duration(d))
            .is_some_and(|grace| now < self.superseded_at + grace)
    }
}

/// Keep `old` as a superseded version, unless its replacement digests the
/// same (an identical re-registration supersedes nothing).
async fn supersede(
    schemas_ks: &KeyspaceHandle,
    old: AcceptsCriterion,
    replacement_digest: Option<&str>,
) -> Result<(), AppError> {
    let digest = crate::routes::join_requests::manifest::manifest_criterion(old.clone())
        .map(|s| s.digest)
        // A stored row the manifest can no longer carry was never published as
        // it stands, so no applicant can be citing it.
        .ok();
    let Some(digest) = digest else {
        return Ok(());
    };
    if replacement_digest == Some(digest.as_str()) {
        return Ok(());
    }
    schemas_ks
        .insert(
            format!("{VERSION_PREFIX}{digest}"),
            &SupersededVersion {
                criterion: old,
                superseded_at: Utc::now(),
            },
        )
        .await
}

/// The superseded version whose `requirementsDigest` is `digest`, if one is
/// kept. Whether it still governs is [`SupersededVersion::within_grace`].
pub async fn superseded_version(
    schemas_ks: &KeyspaceHandle,
    digest: &str,
) -> Result<Option<SupersededVersion>, AppError> {
    schemas_ks.get(format!("{VERSION_PREFIX}{digest}")).await
}

/// Fetch a stored Accepts criterion by id.
pub async fn get_accepts(
    schemas_ks: &KeyspaceHandle,
    id: &str,
) -> Result<Option<AcceptsCriterion>, AppError> {
    match schemas_ks.get_raw(key(id)).await? {
        Some(bytes) => Ok(Some(serde_json::from_slice(&bytes).map_err(|e| {
            AppError::Internal(format!("AcceptsCriterion decode: {e}"))
        })?)),
        None => Ok(None),
    }
}

/// List all stored Accepts criteria, in id order.
pub async fn list_accepts(schemas_ks: &KeyspaceHandle) -> Result<Vec<AcceptsCriterion>, AppError> {
    let mut pairs = schemas_ks.prefix_iter_raw(ACCEPTS_PREFIX.to_vec()).await?;
    pairs.sort_by(|(a, _), (b, _)| a.cmp(b));
    pairs
        .iter()
        .map(|(_, v)| {
            serde_json::from_slice(v)
                .map_err(|e| AppError::Internal(format!("AcceptsCriterion decode: {e}")))
        })
        .collect()
}

/// Every stored criterion, in the order the community decides by — the order
/// the join manifest publishes them in.
pub async fn published_criteria(
    schemas_ks: &KeyspaceHandle,
) -> Result<Vec<AcceptsCriterion>, AppError> {
    let mut criteria = list_accepts(schemas_ks).await?;
    criteria.sort_by(|a, b| a.position.cmp(&b.position).then_with(|| a.id.cmp(&b.id)));
    Ok(criteria)
}

/// Remove a stored Accepts criterion, keeping the version it was for the grace
/// window — an applicant part-way through gathering for it is decided under it
/// while that lasts.
pub async fn delete_accepts(schemas_ks: &KeyspaceHandle, id: &str) -> Result<(), AppError> {
    if let Some(old) = get_accepts(schemas_ks, id).await? {
        supersede(schemas_ks, old, None).await?;
    }
    schemas_ks.remove(key(id)).await
}

/// The DID recorded as the registrant of a seeded default criterion.
const SEED_AUTHOR: &str = "did:vtc:system";

/// The criteria a new community starts with, in decision order: an invitation
/// it issued admits; a membership credential of this community, or of one it
/// recognises, admits; anything else is reviewed.
///
/// These are a starting point an administrator can change, not a rule: the
/// specification assumes no criterion, and neither does anything that reads
/// them. A community that should review everyone deletes the first two; one
/// that should admit everyone replaces the last with an automatic criterion.
///
/// `recognises` says whether this community can recognise another (a trust
/// registry is configured). Without one, "recognised" is a requirement it
/// cannot evaluate, so the credential criterion counts its own credentials only.
pub fn default_criteria(recognises: bool) -> Vec<AcceptsCriterion> {
    let mut invited = AcceptsCriterion::new("invited", Admission::Automatic, SEED_AUTHOR);
    invited.invitation_required = true;
    invited.description = Some("Invited by this community".into());

    let mut member = AcceptsCriterion::new("member-credential", Admission::Automatic, SEED_AUTHOR);
    member.query = Some(json!({
        "credentials": [{
            "id": "membership",
            "format": crate::join::criteria::LDP_VC_FORMAT,
            "meta": { "type_values": [["MembershipCredential"]] }
        }]
    }));
    member.credential_issuers = Some(if recognises {
        CredentialIssuers::Recognised
    } else {
        CredentialIssuers::Community
    });
    member.description = Some(if recognises {
        "A member of this community, or of a community it recognises".into()
    } else {
        "A member of this community".into()
    });

    let mut review = AcceptsCriterion::new("review", Admission::Review, SEED_AUTHOR);
    review.description = Some("Reviewed by an administrator".into());

    vec![invited, member, review]
}

/// Store [`default_criteria`] the first time this community boots with none.
///
/// Once only: [`SEEDED_KEY`] records that the offer was made, so a community
/// whose administrators deleted every criterion is not handed the defaults
/// back. A community that registered its own before the first boot of this
/// release keeps them untouched. Returns how many were stored.
pub async fn seed_default_criteria(
    schemas_ks: &KeyspaceHandle,
    recognises: bool,
) -> Result<usize, AppError> {
    if schemas_ks.get_raw(SEEDED_KEY).await?.is_some() {
        return Ok(0);
    }
    let mut stored = 0;
    if list_accepts(schemas_ks).await?.is_empty() {
        for criterion in default_criteria(recognises) {
            store_accepts(schemas_ks, &criterion).await?;
            stored += 1;
        }
    }
    schemas_ks
        .insert(SEEDED_KEY, &json!({ "seededAt": Utc::now() }))
        .await?;
    Ok(stored)
}

#[cfg(test)]
mod tests {
    use super::super::{SchemaEntry, SchemaKind, store_schema};
    use super::*;
    use chrono::Utc;
    use serde_json::json;
    use vti_common::config::StoreConfig;
    use vti_common::store::Store;

    const MEMBERSHIP_VCT: &str = "https://openvtc.org/credentials/MembershipCredential";

    async fn ks() -> (tempfile::TempDir, Store, KeyspaceHandle) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&StoreConfig {
            data_dir: dir.path().to_path_buf(),
        })
        .unwrap();
        let ks = store.keyspace("schemas").unwrap();
        (dir, store, ks)
    }

    /// Register an evidence type so an Accepts criterion can reference it.
    async fn register_type(ks: &KeyspaceHandle, type_uri: &str) {
        store_schema(
            ks,
            &SchemaEntry {
                type_uri: type_uri.into(),
                dtg_type: Some("MembershipCredential".into()),
                credential_schema: None,
                kind: SchemaKind::Accepts,
                description: None,
                created_at: Utc::now(),
                created_by_did: "did:key:zAdmin".into(),
            },
        )
        .await
        .unwrap();
    }

    async fn register_membership(ks: &KeyspaceHandle) {
        register_type(ks, MEMBERSHIP_VCT).await;
    }

    fn criterion(id: &str, vct: &str) -> AcceptsCriterion {
        let mut c = AcceptsCriterion::new(id, Admission::Automatic, "did:key:zAdmin");
        c.query = Some(json!({
            "credentials": [{
                "id": "membership",
                "format": "dc+sd-jwt",
                "meta": { "vct_values": [vct] },
                "claims": [{ "path": ["givenName"] }]
            }]
        }));
        c.credential_issuers = Some(CredentialIssuers::Community);
        c.description = Some("join evidence".into());
        c
    }

    #[tokio::test]
    async fn stores_a_criterion_that_references_a_registered_type() {
        let (_d, _s, ks) = ks().await;
        register_membership(&ks).await;

        let c = criterion("join", MEMBERSHIP_VCT);
        let stored = store_accepts(&ks, &c)
            .await
            .expect("valid criterion stores");

        let got = get_accepts(&ks, "join").await.unwrap().unwrap();
        assert_eq!(
            serde_json::to_value(&got).unwrap(),
            serde_json::to_value(&stored).unwrap()
        );
        assert_eq!(list_accepts(&ks).await.unwrap().len(), 1);

        // Retrievable as a runnable DCQL query (what a ceremony does).
        let dcql = got.dcql().unwrap().expect("stored query is valid DCQL");
        assert_eq!(dcql.credentials.len(), 1);

        delete_accepts(&ks, "join").await.unwrap();
        assert!(get_accepts(&ks, "join").await.unwrap().is_none());
    }

    /// Open admission is a criterion that requires nothing: no query, no
    /// vetting, no invitation. It stores like any other.
    #[tokio::test]
    async fn stores_a_criterion_that_requires_nothing() {
        let (_d, _s, ks) = ks().await;
        for admission in [Admission::Automatic, Admission::Review] {
            let c = AcceptsCriterion::new("open", admission, "did:key:zAdmin");
            let stored = store_accepts(&ks, &c).await.expect("stores");
            assert_eq!(stored.admission, admission);
            assert!(stored.query.is_none());
        }
    }

    #[tokio::test]
    async fn credential_issuers_is_present_exactly_when_the_query_is() {
        let (_d, _s, ks) = ks().await;
        register_membership(&ks).await;
        let mut no_issuers = criterion("join", MEMBERSHIP_VCT);
        no_issuers.credential_issuers = None;
        assert!(matches!(
            store_accepts(&ks, &no_issuers).await,
            Err(AppError::Validation(_))
        ));
        let mut no_query = AcceptsCriterion::new("join", Admission::Review, "did:key:zAdmin");
        no_query.credential_issuers = Some(CredentialIssuers::Any);
        assert!(matches!(
            store_accepts(&ks, &no_query).await,
            Err(AppError::Validation(_))
        ));
        assert!(list_accepts(&ks).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn rejects_a_criterion_referencing_an_unregistered_type() {
        let (_d, _s, ks) = ks().await;
        // No type registered → the reference is dangling.
        let c = criterion("join", "https://openvtc.org/credentials/Unknown");
        let err = store_accepts(&ks, &c)
            .await
            .expect_err("dangling type reference must be rejected");
        assert!(matches!(err, AppError::Validation(_)), "{err:?}");
        assert!(
            get_accepts(&ks, "join").await.unwrap().is_none(),
            "not stored"
        );
    }

    #[tokio::test]
    async fn rejects_a_structurally_invalid_dcql_query() {
        let (_d, _s, ks) = ks().await;
        let mut bad = criterion("bad", MEMBERSHIP_VCT);
        // Empty `credentials` is invalid DCQL.
        bad.query = Some(json!({ "credentials": [] }));
        let err = store_accepts(&ks, &bad)
            .await
            .expect_err("invalid DCQL must be rejected");
        assert!(matches!(err, AppError::Validation(_)), "{err:?}");
    }

    fn vetting(min: u32, min_by_method: Value) -> VettingRequirements {
        serde_json::from_value(json!({
            "version": "0.1",
            "statementType": "https://registry.trustoverip.org/dtg/vsc/vetted/1",
            "minStatements": min,
            "minByMethod": min_by_method,
            "acceptedMethods": ["inPerson"],
            "eligibleVetters": { "role": "vetter" },
            "requirementsGrace": "P14D"
        }))
        .unwrap()
    }

    #[tokio::test]
    async fn stores_and_returns_a_criterion_with_vetting_requirements() {
        let (_d, _s, ks) = ks().await;
        register_membership(&ks).await;
        let mut c = criterion("kernel", MEMBERSHIP_VCT);
        c.vetting = Some(vetting(2, json!({ "inPerson": 1 })));
        store_accepts(&ks, &c)
            .await
            .expect("evaluable requirements store");
        let got = get_accepts(&ks, "kernel").await.unwrap().unwrap();
        assert_eq!(
            serde_json::to_value(got.vetting).unwrap(),
            serde_json::to_value(c.vetting).unwrap()
        );
    }

    #[tokio::test]
    async fn refuses_vetting_requirements_no_applicant_could_satisfy() {
        let (_d, _s, ks) = ks().await;
        register_membership(&ks).await;
        let mut c = criterion("kernel", MEMBERSHIP_VCT);
        c.vetting = Some(vetting(2, json!({ "video": 1 })));
        let err = store_accepts(&ks, &c)
            .await
            .expect_err("a floor on a method the requirements do not accept is refused");
        assert!(matches!(err, AppError::Validation(_)), "{err:?}");
        assert!(get_accepts(&ks, "kernel").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn refuses_a_criterion_the_join_manifest_cannot_publish() {
        let (_d, _s, ks) = ks().await;
        register_membership(&ks).await;
        let c = criterion(&"k".repeat(129), MEMBERSHIP_VCT);
        let err = store_accepts(&ks, &c)
            .await
            .expect_err("a criterion id longer than the manifest allows is refused");
        assert!(matches!(err, AppError::Validation(_)), "{err:?}");
        assert!(list_accepts(&ks).await.unwrap().is_empty());
    }

    /// The decision order is registration order, and replacing a criterion
    /// does not move it — only deleting and registering it again does.
    #[tokio::test]
    async fn published_order_is_registration_order_and_survives_replacement() {
        let (_d, _s, ks) = ks().await;
        for id in ["zeta", "alpha", "mid"] {
            store_accepts(
                &ks,
                &AcceptsCriterion::new(id, Admission::Review, "did:key:zAdmin"),
            )
            .await
            .unwrap();
        }
        let order = |v: Vec<AcceptsCriterion>| v.into_iter().map(|c| c.id).collect::<Vec<_>>();
        assert_eq!(
            order(published_criteria(&ks).await.unwrap()),
            ["zeta", "alpha", "mid"]
        );
        // `list_accepts` stays in id order, as accepts/list specifies.
        assert_eq!(
            order(list_accepts(&ks).await.unwrap()),
            ["alpha", "mid", "zeta"]
        );

        store_accepts(
            &ks,
            &AcceptsCriterion::new("zeta", Admission::Automatic, "did:key:zAdmin"),
        )
        .await
        .unwrap();
        assert_eq!(
            order(published_criteria(&ks).await.unwrap()),
            ["zeta", "alpha", "mid"],
            "a replacement keeps its place"
        );

        delete_accepts(&ks, "zeta").await.unwrap();
        store_accepts(
            &ks,
            &AcceptsCriterion::new("zeta", Admission::Automatic, "did:key:zAdmin"),
        )
        .await
        .unwrap();
        assert_eq!(
            order(published_criteria(&ks).await.unwrap()),
            ["alpha", "mid", "zeta"],
            "delete and register again moves it last"
        );
    }

    /// A replaced version stays readable by its digest, and governs only while
    /// the grace it declared lasts.
    #[tokio::test]
    async fn a_replaced_version_is_kept_for_its_grace() {
        let (_d, _s, ks) = ks().await;
        register_membership(&ks).await;
        let mut first = criterion("kernel", MEMBERSHIP_VCT);
        first.vetting = Some(vetting(2, json!({})));
        let first = store_accepts(&ks, &first).await.unwrap();
        let first_digest = crate::routes::join_requests::manifest::manifest_criterion(first)
            .unwrap()
            .digest;

        let mut second = criterion("kernel", MEMBERSHIP_VCT);
        second.vetting = Some(vetting(3, json!({})));
        store_accepts(&ks, &second).await.unwrap();

        let kept = superseded_version(&ks, &first_digest)
            .await
            .unwrap()
            .expect("the superseded version is kept");
        assert_eq!(
            kept.criterion
                .vetting
                .as_ref()
                .map(|v| u64::from(v.min_statements)),
            Some(2)
        );
        assert!(kept.within_grace(Utc::now()));
        assert!(!kept.within_grace(Utc::now() + chrono::Duration::days(15)));
    }

    #[tokio::test]
    async fn without_a_declared_grace_a_superseded_version_never_governs() {
        let (_d, _s, ks) = ks().await;
        let first = store_accepts(
            &ks,
            &AcceptsCriterion::new("open", Admission::Review, "did:key:zAdmin"),
        )
        .await
        .unwrap();
        let digest = crate::routes::join_requests::manifest::manifest_criterion(first)
            .unwrap()
            .digest;
        delete_accepts(&ks, "open").await.unwrap();
        let kept = superseded_version(&ks, &digest).await.unwrap().unwrap();
        assert!(!kept.within_grace(Utc::now()));
    }

    #[tokio::test]
    async fn seeds_the_defaults_once_and_never_again() {
        let (_d, _s, ks) = ks().await;
        // The credential criterion names the catalog type the boot seed registers.
        register_type(&ks, "MembershipCredential").await;

        assert_eq!(seed_default_criteria(&ks, true).await.unwrap(), 3);
        let published = published_criteria(&ks).await.unwrap();
        let summary: Vec<_> = published
            .iter()
            .map(|c| (c.id.as_str(), c.admission))
            .collect();
        assert_eq!(
            summary,
            [
                ("invited", Admission::Automatic),
                ("member-credential", Admission::Automatic),
                ("review", Admission::Review),
            ],
            "review last, so it governs only what meets neither of the others"
        );
        assert!(published[0].invitation_required);
        assert_eq!(
            published[1].credential_issuers,
            Some(CredentialIssuers::Recognised)
        );

        // An administrator who deletes every criterion is left with none.
        for c in published {
            delete_accepts(&ks, &c.id).await.unwrap();
        }
        assert_eq!(seed_default_criteria(&ks, true).await.unwrap(), 0);
        assert!(list_accepts(&ks).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn a_community_that_recognises_nobody_counts_only_its_own_credentials() {
        let defaults = default_criteria(false);
        assert_eq!(
            defaults[1].credential_issuers,
            Some(CredentialIssuers::Community)
        );
    }

    #[tokio::test]
    async fn a_community_with_its_own_criteria_is_not_seeded() {
        let (_d, _s, ks) = ks().await;
        store_accepts(
            &ks,
            &AcceptsCriterion::new("mine", Admission::Review, "did:key:zAdmin"),
        )
        .await
        .unwrap();
        assert_eq!(seed_default_criteria(&ks, true).await.unwrap(), 0);
        assert_eq!(list_accepts(&ks).await.unwrap().len(), 1);
    }

    /// What `show` and `list` answer is exactly the generated wire type: no
    /// store-only member reaches it.
    #[test]
    fn the_wire_form_is_the_specifications_type() {
        let mut c = criterion("kernel", MEMBERSHIP_VCT);
        c.invitation_required = true;
        c.position = 7;
        c.hidden_vetting = Some(json!({ "suite": "x" }));
        let wire = c.to_wire();
        assert!(wire.get("position").is_none());
        assert!(wire.get("hiddenVetting").is_none());
        use trust_tasks_rs::specs::vtc::schemas::accepts::{list, register, show};
        serde_json::from_value::<register::v0_2::AcceptsCriterion>(wire.clone()).unwrap();
        serde_json::from_value::<show::v0_2::AcceptsCriterion>(wire.clone()).unwrap();
        serde_json::from_value::<list::v0_2::AcceptsCriterion>(wire).unwrap();
    }
}
