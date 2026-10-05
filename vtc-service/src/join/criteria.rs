//! Deciding a join submission against the community's published criteria
//! (`vtc/join-requests/submit/0.3` §Deciding a submission).
//!
//! The criteria are the community's join rules, and this module adds none of
//! its own. It answers three questions, in this order:
//!
//! 1. **Which criterion governs.** The one the submission names by its
//!    `requirementsDigest` — at the version that digest names while that
//!    version is within its `requirementsGrace` — or, when it names none, the
//!    first criterion in published order that the submission meets, and when it
//!    meets none, the first published. A community with no criteria accepts no
//!    applications ([`CriterionRefusal::NotAccepting`]); a digest naming none of
//!    them is [`CriterionRefusal::Unknown`].
//! 2. **Whether the submission meets it** — every requirement it states, and
//!    only those:
//!    - *credentials*: the presentation carries credentials satisfying the DCQL
//!      query, each verifying (signature, validity window, revocation), bound
//!      to the applicant, and issued by a party `credentialIssuers` admits;
//!    - *vetting*: the statements presented meet the `vetting` object, counted
//!      by [`crate::vetting::vetting_facts`];
//!    - *invitation*: when `invitationRequired`, a valid, unconsumed invitation
//!      this community issued to the applicant.
//! 3. **What that obliges** — carried to the decision as a
//!    [`CriterionFact`], which the host invariant
//!    ([`crate::ceremony::invariant`]) holds the policy to: a submission that
//!    does not meet its criterion is never admitted, nor referred for an
//!    administrator to admit; one meeting a `review` criterion is referred,
//!    never admitted on the submission; one meeting an `automatic` criterion is
//!    admitted unless the policy refuses or refers it on grounds of its own.
//!
//! Something presented that the governing criterion does not ask for — an
//! invitation, a credential — does not help meet it.

use std::collections::HashMap;

use affinidi_openid4vp::dcql::CandidateCredential;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value as JsonValue, json};
use tracing::{debug, warn};
use vti_common::error::AppError;

use crate::ceremony::{CredentialStatus, Invitation, Presentation};
use crate::routes::join_requests::manifest::{ServedCriterion, manifest_criterion};
use crate::schemas::accepts::{
    AcceptsCriterion, Admission, CredentialIssuers, published_criteria, superseded_version,
};
use crate::server::AppState;
use crate::vetting::VettingFacts;
use crate::vetting::challenge_refusal::ChallengeRefusal;

/// The DCQL `format` of a W3C Verifiable Credential secured with a Data
/// Integrity proof — what a join presentation's `verifiableCredential` carries.
pub const LDP_VC_FORMAT: &str = "ldp_vc";

/// The DCQL `format` of an SD-JWT VC.
pub const SD_JWT_VC_FORMAT: &str = "dc+sd-jwt";

/// The need named when a criterion's credentials are not presented.
pub const NEED_CREDENTIALS: &str = "credentials";

/// The need named when a criterion requires an invitation and none valid was
/// presented.
pub const NEED_INVITATION: &str = "invitation";

/// The generic need a policy returns for "whatever the criterion still
/// lacks"; the host expands it into [`CriterionFact::needs`].
pub const NEED_CRITERION: &str = "criterion";

/// What the decision is told about the criterion a submission is decided
/// under. Every member is a host verdict.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CriterionFact {
    /// The criterion's id.
    pub id: String,
    /// The `requirementsDigest` of the version that governed.
    pub requirements_digest: String,
    /// How a submission meeting it is decided.
    pub admission: Admission,
    /// The submission meets every requirement the criterion states.
    pub met: bool,
    /// What is still missing, when not met: [`NEED_CREDENTIALS`],
    /// [`NEED_INVITATION`], or the vetting shortfall in the `vetting:*`
    /// grammar. Never empty when `met` is false.
    #[serde(default)]
    pub needs: Vec<String>,
    /// The submission named this criterion.
    pub cited: bool,
    /// The version that governed is not the current one: the submission cited
    /// a superseded version still within its grace.
    #[serde(default)]
    pub superseded: bool,
}

/// The criterion a submission is decided under, and what it established.
#[derive(Debug, Clone)]
pub struct Governing {
    /// The criterion, as served at the version that governed.
    pub served: ServedCriterion,
    /// The decision's view of it.
    pub fact: CriterionFact,
    /// The vetting count under it, when it requires vetting.
    pub vetting: Option<VettingFacts>,
}

impl Governing {
    /// The DCQL query the applicant still has to satisfy, for a `requestMore`.
    pub fn presentation_definition(&self) -> Option<JsonValue> {
        self.fact
            .needs
            .iter()
            .any(|n| n == NEED_CREDENTIALS)
            .then(|| self.served.stored.query.clone())
            .flatten()
    }
}

/// Why no criterion could govern.
#[derive(Debug)]
pub enum CriterionRefusal {
    /// The community publishes no criteria (`submit:notAccepting`).
    NotAccepting,
    /// The cited digest names no criterion the community publishes, nor a
    /// superseded version within its grace (`submit:criterionUnknown`).
    Unknown(String),
    /// The hidden-vetting challenge the submission's proof is bound to was refused
    /// (`submit:challenge*` / `supplement:challenge*`).
    Challenge(ChallengeRefusal),
    /// Everything else.
    Other(AppError),
}

impl From<AppError> for CriterionRefusal {
    fn from(e: AppError) -> Self {
        Self::Other(e)
    }
}

impl From<crate::vetting::FactsError> for CriterionRefusal {
    fn from(e: crate::vetting::FactsError) -> Self {
        match e {
            crate::vetting::FactsError::Challenge(r) => Self::Challenge(r),
            crate::vetting::FactsError::App(e) => Self::Other(e),
        }
    }
}

/// A presented credential that verified and is the applicant's own, as a
/// criterion's query reads it.
#[derive(Debug, Clone)]
pub struct PresentedCredential {
    /// The DCQL formats it can be matched as.
    pub formats: Vec<&'static str>,
    /// The type names a query's `meta.vct_values` can select it by.
    pub types: Vec<String>,
    /// The tree a DCQL claim `path` walks.
    pub claims: JsonValue,
    /// Its issuer's DID.
    pub issuer: String,
}

/// Everything a submission presented that a criterion can ask for, verified
/// once and read by every criterion evaluated.
#[derive(Debug, Clone, Default)]
pub struct Presented {
    /// Credentials that verified and are bound to the applicant.
    pub credentials: Vec<PresentedCredential>,
    /// The invitation, when one was presented and verified.
    pub invitation: Option<Invitation>,
    /// The raw presentation, for the vetting count. `None` on a path that
    /// carries no vetting statements.
    pub vp: Option<JsonValue>,
    /// The submission's `extensions`, where a hidden-vetting proof rides.
    pub extensions: JsonValue,
}

/// Decide which criterion governs a submission, and whether it meets it.
///
/// `cited` is the `requirementsDigest` the submission names as its
/// `criterion`, if any.
pub async fn govern(
    state: &AppState,
    applicant_did: &str,
    presented: &Presented,
    cited: Option<&str>,
    now: DateTime<Utc>,
) -> Result<Governing, CriterionRefusal> {
    let published = published_criteria(&state.schemas_ks).await?;
    if published.is_empty() {
        return Err(CriterionRefusal::NotAccepting);
    }
    let mut ctx = Evaluator::new(state, applicant_did, presented, now).await;

    if let Some(digest) = cited {
        for stored in &published {
            let served = manifest_criterion(stored.clone())?;
            if served.digest == digest {
                return ctx.evaluate(served, true, false).await;
            }
        }
        if let Some(version) = superseded_version(&state.schemas_ks, digest).await?
            && version.within_grace(now)
        {
            let served = manifest_criterion(version.criterion)?;
            return ctx.evaluate(served, true, true).await;
        }
        return Err(CriterionRefusal::Unknown(digest.to_string()));
    }

    let mut first = None;
    for stored in published {
        let served = manifest_criterion(stored)?;
        let governing = ctx.evaluate(served, false, false).await?;
        if governing.fact.met {
            return Ok(governing);
        }
        first.get_or_insert(governing);
    }
    Ok(first.expect("published is not empty"))
}

/// Decide a credential-exchange presentation under the criterion the query it
/// answers was built from (`id`), or — for a challenge that names none — as a
/// submission naming no criterion is decided.
pub async fn govern_by_id(
    state: &AppState,
    applicant_did: &str,
    presented: &Presented,
    id: Option<&str>,
    now: DateTime<Utc>,
) -> Result<Governing, CriterionRefusal> {
    let Some(id) = id else {
        return govern(state, applicant_did, presented, None, now).await;
    };
    let Some(stored) = crate::schemas::accepts::get_accepts(&state.schemas_ks, id).await? else {
        return Err(CriterionRefusal::Unknown(id.to_string()));
    };
    let served = manifest_criterion(stored)?;
    let mut ctx = Evaluator::new(state, applicant_did, presented, now).await;
    ctx.evaluate(served, true, false).await
}

/// Re-decide a request under the criterion it was first decided under — a
/// supplement adds evidence to a request, it does not reopen the choice of
/// criterion.
///
/// The version recorded governs while it is current, or superseded and within
/// its grace; past that, the criterion's current version under the same id.
/// A criterion since deleted, and past its grace, governs nothing.
pub async fn govern_again(
    state: &AppState,
    applicant_did: &str,
    presented: &Presented,
    id: &str,
    digest: &str,
    now: DateTime<Utc>,
) -> Result<Governing, CriterionRefusal> {
    let mut ctx = Evaluator::new(state, applicant_did, presented, now).await;
    let current = crate::schemas::accepts::get_accepts(&state.schemas_ks, id).await?;
    if let Some(stored) = current.clone() {
        let served = manifest_criterion(stored)?;
        if served.digest == digest {
            return ctx.evaluate(served, true, false).await;
        }
    }
    if let Some(version) = superseded_version(&state.schemas_ks, digest).await?
        && version.within_grace(now)
    {
        let served = manifest_criterion(version.criterion)?;
        return ctx.evaluate(served, true, true).await;
    }
    match current {
        Some(stored) => {
            let served = manifest_criterion(stored)?;
            ctx.evaluate(served, false, false).await
        }
        None => Err(CriterionRefusal::Unknown(digest.to_string())),
    }
}

/// Evaluates criteria against one submission, holding what every criterion
/// reads the same way: the community's DID and each issuer's recognition, which
/// is asked once.
struct Evaluator<'a> {
    state: &'a AppState,
    applicant_did: &'a str,
    presented: &'a Presented,
    now: DateTime<Utc>,
    own_did: Option<String>,
    recognised: HashMap<String, bool>,
}

impl<'a> Evaluator<'a> {
    async fn new(
        state: &'a AppState,
        applicant_did: &'a str,
        presented: &'a Presented,
        now: DateTime<Utc>,
    ) -> Self {
        let own_did = state.config.read().await.vtc_did.clone();
        Self {
            state,
            applicant_did,
            presented,
            now,
            own_did,
            recognised: HashMap::new(),
        }
    }

    async fn evaluate(
        &mut self,
        served: ServedCriterion,
        cited: bool,
        superseded: bool,
    ) -> Result<Governing, CriterionRefusal> {
        let stored = &served.stored;
        let mut needs = Vec::new();

        if let Some(query) = stored.dcql()?
            && !self.credentials_meet(stored, &query).await
        {
            needs.push(NEED_CREDENTIALS.to_string());
        }

        let vetting = match &self.presented.vp {
            Some(vp) => {
                crate::vetting::vetting_facts(
                    self.state,
                    self.applicant_did,
                    vp,
                    &self.presented.extensions,
                    &served,
                    cited,
                    self.now,
                )
                .await?
            }
            None => None,
        };
        if stored.vetting.is_some() {
            match &vetting {
                Some(facts) => needs.extend(vetting_shortfall(facts, self.vetting_invitation())),
                // A path that carries no statements cannot meet a vetting
                // requirement.
                None => needs.push(crate::vetting::NEED_VETTING.to_string()),
            }
        }

        if stored.invitation_required && !self.own_invitation() {
            needs.push(NEED_INVITATION.to_string());
        }

        let fact = CriterionFact {
            id: stored.id.clone(),
            requirements_digest: served.digest.clone(),
            admission: stored.admission,
            met: needs.is_empty(),
            needs,
            cited,
            superseded,
        };
        debug!(
            criterion = %fact.id,
            met = fact.met,
            needs = ?fact.needs,
            "join criterion evaluated"
        );
        Ok(Governing {
            served,
            fact,
            vetting,
        })
    }

    /// `invitationRequired`: a valid, unconsumed invitation **this community**
    /// issued — an invitation from a recognised peer is not one.
    fn own_invitation(&self) -> bool {
        self.presented.invitation.as_ref().is_some_and(|inv| {
            inv.verified && !inv.consumed && self.own_did.as_deref() == Some(inv.issuer.as_str())
        })
    }

    /// The invitation a `vetting` object's own `invitation: required` asks for:
    /// valid, unconsumed, and from an issuer the community trusts for
    /// invitations — what that member has always meant.
    fn vetting_invitation(&self) -> bool {
        self.presented
            .invitation
            .as_ref()
            .is_some_and(|inv| inv.verified && inv.issuer_trusted && !inv.consumed)
    }

    /// Whether the credentials presented, from issuers this criterion admits,
    /// satisfy its query.
    async fn credentials_meet(
        &mut self,
        stored: &AcceptsCriterion,
        query: &affinidi_openid4vp::DcqlQuery,
    ) -> bool {
        let issuers = stored
            .credential_issuers
            // Registration refuses a query without one; a row that has one
            // anyway is read the restrictive way.
            .unwrap_or(CredentialIssuers::Community);
        let mut admitted = Vec::new();
        for c in &self.presented.credentials {
            if self.issuer_admitted(issuers, &c.issuer).await {
                admitted.push(c);
            }
        }
        query_met_by(query, &admitted)
    }

    async fn issuer_admitted(&mut self, issuers: CredentialIssuers, issuer: &str) -> bool {
        let own = self.own_did.as_deref() == Some(issuer);
        match issuers {
            CredentialIssuers::Any => true,
            CredentialIssuers::Community => own,
            CredentialIssuers::Recognised => {
                if own {
                    return true;
                }
                if let Some(known) = self.recognised.get(issuer) {
                    return *known;
                }
                let known = crate::routes::join_requests::present::issuer_trusted(
                    self.state.registry_client.as_deref(),
                    self.own_did.as_deref(),
                    issuer,
                )
                .await;
                self.recognised.insert(issuer.to_string(), known);
                known
            }
        }
    }
}

/// Whether `credentials` — already limited to issuers the criterion admits —
/// satisfy `query`.
fn query_met_by(
    query: &affinidi_openid4vp::DcqlQuery,
    credentials: &[&PresentedCredential],
) -> bool {
    let (query, type_selectors) = with_type_values_as_keys(query);
    let mut candidates = Vec::new();
    for (n, c) in credentials.iter().enumerate() {
        let selected_by = type_selectors
            .iter()
            .filter(|(_, alternatives)| {
                alternatives
                    .iter()
                    .any(|all| all.iter().all(|t| c.types.contains(t)))
            })
            .map(|(key, _)| key.clone());
        let keys: Vec<String> = c.types.iter().cloned().chain(selected_by).collect();
        for format in &c.formats {
            for vct in &keys {
                candidates.push(CandidateCredential {
                    id: n.to_string(),
                    format: (*format).to_string(),
                    claims: c.claims.clone(),
                    vct: Some(vct.clone()),
                    doctype: None,
                    // Every presented credential here is bound to the
                    // applicant: its subject is the proven submitter.
                    supports_holder_binding: true,
                });
            }
        }
    }
    query.match_credentials(&candidates).is_ok()
}

/// DCQL selects a W3C credential by `meta.type_values` — alternatives, each a
/// set of types the credential's `type` must all carry — and the matcher reads
/// only `vct_values`. So each credential query selecting by `type_values` (and
/// not also by `vct_values`) is rewritten to select by a key of its own, and a
/// candidate whose types satisfy one of its alternatives is offered under that
/// key. Returns the rewritten query and, per key, the alternatives it stands
/// for. Without this a `type_values` query would match a credential of any
/// type.
fn with_type_values_as_keys(
    query: &affinidi_openid4vp::DcqlQuery,
) -> (
    affinidi_openid4vp::DcqlQuery,
    Vec<(String, Vec<Vec<String>>)>,
) {
    let mut query = query.clone();
    let mut selectors = Vec::new();
    for cq in &mut query.credentials {
        let Some(meta) = cq.meta.as_mut() else {
            continue;
        };
        if meta.contains_key("vct_values") {
            continue;
        }
        let Some(type_values) = meta.remove("type_values") else {
            continue;
        };
        let alternatives: Vec<Vec<String>> = type_values
            .as_array()
            .into_iter()
            .flatten()
            .map(|alt| match alt {
                // An array of types the credential must all carry.
                JsonValue::Array(types) => types
                    .iter()
                    .filter_map(JsonValue::as_str)
                    .map(str::to_string)
                    .collect(),
                // A bare type, read as the one-type set it means.
                JsonValue::String(t) => vec![t.clone()],
                _ => Vec::new(),
            })
            // An empty set would select everything; it selects nothing here.
            .filter(|alt: &Vec<String>| !alt.is_empty())
            .collect();
        let key = format!("urn:vtc:dcql:type-values:{}", cq.id);
        meta.insert("vct_values".into(), json!([key]));
        selectors.push((key, alternatives));
    }
    (query, selectors)
}

/// What a vetting count still lacks, in the `vetting:*` grammar. Never empty
/// when the vetting requirement is unmet: a count that is complete but whose
/// vetters disagree, or are not independent enough, names that.
fn vetting_shortfall(facts: &VettingFacts, invitation_held: bool) -> Vec<String> {
    let mut needs = Vec::new();
    if !facts.commitments_consistent {
        needs.push("vetting:consistency".to_string());
    }
    needs.extend(facts.needs.iter().cloned());
    if facts.commitments_consistent && facts.needs.is_empty() && !facts.independence_ok {
        needs.push("vetting:independence".to_string());
    }
    if !facts.satisfied && needs.is_empty() {
        needs.push(crate::vetting::NEED_VETTING.to_string());
    }
    if facts.satisfied && facts.invitation_required && !invitation_held {
        needs.push(crate::vetting::NEED_INVITATION.to_string());
    }
    needs
}

/// Replace a policy's generic [`NEED_CRITERION`] with what the criterion
/// still lacks. Leaves `needs` untouched when there is nothing specific.
pub fn expand_needs(needs: &mut Vec<String>, fact: Option<&CriterionFact>) {
    let Some(fact) = fact else {
        return;
    };
    if fact.needs.is_empty() {
        return;
    }
    if let Some(pos) = needs.iter().position(|n| n == NEED_CRITERION) {
        needs.splice(pos..=pos, fact.needs.iter().cloned());
    }
}

/// Verify the credentials embedded in a join presentation that a criterion's
/// query can read: each one's issuer proof set, its validity window and its
/// revocation status, and that its subject is the applicant.
///
/// A credential that fails any of those is left out, not refused: a credential
/// that does not verify meets no criterion, and the decision is made on what
/// did. Each one left out is logged with its reason. Invitations are verified
/// by their own path ([`crate::credentials::invitation_verify`]) and vetting
/// statements by theirs, but a query naming either type can still be met by
/// one here — whether it is, is the criterion's business.
pub async fn verify_embedded_credentials(
    state: &AppState,
    applicant_did: &str,
    vp: &JsonValue,
    now: DateTime<Utc>,
) -> Result<Vec<PresentedCredential>, AppError> {
    let Some(vcs) = vp.get("verifiableCredential").and_then(JsonValue::as_array) else {
        return Ok(Vec::new());
    };
    if vcs.is_empty() {
        return Ok(Vec::new());
    }
    let resolver = crate::credentials::vm_resolver::DidVmResolver::new(state.did_resolver.clone());
    let fetcher = match state.did_resolver.clone() {
        Some(r) => {
            let key_resolver: std::sync::Arc<dyn vti_common::auth::PurposeVmResolver> =
                std::sync::Arc::new(crate::credentials::vm_resolver::DidVmResolver::new(Some(r)));
            crate::recognition::HttpStatusListFetcher::with_issuer_verification(key_resolver)
        }
        None => crate::recognition::HttpStatusListFetcher::new(),
    };
    let aliases = type_aliases(state).await?;

    let mut out = Vec::new();
    for vc in vcs.iter().filter(|v| v.is_object()) {
        match verify_one_credential(vc, applicant_did, &resolver, &fetcher, now).await {
            Ok((issuer, concrete)) => {
                // Its own `type` array, and the registered URIs its concrete
                // type is also known by.
                let mut types: Vec<String> = match vc.get("type") {
                    Some(JsonValue::Array(t)) => t
                        .iter()
                        .filter_map(JsonValue::as_str)
                        .map(str::to_string)
                        .collect(),
                    Some(JsonValue::String(t)) => vec![t.clone()],
                    _ => Vec::new(),
                };
                if !types.contains(&concrete) {
                    types.push(concrete.clone());
                }
                if let Some(more) = aliases.get(&concrete) {
                    types.extend(more.iter().cloned());
                }
                out.push(PresentedCredential {
                    formats: vec![LDP_VC_FORMAT],
                    types,
                    claims: vc.clone(),
                    issuer,
                });
            }
            Err(reason) => warn!(
                applicant = %applicant_did,
                credential = vc.get("id").and_then(JsonValue::as_str).unwrap_or("<no id>"),
                %reason,
                "presented credential did not verify — it meets no join criterion"
            ),
        }
    }
    Ok(out)
}

/// The registered type URIs each concrete DTG type is also known by, so a
/// query naming a registered URI selects the credential carrying that type.
async fn type_aliases(state: &AppState) -> Result<HashMap<String, Vec<String>>, AppError> {
    let mut aliases: HashMap<String, Vec<String>> = HashMap::new();
    for entry in crate::schemas::list_schemas(&state.schemas_ks).await? {
        if let Some(dtg) = entry.dtg_type
            && dtg != entry.type_uri
        {
            aliases.entry(dtg).or_default().push(entry.type_uri);
        }
    }
    Ok(aliases)
}

/// Verify one embedded credential. Returns its issuer and concrete type.
async fn verify_one_credential(
    vc: &JsonValue,
    applicant_did: &str,
    resolver: &dyn vti_common::auth::PurposeVmResolver,
    fetcher: &dyn crate::recognition::StatusListFetcher,
    now: DateTime<Utc>,
) -> Result<(String, String), String> {
    let issuer = match vc.get("issuer") {
        Some(JsonValue::String(s)) => s.clone(),
        Some(JsonValue::Object(o)) => o
            .get("id")
            .and_then(JsonValue::as_str)
            .ok_or("issuer has no id")?
            .to_string(),
        _ => return Err("no issuer".into()),
    };
    let subject = vc
        .pointer("/credentialSubject/id")
        .and_then(JsonValue::as_str)
        .ok_or("no credentialSubject.id")?;
    if subject.split('#').next().unwrap_or(subject) != applicant_did {
        return Err(format!("its subject ({subject}) is not the applicant"));
    }
    let concrete = crate::credentials::ingress::concrete_type(vc).ok_or("no concrete type")?;
    crate::credentials::ingress::check_validity_window(vc, now, "credential")
        .map_err(|e| e.to_string())?;
    crate::credentials::proof_set::verify_issued(vc, &issuer, resolver).await?;
    match crate::routes::join_requests::present::resolve_presented_status(
        vc.get("credentialStatus"),
        Some(&issuer),
        fetcher,
    )
    .await
    {
        CredentialStatus::Valid => Ok((issuer, concrete)),
        other => Err(format!("its status is {other:?}")),
    }
}

/// The credentials a cryptographically verified `vp_token` carried, as a
/// criterion's query reads them: those bound to the holder and valid now.
///
/// The SD-JWT path's claims are the credential's own; the Data Integrity
/// path's are its `credentialSubject`, so as an `ldp_vc` they are read from
/// under that member, where a W3C claim path starts.
pub fn presented_from_verified(presentation: &Presentation) -> Vec<PresentedCredential> {
    presentation
        .credentials
        .iter()
        .filter(|c| c.holder_bound && c.status == CredentialStatus::Valid)
        .map(|c| PresentedCredential {
            formats: vec![SD_JWT_VC_FORMAT, LDP_VC_FORMAT],
            types: vec![c.credential_type.clone()],
            claims: match c.claims.get("credentialSubject") {
                Some(_) => c.claims.clone(),
                None => {
                    let mut flat = c.claims.clone();
                    if let Some(map) = flat.as_object_mut() {
                        map.insert("credentialSubject".into(), json!(c.claims));
                    }
                    flat
                }
            },
            issuer: c.issuer.clone(),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vetting(
        consistent: bool,
        independent: bool,
        needs: &[&str],
        satisfied: bool,
    ) -> VettingFacts {
        VettingFacts {
            criterion_id: "k".into(),
            requirements_digest: "zK".into(),
            applicant_digest_matches: true,
            statements: vec![],
            distinct_counted_vetters: 0,
            by_method: Default::default(),
            commitments_consistent: consistent,
            independence_ok: independent,
            invitation_required: false,
            satisfied,
            needs: needs.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn an_unmet_vetting_requirement_always_names_what_is_missing() {
        assert_eq!(
            vetting_shortfall(
                &vetting(true, true, &["vetting:statements:1"], false),
                false
            ),
            ["vetting:statements:1"]
        );
        assert_eq!(
            vetting_shortfall(&vetting(false, true, &[], false), false),
            ["vetting:consistency"]
        );
        assert_eq!(
            vetting_shortfall(&vetting(true, false, &[], false), false),
            ["vetting:independence"]
        );
        assert!(vetting_shortfall(&vetting(true, true, &[], true), false).is_empty());
    }

    #[test]
    fn a_vetting_invitation_requirement_is_part_of_the_vetting() {
        let mut facts = vetting(true, true, &[], true);
        facts.invitation_required = true;
        assert_eq!(
            vetting_shortfall(&facts, false),
            [crate::vetting::NEED_INVITATION]
        );
        assert!(vetting_shortfall(&facts, true).is_empty());
    }

    fn ldp(types: &[&str], subject: serde_json::Value) -> PresentedCredential {
        PresentedCredential {
            formats: vec![LDP_VC_FORMAT],
            types: types.iter().map(|t| t.to_string()).collect(),
            claims: json!({ "type": types, "credentialSubject": subject }),
            issuer: "did:web:issuer.example".into(),
        }
    }

    fn query(v: serde_json::Value) -> affinidi_openid4vp::DcqlQuery {
        affinidi_openid4vp::DcqlQuery::from_json(&v).unwrap()
    }

    /// `type_values` selects by the credential's types. The matcher alone
    /// ignores it, which would let a credential of any type meet the query.
    #[test]
    fn a_type_values_query_selects_only_credentials_of_that_type() {
        let q = query(json!({ "credentials": [{
            "id": "membership",
            "format": "ldp_vc",
            "meta": { "type_values": [["VerifiableCredential", "MembershipCredential"]] }
        }]}));
        let membership = ldp(&["VerifiableCredential", "MembershipCredential"], json!({}));
        let other = ldp(&["VerifiableCredential", "EmailCredential"], json!({}));
        assert!(query_met_by(&q, &[&membership]));
        assert!(!query_met_by(&q, &[&other]));
        assert!(!query_met_by(&q, &[]));
    }

    /// One alternative of `type_values` is enough; within it every type must
    /// be carried.
    #[test]
    fn any_one_type_values_alternative_selects() {
        let q = query(json!({ "credentials": [{
            "id": "proof-of-employment",
            "format": "ldp_vc",
            "meta": { "type_values": [["EmployeeCredential"], ["ContractorCredential", "Vetted"]] }
        }]}));
        assert!(query_met_by(
            &q,
            &[&ldp(&["EmployeeCredential"], json!({}))]
        ));
        assert!(!query_met_by(
            &q,
            &[&ldp(&["ContractorCredential"], json!({}))]
        ));
        assert!(query_met_by(
            &q,
            &[&ldp(&["ContractorCredential", "Vetted"], json!({}))]
        ));
    }

    #[test]
    fn a_claims_constraint_reads_the_credential() {
        let q = query(json!({ "credentials": [{
            "id": "membership",
            "format": "ldp_vc",
            "meta": { "type_values": [["MembershipCredential"]] },
            "claims": [{ "path": ["credentialSubject", "level"], "values": ["full"] }]
        }]}));
        let full = ldp(&["MembershipCredential"], json!({ "level": "full" }));
        let associate = ldp(&["MembershipCredential"], json!({ "level": "associate" }));
        assert!(query_met_by(&q, &[&full]));
        assert!(!query_met_by(&q, &[&associate]));
    }

    /// The default `member-credential` criterion is met by a membership
    /// credential and nothing else.
    #[test]
    fn the_default_credential_criterion_is_met_by_a_membership_credential() {
        let defaults = crate::schemas::accepts::default_criteria(true);
        let q = defaults[1].dcql().unwrap().expect("a query");
        let vmc = ldp(
            &[
                "VerifiableCredential",
                "DTGCredential",
                "MembershipCredential",
            ],
            json!({}),
        );
        let vic = ldp(
            &[
                "VerifiableCredential",
                "DTGCredential",
                "InvitationCredential",
            ],
            json!({}),
        );
        assert!(query_met_by(&q, &[&vmc]));
        assert!(!query_met_by(&q, &[&vic]));
    }

    #[test]
    fn the_generic_need_becomes_what_the_criterion_lacks() {
        let fact = CriterionFact {
            id: "k".into(),
            requirements_digest: "zK".into(),
            admission: Admission::Automatic,
            met: false,
            needs: vec![NEED_INVITATION.into(), NEED_CREDENTIALS.into()],
            cited: false,
            superseded: false,
        };
        let mut needs = vec!["agreed:code-of-conduct".to_string(), NEED_CRITERION.into()];
        expand_needs(&mut needs, Some(&fact));
        assert_eq!(
            needs,
            ["agreed:code-of-conduct", NEED_INVITATION, NEED_CREDENTIALS]
        );
    }
}
