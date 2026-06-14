//! The schema store's **Accepts** half (task 2.4,
//! `docs/05-design-notes/vti-credential-architecture.md` §8).
//!
//! Where the **Issues** registry ([`super::SchemaEntry`]) names the types the
//! community *mints*, an **Accepts criterion** names the evidence the community
//! *recognises* — expressed as a **DCQL query** ([`affinidi_openid4vp::DcqlQuery`])
//! over the registry. This is the join "manifest" / required-evidence, now
//! concrete: a ceremony's required evidence is a stored Accepts criterion, run
//! against a holder's presented credentials via
//! [`DcqlQuery::match_credentials`](affinidi_openid4vp::DcqlQuery::match_credentials)
//! (Phase 5).
//!
//! ## Validation
//!
//! A criterion is only stored if its query is (a) a **structurally-valid DCQL
//! query** and (b) every credential type it references (`meta.vct_values`) is a
//! **registered** schema-store type — no dangling references to types the
//! community doesn't know about.
//!
//! Criteria live in the same `schemas` keyspace under a disjoint `accepts:<id>`
//! key namespace (the Issues registry uses `schemas:<type-uri>`).

use affinidi_openid4vp::DcqlQuery;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use vti_common::error::AppError;
use vti_common::store::KeyspaceHandle;

use super::schema_exists;

/// Key prefix for stored Accepts criteria — disjoint from `schemas:` (the
/// per-type Issues registry).
pub const ACCEPTS_PREFIX: &[u8] = b"accepts:";

fn key(id: &str) -> Vec<u8> {
    let mut k = ACCEPTS_PREFIX.to_vec();
    k.extend_from_slice(id.as_bytes());
    k
}

/// A named required-evidence criterion: a DCQL query over the schema-store
/// registry that a ceremony runs to decide whether a holder's presented
/// credentials satisfy the community's acceptance rules.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
#[derive(utoipa::ToSchema)]
pub struct AcceptsCriterion {
    /// Criterion id (e.g. a ceremony purpose or a named manifest). Primary key.
    pub id: String,
    /// The DCQL query, stored as JSON. Structurally validated and every
    /// referenced type checked against the registry when stored (see
    /// [`validate_accepts_query`]).
    pub query: Value,
    /// Free-form description shown in admin UIs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub created_at: DateTime<Utc>,
    /// Admin DID that registered the criterion (audit correlation).
    pub created_by_did: String,
}

/// The credential type URIs a DCQL query references via each credential query's
/// `meta.vct_values` (the SD-JWT-VC type selector).
fn referenced_types(query: &DcqlQuery) -> Vec<String> {
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

/// Validate + store an Accepts criterion. The query is validated against the
/// registry first; a criterion with a malformed query or a dangling type
/// reference is **not** stored.
pub async fn store_accepts(
    schemas_ks: &KeyspaceHandle,
    criterion: &AcceptsCriterion,
) -> Result<(), AppError> {
    validate_accepts_query(schemas_ks, &criterion.query).await?;
    schemas_ks
        .insert(
            String::from_utf8(key(&criterion.id)).expect("ascii key"),
            criterion,
        )
        .await
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

/// List all stored Accepts criteria.
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

/// Remove a stored Accepts criterion.
pub async fn delete_accepts(schemas_ks: &KeyspaceHandle, id: &str) -> Result<(), AppError> {
    schemas_ks.remove(key(id)).await
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
    async fn register_membership(ks: &KeyspaceHandle) {
        store_schema(
            ks,
            &SchemaEntry {
                type_uri: MEMBERSHIP_VCT.into(),
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

    fn criterion(id: &str, vct: &str) -> AcceptsCriterion {
        AcceptsCriterion {
            id: id.into(),
            query: json!({
                "credentials": [{
                    "id": "membership",
                    "format": "dc+sd-jwt",
                    "meta": { "vct_values": [vct] },
                    "claims": [{ "path": ["givenName"] }]
                }]
            }),
            description: Some("join evidence".into()),
            created_at: Utc::now(),
            created_by_did: "did:key:zAdmin".into(),
        }
    }

    #[tokio::test]
    async fn stores_a_criterion_that_references_a_registered_type() {
        let (_d, _s, ks) = ks().await;
        register_membership(&ks).await;

        let c = criterion("join", MEMBERSHIP_VCT);
        store_accepts(&ks, &c)
            .await
            .expect("valid criterion stores");

        let got = get_accepts(&ks, "join").await.unwrap().unwrap();
        assert_eq!(got, c);
        assert_eq!(list_accepts(&ks).await.unwrap().len(), 1);

        // Retrievable as a runnable DCQL query (what a ceremony does).
        let dcql = DcqlQuery::from_json(&got.query).expect("stored query is valid DCQL");
        assert_eq!(dcql.credentials.len(), 1);

        delete_accepts(&ks, "join").await.unwrap();
        assert!(get_accepts(&ks, "join").await.unwrap().is_none());
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
        let bad = AcceptsCriterion {
            id: "bad".into(),
            // Empty `credentials` is invalid DCQL.
            query: json!({ "credentials": [] }),
            description: None,
            created_at: Utc::now(),
            created_by_did: "did:key:zAdmin".into(),
        };
        let err = store_accepts(&ks, &bad)
            .await
            .expect_err("invalid DCQL must be rejected");
        assert!(matches!(err, AppError::Validation(_)), "{err:?}");
    }
}
