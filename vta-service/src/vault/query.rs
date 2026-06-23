//! Local search over the credential vault — DCQL-*shaped* filtering that
//! returns lightweight **descriptors**, never credential bodies (task 1.3 of
//! the VTI credential architecture,
//! `docs/05-design-notes/vti-credential-architecture.md` §5 search, §14
//! invariants).
//!
//! ## What this is — and what it deliberately is not
//!
//! This is the *local* search primitive the holder's agent uses to find the
//! credentials it already holds, matching on the indexed envelope fields
//! `{type, community_did, issuer_did, purpose, status}`. The filter is
//! **DCQL-shaped** — it expresses the same "find credentials matching these
//! criteria" intent — but it is **not** the TDK DCQL model. Full
//! claims-level DCQL matching (querying into the credential body) arrives
//! later with TDK Phase 0c; this layer never parses a body, so it can only
//! match the indexed metadata, by design.
//!
//! ## No-enumeration invariant (§14.1, §16 "Ask first" / "Never")
//!
//! The spec is categorical: *no endpoint returns a holder's credential
//! list; discovery is DCQL-targeted only.* This module is the storage-layer
//! expression of that rule, and it enforces it three ways:
//!
//! 1. **At least one explicit filter is required.** An empty
//!    [`CredentialQuery`] (no field set) is rejected with
//!    [`AppError::Validation`] *before any I/O* — there is no
//!    "return everything" path to reach.
//! 2. **There is no return-all primitive.** Every search starts from an
//!    index scan on a concrete `(field, value)` pair (reusing
//!    [`super::index::scan`] via [`super::storage::find_by_index`]), so a
//!    caller can only ever retrieve credentials it can already *name* by an
//!    indexed value.
//! 3. **Descriptors never carry the body.** The returned
//!    [`CredentialDescriptor`] is a metadata projection — id, types, issuer,
//!    purpose, status, validity window. The opaque (and at-rest-encrypted)
//!    `body` is never read into a descriptor, so a search result cannot leak
//!    credential contents even to an authorised caller.
//!
//! Higher layers (routes / operations / DCQL) built on top must preserve all
//! three properties; this module gives them only a targeted primitive to
//! build on, never a firehose.
//!
//! ## Archival lifecycle is opt-in, and does not weaken any of the above
//!
//! By default search returns only `Active` credentials. The
//! [`CredentialQuery::include_archived`] / [`CredentialQuery::include_deleted`]
//! flags let the **holder** (this is a holder-scoped, `VaultRead`-gated
//! surface — there is no cross-holder enumeration) additionally surface
//! `Archived` / `Deleted` rows so a management UI can browse the archive,
//! restore from trash, or purge. This is a **relaxation of the lifecycle
//! post-filter only**, applied *after* the indexed match — all three
//! no-enumeration properties stand: at least one real filter is still
//! required (the include flags are modifiers, not filters, so
//! `{ includeArchived: true }` alone is still refused), the scan is still
//! anchored on a named indexed value, and descriptors still never carry the
//! body. Archived / soft-deleted credentials remain refused at `get` /
//! present regardless of the flags — surfacing them here only enables
//! management-by-id, never presentation.
//!
//! ## Revoked / expired credentials are never surfaced (§14 invariant 5)
//!
//! Search **unconditionally excludes** any matched credential whose
//! [`CredentialStatus`] is [`CredentialStatus::Revoked`] or
//! [`CredentialStatus::Expired`]. A credential the status task ([`super::status`])
//! has marked revoked must not reach a verifier as a candidate to present
//! (`vti-credential-architecture.md` §14 invariant 5: *a revoked credential MUST be
//! excluded from search results*). The exclusion is applied **after** the
//! indexed filter match, so it holds even when the caller does not constrain
//! on `status` — and even if a caller explicitly asks for
//! `status = revoked`, the result is empty (there is no "show me my revoked
//! credentials" surface here). `Unknown` and `Valid` are surfaced; resolving
//! `Unknown` → `Valid`/`Revoked` is the status task's job, run before a
//! present.

use vti_common::error::AppError;
use vti_common::store::KeyspaceHandle;
use vti_common::vault::{VaultStatus, default_active};

use super::model::{CredentialPurpose, CredentialStatus, IndexField, StoredCredential};

/// A lightweight, body-free projection of a matched [`StoredCredential`].
///
/// This is what local search returns: enough metadata for the holder's agent
/// to decide *which* credential(s) to act on (and then fetch the full record
/// by id via [`super::storage::get`] when it genuinely needs the body), with
/// **no** credential contents. The opaque `body` is intentionally absent — a
/// search result must never be a vector for leaking credential material
/// (§14, §16 "Never: disclosing claims beyond the DCQL request").
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialDescriptor {
    /// Local handle — the id under which the full record can be fetched.
    pub id: String,
    /// VC `type` tags carried by the credential.
    pub types: Vec<String>,
    /// Issuer DID, when the stored envelope records one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer_did: Option<String>,
    /// Semantic purpose (invite / membership / role / …), when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub purpose: Option<CredentialPurpose>,
    /// Validity status (valid / expired / revoked / unknown) — the
    /// status-list-driven dimension. **Orthogonal** to [`Self::lifecycle`]
    /// below: a credential can be `valid` *and* `archived`.
    pub status: CredentialStatus,
    /// **Archival** lifecycle state (active / archived / deleted) —
    /// orthogonal to [`Self::status`] (validity). Lets a management UI
    /// categorise a row and decide which lifecycle verb applies
    /// (unarchive / restore / purge). Omitted (and defaulted back to
    /// `active` on read) for active credentials, so active-only query
    /// results — the only ones returned without `include_archived` /
    /// `include_deleted` — are byte-for-byte unchanged from before this
    /// field existed; present only on the archived / deleted rows that the
    /// opt-in flags surface.
    #[serde(
        default = "default_active",
        skip_serializing_if = "VaultStatus::is_active"
    )]
    pub lifecycle: VaultStatus,
    /// RFC 3339 validity-window start, when the envelope declares one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_from: Option<String>,
    /// RFC 3339 validity-window end, when the envelope declares one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_until: Option<String>,
    /// RFC 3339 — when the credential was archived. Set iff
    /// `lifecycle == archived`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub archived_at: Option<String>,
    /// RFC 3339 — when the credential was soft-deleted (moved to trash). Set
    /// iff `lifecycle == deleted`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deleted_at: Option<String>,
    /// RFC 3339 purge deadline for a soft-deleted credential — restorable
    /// while `now < grace_until`, hard-purged by the sweeper afterwards. Set
    /// iff `lifecycle == deleted`; lets a trash UI show "purges in N days".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grace_until: Option<String>,
}

impl CredentialDescriptor {
    /// Project a full record down to its body-free descriptor. The `body`
    /// field is *not* read — this is the only place the metadata→descriptor
    /// mapping lives, so "descriptors never carry the body" is enforced in
    /// one spot.
    fn from_record(cred: &StoredCredential) -> Self {
        CredentialDescriptor {
            id: cred.id.clone(),
            types: cred.types.clone(),
            issuer_did: cred.issuer_did.clone(),
            purpose: cred.purpose.clone(),
            status: cred.status,
            lifecycle: cred.lifecycle,
            valid_from: cred.valid_from.clone(),
            valid_until: cred.valid_until.clone(),
            // The soft-delete `reason` is intentionally *not* surfaced: it is
            // never persisted on the record (it lands only in the audit row's
            // `detail` at the dispatch spine), so there is nothing to project.
            archived_at: cred.archived_at.clone(),
            deleted_at: cred.deleted_at.clone(),
            grace_until: cred.grace_until.clone(),
        }
    }
}

/// A DCQL-*shaped* filter over the vault's indexed envelope fields.
///
/// Every field is optional, and the fields that are `Some` are combined with
/// **AND** semantics: a credential matches only if it satisfies *all* set
/// constraints. At least one field must be set — an all-`None` query is
/// rejected (no-enumeration, §14.1).
///
/// `r#type` matches a single VC `type` tag: a credential is a match if *any*
/// of its `types` equals the requested tag (the index already records each
/// tag independently).
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialQuery {
    /// Match credentials carrying this VC `type` tag.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub r#type: Option<String>,
    /// Match credentials for this community / context DID.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub community_did: Option<String>,
    /// Match credentials from this issuer DID.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer_did: Option<String>,
    /// Match credentials with this semantic purpose.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub purpose: Option<CredentialPurpose>,
    /// Match credentials with this validity status.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<CredentialStatus>,
    /// Opt-in: also return **archived** credentials (default `false`). This is
    /// a *modifier*, not a filter — it does not count toward the ≥1-filter
    /// requirement, so `{ includeArchived: true }` alone is still refused as
    /// an enumeration. With it set, the lifecycle post-filter additionally
    /// admits `Archived` rows that match the indexed filter(s); the scan is
    /// still index-driven (archive does not touch the indexed fields, so the
    /// rows are still reachable).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub include_archived: bool,
    /// Opt-in: also return **soft-deleted** (tombstoned) credentials, so a
    /// trash UI can list them to restore or purge (default `false`). Same
    /// modifier semantics as [`Self::include_archived`]: not a filter, and
    /// still index-driven.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub include_deleted: bool,
}

impl CredentialQuery {
    /// `true` when no filter field is set. Such a query is **not runnable** —
    /// running it would be a wallet enumeration. [`search`] rejects it.
    pub fn is_empty(&self) -> bool {
        self.r#type.is_none()
            && self.community_did.is_none()
            && self.issuer_did.is_none()
            && self.purpose.is_none()
            && self.status.is_none()
    }

    /// The ordered list of set `(field, value)` constraints. The first entry
    /// is used as the index-scan anchor (it bounds the candidate set to one
    /// indexed value); the rest are applied as in-memory predicates.
    fn constraints(&self) -> Vec<(IndexField, String)> {
        let mut c = Vec::new();
        if let Some(t) = &self.r#type {
            c.push((IndexField::Type, t.clone()));
        }
        if let Some(d) = &self.community_did {
            c.push((IndexField::CommunityDid, d.clone()));
        }
        if let Some(d) = &self.issuer_did {
            c.push((IndexField::IssuerDid, d.clone()));
        }
        if let Some(p) = &self.purpose {
            c.push((IndexField::Purpose, p.as_index_token()));
        }
        if let Some(s) = &self.status {
            c.push((IndexField::Status, s.as_index_token().to_string()));
        }
        c
    }
}

/// Does `cred` satisfy a single `(field, value)` constraint? Mirrors the
/// index semantics in [`StoredCredential::index_terms`] so the in-memory
/// re-check of the non-anchor constraints agrees exactly with what the index
/// scan would have matched.
fn matches_constraint(cred: &StoredCredential, field: IndexField, value: &str) -> bool {
    match field {
        IndexField::Type => cred.types.iter().any(|t| t == value),
        IndexField::CommunityDid => cred.community_did.as_deref() == Some(value),
        IndexField::IssuerDid => cred.issuer_did.as_deref() == Some(value),
        IndexField::Purpose => cred
            .purpose
            .as_ref()
            .map(|p| p.as_index_token() == value)
            .unwrap_or(false),
        IndexField::Status => cred.status.as_index_token() == value,
    }
}

/// Run a local, DCQL-shaped search over the vault and return body-free
/// [`CredentialDescriptor`]s for the matched set.
///
/// **Requires at least one filter.** An empty [`CredentialQuery`] is rejected
/// with [`AppError::Validation`] before any I/O — there is no return-all
/// path, by design (no-enumeration, §14.1 / §16). When several filters are
/// set they are AND-combined: a credential must satisfy every constraint.
///
/// Mechanics: the first set constraint anchors an index scan (via
/// [`super::storage::find_by_index`]), bounding the candidate set to records
/// already known to match one indexed value; the remaining constraints are
/// applied as in-memory predicates. Bodies are loaded only to evaluate those
/// predicates and are **never** placed in the returned descriptors.
///
/// By default only `Active` credentials are returned. Set
/// [`CredentialQuery::include_archived`] / [`CredentialQuery::include_deleted`]
/// to additionally surface archived / soft-deleted rows for management UX;
/// these are modifiers, not filters, so they do not satisfy the
/// at-least-one-filter requirement on their own.
pub async fn search(
    vault: &KeyspaceHandle,
    query: &CredentialQuery,
) -> Result<Vec<CredentialDescriptor>, AppError> {
    // No-enumeration gate: reject an unfiltered query outright, before any
    // store access. This is the load-bearing check — without an explicit
    // filter there is no way to start a scan, so the vault cannot be
    // enumerated.
    if query.is_empty() {
        return Err(AppError::Validation(
            "credential search requires at least one filter \
             (type, community_did, issuer_did, purpose, or status); \
             an unfiltered query would enumerate the wallet and is refused"
                .to_string(),
        ));
    }

    let constraints = query.constraints();
    // `constraints()` is non-empty here: `is_empty()` is false, and the two
    // are computed from the same fields. Index 0 is the scan anchor.
    let (anchor_field, anchor_value) = &constraints[0];
    let candidates = super::storage::find_by_index(vault, *anchor_field, anchor_value).await?;

    let mut out = Vec::new();
    for cred in &candidates {
        // Archival lifecycle gate, applied here (after the indexed match): an
        // archived / soft-deleted credential is hidden by default — it's not a
        // candidate to present — but the holder can opt into seeing it for
        // management (browse archive, restore-from-trash, purge) via
        // `include_archived` / `include_deleted`. The status index still lists
        // it regardless (archive/soft-delete don't touch the indexed fields),
        // so the opt-in is a relaxation of *this* post-filter, never a new
        // scan or a return-all path.
        let lifecycle_admitted = match cred.lifecycle {
            VaultStatus::Active => true,
            VaultStatus::Archived => query.include_archived,
            VaultStatus::Deleted => query.include_deleted,
        };
        if !lifecycle_admitted {
            continue;
        }
        // §14 invariant 5: a revoked (or expired) credential is never a search result,
        // regardless of the filter — not even when the caller explicitly asks
        // for `status = revoked`. This is the load-bearing exclusion that keeps
        // the status task's revocation verdict from being undone by search
        // surfacing the credential to a verifier as presentable.
        if is_excluded_status(cred.status) {
            continue;
        }
        // The anchor already matched via the index; re-check the remaining
        // constraints in memory. AND semantics: any miss drops the record.
        let all_match = constraints[1..]
            .iter()
            .all(|(field, value)| matches_constraint(cred, *field, value));
        if all_match {
            out.push(CredentialDescriptor::from_record(cred));
        }
    }
    Ok(out)
}

/// `true` for the **validity** states that must never appear in a search
/// result (§14 invariant 5). A [`CredentialStatus::Revoked`] credential is
/// unpresentable, and an [`CredentialStatus::Expired`] one is past its
/// validity window — neither is a candidate the holder's agent should offer.
/// [`CredentialStatus::Valid`] and [`CredentialStatus::Unknown`] are surfaced.
///
/// This exclusion is **orthogonal to the archival lifecycle** and is *not*
/// relaxed by `include_archived` / `include_deleted`: those flags admit
/// `Archived` / `Deleted` rows, but a row that is *also* revoked/expired stays
/// excluded (§14 invariant 5 is load-bearing for the present path and is not in
/// scope of the management opt-in). Such a credential is still reachable for
/// management by its id (unarchive / restore / purge take an id, not a query).
fn is_excluded_status(status: CredentialStatus) -> bool {
    matches!(
        status,
        CredentialStatus::Revoked | CredentialStatus::Expired
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::model::{CredentialFormat, CredentialPurpose, CredentialStatus};
    use crate::vault::storage::put;
    use vti_common::config::StoreConfig;
    use vti_common::store::Store;

    fn fresh_vault() -> (tempfile::TempDir, Store, KeyspaceHandle) {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = Store::open(&StoreConfig {
            data_dir: dir.path().to_path_buf(),
        })
        .expect("open store");
        let ks = store
            .keyspace(crate::keyspaces::VAULT)
            .expect("vault keyspace");
        (dir, store, ks)
    }

    fn sample(id: &str) -> StoredCredential {
        StoredCredential {
            id: id.to_string(),
            format: CredentialFormat::SdJwtVc,
            types: vec!["VerifiableCredential".into(), "InvitationCredential".into()],
            schema_id: Some("schema:invite:1".into()),
            community_did: Some("did:web:acme".into()),
            context_id: None,
            subject_did: Some("did:key:zAlice".into()),
            issuer_did: Some("did:web:issuer.example".into()),
            purpose: Some(CredentialPurpose::Invite),
            status: CredentialStatus::Unknown,
            valid_from: Some("2026-01-01T00:00:00Z".into()),
            valid_until: Some("2027-01-01T00:00:00Z".into()),
            received_at: "2026-06-03T00:00:00Z".into(),
            source: Some("exchange:thread-42".into()),
            tags: std::collections::BTreeMap::from([("label".into(), "alice-invite".into())]),
            body: b"opaque.credential.bytes".to_vec(),
            lifecycle: vti_common::vault::VaultStatus::Active,
            archived_at: None,
            deleted_at: None,
            grace_until: None,
        }
    }

    #[tokio::test]
    async fn search_by_indexed_field_returns_descriptors() {
        let (_dir, _store, vault) = fresh_vault();
        put(&vault, &sample("cred-1")).await.unwrap();

        let q = CredentialQuery {
            issuer_did: Some("did:web:issuer.example".into()),
            ..Default::default()
        };
        let hits = search(&vault, &q).await.unwrap();
        assert_eq!(hits.len(), 1);
        let d = &hits[0];
        assert_eq!(d.id, "cred-1");
        assert_eq!(
            d.types,
            vec![
                "VerifiableCredential".to_string(),
                "InvitationCredential".to_string()
            ]
        );
        assert_eq!(d.issuer_did.as_deref(), Some("did:web:issuer.example"));
        assert_eq!(d.purpose, Some(CredentialPurpose::Invite));
        assert_eq!(d.status, CredentialStatus::Unknown);
        assert_eq!(d.valid_from.as_deref(), Some("2026-01-01T00:00:00Z"));
        assert_eq!(d.valid_until.as_deref(), Some("2027-01-01T00:00:00Z"));
    }

    #[tokio::test]
    async fn search_matches_any_type_tag() {
        let (_dir, _store, vault) = fresh_vault();
        put(&vault, &sample("cred-1")).await.unwrap();

        for tag in ["VerifiableCredential", "InvitationCredential"] {
            let q = CredentialQuery {
                r#type: Some(tag.into()),
                ..Default::default()
            };
            let hits = search(&vault, &q).await.unwrap();
            assert_eq!(hits.len(), 1, "type tag {tag} must match");
            assert_eq!(hits[0].id, "cred-1");
        }
    }

    /// CRITICAL: the descriptor never carries the credential body. We prove
    /// it structurally (no `body` field) by serialising the descriptor and
    /// confirming the opaque body bytes are absent from the JSON.
    #[tokio::test]
    async fn descriptors_never_contain_the_body() {
        let (_dir, _store, vault) = fresh_vault();
        put(&vault, &sample("cred-1")).await.unwrap();

        let q = CredentialQuery {
            community_did: Some("did:web:acme".into()),
            ..Default::default()
        };
        let hits = search(&vault, &q).await.unwrap();
        assert_eq!(hits.len(), 1);

        let json = serde_json::to_string(&hits[0]).unwrap();
        assert!(
            !json.contains("opaque.credential.bytes"),
            "descriptor JSON must not contain the credential body"
        );
        assert!(
            !json.contains("body"),
            "descriptor must not even have a body field"
        );
        // It must, however, carry the metadata the holder agent needs.
        assert!(json.contains("cred-1"));
    }

    /// NEGATIVE / no-enumeration test: an unfiltered query is impossible to
    /// run. There is no return-all path; the empty query is refused.
    #[tokio::test]
    async fn unfiltered_query_is_rejected_no_enumeration() {
        let (_dir, _store, vault) = fresh_vault();
        // Several credentials exist...
        put(&vault, &sample("cred-1")).await.unwrap();
        let mut other = sample("cred-2");
        other.issuer_did = Some("did:web:other".into());
        other.community_did = Some("did:web:other-co".into());
        put(&vault, &other).await.unwrap();

        // ...but a no-filter query cannot retrieve any of them.
        let empty = CredentialQuery::default();
        assert!(empty.is_empty());
        let err = search(&vault, &empty).await.unwrap_err();
        assert!(
            matches!(err, AppError::Validation(_)),
            "an unfiltered (enumerate-all) query must be rejected, got {err:?}"
        );

        // And there is genuinely no other entry point that returns the set:
        // the only way to get results is to name an indexed value. Naming a
        // value the caller already knows returns exactly that one.
        let q = CredentialQuery {
            issuer_did: Some("did:web:other".into()),
            ..Default::default()
        };
        let hits = search(&vault, &q).await.unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].id, "cred-2");
    }

    #[tokio::test]
    async fn multiple_filters_are_and_combined() {
        let (_dir, _store, vault) = fresh_vault();

        // Two credentials share a community but differ by issuer + purpose.
        let mut a = sample("cred-a");
        a.issuer_did = Some("did:web:issuer-a".into());
        a.purpose = Some(CredentialPurpose::Membership);

        let mut b = sample("cred-b");
        b.issuer_did = Some("did:web:issuer-b".into());
        b.purpose = Some(CredentialPurpose::Invite);

        put(&vault, &a).await.unwrap();
        put(&vault, &b).await.unwrap();

        // Filter on shared community alone → both.
        let q = CredentialQuery {
            community_did: Some("did:web:acme".into()),
            ..Default::default()
        };
        let mut ids = search(&vault, &q)
            .await
            .unwrap()
            .into_iter()
            .map(|d| d.id)
            .collect::<Vec<_>>();
        ids.sort();
        assert_eq!(ids, vec!["cred-a", "cred-b"]);

        // Add a purpose constraint → AND narrows to exactly one.
        let q = CredentialQuery {
            community_did: Some("did:web:acme".into()),
            purpose: Some(CredentialPurpose::Membership),
            ..Default::default()
        };
        let hits = search(&vault, &q).await.unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].id, "cred-a");

        // Contradictory AND (community matches, issuer doesn't) → empty,
        // never an error and never a wider fallback.
        let q = CredentialQuery {
            community_did: Some("did:web:acme".into()),
            issuer_did: Some("did:web:nobody".into()),
            ..Default::default()
        };
        assert!(search(&vault, &q).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn search_by_status_filter_surfaces_valid() {
        let (_dir, _store, vault) = fresh_vault();
        let mut valid = sample("cred-valid");
        valid.status = CredentialStatus::Valid;
        put(&vault, &valid).await.unwrap();

        let q = CredentialQuery {
            status: Some(CredentialStatus::Valid),
            ..Default::default()
        };
        let hits = search(&vault, &q).await.unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].id, "cred-valid");
        assert_eq!(hits[0].status, CredentialStatus::Valid);
    }

    /// §14 invariant 5: revoked credentials are excluded from search — even when the
    /// caller explicitly filters `status = revoked`, there is no "show me my
    /// revoked credentials" surface here.
    #[tokio::test]
    async fn revoked_and_expired_are_excluded_from_search() {
        let (_dir, _store, vault) = fresh_vault();
        let mut valid = sample("cred-valid");
        valid.status = CredentialStatus::Valid;
        let mut revoked = sample("cred-revoked");
        revoked.status = CredentialStatus::Revoked;
        revoked.issuer_did = Some("did:web:issuer-r".into());
        let mut expired = sample("cred-expired");
        expired.status = CredentialStatus::Expired;
        expired.issuer_did = Some("did:web:issuer-e".into());
        put(&vault, &valid).await.unwrap();
        put(&vault, &revoked).await.unwrap();
        put(&vault, &expired).await.unwrap();

        // A shared-community search returns ONLY the valid credential; the
        // revoked and expired ones are dropped.
        let q = CredentialQuery {
            community_did: Some("did:web:acme".into()),
            ..Default::default()
        };
        let hits = search(&vault, &q).await.unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].id, "cred-valid");

        // Explicitly asking for revoked still returns nothing.
        let q = CredentialQuery {
            status: Some(CredentialStatus::Revoked),
            ..Default::default()
        };
        assert!(
            search(&vault, &q).await.unwrap().is_empty(),
            "there is no search surface that returns revoked credentials"
        );

        // Likewise for expired.
        let q = CredentialQuery {
            status: Some(CredentialStatus::Expired),
            ..Default::default()
        };
        assert!(search(&vault, &q).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn no_match_returns_empty_not_error() {
        let (_dir, _store, vault) = fresh_vault();
        put(&vault, &sample("cred-1")).await.unwrap();

        let q = CredentialQuery {
            issuer_did: Some("did:web:nonexistent".into()),
            ..Default::default()
        };
        assert!(search(&vault, &q).await.unwrap().is_empty());
    }

    /// By default an archived credential is hidden; `include_archived` opts it
    /// back in, and the descriptor then carries `lifecycle = archived` plus
    /// `archived_at`. An active sibling is returned in both cases.
    #[tokio::test]
    async fn include_archived_surfaces_archived_rows() {
        let (_dir, _store, vault) = fresh_vault();
        let active = sample("cred-active");
        let mut archived = sample("cred-archived");
        archived.archive("2026-06-18T10:00:00+00:00").unwrap();
        put(&vault, &active).await.unwrap();
        put(&vault, &archived).await.unwrap();

        // Default (active-only): only the active credential, even though both
        // share the community index row.
        let base = CredentialQuery {
            community_did: Some("did:web:acme".into()),
            ..Default::default()
        };
        let hits = search(&vault, &base).await.unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].id, "cred-active");
        // The active descriptor omits the lifecycle key (defaults to active).
        assert_eq!(hits[0].lifecycle, VaultStatus::Active);

        // Opt in → both, and the archived one is categorised + timestamped.
        let q = CredentialQuery {
            include_archived: true,
            ..base.clone()
        };
        let mut hits = search(&vault, &q).await.unwrap();
        hits.sort_by(|a, b| a.id.cmp(&b.id));
        assert_eq!(hits.len(), 2);
        let arch = hits.iter().find(|d| d.id == "cred-archived").unwrap();
        assert_eq!(arch.lifecycle, VaultStatus::Archived);
        assert_eq!(
            arch.archived_at.as_deref(),
            Some("2026-06-18T10:00:00+00:00")
        );
        assert!(arch.deleted_at.is_none() && arch.grace_until.is_none());

        // include_deleted does NOT pull in an archived row.
        let q = CredentialQuery {
            include_deleted: true,
            ..base
        };
        let hits = search(&vault, &q).await.unwrap();
        assert_eq!(hits.len(), 1, "include_deleted must not surface archived");
        assert_eq!(hits[0].id, "cred-active");
    }

    /// `include_deleted` surfaces a soft-delete tombstone for restore/purge UX,
    /// exposing `lifecycle = deleted`, `deleted_at`, and the `grace_until`
    /// purge deadline.
    #[tokio::test]
    async fn include_deleted_surfaces_tombstones_with_grace() {
        let (_dir, _store, vault) = fresh_vault();
        let mut deleted = sample("cred-trash");
        deleted
            .soft_delete("2026-06-18T10:00:00+00:00", "2026-07-18T10:00:00+00:00")
            .unwrap();
        put(&vault, &deleted).await.unwrap();

        // Hidden by default and from include_archived.
        let base = CredentialQuery {
            purpose: Some(CredentialPurpose::Invite),
            ..Default::default()
        };
        assert!(search(&vault, &base).await.unwrap().is_empty());
        let q = CredentialQuery {
            include_archived: true,
            ..base.clone()
        };
        assert!(
            search(&vault, &q).await.unwrap().is_empty(),
            "include_archived must not surface a tombstone"
        );

        // Opt in → returned, fully categorised.
        let q = CredentialQuery {
            include_deleted: true,
            ..base
        };
        let hits = search(&vault, &q).await.unwrap();
        assert_eq!(hits.len(), 1);
        let d = &hits[0];
        assert_eq!(d.lifecycle, VaultStatus::Deleted);
        assert_eq!(d.deleted_at.as_deref(), Some("2026-06-18T10:00:00+00:00"));
        assert_eq!(d.grace_until.as_deref(), Some("2026-07-18T10:00:00+00:00"));
        assert!(d.archived_at.is_none());
    }

    /// The include flags are modifiers, not filters: an otherwise-empty query
    /// is still refused (no-enumeration), so they can never become a
    /// return-all path.
    #[tokio::test]
    async fn include_flags_alone_are_not_a_filter() {
        let (_dir, _store, vault) = fresh_vault();
        let mut archived = sample("cred-archived");
        archived.archive("2026-06-18T10:00:00+00:00").unwrap();
        put(&vault, &archived).await.unwrap();

        for q in [
            CredentialQuery {
                include_archived: true,
                ..Default::default()
            },
            CredentialQuery {
                include_deleted: true,
                ..Default::default()
            },
            CredentialQuery {
                include_archived: true,
                include_deleted: true,
                ..Default::default()
            },
        ] {
            assert!(q.is_empty(), "include flags must not count as a filter");
            let err = search(&vault, &q).await.unwrap_err();
            assert!(
                matches!(err, AppError::Validation(_)),
                "an include-only query must still be refused as enumeration"
            );
        }
    }

    /// §14 invariant 5 is orthogonal to the archival opt-in: a credential that
    /// is *both* archived and revoked stays excluded even with
    /// `include_archived`. (Manage it by id instead.)
    #[tokio::test]
    async fn revoked_archived_row_stays_excluded_even_with_include_archived() {
        let (_dir, _store, vault) = fresh_vault();
        let mut cred = sample("cred-archived-revoked");
        cred.status = CredentialStatus::Revoked;
        cred.archive("2026-06-18T10:00:00+00:00").unwrap();
        put(&vault, &cred).await.unwrap();

        let q = CredentialQuery {
            community_did: Some("did:web:acme".into()),
            include_archived: true,
            include_deleted: true,
            ..Default::default()
        };
        assert!(
            search(&vault, &q).await.unwrap().is_empty(),
            "a revoked credential is never surfaced by search, even when archived \
             and explicitly included"
        );
    }

    /// Active-only results are byte-for-byte unchanged: the descriptor JSON for
    /// an active credential carries no `lifecycle` / `archivedAt` / `deletedAt`
    /// / `graceUntil` keys.
    #[tokio::test]
    async fn active_descriptor_omits_lifecycle_keys() {
        let (_dir, _store, vault) = fresh_vault();
        put(&vault, &sample("cred-1")).await.unwrap();

        let q = CredentialQuery {
            issuer_did: Some("did:web:issuer.example".into()),
            ..Default::default()
        };
        let hits = search(&vault, &q).await.unwrap();
        assert_eq!(hits.len(), 1);
        let json = serde_json::to_string(&hits[0]).unwrap();
        for key in ["lifecycle", "archivedAt", "deletedAt", "graceUntil"] {
            assert!(
                !json.contains(key),
                "an active descriptor must omit `{key}`: {json}"
            );
        }
    }
}
