//! `audit/verify/0.1` — the result of checking an audit log's hash chain.
//!
//! The canonical task, served by the registry, so these types follow its
//! published schema rather than a shape of our own. Anything this VTA reports
//! beyond it travels in the `ext` slot, which is what that slot is for: the
//! payload is closed, and a member added beside it would be invisible to a
//! peer that does not know it and indistinguishable from a typo to one that
//! validates.

use serde::{Deserialize, Serialize};

/// Payload of `audit/verify/0.1`. Verification is store-wide, so there is
/// nothing to select.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VerifyChainBody {
    /// Ecosystem-defined extension members (SPEC §4.5.1).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ext: Option<serde_json::Value>,
}

/// What verifying the audit chain found, in the canonical response shape.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditChainReport {
    /// True only when every chainable envelope re-derived its own hash and
    /// pointed at its predecessor's.
    ///
    /// It establishes that the log is internally consistent. It does not
    /// establish who wrote it: a party who can rewrite the store can rewrite
    /// the chain along with it.
    pub verified: bool,
    /// Rows examined, chainable or not.
    pub entries_examined: usize,
    /// Envelopes that carried a chain link and verified.
    pub entries_verified: usize,
    /// Envelopes the verifier passed over by schema version.
    ///
    /// **A finding wherever the chain has opened**: these were not checked, so
    /// an envelope forged with an older schema version passes untouched.
    pub legacy_skipped: usize,
    /// Rows that would not parse as an envelope at all.
    ///
    /// On a VTA this is two different facts under one name — rows written
    /// before the log was chained are expected, and rows appearing after it
    /// was are not. The breakdown is in `ext`.
    pub unparseable_skipped: usize,
    /// Head of the verified chain, as a multibase-encoded multihash.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub head: Option<String>,
    /// Where the chain first broke. Absent when `verified` is true.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chain_break: Option<AuditChainBreak>,
    /// What this maintainer reports beyond the canonical shape.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ext: Option<serde_json::Value>,
}

/// Where a chain stopped verifying.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditChainBreak {
    /// `tamperedEntry` — the envelope's content was altered after it was
    /// written; or `brokenLink` — an entry was reordered, dropped or inserted.
    pub kind: String,
    /// Position among the chainable envelopes, counting from the start.
    pub index: usize,
    /// The envelope the break was found at.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_id: Option<String>,
}

/// The members this VTA carries in [`AuditChainReport::ext`], under the key
/// naming this implementation.
///
/// Split out because the canonical shape has one bucket for rows it could not
/// parse and a VTA has two kinds: rows written before its log was chained,
/// which are expected and cannot be covered by any chain, and rows appearing
/// after it was, which is what an insertion looks like. Collapsing them would
/// report an ordinary history as a finding, or hide a finding in an ordinary
/// history.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VtaVerifyExt {
    /// Rows written before the chain opened. Expected.
    pub pre_chain_rows: usize,
    /// Rows after the chain opened that are not chainable envelopes. A
    /// finding.
    pub unchained_after_open: usize,
    /// Whether verification resumed from the retention sweep's watermark
    /// rather than from the opening of the chain.
    ///
    /// The pruned entries were not verified by this run and cannot be — they
    /// are gone. What holds is that the survivors continue a chain that ran
    /// through the watermark, which lives in the same store as the log.
    pub resumed_from_prune: bool,
    /// Chained entries the retention sweep has removed over the log's life.
    pub pruned_entries: usize,
}

/// The `ext` key this VTA's members live under.
pub const VTA_EXT_KEY: &str = "org.openvtc.vta";
