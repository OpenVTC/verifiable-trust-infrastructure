//! `spec/vta/audit/verify/1.0` — the result of checking the audit log's
//! hash chain.
//!
//! Published here rather than kept in the service because a caller has to be
//! able to read the answer, and because the counts in it are the answer: a
//! consumer that reads only `verified` has been told less than this reports.

use serde::{Deserialize, Serialize};

/// Payload of `spec/vta/audit/verify/1.0`. The whole log is verified, so there
/// is nothing to select.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VerifyChainBody {
    /// Ecosystem-defined extension members (SPEC §4.5.1).
    ///
    /// Carried explicitly rather than by relaxing `deny_unknown_fields`: the
    /// published schemas declare an `ext` slot, so a conforming producer may
    /// send one and refusing the whole document over it would break interop
    /// with a peer doing exactly what the spec allows. Keeping
    /// `deny_unknown_fields` beside it means a *typo* is still refused, which
    /// is the guard that clause is there for.
    ///
    /// The VTA does not interpret the contents.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ext: Option<serde_json::Value>,
}

/// What verifying the audit chain found.
///
/// The counts are not decoration. Every row this reports as skipped is a row
/// the chain does not cover, and a reader who sees only `verified: true` has
/// been told less than they think.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditChainReport {
    /// Whether every chainable envelope verified.
    pub verified: bool,
    /// Rows examined, of any shape.
    pub rows_examined: usize,
    /// Envelopes that carried a chain link and verified.
    pub entries_verified: usize,
    /// Rows written before the chain opened.
    ///
    /// **Expected on a VTA**, which audited to this keyspace before its log
    /// was chained. They are not covered by the chain and cannot be: nothing
    /// committed to them at the time.
    pub pre_chain_rows: usize,
    /// Rows after the chain opened that are not chainable envelopes.
    ///
    /// **A finding.** Once the chain has opened, every row this sink writes is
    /// an envelope, so a row that is not one arrived by some other route —
    /// which is exactly what an insertion looks like. Reported separately from
    /// `preChainRows` because the two mean opposite things.
    pub unchained_after_open: usize,
    /// Envelopes skipped as unchainable by their own schema version.
    ///
    /// **A finding wherever the chain has opened.** The verifier passes over
    /// these rather than checking them, so an envelope forged with an older
    /// schema version passes untouched.
    pub legacy_envelopes_skipped: usize,
    /// Head of the verified chain, hex-encoded. `None` when nothing chainable
    /// was found.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub head: Option<String>,
    /// Where the chain broke, when it did.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chain_break: Option<AuditChainBreak>,
}

/// Where a chain stopped verifying, in the shape a caller can act on.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditChainBreak {
    /// `tamperedEntry` — the envelope's content was altered after it was
    /// written; or `brokenLink` — an entry was reordered, dropped or inserted.
    pub kind: String,
    /// Position among the chainable envelopes, counting from the start.
    pub index: usize,
    /// The envelope the break was found at.
    pub event_id: String,
}
