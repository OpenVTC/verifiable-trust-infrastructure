//! Shared helpers for the `webvh edit-did` command.
//!
//! Two flows live here, both producing an [`UpdateDidWebvhBody`]
//! that the caller hands to either the SDK client (online) or the
//! local op (offline):
//!
//! 1. **Interactive** — pull the latest LogEntry's published DID
//!    document, open it in `$EDITOR` via `dialoguer::Editor`, then
//!    walk a `Confirm`/`Input` chain asking the operator about the
//!    webvh parameters (pre-rotation count, watcher set, TTL,
//!    audit label).
//!
//! 2. **Non-interactive** — load a JSON document from a file and
//!    apply CLI flags for the parameters. Suited for scripted
//!    flows / CI / TEE-host operators.
//!
//! Both flows enforce the **DID-id invariant**: the operator can
//! change everything about the document *except* the top-level
//! `id` field. Mutating the DID identifier mid-stream would
//! invalidate every existing reference to it; the WebVH spec
//! treats it as a permanent commitment from the first LogEntry.

use serde_json::Value;

use vta_sdk::protocols::did_management::update::UpdateDidWebvhBody;

/// Errors from the editor flow. Variant strings are operator-facing
/// — formatted with leading lowercase so they read naturally after
/// "Error: " in the CLI output.
#[derive(Debug, thiserror::Error)]
pub enum EditFlowError {
    #[error("DID log is empty — cannot extract the current document")]
    EmptyLog,
    #[error("DID log line parse: {0}")]
    LogParse(String),
    #[error("DID document missing `id` field")]
    DocumentMissingId,
    #[error(
        "the edited document changed the DID identifier (`{prior}` → `{edited}`). \
         The DID id is a permanent commitment from the first LogEntry; mutating it \
         would invalidate every existing reference to the DID. Re-run the editor \
         with the original `id` restored, or use `pnm did-mgmt dids create` to mint a \
         new DID instead."
    )]
    DidIdChanged { prior: String, edited: String },
    #[error("edited content is not valid JSON: {0}")]
    InvalidJson(String),
    #[error("editor was cancelled — nothing to publish")]
    EditorCancelled,
    #[error("could not read document file `{path}`: {source}")]
    ReadFile {
        path: String,
        source: std::io::Error,
    },
    #[error("could not read options file `{path}`: {source}")]
    ReadOptions {
        path: String,
        source: std::io::Error,
    },
    #[error("invalid options JSON in `{path}`: {source}")]
    InvalidOptions {
        path: String,
        source: serde_json::Error,
    },
    #[error("publish cancelled by operator")]
    PublishCancelled,
    #[error("interactive prompt failed: {0}")]
    Prompt(String),
}

/// Extract the published DID document from the most recent
/// non-empty line of a `did.jsonl` log. The line is parsed as a
/// LogEntry and its `state` field is returned.
///
/// Implemented inline (rather than calling didwebvh-rs) because
/// vta-cli-common doesn't depend on that crate; the LogEntry
/// surface we need is just the `state` JSON value.
pub fn extract_current_document(did_log: &str) -> Result<Value, EditFlowError> {
    let line = did_log
        .lines()
        .rfind(|l| !l.trim().is_empty())
        .ok_or(EditFlowError::EmptyLog)?;
    let entry: Value = serde_json::from_str(line)
        .map_err(|e| EditFlowError::LogParse(format!("line parse: {e}")))?;
    let state = entry
        .get("state")
        .cloned()
        .ok_or_else(|| EditFlowError::LogParse("LogEntry has no `state` field".into()))?;
    Ok(state)
}

/// Extract the `versionId` of the last non-empty log entry. Used as
/// the optimistic-concurrency precondition on the save call: the VTA
/// rejects the update if the DID has moved on since this versionId.
/// Returns `Err(EmptyLog)` when the log has no entries; returns
/// `Err(LogParse)` if the latest entry is malformed or missing
/// `versionId` (extremely unlikely on a valid did:webvh log — but
/// fall back to None at the call site rather than blocking the save
/// just because we couldn't read a version).
pub fn extract_latest_version_id(did_log: &str) -> Result<String, EditFlowError> {
    let line = did_log
        .lines()
        .rfind(|l| !l.trim().is_empty())
        .ok_or(EditFlowError::EmptyLog)?;
    let entry: Value = serde_json::from_str(line)
        .map_err(|e| EditFlowError::LogParse(format!("line parse: {e}")))?;
    entry
        .get("versionId")
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| EditFlowError::LogParse("LogEntry has no `versionId` field".into()))
}

/// Summary of the DID's currently-effective pre-rotation setup,
/// extracted from the on-disk log without needing to depend on
/// didwebvh-rs. Surfaced before the "Override pre-rotation count?"
/// prompt so the operator can see what they're choosing to change.
///
/// Pre-rotation is "active" when the most recent log entry that
/// mentions `nextKeyHashes` has a non-empty array. Walking back
/// through entries handles the did:webvh delta-parameter model
/// (subsequent entries may omit unchanged fields).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreRotationStatus {
    /// Number of pre-rotation keys committed in the most recent
    /// non-empty commitment. `0` when pre-rotation is disabled or
    /// has never been enabled.
    pub committed_count: usize,
    /// True iff the most recent mention of `nextKeyHashes` was
    /// non-empty. False when the most recent mention was an empty
    /// array (explicit disable) or when no entry has ever mentioned
    /// the field.
    pub active: bool,
    /// True when no entry in the log has ever mentioned
    /// `nextKeyHashes` — distinguishes "never enabled" from
    /// "explicitly disabled" for the operator-facing display.
    pub never_set: bool,
}

/// Walk the log latest-first to find the most recent entry that
/// declared `nextKeyHashes`. The latest such declaration is
/// authoritative under did:webvh delta-parameter semantics.
pub fn extract_pre_rotation_status(did_log: &str) -> PreRotationStatus {
    for line in did_log.lines().rev() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let Ok(entry) = serde_json::from_str::<Value>(trimmed) else {
            continue;
        };
        let Some(hashes) = entry
            .get("parameters")
            .and_then(|p| p.get("nextKeyHashes"))
            .and_then(Value::as_array)
        else {
            continue;
        };
        let count = hashes.len();
        return PreRotationStatus {
            committed_count: count,
            active: count > 0,
            never_set: false,
        };
    }
    PreRotationStatus {
        committed_count: 0,
        active: false,
        never_set: true,
    }
}

/// Read the `id` field from a DID document. Used to enforce the
/// DID-id invariant after the operator edits the document.
pub fn document_id(doc: &Value) -> Result<&str, EditFlowError> {
    doc.get("id")
        .and_then(Value::as_str)
        .ok_or(EditFlowError::DocumentMissingId)
}

/// Verify that the edited document carries the same `id` as the
/// prior version. Returns `Err(DidIdChanged)` if mutated.
pub fn assert_did_id_unchanged(prior: &Value, edited: &Value) -> Result<(), EditFlowError> {
    let prior_id = document_id(prior)?;
    let edited_id = document_id(edited)?;
    if prior_id != edited_id {
        return Err(EditFlowError::DidIdChanged {
            prior: prior_id.to_string(),
            edited: edited_id.to_string(),
        });
    }
    Ok(())
}

/// Open `initial` in `$EDITOR` (via `dialoguer::Editor`), parse
/// the result as JSON, and verify the DID `id` wasn't mutated.
/// Returns `Ok(None)` when the operator cancels (saves an empty
/// buffer) — the caller treats that as "abort, don't publish."
pub fn launch_editor(prior_doc: &Value) -> Result<Option<Value>, EditFlowError> {
    let pretty = serde_json::to_string_pretty(prior_doc).map_err(|e| {
        EditFlowError::Prompt(format!(
            "could not serialise current document for editor: {e}"
        ))
    })?;

    let edited = dialoguer::Editor::new()
        .extension(".json")
        .edit(&pretty)
        .map_err(|e| EditFlowError::Prompt(format!("editor launch failed: {e}")))?;

    let Some(raw) = edited else {
        // Operator quit without saving (or saved empty). Treat as
        // cancel — don't publish.
        return Ok(None);
    };
    if raw.trim().is_empty() {
        return Err(EditFlowError::EditorCancelled);
    }
    let edited_doc: Value =
        serde_json::from_str(&raw).map_err(|e| EditFlowError::InvalidJson(e.to_string()))?;
    assert_did_id_unchanged(prior_doc, &edited_doc)?;
    Ok(Some(edited_doc))
}

/// Operator-facing summary of how many top-level fields differ
/// between the prior and edited documents. Cheap heuristic — the
/// CLI prints it before asking "looks good?" so the operator has
/// a sanity check on what they touched.
pub fn diff_summary(prior: &Value, edited: &Value) -> String {
    let prior_obj = prior.as_object();
    let edited_obj = edited.as_object();
    let (Some(prior_obj), Some(edited_obj)) = (prior_obj, edited_obj) else {
        return "(non-object document — diff unavailable)".to_string();
    };

    let mut added = Vec::new();
    let mut changed = Vec::new();
    let mut removed = Vec::new();

    for (k, v) in edited_obj {
        match prior_obj.get(k) {
            None => added.push(k.as_str()),
            Some(prior_v) if prior_v != v => changed.push(k.as_str()),
            Some(_) => {}
        }
    }
    for k in prior_obj.keys() {
        if !edited_obj.contains_key(k) {
            removed.push(k.as_str());
        }
    }

    if added.is_empty() && changed.is_empty() && removed.is_empty() {
        return "(no top-level fields changed)".to_string();
    }
    let mut out = String::new();
    if !added.is_empty() {
        out.push_str(&format!("added: {}\n", added.join(", ")));
    }
    if !changed.is_empty() {
        out.push_str(&format!("changed: {}\n", changed.join(", ")));
    }
    if !removed.is_empty() {
        out.push_str(&format!("removed: {}\n", removed.join(", ")));
    }
    out.trim_end().to_string()
}

/// Non-interactive flag bundle. Fed into [`build_options_from_flags`]
/// to produce an [`UpdateDidWebvhBody`]. Keeping this separate from
/// `UpdateDidWebvhBody` avoids parser/clap concerns leaking into the
/// SDK wire type.
#[derive(Debug, Clone, Default)]
pub struct EditFlags {
    /// Path to a JSON file containing the new DID document. When set,
    /// the editor is bypassed.
    pub document_file: Option<std::path::PathBuf>,
    /// Path to a JSON file containing a full `UpdateDidWebvhBody`.
    /// Mutually exclusive with the per-field flags below; useful for
    /// power users who want witness changes (witness shape requires
    /// multibase ids and is awkward to express on the command line).
    pub options_file: Option<std::path::PathBuf>,
    pub pre_rotation: Option<u32>,
    pub ttl: Option<u32>,
    /// Replace the watcher set with these URLs. Mutually exclusive
    /// with `no_watchers`.
    pub watchers: Vec<String>,
    /// Disable watchers entirely (sets `Some(vec![])` on the body).
    pub no_watchers: bool,
    pub label: Option<String>,
}

/// Build an [`UpdateDidWebvhBody`] from the non-interactive flag
/// bundle. The operator either runs in interactive mode (no flags
/// → editor + prompts), supplies a `--options-file` for full control
/// (witnesses included), or uses the per-field flags below.
pub fn build_options_from_flags(flags: &EditFlags) -> Result<UpdateDidWebvhBody, EditFlowError> {
    if let Some(path) = &flags.options_file {
        let raw = std::fs::read_to_string(path).map_err(|e| EditFlowError::ReadOptions {
            path: path.display().to_string(),
            source: e,
        })?;
        let body: UpdateDidWebvhBody =
            serde_json::from_str(&raw).map_err(|e| EditFlowError::InvalidOptions {
                path: path.display().to_string(),
                source: e,
            })?;
        return Ok(body);
    }

    let document = match &flags.document_file {
        Some(path) => {
            let raw = std::fs::read_to_string(path).map_err(|e| EditFlowError::ReadFile {
                path: path.display().to_string(),
                source: e,
            })?;
            let v: Value = serde_json::from_str(&raw)
                .map_err(|e| EditFlowError::InvalidJson(e.to_string()))?;
            // Caller passes `prior_doc` separately when validating;
            // here we just verify the edited shape has an `id`.
            document_id(&v)?;
            Some(v)
        }
        None => None,
    };

    let watchers = if flags.no_watchers {
        Some(Vec::new())
    } else if !flags.watchers.is_empty() {
        Some(flags.watchers.clone())
    } else {
        None
    };

    Ok(UpdateDidWebvhBody {
        document,
        pre_rotation_count: flags.pre_rotation,
        witnesses: None,
        watchers,
        ttl: flags.ttl,
        label: flags.label.clone(),
        // Non-interactive flag-driven path (e.g. `pnm webvh edit-did
        // --document <file>` from a script). The interactive flow sets
        // this to the fetched versionId so a stale `get → edit → save`
        // cycle gets a 409; scripted callers opt in by passing
        // `--expected-version-id` (wired separately).
        expected_version_id: None,
    })
}

/// Walk an interactive `Confirm`/`Input` chain asking the operator
/// about the webvh parameters they want to change. `edited_doc` is
/// the post-editor DID document (or `None` if the operator
/// declined to edit). Returns the assembled
/// [`UpdateDidWebvhBody`].
///
/// The chain is opt-in for every field: each starts with a
/// `Confirm` defaulting to `false` so the operator can hit Enter
/// repeatedly to skip everything and just publish the document
/// edit on its own.
pub fn prompt_webvh_params(
    edited_doc: Option<Value>,
    pre_rotation_status: Option<&PreRotationStatus>,
) -> Result<UpdateDidWebvhBody, EditFlowError> {
    use dialoguer::{Confirm, Input};

    fn err(e: dialoguer::Error) -> EditFlowError {
        EditFlowError::Prompt(e.to_string())
    }

    let mut body = UpdateDidWebvhBody {
        document: edited_doc,
        ..Default::default()
    };

    // Show the current pre-rotation setup so the operator can decide
    // what (if anything) to change. Skipped when the caller didn't
    // supply a status (e.g. an offline test path that has no log).
    if let Some(s) = pre_rotation_status {
        if s.never_set {
            eprintln!("  Pre-rotation: disabled (never enabled on this DID).");
        } else if !s.active {
            eprintln!("  Pre-rotation: disabled (explicitly turned off).");
        } else {
            let plural = if s.committed_count == 1 {
                "key"
            } else {
                "keys"
            };
            eprintln!(
                "  Pre-rotation: active — {} {plural} currently committed.",
                s.committed_count
            );
        }
    }

    if Confirm::new()
        .with_prompt("Override pre-rotation count?")
        .default(false)
        .interact()
        .map_err(err)?
    {
        let n: u32 = Input::new()
            .with_prompt("New pre-rotation count (0 disables)")
            .default(0)
            .interact_text()
            .map_err(err)?;
        body.pre_rotation_count = Some(n);
    }

    if Confirm::new()
        .with_prompt("Replace watcher URLs?")
        .default(false)
        .interact()
        .map_err(err)?
    {
        let raw: String = Input::new()
            .with_prompt("Comma-separated watcher URLs (empty input disables watchers entirely)")
            .allow_empty(true)
            .interact_text()
            .map_err(err)?;
        let watchers: Vec<String> = raw
            .split(',')
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .collect();
        body.watchers = Some(watchers);
    }

    if Confirm::new()
        .with_prompt("Set a new TTL (seconds)?")
        .default(false)
        .interact()
        .map_err(err)?
    {
        let ttl: u32 = Input::new()
            .with_prompt("TTL (seconds)")
            .interact_text()
            .map_err(err)?;
        body.ttl = Some(ttl);
    }

    if Confirm::new()
        .with_prompt("Add an audit label for this update?")
        .default(true)
        .interact()
        .map_err(err)?
    {
        let label: String = Input::new()
            .with_prompt("Audit label")
            .allow_empty(true)
            .interact_text()
            .map_err(err)?;
        if !label.trim().is_empty() {
            body.label = Some(label.trim().to_string());
        }
    }

    Ok(body)
}

/// Final confirmation before publishing. Shows a one-line summary
/// of what the body actually contains; operator hits Enter (default
/// `false`) to abort. Returns `Err(PublishCancelled)` on `false`.
pub fn confirm_publish(body: &UpdateDidWebvhBody, no_confirm: bool) -> Result<(), EditFlowError> {
    if no_confirm {
        return Ok(());
    }

    let mut summary = Vec::<&str>::new();
    if body.document.is_some() {
        summary.push("document");
    }
    if body.pre_rotation_count.is_some() {
        summary.push("pre-rotation");
    }
    if body.watchers.is_some() {
        summary.push("watchers");
    }
    if body.witnesses.is_some() {
        summary.push("witnesses");
    }
    if body.ttl.is_some() {
        summary.push("ttl");
    }
    if body.label.is_some() {
        summary.push("label");
    }
    let summary = if summary.is_empty() {
        "(nothing — body is empty)".to_string()
    } else {
        summary.join(", ")
    };

    let go = dialoguer::Confirm::new()
        .with_prompt(format!(
            "Publish a new LogEntry with these changes ({summary})?"
        ))
        .default(false)
        .interact()
        .map_err(|e| EditFlowError::Prompt(e.to_string()))?;
    if !go {
        return Err(EditFlowError::PublishCancelled);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn extract_current_document_returns_state_of_last_line() {
        let log = "{\"versionId\":\"1\",\"state\":{\"id\":\"did:webvh:foo\"}}\n\
                   {\"versionId\":\"2\",\"state\":{\"id\":\"did:webvh:foo\",\"key\":\"v2\"}}\n";
        let doc = extract_current_document(log).unwrap();
        assert_eq!(doc["id"], "did:webvh:foo");
        assert_eq!(doc["key"], "v2");
    }

    #[test]
    fn extract_latest_version_id_returns_last_entrys_version_id() {
        let log = "{\"versionId\":\"1-aaa\",\"state\":{\"id\":\"did:webvh:foo\"}}\n\
                   {\"versionId\":\"2-bbb\",\"state\":{\"id\":\"did:webvh:foo\"}}\n";
        assert_eq!(extract_latest_version_id(log).unwrap(), "2-bbb");
    }

    #[test]
    fn extract_latest_version_id_skips_trailing_blank_lines() {
        let log = "{\"versionId\":\"1-aaa\",\"state\":{\"id\":\"x\"}}\n\
                   {\"versionId\":\"2-bbb\",\"state\":{\"id\":\"x\"}}\n\n\n";
        assert_eq!(extract_latest_version_id(log).unwrap(), "2-bbb");
    }

    #[test]
    fn extract_latest_version_id_errors_on_empty_log() {
        let err = extract_latest_version_id("").unwrap_err();
        assert!(matches!(err, EditFlowError::EmptyLog), "got {err:?}");
    }

    #[test]
    fn extract_pre_rotation_status_walks_back_through_deltas() {
        // Latest entry omits parameters → walk back to entry 2 which
        // committed 2 next-key hashes.
        let log = "{\"versionId\":\"1-aaa\",\"parameters\":{\"nextKeyHashes\":[\"Qm1\"]}}\n\
                   {\"versionId\":\"2-bbb\",\"parameters\":{\"nextKeyHashes\":[\"Qm2a\",\"Qm2b\"]}}\n\
                   {\"versionId\":\"3-ccc\",\"parameters\":{}}\n";
        let s = extract_pre_rotation_status(log);
        assert!(s.active);
        assert_eq!(s.committed_count, 2);
        assert!(!s.never_set);
    }

    #[test]
    fn extract_pre_rotation_status_recognises_explicit_disable() {
        // Entry 2 explicitly empties nextKeyHashes → pre-rotation off.
        let log = "{\"versionId\":\"1-aaa\",\"parameters\":{\"nextKeyHashes\":[\"Qm1\"]}}\n\
                   {\"versionId\":\"2-bbb\",\"parameters\":{\"nextKeyHashes\":[]}}\n";
        let s = extract_pre_rotation_status(log);
        assert!(!s.active);
        assert_eq!(s.committed_count, 0);
        assert!(!s.never_set);
    }

    #[test]
    fn extract_pre_rotation_status_returns_never_set_when_no_entry_mentions_it() {
        let log = "{\"versionId\":\"1-aaa\",\"parameters\":{}}\n\
                   {\"versionId\":\"2-bbb\",\"parameters\":{}}\n";
        let s = extract_pre_rotation_status(log);
        assert!(!s.active);
        assert_eq!(s.committed_count, 0);
        assert!(
            s.never_set,
            "no nextKeyHashes anywhere → never_set must be true"
        );
    }

    #[test]
    fn extract_current_document_skips_trailing_blank_lines() {
        let log = "{\"versionId\":\"1\",\"state\":{\"id\":\"did:webvh:foo\"}}\n\n\n";
        let doc = extract_current_document(log).unwrap();
        assert_eq!(doc["id"], "did:webvh:foo");
    }

    #[test]
    fn extract_current_document_rejects_empty_log() {
        let err = extract_current_document("").unwrap_err();
        assert!(matches!(err, EditFlowError::EmptyLog));
    }

    #[test]
    fn extract_current_document_rejects_unparseable_line() {
        let err = extract_current_document("not json").unwrap_err();
        assert!(matches!(err, EditFlowError::LogParse(_)));
    }

    #[test]
    fn assert_did_id_unchanged_passes_when_id_matches() {
        let prior = json!({"id": "did:webvh:foo", "x": 1});
        let edited = json!({"id": "did:webvh:foo", "x": 2});
        assert!(assert_did_id_unchanged(&prior, &edited).is_ok());
    }

    #[test]
    fn assert_did_id_unchanged_rejects_id_mutation() {
        let prior = json!({"id": "did:webvh:foo"});
        let edited = json!({"id": "did:webvh:bar"});
        let err = assert_did_id_unchanged(&prior, &edited).unwrap_err();
        match err {
            EditFlowError::DidIdChanged { prior, edited } => {
                assert_eq!(prior, "did:webvh:foo");
                assert_eq!(edited, "did:webvh:bar");
            }
            other => panic!("expected DidIdChanged, got {other:?}"),
        }
    }

    #[test]
    fn diff_summary_describes_added_changed_removed() {
        let prior = json!({"id": "did:webvh:foo", "service": [], "kept": "v1"});
        let edited = json!({"id": "did:webvh:foo", "service": [{}], "newField": 1});
        let summary = diff_summary(&prior, &edited);
        assert!(summary.contains("added: newField"), "got: {summary}");
        assert!(summary.contains("changed: service"), "got: {summary}");
        assert!(summary.contains("removed: kept"), "got: {summary}");
    }

    #[test]
    fn diff_summary_handles_no_changes() {
        let doc = json!({"id": "did:webvh:foo"});
        let summary = diff_summary(&doc, &doc);
        assert!(summary.contains("no top-level fields changed"));
    }

    #[test]
    fn build_options_from_flags_no_flags_produces_empty_body() {
        let flags = EditFlags::default();
        let body = build_options_from_flags(&flags).unwrap();
        assert!(body.document.is_none());
        assert!(body.pre_rotation_count.is_none());
        assert!(body.watchers.is_none());
        assert!(body.ttl.is_none());
        assert!(body.label.is_none());
    }

    #[test]
    fn build_options_from_flags_no_watchers_clears_set() {
        let flags = EditFlags {
            no_watchers: true,
            ..Default::default()
        };
        let body = build_options_from_flags(&flags).unwrap();
        assert_eq!(body.watchers, Some(Vec::<String>::new()));
    }

    #[test]
    fn build_options_from_flags_watchers_replace_set() {
        let flags = EditFlags {
            watchers: vec!["https://w1.example".into(), "https://w2.example".into()],
            ..Default::default()
        };
        let body = build_options_from_flags(&flags).unwrap();
        assert_eq!(
            body.watchers,
            Some(vec![
                "https://w1.example".to_string(),
                "https://w2.example".to_string(),
            ])
        );
    }

    #[test]
    fn build_options_from_flags_propagates_pre_rotation_ttl_label() {
        let flags = EditFlags {
            pre_rotation: Some(3),
            ttl: Some(86_400),
            label: Some("audit".into()),
            ..Default::default()
        };
        let body = build_options_from_flags(&flags).unwrap();
        assert_eq!(body.pre_rotation_count, Some(3));
        assert_eq!(body.ttl, Some(86_400));
        assert_eq!(body.label.as_deref(), Some("audit"));
    }

    #[test]
    fn build_options_from_flags_loads_document_from_file() {
        // tempfile is already a workspace-wide test dep but not in
        // vta-cli-common's dev-deps; use std::env::temp_dir +
        // pid-suffix instead so the test stays self-contained.
        let dir = std::env::temp_dir();
        let path = dir.join(format!(
            "vta-cli-common-edit-flags-{}.json",
            std::process::id()
        ));
        std::fs::write(&path, r#"{"id":"did:webvh:foo","verificationMethod":[]}"#).unwrap();
        let flags = EditFlags {
            document_file: Some(path.clone()),
            ..Default::default()
        };
        let body = build_options_from_flags(&flags).unwrap();
        assert_eq!(body.document.as_ref().unwrap()["id"], "did:webvh:foo");
        let _ = std::fs::remove_file(&path);
    }
}
