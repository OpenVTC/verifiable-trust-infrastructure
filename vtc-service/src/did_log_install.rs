//! Installing a community's own `did:webvh` log, delivered by an administrator
//! (`vtc/admin/did-log/install/0.1`, Keyring VTI-35).
//!
//! Only a **serverless** community needs this. A community whose DID is on a
//! did-hosting server gets new entries there directly: the VTA holds the DID's
//! keys, and its update path publishes each entry to the host. A serverless
//! community instead serves its own log from `data/did/<label>.jsonl` (see
//! `routes::did_log`), and the VTA — which still holds the keys — has no way to
//! reach that file: the VTC keeps no VTA credential after setup. So an entry the
//! VTA appends later (a transport added to the community's services, a key
//! rotated) has to be delivered. This module decides whether a delivered log may
//! replace the served one, and swaps it in.
//!
//! ## What the administrator's authority covers
//!
//! Delivery, not content. The log authorises its own entries: each is proven
//! under the update keys its predecessor committed to, so the checks below
//! admit only entries the DID's key holder signed. An administrator — or a
//! stolen administrator token — cannot use this to publish a document the key
//! holder did not sign, and cannot move the served log backwards, because
//! every served entry must survive unchanged as a prefix.
//!
//! Witness proofs are not delivered with the log, so a DID that requires
//! witnesses fails verification here and is refused as `invalidLog` rather
//! than served without them.

use std::path::{Path, PathBuf};

use didwebvh_rs::DIDWebVHState;
use didwebvh_rs::log_entry::LogEntry;

/// Why a delivered log was refused. One variant per error code the
/// specification defines, so the route maps them without interpretation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InstallRefusal {
    /// `invalidLog`: a line fails to parse, a proof fails, or the chain breaks.
    InvalidLog(String),
    /// `wrongDid`: the log verifies, for a DID that is not this community's.
    WrongDid { expected: String, found: String },
    /// `notAnExtension`: a served entry is missing, changed or reordered.
    NotAnExtension(String),
    /// `notServedHere`: this community does not serve its own `did:webvh` log.
    NotServedHere(String),
}

impl std::fmt::Display for InstallRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidLog(why) => write!(f, "the log does not verify as did:webvh: {why}"),
            Self::WrongDid { expected, found } => {
                write!(
                    f,
                    "the log is for {found}, not this community's DID {expected}"
                )
            }
            Self::NotAnExtension(why) => write!(
                f,
                "the log does not keep every entry this community serves, unchanged and in \
                 order: {why}"
            ),
            Self::NotServedHere(why) => {
                write!(
                    f,
                    "this community does not serve its own did:webvh log: {why}"
                )
            }
        }
    }
}

impl std::error::Error for InstallRefusal {}

/// What an accepted install changes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Accepted {
    pub did: String,
    pub version_id: String,
    pub previous_version_id: String,
    pub entries_added: usize,
    /// Entries in the log now served.
    pub entry_count: usize,
    /// The first entry's `versionTime` — when the DID was created.
    pub created: Option<String>,
}

/// The lines of a served or supplied log: one entry per line, a final newline
/// optional. A blank line anywhere else is not a log line and fails parsing.
fn lines(log: &str) -> Vec<&str> {
    let body = log.strip_suffix('\n').unwrap_or(log);
    let body = body.strip_suffix('\r').unwrap_or(body);
    if body.is_empty() {
        return Vec::new();
    }
    body.split('\n')
        .map(|l| l.strip_suffix('\r').unwrap_or(l))
        .collect()
}

/// Verify `supplied` against the log served now, for the community `did`.
///
/// Pure — no I/O — so every refusal is testable without a server. The order of
/// the checks follows the specification's conformance rules: verify the whole
/// chain, then the DID, then the prefix.
pub fn check(did: &str, served: &str, supplied: &str) -> Result<Accepted, InstallRefusal> {
    let supplied_lines = lines(supplied);
    if supplied_lines.is_empty() {
        return Err(InstallRefusal::InvalidLog("the log has no entries".into()));
    }

    // 1. The whole chain, from its first entry.
    let mut entries = Vec::with_capacity(supplied_lines.len());
    let mut version = None;
    for (i, line) in supplied_lines.iter().enumerate() {
        let entry = LogEntry::deserialize_string(line, version)
            .map_err(|e| InstallRefusal::InvalidLog(format!("line {}: {e}", i + 1)))?;
        version = Some(entry.get_webvh_version());
        entries.push(entry);
    }
    let mut state = DIDWebVHState::from_log_entries(entries);
    state
        .validate()
        .map_err(|e| InstallRefusal::InvalidLog(e.to_string()))?
        // `validate` keeps the longest valid prefix and reports the rest as a
        // truncation. Serving that prefix would silently drop what was
        // delivered, so a partial chain is a refusal, not a smaller install.
        .assert_complete()
        .map_err(|e| InstallRefusal::InvalidLog(e.to_string()))?;
    if state.log_entries().len() != supplied_lines.len() {
        return Err(InstallRefusal::InvalidLog(format!(
            "{} of {} entries verified",
            state.log_entries().len(),
            supplied_lines.len()
        )));
    }

    // 2. The community's own DID.
    let last = state
        .log_entries()
        .last()
        .ok_or_else(|| InstallRefusal::InvalidLog("the log has no entries".into()))?;
    let found = last
        .get_state()
        .get("id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| InstallRefusal::InvalidLog("the last entry's document has no id".into()))?;
    if found != did {
        return Err(InstallRefusal::WrongDid {
            expected: did.to_string(),
            found: found.to_string(),
        });
    }

    // 3. Every served entry, unchanged and in order. Byte comparison, not
    //    semantic: the served bytes are what resolvers already verified, and a
    //    re-serialisation of the same entry is a different log to them.
    let served_lines = lines(served);
    if served_lines.len() > supplied_lines.len() {
        return Err(InstallRefusal::NotAnExtension(format!(
            "it has {} entries, and {} are served",
            supplied_lines.len(),
            served_lines.len()
        )));
    }
    if let Some(i) = served_lines
        .iter()
        .zip(&supplied_lines)
        .position(|(a, b)| a != b)
    {
        return Err(InstallRefusal::NotAnExtension(format!(
            "entry {} differs from the one served",
            i + 1
        )));
    }

    let version_of = |line: &str| -> String {
        serde_json::from_str::<serde_json::Value>(line)
            .ok()
            .and_then(|v| {
                v.get("versionId")
                    .and_then(|s| s.as_str())
                    .map(String::from)
            })
            .unwrap_or_default()
    };
    let version_id = last.get_version_id().to_string();
    let previous_version_id = served_lines
        .last()
        .map(|l| version_of(l))
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| version_id.clone());
    let created = serde_json::from_str::<serde_json::Value>(supplied_lines[0])
        .ok()
        .and_then(|v| {
            v.get("versionTime")
                .and_then(|t| t.as_str())
                .map(String::from)
        });
    Ok(Accepted {
        did: did.to_string(),
        version_id,
        previous_version_id,
        entries_added: supplied_lines.len() - served_lines.len(),
        entry_count: supplied_lines.len(),
        created,
    })
}

/// Serialises installs, so two deliveries cannot both read the same served log
/// and race their swaps — the second would be checked against a log that is no
/// longer the one served.
static INSTALL_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Check `supplied` against the log at `path` and, if accepted, replace it
/// atomically: written beside it and renamed over it, so `routes::did_log`
/// reads either the whole previous log or the whole new one. No restart is
/// needed — the route reads the file per request.
pub async fn install(did: &str, path: &Path, supplied: &str) -> Result<Accepted, InstallError> {
    let _guard = INSTALL_LOCK.lock().await;
    let served = match tokio::fs::read_to_string(path).await {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(
                InstallRefusal::NotServedHere(format!("no log at {}", path.display())).into(),
            );
        }
        Err(e) => return Err(InstallError::Io(e)),
    };
    let accepted = check(did, &served, supplied)?;
    if accepted.entries_added == 0 {
        // Already served: nothing to write, and rewriting identical bytes would
        // only open a window for a failed write to damage a good log.
        return Ok(accepted);
    }
    let mut body = supplied.to_string();
    if !body.ends_with('\n') {
        body.push('\n');
    }
    let tmp = temp_path(path);
    tokio::fs::write(&tmp, body.as_bytes())
        .await
        .map_err(InstallError::Io)?;
    if let Err(e) = tokio::fs::rename(&tmp, path).await {
        let _ = tokio::fs::remove_file(&tmp).await;
        return Err(InstallError::Io(e));
    }
    Ok(accepted)
}

fn temp_path(path: &Path) -> PathBuf {
    let mut name = path
        .file_name()
        .map(|n| n.to_os_string())
        .unwrap_or_default();
    name.push(".installing");
    path.with_file_name(name)
}

/// A refusal, or a failure to read or write the served log.
#[derive(Debug)]
pub enum InstallError {
    Refused(InstallRefusal),
    Io(std::io::Error),
}

impl From<InstallRefusal> for InstallError {
    fn from(r: InstallRefusal) -> Self {
        Self::Refused(r)
    }
}

impl std::fmt::Display for InstallError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Refused(r) => r.fmt(f),
            Self::Io(e) => write!(f, "could not replace the served log: {e}"),
        }
    }
}

impl std::error::Error for InstallError {}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use didwebvh_rs::DIDWebVHState;
    use didwebvh_rs::prelude::*;
    use serde_json::json;

    use super::*;

    /// A signed log: genesis, then one entry per `services` step. Returns the
    /// DID, the key, and the log's lines.
    async fn mint(host: &str, steps: &[&str]) -> (String, Secret, Vec<String>) {
        // A `did:key` signer: didwebvh-rs requires the proof's verification
        // method in `did:key:{mb}#{mb}` form.
        let (_, key) = didwebvh_rs::did_key::generate_did_key(KeyType::Ed25519).unwrap();
        let pk = key.get_public_keymultibase().unwrap();
        let document = json!({
            "id": "{DID}",
            "@context": ["https://www.w3.org/ns/did/v1"],
            "verificationMethod": [{
                "id": "{DID}#key-0", "type": "Multikey", "controller": "{DID}",
                "publicKeyMultibase": pk,
            }],
            "authentication": ["{DID}#key-0"],
            "assertionMethod": ["{DID}#key-0"],
        });
        let parameters = Parameters {
            update_keys: Some(Arc::new(vec![Multibase::new(pk)])),
            ..Default::default()
        };
        // Backdated, so the updates below stay strictly increasing and never
        // in the future at second granularity.
        let then = chrono::Utc::now() - chrono::Duration::minutes(10);
        let config = CreateDIDConfig::builder()
            .address(format!("https://{host}/"))
            .authorization_key(key.clone())
            .did_document(document)
            .parameters(parameters)
            .version_time(then.fixed_offset())
            .build()
            .unwrap();
        let created = create_did(config).await.unwrap();
        let did = created.did().to_string();
        let mut state = DIDWebVHState::from_log_entries(vec![created.log_entry().clone()]);
        state.validate().unwrap().assert_complete().unwrap();
        for step in steps {
            let mut doc = state.log_entries().last().unwrap().get_state().clone();
            doc["service"] = json!([{ "id": format!("{did}#{step}"), "type": "TSPTransport",
                                      "serviceEndpoint": "did:example:mediator" }]);
            tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
            state.update_document(doc, &key).await.unwrap();
        }
        let lines = state
            .log_entries()
            .iter()
            .map(|e| serde_json::to_string(&e.log_entry).unwrap())
            .collect();
        (did, key, lines)
    }

    fn log(lines: &[String]) -> String {
        format!("{}\n", lines.join("\n"))
    }

    /// The case VTI-35 is about: one entry appended by the key holder.
    #[tokio::test]
    async fn an_extension_signed_by_the_key_holder_is_accepted() {
        let (did, _, lines) = mint("community.example", &["tsp"]).await;
        let accepted = check(&did, &log(&lines[..1]), &log(&lines)).unwrap();
        assert_eq!(accepted.entries_added, 1);
        assert_eq!(accepted.did, did);
        assert!(
            accepted.version_id.starts_with("2-"),
            "{}",
            accepted.version_id
        );
        assert!(accepted.previous_version_id.starts_with("1-"));
    }

    /// Idempotent: the served log again changes nothing.
    #[tokio::test]
    async fn the_served_log_again_adds_nothing() {
        let (did, _, lines) = mint("community.example", &["tsp"]).await;
        let accepted = check(&did, &log(&lines), &log(&lines)).unwrap();
        assert_eq!(accepted.entries_added, 0);
        assert_eq!(accepted.version_id, accepted.previous_version_id);
    }

    /// The served log cannot move backwards: a shorter log is refused even
    /// though every entry in it is genuine.
    #[tokio::test]
    async fn a_shorter_log_is_refused() {
        let (did, _, lines) = mint("community.example", &["tsp"]).await;
        let err = check(&did, &log(&lines), &log(&lines[..1])).unwrap_err();
        assert!(matches!(err, InstallRefusal::NotAnExtension(_)), "{err}");
    }

    /// A fork: a validly signed log that diverges from what is served.
    #[tokio::test]
    async fn a_fork_is_refused() {
        let (did, key, lines) = mint("community.example", &["tsp"]).await;
        // Branch from the genesis with a different second entry, same key.
        let mut state = DIDWebVHState::from_log_entries(vec![
            LogEntry::deserialize_string(&lines[0], None).unwrap(),
        ]);
        state.validate().unwrap().assert_complete().unwrap();
        let mut doc = state.log_entries().last().unwrap().get_state().clone();
        doc["service"] = json!([]);
        tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
        state.update_document(doc, &key).await.unwrap();
        let fork: Vec<String> = state
            .log_entries()
            .iter()
            .map(|e| serde_json::to_string(&e.log_entry).unwrap())
            .collect();
        let err = check(&did, &log(&lines), &log(&fork)).unwrap_err();
        assert!(matches!(err, InstallRefusal::NotAnExtension(_)), "{err}");
    }

    /// An entry the key holder did not sign fails verification — whoever
    /// delivers it.
    #[tokio::test]
    async fn a_tampered_entry_is_refused() {
        let (did, _, mut lines) = mint("community.example", &["tsp"]).await;
        let served = log(&lines[..1]);
        lines[1] = lines[1].replace("did:example:mediator", "did:example:attacker");
        let err = check(&did, &served, &log(&lines)).unwrap_err();
        assert!(matches!(err, InstallRefusal::InvalidLog(_)), "{err}");
    }

    #[tokio::test]
    async fn another_dids_log_is_refused() {
        let (did, _, lines) = mint("community.example", &[]).await;
        let (_, _, other) = mint("elsewhere.example", &[]).await;
        let err = check(&did, &log(&lines), &log(&other)).unwrap_err();
        assert!(matches!(err, InstallRefusal::WrongDid { .. }), "{err}");
    }

    #[tokio::test]
    async fn garbage_is_refused_as_invalid() {
        let (did, _, lines) = mint("community.example", &[]).await;
        for bad in ["", "not json\n", "{}\n"] {
            let err = check(&did, &log(&lines), bad).unwrap_err();
            assert!(
                matches!(err, InstallRefusal::InvalidLog(_)),
                "{bad:?}: {err}"
            );
        }
    }

    /// End to end on disk: accepted, written, and the file is the new log.
    #[tokio::test]
    async fn install_swaps_the_served_file() {
        let (did, _, lines) = mint("community.example", &["tsp"]).await;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("community.example.jsonl");
        std::fs::write(&path, log(&lines[..1])).unwrap();
        let accepted = install(&did, &path, &log(&lines)).await.unwrap();
        assert_eq!(accepted.entries_added, 1);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), log(&lines));
        assert!(!temp_path(&path).exists(), "no temporary file left behind");

        // A refusal leaves the served file exactly as it was.
        let before = std::fs::read_to_string(&path).unwrap();
        assert!(install(&did, &path, &log(&lines[..1])).await.is_err());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), before);
    }

    #[tokio::test]
    async fn no_served_log_is_not_served_here() {
        let dir = tempfile::tempdir().unwrap();
        let err = install("did:webvh:x:y", &dir.path().join("none.jsonl"), "{}\n")
            .await
            .unwrap_err();
        assert!(
            matches!(err, InstallError::Refused(InstallRefusal::NotServedHere(_))),
            "{err}"
        );
    }
}
