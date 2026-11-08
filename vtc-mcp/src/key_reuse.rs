//! A local note of the community each agent key signed in to, so the bridge
//! can warn when one key is pointed at a second community.
//!
//! An agent DID is recorded by every community it signs in to — its audit
//! trail, its list of the administrator's signing keys, its delegations. Two
//! communities that hold the same agent DID can tell that the same assistant,
//! and so the same person, stands behind both; neither can see that from its
//! own records (VTI-KEY-005, VTI-KEY-006: a distinct identifier
//! for each relationship, and a client identifier never reused across trust
//! contexts). Only the machine that holds
//! the key can notice the reuse, so the bridge does.
//!
//! The note warns and never refuses: an operator may mean to use one key at
//! two communities. It holds DIDs only, never key material, and is written
//! owner-only because a list of the communities one person uses is itself
//! the correlation it exists to prevent.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// The file the note is kept in: `$VTC_MCP_STATE_DIR`, else
/// `$XDG_STATE_HOME/vtc-mcp`, else `~/.local/state/vtc-mcp`. `None` when none
/// of them is set.
pub fn default_path() -> Option<PathBuf> {
    let env = |k: &str| {
        std::env::var_os(k)
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
    };
    let dir = env("VTC_MCP_STATE_DIR")
        .or_else(|| env("XDG_STATE_HOME").map(|d| d.join("vtc-mcp")))
        .or_else(|| env("HOME").map(|h| h.join(".local/state/vtc-mcp")))?;
    Some(dir.join("agent-communities.json"))
}

/// The communities other than `vtc_did` that `agent_did` was used with, read
/// from the note at `path`; `vtc_did` is then added to it. An unreadable note
/// reads as empty and is rewritten, since the note only ever warns.
pub fn check_and_record(
    path: &Path,
    agent_did: &str,
    vtc_did: &str,
) -> std::io::Result<Vec<String>> {
    let mut note: BTreeMap<String, Vec<String>> = std::fs::read(path)
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default();
    let used = note.entry(agent_did.to_string()).or_default();
    let others: Vec<String> = used.iter().filter(|d| *d != vtc_did).cloned().collect();
    if used.iter().any(|d| d == vtc_did) {
        return Ok(others);
    }
    used.push(vtc_did.to_string());
    write_owner_only(path, &serde_json::to_vec_pretty(&note)?)?;
    Ok(others)
}

fn write_owner_only(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let tmp = path.with_extension("json.tmp");
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(&tmp)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    drop(f);
    std::fs::rename(&tmp, path)
}

/// The words the operator and the model are given for a key seen elsewhere.
pub fn warning(agent_did: &str, others: &[String]) -> String {
    format!(
        "agent key {agent_did} was also used with {}; communities that compare what they \
         recorded can tell that the same person stands behind both. Mint a key for each \
         community (`vtc-mcp --mint-did-key`).",
        others.join(", ")
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn note_path(dir: &Path) -> PathBuf {
        dir.join("state").join("agent-communities.json")
    }

    #[test]
    fn a_key_used_with_one_community_is_not_flagged() {
        let dir = tempfile::tempdir().unwrap();
        let p = note_path(dir.path());
        assert!(
            check_and_record(&p, "did:key:zA", "did:web:one")
                .unwrap()
                .is_empty()
        );
        assert!(
            check_and_record(&p, "did:key:zA", "did:web:one")
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn a_key_pointed_at_a_second_community_names_the_first() {
        let dir = tempfile::tempdir().unwrap();
        let p = note_path(dir.path());
        check_and_record(&p, "did:key:zA", "did:web:one").unwrap();
        assert_eq!(
            check_and_record(&p, "did:key:zA", "did:web:two").unwrap(),
            vec!["did:web:one".to_string()]
        );
        // Another key at the second community is its own.
        assert!(
            check_and_record(&p, "did:key:zB", "did:web:two")
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn an_unreadable_note_reads_as_empty() {
        let dir = tempfile::tempdir().unwrap();
        let p = note_path(dir.path());
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, b"not json").unwrap();
        assert!(
            check_and_record(&p, "did:key:zA", "did:web:one")
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            check_and_record(&p, "did:key:zA", "did:web:two")
                .unwrap()
                .len(),
            1
        );
    }

    #[cfg(unix)]
    #[test]
    fn the_note_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let p = note_path(dir.path());
        check_and_record(&p, "did:key:zA", "did:web:one").unwrap();
        let mode = std::fs::metadata(&p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }
}
