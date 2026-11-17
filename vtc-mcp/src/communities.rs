//! `--communities <file>`: one `--listen` process bridging several communities,
//! each served at its own path (`/mcp/<name>`) as its own identity, under its
//! own policy, with its own audit log and sign-in.
//!
//! The file is TOML, one section per community:
//!
//! ```toml
//! [community.first-vtc]
//! vtc_did        = "did:webvh:…:vtc.example.com"
//! agent_key_file = "keys/first-vtc.json"   # owner-only; relative to this file
//! confirm        = "sensitive"
//! audit_log      = "first-vtc-audit.jsonl"
//!
//! [community.acme]
//! vtc_did            = "did:webvh:…:acme.example"
//! agent_secrets_file = "~/.config/vtc-mcp/acme-persona.json"
//! read_only          = true
//! ```
//!
//! Why a path per community and not one endpoint with a `community` argument
//! (design note D7a): each MCP server a host sees is then exactly one identity
//! at one community, so a host's approval of one server's tools is never an
//! approval at another community, and the guard, the audit log and the
//! sign-in stay those of the one community they were written for.
//!
//! What is the operator's policy is settled here and is fatal when wrong — a
//! file that cannot be read, an unknown key, a bad name, a confirm level or
//! transport that does not parse, an audit log that cannot be opened, and
//! **one agent key named for two communities** (VTI-KEY-005, VTI-KEY-006: the
//! key-reuse note only warns, because a single bridge cannot see the second
//! community; a file that names both can, so it refuses). What is identity —
//! a key file that is missing or readable by others — leaves that one
//! community serving degraded, as a single bridge would, so its own
//! `vtc_status` says what is wrong while the others work.
//!
//! Key material never sits in the file itself: `agent_key_file` names an
//! owner-only file holding the key (the JSON `--mint-did-key` prints, or the
//! bare multibase key), and `agent_secrets_file` a persona's secrets bundle.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::Deserialize;
use vta_sdk::did_secrets::DidSecretsBundle;
use vtc_client::SessionIdentity;
use vti_mcp_common::guard::{ConfirmLevel, Guard};
use vti_mcp_common::listen::check_service_name;

use crate::TransportOpt;

/// The file as written.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct File {
    #[serde(default)]
    community: BTreeMap<String, Section>,
}

/// One `[community.<name>]` section as written.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct Section {
    vtc_did: String,
    vtc_url: Option<String>,
    /// Rung 2: optional, as the key determines it; checked against the key
    /// when given.
    agent_did: Option<String>,
    agent_key_file: Option<PathBuf>,
    /// Rung 1.
    agent_secrets_file: Option<PathBuf>,
    transport: Option<String>,
    read_only: Option<bool>,
    allow: Option<Vec<String>>,
    #[serde(default)]
    deny: Vec<String>,
    confirm: Option<String>,
    audit_log: Option<PathBuf>,
}

/// The process-wide flags a section falls back to: the policy flags given
/// beside `--communities` are every community's default.
pub struct Defaults {
    pub transport: TransportOpt,
    pub read_only: bool,
    pub allow: Vec<String>,
    pub deny: Vec<String>,
    pub confirm: String,
}

/// The identity rung a section selects: the session identity and its label,
/// or why there is none.
pub type Rung = Result<(SessionIdentity, &'static str), String>;

/// One community, resolved: everything needed to open its bridge.
pub struct Community {
    pub name: String,
    pub vtc_did: String,
    pub vtc_url: Option<String>,
    pub rung: Rung,
    pub transport: TransportOpt,
    pub guard: Guard,
    pub audit_log: Option<PathBuf>,
}

/// Read and resolve the communities file at `path`.
pub fn load(path: &Path, defaults: &Defaults) -> Result<Vec<Community>, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("reading --communities {}: {e}", path.display()))?;
    let base = path.parent().unwrap_or(Path::new("."));
    parse(&text, base, defaults).map_err(|e| format!("--communities {}: {e}", path.display()))
}

/// Resolve the file's text; relative paths in it are read from `base`.
fn parse(text: &str, base: &Path, defaults: &Defaults) -> Result<Vec<Community>, String> {
    let file: File = toml::from_str(text).map_err(|e| e.to_string())?;
    if file.community.is_empty() {
        return Err("names no community: add a [community.<name>] section".into());
    }
    let mut communities = Vec::with_capacity(file.community.len());
    for (name, section) in file.community {
        check_service_name(&name).map_err(|e| format!("[community.{name}]: {e}"))?;
        communities.push(
            resolve(&name, section, base, defaults)
                .map_err(|e| format!("[community.{name}]: {e}"))?,
        );
    }
    refuse_shared_keys(&communities)?;
    Ok(communities)
}

fn resolve(
    name: &str,
    section: Section,
    base: &Path,
    defaults: &Defaults,
) -> Result<Community, String> {
    let vtc_did = section.vtc_did.trim().to_string();
    if vtc_did.is_empty() {
        return Err("vtc_did is empty: it names the community".into());
    }
    let transport = match section.transport.as_deref() {
        None => defaults.transport,
        Some(t) => <TransportOpt as clap::ValueEnum>::from_str(t, true)
            .map_err(|_| format!("transport `{t}`: expected auto, tsp, didcomm or rest"))?,
    };
    let confirm = section.confirm.as_deref().unwrap_or(&defaults.confirm);
    // A section narrows the process-wide deny list; it never lifts it.
    let mut deny = defaults.deny.clone();
    deny.extend(section.deny);
    let guard = Guard {
        read_only: section.read_only.unwrap_or(defaults.read_only),
        allow: section.allow.unwrap_or_else(|| defaults.allow.clone()),
        deny,
        confirm: ConfirmLevel::parse(confirm).map_err(|e| format!("confirm: {e}"))?,
        node: "VTC",
    };
    let rung = rung(
        section.agent_did.as_deref(),
        section.agent_key_file.as_deref().map(|p| expand(p, base)),
        section
            .agent_secrets_file
            .as_deref()
            .map(|p| expand(p, base)),
    )?;
    Ok(Community {
        name: name.to_string(),
        vtc_did,
        vtc_url: section.vtc_url,
        rung,
        transport,
        guard,
        audit_log: section.audit_log.as_deref().map(|p| expand(p, base)),
    })
}

/// The identity a section names. Configuration that cannot name one — both
/// rungs, or neither — is the operator's error and fatal (the outer `Err`).
/// A key that cannot be used is the inner `Err`: that community serves
/// degraded and says why.
fn rung(
    agent_did: Option<&str>,
    key_file: Option<PathBuf>,
    secrets_file: Option<PathBuf>,
) -> Result<Rung, String> {
    match (key_file, secrets_file) {
        (Some(_), Some(_)) => Err(
            "agent_key_file (a did:key) and agent_secrets_file (a did:webvh persona) are \
             mutually exclusive — name one identity, not both"
                .into(),
        ),
        (None, None) => Err(
            "no identity: name agent_key_file (a did:key, as `vtc-mcp --mint-did-key` prints \
             it) or agent_secrets_file (a member persona's secrets bundle)"
                .into(),
        ),
        (None, Some(path)) => {
            if agent_did.is_some() {
                return Err(
                    "agent_did goes with agent_key_file; a persona's DID is its bundle's".into(),
                );
            }
            Ok(read_owner_only(&path).and_then(|json| {
                let bundle: DidSecretsBundle = serde_json::from_str(&json)
                    .map_err(|e| format!("parsing the secrets bundle {}: {e}", path.display()))?;
                Ok((SessionIdentity::Bundle(bundle), "did:webvh-bundle"))
            }))
        }
        (Some(path), None) => Ok(read_owner_only(&path)
            .and_then(|text| did_key(&text, agent_did, &path))
            .map(|(did, key)| {
                (
                    SessionIdentity::DidKey {
                        did,
                        private_key_multibase: key,
                    },
                    "did:key",
                )
            })),
    }
}

/// The DID and key in a key file: the JSON `--mint-did-key` prints, or the
/// bare multibase key. The DID is derived from the key; one written beside it
/// (in the file, or as `agent_did`) must agree.
fn did_key(text: &str, agent_did: Option<&str>, path: &Path) -> Result<(String, String), String> {
    let text = text.trim();
    let (key, written) = if text.starts_with('{') {
        let v: serde_json::Value = serde_json::from_str(text)
            .map_err(|e| format!("parsing the key file {}: {e}", path.display()))?;
        let key = v["privateKeyMultibase"]
            .as_str()
            .ok_or_else(|| format!("the key file {} has no privateKeyMultibase", path.display()))?;
        (key.to_string(), v["did"].as_str().map(str::to_string))
    } else {
        (text.to_string(), None)
    };
    let seed = vta_sdk::did_key::decode_private_key_multibase(&key)
        .map_err(|e| format!("the key in {} is not an Ed25519 key: {e}", path.display()))?;
    let signing = ed25519_dalek::SigningKey::from_bytes(&seed);
    let did = format!(
        "did:key:{}",
        vta_sdk::did_key::ed25519_multibase_pubkey(&signing.verifying_key().to_bytes())
    );
    for claimed in written.as_deref().into_iter().chain(agent_did) {
        if claimed.trim() != did {
            return Err(format!(
                "the key in {} is {did}, not {claimed}",
                path.display()
            ));
        }
    }
    Ok((did, key))
}

/// Read a file that holds key material, refusing one anyone but its owner
/// can read.
fn read_owner_only(path: &Path) -> Result<String, String> {
    let text =
        std::fs::read_to_string(path).map_err(|e| format!("reading {}: {e}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(path)
            .map_err(|e| format!("reading {}: {e}", path.display()))?
            .permissions()
            .mode();
        if mode & 0o077 != 0 {
            return Err(format!(
                "{} holds a key and is readable by others (mode {:o}); run `chmod 600` on it",
                path.display(),
                mode & 0o777
            ));
        }
    }
    Ok(text)
}

/// One agent key for two communities is the correlation the key-reuse note
/// warns of (VTI-KEY-005, VTI-KEY-006); a file that names both is refused.
fn refuse_shared_keys(communities: &[Community]) -> Result<(), String> {
    let mut seen: BTreeMap<&str, &str> = BTreeMap::new();
    for c in communities {
        let Ok((identity, _)) = &c.rung else { continue };
        if let Some(first) = seen.insert(identity.did(), &c.name) {
            return Err(format!(
                "[community.{first}] and [community.{}] both use agent {}: communities that \
                 compare what they recorded could tell the same person stands behind both. \
                 Mint a key for each (`vtc-mcp --mint-did-key`).",
                c.name,
                identity.did()
            ));
        }
    }
    Ok(())
}

/// `~/…` from `$HOME`; a relative path from the file's directory.
fn expand(path: &Path, base: &Path) -> PathBuf {
    if let Ok(rest) = path.strip_prefix("~")
        && let Some(home) = std::env::var_os("HOME")
    {
        return PathBuf::from(home).join(rest);
    }
    if path.is_relative() {
        base.join(path)
    } else {
        path.to_path_buf()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn defaults() -> Defaults {
        Defaults {
            transport: TransportOpt::Auto,
            read_only: false,
            allow: vec![],
            deny: vec!["vtc/backup/*".into()],
            confirm: "destructive".into(),
        }
    }

    /// A minted key written owner-only into `dir`, and its DID.
    fn key_file(dir: &Path, name: &str) -> (PathBuf, String) {
        let minted = crate::mint_did_key().unwrap();
        let path = dir.join(name);
        vti_mcp_common::listen::write_owner_only(&path, minted.to_string().as_bytes()).unwrap();
        (path, minted["did"].as_str().unwrap().to_string())
    }

    fn did_of(c: &Community) -> &str {
        c.rung.as_ref().unwrap().0.did()
    }

    #[test]
    fn each_section_is_its_own_identity_and_policy() {
        let dir = tempfile::tempdir().unwrap();
        let (_, a_did) = key_file(dir.path(), "a.json");
        let (_, b_did) = key_file(dir.path(), "b.json");
        let text = r#"
            [community.first-vtc]
            vtc_did = "did:webvh:x:first.example"
            agent_key_file = "a.json"
            confirm = "sensitive"
            audit_log = "first.jsonl"

            [community.acme]
            vtc_did = "did:webvh:y:acme.example"
            agent_key_file = "b.json"
            read_only = true
            deny = ["vtc/groups/*"]
            transport = "rest"
        "#;
        let communities = parse(text, dir.path(), &defaults()).unwrap();
        let by_name: BTreeMap<_, _> = communities.iter().map(|c| (c.name.as_str(), c)).collect();

        let first = by_name["first-vtc"];
        assert_eq!(did_of(first), a_did);
        assert_eq!(
            first.guard.confirm,
            ConfirmLevel::parse("sensitive").unwrap()
        );
        assert!(!first.guard.read_only);
        assert_eq!(first.transport, TransportOpt::Auto);
        assert_eq!(
            first.audit_log.as_deref(),
            Some(dir.path().join("first.jsonl").as_path())
        );

        let acme = by_name["acme"];
        assert_eq!(did_of(acme), b_did);
        assert!(acme.guard.read_only);
        assert_eq!(acme.transport, TransportOpt::Rest);
        assert_eq!(acme.guard.confirm, ConfirmLevel::Destructive, "the default");
        assert_eq!(
            acme.guard.deny,
            vec!["vtc/backup/*", "vtc/groups/*"],
            "narrowed, not lifted"
        );
    }

    /// VTI-KEY-005, VTI-KEY-006: one key at two communities is refused when
    /// the file names both.
    #[test]
    fn vti_key_005_one_key_for_two_communities_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        key_file(dir.path(), "a.json");
        let text = r#"
            [community.one]
            vtc_did = "did:webvh:x:one.example"
            agent_key_file = "a.json"
            [community.two]
            vtc_did = "did:webvh:y:two.example"
            agent_key_file = "a.json"
        "#;
        let err = parse(text, dir.path(), &defaults()).err().expect("refused");
        assert!(err.contains("both use agent"), "{err}");
    }

    #[test]
    fn a_bare_key_derives_its_did_and_a_wrong_did_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let minted = crate::mint_did_key().unwrap();
        let bare = dir.path().join("bare.key");
        let key = minted["privateKeyMultibase"].as_str().unwrap();
        vti_mcp_common::listen::write_owner_only(&bare, format!("{key}\n").as_bytes()).unwrap();
        let (did, _) = did_key(&std::fs::read_to_string(&bare).unwrap(), None, &bare).unwrap();
        assert_eq!(did, minted["did"].as_str().unwrap());

        let text = r#"
            [community.one]
            vtc_did = "did:webvh:x:one.example"
            agent_key_file = "bare.key"
            agent_did = "did:key:z6MkSomebodyElse"
        "#;
        let communities = parse(text, dir.path(), &defaults()).unwrap();
        let err = communities[0].rung.as_ref().err().unwrap();
        assert!(err.contains("not did:key:z6MkSomebodyElse"), "{err}");
    }

    /// A key that cannot be used leaves that community degraded, not the
    /// process down.
    #[cfg(unix)]
    #[test]
    fn a_key_file_others_can_read_degrades_only_its_community() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let (open, _) = key_file(dir.path(), "open.json");
        std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o644)).unwrap();
        key_file(dir.path(), "ok.json");
        let text = r#"
            [community.open]
            vtc_did = "did:webvh:x:one.example"
            agent_key_file = "open.json"
            [community.ok]
            vtc_did = "did:webvh:y:two.example"
            agent_key_file = "ok.json"
            [community.missing]
            vtc_did = "did:webvh:z:three.example"
            agent_key_file = "nowhere.json"
        "#;
        let communities = parse(text, dir.path(), &defaults()).unwrap();
        let rung = |n: &str| &communities.iter().find(|c| c.name == n).unwrap().rung;
        assert!(
            rung("open")
                .as_ref()
                .err()
                .unwrap()
                .contains("readable by others")
        );
        assert!(rung("missing").is_err());
        assert!(rung("ok").is_ok());
    }

    #[test]
    fn what_is_the_operators_policy_is_fatal() {
        let dir = tempfile::tempdir().unwrap();
        key_file(dir.path(), "a.json");
        let cases = [
            ("", "names no community"),
            (
                "[community.Bad]\nvtc_did = \"d\"\nagent_key_file = \"a.json\"",
                "cannot be served",
            ),
            (
                "[community.a]\nvtc_did = \"d\"\nagent_key = \"z3u2\"\nagent_key_file = \"a.json\"",
                "unknown field",
            ),
            ("[community.a]\nvtc_did = \"d\"", "no identity"),
            (
                "[community.a]\nvtc_did = \"d\"\nagent_key_file = \"a.json\"\nagent_secrets_file = \"b\"",
                "mutually exclusive",
            ),
            (
                "[community.a]\nvtc_did = \" \"\nagent_key_file = \"a.json\"",
                "vtc_did is empty",
            ),
            (
                "[community.a]\nvtc_did = \"d\"\nagent_key_file = \"a.json\"\nconfirm = \"maybe\"",
                "confirm",
            ),
            (
                "[community.a]\nvtc_did = \"d\"\nagent_key_file = \"a.json\"\ntransport = \"pigeon\"",
                "transport",
            ),
        ];
        for (text, expected) in cases {
            let err = parse(text, dir.path(), &defaults())
                .err()
                .unwrap_or_else(|| panic!("accepted: {text}"));
            assert!(err.contains(expected), "{text}: {err}");
        }
    }

    #[test]
    fn paths_resolve_from_home_and_from_the_file() {
        let base = Path::new("/etc/vtc-mcp");
        assert_eq!(expand(Path::new("k.json"), base), base.join("k.json"));
        assert_eq!(
            expand(Path::new("/abs/k.json"), base),
            PathBuf::from("/abs/k.json")
        );
        if let Some(home) = std::env::var_os("HOME") {
            assert_eq!(
                expand(Path::new("~/k.json"), base),
                PathBuf::from(home).join("k.json")
            );
        }
    }
}
