//! The `did:scid:vh:1` form of a `did:webvh` identity (VTI-KEY-160 to
//! VTI-KEY-166).
//!
//! A `did:scid:vh:1` identity is the DID `did:scid:vh:1:<scid>`, verified by a
//! `did:webvh` log but not bound to the host serving it. Its `?src=` query is a
//! locator, not part of the identity (VTI-KEY-160): two DID URLs that differ only
//! in `src` name the same subject, and the log can move without the DID
//! changing.
//!
//! These are string rules only, so every consumer of this crate can apply them
//! without a DID library: what a durable identity is, the identity a reference
//! names, and the two forms of one log. They agree with `didwebvh-rs`
//! (`convert_webvh_id_to_scid_id` / `convert_scid_id_to_webvh_id`) and
//! `affinidi_did_common::scid`; the VTA holds the three to that in a test.

use std::borrow::Cow;
use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

/// The `did:scid:vh:1` prefix.
pub const SCID_VH_PREFIX: &str = "did:scid:vh:1:";
/// The `did:webvh` prefix.
pub const WEBVH_PREFIX: &str = "did:webvh:";

/// The identity a new `did:webvh` log is presented as (VTI-KEY-165,
/// VTI-VTA-034, VTI-VTC-004). The log is a `did:webvh` log either way.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[non_exhaustive]
pub enum DidMethod {
    /// `did:webvh:<scid>:<host>[:<path>]` — the default.
    #[default]
    Webvh,
    /// `did:scid:vh:1:<scid>`, located by `?src=<host>[/<path>]`.
    Scid,
}

impl DidMethod {
    /// The configuration and wire spelling: `webvh` or `scid`.
    pub fn as_str(&self) -> &'static str {
        match self {
            DidMethod::Webvh => "webvh",
            DidMethod::Scid => "scid",
        }
    }
}

impl fmt::Display for DidMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for DidMethod {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "webvh" | "did:webvh" => Ok(DidMethod::Webvh),
            "scid" | "did:scid" => Ok(DidMethod::Scid),
            other => Err(format!(
                "unknown DID method '{other}', expected 'webvh' or 'scid'"
            )),
        }
    }
}

/// Whether `did` is a `did:scid` DID or DID URL.
pub fn is_scid(did: &str) -> bool {
    did.starts_with("did:scid:")
}

/// Whether `did` names a durable node identity (VTI-KEY-001): a `did:webvh`, or
/// a `did:scid:vh:1`, with or without `src`.
pub fn is_durable(did: &str) -> bool {
    did.starts_with(WEBVH_PREFIX) || did.starts_with(SCID_VH_PREFIX)
}

/// Whether `did` names a DID resolved over the network from the host it names:
/// `did:web`, `did:webvh`, or a `did:scid:vh:1` whose log is a `did:webvh` log.
pub fn is_network_resolved(did: &str) -> bool {
    did.starts_with("did:web:") || is_durable(did)
}

fn split_src(did_url: &str) -> Option<(&str, &str, &str)> {
    if !is_scid(did_url) {
        return None;
    }
    let (did, rest) = did_url.split_once('?')?;
    let (query, fragment) = match rest.find('#') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, ""),
    };
    let src = query.strip_prefix("src=")?;
    if src.is_empty() || src.contains('&') {
        return None;
    }
    Some((did, src, fragment))
}

/// The identity a reference names: a `did:scid` DID URL without its `src`
/// locator, keeping any fragment. Anything else is returned unchanged.
pub fn strip_src(did_url: &str) -> Cow<'_, str> {
    match split_src(did_url) {
        Some((did, _, "")) => Cow::Borrowed(did),
        Some((did, _, fragment)) => Cow::Owned(format!("{did}{fragment}")),
        None => Cow::Borrowed(did_url),
    }
}

/// The `src` locator of a `did:scid` DID URL, if it carries one.
pub fn src(did_url: &str) -> Option<&str> {
    split_src(did_url).map(|(_, src, _)| src)
}

/// The DID a reference names, with no fragment and no `did:scid` `src`: the
/// identity to compare, authorise and record (VTI-KEY-160, VTI-KEY-164).
pub fn identity(reference: &str) -> String {
    let did = reference.split('#').next().unwrap_or(reference);
    strip_src(did).into_owned()
}

/// Whether two references name the same thing, ignoring a `did:scid` `src`
/// (VTI-KEY-163). A `did:scid` and a `did:webvh` are never the same reference,
/// even for one log (VTI-KEY-164).
pub fn same_reference(a: &str, b: &str) -> bool {
    a == b || strip_src(a) == strip_src(b)
}

/// The two `did:scid` forms of a `did:webvh` DID: the bare DID (the identity)
/// and the DID URL with `src` (what is given out where a recipient may need a
/// source). `None` for anything that is not a `did:webvh:<scid>:<host>[...]`.
pub fn scid_forms(webvh_did: &str) -> Option<(String, String)> {
    let rest = webvh_did.strip_prefix(WEBVH_PREFIX)?;
    let rest = rest.split('#').next().unwrap_or(rest);
    let (scid, tail) = rest.split_once(':')?;
    if scid.is_empty() || tail.is_empty() {
        return None;
    }
    let bare = format!("{SCID_VH_PREFIX}{scid}");
    let url = format!("{bare}?src={}", tail.replace(':', "/"));
    Some((bare, url))
}

/// The did:webvh DID of the log a `did:scid:vh:1:<scid>?src=<source>` DID URL
/// names: `<source>` with each `/` replaced by `:` (VTI-KEY-160). A reader's
/// leniency is applied first — an `https://`/`http://` scheme and trailing `/`
/// dropped, a literal `:` before a port encoded as `%3A`. `None` for a bare
/// did:scid (it names no source), another format, or a malformed `src`.
pub fn webvh_did(did_url: &str) -> Option<String> {
    let did_url = did_url.split('#').next().unwrap_or(did_url);
    let scid = did_url.strip_prefix(SCID_VH_PREFIX)?.split('?').next()?;
    if scid.is_empty() || scid.contains(':') {
        return None;
    }
    let source = src(did_url)?;
    let source = source
        .strip_prefix("https://")
        .or_else(|| source.strip_prefix("http://"))
        .unwrap_or(source)
        .trim_end_matches('/');
    let (host, path) = match source.split_once('/') {
        Some((h, p)) => (h, Some(p)),
        None => (source, None),
    };
    let host = match host.split_once(':') {
        Some((h, port)) if !h.is_empty() && port.parse::<u16>().is_ok() => {
            format!("{h}%3A{port}")
        }
        Some(_) => return None,
        None => host.to_string(),
    };
    if host.is_empty() {
        return None;
    }
    let mut out = format!("{WEBVH_PREFIX}{scid}:{host}");
    if let Some(path) = path.filter(|p| !p.is_empty()) {
        if path.split('/').any(str::is_empty) {
            return None;
        }
        out.push(':');
        out.push_str(&path.replace('/', ":"));
    }
    Some(out)
}

/// The SCID a `did:webvh` or `did:scid:vh:1` reference carries.
pub fn scid_of(did: &str) -> Option<&str> {
    let did = did.split('#').next().unwrap_or(did);
    if let Some(rest) = did.strip_prefix(SCID_VH_PREFIX) {
        let scid = rest.split('?').next().unwrap_or(rest);
        return (!scid.is_empty()).then_some(scid);
    }
    let rest = did.strip_prefix(WEBVH_PREFIX)?;
    let (scid, _) = rest.split_once(':')?;
    (!scid.is_empty()).then_some(scid)
}

/// A key or service reference under a `did:webvh` log, expressed under the
/// `did:scid` identity of the same log: `did:webvh:<scid>:host#key-1` with
/// identity `did:scid:vh:1:<scid>` becomes `did:scid:vh:1:<scid>#key-1`.
///
/// `None` unless `identity` is a bare `did:scid:vh:1` DID and `reference` is a
/// fragment reference under a `did:webvh` DID carrying the same SCID. The VTA
/// names key records by the log's own method ids; a did:scid identity's
/// document lists them under the did:scid DID (VTI-KEY-161), so this is the
/// name a secret is used under.
pub fn presented_reference(identity: &str, reference: &str) -> Option<String> {
    let identity = strip_src(identity);
    let scid = identity.strip_prefix(SCID_VH_PREFIX)?;
    if scid.is_empty() || scid.contains(['?', '#', ':']) {
        return None;
    }
    let (did, fragment) = reference.split_once('#')?;
    if !did.starts_with(WEBVH_PREFIX) || scid_of(did) != Some(scid) {
        return None;
    }
    Some(format!("{identity}#{fragment}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn method_parses_and_prints() {
        assert_eq!("webvh".parse::<DidMethod>().unwrap(), DidMethod::Webvh);
        assert_eq!("SCID".parse::<DidMethod>().unwrap(), DidMethod::Scid);
        assert_eq!("did:scid".parse::<DidMethod>().unwrap(), DidMethod::Scid);
        assert!("key".parse::<DidMethod>().is_err());
        assert_eq!(DidMethod::default(), DidMethod::Webvh);
        assert_eq!(serde_json::to_value(DidMethod::Scid).unwrap(), "scid");
    }

    #[test]
    fn durable_identities() {
        assert!(is_durable("did:webvh:Qm:example.com"));
        assert!(is_durable("did:scid:vh:1:Qm"));
        assert!(is_durable("did:scid:vh:1:Qm?src=example.com"));
        assert!(!is_durable("did:scid:ke:1:Qm?src=example.com"));
        assert!(!is_durable("did:key:z6Mk"));
        assert!(is_network_resolved("did:web:example.com"));
        assert!(!is_network_resolved("did:peer:2.Ez"));
    }

    #[test]
    fn src_is_a_locator() {
        assert_eq!(
            strip_src("did:scid:vh:1:Qm?src=example.com/a#key-1"),
            "did:scid:vh:1:Qm#key-1"
        );
        assert_eq!(
            src("did:scid:vh:1:Qm?src=example.com/a"),
            Some("example.com/a")
        );
        assert_eq!(
            identity("did:scid:vh:1:Qm?src=example.com/a#key-1"),
            "did:scid:vh:1:Qm"
        );
        assert_eq!(
            identity("did:webvh:Qm:example.com#key-1"),
            "did:webvh:Qm:example.com"
        );
        for unchanged in [
            "did:scid:vh:1:Qm?src=a&versionId=1",
            "did:webvh:Qm:example.com?versionId=1",
        ] {
            assert_eq!(strip_src(unchanged), unchanged);
        }
        assert!(same_reference(
            "did:scid:vh:1:Qm?src=a.example#key-1",
            "did:scid:vh:1:Qm#key-1"
        ));
        assert!(!same_reference(
            "did:scid:vh:1:Qm#key-1",
            "did:webvh:Qm:a.example#key-1"
        ));
    }

    #[test]
    fn forms_of_a_log() {
        assert_eq!(
            scid_forms("did:webvh:Qm:example.com:alice"),
            Some((
                "did:scid:vh:1:Qm".to_string(),
                "did:scid:vh:1:Qm?src=example.com/alice".to_string()
            ))
        );
        assert_eq!(
            scid_forms("did:webvh:Qm:localhost%3A8000").unwrap().1,
            "did:scid:vh:1:Qm?src=localhost%3A8000"
        );
        assert_eq!(scid_forms("did:webvh:Qm"), None);
        assert_eq!(scid_forms("did:key:z6Mk"), None);
        assert_eq!(scid_of("did:scid:vh:1:Qm?src=a#k"), Some("Qm"));
        assert_eq!(scid_of("did:webvh:Qm:a"), Some("Qm"));
    }

    #[test]
    fn a_did_url_names_its_log() {
        assert_eq!(
            webvh_did("did:scid:vh:1:Qm?src=example.com/alice").as_deref(),
            Some("did:webvh:Qm:example.com:alice")
        );
        for lenient in [
            "did:scid:vh:1:Qm?src=https://localhost:8000/a/",
            "did:scid:vh:1:Qm?src=localhost%3A8000/a",
            "did:scid:vh:1:Qm?src=localhost:8000/a#key-1",
        ] {
            assert_eq!(
                webvh_did(lenient).as_deref(),
                Some("did:webvh:Qm:localhost%3A8000:a"),
                "{lenient}"
            );
        }
        for none in [
            "did:scid:vh:1:Qm",
            "did:scid:ke:1:Qm?src=example.com",
            "did:scid:vh:1:Qm?src=example.com:notaport",
            "did:scid:vh:1:Qm?src=example.com//a",
            "did:webvh:Qm:example.com",
        ] {
            assert_eq!(webvh_did(none), None, "{none}");
        }
        // The two directions agree.
        let (_, url) = scid_forms("did:webvh:Qm:localhost%3A8000:a:b").unwrap();
        assert_eq!(
            webvh_did(&url).as_deref(),
            Some("did:webvh:Qm:localhost%3A8000:a:b")
        );
    }

    #[test]
    fn webvh_references_present_under_the_scid_identity() {
        assert_eq!(
            presented_reference("did:scid:vh:1:Qm", "did:webvh:Qm:example.com#key-1").as_deref(),
            Some("did:scid:vh:1:Qm#key-1")
        );
        assert_eq!(
            presented_reference(
                "did:scid:vh:1:Qm?src=example.com",
                "did:webvh:Qm:example.com#key-1"
            )
            .as_deref(),
            Some("did:scid:vh:1:Qm#key-1")
        );
        // Another log's key is never this identity's.
        assert_eq!(
            presented_reference("did:scid:vh:1:Qm", "did:webvh:QmOther:example.com#key-1"),
            None
        );
        assert_eq!(
            presented_reference("did:webvh:Qm:example.com", "did:webvh:Qm:example.com#key-1"),
            None
        );
    }
}
