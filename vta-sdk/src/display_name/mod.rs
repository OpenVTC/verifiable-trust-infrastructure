//! DID → human-readable display name.
//!
//! Operators read DIDs constantly and can't. Every operator-facing surface in
//! the workspace — the PNM/CNM CLIs, the VTC operator CLI, the VTC admin UI —
//! prints raw DIDs, each truncating them its own way. This module is the one
//! seam they all render through.
//!
//! # The model: a book the caller fills, not a resolver that fetches
//!
//! [`NameBook`] is a plain `DID → name` map. Commands populate it from data
//! they *already hold* and then query it while rendering. That shape is what
//! keeps naming free: `acl list` already receives every entry with its
//! `label`, so filling the book from that one response also names the
//! `created_by` column — a DID that has no label of its own but is very often
//! another entry's subject. No extra request, no N+1 lookup.
//!
//! Nothing here performs I/O. The one source that needs the network — a
//! verified agent name — lives in [`agent_name`] behind the `agent-names`
//! feature and hands its result back as a [`DisplayName`] like any other.
//!
//! # Where names come from today
//!
//! No DID document in this workspace currently publishes an `alsoKnownAs`
//! entry, so there are no agent names to show yet. The names that exist are
//! local: `AclEntry.label`, `ContextRecord.name`, `WebvhServerRecord.label`,
//! the PNM/CNM per-VTA config `name`. [`NameSource`] keeps them distinguished
//! rather than flattening them to a string, because they are not equally
//! trustworthy — see below.
//!
//! # Trust
//!
//! A name is a claim, and the claims differ in who is making them.
//!
//! A local label was typed by the operator into their own store. A *verified*
//! agent name round-tripped: the DID's document claimed it and resolving the
//! name led back to that same DID.
//!
//! An **unverified** agent name is neither. `alsoKnownAs` is self-asserted —
//! the two-sided binding in the agent-name specification protects the
//! name→DID direction, not the reverse — so a hostile DID can claim
//! `alsoKnownAs: ["mybank.com/@treasury"]` and anything that renders that
//! bare has just told the operator a lie in an authoritative voice. Such
//! names sort *below* every local source in [`NameSource::rank`] and report
//! [`DisplayName::is_trusted`] `== false`, and [`NameBook::render_inline`]
//! tags them. Surfaces must not strip that tag.

use std::collections::HashMap;

#[cfg(feature = "agent-names")]
pub mod agent_name;

/// Where a display name came from.
///
/// Kept as a distinct type rather than folding everything into a `String`
/// because the sources are not equally trustworthy, and the difference has to
/// survive all the way to the pixel — see the module-level note on trust.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NameSource {
    /// An `alsoKnownAs` entry on the DID's own document.
    ///
    /// `verified` means the name was resolved forward and led back to this
    /// same DID. `verified == false` is a bare self-assertion and is the
    /// least trustworthy source there is.
    AgentName { verified: bool },
    /// `AclEntry.label` / `VtcAclEntry.label` — operator-typed, our store.
    AclLabel,
    /// A `DeviceBinding.display_name` from an agent device registration.
    DeviceName,
    /// The `name` of a locally-configured VTA / community (`~/.config/{pnm,cnm}`).
    LocalAlias,
    /// `WebvhServerRecord.label` — names a DID-hosting server.
    ServerLabel,
    /// `ContextRecord.name` — names a context, used for the context's own DID.
    ContextName,
}

impl NameSource {
    /// Precedence when two sources name the same DID. Higher wins.
    ///
    /// A verified agent name outranks everything: it is globally meaningful
    /// and cryptographically bound to the DID, where a local label is one
    /// operator's private note. An *unverified* agent name ranks below every
    /// local source for the reason in the module docs — the operator's own
    /// data must never be displaced by a stranger's unchecked claim.
    #[must_use]
    pub fn rank(self) -> u8 {
        match self {
            Self::AgentName { verified: true } => 100,
            Self::AclLabel => 60,
            Self::LocalAlias => 50,
            Self::DeviceName => 45,
            Self::ServerLabel => 40,
            Self::ContextName => 30,
            Self::AgentName { verified: false } => 10,
        }
    }

    /// Stable machine-readable tag, used for the `nameSource` field in
    /// `--json` output. Kebab-case so it reads well through `jq`.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AgentName { verified: true } => "agent-name",
            Self::AgentName { verified: false } => "agent-name-unverified",
            Self::AclLabel => "acl-label",
            Self::DeviceName => "device-name",
            Self::LocalAlias => "local-alias",
            Self::ServerLabel => "server-label",
            Self::ContextName => "context-name",
        }
    }

    /// Whether a name from this source may be shown without qualification.
    ///
    /// False only for an unverified agent name.
    #[must_use]
    pub fn is_trusted(self) -> bool {
        !matches!(self, Self::AgentName { verified: false })
    }
}

impl serde::Serialize for NameSource {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(self.as_str())
    }
}

/// A name for a DID, and the provenance of that name.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DisplayName {
    pub name: String,
    pub source: NameSource,
}

impl DisplayName {
    pub fn new(name: impl Into<String>, source: NameSource) -> Self {
        Self {
            name: name.into(),
            source,
        }
    }

    /// See [`NameSource::is_trusted`].
    #[must_use]
    pub fn is_trusted(&self) -> bool {
        self.source.is_trusted()
    }
}

/// Marker appended to a name that has not been verified. Surfaces may
/// restyle it (the CLI colours it yellow) but must not drop it.
pub const UNVERIFIED_SUFFIX: &str = " [unverified]";

/// A `DID → name` map, populated by the caller from data it already holds.
///
/// Insertion is idempotent and order-independent: a lower-ranked source never
/// displaces a higher-ranked one, so a command can fill the book from several
/// responses in whatever order they arrive without the result depending on
/// that order.
#[derive(Debug, Clone, Default)]
pub struct NameBook {
    entries: HashMap<String, DisplayName>,
}

impl NameBook {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a name for `did`, keeping whichever source ranks higher.
    ///
    /// Empty and whitespace-only names are dropped rather than stored: an
    /// unset label deserialises as `Some("")` often enough that storing it
    /// would put a blank string where the DID should be.
    pub fn insert(&mut self, did: impl Into<String>, name: DisplayName) {
        if name.name.trim().is_empty() {
            return;
        }
        let did = did.into();
        match self.entries.get(&did) {
            Some(existing) if existing.source.rank() >= name.source.rank() => {}
            _ => {
                self.entries.insert(did, name);
            }
        }
    }

    /// Convenience for the common case: an `Option<String>` label straight
    /// off a response struct.
    pub fn insert_opt(&mut self, did: impl Into<String>, name: Option<&str>, source: NameSource) {
        if let Some(n) = name {
            self.insert(did, DisplayName::new(n, source));
        }
    }

    #[must_use]
    pub fn get(&self, did: &str) -> Option<&DisplayName> {
        self.entries.get(did)
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether any DID in `dids` has a name.
    ///
    /// Table renderers call this to decide whether to emit a NAME column at
    /// all — on a VTA where nothing has been labelled, a column of dashes is
    /// worse than no column.
    pub fn names_any<'a>(&self, dids: impl IntoIterator<Item = &'a str>) -> bool {
        dids.into_iter().any(|d| self.entries.contains_key(d))
    }

    /// The name for `did` as a bare string, tagged when unverified.
    ///
    /// Returns `None` when the DID has no name, so callers can decide between
    /// a placeholder and the shortened DID.
    #[must_use]
    pub fn name_of(&self, did: &str) -> Option<String> {
        self.entries.get(did).map(|n| {
            if n.is_trusted() {
                n.name.clone()
            } else {
                format!("{}{UNVERIFIED_SUFFIX}", n.name)
            }
        })
    }

    /// One-line rendering for prose and confirmations:
    /// `mediator-prod (did:webvh:QmXk…9f2:example.com)`.
    ///
    /// Falls back to the shortened DID alone when there is no name. The DID is
    /// always present — a name the operator cannot cross-check against an
    /// identifier is a name they cannot audit.
    #[must_use]
    pub fn render_inline(&self, did: &str) -> String {
        match self.name_of(did) {
            Some(name) => format!("{name} ({})", shorten_did(did)),
            None => shorten_did(did),
        }
    }
}

/// Shorten a DID for a fixed-width cell while keeping the part that
/// identifies it.
///
/// A `did:webvh` / `did:web` carries its meaning in the *tail* — the domain
/// and path, e.g. `…:webvh.storm.ws:glenn-vta` — and its noise in the middle:
/// the SCID, a content hash. So the SCID is abbreviated and everything after
/// it kept verbatim. That is the opposite of a CSS-style trailing ellipsis,
/// which clips off precisely the informative half.
///
/// Other methods (`did:key` and friends) have no human tail, so the opaque id
/// is middle-truncated instead, keeping a head and a tail so an operator can
/// still tell two of them apart at a glance.
///
/// Inputs that aren't DIDs, and DIDs already short enough, are returned
/// unchanged. This is a port of `shortenDid` in
/// `vtc-service/admin-ui/src/lib/format.ts`; the two are pinned to identical
/// output by a shared vector table (see the tests below and `format.test.ts`).
#[must_use]
pub fn shorten_did(did: &str) -> String {
    shorten_did_keep(did, DEFAULT_KEEP)
}

/// Number of leading characters kept from an opaque DID segment.
pub const DEFAULT_KEEP: usize = 10;

/// Trailing characters kept when middle-truncating a non-`webvh` DID.
const TAIL: usize = 6;

#[must_use]
pub fn shorten_did_keep(did: &str, keep: usize) -> String {
    if !did.starts_with("did:") {
        return did.to_string();
    }
    let parts: Vec<&str> = did.split(':').collect();
    let method = parts.get(1).copied().unwrap_or_default();

    if (method == "webvh" || method == "web") && parts.len() > 3 {
        let scid = parts[2];
        if char_len(scid) <= keep + 1 {
            return did.to_string();
        }
        let mut out = parts.clone();
        let abbreviated = format!("{}…", take_chars(scid, keep));
        out[2] = &abbreviated;
        return out.join(":");
    }

    // `did:<method>:<id>`, where `<id>` may itself contain colons.
    let id = parts[2..].join(":");
    if char_len(&id) <= keep + TAIL + 1 {
        return did.to_string();
    }
    format!(
        "{}:{}:{}…{}",
        parts[0],
        method,
        take_chars(&id, keep),
        take_last_chars(&id, TAIL)
    )
}

fn char_len(s: &str) -> usize {
    s.chars().count()
}

fn take_chars(s: &str, n: usize) -> String {
    s.chars().take(n).collect()
}

fn take_last_chars(s: &str, n: usize) -> String {
    let len = char_len(s);
    s.chars().skip(len.saturating_sub(n)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── shorten_did ─────────────────────────────────────────────────
    //
    // This table is duplicated verbatim in
    // `vtc-service/admin-ui/src/lib/format.test.ts`. The Rust CLI and the
    // React admin UI show the same operator the same DIDs; if they abbreviate
    // differently, the operator cannot tell whether two screens are showing
    // one identity or two. Change one side and you must change the other.
    const VECTORS: &[(&str, &str)] = &[
        // Not a DID — untouched.
        ("alice", "alice"),
        ("https://example.com/@alice", "https://example.com/@alice"),
        // webvh: SCID abbreviated, domain + path tail kept in full.
        (
            "did:webvh:QmXkAbCdEfGhIjKlMnOp:webvh.storm.ws:glenn-vta",
            "did:webvh:QmXkAbCdEf…:webvh.storm.ws:glenn-vta",
        ),
        // web: same rule.
        (
            "did:web:QmXkAbCdEfGhIjKlMnOp:example.com",
            "did:web:QmXkAbCdEf…:example.com",
        ),
        // webvh with a short SCID — nothing to gain, left alone.
        ("did:webvh:Qm123:example.com", "did:webvh:Qm123:example.com"),
        // did:key — no human tail, so middle-truncate head + tail.
        (
            "did:key:z6MkfrQjWzPQrTuVwXyZaBcDeFgHiJkLmNoPqRsTuVwXyZ4rT",
            "did:key:z6MkfrQjWz…XyZ4rT",
        ),
        // Short did:key — under the threshold, untouched.
        ("did:key:z6MkfrQjWz", "did:key:z6MkfrQjWz"),
        // A webvh DID with only 3 segments has no domain tail to protect, so
        // it falls through to the generic middle-truncating arm.
        (
            "did:webvh:QmXkAbCdEfGhIjKlMnOpQrSt",
            "did:webvh:QmXkAbCdEf…OpQrSt",
        ),
    ];

    #[test]
    fn shorten_did_matches_shared_vectors() {
        for (input, expected) in VECTORS {
            assert_eq!(&shorten_did(input), expected, "input: {input}");
        }
    }

    #[test]
    fn shorten_did_is_char_safe() {
        // Non-ASCII in the opaque segment must not panic on a byte boundary.
        let did = "did:key:zÄÖÜäöüßÅÆØåæøΩμλ0123456789";
        let out = shorten_did(did);
        assert!(out.starts_with("did:key:"));
        assert!(out.contains('…'));
    }

    // ── NameSource precedence ───────────────────────────────────────

    #[test]
    fn verified_agent_name_outranks_local_label() {
        assert!(
            NameSource::AgentName { verified: true }.rank() > NameSource::AclLabel.rank(),
            "a cryptographically bound global name beats one operator's private note"
        );
    }

    #[test]
    fn unverified_agent_name_ranks_below_every_local_source() {
        let unverified = NameSource::AgentName { verified: false }.rank();
        for local in [
            NameSource::AclLabel,
            NameSource::DeviceName,
            NameSource::LocalAlias,
            NameSource::ServerLabel,
            NameSource::ContextName,
        ] {
            assert!(
                local.rank() > unverified,
                "{local:?} must not be displaced by an unchecked claim"
            );
        }
    }

    #[test]
    fn only_unverified_agent_names_are_untrusted() {
        assert!(!NameSource::AgentName { verified: false }.is_trusted());
        assert!(NameSource::AgentName { verified: true }.is_trusted());
        assert!(NameSource::AclLabel.is_trusted());
    }

    // ── NameBook ────────────────────────────────────────────────────

    const DID_A: &str = "did:key:z6MkfrQjWzPQrTuVwXyZaBcDeFgHiJkLmNoPqRsTuVwXyZ4rT";

    #[test]
    fn insert_is_order_independent() {
        let strong = DisplayName::new(
            "agent.example/@ops",
            NameSource::AgentName { verified: true },
        );
        let weak = DisplayName::new("my-note", NameSource::AclLabel);

        let mut a = NameBook::new();
        a.insert(DID_A, weak.clone());
        a.insert(DID_A, strong.clone());

        let mut b = NameBook::new();
        b.insert(DID_A, strong.clone());
        b.insert(DID_A, weak);

        assert_eq!(a.get(DID_A), b.get(DID_A));
        assert_eq!(a.get(DID_A), Some(&strong));
    }

    #[test]
    fn unverified_claim_never_displaces_an_operator_label() {
        let mut book = NameBook::new();
        book.insert(DID_A, DisplayName::new("payroll-bot", NameSource::AclLabel));
        book.insert(
            DID_A,
            DisplayName::new(
                "mybank.com/@treasury",
                NameSource::AgentName { verified: false },
            ),
        );
        assert_eq!(
            book.get(DID_A).map(|n| n.name.as_str()),
            Some("payroll-bot")
        );
    }

    #[test]
    fn unverified_names_are_tagged_when_rendered() {
        let mut book = NameBook::new();
        book.insert(
            DID_A,
            DisplayName::new(
                "mybank.com/@treasury",
                NameSource::AgentName { verified: false },
            ),
        );
        let rendered = book.name_of(DID_A).unwrap();
        assert!(
            rendered.contains("unverified"),
            "a self-asserted name must never render bare: {rendered}"
        );
        assert!(book.render_inline(DID_A).contains("unverified"));
    }

    #[test]
    fn blank_labels_are_not_stored() {
        let mut book = NameBook::new();
        book.insert(DID_A, DisplayName::new("", NameSource::AclLabel));
        book.insert(DID_A, DisplayName::new("   ", NameSource::AclLabel));
        assert!(book.is_empty(), "a blank label must not shadow the DID");
    }

    #[test]
    fn insert_opt_skips_none() {
        let mut book = NameBook::new();
        book.insert_opt(DID_A, None, NameSource::AclLabel);
        assert!(book.is_empty());
        book.insert_opt(DID_A, Some("ops"), NameSource::AclLabel);
        assert_eq!(book.len(), 1);
    }

    #[test]
    fn render_inline_always_shows_the_did() {
        let mut book = NameBook::new();
        book.insert(DID_A, DisplayName::new("ops", NameSource::AclLabel));
        let rendered = book.render_inline(DID_A);
        assert!(rendered.starts_with("ops ("));
        assert!(
            rendered.contains("did:key:"),
            "the operator must be able to audit the name against an identifier"
        );
    }

    #[test]
    fn render_inline_falls_back_to_the_shortened_did() {
        let book = NameBook::new();
        assert_eq!(book.render_inline(DID_A), shorten_did(DID_A));
    }

    #[test]
    fn names_any_drives_the_optional_name_column() {
        let mut book = NameBook::new();
        assert!(!book.names_any([DID_A, "did:key:zOther"]));
        book.insert(DID_A, DisplayName::new("ops", NameSource::AclLabel));
        assert!(book.names_any([DID_A, "did:key:zOther"]));
        assert!(!book.names_any(["did:key:zOther"]));
    }

    #[test]
    fn name_source_json_tags_are_stable() {
        // These strings appear in `--json` output; scripts key off them.
        assert_eq!(
            serde_json::to_string(&NameSource::AgentName { verified: false }).unwrap(),
            "\"agent-name-unverified\""
        );
        assert_eq!(
            serde_json::to_string(&NameSource::AclLabel).unwrap(),
            "\"acl-label\""
        );
    }
}
