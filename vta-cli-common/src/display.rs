//! Terminal rendering for DIDs and their display names.
//!
//! The naming logic itself lives in [`vta_sdk::display_name`] — this module is
//! the thin CLI layer on top: ANSI colour, ratatui cells, and the decision
//! about whether a table gets a NAME column at all.
//!
//! # Usage
//!
//! A command builds a [`NameBook`] from the response it already has, then
//! renders through it:
//!
//! ```ignore
//! let mut book = NameBook::new();
//! book_from_acl(&mut book, &resp.entries);   // one pass, no extra requests
//! let show_names = book.names_any(resp.entries.iter().map(|e| e.did.as_str()));
//! ```
//!
//! The `book_from_*` helpers are the payoff: filling the book from an ACL
//! listing also names the `Created By` column, because a granting admin is
//! very often another entry's subject. No lookup, no round trip.

use std::sync::atomic::{AtomicBool, Ordering};

use ratatui::{
    style::{Color, Style},
    widgets::Cell,
};

pub use vta_sdk::display_name::{DisplayName, NameBook, NameSource, shorten_did};

use crate::render::{DIM, RESET, YELLOW};

/// Column heading for the name column. One constant so every table agrees.
pub const NAME_HEADER: &str = "Name";

/// Placeholder for a row with no name, used only when *some* other row in the
/// same table has one.
pub const UNNAMED: &str = "\u{2014}";

/// A DID rendered for a fixed-width table cell: shortened, dimmed.
#[must_use]
pub fn did_cell(did: &str) -> Cell<'static> {
    Cell::from(shorten_did(did)).style(Style::default().fg(Color::DarkGray))
}

/// A name cell for `did`.
///
/// Unverified agent names are yellow — see [`vta_sdk::display_name`] for why
/// they must stay visually distinct from a name the operator can rely on.
#[must_use]
pub fn name_cell(book: &NameBook, did: &str) -> Cell<'static> {
    match book.get(did) {
        Some(n) if n.is_trusted() => Cell::from(n.name.clone()),
        Some(_) => Cell::from(book.name_of(did).unwrap_or_default())
            .style(Style::default().fg(Color::Yellow)),
        None => Cell::from(UNNAMED).style(Style::default().fg(Color::DarkGray)),
    }
}

/// A cell for a DID that may carry a name — used where a column holds a
/// *reference* to some other principal (`Created By`, `Actor`, a sender)
/// rather than the row's own subject, so there is no room for a paired name
/// column. Falls back to the shortened DID.
#[must_use]
pub fn named_did_cell(book: &NameBook, did: &str) -> Cell<'static> {
    match book.name_of(did) {
        Some(name) => {
            let style = if book.get(did).is_some_and(DisplayName::is_trusted) {
                Style::default()
            } else {
                Style::default().fg(Color::Yellow)
            };
            Cell::from(name).style(style)
        }
        None => did_cell(did),
    }
}

/// Plain-text name-or-DID for a fixed-width column.
///
/// No ANSI: these go through `{:<60}`-style padding, which counts escape
/// bytes as width and would wreck the alignment.
#[must_use]
pub fn name_or_did(book: &NameBook, did: &str) -> String {
    book.name_of(did).unwrap_or_else(|| shorten_did(did))
}

/// One-line rendering for prose, confirmations and progress messages:
/// `mediator-prod (did:webvh:QmXk…9f2:example.com)`.
///
/// Colours the name when it is an unverified claim; leaves it plain
/// otherwise. Falls back to the shortened DID alone.
#[must_use]
pub fn inline(book: &NameBook, did: &str) -> String {
    match book.name_of(did) {
        Some(name) => {
            let short = shorten_did(did);
            if book.get(did).is_some_and(DisplayName::is_trusted) {
                format!("{name} {DIM}({short}){RESET}")
            } else {
                format!("{YELLOW}{name}{RESET} {DIM}({short}){RESET}")
            }
        }
        None => shorten_did(did),
    }
}

/// Key-value pairs for a `--full-display` block: a `Name` line *above* the
/// `DID` line, and the DID in full — abbreviating it is the one thing full
/// display exists to avoid.
///
/// Returns just the DID pair when the DID has no name, so unnamed entries
/// don't grow a `Name: —` line.
#[must_use]
pub fn full_display_pairs(book: &NameBook, did: &str) -> Vec<(&'static str, String)> {
    match book.name_of(did) {
        Some(name) => vec![("Name", name), ("DID", did.to_string())],
        None => vec![("DID", did.to_string())],
    }
}

// ── Agent-name resolution toggle ────────────────────────────────────
//
// Global `--resolve-agent-names`. Off by default: a verified lookup is a DID
// resolution plus an outbound HTTPS fetch per claimed name, per DID on
// screen, against hosts we do not control. On a fifty-row `acl list` that is
// fifty fan-outs, so the operator asks for it rather than paying for it by
// accident.

static RESOLVE_AGENT_NAMES: AtomicBool = AtomicBool::new(false);

/// Register the operator's `--resolve-agent-names` choice. Called once at
/// CLI startup.
pub fn set_resolve_agent_names(enabled: bool) {
    RESOLVE_AGENT_NAMES.store(enabled, Ordering::Relaxed);
}

/// Whether agent-name resolution was requested.
#[must_use]
pub fn resolve_agent_names() -> bool {
    RESOLVE_AGENT_NAMES.load(Ordering::Relaxed)
}

/// Add verified agent names to `book` for each DID in `dids`.
///
/// No-op unless `--resolve-agent-names` was passed. Each name is
/// round-tripped before being trusted (see
/// [`vta_sdk::display_name::agent_name`]); a claim that does not lead back to
/// its DID still lands in the book, but as `AgentName { verified: false }`,
/// which ranks below every local label and renders tagged.
///
/// Failures are swallowed per DID — an unreachable name server degrades that
/// row to its local name or bare DID rather than failing the command.
#[cfg(feature = "agent-names")]
pub async fn resolve_agent_names_into<'a>(
    book: &mut NameBook,
    dids: impl IntoIterator<Item = &'a str>,
) {
    if !resolve_agent_names() {
        return;
    }
    vta_sdk::display_name::agent_name::fill_book(book, dids).await;
}

/// Without the `agent-names` feature there is nothing to resolve.
#[cfg(not(feature = "agent-names"))]
pub async fn resolve_agent_names_into<'a>(
    _book: &mut NameBook,
    _dids: impl IntoIterator<Item = &'a str>,
) {
}

// ── Book builders ───────────────────────────────────────────────────
//
// Each takes a response the command already fetched. Adding one here is
// preferable to naming DIDs at the call site, so that every command that
// touches the same response type gets the same names.

/// Fill `book` from an ACL listing.
///
/// Names every entry's subject from its `label`. The `created_by` DIDs are
/// *not* inserted — they carry no label of their own — but they resolve
/// anyway whenever the granting admin also holds an ACL entry, which is the
/// common case.
pub fn book_from_acl(book: &mut NameBook, entries: &[vta_sdk::client::AclEntryResponse]) {
    for entry in entries {
        book.insert_opt(&entry.did, entry.label.as_deref(), NameSource::AclLabel);
    }
}

/// Fill `book` from a context listing: each context's `name` names its DID.
pub fn book_from_contexts(book: &mut NameBook, contexts: &[vta_sdk::client::ContextResponse]) {
    for ctx in contexts {
        if let Some(did) = &ctx.did {
            book.insert(did, DisplayName::new(&ctx.name, NameSource::ContextName));
        }
    }
}

/// Best-effort book from the two listings that name DIDs on a VTA: the ACL
/// (subject labels) and the contexts (each context's name, for its own DID).
///
/// For surfaces whose own response carries no name — hosted `did:webvh`
/// records, sealed-bundle banners, mediator tables. Both fetches are
/// swallowed on failure: naming is decoration, and a caller who may read
/// their own DIDs but not the ACL must still get their output.
pub async fn book_from_vta(client: &vta_sdk::client::VtaClient) -> NameBook {
    let mut book = NameBook::new();
    if let Ok(acl) = client.list_acl(None).await {
        book_from_acl(&mut book, &acl.entries);
    }
    if let Ok(ctxs) = client.list_contexts().await {
        book_from_contexts(&mut book, &ctxs.contexts);
    }
    book
}

/// Fill `book` from a webvh hosting-server listing.
pub fn book_from_webvh_servers(book: &mut NameBook, servers: &[vta_sdk::webvh::WebvhServerRecord]) {
    for s in servers {
        book.insert_opt(&s.did, s.label.as_deref(), NameSource::ServerLabel);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DID: &str = "did:webvh:QmScidAbCdEfGhIj:example.com:ops";

    #[test]
    fn full_display_keeps_the_did_whole() {
        let mut book = NameBook::new();
        book.insert(DID, DisplayName::new("ops", NameSource::AclLabel));
        let pairs = full_display_pairs(&book, DID);
        assert_eq!(pairs[0], ("Name", "ops".to_string()));
        assert_eq!(
            pairs[1],
            ("DID", DID.to_string()),
            "full display must never abbreviate — that is what it is for"
        );
    }

    #[test]
    fn unnamed_entries_get_no_name_line() {
        let book = NameBook::new();
        let pairs = full_display_pairs(&book, DID);
        assert_eq!(pairs.len(), 1);
        assert_eq!(pairs[0].0, "DID");
    }

    #[test]
    fn inline_marks_an_unverified_claim() {
        let mut book = NameBook::new();
        book.insert(
            DID,
            DisplayName::new(
                "mybank.com/@treasury",
                NameSource::AgentName { verified: false },
            ),
        );
        let out = inline(&book, DID);
        assert!(out.contains("unverified"));
        assert!(out.contains(YELLOW), "an unchecked claim must stand out");
    }

    #[test]
    fn inline_falls_back_to_the_shortened_did() {
        let book = NameBook::new();
        assert_eq!(inline(&book, DID), shorten_did(DID));
    }
}
