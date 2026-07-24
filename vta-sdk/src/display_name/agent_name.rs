//! Verified agent names, the network-backed [`super::NameSource`].
//!
//! An agent name is a human-memorable URL — `example.com/@alice` — that
//! resolves to a DID. This module implements the **reverse** direction, which
//! is the one a display layer needs: given a DID, what name should we show?
//!
//! # Why a round trip is mandatory
//!
//! The obvious implementation is to resolve the DID, read the `alsoKnownAs`
//! entries its document claims, and print one. That is wrong, and the way it
//! is wrong is not subtle.
//!
//! Agent names are secured by a *two-sided* binding. Resolving a name to a DID
//! requires both that the name's domain redirects to that DID **and** that the
//! DID's document claims the name back. The first half stops a domain owner
//! pointing a name at somebody else's identity; the second half is what the
//! resolver checks. But the second half **on its own is a bare self-assertion**
//! — anybody can put anything in their own `alsoKnownAs`. Nothing stops a
//! hostile DID from claiming `mybank.com/@treasury`, and a display layer that
//! prints that claim has told the operator, in an authoritative voice, that
//! they are looking at the bank. In this workspace those operators are
//! approving ACL grants and admitting community members.
//!
//! So every claim is round-tripped: resolve the claimed name forward and
//! require it to lead back to *this* DID. Only then is the name shown
//! unqualified. A claim that fails still surfaces — as
//! [`NameSource::AgentName { verified: false }`], which ranks below every
//! local source and renders with an `[unverified]` tag — because a DID
//! *attempting* to present as `mybank.com/@treasury` is something an operator
//! should see, just not something they should believe.
//!
//! There is deliberately no path that guesses a name from a DID's domain. The
//! `agent-names` crate omits such a helper on purpose: the name→DID link is a
//! web redirect and is not derivable from DID structure, so a constructed
//! "likely name" would be an unverified guess wearing an authoritative API.
//!
//! # Nothing publishes names yet
//!
//! No DID template, DID document, or webvh record in this workspace emits an
//! `alsoKnownAs` entry, so [`lookup`] returns `None` for every DID here today.
//! That is expected: this is the consumer half, built so that minting names
//! lights up every operator surface without a single display site changing.

use affinidi_did_common::Document;
use affinidi_did_resolver_cache_sdk::DIDCacheClient;
use agent_names::extract_agent_names;

use super::{DisplayName, NameSource};

/// Most claimed names round-tripped for one DID.
///
/// A document may claim arbitrarily many names and each check is an outbound
/// HTTPS fetch to a host the *document's author* chose — the same
/// amplification primitive the agent-name specification bounds with a
/// concurrency ceiling on the server side. Cap it here for the same reason.
/// Documents in practice claim one.
pub const MAX_CLAIMS_CHECKED: usize = 4;

/// The names `doc` claims, in document order, capped at
/// [`MAX_CLAIMS_CHECKED`].
///
/// Entries that are not well-formed agent names (a `did:` URI, say) are
/// skipped rather than treated as errors — `alsoKnownAs` legitimately holds
/// other identifier types.
#[must_use]
pub fn claimed_names(doc: &Document) -> Vec<String> {
    extract_agent_names(doc)
        .into_iter()
        .take(MAX_CLAIMS_CHECKED)
        .map(|n| n.as_str().to_string())
        .collect()
}

/// Choose what to display, given each claimed name and the DID it actually
/// resolved to.
///
/// `outcomes` is `(claimed_name, resolved_did)` in document order, where
/// `None` means the name did not resolve at all. Split out from [`lookup`] so
/// the security-relevant decision is testable without a network.
///
/// The first claim that resolves back to `did` wins. If none does, the first
/// claim is reported unverified so the operator can see what the DID is
/// asserting.
#[must_use]
pub fn select<'a>(
    did: &str,
    outcomes: impl IntoIterator<Item = (&'a str, Option<&'a str>)>,
) -> Option<DisplayName> {
    let mut first_claim: Option<&str> = None;

    for (name, resolved) in outcomes {
        if resolved == Some(did) {
            return Some(DisplayName::new(
                name,
                NameSource::AgentName { verified: true },
            ));
        }
        first_claim.get_or_insert(name);
    }

    first_claim.map(|name| DisplayName::new(name, NameSource::AgentName { verified: false }))
}

/// Resolve a display name for `did` from the agent names its document claims.
///
/// Returns `None` when the DID does not resolve or claims no agent name.
/// Errors are swallowed rather than propagated: this is a *display* helper, and
/// an unreachable name server must degrade to showing the DID, never fail the
/// operator's command.
///
/// Costs one DID resolution plus up to [`MAX_CLAIMS_CHECKED`] outbound
/// fetches, so callers gate it behind an explicit opt-in.
pub async fn lookup(client: &DIDCacheClient, did: &str) -> Option<DisplayName> {
    let resolved = client.resolve(did).await.ok()?;
    let claims = claimed_names(&resolved.doc);
    if claims.is_empty() {
        return None;
    }

    // Resolve each claim forward. `resolve_any` performs the specification's
    // mandatory `alsoKnownAs` check internally — but against whatever document
    // *it* landed on, which is why the DID it returns still has to be compared
    // with ours. A name that legitimately belongs to somebody else will
    // resolve perfectly well; it just won't resolve to us.
    let mut outcomes: Vec<(String, Option<String>)> = Vec::with_capacity(claims.len());
    for name in claims {
        let landed = client.resolve_any(&name).await.ok().map(|r| r.did);
        let matched = landed.as_deref() == Some(did);
        outcomes.push((name, landed));
        if matched {
            break; // Verified — no reason to fetch the rest.
        }
    }

    select(
        did,
        outcomes.iter().map(|(n, d)| (n.as_str(), d.as_deref())),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const OURS: &str = "did:webvh:QmScidAbCdEfGh:example.com";
    const THEIRS: &str = "did:webvh:QmOtherXyZ123:evil.example";

    #[test]
    fn a_round_tripping_claim_is_verified() {
        let name = select(OURS, [("https://example.com/@alice", Some(OURS))]).unwrap();
        assert_eq!(name.source, NameSource::AgentName { verified: true });
        assert_eq!(name.name, "https://example.com/@alice");
        assert!(name.is_trusted());
    }

    #[test]
    fn a_claim_that_lands_on_another_did_is_not_verified() {
        // The spoof this whole module exists for: our DID claims the bank's
        // name, and the bank's name legitimately resolves to the bank.
        let name = select(THEIRS, [("https://mybank.com/@treasury", Some(OURS))]).unwrap();
        assert_eq!(name.source, NameSource::AgentName { verified: false });
        assert!(
            !name.is_trusted(),
            "a name belonging to somebody else must never be shown as this DID's"
        );
    }

    #[test]
    fn a_claim_that_does_not_resolve_is_not_verified() {
        let name = select(OURS, [("https://gone.example/@alice", None)]).unwrap();
        assert_eq!(name.source, NameSource::AgentName { verified: false });
    }

    #[test]
    fn the_verified_claim_wins_over_earlier_failures() {
        let name = select(
            OURS,
            [
                ("https://gone.example/@alice", None),
                ("https://mybank.com/@treasury", Some(THEIRS)),
                ("https://example.com/@real", Some(OURS)),
            ],
        )
        .unwrap();
        assert_eq!(name.source, NameSource::AgentName { verified: true });
        assert_eq!(name.name, "https://example.com/@real");
    }

    #[test]
    fn with_no_verified_claim_the_first_is_reported_unverified() {
        // Surfacing the attempt is the point — an operator seeing
        // `mybank.com/@treasury [unverified]` learns something a bare DID
        // would not have told them.
        let name = select(
            OURS,
            [
                ("https://mybank.com/@treasury", Some(THEIRS)),
                ("https://other.example/@x", None),
            ],
        )
        .unwrap();
        assert_eq!(name.source, NameSource::AgentName { verified: false });
        assert_eq!(name.name, "https://mybank.com/@treasury");
    }

    #[test]
    fn no_claims_means_no_name() {
        assert!(select(OURS, []).is_none());
    }

    #[test]
    fn a_document_claiming_nothing_yields_no_names() {
        // The state of every DID in this workspace today.
        let doc = Document::default();
        assert!(claimed_names(&doc).is_empty());
    }
}
