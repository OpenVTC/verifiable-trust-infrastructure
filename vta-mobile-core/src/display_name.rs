//! DID → human-readable name, for the mobile agent's display surfaces.
//!
//! The phone shows DIDs where it has no choice: *who* is asking for a step-up,
//! *who* delivered a task-consent request, which VTA and mediator it is bound
//! to. A `did:webvh` in a caption is unreadable, and on an approval sheet
//! unreadable is not a cosmetic problem — it is the operator approving something
//! they cannot identify.
//!
//! This module is a thin FFI skin over [`vta_sdk::display_name`], which every
//! other operator surface in the workspace already renders through (the PNM/CNM
//! CLIs, the VTC CLI, the admin console). Two exports:
//!
//! - [`resolve_agent_name`] — the network lookup, [`agent_name::lookup`] verbatim.
//! - [`shorten_did`] — the pure abbreviation, [`display_name::shorten_did`]
//!   verbatim.
//!
//! # Why this is a skin and not an implementation
//!
//! An agent name is only safe to show because it was **round-tripped**: the
//! DID's document claimed the name *and* resolving that name led back to the
//! same DID. `alsoKnownAs` on its own is self-asserted, so a hostile DID can
//! claim `mybank.com/@treasury` and a display layer that prints the claim bare
//! has told the operator, in an authoritative voice, that they are looking at
//! their bank — on the one screen where they are about to approve something.
//!
//! That check is security-critical and already written, audited and tested in
//! `vta-sdk`. Re-deriving it in the engine (or worse, in Swift on the other side
//! of the FFI) would mean two implementations of a spoofing defence that must
//! agree forever. So the verdict crosses the boundary instead: `verified` is
//! [`vta_sdk`]'s conclusion, and the app's job is to not discard it.
//!
//! # Nothing publishes names yet
//!
//! No DID in this workspace writes an `alsoKnownAs` entry today, so
//! [`resolve_agent_name`] returns `None` for every DID it is asked about. That
//! is the intended state: the surfaces are wired so that minting names lights
//! them up without another mobile release.

use vta_sdk::display_name::{self, NameSource, agent_name};

/// A name to show for a DID, plus the provenance the UI must not throw away.
///
/// `verified == false` is a bare self-assertion. It is still returned — a DID
/// *attempting* to present as somebody else is something the operator should
/// see — but the app must qualify it (see `DisplayName.rendered` on the Swift
/// side, which appends `[unverified]`). Never render `name` alone.
#[derive(Debug, Clone, uniffi::Record)]
pub struct AgentName {
    /// The claimed name, e.g. `example.com/@treasury`.
    pub name: String,
    /// Whether the claim round-tripped back to this DID.
    pub verified: bool,
}

/// The agent name a DID's document claims, if any, with the round trip already
/// performed.
///
/// Returns `None` when the DID does not resolve, claims no agent name, or the
/// lookup fails. **Infallible on purpose**: this is a display helper, and an
/// unreachable name server must degrade to showing the DID, never fail the
/// operator's approval. That mirrors [`agent_name::lookup`], which swallows its
/// own errors for the same reason.
///
/// Costs one DID resolution plus up to
/// [`agent_name::MAX_CLAIMS_CHECKED`] outbound fetches, so the app resolves
/// lazily — per DID actually on screen — and caches the result rather than
/// calling this on every render.
#[uniffi::export(async_runtime = "tokio")]
pub async fn resolve_agent_name(did: String) -> Option<AgentName> {
    let client = crate::resolver::client().await.ok()?;
    let name = agent_name::lookup(client, &did).await?;
    Some(AgentName {
        name: name.name,
        // `lookup` only ever returns an `AgentName` source, but match rather
        // than assume: if the SDK ever routes another source through here,
        // defaulting to unverified fails safe.
        verified: matches!(name.source, NameSource::AgentName { verified: true }),
    })
}

/// Abbreviate a DID for a narrow phone caption, keeping the part that
/// identifies it.
///
/// Exported rather than ported so the phone, the CLIs and the admin console
/// cannot drift: an operator moves between all three looking at the same
/// community, and a DID abbreviated two ways is one they must re-identify on
/// every switch. See [`display_name::shorten_did`] for the rule and the shared
/// vector table that is its authority.
#[uniffi::export]
#[must_use]
pub fn shorten_did(did: String) -> String {
    display_name::shorten_did(&did)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The same vectors `vta_sdk`'s `shorten_did_matches_shared_vectors`
    /// asserts, re-asserted through the FFI signature the app actually calls —
    /// so a `String`-by-value wrapper that mangled its input could not pass.
    #[test]
    fn shorten_did_matches_the_shared_vectors() {
        for (input, expected) in [
            ("alice", "alice"),
            (
                "did:webvh:QmXkAbCdEfGhIjKlMnOp:webvh.storm.ws:glenn-vta",
                "did:webvh:QmXkAbCdEf…:webvh.storm.ws:glenn-vta",
            ),
            (
                "did:key:z6MkfrQjWzPQrTuVwXyZaBcDeFgHiJkLmNoPqRsTuVwXyZ4rT",
                "did:key:z6MkfrQjWz…XyZ4rT",
            ),
            ("did:webvh:Qm123:example.com", "did:webvh:Qm123:example.com"),
        ] {
            assert_eq!(shorten_did(input.to_string()), expected, "input: {input}");
        }
    }

    /// A DID claiming nothing must yield no name rather than a guess. There is
    /// deliberately no path from a DID's domain to a "likely" name.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_did_key_claims_no_agent_name() {
        // `did:key` resolves offline and its document has no `alsoKnownAs`, so
        // this exercises the whole export without touching the network.
        let did = "did:key:z6MkiToqovww7vYtxm1xNM15u9JzqzUFZ1k7s7MazYJUyAxv";
        assert!(
            resolve_agent_name(did.to_string()).await.is_none(),
            "a document claiming nothing must not produce a name"
        );
    }

    /// A DID that does not resolve must degrade to `None`, not propagate an
    /// error: an approval sheet has to render regardless.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_unresolvable_did_degrades_to_no_name() {
        assert!(resolve_agent_name("not-a-did".to_string()).await.is_none());
    }
}
