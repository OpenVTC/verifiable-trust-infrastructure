//! How long a caller must wait for a Trust Task, given what the VTA may do with
//! it on the way.
//!
//! # The failure this exists to prevent
//!
//! A client's budget and the VTA's own were two unrelated literals in two
//! crates, and they inverted. `create_did_webvh` allowed 60s; the VTA, relaying
//! the mint onward to a DID hosting server, spends up to
//! [`TSP_REPLY_TIMEOUT_SECS`] on the first send and — under the §7.2.2
//! self-repair path in `recover_send_tsp` — the same again on the resend after
//! re-forming the relationship. Observed live: 60.27s, 60.58s. The client gave
//! up a few hundred milliseconds before the VTA's real answer arrived, on all
//! four attempts, so the operator saw "timed out waiting for the TSP reply"
//! instead of the diagnosis, **every time and by construction**.
//!
//! Neither number was wrong on its own. What was missing was anything relating
//! them, so nothing could notice they had crossed.
//!
//! # The rule
//!
//! > A caller's budget must strictly exceed the worst case of whoever it is
//! > waiting on.
//!
//! [`min_relay_budget_secs`] is that bound, derived from the VTA's own constant
//! rather than guessed alongside it, and `budget_floor_holds_for_every_task`
//! pins every call site against it. The arithmetic is a test, not a coincidence.
//!
//! # Why the constant lives here
//!
//! It is a fact about a conversation, so it cannot belong to one end of it.
//! `vta-service` reads [`TSP_REPLY_TIMEOUT_SECS`] from here rather than keeping
//! its own copy, exactly as it already reads
//! [`retry_safety`](crate::retry_safety) — the precedent this module follows,
//! and for the same reason: a shared fact with two homes has none.
//!
//! Like [`retry_safety`](crate::retry_safety) this module is always-on and
//! dependency-free, so the service can consult it without pulling in the client.

use crate::trust_tasks;

/// How long the VTA waits for a peer's reply on one TSP hop.
///
/// The authoritative copy. `vta-service`'s `operations::outbound` reads this;
/// it must not define its own, or the two ends can drift apart silently — which
/// is the whole defect this module was written for.
pub const TSP_REPLY_TIMEOUT_SECS: u64 = 30;

/// Reply-awaiting hops a relayed task may spend at the VTA: the first send,
/// then the §7.2.2 self-repair resend after the relationship is re-formed.
///
/// Two, not one, because the resend is where a task whose URI is blind-retry-
/// safe spends a second full window — and that is not decided by the task the
/// *client* named. The VTA relays under a different URI, so a client cannot
/// reason about it from its own request. Hence the floor assumes the resend
/// happens.
const RELAY_HOPS: u64 = 2;

/// Slack between those hops for the relationship re-form itself.
///
/// Measured sub-second in the field (the whole overshoot that broke
/// `create_did_webvh` was 0.58s), so this is deliberately generous: it is
/// bounding a network round trip whose cost we do not otherwise model, and
/// being too small here re-creates the defect while being too large costs only
/// a slower report of a peer that is genuinely gone.
const REFORM_MARGIN_SECS: u64 = 10;

/// Headroom between the VTA's worst case and the client's budget, covering the
/// legs this module does not model: mediator queueing either way, and the
/// client's own send before its clock starts.
const CLIENT_MARGIN_SECS: u64 = 10;

// The margins are the only thing standing between a derived floor and the
// hand-picked literals it replaced, so a zeroed one is worth refusing to
// compile. Stated here rather than as a test because it is knowable without
// running anything — and a test asserting on constants is one clippy is right
// to distrust.
const _: () = assert!(
    RELAY_HOPS >= 2,
    "the §7.2.2 self-repair resend is not optional — the floor must cover it"
);
const _: () = assert!(
    REFORM_MARGIN_SECS > 0 && CLIENT_MARGIN_SECS > 0,
    "a zeroed margin puts the floor back level with the VTA's worst case"
);

/// The longest the VTA can take on a task it relays onward before answering.
#[must_use]
pub const fn relay_worst_case_secs() -> u64 {
    RELAY_HOPS * TSP_REPLY_TIMEOUT_SECS + REFORM_MARGIN_SECS
}

/// The smallest client budget that can outlast [`relay_worst_case_secs`] — i.e.
/// the smallest one on which the VTA's real error is reachable at all.
///
/// A budget below this does not make a relayed call fail faster. It makes it
/// fail *uninformatively*, which is strictly worse: the work still happens, the
/// answer still comes, and the caller is no longer listening.
#[must_use]
pub const fn min_relay_budget_secs() -> u64 {
    relay_worst_case_secs() + CLIENT_MARGIN_SECS
}

/// Tasks the VTA may answer by calling a third party and waiting for a reply.
///
/// These are the tasks whose budget must clear [`min_relay_budget_secs`]: the
/// VTA's own wait is *inside* the caller's, so a caller that allows less than
/// the VTA can spend is guaranteed to stop listening before the answer comes.
/// Everything absent is served from the VTA's own storage and needs only the
/// caller's own patience.
///
/// # Conservative by construction
///
/// Several of these relay only for *some* payloads — `services/enable` only for
/// `service: "didcomm"` (the mediator handshake), `vault/proxy-login` only for
/// a `password` entry, `provision/integration` only when the template names a
/// `WEBVH_SERVER`, and the webvh DID verbs only for server-managed (non-
/// serverless) DIDs. A URI cannot distinguish those, so a task that relays
/// under *any* payload is listed. Over-listing costs a slower report of a peer
/// that is genuinely gone; under-listing costs the silent, undiagnosable
/// timeout this module exists to prevent. Same asymmetry, and same answer, as
/// [`retry_safety`](crate::retry_safety)'s.
///
/// # Keeping it true
///
/// This is a fact about `vta-service`'s handlers, not about the URI, so nothing
/// here can derive it — `relay_list_names_only_real_tasks` can only catch a URI
/// that no longer exists. **If you give a handler an onward call that waits for
/// a reply, add its URI here.** The transport it relays over does not matter:
/// TSP is the worst case this floor is sized for, and DIDComm and REST both sit
/// inside it.
#[allow(deprecated)] // names the deprecated 0.1 proxy-login URI on purpose — still served
pub const RELAYS_ONWARD: &[&str] = &[
    // ── did:webvh, server-managed ───────────────────────────────────────
    // Each of these publishes to, or reads from, the DID hosting server that
    // holds the log. `create` is the one that failed in the field; the rest
    // share its path and were latent behind the same arithmetic.
    trust_tasks::TASK_WEBVH_DIDS_CREATE_1_0,
    trust_tasks::TASK_WEBVH_DIDS_DELETE_1_0,
    trust_tasks::TASK_WEBVH_DIDS_UPDATE_1_0,
    trust_tasks::TASK_WEBVH_DIDS_ROTATE_KEYS_1_0,
    trust_tasks::TASK_WEBVH_DIDS_REGISTER_WITH_SERVER_1_0,
    // Agent names live on the hosting server, so every verb is a round trip —
    // including the two reads.
    trust_tasks::TASK_WEBVH_AGENT_NAME_LIST_1_0,
    trust_tasks::TASK_WEBVH_AGENT_NAME_CHECK_1_0,
    trust_tasks::TASK_WEBVH_AGENT_NAME_SET_1_0,
    trust_tasks::TASK_WEBVH_AGENT_NAME_REMOVE_1_0,
    trust_tasks::TASK_WEBVH_AGENT_NAME_DISABLE_1_0,
    trust_tasks::TASK_WEBVH_AGENT_NAME_ENABLE_1_0,
    // Server-wide queries and repairs, which interrogate the server itself.
    trust_tasks::TASK_WEBVH_SERVERS_DOMAINS_0_1,
    trust_tasks::TASK_WEBVH_SERVERS_RECONCILE_0_1,
    trust_tasks::TASK_WEBVH_SERVERS_RETIRE_ORPHAN_0_1,
    // ── Rooms ───────────────────────────────────────────────────────────
    // Anchoring and registration reach the room's host; the three reads fetch
    // epoch state from it.
    trust_tasks::TASK_ROOMS_OWNER_ANCHOR_0_1,
    trust_tasks::TASK_ROOMS_OWNER_REGISTER_0_1,
    trust_tasks::TASK_ROOMS_KEYS_BACKFILL_0_1,
    trust_tasks::TASK_ROOMS_KEYS_READ_0_1,
    trust_tasks::TASK_ROOMS_KEYS_BROWSE_0_1,
    // ── Vault ───────────────────────────────────────────────────────────
    // A `password` entry logs in to the third-party site and waits on it. The
    // `did-self-issued` driver mints locally, but the URI cannot say which.
    trust_tasks::TASK_VAULT_PROXY_LOGIN_0_1,
    trust_tasks::TASK_VAULT_PROXY_LOGIN_0_2,
    // ── Services ────────────────────────────────────────────────────────
    // Enabling or updating `didcomm` runs the mediator handshake and awaits the
    // pong. TSP has no handshake and REST none either, but again: not from the
    // URI.
    trust_tasks::TASK_SERVICES_ENABLE_1_0,
    trust_tasks::TASK_SERVICES_UPDATE_1_0,
    // ── Provisioning ────────────────────────────────────────────────────
    // A template naming a `WEBVH_SERVER` mints through the very same
    // server-managed path as `dids/create`.
    trust_tasks::TASK_PROVISION_INTEGRATION_0_3,
];

/// Whether the VTA may answer `type_uri` by waiting on a third party.
#[must_use]
pub fn relays_onward(type_uri: &str) -> bool {
    RELAYS_ONWARD.contains(&type_uri)
}

/// The budget a caller should actually use for `type_uri`, given what it asked
/// for.
///
/// For a relaying task this raises `requested` to [`min_relay_budget_secs`]; it
/// never lowers anything. Raising rather than replacing keeps a caller that
/// deliberately allows longer — a slow link, a patient batch job — in charge of
/// its own patience, while making the incoherent case impossible: a budget
/// under the floor does not fail a relayed call faster, it fails it blind.
#[must_use]
pub fn client_budget_secs(type_uri: &str, requested: u64) -> u64 {
    if relays_onward(type_uri) {
        requested.max(min_relay_budget_secs())
    } else {
        requested
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The inversion that caused the outage, stated as arithmetic: the budget
    /// `create_did_webvh` used to carry could not outlast the VTA.
    #[test]
    fn the_old_sixty_second_budget_could_not_have_worked() {
        assert!(
            60 < relay_worst_case_secs(),
            "60s was below the VTA's worst case ({}s) — the timeout could never \
             have been anything but a mask",
            relay_worst_case_secs()
        );
        assert!(min_relay_budget_secs() > relay_worst_case_secs());
    }

    /// The defect, as arithmetic: `create_did_webvh` asked for 60s, and the
    /// clamp now lifts it clear of the VTA's worst case. This is the test that
    /// would have failed before the fix.
    #[test]
    fn the_task_that_failed_now_outlasts_the_vta() {
        let budget = client_budget_secs(trust_tasks::TASK_WEBVH_DIDS_CREATE_1_0, 60);
        assert!(
            budget > relay_worst_case_secs(),
            "a relayed mint must outlast the VTA ({budget}s vs {}s)",
            relay_worst_case_secs()
        );
    }

    /// Every relaying task, not just the one that was reported. All of them
    /// shipped at 30s or 60s — every one was a latent copy of the same bug.
    #[test]
    fn budget_floor_holds_for_every_relaying_task() {
        for uri in RELAYS_ONWARD {
            for requested in [1, 30, 60] {
                assert!(
                    client_budget_secs(uri, requested) > relay_worst_case_secs(),
                    "{uri} asked {requested}s and still cannot outlast the VTA"
                );
            }
        }
    }

    /// The clamp raises and never lowers: a caller that deliberately allows
    /// longer stays in charge of its own patience.
    #[test]
    fn the_clamp_never_shortens_a_budget() {
        let generous = min_relay_budget_secs() + 600;
        assert_eq!(
            client_budget_secs(trust_tasks::TASK_WEBVH_DIDS_CREATE_1_0, generous),
            generous
        );
        // And a task served from the VTA's own storage keeps the caller's
        // number, so a local failure still reports as promptly as it used to.
        assert_eq!(
            client_budget_secs(trust_tasks::TASK_KEYS_CREATE_0_1, 30),
            30
        );
    }

    /// The list is a fact about `vta-service`'s handlers, so nothing can derive
    /// it — but a URI that no longer exists is a clamp silently doing nothing,
    /// which is the one failure mode a test *can* catch.
    #[test]
    fn relay_list_names_only_real_tasks() {
        let catalog: std::collections::HashSet<&str> =
            trust_tasks::ALL_URIS.iter().copied().collect();
        let unknown: Vec<_> = RELAYS_ONWARD
            .iter()
            .filter(|u| !catalog.contains(*u))
            .collect();
        assert!(
            unknown.is_empty(),
            "these relay URIs are not in ALL_URIS — renamed or dropped, and \
             their clamp now does nothing: {unknown:#?}"
        );
    }

    #[test]
    fn no_duplicate_relay_entries() {
        let mut seen = std::collections::HashSet::new();
        for uri in RELAYS_ONWARD {
            assert!(seen.insert(*uri), "{uri} is listed twice");
        }
    }
}
