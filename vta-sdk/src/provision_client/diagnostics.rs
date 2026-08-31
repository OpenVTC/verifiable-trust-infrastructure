//! Live checklist of diagnostic steps run against the VTA during the
//! provisioning attempt. Each entry's status is updated as events arrive
//! from the runner; consumers render the whole list with per-step icons
//! and detail text in their UI of choice.

use super::intent::VtaReply;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DiagCheck {
    ResolveDid,
    EnumerateServices,
    /// TSP-leg transport open. Emitted when the VTA advertises a
    /// `#tsp` (`TSPTransport`) service — TSP is the highest-preference
    /// transport (TSP > DIDComm > REST), so this row runs first. Stays
    /// `Skipped` when no `#tsp` service is advertised, or when the SDK
    /// was built without the `tsp` feature and another transport is
    /// available to fall back to.
    ///
    /// **This row is not an authorization result.** Opening a TSP session
    /// means sealing to the VTA's mediator; there is no challenge, no token,
    /// and no VTA round-trip, so a setup DID with no ACL grant on this VTA
    /// gets a green row here. [`Self::VerifyAuthorization`] is the row that
    /// actually asks the VTA.
    AuthenticateTSP,
    /// DIDComm-leg transport open. The runner emits `Running` /
    /// `Ok` / `Failed` on this row when the configured transport is
    /// DIDComm. When DIDComm isn't advertised by the VTA, this row
    /// stays `Skipped`.
    ///
    /// Carries the same caveat as [`Self::AuthenticateTSP`]: connecting sets
    /// the client's ACL **at the mediator**, which says nothing about the
    /// VTA's.
    AuthenticateDIDComm,
    /// REST-leg of the auth check. Emitted when the runner falls back to
    /// REST after a DIDComm failure, when the VTA advertises only REST,
    /// or as a `Skipped` placeholder when the DIDComm path completed
    /// without needing a fallback.
    ///
    /// Unlike the other two legs this one *is* a VTA round-trip — the
    /// challenge/authenticate ceremony, which checks the ACL before minting a
    /// token — so a green row here does mean the grant landed.
    AuthenticateREST,
    /// The first round-trip that asks the **VTA** anything:
    /// `trust-task-discovery/0.1`, whose answer is the VTA's own dispatch
    /// table.
    ///
    /// It settles the three questions the rows above cannot, in one call and
    /// before any key is minted:
    ///
    /// - *is the setup DID granted on this VTA* — a missing ACL entry comes
    ///   back `permissionDenied` here rather than as a puzzling failure three
    ///   steps later;
    /// - *is this the VTA you meant* — the reply is that VTA's task list;
    /// - *do both ends agree on a version* — the provisioning URI this run
    ///   will dispatch is either in the list or it is not.
    ///
    /// `Skipped` rather than `Failed` when the VTA does not serve discovery:
    /// it is a published family but not an ancient one, and refusing to
    /// provision against a VTA that works would be a worse failure than the
    /// one this row exists to catch.
    VerifyAuthorization,
    /// FullSetup-only: fetches the VTA's registered webvh-daemon
    /// catalogue so the runner can either auto-pick (0/1 entries) or
    /// surface a choice (2+). Skipped on AdminOnly.
    ListWebvhServers,
    ProvisionIntegration,
}

impl DiagCheck {
    pub fn label(&self) -> &'static str {
        match self {
            Self::ResolveDid => "Resolve VTA DID",
            Self::EnumerateServices => "Enumerate service endpoints",
            Self::AuthenticateTSP => "Open TSP session",
            Self::AuthenticateDIDComm => "Open DIDComm session",
            Self::AuthenticateREST => "Authenticate via REST",
            Self::VerifyAuthorization => "Verify authorization with the VTA",
            Self::ListWebvhServers => "List webvh hosting servers",
            Self::ProvisionIntegration => "Provision integration DID + admin credential",
        }
    }

    /// Ordered list of every check the runner performs, in execution order.
    pub fn all() -> &'static [DiagCheck] {
        &[
            Self::ResolveDid,
            Self::EnumerateServices,
            Self::AuthenticateTSP,
            Self::AuthenticateDIDComm,
            Self::AuthenticateREST,
            Self::VerifyAuthorization,
            Self::ListWebvhServers,
            Self::ProvisionIntegration,
        ]
    }
}

#[derive(Clone, Debug)]
pub enum DiagStatus {
    Pending,
    Running,
    Ok(String),
    Skipped(String),
    Failed(String),
}

#[derive(Clone, Debug)]
pub struct DiagEntry {
    pub check: DiagCheck,
    pub status: DiagStatus,
}

/// Which authentication path the runner actually completed with.
///
/// Also the `force_transport` vocabulary for
/// [`run_connection_test`](super::run_connection_test) — forcing a transport
/// pins the runner to that leg with no fallback.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Protocol {
    /// Trust Spanning Protocol, routed through the mediator named by the VTA's
    /// `#tsp` (`TSPTransport`) service. Highest preference.
    Tsp,
    DidComm,
    Rest,
}

impl Protocol {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Tsp => "TSP",
            Self::DidComm => "DIDComm",
            Self::Rest => "REST",
        }
    }
}

/// Info about a successful VTA round-trip. Surfaced to the consumer so
/// downstream steps can read the result without re-contacting the VTA.
#[derive(Clone, Debug)]
pub struct ConnectedInfo {
    /// Which transport actually carried the round-trip.
    pub protocol: Protocol,
    /// REST URL advertised by the VTA DID document, for runtime-side
    /// fallback. The provisioning workflow itself does not use it.
    pub rest_url: Option<String>,
    /// Mediator DID the round-trip was routed through. Always `Some` when
    /// `protocol == DidComm` (the `#DIDCommMessaging` mediator) or
    /// `protocol == Tsp` (the `#tsp` mediator).
    pub mediator_did: Option<String>,
    /// Unified reply — see [`VtaReply`] for the variants.
    pub reply: VtaReply,
}

/// Seed a fresh diagnostics list with every check in `Pending`.
pub fn pending_list() -> Vec<DiagEntry> {
    DiagCheck::all()
        .iter()
        .map(|c| DiagEntry {
            check: *c,
            status: DiagStatus::Pending,
        })
        .collect()
}

/// Apply a single (check, status) update to an existing diagnostics list.
/// If the check is not present, the update is silently ignored (the runner
/// and the list come from the same source so this should not happen in
/// practice — we avoid the panic for robustness).
pub fn apply_update(list: &mut [DiagEntry], check: DiagCheck, status: DiagStatus) {
    for entry in list.iter_mut() {
        if entry.check == check {
            entry.status = status;
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pending_list_has_all_checks() {
        let list = pending_list();
        assert_eq!(list.len(), DiagCheck::all().len());
        assert!(list.iter().all(|e| matches!(e.status, DiagStatus::Pending)));
    }

    #[test]
    fn apply_update_sets_status_on_matching_check() {
        let mut list = pending_list();
        apply_update(
            &mut list,
            DiagCheck::ResolveDid,
            DiagStatus::Ok("did:webvh:...".into()),
        );
        let resolved = &list[0];
        assert_eq!(resolved.check, DiagCheck::ResolveDid);
        assert!(matches!(resolved.status, DiagStatus::Ok(_)));
    }

    /// The authenticate rows are listed in the runner's own preference order —
    /// TSP > DIDComm > REST — so a consumer rendering `all()` top-to-bottom
    /// shows them in the order the runner will actually try them.
    #[test]
    fn all_lists_split_authenticate_rows_in_order() {
        let all = DiagCheck::all();
        assert_eq!(
            all,
            &[
                DiagCheck::ResolveDid,
                DiagCheck::EnumerateServices,
                DiagCheck::AuthenticateTSP,
                DiagCheck::AuthenticateDIDComm,
                DiagCheck::AuthenticateREST,
                DiagCheck::VerifyAuthorization,
                DiagCheck::ListWebvhServers,
                DiagCheck::ProvisionIntegration,
            ]
        );
    }

    #[test]
    fn authenticate_rows_have_distinct_labels() {
        assert_eq!(DiagCheck::AuthenticateTSP.label(), "Open TSP session");
        assert_eq!(
            DiagCheck::AuthenticateDIDComm.label(),
            "Open DIDComm session"
        );
        assert_eq!(DiagCheck::AuthenticateREST.label(), "Authenticate via REST");
    }

    /// Only the leg that performs the challenge/authenticate ceremony may say
    /// "authenticate".
    ///
    /// REGRESSION (2026-08-31): the TSP and DIDComm rows both read
    /// "Authenticate via …" while their proxy was a socket open — no VTA
    /// round-trip, no ACL check. An operator whose setup DID had no grant on
    /// the VTA they were pointed at watched that row go green, and read the
    /// failure three steps later as a fault in provisioning rather than in
    /// which VTA they had reached.
    #[test]
    fn only_the_rest_leg_claims_to_authenticate() {
        for check in DiagCheck::all() {
            if matches!(
                check,
                DiagCheck::AuthenticateTSP | DiagCheck::AuthenticateDIDComm
            ) {
                assert!(
                    !check.label().to_lowercase().contains("authenticate"),
                    "{} opens a transport; it does not authenticate against the VTA",
                    check.label()
                );
            }
        }
        assert!(
            DiagCheck::AuthenticateREST
                .label()
                .to_lowercase()
                .contains("authenticate")
        );
    }

    /// The authorization probe runs after every transport leg and before the
    /// first step that mints anything — it is the row that makes a missing ACL
    /// grant, a wrong VTA and a version skew visible while all three are still
    /// cheap to fix.
    #[test]
    fn authorization_is_verified_before_anything_is_minted() {
        let all = DiagCheck::all();
        let pos = |c: DiagCheck| all.iter().position(|x| *x == c).expect("row present");
        assert!(pos(DiagCheck::VerifyAuthorization) > pos(DiagCheck::AuthenticateREST));
        assert!(pos(DiagCheck::VerifyAuthorization) < pos(DiagCheck::ListWebvhServers));
        assert!(pos(DiagCheck::VerifyAuthorization) < pos(DiagCheck::ProvisionIntegration));
    }

    /// Every transport the runner can complete over has a distinct operator-
    /// facing label — `Connected via {label}` is rendered verbatim.
    #[test]
    fn protocol_labels_are_distinct() {
        assert_eq!(Protocol::Tsp.label(), "TSP");
        assert_eq!(Protocol::DidComm.label(), "DIDComm");
        assert_eq!(Protocol::Rest.label(), "REST");
    }

    #[test]
    fn provision_label_is_template_agnostic() {
        // Spec invariant: no integration-specific noun in this enum's
        // labels — the per-integration label comes from OperatorMessages.
        let label = DiagCheck::ProvisionIntegration.label();
        assert!(!label.to_lowercase().contains("mediator"));
        assert!(!label.to_lowercase().contains("webvh"));
        assert!(label.contains("integration"));
    }
}
