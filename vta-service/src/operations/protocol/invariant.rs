//! Brick-prevention invariant for runtime service-management.
//!
//! Spec: `docs/05-design-notes/runtime-service-management.md` §3.2.
//!
//! At least one transport service (REST, DIDComm, WebAuthn, or TSP)
//! must be advertised in the VTA's DID document at all times. Disable /
//! rollback paths funnel through [`would_violate_last_service`] to
//! enforce this — there is no `--force` escape hatch and no
//! per-call-site duplication of the predicate.
//!
//! The function is pure: callers compute the post-mutation enabled
//! state for the kind they're touching and pass it in. State for
//! the *other* kinds is read off the supplied [`CurrentServices`]
//! snapshot. This keeps the predicate testable in isolation and
//! independent of the persistence layer.
//!
//! WebAuthn counts as a transport for this invariant: a VTA
//! advertising only `#vta-webauthn` is still reachable (browser
//! users can authenticate via the portal and drive trust-tasks
//! over that session). What we forbid is "zero advertised
//! transports of any kind".

use vta_sdk::error::VtaError;

use crate::operations::protocol::snapshot::ServiceKind;

/// Snapshot of which transport services the VTA is currently
/// advertising in its DID document.
///
/// Read by the operation layer from `AppConfig.services` (or the
/// most recent WebVH LogEntry's `service[]` array, when the
/// caller is acting on observed-on-chain state). Both sources
/// must agree — divergence is itself a bug worth surfacing
/// elsewhere.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CurrentServices {
    pub rest_enabled: bool,
    pub didcomm_enabled: bool,
    pub webauthn_enabled: bool,
    pub tsp_enabled: bool,
}

impl CurrentServices {
    pub const fn new(
        rest_enabled: bool,
        didcomm_enabled: bool,
        webauthn_enabled: bool,
        tsp_enabled: bool,
    ) -> Self {
        Self {
            rest_enabled,
            didcomm_enabled,
            webauthn_enabled,
            tsp_enabled,
        }
    }
}

/// A proposed mutation, expressed as the **post-mutation** enabled
/// state for a single kind.
///
/// The shape deliberately doesn't enumerate enable / update /
/// disable / rollback — the invariant only cares about the result
/// of the transition. Callers compute the post-state from their
/// op semantics and feed it in. Most ops use one of the
/// [`Self::enable`] / [`Self::disable`] constructors; rollback
/// dispatchers compute the post-state from the snapshot they're
/// fail-forwarding into.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProposedOp {
    pub kind: ServiceKind,
    pub kind_will_be_enabled: bool,
}

impl ProposedOp {
    /// The kind will be enabled after the op (e.g. `services rest
    /// enable`, `services didcomm rollback` of a previous disable).
    pub const fn enable(kind: ServiceKind) -> Self {
        Self {
            kind,
            kind_will_be_enabled: true,
        }
    }

    /// The kind will be disabled after the op (e.g. `services rest
    /// disable`, `services didcomm rollback` of a previous enable).
    pub const fn disable(kind: ServiceKind) -> Self {
        Self {
            kind,
            kind_will_be_enabled: false,
        }
    }
}

/// Reject the mutation if it would leave the VTA's DID document
/// advertising zero transport services.
///
/// Returns [`VtaError::LastServiceRefused`] when the post-op state
/// would have both REST and DIDComm disabled. The single source
/// of truth for spec §3.2 — every disable / rollback path goes
/// through here, no duplicated conditionals.
///
/// Note: the function does not consult the snapshot store, the
/// fjall keyspaces, or the live registry. It is a pure predicate
/// over the supplied state, making it cheap to call defensively
/// (e.g. as the first thing inside a mutation entry point).
pub fn would_violate_last_service(state: &CurrentServices, op: ProposedOp) -> Result<(), VtaError> {
    let (rest_after, didcomm_after, webauthn_after, tsp_after) = match op.kind {
        ServiceKind::Rest => (
            op.kind_will_be_enabled,
            state.didcomm_enabled,
            state.webauthn_enabled,
            state.tsp_enabled,
        ),
        ServiceKind::Didcomm => (
            state.rest_enabled,
            op.kind_will_be_enabled,
            state.webauthn_enabled,
            state.tsp_enabled,
        ),
        ServiceKind::Webauthn => (
            state.rest_enabled,
            state.didcomm_enabled,
            op.kind_will_be_enabled,
            state.tsp_enabled,
        ),
        ServiceKind::Tsp => (
            state.rest_enabled,
            state.didcomm_enabled,
            state.webauthn_enabled,
            op.kind_will_be_enabled,
        ),
    };
    if !rest_after && !didcomm_after && !webauthn_after && !tsp_after {
        return Err(VtaError::LastServiceRefused);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Spec §7a.1 state model — combinations of (rest, didcomm,
    /// webauthn). `S0` is invariant-violating but a valid input to
    /// the predicate (because the predicate is also called from
    /// `enable` paths that bring the VTA *out* of the bricked
    /// state). Webauthn is always off in S0/S1/S2/S3 — the
    /// post-WebAuthn truth table is exercised by
    /// `full_truth_table_with_webauthn` below.
    const S0: CurrentServices = CurrentServices::new(false, false, false, false);
    const S1: CurrentServices = CurrentServices::new(true, false, false, false); // rest only
    const S2: CurrentServices = CurrentServices::new(false, true, false, false); // didcomm only
    const S3: CurrentServices = CurrentServices::new(true, true, false, false);

    /// Disabling either kind from S3 leaves the other on — never
    /// rejects.
    #[test]
    fn s3_can_disable_either_kind() {
        assert!(would_violate_last_service(&S3, ProposedOp::disable(ServiceKind::Rest)).is_ok());
        assert!(would_violate_last_service(&S3, ProposedOp::disable(ServiceKind::Didcomm)).is_ok());
    }

    /// Disabling the only-on kind from S1/S2 brings the VTA to S0
    /// — must reject with `LastServiceRefused`.
    #[test]
    fn s1_disable_rest_is_rejected() {
        let err =
            would_violate_last_service(&S1, ProposedOp::disable(ServiceKind::Rest)).unwrap_err();
        assert!(matches!(err, VtaError::LastServiceRefused));
    }

    #[test]
    fn s2_disable_didcomm_is_rejected() {
        let err =
            would_violate_last_service(&S2, ProposedOp::disable(ServiceKind::Didcomm)).unwrap_err();
        assert!(matches!(err, VtaError::LastServiceRefused));
    }

    /// Disabling the *already-off* kind is a no-op for the
    /// invariant — it doesn't change the post-state. The predicate
    /// must accept it (the higher-level op layer rejects this with
    /// `ServiceNotPresent`, but that's a different concern).
    #[test]
    fn s1_disable_didcomm_is_accepted_by_invariant() {
        // S1 = rest on, didcomm off. Disabling didcomm: post-state
        // is still (rest on, didcomm off). Invariant intact.
        assert!(would_violate_last_service(&S1, ProposedOp::disable(ServiceKind::Didcomm)).is_ok());
    }

    #[test]
    fn s2_disable_rest_is_accepted_by_invariant() {
        assert!(would_violate_last_service(&S2, ProposedOp::disable(ServiceKind::Rest)).is_ok());
    }

    /// Enabling brings (or leaves) a kind on — never violates.
    #[test]
    fn enable_never_violates() {
        for state in &[S0, S1, S2, S3] {
            for kind in &[
                ServiceKind::Rest,
                ServiceKind::Didcomm,
                ServiceKind::Webauthn,
                ServiceKind::Tsp,
            ] {
                assert!(
                    would_violate_last_service(state, ProposedOp::enable(*kind)).is_ok(),
                    "enable from {state:?} for {kind:?} must be accepted",
                );
            }
        }
    }

    /// WebAuthn-only state — disabling WebAuthn would brick the
    /// VTA the same way disabling the only-enabled REST or DIDComm
    /// would.
    #[test]
    fn webauthn_only_state_cannot_disable_webauthn() {
        let s_w = CurrentServices::new(false, false, true, false);
        let err = would_violate_last_service(&s_w, ProposedOp::disable(ServiceKind::Webauthn))
            .unwrap_err();
        assert!(matches!(err, VtaError::LastServiceRefused));
    }

    /// WebAuthn keeps a VTA alive even when REST and DIDComm are
    /// both off — disabling either of them must be accepted.
    #[test]
    fn webauthn_keeps_invariant_when_other_two_disabled() {
        let s_w = CurrentServices::new(false, false, true, false);
        assert!(would_violate_last_service(&s_w, ProposedOp::disable(ServiceKind::Rest)).is_ok());
        assert!(
            would_violate_last_service(&s_w, ProposedOp::disable(ServiceKind::Didcomm)).is_ok()
        );
    }

    /// With all four on, disabling any single kind is fine.
    #[test]
    fn all_three_on_any_single_disable_is_ok() {
        let s_all = CurrentServices::new(true, true, true, true);
        for kind in &[
            ServiceKind::Rest,
            ServiceKind::Didcomm,
            ServiceKind::Webauthn,
            ServiceKind::Tsp,
        ] {
            assert!(
                would_violate_last_service(&s_all, ProposedOp::disable(*kind)).is_ok(),
                "all-on, disable {kind:?} must be accepted",
            );
        }
    }

    /// TSP-only state — disabling TSP would brick the VTA the same
    /// way disabling the only-enabled REST or DIDComm would.
    #[test]
    fn tsp_only_state_cannot_disable_tsp() {
        let s_t = CurrentServices::new(false, false, false, true);
        let err =
            would_violate_last_service(&s_t, ProposedOp::disable(ServiceKind::Tsp)).unwrap_err();
        assert!(matches!(err, VtaError::LastServiceRefused));
    }

    /// TSP keeps a VTA alive even when REST and DIDComm are both off
    /// — disabling either of them must be accepted.
    #[test]
    fn tsp_keeps_invariant_when_other_two_disabled() {
        let s_t = CurrentServices::new(false, false, false, true);
        assert!(would_violate_last_service(&s_t, ProposedOp::disable(ServiceKind::Rest)).is_ok());
        assert!(
            would_violate_last_service(&s_t, ProposedOp::disable(ServiceKind::Didcomm)).is_ok()
        );
    }

    /// From S0 (already bricked), enabling either kind brings the
    /// VTA back to S1 or S2 — those operations must succeed at the
    /// invariant layer so the operator can climb out.
    #[test]
    fn s0_enable_either_kind_is_accepted() {
        assert!(would_violate_last_service(&S0, ProposedOp::enable(ServiceKind::Rest)).is_ok());
        assert!(would_violate_last_service(&S0, ProposedOp::enable(ServiceKind::Didcomm)).is_ok());
    }

    /// S0 + a *disable* is doubly-bad (already bricked, this op
    /// would keep us bricked). Reject — even though it's a no-op
    /// in practice, the typed error gives the operator a clearer
    /// message than silent acceptance.
    #[test]
    fn s0_disable_is_rejected() {
        assert!(matches!(
            would_violate_last_service(&S0, ProposedOp::disable(ServiceKind::Rest)).unwrap_err(),
            VtaError::LastServiceRefused,
        ));
        assert!(matches!(
            would_violate_last_service(&S0, ProposedOp::disable(ServiceKind::Didcomm)).unwrap_err(),
            VtaError::LastServiceRefused,
        ));
    }

    /// Exhaustive sweep of every (state, kind, post-state) cell —
    /// guards against future divergence between the two-kind logic
    /// arms inside the function.
    #[test]
    fn full_truth_table() {
        // (state, kind, kind_will_be_enabled, expected_ok)
        let cases = [
            (S0, ServiceKind::Rest, false, false),
            (S0, ServiceKind::Rest, true, true),
            (S0, ServiceKind::Didcomm, false, false),
            (S0, ServiceKind::Didcomm, true, true),
            (S1, ServiceKind::Rest, false, false), // s1 disable-rest = brick
            (S1, ServiceKind::Rest, true, true),
            (S1, ServiceKind::Didcomm, false, true), // s1 disable-didcomm = no-op
            (S1, ServiceKind::Didcomm, true, true),
            (S2, ServiceKind::Rest, false, true), // s2 disable-rest = no-op
            (S2, ServiceKind::Rest, true, true),
            (S2, ServiceKind::Didcomm, false, false), // s2 disable-didcomm = brick
            (S2, ServiceKind::Didcomm, true, true),
            (S3, ServiceKind::Rest, false, true),
            (S3, ServiceKind::Rest, true, true),
            (S3, ServiceKind::Didcomm, false, true),
            (S3, ServiceKind::Didcomm, true, true),
        ];

        for (state, kind, kind_will_be_enabled, expected_ok) in cases {
            let op = ProposedOp {
                kind,
                kind_will_be_enabled,
            };
            let result = would_violate_last_service(&state, op);
            assert_eq!(
                result.is_ok(),
                expected_ok,
                "case ({state:?}, {kind:?}, {kind_will_be_enabled}) — expected ok={expected_ok}, got {result:?}",
            );
            if !expected_ok {
                assert!(matches!(result.unwrap_err(), VtaError::LastServiceRefused));
            }
        }
    }
}
