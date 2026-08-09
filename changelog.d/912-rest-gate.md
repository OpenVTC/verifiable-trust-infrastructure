### vti-common 0.11.36 / vta-service 0.14.20 — the PDP gate reaches the REST routes (#912)

Closes most of a live enforcement gap: the Policy Decision Point ran **only** in
the trust-task dispatcher, so `POST /acl` and friends called their operations
directly and a `requireConsent` rule an operator had written bound one transport
and silently not the other. Same mutation, same policy, two answers.

Purely additive — `RequireStepUp` stays in place, so REST is now gated by both
the old step-up floors and the PDP, and nothing is removed until the retirement
that follows.

- **`policy_gate` is split into a decision and its shaping.** It used to do both,
  threading `&TrustTask<Value>` down to nine `app_error_to_reject(doc, e)` sites
  — which is the mechanical reason the decision was unreachable from a REST
  handler, which has a parsed body and no document. `decide` now takes the
  payload and returns `GateReject`; `policy_gate` shapes it exactly as before,
  and `rest_gate` shapes it for a route. `require_step_up` /
  `initiate_self_step_up` likewise take `&Value` and return a `RejectReason`.
  No behaviour change — the 791 lib tests pass unmoved.
- **New `AppError::ApprovalRequired { code, details }`.** `StepUpRequired(String)`
  renders `{error, message, requiredAcr}` and has nowhere to put the
  `approveRequest` a caller needs, nor any way to express a consent requirement,
  so a REST caller could learn it was blocked but not what to do about it while
  the trust-task caller for the same decision got the whole document. `details`
  is merged at the top level so the body reads like the trust-task reject's, with
  `error` written last so a `details` carrying that key cannot displace the code
  clients switch on.
- **Gated in-handler** (the consent digest is taken over the payload, which an
  axum extractor cannot see): `POST /acl`, `PATCH /acl/{did}`,
  `POST /acl/{did}/change-role`, `DELETE /acl/{did}`, `DELETE /contexts/{id}`.
  Each gates on the same payload shape its trust-task counterpart digests — the
  whole `{entry: …}` body for a grant, not the inner entry — because a digest
  that differed by transport would mean an approval obtained over one could not
  be consumed over the other.
- **A transport-parity test**: one policy, both paths, same decision, and the
  REST body must carry the consent `challenge` rather than a bare 403. The
  absence of exactly this test is why the bypass went unnoticed.

**Still open — `POST /contexts/{ctx}/dids/{scid}`.** The planner parses the gated
payload as `UpdateDidWithDid { did, .. }`, but that handler is addressed by
**SCID**; gating on what it holds would produce a digest disagreeing with the
trust-task path's for the same update. Resolving the SCID to its DID first is the
fix, and it belongs with the change that can test it end to end rather than
bolted on. Recorded in `docs/05-design-notes/approvals-convergence.md`.
