# Changelog

Notable changes to the published crates. Generated from conventional commits by
[git-cliff](https://git-cliff.org) when a release is cut — do not edit by hand.
## [0.16.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-vetting-pcs-v0.15.0...vti-vetting-pcs-v0.16.0) — 2026-11-05


## [0.15.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-vetting-pcs-v0.14.0...vti-vetting-pcs-v0.15.0) — 2026-11-04


## [0.14.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-vetting-pcs-v0.13.0...vti-vetting-pcs-v0.14.0) — 2026-11-04


## [0.13.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-vetting-pcs-v0.12.0...vti-vetting-pcs-v0.13.0) — 2026-11-04


## [0.12.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-vetting-pcs-v0.11.0...vti-vetting-pcs-v0.12.0) — 2026-11-03


### Added

- **vetting**: Recover or reset a lost hidden-vetting key (pcs-binding/show, pcs-binding/reset, vta/pcs/vetter/recover) ([#2406](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2406))

* feat(vtc): recover or reset a lost hidden-vetting key (pcs-binding/show, pcs-binding/reset)

  A vetter is bound to the PCS identifier of their first enrolment, and a
  second identifier is refused with pcs-root:identifierRebound. The binding
  was never cleared, so a vetter whose key was lost was locked out of hidden
  vetting for as long as they stayed a member; revoking and re-granting the
  role did not help.

  - vtc/vetting/vetters/pcs-binding/show/0.1: a member reads their own
    binding (identifier, enrolled labels, any pending reset), so their client
    can recover the matching key. Membership is the entitlement;
    notAMember otherwise.
  - vtc/vetting/vetters/pcs-binding/reset/0.1: an administrator holding
    vtc.vetting.manage (as vetters/grant) resets a member's binding with a
    reason. Idempotent; notBound for a member who never enrolled. Audited as
    HiddenVetterBindingReset, never with the identifier.
  - Enrolment after a reset: the recorded identifier cancels it
    (HiddenVetterResetCancelled); a new one is refused (identifierRebound)
    while any label the old one enrolled under is live, judged at each
    request against the caller's configuration and the stored one under the
    enrolment lock, and bound once none is (HiddenVetterRebound) with its
    labels afresh. The old labels are retired on the record.
  - vtc/vetting/hidden/publish refuses to make a retired label live again,
    checked before the consent gate and again under the enrolment lock
    before the write. publish/0.1 declares no code for it, so it is a
    validation refusal.
  - Admin console: a "Reset a hidden-vetting key" card under Vetting ->
    Vetters, shown when discovery lists the task.
  - EnrolmentRecord gains optional reset and retiredLabels members; rows
    without them read and write as before.

  The two specifications are pinned from a locally built registry ahead of
  their publication; trust-tasks.lock records that registry until they are
  re-pinned against trusttasks.org.



## [0.11.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-vetting-pcs-v0.10.0...vti-vetting-pcs-v0.11.0) — 2026-11-02


## [0.10.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-vetting-pcs-v0.9.0...vti-vetting-pcs-v0.10.0) — 2026-10-30


## [0.9.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-vetting-pcs-v0.8.0...vti-vetting-pcs-v0.9.0) — 2026-10-30


## [0.8.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-vetting-pcs-v0.7.0...vti-vetting-pcs-v0.8.0) — 2026-10-28


### Chore

- **deps**: Trust-tasks-rs 0.36, affinidi-tdk 0.36, affinidi-messaging-sdk 0.44, mediator 0.48 ([#2319](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2319))

One trust-tasks-rs in the graph again, at 0.36.1 — the first release
  carrying vta/contexts/delete/1.1 (trust-tasks-tf #967). TDK moved in
  lockstep (affinidi-tdk-rs #978: affinidi-tdk 0.36, affinidi-messaging-sdk
  0.44) and so did the mediator (affinidi-messaging-mediator #46, released as
  0.48.0: test-mediator, mediator-admin, mediator-tui).

  trust-tasks-rs 0.36 emits trust-task-error/0.6, which adds the
  unsupportedExtension and indeterminate standard codes (framework 0.7,
  SPEC §8.3). Both services' framework_error_type_uri() move to 0.6 so an
  unrouted refusal speaks the same version as a routed one — the drift
  unrouted_and_routed_errors_agree_on_the_type_uri exists to catch — and the
  fixtures standing in for this workspace's own refusals follow, keeping
  one error version in vtc-service's binding census. Fixtures for foreign
  peers (a DID host) keep 0.5: a consumer still accepts it (SPEC §5.2).
  vta-sdk and the admin console recognise any trust-task-error/ version.

  0.36 also marks every prebuilt spec module deprecated in favour of
  trust-tasks-build. The workspace already allows `deprecated`;
  vta-external, vti-vetting-pcs and vta-persona did not inherit the
  workspace lints, and now do.



## [0.7.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-vetting-pcs-v0.6.0...vti-vetting-pcs-v0.7.0) — 2026-10-27


## [0.6.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-vetting-pcs-v0.5.0...vti-vetting-pcs-v0.6.0) — 2026-10-26


### Added

- Growth types in published crates are #[non_exhaustive] ([#2196](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2196))

A new variant on a public enum, or a new field on a public struct a consumer
  can build with a literal, is a breaking change in a published crate. It kept
  happening on types that were always going to grow (#1231, #1234, #1244, #1247,
  #1250); #1262 fixed it for Capability and AuditEvent only.

  This marks the rest once. 143 enums are marked: every error and refusal enum
  (VtaError, AppError, ...) and the growth vocabularies (kinds, statuses,
  reasons, codes, transports, SealedPayloadV1). 32 structs are marked: config
  and response bags that no caller builds with a literal. Adding the attribute
  is itself breaking, once. After it, additions to these types are minor
  changes.

  Left exhaustive on purpose, and pinned that way by the census:
  VerifiedAssertion, AssertionProof, ActScope, ApproveScope, ContextDirection,
  SigningDomain, TokenStatus and Role. For each of these, every arm must be
  considered, and a downstream wildcard would be the bug.

  Every downstream match in the workspace gets a `_ =>` arm that takes the most
  restrictive or most generic reading: an internal error, a hidden or refused
  entry, a stale attribute. None is unreachable!().

  vta-sdk/tests/non_exhaustive_census.rs fails on a public enum in a published
  library crate whose name ends in Error, Refusal, Violation, Kind, Event,
  Status, Capability, Reason or Code and that is not #[non_exhaustive], unless
  it is listed as deliberately exhaustive with a reason. It also fails when a
  listed enum gains the attribute or disappears.



## [0.5.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-vetting-pcs-v0.4.0...vti-vetting-pcs-v0.5.0) — 2026-10-18


## [0.4.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-vetting-pcs-v0.3.0...vti-vetting-pcs-v0.4.0) — 2026-10-18


## [0.3.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-vetting-pcs-v0.2.0...vti-vetting-pcs-v0.3.0) — 2026-10-16


## [0.2.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-vetting-pcs-v0.1.0...vti-vetting-pcs-v0.2.0) — 2026-10-15


## [0.1.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/releases/tag/vti-vetting-pcs-v0.1.0) — 2026-10-13


### Added

- **vta**: The VTA as hidden-vetting (PCS) engine — vta/pcs/* for clients that cannot run PCS ([#2056](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2056))

* feat(vta)!: the VTA as hidden-vetting (PCS) engine — vta/pcs/* for clients that cannot run PCS

  A community that runs hidden vetting admits an applicant on a zero-knowledge
  proof that distinct eligible vetters vetted them. Every vetter and applicant
  holds a PCS secret key, and until now the member side ran only in a client
  linking the PCS library, so a mobile wallet (Keyring) could not take part.

  The VTA now holds those keys and runs every member-side operation (design
  vetting-hidden-vetters-pcs.md §13 C7); the client carries messages and never
  holds a key. Twelve Trust Tasks (trust-tasks-tf #756):

  - applicant: applications/{create,show,delete}, verify-attestation, prove
  - vetter: root-request, root-accept, tokens/{request,accept,abandon}, attest,
    vetter/show

- **vtc**: Join criteria state their own admission (Keyring VTI-13) ([#1907](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1907))

A community's join criteria are its join rules, and the VTC now decides a
  submission by them as vtc/join-requests/submit/0.3 specifies
  (dtgwg-trust-tasks-tf#710, trust-tasks-rs 0.26.1). Nothing in the service
  assumes a criterion: open admission, review only, invitation only and any
  combination are all criteria an administrator registers.

  - Criteria (vtc/schemas/accepts/{register,list,show}/0.2) carry `admission`
    (automatic | review), an optional DCQL query with `credentialIssuers`
    (community | recognised | any), `invitationRequired` and `vetting`.
    `recognised` without a trust registry is `unsupportedRequirement`.
  - The manifest (vtc/join-requests/manifest/0.3) publishes them in the order
    the community decides by — registration order, kept on replacement.
  - A submission is decided under the criterion it names by digest, else the
    first it meets, else the first published. No criteria → `notAccepting`;
    an unpublished digest → `criterionUnknown`. Superseded versions are kept
    and govern while their `requirementsGrace` lasts.
  - The host verifies the presentation's embedded credentials (proof set,
    validity window, revocation, subject = applicant) and matches the query,
    applying DCQL `type_values`, which the matcher alone ignores.
  - The host holds the policy to the criterion: unmet → never admitted or
    referred (requestMore naming what is missing); met review → refer; met
    automatic → the policy's verdict. Policy may tighten, never loosen.
    The default join.rego follows the criterion.
  - A new community is seeded once with `invited` (automatic) →
    `member-credential` (automatic) → `review`.
  - The criterion and version that governed are recorded beside the request;
    a supplement re-decides under it.

- DTG Credentials v1 — role VACs, vetted/1 and witnessed/1 statements, IDVCs, issuerScope ([#1859](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1859))

* feat(vta-sdk)!: vetting statements are vetted/1 VSCs; role credentials are VACs

  Conform the SDK's vetting artifacts to the DTG Credentials Core
  Specification (v1 context, `issuerScope`) and the DTG VSC predicate
  registry, following the regenerated vetting specifications
  (dtgwg-trust-tasks-tf feat/dtg-vsc-conformance).

  Vetting Statement (vetting/session/0.1): no longer an
  EndorsementCredential. `sign_statement` builds a StatementCredential with
  `new_vetted_vsc` under `https://registry.trustoverip.org/dtg/vsc/vetted/1`;
  the body is `credentialSubject.object.value`, with no `type` member.
  `taskContext` and `taskDigestMultibase` are both read from the
  `vetting/session` document, which `StatementDraft::session` now carries
  in place of `task_context`, and `StatementDraft::issuer_scope` is
  `directed` or `public` (pairwise is refused by the profile).
  `verify_statement` parses through `dtg-credentials`, so the v1 context,
  the one-subtype rule and the profile are checked by the code that issues
  them; `VerifiedVettingStatement::check_against_session` binds a statement
  to the session document by id and task digest.

  - `IdentityVettingEndorsement` -> `VettedObjectValue` (no `type`; digests
    and commitment must be base58btc, as the registry schema requires).
  - `IDENTITY_VETTING_ENDORSEMENT_TYPE` -> `VETTED_PREDICATE`.
  - `VerifiedVettingStatement::endorsement()` -> `value()`; new
    `issuer_scope()`, `task_digest_multibase()`.

  Vetter role credential (vtc/vetting/vetters/grant/0.1, vetting/request/0.1):
  a community-issued VAC, `issuerScope` public, `authority` { scope:
  <community DID>, actions: ["role:vetter"], maxAttenuation: 0 }.
  `eligibility::community_role` -> `community_roles`, returning every
  `role:<name>` of a VAC the community issued in its own scope with no
  parent; `verify_eligibility_vp` parses the VAC strictly and refuses a
  non-public scope or an attenuation.

  - `COMMUNITY_ROLE_ENDORSEMENT_TYPE` removed; new `ROLE_ACTION_PREFIX`,
    `VETTER_ROLE_ACTION`, `role_action`, `role_of_action`.
  - `protocols::members::ENDORSEMENT_CREDENTIAL_TYPE` removed; new
    `AUTHORITY_CREDENTIAL_TYPE` and `STATEMENT_CREDENTIAL_TYPE`.
  - `VerdictWith::role_vec` -> `role_vac` (wire `roleVac`).


