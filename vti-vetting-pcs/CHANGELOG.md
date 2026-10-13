# Changelog

Notable changes to the published crates. Generated from conventional commits by
[git-cliff](https://git-cliff.org) when a release is cut — do not edit by hand.
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


