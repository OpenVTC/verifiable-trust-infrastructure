# Changelog

Notable changes to the published crates. Generated from conventional commits by
[git-cliff](https://git-cliff.org) when a release is cut — do not edit by hand.
## [0.1.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/releases/tag/vti-rooms-host-v0.1.0) — 2026-11-14


### Changed

- **rooms**: Share the rooms/* handlers between hosts and run every host receive path on Spine ([#2731](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2731))

* refactor(room-host): receive every document through vti_trust_task_server::Spine

  room-host re-implemented the receive pipeline inline: size, freshness,
  validate_basic and the accepted-id claim/settle, with no spec-policy step
  and the proof verified lazily inside each handler. It now runs the shared
  Spine the VTC runs ([#2576](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2576)): the size gate holds each task to its declared
  maxDocumentBytes, the spec policy comes from
  vti_specs::schema_index::spec_policy_for, the proof is verified once over
  the document as received and bound to its issuer, DIDComm and TSP frames
  carry their authenticated sender so the spine binds it (VTI-OPS-021/093),
  and the duplicate-id record is StoreAcceptedIds (VTI-OPS-025..029).

  A host without a DID still refuses an expired document: the spine skips
  the recipient binding then, so before_proof applies the expiry check.
  A proof made by someone other than the issuer is now proofInvalid, as at
  the VTC, rather than permissionDenied.


