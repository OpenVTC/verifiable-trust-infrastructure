# Changelog

Notable changes to the published crates. Generated from conventional commits by
[git-cliff](https://git-cliff.org) when a release is cut — do not edit by hand.
## [0.3.2](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-vault-v0.3.1...vta-vault-v0.3.2) — 2026-08-20


## [0.3.1](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-vault-v0.3.0...vta-vault-v0.3.1) — 2026-08-18


## [0.3.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-vault-v0.2.0...vta-vault-v0.3.0) — 2026-08-17


### Added

- **vta-service**: Present ISO mdoc credentials over OID4VP ([#993](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/993))

* feat(vta-service)!: present ISO mdoc credentials over OID4VP

  Completes mdoc support. A VTA could receive, verify and store an mdoc; it could
  not present one. This is the last piece, and it needed three things the other
  formats do not.

  An OID4VP session on the query wire. An mdoc's holder binding is a DeviceAuth
  signature over an ISO 18013-7 SessionTranscript, whose handover is
  [clientId, responseUri, nonce, mdocGeneratedNonce]. Two of those exist only in
  an OID4VP exchange, so a verifier that wants an mdoc supplies them; QueryBody
  gains an optional oid4vp_session carrying OID4VP's own field names, so a
  verifier can copy them out of its authorization request unrenamed.

  Absent, an mdoc is not offered at all rather than offered unbound. A DeviceAuth
  over invented handover values verifies nowhere and, worse, looks bound. The gate
  lives in match_held so matchable and presentable stay the same set: a
  matched-but-unpresentable credential bails the entire vp_token, not just itself,
  taking every other credential the verifier legitimately asked for with it. A
  mutation removing the gate fails the test that pins this.

  Holder identity that is key-shaped. ConsentGrant.holder_did becomes
  HolderIdentity::{Subject, DeviceKey}: every other format names a subject DID,
  while an mdoc names a device key discovered at receive. Both resolve to a
  did:key because ConsentRecord::verify_proof binds the proof's
  verificationMethod to the data subject — the variant records provenance that
  would otherwise be silently lost, not a different kind of value.

  A P-256 consent receipt. The device key signs its own receipt under
  ecdsa-jcs-2019 (affinidi-data-integrity 0.7.10), where every other format uses
  eddsa-jcs-2022. Signing the receipt with some other key would break the
  verificationMethod binding above; that is why the cryptosuite was added upstream
  rather than worked around here.

  Presentation itself is not a present_single arm: an mdoc vp_token entry is
  base64url CBOR of a DeviceResponse, not a W3C VP object, so present_mdoc sits
  beside it. Selective disclosure is by omission — only the [namespace, element]
  paths the query asked for are included.



## [0.2.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-vault-v0.1.4...vta-vault-v0.2.0) — 2026-08-16


### Added

- **vta-vault**: Bind an mdoc to the VTA key that can present it ([#990](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/990))

An mdoc's holder binding is a key, not a DID: the MSO carries a deviceKey, and
  only its private half can sign DeviceAuth. Nothing in the stored envelope said
  which VTA key that was, so a received mdoc could be stored and then turn out to
  be unpresentable — with the failure surfacing much later, at presentation, and
  nothing pointing at the cause.

  Receive now resolves that binding and refuses the credential if this VTA does
  not hold the key. Storing a credential you can never present is a trap, and the
  right moment to find out is the moment it arrives.

  mdoc_device_key_sec1 extracts the MSO deviceKey as a compressed SEC1 point —
  the same encoding the VTA stores its own P-256 public keys in — so the caller
  can compare without re-deriving either side. Extraction lives in vta-vault
  because it reads mdoc internals; the matching lives in vta-service because that
  is the layer that can see the keyspace. vta-vault does not depend on vta-keys,
  and this keeps it that way.

  find_key_by_public_multibase is a linear scan: the keyspace is indexed by key
  id, not by public key, and a reverse index for one receive-path caller is not
  worth the write amplification on every mint. It takes no AuthClaims because it
  answers a factual question, not an authorization one — the caller gates on the
  returned record's context_id, because binding a credential to a key in a
  context the caller cannot act in would be a cross-tenant escape.

- **vta-vault**: Resolve mdoc issuers against configured IACA trust anchors ([#987](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/987))

Answers the one question mdoc asks differently from every other credential
  format here: which key do I trust to have issued this?

  Every other format names its issuer as a DID, so receiving resolves that DID
  and verifies against whatever comes back — the VTA holds no list and there is
  no operator step. An mdoc has no issuer DID. It carries an X.509 chain in the
  issuerAuth COSE unprotected header (x5chain, label 33): a Document Signer
  certificate issued by an IACA. Verifying it means the VTA must already hold the
  roots it accepts, which is a trust store, not a lookup.

  The decision taken is a configured set of IACA root certificates — how
  production EUDI verifiers work, and what Member State trusted lists (ETSI TS
  119 612) distribute. It keeps X.509 at the boundary: nothing below this module
  learns certificates exist, and receive_mdoc still takes a plain resolved key.

  Validation is scoped to what ISO 18013-5 Annex B actually specifies — a
  two-level IACA to Document Signer hierarchy, so no general RFC 5280 path
  building. Checks the leaf issuer DN against a configured anchor subject, the
  leaf signature against that anchor key, the leaf validity window, that the
  anchor is a CA (a DS certificate configured by mistake cannot become a root),
  and keyUsage.digitalSignature where present.

  Deliberately not checked, both documented in the module: revocation (CRL/OCSP
  needs egress and an unavailability policy — its own decision), and the ISO mDL
  EKU 1.0.18013.5.1.2, which the EUDI PID profile does not share, so enforcing it
  would reject valid PID credentials as what looks exactly like a trust failure.

  Fails closed. An empty anchor set is an error, not permissive — mdoc is the one
  format whose issuer is not a resolvable DID, so there is no safe default. The
  config field defaults to empty, so an existing config still loads and an upgrade
  neither breaks a deployment nor silently starts trusting mdocs.

  Anchors are inline PEM in [vault] rather than file paths: an enclave has no
  convenient filesystem, and inline values are covered by the effective-config
  digest boot attestation commits to, so a verifier can see which issuers a TEE
  VTA was trusting when it was attested.

  x509-parser takes the verify-aws feature rather than the default verify, which
  pulls ring — ring currently only reaches this workspace through a
  dev-dependency, while aws-lc-rs is already a real dependency. Same crypto, no
  new production tree.



## [0.1.4](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-vault-v0.1.3...vta-vault-v0.1.4) — 2026-08-16


### Added

- **vta-vault**: Verify and store ISO mdoc credentials on receive ([#986](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/986))

#984 gave mdoc a CredentialFormat identity but receive still refused it, because
  affinidi-mdoc had no way to turn a stored body back into an IssuerSigned. 0.2.6
  added that codec, so receive can now do the real work.

  Verifies three things per ISO 18013-5 S9.3.1, rejecting-without-storing on any
  failure: the issuerAuth COSE_Sign1 over the MSO, every item digest against the
  MSO valueDigests (a good signature over an MSO whose digests do not match means
  the items were swapped after signing), and the validityInfo window.

  issuer_pub is the caller-resolved Document Signer key — deliberately the same
  shape as the DI path's issuer key, and for the same reason: deciding *which*
  key to trust is policy that belongs to the wire layer. That seam matters more
  here, because mdoc anchors issuer trust in an X.509 chain (x5chain, COSE label
  33, rooted in an IACA) while this stack is DID-rooted end to end. Taking a
  resolved key keeps that unresolved question out of the storage layer instead of
  quietly settling it.

  ES256 only, checked explicitly before the signature so a mismatched algorithm
  is refused by name rather than failing as an opaque bad signature. ISO 18013-5
  and the EUDI profiles mandate ES256, which the VTA already has via
  KeyType::P256, so no new curve enters the graph.

  subject_did and issuer_did are left None: an mdoc binds to its holder through
  the MSO deviceKey, not a subject DID, and carries no issuer DID. Inventing
  either would put an unverifiable identifier into a secondary index.

  coset and time are declared as direct dependencies rather than used
  transitively through affinidi-mdoc — the receive path names their types, and
  depending on a transitive is how an unrelated version bump breaks a crate.

  DCQL matching and presentation are deliberately NOT in this change. dcql_format
  still returns None for mdoc: admitting it without a present_single arm trips
  formats_admitted_for_dcql_are_all_presentable, and that guard is right — a
  matched-but-unpresentable credential bails the entire vp_token, not just itself.
  Presenting an mdoc needs DeviceResponse::to_cbor_bytes (affinidi-mdoc 0.2.7,
  under review as affinidi/affinidi-tdk-rs#712), so matching and presentation land
  together in a follow-up.

- **vta-vault**: Give ISO mdoc a first-class CredentialFormat identity ([#984](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/984))

An mdoc arriving at the credential vault previously deserialised into the
  `Other(String)` escape hatch, so every downstream `match` treated one of
  the two eIDAS-mandated credential formats as an unknown vendor tag.

  Adds `CredentialFormat::MsoMdoc`, tagged `mso_mdoc` — the OpenID4VP
  `CredentialQuery.format` spelling, explicitly renamed rather than taking
  the enum's kebab-case `mso-mdoc`, so storage and protocol agree on one
  token. A test pins the exact bytes, not just the round-trip.

  Receive refuses an mdoc rather than storing a body it cannot re-read, and
  `dcql_format` returns `None` for it, keeping the existing matchable-implies-
  presentable invariant true. Both carry the reason: affinidi-mdoc 0.2.5 has
  no CBOR codec for `IssuerSigned` (it derives only Debug + Clone, with no
  Serialize/Deserialize and no to/from_cbor_bytes), so the body cannot be
  decoded, verified, or re-encoded for presentation. Wiring receive, DCQL
  matching and presentation is blocked on that codec landing upstream.

  The invariant guard in credential_exchange enumerates formats by hand, so
  MsoMdoc is added there too — otherwise a new variant is silently uncovered.



## [0.1.3](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vta-vault-v0.1.2...vta-vault-v0.1.3) — 2026-08-13


### Added

- **release**: Publish vta-service and its closure again ([#962](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/962))

* feat(release): publish vta-service and its closure again

  #938 unpublished `vta-service` and the twelve subsystem crates behind it,
  on the finding that nothing external depended on them. The audit read
  normal dependencies. `openvtc-core` depends on `vta-service` as a
  **dev-dependency**, for `test_support::MockVta` — an in-process VTA its
  end-to-end tests run against. That harness boots the real service, so no
  client crate can stand in for it.

  Unpublishing did not merely freeze the crate. It broke it.

  `vti-common` re-exports `vta_sdk::acl::{ActScope, ApproveScope,
  ContextDirection}` as its own public API, so **a re-export makes the
  re-exported crate's version part of your public API**: any graph
  combining `vti-common` with another `vta-sdk` consumer must resolve one
  `vta-sdk`. The frozen `vta-service` 0.14.37 asks for `vta-sdk ^0.21`
  while `vti-common` has moved to `^0.23`. A downstream `cargo update`
  resolves both and `vta-service` fails to compile with

    expected `vti_common::acl::ApproveScope`,
       found `vta_sdk::acl::ApproveScope`

  at ten call sites — which is how this surfaced, in openvtc #213. Nothing
  downstream can fix that; only a release that moves the requirements
  together can.

  So the thirteen manifests go back to the workspace default. The cost is
  the closure — twelve subsystem crates return to crates.io, which is
  exactly what #938 set out to stop. Taken deliberately over the
  alternatives: yanking the published copies breaks OpenVTC's tests with no
  replacement, and leaving them up ships a crate on the registry that
  cannot be built.

  **On release ordering.** `cargo publish --dry-run -p vta-service` fails
  today, and will until the closure is on the registry: packaging strips
  path deps, so `vta-keys = "0.2"` resolves the *published* 0.2.1, which
  still asks for `vta-sdk ^0.21` — two nodes, same error. That resolves
  itself in the release, which publishes in dependency order: every
  subsystem crate in this workspace already requires `vta-sdk = "0.23"`, so
  once they upload, `vta-service` verifies against them. Crates whose
  dependencies are all published already dry-run clean (verified on
  `vta-keyspaces` and `vta-config`).

  Docs updated to match: CLAUDE.md, RELEASING.md and the release-plz.toml
  header all said 7-of-21. They now say 20-of-26, name the six that stay
  internal, and record the rule the audit missed — check dev-dependencies,
  in sibling repos, before unpublishing anything.



### Build & CI

- **release**: Adopt release-plz, publish 7 crates instead of 21 ([#938](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/938))

Merging and releasing were the same act. publish.yml fired on every push to
  main and shipped whatever versions were newly present, and a CI guard required
  the version bump to live in the feature PR — so every PR was a release
  decision, taken by whoever opened it, days before it merged. Two open PRs
  touching one crate wrote the same number into the same line of the same
  Cargo.toml, and the second to merge had to rebase, renumber, and fix a
  changelog entry that had gone stale. #932/#936/#937 hit it three times in one
  afternoon.


