# vti-vetting-pcs

Hidden-vetter admission for Verifiable Trust Communities, on the
[Predicate Credential System](https://crates.io/crates/predicate-credential-system).

An applicant proves, in zero knowledge, that enough distinct eligible vetters of a
community vetted them; the community learns nothing about which vetters did.

- **Community side** — `issuer` (class credentials, the attestation-token drip) and
  `verifier` (the proof, turned into the facts the community's admission policy counts).
- **Member side** — the `vetter` and `applicant` engines. A VTA runs them as its
  principal's PCS engine (the `vta/pcs/*` Trust Tasks), so the client never holds a PCS key.

Feature `harness` adds `vtc::Vtc`, an in-process community for end-to-end tests.
