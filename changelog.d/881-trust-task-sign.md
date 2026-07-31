### vta-sdk 0.20.30 — one holder-signing primitive for Trust Task documents (#881)

Both VTI services authenticate a holder-submitted Trust Task the same way: verify
its `eddsa-jcs-2022` Data-Integrity proof with a **`did:key`-only** resolver
(`vti_common::auth::di_proof`) and take the proof's `verificationMethod` DID as
the proven signer. That is the whole authentication for the VTC's `POST
/trust-tasks` holder surface (join submit / manifest / status) and for both
services' canonical REST login.

The *signing* side had been written three times — `auth_di`, the
provision-client's VP signer, and `vta-mobile-core` — each handling JCS
presence-sensitivity slightly differently. That is a bad thing to have three of:
a mistake in it produces a signature that verifies nowhere, and the failure is
opaque at every call site.

**New `vta_sdk::trust_task_sign`** (feature `client`): `build_unsigned`,
`sign_in_place`, `build_signed`. It enforces by construction the two invariants
that are easy to get wrong —

- **Sign the proof-less document.** `eddsa-jcs-2022` canonicalises via JCS, which
  is presence-sensitive, and the verifier strips `proof` before checking.
- **Set `recipient`.** SPEC §4.8.2 audience binding rejects a signed document
  with no in-band recipient; it is also the replay defence that stops a document
  signed for one community being posted to another.

`auth_di` now builds on it and keeps its public API unchanged, except that its
signing-failure variants collapse into `AuthDiError::Sign(TrustTaskSignError)` —
`NotDidKey` / `BadPrivateKey` / `TypeUri` move to the shared error, which renders
the same text. No behaviour change; the auth suites are unmodified apart from the
two tests that were purely about the signing primitive and now live beside it.
