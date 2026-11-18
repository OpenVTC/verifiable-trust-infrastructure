# CLAUDE.md — vta-signing

The signing core shared by the VTA and by services that sign with their own
keys. Read the workspace `CLAUDE.md` first; this file is what is specific here.

## Rules

- **Stay a leaf.** No dependency on another crate of this workspace, no async,
  no I/O, no logging, no storage. A caller that needs any of those wraps this
  crate; it does not go in it.
- **Everything that signs does it through `Signer`.** A format has `prepare_*`
  (what is signed), `finish_*` (the artefact) and `sign_*` (both with a
  `Signer`), and a test that the phases and the one call give identical output.
  The VTA signs through its own audited step between `prepare_*` and `finish_*`.
- **Bytes are built from the request, never chosen by the caller.** A refusal
  signs nothing. Raw signing exists only as `Signer::sign` and through
  `SigningDomain::Opaque`, which frames the payload.
- **A moved format keeps its bytes.** Golden vectors (the specification's JWS
  example, the OpenSSH signature) and RFC 8032 / RFC 6979 determinism are the
  evidence; `vta-service`'s `sign_characterization_tests` pins the VTA's outputs.
- **`FormatRefusal` is exhaustive on purpose**: the VTA maps every variant to a
  wire code and wants the compiler to fail when one is added. Adding a variant
  is a breaking change. Everything else that may grow is `#[non_exhaustive]`.
- **No secret material in `Debug`, `Display`, errors or test names.**
