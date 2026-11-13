# `webauthn-vti-v1` — Data Integrity Cryptosuite

> **⚠ SUPERSEDED 2026-05-20.** This cryptosuite is no longer planned for
> implementation. WebAuthn-based authentication in this ecosystem follows
> the existing webvh-service pattern: assertion bytes are carried as
> trust-task **payload data**, verified by a standard WebAuthn library
> (webauthn-rs et al.) using DID-resolved VMs as the credential source.
> Embedded third-party Data Integrity proofs in payloads use existing
> standard cryptosuites (`eddsa-jcs-2022`, `ecdsa-jcs-2019`).
>
> What remains useful from this draft:
> - The **document-binding rule** (`clientData.challenge = SHA-256(canonical doc)`),
>   which migrates into the payload spec for `passkey-login-finish/1.0` and
>   any task that carries a WebAuthn assertion.
> - The VM resolution rules and error taxonomy, which inform the
>   per-task handler implementation.
>
> Retained for historical context. See the URI registry +
> `[[project-browser-plugin-rp-login]]` memory for current direction.

**Status:** Superseded by the embedded-proof-as-payload pattern (2026-05-20).
**Original status:** Draft (Phase 0.1 of the trust-task envelope migration initiative).
**Updated:** 2026-05-19; superseded 2026-05-20.
**Target framework version:** Trust Tasks 0.1 (`dtgwg-trust-tasks-tf`).
**Final home:** TBD — drafted in this design-notes folder; will propagate to
`dtgwg-trust-tasks-tf` once approved (location in that repo to be decided —
not under `specs/<slug>/<version>/` since that path is reserved for
trust-task specs, which this isn't).
**Verifier implementation:** `trust-tasks-proof::webauthn::WebauthnExtendedVerifier`.

## Abstract

The `webauthn-vti-v1` cryptosuite binds a [Trust Task](https://trusttasks.org/)
or [W3C Verifiable Credential](https://www.w3.org/TR/vc-data-model-2.0/) to a
**WebAuthn assertion** produced by a FIDO2/CTAP2 authenticator (platform
passkey, security key, etc.). The assertion's public key is identified by a
`verificationMethod` in a DID document — typically enrolled there ahead of
time via a DID-controller-side ceremony.

The cryptosuite is designed so that:

- The signing party never exports a private key; the WebAuthn authenticator
  signs locally.
- Verification requires only the holder's resolvable DID document plus the
  assertion bytes — no trusted intermediary, no live call to the
  authenticator.
- The full trust-task / VC document is bound to the assertion, so tampering
  with any field after signing invalidates the proof.

## Status of this document

This is a **draft** specification. The wire shape MAY change without notice
until status reaches `candidate`. Feedback via the project issue tracker.

## Conformance

[RFC 2119](https://www.rfc-editor.org/rfc/rfc2119) and
[RFC 8174](https://www.rfc-editor.org/rfc/rfc8174) key-word conventions
apply.

A *conforming verifier* **MUST** implement §[Verification](#verification)
in full. A *conforming signer* **MUST** implement §[Signing](#signing) in
full and produce proofs that any conforming verifier accepts.

## Identifier

```
cryptosuite: "webauthn-vti-v1"
```

The identifier appears in the `cryptosuite` field of a
`DataIntegrityProof`. The version segment (`-v1`) is part of the
identifier itself, not a separate field; future revisions are new
identifiers (`webauthn-vti-v2`, etc.), not version bumps.

## Algorithm selection

The signature algorithm is determined by the `verificationMethod`'s
public-key encoding, not by a separate field in the proof. The verifier
resolves the VM, reads the multikey, and selects the algorithm from the
multicodec prefix:

| Multicodec | Public-key type | Signature algorithm | Status |
|---|---|---|---|
| `0x1200` | P-256 | ES256 (ECDSA over P-256 with SHA-256) | **REQUIRED** |
| `0xed01` | Ed25519 | EdDSA (Ed25519, Ed25519ph not used) | OPTIONAL (forward-compat; uncommon in WebAuthn today) |

A conforming verifier **MUST** accept ES256. EdDSA support is OPTIONAL.
Any other multicodec **MUST** be rejected with
`unsupported_cryptosuite_algorithm`.

Multikey encoding follows
[W3C Multibase](https://www.w3.org/TR/cid-1.0/#multibase) +
[multicodec](https://github.com/multiformats/multicodec): the
`publicKeyMultibase` field is `z` (base58btc) followed by the multicodec
varint prefix and the raw public key bytes (33 bytes compressed for
P-256, 32 bytes for Ed25519).

## Signing

A signer follows this procedure to produce a proof:

1. **Construct the unsigned document.** Build the Trust Task (or VC)
   with a `proof` member containing every field EXCEPT `proofValue`.
   The `proof` member's required fields are:
   - `type`: `"DataIntegrityProof"`
   - `cryptosuite`: `"webauthn-vti-v1"`
   - `verificationMethod`: the URL of the VM in the holder's DID
     document (e.g. `did:webvh:vta.example.com:alice#passkey-abc`)
   - `proofPurpose`: typically `"authentication"`
   - `created`: ISO-8601 timestamp at signing time
   - `challenge`: a fresh verifier-issued nonce
   - `domain`: the verifier identifier (typically a DID or a URL)

2. **Canonicalise.** Apply
   [RFC 8785 JCS](https://www.rfc-editor.org/rfc/rfc8785)
   canonicalisation to the document. The resulting bytes are the
   *canonical document bytes*.

3. **Compute the WebAuthn challenge.** The challenge passed to
   `navigator.credentials.get()` is the SHA-256 hash of the canonical
   document bytes:

   ```
   webauthn_challenge = SHA-256(canonical_document_bytes)
   ```

   This binds the WebAuthn assertion to the *entire document*, not
   just the verifier's nonce. Tampering with any field (including
   `proof.challenge` itself) invalidates the assertion.

4. **Invoke the authenticator.** Call:

   ```js
   navigator.credentials.get({
     publicKey: {
       challenge: webauthn_challenge,         // 32 bytes
       allowCredentials: [{ id: credentialId, type: "public-key" }],
       userVerification: "preferred",         // or "required" per policy
       rpId: <expected RP ID>,                // e.g. "control.example.com"
     }
   })
   ```

   Receive an `AuthenticatorAssertionResponse` containing
   `authenticatorData`, `clientDataJSON`, and `signature`.

5. **Encode `proofValue`.** Encode the assertion as a CBOR map and
   wrap in [multibase](https://www.w3.org/TR/cid-1.0/#multibase) with
   the `u` prefix (base64url, no padding):

   ```
   proofValue = "u" || base64url-nopad(CBOR.encode({
     "authenticatorData": <bytes from authenticatorData>,
     "clientDataJSON":    <bytes from clientDataJSON>,
     "signature":         <bytes from signature>
   }))
   ```

   CBOR map keys are byte strings; values are byte strings.

6. **Splice `proofValue` into the document.** Set `proof.proofValue`
   to the string from step 5. The document is now signed.

## Verification

A verifier follows this procedure on receipt of a document:

1. **Extract and validate proof shape.**
   - `proof.type` **MUST** equal `"DataIntegrityProof"`.
   - `proof.cryptosuite` **MUST** equal `"webauthn-vti-v1"`.
   - `proof.proofPurpose` **MUST** equal the proof purpose required
     for this context (typically `"authentication"`).
   - `proof.verificationMethod`, `proof.challenge`, `proof.domain`,
     `proof.created`, `proof.proofValue` **MUST** all be present.
   - Reject `malformed_proof` if any check fails.

2. **Resolve the verification method.** Resolve the DID portion of
   `proof.verificationMethod` and locate the VM whose `id` matches.
   - VM **MUST** be of type `Multikey`.
   - VM's controller **MUST** match the document's `issuer` (or
     `holder`, depending on the proofPurpose).
   - Reject `verification_method_not_found` if the VM doesn't exist
     in the DID document.

3. **Decode the public key.** Parse the `publicKeyMultibase` value.
   - Strip the `z` multibase prefix and base58btc-decode.
   - Read the multicodec varint prefix.
   - Select the signature algorithm per §[Algorithm selection](#algorithm-selection).
   - The remaining bytes are the raw public key.
   - Reject `unsupported_cryptosuite_algorithm` for unknown multicodecs.

4. **Decode `proofValue`.**
   - **MUST** start with `u`. Strip and base64url-nopad decode.
   - **MUST** be a valid CBOR map.
   - **MUST** contain exactly the keys `"authenticatorData"`,
     `"clientDataJSON"`, `"signature"`, each mapping to a byte
     string.
   - Reject `malformed_proof` on any failure.

5. **Reconstruct the canonical document bytes.** Take the inbound
   document, set `proof.proofValue` to absent (or remove the
   `proofValue` member from the proof), and apply JCS to the
   resulting document. These are the canonical document bytes the
   signer used in §Signing step 2.

6. **Parse `clientDataJSON`.** Parse as UTF-8 JSON.
   - `clientDataJSON.type` **MUST** equal `"webauthn.get"`. Reject
     `proof_invalid` (with `details.reason: "wrong_clientdata_type"`).
   - `clientDataJSON.origin` **MUST** equal the verifier's expected
     origin (the verifier's domain, normalised to `https://<host>[:port]`,
     no trailing slash). Reject `proof_invalid` (`wrong_origin`).
   - `clientDataJSON.challenge` (base64url-decoded) **MUST** equal
     `SHA-256(canonical_document_bytes)` from step 5. This is the
     document-binding check. Reject `proof_invalid` (`challenge_mismatch`).

7. **Parse `authenticatorData`.**
   - **MUST** be at least 37 bytes (rpIdHash 32 + flags 1 + signCount 4).
   - `rpIdHash` (first 32 bytes) **MUST** equal `SHA-256(rpId)` where
     `rpId` is the verifier's expected RP ID (e.g. `control.example.com`,
     no scheme, no port, no path). Reject `proof_invalid` (`wrong_rp_id`).
   - The UP (user presence) flag (bit 0 of the flags byte) **MUST**
     be set. Reject `proof_invalid` (`user_presence_missing`).
   - If the verifier requires user verification, the UV flag (bit 2)
     **MUST** be set. Reject `proof_invalid` (`user_verification_missing`).
   - `signCount` (next 4 bytes, big-endian) MAY be used for
     monotonicity tracking; see §[Sign-counter handling](#sign-counter-handling).

8. **Reconstruct the signed message.** Concatenate:

   ```
   message = authenticatorData || SHA-256(clientDataJSON_bytes)
   ```

   where `clientDataJSON_bytes` is the exact byte sequence parsed in
   step 6, not a re-canonicalised form.

9. **Verify the signature.**
   - For ES256: verify `signature` is a DER-encoded ECDSA signature
     over `message` using the P-256 public key. The signature
     **MUST** be in `(r, s)` DER form as produced by WebAuthn (not
     raw concatenation). Reject `signature_invalid` on failure.
   - For EdDSA: verify `signature` is a 64-byte Ed25519 signature
     over `message` using the Ed25519 public key. Reject
     `signature_invalid` on failure.

10. **Check `proof.challenge` freshness.** This is the verifier's
    server-side replay defence — separate from the document-binding
    in step 6. The verifier looks up `proof.challenge` against its
    issued-nonce store; **MUST** reject `proof_invalid`
    (`challenge_replayed`) if the nonce has been seen before or is
    not in the store. **MUST** mark the nonce consumed on success.

11. **Check `proof.domain`.** **MUST** equal the verifier's
    self-identifier (typically the verifier's DID). Reject
    `proof_invalid` (`wrong_domain`).

12. **Check `proof.created` freshness.** **MUST** be within an
    implementation-defined skew window (typically ±5 minutes). Reject
    `proof_invalid` (`stale_proof`) if outside.

If all steps succeed, the proof is valid. The signer (the holder of
the VM's private key) is authenticated as the document's `issuer`
(or `holder`).

## clientDataJSON contents — full reference

WebAuthn produces `clientDataJSON` as a UTF-8 JSON document with the
following fields:

| Field | Required | Verifier action |
|---|---|---|
| `type` | yes | MUST equal `"webauthn.get"` |
| `challenge` | yes | base64url-decoded MUST equal SHA-256(canonical_doc) |
| `origin` | yes | MUST equal verifier's expected origin |
| `crossOrigin` | no | MAY be false; if true, reject unless cross-origin is allowed by deployment |
| `topOrigin` | no | If present and `crossOrigin == true`, MUST equal the verifier's parent origin per [WebAuthn L3 §5.8.1](https://www.w3.org/TR/webauthn-3/#dictdef-collectedclientdata) |
| `tokenBinding` | no | Deprecated; ignore |

Browsers MAY add additional fields. The verifier **MUST NOT** reject a
`clientDataJSON` solely for containing unknown fields (forward
compatibility).

## authenticatorData layout

Per WebAuthn L3, the byte layout is:

```
+----------+------+-----------+
|  rpIdHash | flag | signCount |
|   32 B    | 1 B  |   4 B     |
+----------+------+-----------+
[ optional: attestedCredentialData | extensions ]
```

Authentication assertions (as opposed to enrolment) typically do not
include `attestedCredentialData` (the AT flag is unset). The verifier
**MUST NOT** require `attestedCredentialData` for assertions.

Flags byte:

| Bit | Name | Meaning |
|---|---|---|
| 0 | UP | User Present — MUST be 1 |
| 2 | UV | User Verified — MUST be 1 if verifier requires UV |
| 3 | BE | Backup Eligible — informational (passkey is sync-eligible) |
| 4 | BS | Backup State — informational (passkey is currently backed up) |
| 6 | AT | Attested credential data included — MUST be 0 for assertions |
| 7 | ED | Extension data included — MAY be 0 or 1 |

## Sign-counter handling

Passkeys synced via iCloud Keychain, Google Password Manager, etc.
typically return `signCount: 0` on every assertion (the counter can't
be reliably maintained across synced replicas). Hardware-backed
authenticators (YubiKey, etc.) maintain a strictly-increasing counter.

A conforming verifier **SHOULD**:

- Track the last-seen `signCount` per credential.
- If a credential has ever reported `signCount > 0`, treat it as a
  hardware-backed authenticator and reject any subsequent assertion
  where the new count is less than or equal to the stored count
  (`signature_invalid` with `details.reason: "counter_regression"`).
- If a credential has only ever reported `signCount: 0`, treat it as
  a synced credential and skip counter checks.

Replay defence does NOT rely on `signCount` — the document-binding
check (step 6) and `proof.challenge` freshness (step 10) are
authoritative.

## Verification method resolution rules

The VM **MUST** be of type `Multikey` per the
[W3C Controller Document specification](https://www.w3.org/TR/cid-1.0/).
The `publicKeyMultibase` value **MUST** decode to a P-256 (33-byte
compressed) or Ed25519 (32-byte) public key per the multicodec table
above.

The VM's `purpose` (or `proofPurpose` in some DID method profiles)
**SHOULD** include `authentication`. A verifier MAY enforce this
strictly; doing so **MUST** be reported as `proof_invalid`
(`wrong_proof_purpose`) on failure.

When the holder's DID document publishes multiple VMs, the verifier
**MUST** locate the VM by exact match on the `id` field
(`#fragment` portion of `proof.verificationMethod`), not by iterating
or matching on key material.

## Error taxonomy

The following codes map verification failures to the Trust Tasks
framework error vocabulary ([SPEC.md §8](https://github.com/trustoverip/dtgwg-trust-tasks-tf/blob/main/SPEC.md)):

| Suite code | Framework code | Retryable | Meaning |
|---|---|---|---|
| `webauthn-vti-v1:malformed_proof` | `malformed_proof` | no | `proofValue` couldn't be decoded, missing fields, wrong types |
| `webauthn-vti-v1:verification_method_not_found` | `verification_method_not_found` | no | VM URL doesn't resolve in the DID document |
| `webauthn-vti-v1:unsupported_cryptosuite_algorithm` | `unsupported_cryptosuite` | no | Multicodec prefix unknown |
| `webauthn-vti-v1:wrong_clientdata_type` | `proof_invalid` | no | clientData.type ≠ "webauthn.get" |
| `webauthn-vti-v1:wrong_origin` | `proof_invalid` | no | clientData.origin mismatch |
| `webauthn-vti-v1:challenge_mismatch` | `proof_invalid` | no | clientData.challenge ≠ SHA-256(canonical_doc) |
| `webauthn-vti-v1:wrong_rp_id` | `proof_invalid` | no | authenticatorData.rpIdHash mismatch |
| `webauthn-vti-v1:user_presence_missing` | `proof_invalid` | no | UP flag unset |
| `webauthn-vti-v1:user_verification_missing` | `proof_invalid` | no | UV flag unset when required |
| `webauthn-vti-v1:counter_regression` | `proof_invalid` | no | signCount ≤ stored for hardware-backed credential |
| `webauthn-vti-v1:signature_invalid` | `signature_invalid` | no | Cryptographic signature verification failed |
| `webauthn-vti-v1:challenge_replayed` | `proof_invalid` | no | proof.challenge previously consumed or not issued |
| `webauthn-vti-v1:wrong_domain` | `proof_invalid` | no | proof.domain ≠ verifier identity |
| `webauthn-vti-v1:stale_proof` | `proof_invalid` | no | proof.created outside skew window |

## Test vectors

Concrete test vectors will land in
`dtgwg-trust-tasks-tf/specs/test-vectors/webauthn-vti-v1/` as part of
Phase 1.2. The set **MUST** cover:

- Valid assertion → verifies.
- Valid assertion with EdDSA key → verifies.
- Mutated `proofValue` (any byte flipped) → `signature_invalid`.
- Mutated document body (any field changed) → `signature_invalid`
  (via challenge mismatch path).
- Wrong `clientData.type` → `wrong_clientdata_type`.
- Wrong `clientData.origin` → `wrong_origin`.
- Wrong `clientData.challenge` → `challenge_mismatch`.
- Wrong `rpIdHash` → `wrong_rp_id`.
- UP flag unset → `user_presence_missing`.
- UV flag unset when required → `user_verification_missing`.
- Counter regression on hardware credential → `counter_regression`.
- VM not in DID document → `verification_method_not_found`.
- Unknown multicodec → `unsupported_cryptosuite_algorithm`.
- Replayed `proof.challenge` → `challenge_replayed`.
- Stale `proof.created` → `stale_proof`.

Each vector is a triple `(input_document, expected_outcome, notes)`
stored as JSON. The input includes a fully-populated DID document the
verifier uses for VM resolution (no network access required during
testing).

## Security considerations

### What this cryptosuite protects against

- **Tampering with the document.** Any change to any field after
  signing invalidates the signature because the WebAuthn challenge is
  SHA-256 of the canonical document. There is no separate "signed
  fields" subset — everything is signed.
- **Replay of the WebAuthn assertion.** `proof.challenge` is a
  verifier-issued nonce that the document is canonicalised over;
  reusing the assertion against a different document fails the
  challenge-mismatch check; reusing against the same document fails
  the nonce-store check.
- **Cross-RP confusion.** `clientData.origin` and
  `authenticatorData.rpIdHash` both pin the assertion to a specific
  verifier identity. An assertion produced for `control.example.com`
  cannot be replayed against `other.example.com`.
- **Authenticator substitution.** The public key is fixed in the DID
  document; only signatures from the corresponding private key
  verify. Enrolling a malicious VM would itself require an
  authenticated DID-document update — out of scope for this suite,
  in scope for the controller's DID-method security model.

### What this cryptosuite does NOT protect against

- **Authenticator-side compromise.** If the FIDO2 authenticator is
  compromised (root on a phone, malware extracting from Windows
  Hello, physical YubiKey theft + UV bypass), this suite cannot
  defend the user.
- **Phishing of `clientData.origin`.** WebAuthn binds `origin` to the
  authenticator. The TLS layer and browser must enforce that the
  origin string is the real verifier's origin. We rely on standard
  browser behaviour here.
- **Compromised DID document.** If the holder's DID method (e.g.
  `did:web`, `did:webvh`) is compromised at the registry/host level,
  an attacker may inject a malicious VM. Defence is the DID method's
  registry security, not this suite.
- **Stale public-key material.** If the verifier caches the DID
  document, a revoked VM may continue to verify until the cache
  refreshes. Verifiers **SHOULD** bound the cache lifetime relative
  to the security requirements (e.g. ≤5 minutes for
  high-value operations).

### Cryptographic agility

The version suffix `-v1` is the suite's identity. A future
`webauthn-vti-v2` would change the message construction, the
canonicalisation, or the algorithm selection — not bump the version
of `webauthn-vti-v1`. The `v1` suite is frozen at first
implementation; non-breaking clarifications are issued as errata.

## Privacy considerations

- `clientDataJSON.origin` is in the signed proof; anyone inspecting
  the proof learns which verifier the assertion was produced for.
- The credential ID is implied by the chosen VM (`#passkey-abc` etc.)
  but the VM is already published in the DID document, so the
  credential ID isn't a new disclosure.
- `authenticatorData.signCount` is in the signed proof. For
  hardware-backed authenticators this may leak activity frequency.
  For synced passkeys it's always 0 and leaks nothing.
- The user's biometric / PIN data never leaves the authenticator;
  the WebAuthn assertion contains no raw biometric template.

## References

- [WebAuthn Level 3 (W3C Editor's Draft)](https://www.w3.org/TR/webauthn-3/) — the assertion format, `clientDataJSON` rules, `authenticatorData` layout.
- [FIDO2 / CTAP 2.1](https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html) — authenticator-side spec.
- [W3C VC Data Model 2.0](https://www.w3.org/TR/vc-data-model-2.0/) — Data Integrity proof shape.
- [W3C Data Integrity 1.0](https://www.w3.org/TR/vc-data-integrity/) — cryptosuite framing.
- [W3C Controller Document 1.0](https://www.w3.org/TR/cid-1.0/) — Multikey VM encoding, multibase prefixes.
- [Multicodec](https://github.com/multiformats/multicodec) — algorithm-prefix table.
- [RFC 8785: JSON Canonicalization Scheme (JCS)](https://www.rfc-editor.org/rfc/rfc8785) — canonicalisation algorithm.
- [Trust Tasks framework SPEC.md](https://github.com/trustoverip/dtgwg-trust-tasks-tf/blob/main/SPEC.md) — document envelope, proof field shape.
- [RFC 7515: JSON Web Signature](https://www.rfc-editor.org/rfc/rfc7515) — base64url-no-padding encoding rules.
- [RFC 8949: CBOR](https://www.rfc-editor.org/rfc/rfc8949) — proofValue inner format.

## Open questions

1. **Does the framework's `Proof` type accept any structure other than a multibase string for `proofValue`?** This spec assumes yes (multibase + CBOR). If the framework requires plain multibase byte-string with no structured inner format, switch to a fixed-layout binary encoding (length-prefixed). Confirm with `trust-tasks-rs::Proof` type before implementation.
2. **EdDSA support in WebAuthn-enrolled passkeys.** Are there real-world authenticators we expect to encounter that enrol with Ed25519? If not, drop EdDSA from §Algorithm selection until forward-compat actually matters. Recommendation: keep optional, low cost.
3. **`proofPurpose` strictness.** Verifier behaviour when `proof.proofPurpose` is something other than `"authentication"` — strict reject, or allow `"assertionMethod"` for some use cases (e.g. signing a non-auth artifact)? Implementation choice; spec says SHOULD.
4. **Origin normalisation.** Browsers may produce `https://example.com` or `https://example.com:443` for the default port. The verifier needs a normalisation rule. Recommendation: strip default port (443 for https), require lowercase host, require https scheme. Add an explicit normalisation paragraph after question is closed.
