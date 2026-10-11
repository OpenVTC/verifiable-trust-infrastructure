# The VTC as an OpenID4VP verifier for swiyu and EUDI wallets

Status: design, not implemented
Tracking: OpenVTC/verifiable-trust-infrastructure#1988 (item 4, "plain HTTPS OID4VCI/VP bindings")
Scope: **verification only.** Issuing into these wallets is a later, separate project.
Companions: `vti-credential-architecture.md` (D1, §6, §14, open question 6),
`docs/03-vtc/credentials.md` (*Reading another issuer's status*)

## Why

#1988 asked for a swiyu or EUDI wallet to talk to a VTC directly: "admit a member
on the strength of a swiyu credential". The pieces that *read* such a credential
are done — ES256/ES256K issuer signatures, P-256 `cnf.jwk` holder binding,
`did:web`/`did:webvh` issuers, the IETF Token Status List (#2010, TDK #932,
#2015). What is missing is the conversation a wallet expects: OpenID4VP 1.0 over
HTTPS. Today the VTC speaks OID4VP only as payloads inside
`credential-exchange/*` Trust Tasks, between two parties that each have a DID
agent. A swiyu or EUDI wallet has no DID agent, signs no Trust Task, and receives
no pushed document.

## Decisions taken

1. **Verifier only.** Issuance into wallets is deferred; for EUDI it is gated on
   Member State registration and X.509 issuer certificates anyway.
2. **swiyu and EUDI together.** One OID4VP 1.0 verifier core; two ways for the
   VTC to identify itself (a DID for swiyu, an X.509 access certificate for EUDI).
3. **A wallet credential is evidence on a join** (Option A), not a membership on
   its own. The applicant still joins with their OpenVTC/VTA DID; the join opens
   a presentation session bound to them, and the wallet presents into it. A
   wallet-only member could neither sign in nor sign a Trust Task, and would need
   the issuance and wallet sign-in work deferred above.
4. **The verifier core is built in the TDK**, by bringing `affinidi-openid4vp`
   to OpenID4VP 1.0 and adding the JOSE it lacks, so both ecosystems and any
   other TDK consumer share it.
5. **Key policy.** The VTA may mint **P-256 and secp256k1** keys for
   foreign-protocol identities, still VTA-held. This work uses P-256 only: both
   ecosystems require ES256. The VTC's own DID and everything else the workspace
   mints stay Ed25519 / X25519.
6. **Each VTC is its own verifier.** A wallet trusts the party it presents to, so
   registration with swiyu or an EUDI registrar is per VTC operator, not
   Affinidi's. VTI supplies the tooling; the operator does the registering.

## What the wallets require (as of October 2026)

| | swiyu | EUDI |
|---|---|---|
| Profile | OID4VP 1.0 + JAR (RFC 9101), DCQL only; SD-JWT VC draft-15, `dc+sd-jwt`; Token Status List; not HAIP | HAIP 1.0: OID4VP 1.0, DCQL, `dc+sd-jwt` and `mso_mdoc`, Token Status List, W3C Digital Credentials API |
| Verifier identity | `client_id = decentralized_identifier:<did:webvh>`; the JAR `kid` is that DID's `#key`, a P-256 `publicKeyJwk`. The DID is registered in the swiyu Base Registry and follows the Swiss Profile Anchor (no services, `profile_version`) | `client_id = x509_hash:<b64url SHA-256 of the leaf DER>`; JAR header carries `x5c`, the access certificate chaining to an Access CA on the trusted list. DIDs are not accepted |
| Request | Signed JAR (`typ: oauth-authz-req+jwt`, ES256, `aud: https://self-issued.me/v2`, header `profile_version`), passed by `request_uri`, fetched with GET | Signed JAR by `request_uri` (GET; POST optional) |
| Why the wallet trusts the verifier | Identity Trust Statement (and optionally a Verification Query Public Statement) from the swiyu trust registry, carried in `verifier_info` | Registration certificate (WRPRC) in `verifier_info`; the wallet checks the requested attributes against it |
| Response | `direct_post.jwt`, mandatory encryption: ECDH-ES on P-256, A256GCM; `client_metadata.jwks` per request | `direct_post.jwt`: ECDH-ES on P-256, A128GCM and A256GCM |
| Invocation | `openid4vp://` or `swiyu-verify://` QR / deep link | `haip-vp://`, `openid4vp://`, `eudi-openid4vp://`; DC API |
| Issuer trust | Issuer's Identity Trust Statement; issuer key from the JWT `kid` (`did#key`); status lists on the federal (FOITT) status registry | Issuer key from `x5c`, against a trust anchor (the PID list, or a per-Rulebook anchor for other credentials) |
| Holder binding | P-256 in hardware, `cnf.jwk`, ES256 KB-JWT, `aud` = verifier `client_id` | Same |

Test environments: swiyu Public Beta (`*.swiyu-int.admin.ch`, the Sandbox wallet,
`swiyu-generic-test-wallet`); EUDI test registry
(`registry.serviceproviders.eudiw.dev`, which issues test access and registration
certificates) and the open-source reference wallets.

## Where we start from

- **Verifying the credential: mostly there.** `vtc-service`'s `verify_vp_token`
  verifies SD-JWT VCs (issuer EdDSA/ES256/ES256K by `kid`, KB-JWT with `aud` and
  `nonce`, holder = the `did:key` of `cnf.jwk`) and reads the Token Status List
  signed by the credential's issuer.
- **Speaking OID4VP 1.0: absent.** No authorization request, `request_uri`, JAR,
  `response_uri` or `direct_post` handling anywhere; the VTC has no `.well-known`
  routes; `prepare_join_query` says outright it is "not OID4VP over HTTP".
- **TDK: types, not a server.** `affinidi-openid4vp` 0.1.3 is pre-1.0 apart from
  its DCQL model (`dcql.rs`, sound and 1.0-shaped). It has no JAR, no client_id
  prefixes, no `response_uri`, no `direct_post.jwt` encryption, no 1.0 `vp_token`
  map type and no verifier-side DCQL check. `affinidi-oid4vc-core` has compact
  JWS (ES256, EdDSA) and nothing else of JOSE. `affinidi-sd-jwt` hardcodes the
  issuer `typ` and does not check the KB-JWT `typ`, its `iat`, or an array `aud`.
- **The VTC signs only with Ed25519 / ML-DSA.** The `vtc-host` DID has no P-256
  key.

## Design

### Shape of a presentation

```
Applicant (OpenVTC / VTA)        VTC                                  Wallet
 │ vtc/.../wallet-session/start ─▶ create session: nonce, state,
 │   (signed Trust Task)            ephemeral ECDH P-256 key, DCQL
 │ ◀── { session, walletUri } ──    from the criterion; bind to the
 │                                  applicant DID + join request
 │ shows QR (walletUri) ─────────────────────────────────────────────▶ scans
 │                                  ◀── GET request_uri ──────────────
 │                                  ── signed JAR ───────────────────▶ consent,
 │                                                                      select
 │                                  ◀── POST response_uri ────────────
 │                                       response=<JWE>
 │                                  decrypt, verify, record evidence
 │ vtc/.../wallet-session/status ─▶ ◀── 200 { redirect_uri? } ────────▶
 │ ◀── { state, evidence } ──
```

- **The session is started by the applicant**, in a signed Trust Task, so it is
  bound to the applicant DID from the document proof and to the join request or
  criterion it serves. Starting and reading a session are Trust Tasks; only the
  two wallet-facing calls are HTTPS endpoints (below).
- **The DCQL query comes from the criterion** the applicant is working to satisfy
  (the join manifest already publishes it, under the member name
  `presentationDefinition`), so what the wallet is asked for is what the community
  published.
- **The result is evidence on the join**: "the party holding wallet key K
  presented credential C, satisfying query Q", recorded against the applicant's
  join request. It feeds the same criteria evaluation the `present` path feeds
  today. The applicant's identity stays their DID; the wallet's `did:key` is
  recorded beside it, never instead of it.

### The verifier core (TDK)

In `affinidi-openid4vp` (brought to 1.0) and `affinidi-oid4vc-core`:

- **Authorization request**: typed 1.0 fields (`response_uri`, `dcql_query`,
  `client_metadata` with `jwks` and `encrypted_response_enc_values_supported`,
  `verifier_info`, `request_uri_method`), and a builder that produces the signed
  JAR — `typ: oauth-authz-req+jwt`, `aud`, header `kid` *or* `x5c`, any extra
  header members a profile needs (swiyu's `profile_version`). Signing goes
  through a signer trait, so the key never has to be in the TDK's hands.
- **client_id prefixes**: `decentralized_identifier:` and `x509_hash:` (computed
  from the leaf certificate), with `x509_san_dns:` beside them as it costs little.
- **JOSE**: ES256 signing, and JWE decryption for `ECDH-ES` (direct key
  agreement, P-256) with `A128GCM` and `A256GCM`, plus per-request ephemeral key
  generation and its JWK. Algorithms are allow-listed by the caller, never read
  from the token alone.
- **Response**: parse `direct_post.jwt` (form-encoded `response`), decrypt,
  check `state`, and type the 1.0 `vp_token` map
  (`{ <credential_query_id>: [presentation, …] }`).
- **Verifier-side DCQL**: given the query and the verified presentations, decide
  whether each credential query and `credential_sets` is satisfied — format,
  `meta` (`vct_values`), requested claims and values. `dcql.rs` matches on the
  wallet side; this is its mirror.
- **SD-JWT VC**: accept `typ` `dc+sd-jwt` (and, for now, legacy `vc+sd-jwt`); on
  the KB-JWT check `typ: kb+jwt`, `iat` freshness, and `aud` as a string or array.
- **mdoc is out of scope** for the first release (swiyu does not use it; EUDI PID
  is also offered as SD-JWT VC). The existing `Handover::Oid4vp` in
  `affinidi-mdoc` does not match OID4VP 1.0 Appendix B and would need fixing
  before mdoc is added.

The TDK owns no HTTP, sessions or storage. It is the protocol and the crypto;
the VTC is the server.

### Verifier identities (VTA)

A VTC may hold **two** verifier identities, configured independently:

- **swiyu** — a separate `did:webvh` minted by the VTA from a new DID template
  following the Swiss Profile Anchor: one P-256 key as a `publicKeyJwk`, no
  services, no `keyAgreement`, `profile_version` where the profile requires it.
  The VTC's own DID cannot be used: the Base Registry refuses `services`,
  `keyAgreement` and `publicKeyMultibase`. The operator registers it in the swiyu
  Base Registry and obtains its Identity Trust Statement.
- **EUDI** — a P-256 key minted by the VTA, a certificate signing request built
  from it, and the access certificate the operator's registrar issues for it,
  plus the registration certificate. The VTC config holds the certificate chain
  and the registration certificate.

Both keys are VTA-minted, `attestation`-role keys (VTI-KEY-080) cached by the
VTC like its other keys; the VTA's signing endpoint already signs ES256. Neither
identity is the VTC's own DID, and neither signs anything but OID4VP requests.

### Wallet-facing endpoints (VTC)

| | Endpoint | Body |
|---|---|---|
| Request | `GET /v1/oid4vp/request/{session}` | `application/oauth-authz-req+jwt`: the signed JAR, built when the session is created. Answered once per session; a second fetch is refused |
| Response | `POST /v1/oid4vp/response/{session}` | `application/x-www-form-urlencoded`, `response=<JWE>`. Answers `200 {}`, or `{ "redirect_uri": … }` with a fresh `response_code` for a same-device flow |

- **A declared foreign-protocol exception.** OID4VP is an OAuth-family protocol
  whose wire the wallet fixes. Both endpoints get rows in the VTC's
  `REST_EXCEPTIONS` (naming the session Trust Tasks as their twin) and in
  `GOVERNED_UNAUTH`, exactly as the WebAuthn ceremony routes are declared.
  Starting and reading sessions stay Trust Tasks.
- **Unauthenticated, so bounded.** Per-address rate limit; the session id is
  unguessable and single-use; the JWE decrypts only under that session's
  ephemeral key, so garbage fails before any parsing; the session expires in
  minutes. The response body cap is per route and configurable — swiyu tells
  verifiers to plan for responses up to 21 MB, far above the VTC's usual cap.
- **Session state** lives in a new VTC keyspace with a TTL sweeper: applicant
  DID, join request, criterion, DCQL, nonce, state, which identity signed, the
  ephemeral private key (encrypted at rest, deleted when the session closes) and
  the outcome. It is excluded from backup.

### Verifying a response

In order, stopping at the first failure:

1. The session exists, is open, and has not received a response (single use).
2. Decrypt under the session's ephemeral key (`ECDH-ES`, allow-listed `enc`);
   `state` matches.
3. Each presentation in `vp_token`: issuer signature by the issuer's key
   (swiyu: `kid` DID URL; EUDI: `x5c` chain to a configured trust anchor), validity
   window, Token Status List, then the KB-JWT — `nonce` equals the session nonce
   and `aud` equals the session's `client_id` *with its prefix*
   (VTI-CRD-020, -022), and the holder key is the credential's `cnf.jwk`
   (VTI-CRD-021).
4. Issuer trust, per ecosystem and per criterion: the criterion's
   `credentialIssuers`, plus swiyu's trust registry or the EUDI trust anchors.
5. The verifier-side DCQL check: the presentations satisfy the query.
6. Record the evidence on the join request and close the session.

Steps 3 and 5 reuse `verify_vp_token` and the TDK check; only the issuer-key path
for `x5c` is new on the VTC.

## Requirements this has to meet

- **VTI-OPS-001/002** forbid a second, parallel interface. The two endpoints
  are a *binding* of the presentation operation to the wallet's protocol, and the
  session tasks remain the catalogue's way in; the VTI specification needs a line
  saying a foreign-protocol binding of this kind is a binding and not a parallel
  interface. That goes to `dtgwg-vti-spec` first, or into its divergence
  register.
- **VTI-CRD-020…023** — audience is the prefixed `client_id`, the challenge is
  the single-use session nonce bound to this verifier, possession is the KB-JWT
  under `cnf.jwk`, and nothing is accepted without it.
- **VTI-CRD-002, -010…014** — issuer resolvable (DID or certificate chain);
  status read and never defaulted to valid.
- **VTI-KEY-080, -013** — the new keys are attestation-role and VTA-held;
  widening the accepted algorithms makes the open retirable-algorithms divergence
  more pressing.
- **Credential architecture.** `vti-credential-architecture.md` resolved Q5 as
  "keys are always VTA-managed … a device-held binding key is out of scope", and
  left Q6 (an OID4VP profile for external wallets) open. Both are revised: the
  *member's* keys stay VTA-managed, and a device-held key appears only as the
  holder of presented evidence. Q6 resolves to this note.

## Risks

- **Cross-device relay.** Anyone who sees the QR code can present *their* own
  credential into the applicant's session. This is inherent to cross-device
  OID4VP. Mitigations: the request shows the community and the purpose; sessions
  last minutes and take one response; same-device flow is offered; a criterion
  may require review for wallet evidence; a criterion may require a claim to
  match something the applicant declared.
- **Registration is per operator** and outside our control. Without it the
  verifier works with test wallets and in sandboxes, and production wallets warn
  or refuse. swiyu eligibility for non-Swiss operators is unconfirmed. An EUDI
  registration certificate pins the attributes a VTC may request, so join
  criteria have to stay inside it.
- **Moving profiles.** swiyu's profiles are "draft – technically complete", and
  its wallets do not yet enforce every rule (the published gap list). The
  identity layer is kept per ecosystem so a profile change touches one place.
- **The swiyu DID lives in the Base Registry**, not on our WebVH hosting; how its
  log is created and updated alongside the VTA's key custody needs confirming
  against the Swiss Profile Anchor before the template is written.

## Plan

| Phase | Where | What |
|---|---|---|
| P0 | specs, docs | `dtgwg-vti-spec`: foreign-protocol bindings vs VTI-OPS-002. `dtgwg-trust-tasks-tf`: the session start/status tasks. This note; `vti-credential-architecture.md` Q5/Q6; the CLAUDE.md key-policy exception |
| P1 | TDK | OID4VP 1.0 request/response types, JAR builder, client_id prefixes, verifier-side DCQL, ES256 signing, ECDH-ES + A128GCM/A256GCM decryption, SD-JWT `dc+sd-jwt` and KB-JWT checks |
| P2 | VTA | P-256 (and secp256k1) minting for foreign-protocol identities; the swiyu-profile DID template; CSR generation for an EUDI access certificate |
| P3 | VTC | Session keyspace and sweeper; the two endpoints and their exception rows; session Trust Tasks; JAR signing through the cached key; response verification; evidence recorded on the join and read by criteria evaluation; `x5c` issuer keys |
| P4 | VTC, console, cnm | Per-identity configuration: the swiyu trust statement and trusted issuer DIDs; the EUDI certificates, registration certificate and trust anchors. Console QR and status; operator docs for registering with each ecosystem |
| P5 | test | swiyu Public Beta with the Sandbox wallet and `swiyu-generic-test-wallet`; EUDI test registry certificates with the reference wallet |

## Found along the way (issuance, not this work)

The VTC's current pre-authorized issuance is not standard OID4VCI, which matters
only when issuance into wallets is taken up: the pre-authorized code doubles as
the proof nonce (no token or nonce endpoint), `credential_issuer` is a DID rather
than an https URL, a proof carrying only a `jwk` header (what wallets send) is
refused, the subject is fixed before the offer is made, and
`POST /v1/credential-exchange/request` accepts a bare payload where the
`credential-exchange/request/0.1` specification requires a document proof.
