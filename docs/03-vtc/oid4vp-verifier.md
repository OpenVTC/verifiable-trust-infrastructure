# OpenID4VP verifier identities

A swiyu or EUDI wallet presents credentials only to a verifier it can identify:
the request it receives must be signed by a key the wallet's ecosystem
recognises. That identity is not the community's own DID — swiyu wants a
`did:webvh` in its Base Registry, shaped by the Swiss Profile Anchor, with a
P-256 key; EUDI wants an X.509 access certificate. So a VTC that verifies
wallet presentations holds a separate **verifier identity**, minted by its VTA.

This page covers getting a swiyu or EUDI verifier identity onto a VTC, and the
wallet sessions it serves. The design is
`docs/05-design-notes/oid4vp-wallet-verifier.md`.

## What lives where

- **The VTA** mints the identity's keys, as it mints every key this VTC holds.
  For swiyu: an Ed25519 update key that signs the DID's log (kept out of the
  DID document, as the profile requires) and a P-256 key that signs OpenID4VP
  request objects. For EUDI: one P-256 key, which the access certificate
  certifies and which signs the request objects.
- **The VTC** caches the P-256 key and signs with it locally, so a wallet's
  request never waits on the VTA — or, if you prefer the key never to leave
  the VTA, signs through it instead (see *Keeping the key in the VTA*). It lives in the `oid4vp_keys` keyspace,
  encrypted at rest under the storage key, and is loaded at boot — a record
  that does not load stops the boot. It is never added to the credential
  signer: that key would otherwise put a proof on every credential the
  community issues.
- **The swiyu Base Registry** hosts the DID's log. swiyu wallets do not accept a
  self-hosted one.
- **Your EUDI registrar** issues the access certificate (and the registration
  certificate) for the EUDI identity's key. The VTC keeps the chain beside the
  key.

## A swiyu identity

You need: a swiyu business-partner account with a reserved identifier-registry
slot (its URL is what the swiyu API returns as `identifierRegistryUrl`), and an
admin on the VTA. Give the identity a context of its own — the minted DID
becomes that context's primary DID, which is what `pnm keys bundle` exports.

1. **On the VTC host**, with the daemon stopped, write a request for the key:

   ```sh
   vtc oid4vp request --identity swiyu --out swiyu-request.json
   ```

   Its private half stays in the VTC's data directory (`oid4vp/swiyu.request-key`,
   mode 0600) until the bundle is installed.

2. **On the admin workstation**, mint the identity at the slot URL and seal its
   keys to the request:

   ```sh
   pnm contexts create --id swiyu-verifier --name "swiyu verifier"
   pnm did-mgmt dids create --context swiyu-verifier --template swiyu-verifier \
     --did-url https://identifier-reg.trust-infra.swiyu-int.admin.ch/api/v1/did/<slot-uuid>
   ```

   The template makes the DID non-portable whatever `--portable` says, as the
   profile requires. It prints the DID's log entry: save it as `did.jsonl` and
   upload it to the slot with your swiyu API token
   (`PUT …/identifier-entries/<id>`, `application/jsonl+json`).
   Then:

   ```sh
   pnm keys bundle swiyu-verifier --recipient swiyu-request.json > swiyu.armor
   ```

   Carry the digest it prints to the VTC host separately from the bundle.

3. **On the VTC host**, still stopped:

   ```sh
   vtc oid4vp install --identity swiyu --bundle swiyu.armor --digest <digest>
   ```

   The bundle must open with the request's key and match the digest; the
   P-256 key must be a verification method of the bundle's DID, and its
   private half must be the key the DID publishes. When the identity's DID
   publishes more than one P-256 key, name the request-signing one with
   `--kid`.

4. **Its trust statements.** Complete swiyu's trust onboarding for the DID
   (the Service Portal), after which the trust registry publishes an
   **Identity Trust Statement** about it. Fetch it, and any **Protected
   Verification Authorization** statement you were granted, and install them,
   still with the daemon stopped:

   ```sh
   curl -s https://trust-reg.trust-infra.swiyu-int.admin.ch/api/v2/identity-trust-statement/<did> > idts.jwt
   vtc oid4vp trust-statement --identity swiyu --file idts.jwt
   ```

   Each is checked before it is stored: it must be a swiyu trust statement
   about this identity's DID and not yet expired. Every request object then
   carries them in `verifier_info` (Trust Protocol 2.0), the identity
   statement first, which is where a wallet reads it. Installing a newer one
   replaces the one of its kind; `vtc oid4vp list` shows each with its expiry.
   An expired statement is left out of requests, with a warning in the log —
   renew it before then. Without an identity statement the request still goes
   out, and the wallet cannot say who is asking.

   The VTC checks what the statement says, not who signed it: the wallet
   verifies its signature against the trust registry, and so would refuse a
   forged one. A Verification Query Public Statement is not accepted yet (see
   *Not yet*).

5. Start the VTC. Its log names the verifier identities it loaded.

## An EUDI identity

An EUDI wallet identifies a relying party by its X.509 access certificate,
issued by an Access CA on the wallet's trusted list: `client_id` is
`x509_hash:<base64url SHA-256 of the certificate>`, and each request object
carries the certificate chain as `x5c`. There is no DID.

You need: a registration with an EUDI registrar (for testing, the EU's
reference registry at `registry.serviceproviders.eudiw.dev` issues test
certificates), and an admin on the VTA.

1. **On the VTC host**, with the daemon stopped:

   ```sh
   vtc oid4vp request --identity eudi --out eudi-request.json
   ```

2. **On the admin workstation**, mint a P-256 key and seal it to the request:

   ```sh
   pnm keys create --key-type p256 --context eudi-verifier --label eudi-verifier
   pnm keys bundle-key <key id> --recipient eudi-request.json --out eudi.armor
   ```

   `bundle-key` seals one key that no DID publishes, as `pnm keys bundle` seals
   a DID's. The VTA audits the export. Carry the printed digest separately.

3. **On the VTC host**, still stopped, install the key and write the
   certificate signing request:

   ```sh
   vtc oid4vp install --identity eudi --bundle eudi.armor --digest <digest>
   vtc oid4vp csr --identity eudi --common-name "Example Community" \
     --organization "Example e.V." --organization-identifier VATDE-123456789 \
     --country DE --dns vtc.example.org --out eudi.csr
   ```

   The request is signed by the identity's own key, which is the proof of
   possession a registrar asks for. Your registrar decides what the issued
   certificate finally says.

4. **Submit `eudi.csr` to your registrar.** Install what it issues — the
   access certificate, then each issuer in turn, in one PEM file — and, if it
   gave you one, the registration certificate:

   ```sh
   vtc oid4vp certificate --identity eudi --chain eudi-chain.pem \
     --registration-certificate eudi-wrprc.jwt --registration-format <format>
   ```

   The chain is refused if its first certificate does not certify the
   identity's key, is outside its validity window or may not sign, if any
   certificate is not signed by the one after it, or if it is a single
   self-signed certificate. A self-signed root at the end is left out of `x5c`:
   the wallet holds its trust anchors already. The registration certificate is
   carried in every request's `verifier_info` as `{ "format": <format>,
   "data": <file contents> }`; give the format identifier your ecosystem
   names for it. A wallet checks the claims a request asks for against it, so
   join criteria the EUDI identity serves have to stay inside what it
   registers.

5. Start the VTC.

Until step 4, the identity opens no session (`verifierNotConfigured`). An
applicant's agent chooses it with `clientIdPrefix: "x509_hash"` on the start
task; its wallet link is `haip-vp://?client_id=…&request_uri=…`, and the
response may be encrypted with `A128GCM` or `A256GCM`. When the certificate is
renewed, run `vtc oid4vp certificate` again with the new chain; a new key
needs a new `request` and `install`, and then a new certificate.

## Keeping the key in the VTA

Instead of `request` and `install`, an identity can name a key the VTA keeps.
Every request object is then signed by the VTA through `keys/sign-jws`, over
the VTC's TSP or DIDComm link to it, and the VTC holds no private key. The cost
is a VTA round trip on each wallet session's start, and a VTA that must be
reachable for one to start.

1. **On the admin workstation**, mint the identity as above — for swiyu the
   `swiyu-verifier` DID, for EUDI a P-256 key — and note the key's id and
   public key (`pnm keys list --context <context>`). Let this VTC sign with it:

   ```sh
   pnm acl create --did <the VTC's DID> --role application --contexts <context> \
     --capabilities sign-jws
   ```

   `sign-jws` is a capability of its own; the VTA does not accept `sign` for
   it. For EUDI, request the access certificate there too — the VTC has no key
   to sign the request with:

   ```sh
   pnm keys sign-csr <key id> --country DE --organization "Example e.V." \
     --organization-identifier VATDE-123456789 --common-name "Example Community" \
     --dns vtc.example.org --out eudi.csr
   ```

2. **On the VTC host**, with the daemon stopped:

   ```sh
   # swiyu
   vtc oid4vp attach --identity swiyu --vta-key <key id> --public-key <zDn…> \
     --did <the swiyu DID> --kid <the DID's verification method for that key>
   # EUDI
   vtc oid4vp attach --identity eudi --vta-key <key id> --public-key <zDn…>
   vtc oid4vp certificate --identity eudi --chain eudi-chain.pem
   ```

   The VTC needs `vta_did` in its configuration. A VTC with such an identity and
   no `vta_did` does not start.

3. Start the VTC. Each JWS the VTA returns is checked against the identity's
   public key before a wallet sees it; a VTA that refuses (an entry without
   `sign-jws`, say) refuses the session's start, with the reason in the log.

`vtc oid4vp list` shows where each identity's key is held.

## Managing identities

`vtc oid4vp list` shows what is installed, with each identity's `client_id`
(`decentralized_identifier:<did>` or `x509_hash:<hash>`);
`vtc oid4vp remove --identity <name>` removes one. Installing again under the
same name replaces it, certificate included.

## Wallet sessions

With an identity installed, an applicant can collect evidence for a join
criterion from their wallet. The wallet speaks OpenID4VP 1.0 and signs no Trust
Task, so the applicant's own agent opens the exchange for it:

1. The applicant signs `vtc/join-requests/wallet-session/start/0.1`, naming the
   criterion by the `requirementsDigest` the manifest publishes (and, if they
   have one, the join request the evidence is for). The criterion must ask for
   an SD-JWT VC (`dc+sd-jwt`).
2. The VTC answers with a `walletUri` — `swiyu-verify://?client_id=…&request_uri=…`
   for a swiyu identity, `haip-vp://…` for an EUDI one — which the applicant
   shows as a QR code or opens as a deep link. With both installed, the
   applicant's `clientIdPrefix` chooses; without one, `default_identity`, else
   the first installed.
3. The wallet fetches the signed request object from
   `GET /v1/oid4vp/request/{session}` (answered once), asks its holder, and
   posts the encrypted answer to `POST /v1/oid4vp/response/{session}`
   (accepted once).
4. The applicant polls `vtc/join-requests/wallet-session/status/0.1` until the
   session is `presented`, `refused` or `expired`.

The request object asks for the criterion's published query and nothing else,
names the community (`client_name`, from `vtc_name`) so the holder sees whom
they are presenting to, and is signed ES256 by the identity's key — under
swiyu's profile (`kid`, `profile_version`) or with the EUDI access certificate
chain (`x5c`, plus `verifier_info`), with `aud` `https://self-issued.me/v2`.
The response is `direct_post.jwt`, encrypted to a P-256 key made for that
session alone (`A256GCM` for swiyu; `A128GCM` or `A256GCM` for EUDI); the key
is dropped when the session closes.

A response is accepted only if, in order: it decrypts and echoes the session's
`state`; each presentation's issuer signature, validity window and key-binding
JWT verify, the KB-JWT naming the session nonce and the prefixed `client_id`;
every credential's status is valid; every issuer is one the criterion's
`credentialIssuers` admits; and the presentations satisfy the query. The status
task then reports the evidence — the wallet's holder key, recorded beside the
applicant and never as them, and each credential's query id, format, issuer and
type. It never returns a claim value. A refusal reports which check failed.

### Issuers known by a certificate

An EUDI credential — the PID, or one a Rulebook governs — is not issued by a
DID. Its `iss` is an `https` URL and its issuer JWS names the signing key by an
`x5c` certificate chain. The VTC trusts such an issuer only through the trust
anchors you configure:

```toml
[oid4vp]
x509_trust_anchors = ["/etc/vtc/eudi-pid-providers.pem"]
```

Each file holds one or more PEM certificates (for the PID, the providers'
anchors from the EU trusted list; for a Rulebook, its own). They are read at
boot, and a file that is missing or holds no certificate stops it. A
credential's chain is accepted only if:

- it ends at one of those anchors (or at a certificate an anchor signed);
- every certificate in it is valid now, and each is signed by the next;
- every certificate above the leaf is a CA, and the leaf may sign;
- the leaf names the issuer: a subject-alternative-name `URI` equal to `iss`,
  or a `dNSName` equal to its host.

Its Token Status List must be signed the same way, by a chain to the same
anchors whose leaf names the same issuer, or its status is unknown and the
credential is refused. With no anchors configured, no certificate-named issuer
is trusted.

Such an issuer is neither this community nor one it recognises, so it meets
only a criterion whose `credentialIssuers` is `any`. Keep that criterion to the
credential you mean — its query's `vct_values`, say, the PID's type — and the
anchors to the issuers you mean: `any` admits every issuer whose credential
verifies, DIDs included. The same anchors apply to a credential a member's
agent presents on the credential-exchange path.

To narrow one credential query to the issuers a particular authority
certifies — the PID providers among several anchors, say — give it
`trusted_authorities` of type `aki`, with the authority's key identifier
(base64url) as the value:

```json
{
  "id": "pid",
  "format": "dc+sd-jwt",
  "meta": { "vct_values": ["urn:eudi:pid:1"] },
  "trusted_authorities": [{ "type": "aki", "values": ["s9tIpPmhxdiuNkHMEWNpYim8S8Y"] }]
}
```

The wallet uses it to choose a credential, and the VTC holds it: a credential
meets the query only if one of the values is the key identifier of a CA in its
issuer's chain, up to and including the anchor. That chain must still end at a
configured anchor; `trusted_authorities` narrows the anchors, never adds one. A
DID issuer has no chain, so it meets no such query; a credential that fails one
on a wallet session is refused `issuerNotTrusted`.

Only `aki`, and only on a `dc+sd-jwt` query, is accepted. A criterion asking
for `etsi_tl` or `openid_federation`, or with `trusted_authorities` on another
format, is refused when registered, not published to the wallet and then
ignored.

### What the evidence does for the join

Wallet evidence counts toward the criterion its session was opened for, and no
other. It is bound to the applicant by the session, not by a key: the wallet's
holder key is recorded beside the applicant DID, never as it.

- **With `requestId`**, the evidence is recorded on that request. A `deferred`
  request — typically one waiting for exactly this credential — is decided
  again at once, on its own presentation plus the wallet evidence, under the
  criterion it was decided under, as a supplement would be. A `pending`
  request is under review: the evidence is recorded for the reviewer and
  nothing is decided underneath them.
- **Without `requestId`**, it is held for the applicant's next submission
  (`evidence_hold_secs`, six hours by default) and counts there if the
  submission is decided under that criterion. The session is then bound to
  the new request, which the status task reports, and the evidence is recorded
  on it. Unclaimed evidence is discarded when the hold lapses.

A later supplement replaces the request's presentation but keeps its wallet
evidence: that was recorded on the request, not presented in the VP.

Both wallet endpoints are unauthenticated, as OpenID4VP requires, and sit
behind the unauthenticated rate limit. The session id is unguessable and
single-use, and a response decrypts only under its session's key.

Settings (`[oid4vp]`, all optional):

```toml
[oid4vp]
session_ttl_secs = 600          # how long a session waits for a wallet
max_open_sessions = 3           # per applicant
evidence_hold_secs = 21600      # unbound evidence kept for a submission
max_response_bytes = 4194304    # the largest wallet response accepted
# default_identity = "swiyu"    # when the applicant names no prefix
# wallet_uri_scheme = "openid4vp"
# x509_trust_anchors = ["/etc/vtc/eudi-pid-providers.pem"]
```

The VTC needs an `https` `public_url` for wallets to reach; without one no
session opens (`verifierNotConfigured`). Sessions live in the `oid4vp_sessions`
keyspace, encrypted at rest and excluded from backup; a sweeper closes
unanswered ones at `expiresAt` and drops records an hour after they close, or
when their held evidence lapses.

## Backups

`oid4vp_keys` is in the backup. Its rows are encrypted under the storage key,
which restoring the same key bundle reproduces, so a restored VTC keeps its
verifier identities. `oid4vp_sessions` is not: a session lasts minutes.

## Not yet

- swiyu Verification Query Public Statements: one describes a single query,
  and the swiyu Profile pairs it with `scope`, where the VTC sends each
  criterion's DCQL query. Statements are installed by hand, not fetched and
  renewed from the trust registry.
- swiyu issuer trust from the trust registry (an issuer's Identity Trust
  Statement); a swiyu issuer is trusted as any DID issuer is, through the
  criterion's `credentialIssuers`.
- `trusted_authorities` of type `etsi_tl` or `openid_federation`: the VTC does
  not read ETSI trusted lists or resolve OpenID Federation trust chains.
