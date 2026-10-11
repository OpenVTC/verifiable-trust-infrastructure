# OpenID4VP verifier identities

A swiyu or EUDI wallet presents credentials only to a verifier it can identify:
the request it receives must be signed by a key the wallet's ecosystem
recognises. That identity is not the community's own DID — swiyu wants a
`did:webvh` in its Base Registry, shaped by the Swiss Profile Anchor, with a
P-256 key; EUDI wants an X.509 access certificate. So a VTC that verifies
wallet presentations holds a separate **verifier identity**, minted by its VTA.

This page covers getting a swiyu verifier identity onto a VTC, and the wallet
sessions it serves. The design is
`docs/05-design-notes/oid4vp-wallet-verifier.md`.

## What lives where

- **The VTA** mints the identity and its keys, as it mints every key this VTC
  holds: an Ed25519 update key that signs the DID's log (kept out of the DID
  document, as the profile requires) and a P-256 key that signs OpenID4VP
  request objects.
- **The VTC** caches the P-256 key and signs with it locally, so a wallet's
  request never waits on the VTA. It lives in the `oid4vp_keys` keyspace,
  encrypted at rest under the storage key, and is loaded at boot — a record
  that does not load stops the boot. It is never added to the credential
  signer: that key would otherwise put a proof on every credential the
  community issues.
- **The swiyu Base Registry** hosts the DID's log. swiyu wallets do not accept a
  self-hosted one.

## Steps

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

4. Start the VTC. Its log names the verifier identities it loaded.

`vtc oid4vp list` shows what is installed, with each identity's `client_id`
(`decentralized_identifier:<did>`); `vtc oid4vp remove --identity swiyu` removes
one. Installing again under the same name replaces it.

## Wallet sessions

With an identity installed, an applicant can collect evidence for a join
criterion from their wallet. The wallet speaks OpenID4VP 1.0 and signs no Trust
Task, so the applicant's own agent opens the exchange for it:

1. The applicant signs `vtc/join-requests/wallet-session/start/0.1`, naming the
   criterion by the `requirementsDigest` the manifest publishes (and, if they
   have one, the join request the evidence is for). The criterion must ask for
   an SD-JWT VC (`dc+sd-jwt`).
2. The VTC answers with a `walletUri` — `swiyu-verify://?client_id=…&request_uri=…`
   for a swiyu identity — which the applicant shows as a QR code or opens as a
   deep link.
3. The wallet fetches the signed request object from
   `GET /v1/oid4vp/request/{session}` (answered once), asks its holder, and
   posts the encrypted answer to `POST /v1/oid4vp/response/{session}`
   (accepted once).
4. The applicant polls `vtc/join-requests/wallet-session/status/0.1` until the
   session is `presented`, `refused` or `expired`.

The request object asks for the criterion's published query and nothing else,
names the community (`client_name`, from `vtc_name`) so the holder sees whom
they are presenting to, and is signed ES256 by the identity's key under swiyu's
profile (`profile_version`, `aud` `https://self-issued.me/v2`). The response is
`direct_post.jwt`, encrypted to a P-256 key made for that session alone with
`A256GCM`; the key is dropped when the session closes.

A response is accepted only if, in order: it decrypts and echoes the session's
`state`; each presentation's issuer signature, validity window and key-binding
JWT verify, the KB-JWT naming the session nonce and the prefixed `client_id`;
every credential's status is valid; every issuer is one the criterion's
`credentialIssuers` admits; and the presentations satisfy the query. The status
task then reports the evidence — the wallet's holder key, recorded beside the
applicant and never as them, and each credential's query id, format, issuer and
type. It never returns a claim value. A refusal reports which check failed.

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

- Deciding a join on wallet evidence: it is recorded on the session, and
  feeding it into the join request (with `requestId`) or the applicant's next
  submission (without) comes next.
- swiyu trust statements in `verifier_info`, and swiyu's trusted issuers.
- EUDI: the X.509 access certificate — a certificate request built from a
  VTA-held key, and the issued chain and registration certificate.
- Keeping the key in the VTA instead (`keys/sign-jws`), for a deployment that
  wants it never to leave.
