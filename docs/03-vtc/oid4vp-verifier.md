# OpenID4VP verifier identities

A swiyu or EUDI wallet presents credentials only to a verifier it can identify:
the request it receives must be signed by a key the wallet's ecosystem
recognises. That identity is not the community's own DID — swiyu wants a
`did:webvh` in its Base Registry, shaped by the Swiss Profile Anchor, with a
P-256 key; EUDI wants an X.509 access certificate. So a VTC that verifies
wallet presentations holds a separate **verifier identity**, minted by its VTA.

This page covers getting a swiyu verifier identity onto a VTC. The design is
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

## Backups

`oid4vp_keys` is in the backup. Its rows are encrypted under the storage key,
which restoring the same key bundle reproduces, so a restored VTC keeps its
verifier identities.

## Not yet

- Answering wallets: the request and response endpoints, and the join
  integration, come next (P3 of the design note).
- EUDI: the X.509 access certificate — a certificate request built from a
  VTA-held key, and the issued chain and registration certificate.
- Keeping the key in the VTA instead (`keys/sign-jws`), for a deployment that
  wants it never to leave.
