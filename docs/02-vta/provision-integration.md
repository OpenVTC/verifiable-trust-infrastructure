# Provision-Integration

A single path for standing up any VTA-managed integration — DIDComm
mediators, webvh-hosting servers, custom template-driven services —
against a VTA that may be online, offline, or air-gapped at the
integration's first boot.

This chapter covers both the **operator how-to** (three transports,
phase-by-phase walkthrough) and the **wire-format reference** (VP
shape, sealed payload shape, VC shape) in one place. Operators can
stop reading after [Operating](#operating); engineers and auditors
should continue into [Wire format](#wire-format) and beyond.

---

## What it is

The integration's operator ends up with an armored sealed bundle
that contains:

- A VTA-issued VC stating the integration's admin authorization at the VTA.
- Private key material for any DIDs the VTA minted on the integration's
  behalf (rendered from a DID template the operator named).
- Any template-produced side outputs the integration needs to boot
  (e.g. `did.jsonl` for webvh DIDs, DIDComm service-endpoint config).
- The VTA's own trust material (DID doc + log) so the integration can
  verify the bundle contents offline.

Three transports carry the same VP-and-sealed-bundle exchange:

1. **File** — air-gapped / offline at *both* ends. Operator
   hand-carries the request and the bundle as files between two
   disconnected hosts.
2. **REST** — PNM-bridged. Operator runs `pnm bootstrap
   provision-integration` from a REST-connected `pnm` session.
   Pass `--create-context` to create the target context inline
   if it doesn't already exist (super-admin only; idempotent).
3. **DIDComm** — same `pnm bootstrap provision-integration`
   command when the operator's `pnm` is connected via DIDComm.
   `VtaClient::provision_integration` dispatches based on how
   the client was constructed.

The sealed bundle returned is identical across all three. Both
REST and DIDComm support the **operator-as-relayer** flow.

### Auth model — onion layers

The authentication model is layered the same way on both
transports:

* **Outer (transport):** the *relayer* is authenticated by the
  bearer token (REST) or the authcrypt sender DID (DIDComm). The
  VTA's ACL gates whether the relayer is allowed to call
  `provision-integration` against the target context.
* **Inner (VP):** the *holder* is authenticated by the
  BootstrapRequest's `DataIntegrityProof`. The VTA HPKE-seals
  the issued bundle to the holder's X25519 derivation, so only
  the holder can open it.

Relayer and holder may legitimately differ. The canonical
example is **air-gap onboarding**: a third-party integration on
a disconnected network signs a BootstrapRequest using its own
ephemeral did:key, transfers the request to the operator's host,
the operator's PNM relays it to the VTA over DIDComm (or REST),
and the operator carries the (encrypted) bundle back across the
air-gap. The relayer doesn't gain anything — they can't decrypt
the bundle, and the VP signature requires the holder's private
key, so they can't forge a VP claiming to be a third party.

The only authorization gate is the relayer's ACL membership in
the target context. It is enforced identically on both
transports.

The sealed bundle returned is identical across all three. Only the
transport differs.

## Preconditions

The provisioning call fails fast (400) if any of these aren't already
true at the VTA:

1. **The target context exists.** `provision-integration` doesn't
   create contexts — that's `vta context provision`'s job. The
   integration lands *inside* an existing context.
2. **The template named in the request is registered.** The error
   suggests the fix: `template '{name}' is not registered on this
   VTA. Register it via 'pnm did-templates upload {name} --file
   <path>' then retry.`
3. **The calling operator has admin role in the target context.** ACL
   check is `require_admin` with `allowed_contexts` containing the
   target. Super-admin passes through.

Integrations do not rotate keys on their own. The VTA mints the
integration's signing and key-agreement keys once, at provisioning
time, and the integration uses them for the lifetime of the DID. If a
rotation is ever needed — compromised key, operator policy — it's an
admin operation: revoke the old ACL entry and run
`provision-integration` again with a fresh request.

## Built-in templates

Pick the template that matches the integration's deployment role.
Each template emits one fixed DID-document shape — there is no
conditional logic in the renderer, so the template name is a
1:1 promise of what comes out.

| Template | DID-document services | Required vars (renderer) | Required at provision time | Use for |
|---|---|---|---|---|
| `didcomm-mediator` | `DIDCommMessaging` URL endpoint | `URL` | — | DIDComm v2 routing mediator |
| `did-hosting-control` | `WebVHHosting` + `DIDCommMessaging` | `URL`, `MEDIATOR_DID` | `URL` or `WEBVH_SERVER` | Control-plane node — hosts DID logs **and** accepts DIDComm (admin RPC, witness coordination, control-plane traffic) |
| `did-hosting-daemon` | `WebVHHosting` only | `URL` | `URL` or `WEBVH_SERVER` | Pure hosting daemon — publishes DID logs over HTTP, no DIDComm. If you also need DIDComm, use `did-hosting-control` |
| `did-hosting-server` | `DIDCommMessaging` only | `MEDIATOR_DID` | `URL` or `WEBVH_SERVER` | Witness, watcher, or any service consumed via DIDComm only — no public HTTP endpoint |
| `vta-admin` | (none) | (none) | — | Long-term admin DID for `--admin-template` rollover |

Legacy `webvh-control` / `webvh-daemon` / `webvh-server` names are still
accepted at the wire level and resolve to the renamed templates for one
release; update operator configs to the canonical `did-hosting-*` names
before the alias is removed.

"Required at provision time" applies in addition to the renderer's
`requiredVars`. Any webvh-method template needs to know where its
`did.jsonl` log will be published — pass `--var URL=<host>` for
serverless mode, or `--var WEBVH_SERVER=<id>` to route through a
hosting server registered with `vta did-mgmt servers add`.

---

## Operating

### When to use which transport

| Scenario | Transport |
|---|---|
| First-time setup of a brand-new VTA + first mediator on isolated hosts | **File** |
| Adding an integration to an existing VTA, file-based ops pipeline | **File** |
| VTA reachable over HTTPS from an authenticated PNM workstation | **REST** |
| Already-admin DID provisioning further integrations in the same context | **DIDComm** |

Pick by what the operator has access to, not by what the VTA
supports — all three pass through the same shared library function.

### The principle

- `vta setup` stands up a VTA with no integrations. Done in
  isolation, no network, no dependencies.
- `vta bootstrap provision-integration` runs as a **local CLI**
  against the VTA's own keystore on disk — no HTTP server, no
  DIDComm, no live mediator. Same shared library function that backs
  the REST route; only the I/O differs.
- The integration emits a signed VP request, the VTA produces a
  sealed bundle, the integration opens it. Three files move between
  the two hosts.

Once both endpoints are running and the operator has a hosting
server live, every DID's `did.jsonl` can be published there. Until
then, both DIDs self-host their own logs. No circular dependency.

### File-transport flow

```
┌──────────────────────────┐            ┌──────────────────────────┐
│  Integration host        │            │  VTA host                │
│  (future mediator /      │            │  (already `vta setup`)   │
│   DID-hosting server)          │            │                          │
└──────────────────────────┘            └──────────────────────────┘
            │                                        │
  ┌─────────▼─────────┐                              │
  │ 1. generate VP    │                              │
  │  request.vp.json  │                              │
  │  (signs with      │                              │
  │   ephemeral       │                              │
  │   did:key)        │                              │
  └─────────┬─────────┘                              │
            │     request.vp.json                    │
            └──────────────────────────► ┌───────────▼───────────┐
                                         │ 2. provision-         │
                                         │    integration:       │
                                         │    mint keys, render  │
                                         │    template, issue    │
                                         │    VC, seal bundle    │
                                         └───────────┬───────────┘
            ┌──────────────────────────────── bundle.armor + digest
            │
  ┌─────────▼─────────┐
  │ 3. open bundle    │
  │  verify digest,   │
  │  unseal, install  │
  │  keys + trust     │
  │  bundle + log     │
  └───────────────────┘
```

### Phase 1 — Generate the request (integration host)

On the host that will run the mediator (or DID-hosting server, or whatever).
No VTA contact, no network.

**Mediator example:**

```bash
vta bootstrap provision-request \
    --template       didcomm-mediator \
    --var            URL=https://mediator.example.com \
    --context-hint   mediator-prod \
    --admin-template vta-admin \
    --validity-hours 168 \
    --label          mediator-prod-bootstrap \
    --out            mediator-request.vp.json
```

**did-hosting-daemon example** (hosts DID logs over HTTP, no DIDComm):

```bash
vta bootstrap provision-request \
    --template       did-hosting-daemon \
    --var            URL=https://webvh.example.com \
    --context-hint   webvh-host-prod \
    --admin-template vta-admin \
    --validity-hours 168 \
    --out            webvh-host-request.vp.json
```

**did-hosting-control example** (hosts DID logs **and** accepts DIDComm —
admin RPC, witness coordination, etc.):

```bash
vta bootstrap provision-request \
    --template       did-hosting-control \
    --var            URL=https://webvh.example.com \
    --var            MEDIATOR_DID=did:webvh:mediator.example.com \
    --context-hint   did-hosting-control-prod \
    --admin-template vta-admin \
    --validity-hours 168 \
    --out            did-hosting-control-request.vp.json
```

**did-hosting-server example** (witness/watcher — DIDComm only, no public HTTP):

```bash
vta bootstrap provision-request \
    --template       did-hosting-server \
    --var            MEDIATOR_DID=did:webvh:mediator.example.com \
    --var            URL=https://logs.example.com \
    --context-hint   did-hosting-witness \
    --admin-template vta-admin \
    --validity-hours 168 \
    --out            did-hosting-witness-request.vp.json
```

`URL` is required for any webvh-method template at provision time so
the VTA knows where the DID's `did.jsonl` log will be published —
even on `did-hosting-server`, where `URL` does not appear in the rendered
document. Pass `--var WEBVH_SERVER=<id>` instead to route through a
hosting server already registered with `vta did-mgmt servers add`.

What this does:

1. Mints a fresh ephemeral Ed25519 keypair — this is the VP's
   `holder` DID. Scoped to this one bootstrap round-trip; the
   long-term admin DID you end up with is minted by the VTA in
   Phase 2 if you pass `--admin-template vta-admin` (recommended).
2. Persists the seed under
   `~/.config/vta/bootstrap-secrets/<bundle_id>.key` (mode 0600 on
   Unix, ACL-hardened on Windows). You'll need it in Phase 3 to
   decrypt the returned bundle.
3. Signs a VP (W3C Verifiable Presentation) carrying the template
   name, variables, and context hint. The VP is valid for 168 hours
   (7 days) by default — widen or narrow with `--validity-hours`.
4. Writes the VP to `--out` as JSON.

Also available as `pnm bootstrap provision-request ...` — same
shape, different binary, different default seed directory
(`~/.config/pnm/bootstrap-secrets/`).

| Flag | Required | Notes |
|---|---|---|
| `--template` | yes | Built-in (`didcomm-mediator`, `did-hosting-control`, `did-hosting-daemon`, `did-hosting-server`) or operator-uploaded template name. |
| `--var KEY=VALUE` | varies | Template-specific. Values are parsed as JSON when possible (`true`, numbers, arrays, objects, quoted strings); unquoted values are treated as strings. |
| `--context-hint` | recommended | The VTA context the integration will live in. The VTA operator confirms; mismatch is rejected, not silently normalized. |
| `--admin-template` | recommended | Typically `vta-admin`. The VTA mints a long-term admin DID under its own key custody and binds authorization to it — the ephemeral key stays throwaway. Omit only if you intentionally want the ephemeral `client_did` to remain the admin. |
| `--validity-hours` | default 168 | 7 days. Setup-file shuffling is slow; don't set too low. |
| `--label` | optional | Shows up in the VTA's audit log. |
| `--seed-dir` | optional | Override the default `~/.config/vta/bootstrap-secrets/` for CI or sealed images where `$HOME` isn't writable. |
| `--out` | yes | Path to write the signed VP. |

**Hand off:** copy `mediator-request.vp.json` (or equivalent) to the
VTA host. Any transport is fine — `scp`, USB, carrier pigeon. The VP
is not secret; its value is operator-signed intent.

### Phase 2 — Provision (VTA host)

On the VTA host. The VTA process does **not** need to be running;
this command operates directly on the store on disk.

```bash
vta bootstrap provision-integration \
    --request  mediator-request.vp.json \
    --context  mediator-prod \
    --out      mediator-bundle.armor
```

(Omit `--context` if the request's `contextHint` is authoritative.
Add `--create-context` to provision the context inline if it does
not yet exist — idempotent, equivalent to running
`vta context create --id mediator-prod` first.)

What it does:

1. Loads the VTA's config + opens the store.
2. Verifies the VP: signature (against the ephemeral `holder`),
   types, freshness (`validUntil`), context agreement.
3. Resolves the target context (must already exist, or pass
   `--create-context` to allocate it inline; `--context` must match
   the request's `contextHint` if one is set).
4. Mints the integration's DID + keys via the named template. In
   greenfield setup — no webvh hosting server exists yet — this runs
   in **serverless mode**: the VTA writes `did.jsonl` to its own
   store and the operator publishes it wherever (S3, nginx, GitHub
   Pages) later.
5. Mints the long-term admin DID if `adminTemplate` is set.
6. Writes the admin ACL row.
7. Issues a `VtaAuthorizationCredential` signed with the VTA's key.
8. HPKE-seals a `TemplateBootstrapPayload` (integration keys, admin
   keys, webvh log, VTA trust bundle, VC) to the VP holder's X25519
   derivation.
9. Writes the armored bundle to `--out` and prints the SHA-256 digest
   plus provisioning summary.

**Preconditions** (call fails fast if):

- The calling operator isn't admin of the target context (on the
  CLI path this is synthesised as super-admin — the operator running
  the CLI has root access to the keyspace; ACL gating is enforced on
  the REST endpoint where it actually matters).
- The template isn't registered or known as a built-in.
- The request has expired (`validUntil` past, ±5 min skew).
- The request's signature doesn't verify against the holder DID.

**Hand off:** copy `mediator-bundle.armor` to the integration host.
Communicate the printed SHA-256 digest **out-of-band** — different
channel than the bundle file itself. Examples:

- Print the digest on the VTA-host terminal, type it into a Signal
  message to the integration operator.
- Drop the bundle on shared storage, text the digest.

The digest is the trust anchor. Without it, a bundle tampered in
flight is undetectable.

**Publish the `did.jsonl` files.** Both DIDs are in serverless mode
at this point. The VTA wrote:

- `data/vta/...<vta_did>.../did.jsonl` — the VTA's own log. Publish
  at the URL in `[vta_did] url` from `setup.toml`.
- The integration's `did.jsonl` is inside the sealed bundle as a
  `WebvhLog` output. Phase 3 installs it; the integration operator
  publishes at the URL they supplied in `--var URL=...`.

### Phase 3 — Open the bundle (integration host)

Back on the integration host. Verify and install.

```bash
vta bootstrap open \
    --bundle         mediator-bundle.armor \
    --expect-digest  <digest-from-OOB-channel>
```

(Or `pnm bootstrap open` if you used the `pnm` side in Phase 1.)

What it does:

1. Verifies the OOB digest matches the armored bundle's hash. Aborts
   loudly on mismatch; there is no silent TOFU.
2. Looks up the stashed seed by `bundle_id`
   (`~/.config/vta/bootstrap-secrets/<bundle_id>.key`).
3. Derives the X25519 HPKE secret from the Ed25519 seed.
4. Decrypts the sealed bundle.
5. Prints the payload summary — template name, kind, secret count,
   outputs, VTA URL.

`vta bootstrap open` today **prints** the payload contents; it does
not automatically install them into the integration's keystore. That
install step is integration-specific and lives in the integration's
own setup wizard (mediator repo, did-hosting-daemon repo, etc.).
Those wizards use the SDK directly — see [SDK surface](#sdk-surface).

**What the integration installs:**

| Field | Install into |
|---|---|
| `secrets[integration_did]` | Integration's signing + key-agreement keys — persist into its own keystore (keyring, file, TEE). |
| `secrets[admin_did]` (if admin rollover) | Long-term admin DID keys — persist as the integration's admin identity. |
| `outputs: [WebvhLog { did, log_content }]` | Save `log_content` to disk; operator publishes at the URL from Phase 1's `--var URL=`. |
| `vta_trust_bundle` | VTA DID + root key + context id. Persist so the integration trusts incoming DIDComm from that VTA. |
| The inner VC | Archive for audit. The VTA's ACL is the authoritative authorization source in steady state — this VC is bootstrap-transport only and never re-verified after first open. |

### REST transport (PNM bridge)

When the VTA is reachable over HTTPS from the operator's
workstation, skip the file shuffle:

```bash
pnm bootstrap provision-integration \
    --request    mediator-request.vp.json \
    --vta        prod                       # which VTA (from PNM config)
    --context    mediator-prod \
    --out        mediator-bundle.armor
```

Thin HTTP client around `POST /bootstrap/provision-integration`. PNM
authenticates to the VTA with the operator's session; the VTA does
the provisioning server-side using the same library function the
offline CLI uses. The returned armored bundle is identical.

### DIDComm transport

Used when an integration that already holds admin role in a context
provisions further integrations in the same context over its own
DIDComm session. The integration calls
`vta_sdk::provision_integration::didcomm::provision_integration_didcomm`,
which packs an authcrypt'd DIDComm message carrying the same VP and
parses the same sealed-bundle response.

Protocol URI (canonical Trust Task registry), two versions accepted:
`https://trusttasks.org/spec/provision/integration/0.1` and
`https://trusttasks.org/spec/provision/integration/0.2`. The VTA
dual-accepts both and replies under the matching `#response` URI. The
0.2 wire form differs only in camelCase enum casing (notably the signed
VP's `ask.type`, e.g. `templateBootstrap`); the handler verifies the VP
over the bytes as received so the holder's casing survives. The legacy
`firstperson.network/protocols/provision-integration/1.0/*` URI was
retired now that the browser plugin and Rust CLIs target the canonical
registry.

The VTA's DIDComm handler enforces a **dual check**:
`auth_from_message` verifies the authcrypt sender + ACL entry, AND
the library fn verifies the VP's `DataIntegrityProof`. The DIDComm
sender DID and the VP holder DID must agree; mismatch is rejected as
`Forbidden` (privilege-laundering guard).

Precondition: `client_did` must already hold admin role in the
target context. This is the expected shape for an admin DID minted
in a prior provision-integration rollover provisioning further
integrations.

### Repeat for additional integrations

Every integration goes through the same three phases with the same
CLI. Different `--template`, different `--var` values, different
`--context-hint`. Provision a second mediator in another context,
add a webvh hosting server, then a custom integration from an
operator-uploaded template — all one flow.

Once a hosting server is live and both the VTA's and earlier
integrations' `did.jsonl` files are published there, subsequent
integrations can use `--var WEBVH_SERVER=<registered-id>` (and
optionally `--var WEBVH_PATH=<path>`) to have the VTA publish the
new integration's log directly to that server instead of
self-hosting.

On a multi-tenant hosting server, add `--var WEBVH_DOMAIN=<name>` to
pin which tenant domain the DID is allocated under (the
`did:webvh:<scid>:<host>` host slot). Omit it to let the server run
its own resolution chain (the caller's ACL default → system default).
Like `WEBVH_SERVER` / `WEBVH_PATH`, `WEBVH_DOMAIN` is transport
metadata consumed VTA-side — it never reaches the template renderer.
Discover legitimate domain values with
`pnm did-mgmt dids list-domains --server <id>`. The `vtc setup`
wizard surfaces this as an interactive picker after the ACL grant.

### Exporting existing context state (offline admin handoff)

A second offline scenario: the operator has an
**already-provisioned** context and wants to hand its admin identity
plus DID material to a new or backup admin host. Same sealed-transfer
envelope, different payload shape — `SealedPayloadV1::ContextProvision`
or `SealedPayloadV1::DidSecrets` instead of `TemplateBootstrap`.

```bash
# Export a context's admin credential + all DID keys + DID document +
# log. Consumer imports the bundle and is set up as admin of that
# context. The DID's operational keys (signing, KA, pre-rotation) are
# auto-included — the operator doesn't name them.
vta context reprovision \
    --id        mediator-prod \
    --recipient new-admin-request.json \
    --out       mediator-prod-handoff.armor

# Export all active keys in a context as a portable DID secrets bundle
# (DID + keys only, no admin credential).
vta keys bundle \
    --context   mediator-prod \
    --recipient backup-admin-request.json \
    --out       mediator-prod-keys.armor
```

The consumer generates their bootstrap request with `vta bootstrap
request` (v1 shape — any recipient keypair, not the VP-framed one
the `provision-*` flow uses), hands the JSON to the VTA-host
operator, and decrypts the returned armored bundle with `vta
bootstrap open`.

Same flags work with `pnm context reprovision` / `pnm keys bundle`
on an admin workstation that can reach the VTA over REST — the wire
shapes and sealing logic are shared via `vta-cli-common`.

`vta context reprovision`'s `--admin-key` is optional. When omitted
(recommended default), the VTA mints a fresh Ed25519 key scoped to
the context, derives its `did:key`, writes an admin ACL row for it,
and packs the resulting `CredentialBundle` into the sealed output.
Pass `--admin-key <existing-key-id>` only when reusing a specific
already-stored identity — rotation, backup recovery, or a deliberate
multi-admin setup. The DID's operational keys (signing, KA, any
pre-rotation) are always included regardless.

---

## Wire format

### Request: Verifiable Presentation

A JSON file the integration's operator hands to the VTA admin (or
submits via PNM). Signed by the ephemeral key behind `client_did`.

```json
{
  "@context": [
    "https://www.w3.org/ns/credentials/v2",
    "https://openvtc.org/contexts/bootstrap-v1"
  ],
  "type": ["VerifiablePresentation", "BootstrapRequest"],
  "holder": "did:key:z6Mk...",
  "id": "urn:uuid:...",
  "nonce": "base64url-16-bytes",
  "validUntil": "2026-04-20T12:00:00Z",
  "label": "mediator/conf/mediator.toml",
  "ask": {
    "type": "TemplateBootstrap",
    "template": { "name": "didcomm-mediator", "vars": { "URL": "..." } },
    "adminTemplate": { "name": "vta-admin", "vars": {} },
    "contextHint": "prod-mediator",
    "note": "optional human-readable hint"
  },
  "proof": {
    "type": "DataIntegrityProof",
    "cryptosuite": "eddsa-jcs-2022",
    "verificationMethod": "did:key:z6Mk.../#...",
    "proofPurpose": "authentication",
    "created": "2026-04-20T11:00:00Z",
    "proofValue": "z..."
  }
}
```

Enforcements at `.verify()` time:

- Proof verifies against `holder`'s DID doc (resolve `did:key`,
  extract key, verify signature over JCS-canonicalized bytes).
  `verificationMethod` must reference the same DID as `holder` —
  forged holder substitution rejected.
- `validUntil` is in the future (with ±5 minutes clock-skew tolerance —
  W3C-typical verifier default, applied symmetrically to `validFrom`
  when present).
- Cryptosuite must be `eddsa-jcs-2022` — widens when we intentionally
  accept new suites, not as a side effect.
- `@context` is present but not processed (JCS canonicalizes the JSON
  structure directly, no JSON-LD expansion).
- `proofPurpose == "authentication"`.

### Payload: `SealedPayloadV1::TemplateBootstrap`

```rust
pub enum SealedPayloadV1 {
    AdminCredential(Box<CredentialBundle>),
    ContextProvision(Box<ContextProvisionBundle>),
    DidSecrets(Box<DidSecretsBundle>),
    AdminKeySet(Vec<LabeledKey>),
    RawPrivateKey(RawPrivateKey),
    /// Generic template-driven integration bootstrap.
    TemplateBootstrap(Box<TemplateBootstrapPayload>),
}

pub struct TemplateBootstrapPayload {
    /// VTA-issued VC: "holder is admin of context X at VTA Y, operator
    /// of DID Z". Short-lived (validUntil ~1h), verifiable offline via
    /// the trust bundle below.
    pub authorization: VerifiableCredential,
    /// Private key material for DIDs the VTA minted for the holder.
    /// Keyed by DID. Secrets are `Zeroizing<[u8;32]>` at use.
    pub secrets: BTreeMap<String, DidKeyMaterial>,
    /// Non-credential first-boot config the integration needs.
    pub config: TemplateBootstrapConfig,
}

pub struct DidKeyMaterial {
    pub did: String,
    pub signing_key: KeyPair,   // ed25519
    pub ka_key: KeyPair,        // x25519
}

pub struct KeyPair {
    pub key_id: String,                 // DID URL with fragment
    pub public_key_multibase: String,
    pub private_key_multibase: String,  // Zeroizing at rest
}

pub struct TemplateBootstrapConfig {
    pub template_name: String,
    pub template_kind: String,
    pub did_document: serde_json::Value,
    pub outputs: Vec<TemplateOutput>,
    pub vta_url: Option<String>,
    pub vta_trust: VtaTrustBundle,
}

pub enum TemplateOutput {
    /// webvh `did.jsonl` content. Integration writes to
    /// `/.well-known/did.jsonl` at first boot.
    WebvhLog(String),
    /// DIDComm service-endpoint advertisement.
    DidCommService { url: String, accept: Vec<String>, routing_keys: Vec<String> },
    // Grow here as new template kinds need new side-outputs.
}

pub struct VtaTrustBundle {
    pub vta_did: String,
    pub vta_did_document: serde_json::Value,
    /// For `did:webvh` VTAs — raw `did.jsonl` so the integration can
    /// replay the log and verify the doc independently. None for
    /// self-resolving methods like `did:key`.
    pub vta_did_log: Option<String>,
}
```

### VC: `VtaAuthorizationCredential`

```json
{
  "@context": [
    "https://www.w3.org/ns/credentials/v2",
    "https://openvtc.org/contexts/vta-authorization-v1"
  ],
  "type": ["VerifiableCredential", "VtaAuthorizationCredential"],
  "issuer": "did:webvh:vta.example.com",
  "validFrom": "2026-04-20T11:00:00Z",
  "validUntil": "2026-04-20T12:00:00Z",
  "credentialSubject": {
    "id": "did:key:z6MkVtaMintedAdminDid...",
    "adminOf": {
      "vta": "did:webvh:vta.example.com",
      "context": "prod-mediator",
      "role": "admin"
    },
    "operatorOf": {
      "did": "did:webvh:mediator.example.com",
      "template": "didcomm-mediator"
    }
  },
  "proof": {
    "type": "DataIntegrityProof",
    "cryptosuite": "eddsa-jcs-2022",
    "verificationMethod": "did:webvh:vta.example.com#assertion-key",
    "proofPurpose": "assertionMethod",
    "created": "2026-04-20T11:00:00Z",
    "proofValue": "z..."
  }
}
```

`credentialStatus` is deliberately absent — this VC is not revocable
via a status list. Lifecycle is entirely expiry-based.

`credentialSubject.id` is **the long-term admin DID** — equal to
`client_did` when no rollover was requested, or to the VTA-minted
DID when the request carried `adminTemplate`. The two cases are
distinguishable from the response summary (`admin_rolled_over`,
`admin_did`) but indistinguishable on the VC itself: holders simply
look up `secrets[credentialSubject.id]` to find the matching keys.

## Verification at integration first-boot (offline)

1. Parse the armored bundle, run sealed-transfer integrity checks
   (digest matches `--expect-digest`).
2. Verify sealed-transfer producer assertion: `DidSigned` by `vta_did`.
   Resolve `vta_did` offline via the `VtaTrustBundle` (replay
   `vta_did_log` to verify the shipped doc; extract assertion key;
   verify signature over producer pubkey + bundle digest).
3. Open the HPKE envelope (integration's X25519 secret, derived
   from the Ed25519 seed it kept at request-creation time).
4. Deserialize `TemplateBootstrapPayload`.
5. Verify `authorization` VC: same trust anchor as step 2. Check
   signature, `validUntil`, subject matches `client_did`.
6. Verify `config.did_document` matches the bundled `operatorOf` DID
   (sanity check: "the doc describes the DID the VC says I operate").
7. Write `did.jsonl` if the template emitted one; install keys from
   `secrets` keyed by the DIDs the VC authorizes; write VTA URL +
   trust bundle.
8. VC stashed for audit; never re-verified. ACL is the authority
   from here on.

Everything above happens with no network access. The integration's
subsequent VTA interactions use the installed credentials against
the VTA's native auth, where the VTA's ACL governs.

**Bundle open is not VTA-authoritative.** Bundle verification
confirms the VTA *issued* the authorization — not that it
*currently* holds. Between issuance and open, the VTA's ACL can
change (admin revokes the entry, operator decides not to proceed). A
verified bundle install is tentative until the integration's first
successful VTA interaction. If the ACL has been withdrawn before
first call, the VTA returns 403 and the integration logs the
inconsistency and halts. This is working as intended — the cost of
the tentative window is bounded (zero operation succeeds without ACL
approval), so we accept it rather than introduce a second
authoritative channel.

**Clock-skew note.** The VC's `validUntil` check uses the same ±5min
tolerance as the VP's. The VC's `validFrom` is checked with the same
skew. This is a verifier-library default; we rely on
`affinidi-data-integrity`'s defaults rather than overriding.

## Admin-DID rollover (optional)

The VP's `ask.adminTemplate` field is an **optional** second template
reference that promotes the bootstrap from "issue a VC to the
ephemeral `client_did`" to "mint a long-term admin DID under VTA key
custody and bind the VC + ACL row to *that*". The ephemeral
`client_did` keeps its role as the sealing recipient but gains no
steady-state authority — it's purely a transport key.

Motivation: the ephemeral `client_did` is a `did:key` the holder
generated locally to author the VP. Making that DID the long-term
admin principal ties the ACL row to a short-lived private key that
may have been handled outside the VTA's custody. Rolling over to a
VTA-minted admin DID at bootstrap time puts the admin identity under
the same BIP-32 / keystore / audit infrastructure as every other DID
the VTA manages.

How it works:

1. Request includes `"adminTemplate": { "name": "vta-admin", "vars": {} }`
   (built-in) or a custom operator-registered template with
   `kind: "admin"`.
2. VTA's `provision_integration` library fn renders the admin template,
   mints a fresh Ed25519 key via the normal BIP-32 derivation under
   the target context's base path, registers a `KeyRecord` at
   `{admin_did}#{multibase}`, and returns `(admin_did, priv_mb)`.
3. Admin DID is added as a second entry in `payload.secrets`, keyed
   by the admin DID. Both the Ed25519 signing key and the canonical
   X25519 key-agreement derivation are populated so holders that
   DIDComm-authenticate as the admin DID don't need to derive X25519
   themselves.
4. The authorization VC's `credentialSubject.id` is set to the
   VTA-minted admin DID, not `client_did`.
5. The ACL row is written for the VTA-minted admin DID. No transient
   ACL row is created for `client_did` — if bundle open fails,
   there's nothing to clean up.

Absent `adminTemplate`, behaviour is unchanged: VC subject =
`client_did`, ACL row for `client_did`.

Phase 1 only supports `did:key` admin DIDs. Templates that target
other methods are accepted at registration time but rejected by the
mint path until the corresponding mint code lands. Templates with
`methods: []` (no restriction) are accepted.

The holder's install glue (typically an integration setup wizard,
e.g. the mediator tool in `affinidi-tdk-rs`) reads the VC's
`credentialSubject.id`, looks up that DID in `secrets`, installs the
signing + KA keys, and discards `client_did` after the first
successful call to the VTA as the new admin DID.

## Client SDK (`vta_sdk::provision_client`)

Setup tools that drive the **online** provisioning flow on the
integration side (mediator-setup, webvh-* setup wizards, future apps)
build on `vta_sdk::provision_client` rather than re-implementing the
orchestration. The module sits **above** `vta_sdk::provision_integration`
(wire types) and below the consumer-side UI (TUI, headless CLI, custom).
Enable the `provision-client` feature on `vta-sdk` to get it.

### Provisioning vs runtime startup

`provision_client` is *one-shot, first-boot*: it mints a setup `did:key`,
asks the VTA to provision a new integration via a DID template, opens the
sealed response bundle, returns the integration DID + private keys + admin
credential. Runs once per integration.

`integration::startup` (different module) is *every-boot, runtime*: loads
already-provisioned credentials and opens a steady-state authenticated
session with the VTA. Runs on every process start.

Setup tooling wants `provision_client`. The integration itself wants
`integration::startup`.

### Workflow at a glance

```rust
use std::sync::Arc;
use vta_sdk::prelude::*;

// 1. Mint a setup did:key. Persist if you need a two-phase split
//    (operator runs `pnm acl create` between phases).
let key = EphemeralSetupKey::generate()?;

// 2. Resolve the VTA's transport endpoints.
let resolved = resolve_vta(&vta_did).await?;

// 3. Build a ProvisionAsk. Curated builders cover the four built-in
//    templates; for_template handles custom templates.
let ask = ProvisionAsk::didcomm_mediator("prod-mediator", "https://m.example.com");

// 4. Pick (or implement) an OperatorMessages.
let messages: Arc<dyn OperatorMessages> = Arc::new(MediatorMessages);

// 5. Drive the workflow. Events stream to your channel; the result
//    comes back via the Result.
let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
let reply = run_provision(
    VtaIntent::FullSetup,
    vta_did,
    key.did.clone(),
    key.private_key_multibase().to_string(),
    ask,
    /* force_transport */ None,
    messages,
    tx,
).await?;
```

### `ProvisionAsk` — curated vs `for_template`

Five curated builders mirror the built-in templates shipped by
`vta-service`:

| Builder | Template | Required vars |
|---|---|---|
| `ProvisionAsk::didcomm_mediator(ctx, url)` | `didcomm-mediator` | `URL` |
| `ProvisionAsk::did_hosting_control(ctx, url, mediator_did)` | `did-hosting-control` | `URL`, `MEDIATOR_DID` |
| `ProvisionAsk::did_hosting_daemon(ctx, url)` | `did-hosting-daemon` | `URL` |
| `ProvisionAsk::did_hosting_server(ctx, mediator_did)` | `did-hosting-server` | `MEDIATOR_DID` |
| `ProvisionAsk::vta_admin(ctx)` | `vta-admin` | (none) |

For an operator-supplied template, use
`ProvisionAsk::for_template(name, vars, context)` and pass the
`requiredVars` the template declares.

**Adding a built-in template to `vta-service` without adding the
matching curated builder is an SDK-side bug.** An equivalence test in
`vta_sdk::provision_client::ask::tests` pins the two sides together —
each curated builder must produce a `BootstrapRequest` byte-equal to
`for_template(name, expected_vars, ctx)`.

### `OperatorMessages` — per-integration strings

The library never hardcodes integration nouns ("mediator", "WebVH
server") or full PNM commands. Each consumer implements
`OperatorMessages` and passes an `Arc<dyn OperatorMessages>` into
`run_provision` and the headless `driver` helpers. Two default impls
ship: `MediatorMessages` and `WebvhServerMessages`.

```rust
use vta_sdk::prelude::*;

struct MyAppMessages;
impl OperatorMessages for MyAppMessages {
    fn integration_label(&self) -> &str { "MyApp" }
    fn integration_label_lower(&self) -> &str { "myapp" }
    fn pnm_admin_command_hint(&self, ctx: &str, did: &str) -> String {
        format!(
            "pnm contexts create --id {ctx} --name \"MyApp\" \\\n  \
             --admin-did {did} --admin-expires 1h"
        )
    }
}
```

### `VtaEvent` — the channel protocol

The runner emits a typed event sequence on a consumer-owned
`mpsc::Sender<VtaEvent>`:

```
CheckStart(ResolveDid)
CheckDone(ResolveDid, Ok(...))
Resolved(ResolvedVta)
CheckStart(EnumerateServices)
CheckDone(EnumerateServices, Ok(...))
... transport-specific check rows ...
AttemptCompleted { protocol, outcome }
[ PreflightDone { servers, ... } ]   // FullSetup over DIDComm only
CheckDone(ProvisionIntegration, Ok(...))
Connected { protocol, reply, ... }   // success terminal
```

Or, on failure: `CheckDone(..., Failed(...))` followed by `Failed(reason)`
as the terminal event. Variants are stable; new variants are
**additive only** — match exhaustively and treat unknown variants as
forward-compat noise once the channel grows past v1.

### Headless driver

`provision_client::driver` ships a non-interactive helper that takes a
`&mut dyn Write` and renders the event stream as text. Two phases:

- `run_phase1_init` — mint key, persist, write the `pnm contexts
  create` command for the operator.
- `run_phase2_connect` — reload key, drive `run_provision`, render
  diagnostic checklist lines.

The library is fully TUI-agnostic — `provision_client` has no
`ratatui` / `crossterm` / `dialoguer` dep, and no `print!` / `println!`
appears anywhere in the module (`driver` writes to the supplied
`&mut dyn Write` only). TUI consumers route the same `VtaEvent` stream
into their state machine.

### Test fixtures (`test-support` feature)

Enable both `provision-client` and `test-support` to reach
`vta_sdk::provision_client::test_helpers::sample_provision_result` for
seeding integration tests with a populated `ProvisionResult` without
standing up a live VTA.

## CLI + HTTP surface

### VTA host (offline flow)

```
vta bootstrap provision-integration \
    --request    <request.vp.json>       # required
    --context    <id>                    # required if request has no contextHint
    --out        <bundle.armor>          # required
    [--assertion <did-signed|pinned-only>]  # default: did-signed
```

Uses `vta_did` (assertion key) to sign both the VC and the
sealed-transfer producer assertion. Mints key material, renders
template, writes bundle to disk, prints digest + summary.

The integration operator generates the request side with:

```
vta bootstrap provision-request \
    --template       <name>               # didcomm-mediator | did-hosting-control | did-hosting-daemon | did-hosting-server | …
    --var KEY=VALUE                       # repeat for each template variable
    --context-hint   <id>                 # recommended
    --admin-template vta-admin            # recommended (long-term admin rollover)
    --validity-hours 168                  # default: 7 days
    --out            <request.vp.json>
```

`--assertion pinned-only` is a dev/test-only escape hatch for
environments where `vta_did` is not yet configured. Production flows
must use `did-signed`.

### PNM bridge (online flow)

```
pnm bootstrap provision-integration \
    --request    <request.vp.json>
    --vta        <slug>                   # which VTA (from PNM config)
    --context    <id>
    --out        <bundle.armor>
    [--assertion <did-signed|pinned-only>]
```

Thin HTTP client around `POST /bootstrap/provision-integration`. PNM
authenticates to the VTA with the operator's session.

### HTTP endpoint

```
POST /bootstrap/provision-integration
Authorization: <PNM session token>
Body:  { request: <VP JSON>, context: <id>, assertion: <variant> }
Response: { bundle: <armor string>, digest: <sha256 hex>, summary: {...} }
```

ACL: `require_admin` scoped to the target context. Super-admin passes
through. If the caller is context-admin but the request's
`context_hint` disagrees with `context`, reject (don't silently
normalize).

### `did.jsonl` retrieval

```
vta did log --did <did> [--out <file>]
pnm did log --did <did> --vta <slug> [--out <file>]

GET /did/{did}/log      # public, unauthenticated, rate-limited
```

Returns raw `did.jsonl` bytes. 404 if the VTA doesn't know the DID.
Public because webvh logs are world-readable by design — security is
cryptographic (signatures, SCID anchoring), not access-gated.

**Snapshot semantics.** The VTA's copy of an integration's
`did.jsonl` is the provisioning-time snapshot. Once the integration
boots and publishes the log at its own webvh host, the integration
becomes the live source of truth and may extend the log (key
rotation, service updates) without re-syncing to the VTA. Use this
endpoint for audit and as a bootstrap/recovery fallback when the
integration's webvh host is unreachable. Don't treat it as a live
resolver — live resolution goes to the integration's own host per
standard webvh semantics.

## SDK surface

Integration setup wizards (the mediator binary's own setup, the
DID-hosting server's own setup, any custom operator glue) should import
the SDK directly rather than shelling out to the CLI.

### Generate a request

```rust
use chrono::Duration;
use vta_sdk::provision_integration::ProvisionRequestBuilder;

let signed = ProvisionRequestBuilder::new("didcomm-mediator")
    .var("URL", "https://mediator.example.com")
    .context_hint("mediator-prod")
    .admin_template("vta-admin")
    .validity(Duration::days(7))
    .label("mediator-prod-bootstrap")
    .sign_ephemeral()
    .await?;

// Persist signed.seed under signed.bundle_id (hex) wherever your
// integration stores secrets. Serialize signed.request as JSON and
// hand to the VTA operator.
```

For integrations that already have a long-lived keypair they want
to reuse as the bootstrap identity, use `sign_with(&seed,
&client_did)` instead of `sign_ephemeral()`.

### Open a bundle

```rust
use vta_sdk::sealed_transfer::{armor, open_bundle, ed25519_seed_to_x25519_secret};

let armored = std::fs::read_to_string(&bundle_path)?;
let bundles = armor::decode(&armored)?;
let bundle = &bundles[0];

// Re-load the seed you persisted in Phase 1 (look up by bundle.bundle_id).
let x_secret = ed25519_seed_to_x25519_secret(&ed_seed);
let opened = open_bundle(&x_secret, bundle, Some(&oob_digest_hex))?;

// opened.payload is a SealedPayloadV1::TemplateBootstrap(...). Install
// its secrets, outputs, and vta_trust_bundle per your integration's
// keystore layout.
```

The CLI-common layer (`vta_cli_common::sealed_consumer`) wraps these
calls with the `~/.config/<tool>/bootstrap-secrets/` persistence
convention. Integrations with their own secret-storage strategy
(keyring, TEE, custom dir) should call the SDK directly.

### Provision-integration over DIDComm

For an admin-DID provisioning further integrations from inside the
network:

```rust
use vta_sdk::provision_integration::didcomm::provision_integration_didcomm;

let bundle = provision_integration_didcomm(
    &session,         // already-connected DIDCommSession with admin DID
    request_vp_json,
    context_id,
).await?;
```

## Trust model

- **In-flight integrity**: SHA-256 digest communicated out-of-band.
  The bundle armor is public; the digest is the anchor.
- **Producer assertion**: `did-signed` (default) — the VTA signs the
  sealed-transfer envelope with its `{vta_did}#key-0` key. The
  integration can verify once the VTA DID is resolvable (may require
  both `did.jsonl` files to be published first).
- **VC verification**: the inner `VtaAuthorizationCredential` is
  verified at first open if the VTA DID is resolvable. In greenfield
  setup neither DID is published yet — use `--assertion pinned-only`
  on the provision-integration side, or defer VC verification until
  first live handshake.
- **Steady state**: the VC is bootstrap-only. After first open, the
  VTA's ACL is the authoritative authorization source. Revocation
  is ACL removal, not VC status change.

### Security note on signing-key reuse

`vta_did`'s assertion key signs both the VC (Data Integrity proof
over JCS-canonicalized VC bytes, `proofPurpose = "assertionMethod"`)
and the sealed-transfer producer assertion (Ed25519 signature over
`producer_pubkey || bundle_digest` in a framed context). This reuse
is safe: the two signed targets are structurally disjoint —
different canonicalization, different byte prefixes, different
framing — so a signature produced for one cannot be verified as
valid in the other's verifier. Standard cross-protocol replay
analysis applies. No separate issuer key is needed.

If at any point we introduce a third signed-by-`vta_did` artifact,
the same disjointness analysis must be re-run. The DID doc
explicitly marks the reused key as `assertionMethod`; anything
claiming `authentication` or other purposes should use a distinct
verification method on the same DID, not conflate purposes on one
key.

## Implementation reference

### JSON-LD context files

Ship in `vta-sdk/src/sealed_transfer/contexts/`:

- `bootstrap-v1.jsonld` — defines `BootstrapRequest` type, `nonce`,
  `ask`, `label`, `validUntil` terms.
- `vta-authorization-v1.jsonld` — defines
  `VtaAuthorizationCredential` type, `adminOf`, `operatorOf` terms
  with their sub-properties.

Both marked `@protected: true`. Baked at compile time via
`include_str!` and registered with `ssi-json-ld`'s context loader.
Tests include an offline-verification sanity check that fails if
the loader touches the network.

Publishing at `https://openvtc.org/contexts/...` is an operational
follow-up. No code change required when it happens.

### Shared library entry point

Both CLI and HTTP handler route through:

```rust
// vta-service core library
pub async fn provision_integration(
    state: &AppState,
    auth: &AuthClaims,  // from PNM session or CLI local auth
    request: VerifiedBootstrapRequest,
    context: ContextId,
    assertion_mode: AssertionMode,
) -> Result<ProvisionIntegrationOutput, AppError>;

pub struct ProvisionIntegrationOutput {
    pub armored: String,       // sealed bundle, armored
    pub digest: String,        // sha256 of ciphertext
    pub summary: ProvisionSummary,  // admin did, integration did, log bytes, vta did
}
```

Inside:

1. Auth / ACL check (`require_admin` + `allowed_contexts`).
2. Resolve `context` — must already exist.
3. Resolve template (reject if template references an unregistered
   name).
4. Render template (existing `did_templates::render` path). Mint
   signing + KA keys. Capture `did.jsonl` for webvh, service
   endpoint for DIDComm, etc. as `TemplateOutput` values.
5. Mint admin credential for `client_did` in `context` (existing
   `operations::acl::create_acl` — role=admin, contexts=[context]).
6. Build + sign `VtaAuthorizationCredential` with `vta_did`'s
   assertion key. Set `validUntil` per operator config (default 1h).
7. Assemble `TemplateBootstrapPayload`. Secrets map keyed by
   integration DIDs. Config includes `VtaTrustBundle`.
8. Seal payload to `client_did`'s X25519 pubkey (derived from
   Ed25519 via `affinidi_crypto::did_key`). `ProducerAssertion` =
   `DidSigned` by `vta_did`. Fresh `bundle_id`, persistent nonce
   store to prevent replay.
9. Armor, digest, return.

Persistence: admin ACL row written atomically with the seal (same
pattern as `vta context provision`). Integration DID + log cached in
the VTA's webvh store (existing schema) so `GET /did/{did}/log` can
serve it later.

## Design decisions, at a glance

| # | Decision | Chosen |
|---|---|---|
| 1 | DID ownership / caller-vs-VTA key custody | DID templates always; VTA always mints keys |
| 2 | Payload variant shape | Generic `SealedPayloadV1::TemplateBootstrap` with typed `TemplateOutput` enum |
| 3 | Request format | VP (VC Data Model 2.0, `eddsa-jcs-2022`) |
| 4 | VC subject (admin authorization) | `client_did` by default; VTA-minted long-term admin DID when `ask.adminTemplate` is present |
| 5 | VC revocation | Short-lived VC only (1h default); no StatusList; revocation = ACL removal |
| 6 | VTA issuer DID | Reuse `vta_did`; template marks an `assertionMethod` key |
| 7 | VC claim shape | `adminOf` always, `operatorOf` when template mints an integration DID |
| 8 | Command name | `provision-integration` |
| 9 | HTTP endpoint ACL | `require_admin` scoped to target context |
| 10 | `GET /did/{did}/log` auth | Public, unauthenticated, `tower_governor` rate-limited |
| 11 | Sealed-transfer producer assertion | `DidSigned` by `vta_did`; `--expect-digest` mandatory; `--assertion pinned-only` escape hatch |
| 12 | JSON-LD context hosting | Bake locally; publishing at canonical URL is operational follow-up |
| 13 | VP `proofPurpose` | `authentication` (VC `proofPurpose` stays `assertionMethod`) |
| 14 | Transport for the VP→bundle round-trip | File + REST + DIDComm (same VP, same payload, shared library fn) |
| 15 | DIDComm steady-state auth | Authcrypt-as-auth, no JWT |
| 16 | Admin-DID mint method (phase 1) | `did:key` only — Ed25519 via BIP-32 under the context base path |

## Non-goals

- **VC for other `SealedPayloadV1` variants.** `AdminCredential`,
  `ContextProvision`, `DidSecrets`, etc. stay as bespoke structs.
  Their VC migration is a separate design conversation.
- **Inline template JSON in requests.** Templates must be registered
  on the VTA via the existing authed endpoint first.
- **Federation / cross-VTA trust.** `VtaTrustBundle` is single-VTA
  in phase 1; federation is future work.
- **Integration key rotation.** The integration uses its minted keys
  for the lifetime of the DID. Rotation, if ever needed, is an admin
  operation (revoke + reprovision), not a built-in feature.
- **StatusList2021 or any VC revocation infrastructure.** Revocation
  is ACL removal.
- **VC-v2 post-rotation on the admin side.** Admin auth rotation
  updates the ACL entry's DID; no new VC issued.
- **`webvh` admin-DID templates in phase 1.** The admin mint path
  rejects templates whose `methods` list excludes `"key"`. Adding
  webvh-hosted admin DIDs is a follow-up.
- **Custom `TemplateOutput` variants without a workspace PR.** Phase
  1 has `WebvhLog` and `DidCommService` only; new variants require a
  core change.

## See also

- [`did-templates.md`](did-templates.md) — how templates are
  authored, uploaded, resolved (context → global → built-in).
- [`integration-guide.md`](integration-guide.md) — building an
  application that consumes a provisioned integration's keys.
- [`../02-vta/cold-start.md`](../02-vta/cold-start.md) —
  interactive VTA setup walkthrough and admin seeding.
- [`../02-vta/non-interactive-setup.md`](../02-vta/non-interactive-setup.md) —
  `vta setup --from <file>` for the pre-provision VTA stand-up step.
