# The witness host service (`vti-witness`)

`vti-witness` runs **witnesses**: the parties that `witness/session/0.1` and
`witness/session/submit/0.1` define. A witness opens a session for a party to an
exchange, verifies that party's presentation of its relationship credential, and
issues a Verifiable Witness Credential (VWC) saying the exchange happened.

It is a **host service**, not a role of the VTA or the VTC. A witness has value
only as a third party independent of the exchange it attests; most VTAs and VTCs
never witness anything; and a witness is public by design, so its identity must
never be a node's own (VTI-KEY-007). The reasoning is in the design note,
[the witness as a host service](../05-design-notes/witness-host-service.md).

> **Status: P1, the skeleton.** This release sets up witness identities, keeps
> one mediator session per identity, and answers `trust-task-discovery`. It does
> **not** witness yet: `witness/session/0.1` and `witness/session/submit/0.1`
> are refused (see [What it serves](#what-it-serves)). Witnessing — independence
> checks, community eligibility, VWC issuance, storage — is phase P2.

## What it is

- **One binary, up to ten witness identities.** Each identity is its own
  `did:webvh`, with its own mediator session and (from P2) its own policy, so one
  deployment can run a separate witness per community or per purpose. An
  eleventh is a configuration error.
- **Provisioned, not self-minted.** Every identity is minted by the
  **operator's** VTA from the built-in [`dtg-witness` DID template](../02-vta/did-templates.md),
  through the same two-phase, VTA-granted setup as the VTC, the mediator and
  did-hosting. (`dtg-witness`, not `witness`: `pnm did-templates init witness`
  stays an alias for the did:webvh log witness's shape, `did-host-didcomm`.)
  The VTA is the key custodian. It is never a party to anything
  witnessed, and the witness never acts as it.
- **TSP, then DIDComm. No HTTPS.** Each identity's DID document advertises
  `TSPTransport` and `DIDCommMessaging`, both naming its mediator, and nothing
  else — an HTTPS door would need a hostname of its own to avoid a naming
  correlator. Both protocols ride the identity's one mediator websocket.
- **No ACL and no administrator surface.** Nobody administers a witness over the
  wire. Its policy is its configuration file.

## Setup

Setup is two-phase, exactly as for a VTC (`docs/03-vtc/non-interactive-setup.md`).

**1. Mint a setup key** and print the grant to run at the operator's VTA:

```sh
vti-witness setup --setup-key-out /secrets/witness-setup-key.json --context witness
```

**2. Grant it**, from a `pnm` connected to the operator's VTA (the command is
printed by step 1):

```sh
pnm contexts create --id witness --name "Witness" \
  --admin-did did:key:z6Mk… --admin-expires 1h --admin-handoff
```

(`pnm acl create --did did:key:z6Mk… --role admin --contexts witness --expires 1h`
if the context already exists.)

**3. Provision** every identity from a setup file:

```toml
# witness-setup.toml
config_path    = "/etc/vti-witness/config.toml"
vta_did        = "did:webvh:Qm…:vta.operator.example"
context        = "witness"                       # default
setup_key_file = "/secrets/witness-setup-key.json"
# data_dir     = "/etc/vti-witness/data"         # default: data/ beside config_path
# resolver_url = "ws://resolver:8080/did/v1/ws"  # optional resolver sidecar

[secrets]                       # where the identities' keys are kept
backend = "keyring"
keyring_service = "vti-witness"

[[witness]]
name         = "community-a"
mediator_did = "did:webvh:Qm…:mediator.independent.example"
webvh_server = "prod"           # a DID-hosting server registered at the VTA…
# url        = "https://witness.independent.example/a"   # …or serve the log yourself
# webvh_domain / webvh_path     # optional, as for any provisioned DID
enabled      = false            # default
```

```sh
vti-witness setup --from witness-setup.toml
```

For each `[[witness]]`, setup asks the VTA to render the `dtg-witness` template at
that mediator, opens the sealed bundle, and keeps the identity's keys in the
`[secrets]` store — never in `config.toml`. It then writes `config.toml`
(owner-only) naming each identity, and, for a serverless identity, the
`did/<name>.jsonl` log to publish where its DID resolves.

The setup DID is **never handed off**. Every other integration rolls its setup
DID over to a long-term VTA admin; a witness administers nothing at its VTA, so
no admin DID is minted and no VTA credential reaches the witness host. The
setup DID's grant ends at its `--admin-expires`; setup prints the `pnm acl
delete` that ends it sooner.

Setup refuses to overwrite an existing `config.toml`, or a secret store that
already holds witness keys. If provisioning fails part-way, it names the
identities already minted at the VTA (and saved nowhere) so they can be removed
there.

## Configuration

`config.toml`, as setup writes it:

```toml
data_dir         = "/etc/vti-witness/data"
operator_vta_did = "did:webvh:Qm…:vta.operator.example"
# resolver_url   = "ws://resolver:8080/did/v1/ws"

[secrets]
backend = "keyring"
keyring_service = "vti-witness"

[[witness]]
name         = "community-a"
did          = "did:webvh:Qm…:witness.independent.example:a"
mediator_did = "did:webvh:Qm…:mediator.independent.example"
enabled      = true
```

| Key | Meaning |
|---|---|
| `data_dir` | Local state: the plaintext secret store if one is explicitly chosen, and setup's `did/<name>.jsonl` logs. |
| `operator_vta_did` | The VTA that minted the identities. Read only to warn about correlators; the witness never acts as it. |
| `resolver_url` | Optional DID resolver sidecar (network mode). |
| `[secrets]` | The secret-store backend — the same table and backends as the VTA and VTC. `config_seed` is refused, since it would put keys in this file. |
| `[[witness]]` | 1–10 identities: `name` (local label, `a-z0-9-_`), `did`, `mediator_did`, `enabled` (default **false**). |

Every key is checked: an unknown one anywhere, including inside `[secrets]`, is a
load error rather than a silently ignored setting. Names and DIDs must be unique,
and no identity may be the operator VTA's own DID.

## Running

```sh
vti-witness run --config /etc/vti-witness/config.toml
```

For each **enabled** identity, `run` keeps one mediator session: its own ATM,
holding only that identity's keys, and one websocket carrying both TSP and
DIDComm. Each session is supervised the way the VTA's is:

- it waits until the identity's DID resolves over the network (the mediator
  authenticates it by resolving it);
- it connects with capped exponential backoff and full jitter (2 s to 60 s),
  re-checking resolution before every attempt;
- a session counts as healthy only after 60 s, so a flapping mediator is not
  retried at full rate;
- every failed or ended session is torn down (`ATM::graceful_shutdown`), so no
  abandoned socket holds the mediator's one slot for that DID;
- it collects the mediator inbox live delivery missed, and rebuilds the session
  when the receive leg stops delivering.

SIGINT or SIGTERM closes every session and exits.

## What it serves

Each identity answers only documents addressed to **its own DID**, from a
sender the transport proved, and every answer is signed by that identity's own
key. Nothing is signed as, or names, the operator's VTA.

| Type | P1 answer |
|---|---|
| `trust-task-discovery/0.3`, `/0.1` | This identity's task list: the discovery versions it serves. |
| `witness/session/0.1`, `witness/session/submit/0.1` | `unsupportedType`, with a message that witnessing is not enabled in this release. |
| Any other type | `unsupportedType` (`unsupportedVersion` for another version of discovery). |

The witness tasks are refused as `unsupportedType` **and are not listed in
discovery**: discovery answers "which tasks does this agent serve", and listing a
task that is always refused would tell a client to send something it can never
get answered. P2 lists them when it serves them.

Every inbound document goes through the framework's §7.2 checks before anything
is dispatched: freshness (the ten-minute acceptance window every VTI node
applies, `issuedAt` required), expiry, `recipient` equal to this identity, an
in-band `issuer` consistent with the proven sender, the task specification's own
requirements, and — where a proof is present — verification of that proof
against the document's `issuer`. A `trust-task-error` or a `#response` is never
answered: the witness sends no requests, so nothing is waiting for one.

## Correlators

The witness DID is meant to be seen. What should not be seen is the link between
a witness and its operator (VTI-CMP-062). At setup and at every start the
service **warns** — it never refuses — about the two it can detect:

| Correlator | Where it shows | Mitigation |
|---|---|---|
| The witness DID | Every VWC and session | Intended: the witness is public by design |
| Its mediator | The mediator sees the witness's sessions | Use a mediator other than the operator VTA's. Warned about when they share one |
| Its DID-log host | Anyone resolving the witness | Host the log apart from the operator's own domains. Warned about when they share one |
| Community membership | The witness, at submit (P2) | Inherent to community-keyed eligibility |
| Attestation records | The witness operator (P2) | Kept only for revocation; no presentation is kept |

Each warning says the shared mediator or domain is a **possible correlation
source the operator may accept**. "Shares a domain" is the same host, a
subdomain, or the same last two labels — an approximation that can over-warn
under a two-label public suffix such as `co.uk`, which is acceptable for a
warning.

## What a witness sees: no zero-knowledge path in v1

What the witness sees depends on what it witnesses, and v1 has no zero-knowledge
path. The witness reads the presentation it is given **in full**: the
relationship credential and, under the default eligibility policy, the
submitter's membership credential. The specification gives it no way to verify
less (`vp` is an opaque object), and no ZKP presentation is implemented.

A deployment therefore either **trusts the witness** with what it is shown, or
designs a flow in which the witness adds value without seeing specifics: what is
presented, and which eligibility evidence is asked for, are deployment
decisions. The community-membership check is the default policy, not a
requirement the service imposes; a witness may be configured with no membership
requirement (`communities = ["*"]`, from P2) for a deployment that would rather
trust the witness less with what it learns than gate who it serves.

The independence rule (from P2: a witness refuses sessions involving its own
DIDs or DIDs its operator excludes) is a floor, not a proof — pairwise
relationship DIDs can still hide an operator's own participation. A deployment
wanting stronger independence runs its witness under a separate operator.

## Roadmap

1. **P1 — the skeleton** (this release): the `dtg-witness` template, setup, up to
   ten identities, one mediator session each, discovery, the correlator warnings.
2. **P2 — witnessing**: independence (§3.2), community eligibility (§3.3), the
   session and submit protocol and VWC issuance (§3.4), session storage (excluded
   from backup) and attestation records, a sweeper, and an end-to-end test
   against the VTC's VWC verifier.
3. **P3 — the party side**: the VTA Trust Task that runs a witnessed session for
   its principal; the VTC's list of trusted witnesses.
4. **Later**: VWC revocation through a status list.
