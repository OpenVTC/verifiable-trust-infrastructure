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

> **Status: P2, witnessing; P3 party side in the VTA.** An enabled identity
> opens witness sessions, verifies the party's presentation and issues a VWC
> ([The protocol](#the-protocol)). A VTA can be the party for its principal —
> `vta/witness/{open,present,accept}`, the client carrying the documents
> ([the VTA as a witnessed party](../02-vta/witness-party.md)). The VTC's list
> of trusted witnesses is still to come.

## What it is

- **One binary, up to ten witness identities.** Each identity is its own
  `did:webvh`, with its own mediator session and its own policy, so one
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

[independence]                       # service-wide; optional
exclude = ["did:webvh:Qm…:community.operator.example"]

[[witness]]
name         = "community-a"
did          = "did:webvh:Qm…:witness.independent.example:a"
mediator_did = "did:webvh:Qm…:mediator.independent.example"
enabled      = true
communities  = ["did:webvh:Qm…:vtc.community-a.example"]   # or ["*"]
# allowed_parties = ["did:key:z6Mk…"]                      # optional allow-list

[witness.independence]               # this identity only; optional
exclude = ["did:key:z6Mk…"]

[witness.sessions]                   # optional; defaults shown
ttl_secs           = 600
max_open           = 1000
max_open_per_party = 4
```

Setup writes each identity with the restrictive defaults — off, and witnessing
nobody — so an operator turns an identity on and names its communities by
editing `config.toml`.

| Key | Meaning |
|---|---|
| `data_dir` | Local state: the plaintext secret store if one is explicitly chosen, and setup's `did/<name>.jsonl` logs. |
| `operator_vta_did` | The VTA that minted the identities. Read only to warn about correlators; the witness never acts as it. |
| `resolver_url` | Optional DID resolver sidecar (network mode). |
| `[secrets]` | The secret-store backend — the same table and backends as the VTA and VTC. `config_seed` is refused, since it would put keys in this file. |
| `[independence] exclude` | DIDs no identity of this service witnesses (§3.2). The service's own witness DIDs and `operator_vta_did` are always excluded and need not be listed. |
| `[[witness]]` | 1–10 identities: `name` (local label, `a-z0-9-_`), `did`, `mediator_did`, `enabled` (default **false**). |
| `communities` | The VTC DIDs whose members this identity witnesses (§3.3). **Empty — the default — witnesses nobody**; `["*"]` witnesses anyone who passes the cheap checks, with no membership evidence asked for. `"*"` cannot be combined with DIDs. |
| `allowed_parties` | Optional exact-DID allow-list of session openers, for a closed deployment. Unset admits anyone; an empty list is refused at load (it would admit nobody). |
| `[witness.independence] exclude` | DIDs this identity alone excludes, on top of the service-wide list. |
| `[witness.sessions]` | `ttl_secs` (1–86400, default 600), `max_open` (default 1000) and `max_open_per_party` (default 4, at most `max_open`). |

Every key is checked: an unknown one anywhere, including inside `[secrets]`, is a
load error rather than a silently ignored setting. Names and DIDs must be unique,
no identity may be the operator VTA's own DID, and every DID list must hold DIDs.
`run` warns about an enabled identity whose `communities` is empty.

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

A sweeper removes expired sessions and duplicate-execution records every minute.
SIGINT or SIGTERM closes every session and exits.

## What it serves

Each identity answers only documents addressed to **its own DID**, from a
sender the transport proved, and every answer is signed by that identity's own
key. Nothing is signed as, or names, the operator's VTA.

| Type | Answer |
|---|---|
| `trust-task-discovery/0.3`, `/0.1` | This identity's task list: the four types in this table. |
| `witness/session/0.1` | A session and its challenge — [The protocol](#the-protocol). |
| `witness/session/submit/0.1` | The VWC and its digest — [The protocol](#the-protocol). |
| Any other type | `unsupportedType` (`unsupportedVersion` for another version of discovery). |

Only an enabled identity is connected at all, so "listed in discovery" and
"enabled" are the same fact.

Every inbound document goes through the framework's §7.2 checks before anything
is dispatched: freshness (the ten-minute acceptance window every VTI node
applies, `issuedAt` required), expiry, `recipient` equal to this identity, an
in-band `issuer` consistent with the proven sender, the task specification's own
requirements (a `submit` must carry a proof), and — where a proof is present —
verification of that proof against the document's `issuer`. A `trust-task-error`
or a `#response` is never answered: the witness sends no requests, so nothing is
waiting for one.

**Duplicates (§7.2 item 11).** Both witness tasks keep a record of every
accepted document `id` with a digest of the whole document, in the store, for
the document's acceptance window. The same document again — a mediator
redelivery, a retry — is answered with the first reply, and nothing happens
twice; a different document under a used `id` is `idConflict`.

## The protocol

A witnessed exchange between two parties runs **two sessions** with the same
witness, one per party, both naming the same `parties` pair. Each yields one VWC
attesting that party's issuance of its relationship credential.

### `witness/session/0.1`: open a session

The party sends the two relationship DIDs (`parties`), on a document whose
`threadId` is its own `id` (it names the session, and the VWC cites it). The
witness checks, cheaply and in this order:

1. the opener — the transport-proven `issuer` — is one of `parties`, and the
   two parties differ;
2. **independence**: neither party is one of this service's witness DIDs, the
   operator's VTA, or an excluded DID;
3. the identity witnesses somebody (`communities` is not empty), and
   `allowed_parties`, if set, names the opener;
4. the caps: fewer than `max_open` sessions open at this identity, and fewer
   than `max_open_per_party` opened by this party.

Any failure is `witness/session:refused`, always with the same message: a
refusal naming the rule would let anyone probe which DIDs the operator excludes.
The rule is logged locally. A session document not on its own thread is
`malformedRequest`.

Otherwise the witness draws a 32-byte challenge from the OS RNG, sets `domain`
to its own DID, stores the session — opener, `parties`, challenge, domain, the
session document byte for byte as received, and the expiry (`ttl_secs`) — and
answers `{ challenge, domain }` in a signed `#response`.

### `witness/session/submit/0.1`: submit and receive the VWC

The party sends a signed document **on the session's thread** (`threadId` = the
session document's `id`) carrying `vp`, a W3C Verifiable Presentation bound to
the session: the challenge in its `nonce` (the member the workspace's VP builder
signs it into; `challenge` is accepted too) and the domain in its `domain`, both
covered by the presentation's proof.

**The binding is checked first.** The session must be open and unexpired, the
submitter must be the party that opened it, and the VP's `nonce`/`domain` must
be that session's. Any failure is `witness/session/submit:challengeMismatch` —
before the presentation is looked at, so a replay from another session reads as
one, not as a broken presentation.

**Then the presentation.** Any failure here is
`witness/session/submit:presentationInvalid`, and the session stays open:

- the VP is a `VerifiablePresentation` whose `holder` is the submitter, and
  every proof on it verifies for `authentication` under the submitter's key;
- every credential in it has an issuer proof that verifies for
  `assertionMethod` under a key of its `issuer`, and is within its validity
  window;
- exactly one `RelationshipCredential` is issued by the submitter, and its
  subject is the session's other party — this is the credential the VWC names;
- unless `communities = ["*"]`, a community-issued `MembershipCredential` from
  one of `communities` names the submitter as its subject, **or** the payload
  carries a member presentation (the *member link*, below);
- independence again: no credential is issued by an excluded DID (an excluded
  community counts for nothing even when listed), and neither party is excluded.

#### The member link

A party submits from its pairwise relationship DID, but its community's
membership credential names its member DID. To bridge the two, the payload may
carry a second presentation in the vendor extension:

```json
{
  "vp": { "...": "the relationship presentation, holder = the relationship DID" },
  "ext": {
    "org.openvtc.witness": {
      "memberPresentation": {
        "type": ["VerifiablePresentation"],
        "holder": "did:…member",
        "verifiableCredential": [ { "...": "the community's MembershipCredential naming did:…member" } ],
        "nonce": "<this session's challenge>",
        "domain": "<this session's domain>",
        "proof": { "proofPurpose": "authentication", "...": "signed by did:…member" }
      }
    }
  }
}
```

It counts when it is a presentation by the member DID, signed for
`authentication`, bound to **this** session's challenge and domain, and carries a
valid membership credential from one of `communities` naming its holder. The
member DID may not be the other party or an excluded DID. A failure is
`presentationInvalid`; any other member of `org.openvtc.witness` is
`malformedRequest`. The VWC names the relationship DID, never the member DID,
which is kept and logged nowhere.

**Know what it does and does not prove.** It proves the submitter also held a
member key in this session. It does not prove they are the same person: a member
who signs for somebody else lends them eligibility, and the witness cannot see
that happen. The witness also learns *which member* is behind the relationship
DID, not only which community. The link is an `ext` extension that other witness
implementations ignore, and VWC verifiers cannot see that it was used. The design
note (§3.3a) covers the risks and the options for later: an upstream spec member,
a pairwise membership credential, a zero-knowledge membership proof, and
recording the evidence in the VWC.

**Then the session is spent.** It is removed atomically, so of two submissions
racing on one session exactly one mints; the other is `challengeMismatch`.

**Then the VWC**, a DTG `StatementCredential` under
`https://registry.trustoverip.org/dtg/vsc/witnessed/1`
(`dtg_credentials::DTGCredential::new_witnessed_vsc`): `issuer` this identity,
`issuerScope: public`, `credentialSubject.id` the submitter,
`credentialSubject.object.digestMultibase` the relationship credential's digest,
and `taskContext` / `taskDigestMultibase` naming the stored session document. It
is signed `eddsa-jcs-2022` with the identity's `assertionMethod` key (`#key-0`).
The answer is `{ vwc, vwcDigestMultibase }` in a signed `#response`, where
`vwcDigestMultibase` is the sha2-256 multihash, base58btc, of the RFC 8785
canonicalization of the VWC **including its proof**.

A holder keeps the session document and the `submit#response` with the VWC: a
verifier needs both to recompute the task digest and to pair the credential with
its evidence (`witness/session/submit` §*This response is the outcome evidence*).

### What is kept

| Kept | Where | For how long |
|---|---|---|
| Open sessions (including the session document) | `witness_sessions` | until submitted or expired — never backed up |
| Accepted document `id`s and their digests, and each reply | `witness_accepted_ids` | the acceptance window — never backed up |
| **Attestation records**: VWC `id`, `vwcDigestMultibase`, submitter, session `id`, identity, time | `witness_attestations` | kept, for revocation (a later phase) |
| **The presentation** | nowhere | verified in memory and discarded, never logged |

The store is `<data_dir>/store`.

## Correlators

The witness DID is meant to be seen. What should not be seen is the link between
a witness and its operator (VTI-CMP-062). At setup and at every start the
service **warns** — it never refuses — about the two it can detect:

| Correlator | Where it shows | Mitigation |
|---|---|---|
| The witness DID | Every VWC and session | Intended: the witness is public by design |
| Its mediator | The mediator sees the witness's sessions | Use a mediator other than the operator VTA's. Warned about when they share one |
| Its DID-log host | Anyone resolving the witness | Host the log apart from the operator's own domains. Warned about when they share one |
| The `parties` pair | The witness, at session open | Inherent: it is how two sessions are known to observe one exchange. A witness accumulates a graph of who transacts with whom |
| Community membership | The witness, at submit | Inherent to community-keyed eligibility; `["*"]` asks for none |
| The member DID, under the member link | The witness, at submit | Links the pairwise DID to the member's community identity. Seen, never stored or logged; avoid by `["*"]` |
| Credential identifiers in the presentation | The witness, at submit | Inherent: credential `id`s, issuers and status entries are read in full and could link a pairwise DID to a wider identity. Nothing is stored |
| Attestation records | The witness operator | Kept only for revocation; no presentation is kept |
| The VWC's `taskContext` / digests | Every verifier shown the VWC | Intended: they bind it to one session and one credential, so two verifiers shown it can tell it is the same |

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
requirement (`communities = ["*"]`) for a deployment that would rather
trust the witness less with what it learns than gate who it serves.

The independence rule (a witness refuses sessions involving its own DIDs, its
operator's VTA or DIDs its operator excludes) is a floor, not a proof — pairwise
relationship DIDs can still hide an operator's own participation. A deployment
wanting stronger independence runs its witness under a separate operator.

## Roadmap

1. **P1 — the skeleton**: the `dtg-witness` template, setup, up to
   ten identities, one mediator session each, discovery, the correlator warnings.
2. **P2 — witnessing** (this release): independence (§3.2), community eligibility (§3.3), the
   session and submit protocol and VWC issuance (§3.4), session storage (excluded
   from backup) and attestation records, a sweeper, and an end-to-end test
   against the VTC's VWC verifier.
3. **P3 — the party side**: the VTA side is done — `vta/witness/open`,
   `vta/witness/present` and `vta/witness/accept` (trust-tasks-tf #779), in which
   the VTA builds and signs every document as the principal's relationship DID
   and the client carries them, because the relationship DID's one mediator
   connection is the client's ([the VTA as a witnessed party](../02-vta/witness-party.md)).
   The end-to-end test drives this service's dispatch core as the witness. The
   VTC's list of trusted witnesses remains.
4. **Later**: VWC revocation through a status list.
