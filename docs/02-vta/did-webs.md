# did:webs DIDs

**Status: alpha.** The KERI, ACDC, CESR and `did:webs` specifications are still
settling the questions the [positions note](../05-design-notes/did-webs-keri-v2.md)
answers. A `did:webs` created while the integration is alpha may have to be
created again. Don't use one for a trust relationship that must outlive that.

A VTA can create, host, update, rotate, deactivate and act as `did:webs`
identifiers, the way it does `did:webvh` ones. The design is
[did:webs in the VTA](../05-design-notes/did-webs-in-the-vta.md); the wire is
the `vta/webs/dids/*/0.1` Trust Task family, and `vta/webs/dids/create/0.2`
(dtgwg-trust-tasks-tf), served beside `create/0.1`.

## A node's identity

The VTI specification admits `did:webs` as an **optional**, alpha method for
the durable identity of a VTA, a VTC or a host service (VTI-KEY-001,
VTI-KEY-003). `did:webvh` stays the default. A node whose identity is a
`did:webs` acts as it only toward a peer whose DID document declares that it
resolves `did:webs`, and otherwise sends nothing (VTI-KEY-008, VTI-KEY-009).

**A VTA** can be set up with a `did:webs` as its own DID: `vta setup`, VTA DID
kind `create_webs` (see [non-interactive setup](non-interactive-setup.md)). It
is a key-role identity — distinct attestation, operational and messaging keys
(VTI-KEY-173) — minted offline and registered at its host on its own
authority at first boot, which the host must allow
(`[[hosting.webs_self_register]]`) and whose DID document must declare
`resolvedMethods: ["webs"]`. Its runtime services (`pnm services …`) are
designations, published as for any did:webs; its role keys rotate by a new
designation, after which the VTA restarts to load them. It cannot be deleted
while it is the VTA's DID, and `create --set-primary` on its context is still
refused: re-identifying the VTA is setup's job.

**A TEE VTA** asks for one with `[tee.kms.vta_did_webs]` (server DID, domain,
optional path) in an enclave image built with the `webs` feature: first boot
mints the same key-role identity inside the enclave and publishes it the same
way, through the enclave's egress proxy, which allowlists the host and the
domain from that setting (see the TEE architecture guide, *A did:webs
identity*).

A VTC or host service as a `did:webs` is the next step (the design note's S7).

### What is in place for every node

- **Declaration.** Every DID document this VTA mints carries
  `"resolvedMethods": ["webs"]`, with the JSON-LD term in `@context`, and so
  do the built-in `vtc-host`, `room-host`, `dtg-witness` and `ballot-box`
  templates; the `did-host-*` templates take it as `RESOLVED_METHODS`. A peer
  whose identity is a `did:webs` may act toward any of them. An existing DID
  gains the member when its document is next rebuilt.
- **The sending check.** A node acting as its own DID — the VTA through its
  outbound sender, the VTC toward its VTA, git bridge, ballot boxes and trust
  registry, room-host toward a watch address — refuses to send when that DID
  is of an optional method and the peer has not declared it:
  `methodNotDeclared`, naming the method and the peer.
- **The receiving refusal.** A Trust Task signed by a DID of a method this VTA
  does not resolve is refused `proofInvalid`, with `details.reason`
  `unsupportedDidMethod` and the `method`, not as an unexplained proof
  failure.

## DID classes

`create/0.2` creates every DID in a stated **class**, recorded with it and
fixed for its life (VTI-KEY-190 – 193):

| `--class` | What it is |
|---|---|
| `relationship` | an identifier for one relationship, community or trust context |
| `persona` | a person's own identity |
| `service` | the durable identity of a node or a service: the VTA, a VTC, a VTN, a host service, an integration |

A `create/0.1` (`pnm webs create` without `--class`) states no class, and the
VTA records none and infers none; the family reads that as "not a service DID".

A DID belongs to one class only, so a create whose class disagrees with the
identity it would become or replace is refused as `didClassConflict`:

- a `persona` or `relationship` DID with `--set-primary` on a context whose
  primary DID is a service DID — this VTA's own DID, or a `did:webs` it created
  as `service` (`requiredClass: service`);
- a `service` DID with `--set-primary` on a context whose primary DID is a
  persona `did:webs`;
- a DID made from a template of a node's kind (`mediator`, `dtg-witness`,
  `push-gateway`, `trust-registry`, `vtc-host`, `room-host`, `ballot-box`,
  `did-host-*`) in a class other than `service` (the specification's MAY).

A create never re-identifies this VTA: `--set-primary` on the context holding
its own DID is refused for a `service` DID too (`permissionDenied`; a 0.1
create answers `serviceDidNotPermitted`). Setting a VTA up as a `did:webs` is
`vta setup`'s job.

The VTA knows a context's primary DID's class only for its own DID and the
`did:webs` DIDs it created in a class. A context provisioned for a community, a
VTN or a host service carries no marker saying so, so a persona `did:webs` made
the primary DID of one is not refused. Don't.

## Service DIDs

A `did:webs` service DID is **optional and alpha** (CONVENTIONS.md 0.2 §1.1,
dtgwg-vti-spec#120), at key assurance level 1 — one signing key, no key roles —
and is off unless enabled on its own:

```toml
[dids]
webs_enabled = true        # creation at all
webs_service_dids = true   # or VTA_DIDS_WEBS_SERVICE_DIDS=true
```

With it off, `--class service` is refused as `serviceDidNotPermitted`, and
nothing is derived. Turning it off affects no service DID already created.
Its key agreement key and services are designations that resolve in full only
for verifiers whose `did:webs` resolver implements them, and a peer that has
not declared `did:webs` resolution may not verify it at all: keep a
`did:webvh` identity for such peers. VTI-KEY-196 recommends level 2 or higher
for a VTA, VTC or VTN identity, which this task does not create (that is
`vta/dids/create` with the `webs` profile).

## Templates

`create/0.2` can shape a DID from a [DID template](did-templates.md) instead of
`--didcomm`, `--tsp` and `--also-known-as` (never both):

```sh
pnm webs create --context bots --server host-1 --class service \
  --template ai-agent --var MEDIATOR_DID=did:webvh:…:mediator.example
```

The template resolves in `--template-context`, then the global scope, then the
built-ins, and its variables are checked as `did:webvh` creation checks them
(`templateNotFound`, `templateVarsInvalid`). A `did:webs` document is derived,
not authored, so the VTA reads the template rather than publishing it
(CONVENTIONS.md 0.2 §9.2): it must describe exactly one Ed25519 signing key in
`authentication` and `assertionMethod`, one X25519 key agreement key in
`keyAgreement`, services (designated, ids reduced to fragments) and aliases
(designated after the DID itself and the did:web twin and did:keri form every
`did:webs` designates). Anything else is refused as
`templateNotRepresentable`, with the rule (`reason`) and the members (JSON
Pointers) — a key-role template, another key or algorithm (`swiyu-verifier`),
another verification method or relationship, a member the derivation does not
render. The check runs before any key is derived: a refused template leaves
nothing behind. The checker is `vta_sdk::did_templates::webs::map_webs_document`.

The VTA computes the inception first, because the AID is its digest and
`{DID}` is the final DID, renders the template with the real DID and keys,
and only then writes the designations and publishes.

A template's `resolvedMethods` member is ignored, as its `@context` is
(CONVENTIONS §9.2): a did:webs node declares did:webs by using it. So the node
built-ins that carry it (`dtg-witness`, `did-host-*`, `room-host`,
`ballot-box`) are representable; `vtc-host` is not, for its post-quantum
second signing key, which a level-1 did:webs cannot hold.

## Provisioning an integration as a did:webs

A host service provisioned through [provision-integration](provision-integration.md)
(`vti-witness`, `vti-voting-service`, any template-driven integration) can take
a `did:webs` instead of a `did:webvh` with one more template variable,
`DID_METHOD=webs`:

```sh
pnm bootstrap provision-request --template dtg-witness \
  --var MEDIATOR_DID=did:webvh:…:mediator.example \
  --var WEBVH_SERVER=host-1 --var WEBVH_PATH=witnesses --var DID_METHOD=webs
```

In the host services' setup files it is `did_method = "webs"` beside
`webvh_server`. The DID is minted exactly as a `create/0.2` with
`--class service` and `--template` would mint it — level 1, the same §9.2
checks and refusals, gated by `webs_service_dids` above — and published at
`WEBVH_SERVER`, on `WEBVH_DOMAIN`, under the slot path `WEBVH_PATH`. There is
no serverless mode, so `URL` alone is refused, as are `.well-known` and
`SCID_ALSO_KNOWN_AS`. No new member is added to `provision/integration`: the
method is a template variable, as `DID_METHOD=scid` already was.

The sealed bundle is the `TemplateBootstrap` every opener reads. Its keys are
the key-state key (`authentication` and `assertionMethod`) and the designated
X25519 key agreement key, each under the id the document gives it
(`<did>#<CESR key>`); `config.did_document` is the document the stream
derives; and in place of a `did.jsonl` it carries the stream itself as the
output `webs_keri_cesr` (`ProvisionResult::webs_keri_cesr`). An opener built
before that output existed refuses such a bundle by name (`unknown variant
`webs_keri_cesr``); every other bundle is unchanged. The integration signs its
Trust Tasks with the key its document lists for authentication
(`DidSecretsBundle::trust_task_signing_key_for`, VTI-KEY-150), and the bundle
it stores leads with that key. A context-secrets export of a `did:webs`
(`build_did_secrets_bundle`, what room-host fetches) holds exactly the keys
its document lists — never the pre-rotated successor — led the same way.

A host service's `did:webs` is still used only toward peers that declare they
resolve `did:webs` (VTI-KEY-008).

## Turning it on

Creation is off by default (service DIDs have a switch of their own, above):

```toml
[dids]
webs_enabled = true      # or VTA_DIDS_WEBS_ENABLED=true
```

The setting gates `create` only. With it off, an existing `did:webs` keeps
resolving and every other task still works on it, so turning it off never
strands one.

## Hosting

A `did:webs` is published on a did-hosting server this VTA has registered
(`pnm did-mgmt servers add`), the same servers that host `did:webvh`. A VTA has
no inbound surface, so there is no self-hosted `did:webs`.

The server must be built with its `method-webs` feature: without it, create is
refused as `hostDoesNotHostWebs`. The VTA publishes the key event stream,
`keri.cesr`, by `did-management/did/register/0.1` with `method: "webs"`; the
host derives `did.json` from it on every read, and builds the DID from the
domain and slot:

```
did:webs:<domain>:<path segments>:<AID>
https://<domain>/<path>/<AID>/keri.cesr
https://<domain>/<path>/<AID>/did.json
```

## What a did:webs holds

- **Keys.** One Ed25519 signing key (`kt 1`) and one pre-rotated successor,
  committed by its digest (`nt 1`), both derived by the VTA from its seed under
  the context's base path. KERI v2 events, JSON bodies.
- **Designations.** Everything else in the document is an ACDC the AID issues
  to itself in its own registry, anchored in its key event log: the aliases
  (the DID itself first), the key agreement key, and the services.
- **Key agreement.** A designated X25519 key, never the X25519 key converted
  from the signing key.
- **Messaging.** `#didcomm` (`DIDCommMessaging`) and `#tsp` (`TSPTransport`)
  are designated services through this VTA's mediator, matched by peers on
  their `type`.

## Commands

```sh
pnm webs create --context alice --server host-1 --path people --didcomm --class persona
pnm webs create --context bots --server host-1 --class service --template ai-agent --var MEDIATOR_DID=…
pnm webs get    did:webs:hosting.example:people:EKYL…  [--keri-cesr]
pnm webs list   [--context alice] [--server host-1] [--include-deactivated]
pnm webs update did:webs:… --services didcomm,tsp
pnm webs update did:webs:… --rotate-key-agreement
pnm webs update did:webs:… --also-known-as did:web:alice.example   # or --clear-aliases
pnm webs rotate did:webs:…
pnm webs delete did:webs:…
```

Every write takes `--expect-version <sn>:<said>` (the `versionId` from `get`),
and is refused as `versionConflict` when the DID has moved on. A refusal the
operator can fix prints what to do.

## Rotation

`rotate` installs the committed successor as the signing key and commits a
fresh one. It is staged before it is published: if the host doesn't take it,
the rotation stays staged, `get` reports `rotationStaged`, and the next write
completes it rather than rotating twice (`resumed: true`). A rotation the host
refuses for good blocks further writes until it is resolved on the host.

An update writes interaction events and never changes the keys. An update that
changes several kinds of designation writes the events of each, published
together.

## Deactivation

`delete` rotates to no next keys, which no later event can follow, commits
that, then removes the slot from the host. It cannot be undone. The record is
kept, deactivated, with the final stream. Deleting a deactivated DID publishes
nothing and only retries the slot removal.

## Acting as one

A `did:webs` persona works wherever a persona does (rooms, credentials):
`persona_key_for` and `own_document` answer for it from the stream this VTA
published, with no resolution.
