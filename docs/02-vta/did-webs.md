# did:webs DIDs

**Status: alpha.** The KERI, ACDC, CESR and `did:webs` specifications are still
settling the questions the [positions note](../05-design-notes/did-webs-keri-v2.md)
answers. A `did:webs` created while the integration is alpha may have to be
created again. Don't use one for a trust relationship that must outlive that.

A VTA can create, host, update, rotate, deactivate and act as `did:webs`
identifiers, the way it does `did:webvh` ones. They are **persona,
relationship and integration DIDs**: identities the VTA holds for a person or
an integration in one of its trust contexts. The design is
[did:webs in the VTA](../05-design-notes/did-webs-in-the-vta.md); the wire is
the `vta/webs/dids/*/0.1` Trust Task family (dtgwg-trust-tasks-tf).

## A node's identity: not yet

The VTI specification now admits `did:webs` as an **optional**, alpha method
for the durable identity of a VTA, a VTC or a host service (VTI-KEY-001,
VTI-KEY-003). `did:webvh` stays the default. A node whose identity is a
`did:webs` acts as it only toward a peer whose DID document declares that it
resolves `did:webs`, and otherwise sends nothing (VTI-KEY-008, VTI-KEY-009).

This VTA cannot take a `did:webs` as its own DID yet: setup, first boot and
rotation for it are the next steps of the design note's plan (S6–S8). Until
then `create` with `--set-primary` on the context that holds this VTA's own
DID is still refused as `serviceDidNotPermitted`. A context provisioned for a
community, a VTN or a host service carries no marker saying so, so making a
`did:webs` the primary DID of one is not refused. Don't, yet.

### What is in place

- **Declaration.** Every DID document this VTA mints carries
  `"resolvedMethods": ["webs"]`, with the JSON-LD term in `@context`, and so
  do the built-in `vtc-host`, `room-host`, `dtg-witness` and `ballot-box`
  templates. A peer whose identity is a `did:webs` may act toward any of them.
  An existing DID gains the member when its document is next rebuilt.
- **The sending check.** A node acting as its own DID — the VTA through its
  outbound sender, the VTC toward its VTA, git bridge, ballot boxes and trust
  registry, room-host toward a watch address — refuses to send when that DID
  is of an optional method and the peer has not declared it:
  `methodNotDeclared`, naming the method and the peer. Today no node's DID is
  one, so the check passes every send.
- **The receiving refusal.** A Trust Task signed by a DID of a method this VTA
  does not resolve is refused `proofInvalid`, with `details.reason`
  `unsupportedDidMethod` and the `method`, not as an unexplained proof
  failure.

## Turning it on

Creation is off by default:

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
pnm webs create --context alice --server host-1 --path people --didcomm
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
