# did:webs in the VTA — creating, hosting and acting as one

**Status:** decided 2026-11-11, implementation not started. **Alpha**, like the
rest of the `did:webs` integration ([did-webs-keri-v2.md](did-webs-keri-v2.md)):
expect breaking changes as the KERI and `did:webs` specifications settle.

**Goal.** A VTA can use `did:webs` the way it uses `did:webvh` and
`did:scid:vh:1`: create one in a trust context, host it, update and rotate it,
deactivate it, and act as it, with every party in the stack able to resolve
it. Today VTI only *verifies* `did:webs`: the resolver reads it, and a VTC
accepts a member who rotates onto one. Nothing creates, hosts or updates one,
and the VTA cannot act as one.

## 1. What the specification allows

The VTI specification sorts DIDs into three classes (§ DID classes,
VTI-KEY-190 – 192):

| Class | Methods | `did:webs`? |
|---|---|---|
| Relationship DID (pairwise, per community) | any | **Yes** |
| Persona DID (a person's own identity) | `did:webvh`, any | **Yes** |
| Service DID (the durable identity of a VTA, VTC, host service) | `did:webvh`, `did:scid:vh:1` (VTI-KEY-001) | **No** |

So a VTA creates, hosts and acts as `did:webs` **persona, relationship and
integration DIDs**, at level 1: one signing key, no key roles.

A **service DID** stays `did:webvh` or `did:scid:vh:1`. VTI-KEY-001 names only
those, VTI-KEY-003 forbids requiring a peer to resolve anything else, and the
specification says naming `did:webs` there "waits on the extension's adoption"
(the key-role designation, proposed to the `did:webs` specification). The VTA
and the VTC refuse a `did:webs` as their own durable identity, citing
VTI-KEY-001. Making it eligible is a specification change, raised as an issue
on dtgwg-vti-spec. It is not a divergence taken in code.

A **key-role identity** under `did:webs` (level 2 or 3) comes through the
method-neutral `vta/dids/*` family and its `webs` method profile:
[key-roles-implementation.md](key-roles-implementation.md) step 7 onward. This
note is the level-1 path, and that one builds on it: the same keys, store and
hosting.

## 2. Decisions

1. **Wire: a `vta/webs/dids/*` Trust Task family**, as `vta/webvh/dids/*` is
   for `did:webvh`: `create`, `get`, `list`, `update`, `rotate-keys` and
   `delete`, at `0.1`. It is specified in dtgwg-trust-tasks-tf and pinned in
   `vti-specs-vta`. Adding `webs` to `webvh/dids/create`'s `didMethod` is not
   done: that field chooses how a webvh *log* is presented (`webvh` or `scid`),
   and its other fields (`didLog`, `portable`, `preRotationCount`) have no
   meaning for a key event log.
2. **KERI v2, JSON bodies**, through `affinidi_did_webs::create_controlled`,
   `update_controlled` and `prepare_rotation` / `complete_rotation`. The VTA
   holds the keys. The crate signs through a `KeySigner` the VTA implements
   over the key custody door (`operations::key_custody`), so no secret leaves
   `vta-keys`.
3. **Keys: one Ed25519 signing key (`kt 1`), one pre-rotated successor
   (`nt 1`)**, both derived from the seed under the context base, as webvh's
   signing and pre-rotation keys are (`vta_keys::derive_pre_rotation_keys`).
   The successor's digest is committed in `n`; its key record is made at
   creation and is inactive until the rotation that installs it. A rotation
   derives the next successor the same way.
4. **Messaging: designated services and a designated key agreement key.**
   `#didcomm` and `#tsp` are designated services (`DesignatedService`), typed
   `DIDCommMessaging` and `TSPTransport` like webvh's, so peers match them on
   `type`. Key agreement is a designated X25519 key (`KeyAgreementKey`),
   derived as webvh's level-1 key agreement key is, never the X25519 converted
   from the KERI signing key: the KSWG follow-up drops converted keys, and a
   designation outlives a rotation.
5. **Hosting: the did-hosting service, method `webs`.** `did/register/0.1`
   with `method: "webs"`, the slot path ending in the AID and the `keri.cesr`
   stream as `didData`. The host derives `did.json` on every read and builds
   the DID from the slot (affinidi-webvh-service `docs/did-webs-hosting.md`).
   The host must run with `method-webs`. A VTA has no inbound surface, so
   there is no self-hosted `did:webs`.
6. **Store: a `webs` keyspace**, one row per DID: the DID, its context, its
   host server and slot, the published `keri.cesr`, the controller state
   (sequence number, last SAID, keys, next digests) and the key ids of the
   current and next keys. It is backed up: a restore must be able to continue
   the log. It is listed in the backup partition census.
7. **Remote first (R2.1).** Every change is published to the host before the
   local row is committed. A rotation is staged first, so a process that dies
   between the publish and the commit resumes from the staged event, as webvh's
   `recover_staged_rotations` does.
8. **Acting as one.** `persona_key_for` and `own_document` answer for a
   `did:webs` this VTA holds from the stored `keri.cesr`, with no resolution:
   the current signing key, as the KEL's key state names it, under
   `{did}#{key}`. The context rules are the persona rules.
9. **Resolution everywhere.** `vta_sdk::did_scid::is_network_resolved`, the
   host session's network probe and `url_from_did` treat `did:webs` as the
   network-resolved method it is. `is_durable` does not, by VTI-KEY-001.
10. **Clients.** `pnm webs …` and `cnm webs …` mirror `pnm webvh dids …`, over
   `VtaClient` methods for the family. Errors name the fix, as elsewhere: a
   host without `method-webs` answers with what to enable.
11. **Opt-in while alpha.** `[dids] webs_enabled` (default `false`) gates
   `create`. An existing `did:webs` keeps working with it off, so turning it off
   never strands one.

## 3. Order of work

| # | Where | What |
|---|---|---|
| 1 | VTI `docs` | This note |
| 2 | VTI `vta-sdk` | Resolution everywhere (decision 9) |
| 3 | dtgwg-trust-tasks-tf | `vta/webs/dids/{create,get,list,update,rotate-keys,delete}/0.1` |
| 4 | VTI | Pin the family; `webs` keyspace; `KeySigner` over key custody; `create`, `get`, `list`; hosting with `method: "webs"`; the opt-in |
| 5 | VTI | `update` (services, key agreement, aliases), `rotate-keys` (staged), `delete` (rotation to no next keys, then the slot removed) |
| 6 | VTI | Personas: `persona_key_for`, `own_document`; a room member on a `did:webs` persona, end to end |
| 7 | VTI | `pnm` / `cnm` commands; `docs/02-vta/did-webs.md` |
| 8 | dtgwg-vti-spec | Issue: name `did:webs` for a service DID once the key-role designation is adopted (VTI-KEY-001, the open issue under VTI-KEY-173) |
