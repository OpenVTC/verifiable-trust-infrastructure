# did:webs in the VTA — creating, hosting and acting as one

**Status:** decided 2026-11-11; steps 1–7 implemented (2026-11-11). Operator guide: [did:webs DIDs](../02-vta/did-webs.md). **Alpha**, like the
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
| 1 | VTI `docs` | This note. *Done (#2558).* |
| 2 | VTI `vta-sdk` | Resolution everywhere (decision 9). *Done (#2560).* |
| 3 | dtgwg-trust-tasks-tf | `vta/webs/dids/{create,get,list,update,rotate-keys,delete}/0.1`. *Done (trust-tasks-tf#1082).* |
| 4 | VTI | Pin the family; `webs` keyspace; `KeySigner` over key custody; `create`, `get`, `list`; hosting with `method: "webs"`; the opt-in. *Done (#2561, #2562, and the wire).* |
| 5 | VTI | `update` (services, key agreement, aliases), `rotate-keys` (staged), `delete` (rotation to no next keys, then the slot removed). *Done (#2563, and the wire).* |
| 6 | VTI | Personas: `persona_key_for`, `own_document`; a room member on a `did:webs` persona, end to end. *Done (#2563), except the rooms end-to-end test.* |
| 7 | VTI | `pnm` / `cnm` commands; `docs/02-vta/did-webs.md`. *Done: `pnm webs …` (cnm has no DID commands to mirror) and the operator guide.* |
| 8 | dtgwg-vti-spec | Issue: name `did:webs` for a service DID once the key-role designation is adopted (VTI-KEY-001, the open issue under VTI-KEY-173). *Filed: dtgwg-vti-spec#120.* |

## 4. Service DIDs: a node's own identity as did:webs

**Status:** decided 2026-11-11 by the maintainer; S1–S5 done, S6–S8 to come.
The specification change is dtgwg-vti-spec#121 (refs #120), merged: `did:webs` becomes
an *optional*, alpha method for a node's durable identity (VTI-KEY-001);
`did:webvh` stays the default; a node uses a `did:webs` identity only toward a
peer that has declared it resolves `did:webs` (VTI-KEY-008), and otherwise
fails with `methodNotDeclared` and sends nothing (VTI-KEY-009).

### Decisions

1. **Keys are found by role, not by fragment, for every method.** Node code
   addresses its own keys as `{did}#key-0` (signing), `#key-1` (key agreement)
   and `#sealed-transfer-0`. A `did:webs` cannot publish those: a level-1
   method's id is the key itself, and the key-role designation's roles have
   key-derived ids. So the VTA, the VTC and the host services look their keys
   up in their own current document by relationship and role — the signing key
   by `assertionMethod`/`authentication`, the key agreement key by
   `keyAgreement`, the sealed-transfer key by its role — and keep the key id the
   document gives. This is what VTI-KEY-150 and key-roles step 3 ask for
   anyway, and it changes nothing a webvh peer sees.
2. **A did:webs node identity carries the key-role designation**
   (affinidi-did-webs `key_roles`: attestation, operational, messaging), so its
   signing, sealed-transfer and key agreement keys are distinct as a webvh
   node's are. Without the designation it would be level 1 with one key for
   everything.
3. **First boot registers self-certifyingly.** A node's `did:webs` must be on a
   host before it exists, and today a VTA proves itself to a host with its own
   DID. The host (affinidi-webvh-service) accepts a `did/register/0.1` for a
   `did:webs` whose request is signed by the key the submitted KEL's inception
   names — the KEL proves control — on a domain whose operator allows
   self-registration. No interim identity, no manual step.
4. **Peers declare in their DID document.** `resolvedMethods` (VTI-KEY-008), a
   top-level member read from a peer's verified current document, the way
   protocols are matched today (`vta_sdk::protocol::matching`). A webvh node
   lists it in its own document; a party that addressed the node under its
   `did:webs` has shown it resolves it.

### Order of work

| # | Where | What |
|---|---|---|
| S1 | dtgwg-vti-spec | #121: VTI-KEY-001, 003, 008, 009. *Done.* |
| S2 | dtgwg-trust-tasks-tf | `vta/webs/dids/create/0.2`: templates, and service identities. *Done (trust-tasks-tf#1159); pinned and served in VTI.* |
| S3 | affinidi-webvh-service | Self-certifying `did/register/0.1` for `did:webs`. *Done (webvh-service#411).* |
| S4 | VTI | Node keys by role, for every method (decision 1). *Done (#2670).* |
| S5 | VTI | `resolvedMethods` in node documents and templates; the declaration check and both refusals. *Done (below).* |
| S6 | VTI | A did:webs VTA identity: setup (interactive and TOML), first boot through S3, the key-role designation, readiness, the self-DID preload, `didcomm_light`, runtime services through `update_did_webs`, rotation of its own DID. *Done (#2675 and the PRs after it), except the wire for rotating role keys, which belongs to the `vta/dids` family (trust-tasks-tf#993): the operation restarts the VTA to load keys whose ids changed, rather than swapping them live.* |
| S7 | VTI | A did:webs VTC identity, and host services minted through provision-integration templates |
| S8 | VTI | TEE first boot (the enclave publishes to a host) |

### S5: where the declaration is made and checked

The rule and the declaration are `vta_sdk::resolved_methods`: the required
methods, what this build resolves (`RESOLVED_HERE`) and declares
(`OPTIONAL_METHODS_DECLARED`, `["webs"]`), the lenient reader of a peer's
`resolvedMethods`, `require_declared`, and `declare` (with the JSON-LD term).

- **Declared** in every document the VTA mints
  (`build_did_document_inner`), and in the built-in templates for the nodes
  this workspace runs: `vtc-host`, `room-host`, `dtg-witness`, `ballot-box`.
  Templates for software outside the workspace (mediator, trust registry, push
  gateway) declare nothing; what they resolve is not ours to say.
- **Checked** where a node initiates as its own DID and has already resolved
  the peer's document to choose a transport: the VTA's `Outbound::send`
  (when the VTA's DID is the issuer or the TSP/DIDComm sender — a persona
  issuing over HTTPS is not the VTA's durable identity); the VTC's
  `PeerTasks::select` (its VTA, git bridge, ballot boxes, watch addresses) and
  its trust-registry selection; room-host's watch signals.
- **Not checked, by the rule's own exception**: the Trust-Task push engine
  (`vti_common::trust_task_push`). Every push goes to a party in a
  relationship that addressed the node under its identity — an enrolled
  approver device, a holder that asked for a credential, a joined member — and
  a member's `did:key` carries no document to declare in.
- **To check when a node can be did:webs (S6, S7)**: the sends that do not go
  through a resolving seam — the VTA's push-gateway allowlist and wake
  (`trust_tasks/device.rs`, `step_up.rs`, straight to the DIDComm bridge),
  the VTC's hook writer (`send_trust_task_didcomm`) and VTN requests
  (`vti-vtn` `send_request_to`, HTTPS to a configured URL), and mediator
  login.
- **Refused on receipt**: a proof whose signer is of a method this build does
  not resolve is `DiProofError::UnsupportedDidMethod`, before any resolver is
  asked, answered `proofInvalid` with `details.reason` `unsupportedDidMethod`
  and the `method` (VTA, the Trust-Task spine, VTC). Both refusals read back
  into typed `VtaError` variants.
