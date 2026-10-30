# Key roles: design

**Status:** design, revised 2026-10-30 to key assurance levels, and expanded 2026-10-31 with the signing/encryption distinction, the per-role rationale, a worked community deployment and the design principles. Two maintainer decisions of 2026-10-31 are recorded in §5.4 (the level is set per service, through the DID template) and §15 (retiring the old key on a raise is a SHOULD, not a MUST); the draft spec PRs do not yet carry them. The first design is merged (dtgwg-vti-spec#79, dtgwg-trust-tasks-tf#986) but has not been published for working-group review. The level revision is proposed in dtgwg-vti-spec#82 and dtgwg-trust-tasks-tf#993, both drafts. The build order is in [key-roles-implementation.md](key-roles-implementation.md). **Implementation is paused:** no code has landed, and no step starts without the maintainer's go-ahead.

**Normative sources:**
- **The VTI specification**, chapter *Identity, DIDs and Key Management* (`spec/04-identity-keys.md`). The relevant sections run from *DID classes* through *Authenticator keys*: VTI-KEY-070 to 221.
- **The `vta/dids/*` Trust Task family:**
  - `vta/dids/_shared/0.1`: `CONVENTIONS.md`, `key-roles.schema.json` and `method-profiles/`;
  - `create/1.1`;
  - `upgrade/1.0`;
  - `update`, `keys/{list,add,rotate,retire,revoke}` and `recover`, at 1.0.

Where this note disagrees with either source, the source is right.

This note covers:
- why VTI needs key roles (§1), and the difference between a signing key and an encryption key that the rest of the design rests on (§3);
- which DIDs need roles and how much (§2, §5);
- what each role is for and why it is its own key (§4);
- how a community actually uses its keys on a normal day, and on a bad one (§10);
- what the design costs, what it changes for operators, members and verifiers, and which established practice it borrows from (§19 to §21).

It also records the decisions made on our side, and the questions left for the working group (§18). A one-page visual summary is published separately.

### What changed in the level revision (2026-10-30)

The first design was all-or-nothing:
- every VTA, VTC and VTN identity without key roles was **non-conformant**, and every verifier had to refuse its credentials;
- every key-role identity needed an external recovery key.

That design is replaced as follows:

- **DID classes.** Relationship, persona and service DIDs are distinguished (§2). Only service DIDs have levels.
- **Key assurance levels.** A service DID is at level 1, 2 or 3, chosen by its operator (§5). Every level is conformant, and **each verifier's policy** decides which level it accepts for each use (§7). Today's single-key DIDs are level 1, and nothing breaks.
- **The recovery key is mandatory only at level 3.** It was mandatory everywhere only because of the no-backup rule (§5.2).
- **A declared level, checked against structure.** This is how a verifier tells the levels apart (§6).
- **Threshold recovery custody.** A group of VTAs using FROST (RFC 9591) is added as a recovery custodian (§12).
- **Raising a level in place.** An identity is upgraded with one history entry, without a new identifier, and is never downgraded (§15).

### What this expansion adds (2026-10-31)

Nothing normative changes. The additions explain the design to readers who are not deep in the details, and record the reasoning behind choices the specification only states:

- **§3 Signing keys and encryption keys.** Four of the five roles are signing keys. One is an encryption key. The two fail differently, rotate differently and are custodied differently, and the note now says so before it uses either word.
- **§4.2 Why each role is its own key.** For every role: what a stolen copy lets an attacker do, for how long, how the damage is undone, and therefore how the key is held.
- **§10 A community in operation.** One VTC at level 3, the VTAs around it, and which key does what on a normal day and on a bad one.
- **§19 Principles, precedents and the balance.** Where the design follows established practice (NIST key separation and assurance levels, DNSSEC, TUF, Matrix, social recovery), and the rules by which it trades simplicity against security and privacy. Two recommendations come out of it (§19.4).
- **§5.4 The level is set per service.** Decided 2026-10-31: the default level, and a binding floor, come from the service's DID template, because a mediator, a witness, a community and a network do not need the same custody. A proposed default for every built-in template is listed.
- **§15 The old key on a raise.** Decided 2026-10-31: retiring or revoking it is recommended, not required. What keeping it means is spelled out.
- **§12.7 Post-quantum custody.** FROST cannot carry a post-quantum key and no post-quantum threshold signature is standardised. The commitment is already quantum-safe; the plan is FROST now, a hybrid custodian with a policy-enforced ML-DSA threshold when wanted, and a true post-quantum threshold scheme later, each a witnessed entry on the same DID.

---

## 1. The problem

A VTA, a VTC or a VTN signs two very different kinds of thing with one DID.

| Kind | Examples | Who relies on it, and for how long |
|---|---|---|
| **Decisions** | membership credentials, role credentials, endorsements, **status lists** | Third parties, for months or years, usually without ever contacting the node |
| **Traffic** | Trust Task responses, DIDComm/TSP messages, invitations, audit checkpoints | The immediate recipient, once |

Today one Ed25519 key signs both. `create_did_webvh` mints one key into `authentication` and `assertionMethod`, and that same key is the did:webvh log's `updateKeys`. So:

1. **Compromising the most exposed process yields everything.**
   - The service answers network traffic, so it is the most attacked process in the deployment.
   - Whoever takes its key can issue membership credentials, forge role grants, and rewrite the community's status list.
   - Rewriting the status list re-admits everyone the community has suspended or removed, silently and all at once.
2. **The same key controls the DID itself.** The log's update authority is the same key, so the attacker can also rotate the DID to keys of their choosing and lock the operator out.
3. **A verifier cannot tell which use was meant.** A key listed in both relationships is authorized for both.
4. **Everything derives from one seed.** The seed is in the VTA's store and in every backup, so a leaked backup is a leaked identity.
5. **Rotation cannot say why.** A verifier cannot tell a routine rotation from a compromise.

Not every service needs every fix, and each fix costs the operator something. Mediators, witnesses, a hobby community and a national trust network do not need the same custody.

## 2. DID classes

What a key rule costs and buys depends on what the DID is for, so the specification sorts DIDs into three classes (VTI-KEY-190 to 193). The class is decided by use, not by method.

| Class | What it is | Methods | Keys | Key roles and levels |
|---|---|---|---|---|
| **Relationship DID** | Pairwise, per-community or per-context: a `did:peer`, a client's bootstrap `did:key`, a member's per-community identifier (VTI-KEY-005, 006, 151) | any | one key is normal | none |
| **Persona DID** | A person's own identity, through their VTA (`vta-persona`) | `did:webvh`, any | one key, plus passkeys | `keyRoles` lists **only** `authenticator` keys; no level |
| **Service DID** | The durable identity of a VTA, VTC, VTN, trust registry, host service (witness, log host, push gateway, room host), mediator, or integration | `did:webvh`, `did:scid:vh:1` | chosen | a **key assurance level**, chosen by its operator |

A DID belongs to one class only (VTI-KEY-193). A persona is never a node's identity, and a service DID never carries a person's passkey.

**Why persona DIDs still need `keyRoles` for passkeys.** A passkey and a key held by the person's VTA both sit in `authentication`. The one thing a verifier must tell apart on a persona is which key is the person's own authenticator: only that key's assertion proves the person was present. A VTA-held key can sign anything the VTA is asked to. So the persona carries `keyRoles` listing only its `authenticator` keys, and every other key is read through its relationship (VTI-KEY-191). This is the one place the revision does **not** follow the brief's "no key roles" for personas. It keeps the minimum that makes a passkey distinguishable.

**Witnesses, registries and mediators are service DIDs.** Their operators may choose any level, and verifiers may ask for one. A mediator confers no authority, so it loses nothing at level 1. A witness's proofs, and a registry's records, are relied on by others, so level 2 suits them.

## 3. Signing keys and encryption keys

Everything that follows uses two words that are easy to blur. A DID document can hold two kinds of key, and they do opposite jobs.

| | **Signing key** | **Encryption key** |
|---|---|---|
| In VTI | Ed25519 (a passkey: P-256 or Ed25519, inside the authenticator) | X25519, used for key agreement |
| Roles | `attestation`, `operational`, `update`, `authenticator` | `messaging` |
| Relationship | `assertionMethod` or `authentication` (`update`: none, log only) | `keyAgreement` |
| Who uses the **private** half | The owner, to **produce** something: a signature | The owner, to **read** something: decrypt what was sent to it |
| Who uses the **public** half | Everyone else, to **check** the signature | Everyone else, to **encrypt to** the owner |
| What it establishes | *Who said this*, and that it was not altered | *Who can read this* |
| A stolen private key lets an attacker | **Forge**: say things as the owner | **Read**: everything sent to the owner, including traffic recorded earlier |
| Rotating it | Bounds the forgery window: a revocation with a compromise time tells verifiers what to distrust | Stops *future* reading. Nothing can un-read traffic already captured |
| Must it be online? | Only where it is used. An `attestation` key can live in a process that never talks to the network | Yes, wherever messages for the owner are decrypted |

Four of the five roles are signing keys. **`messaging` is the only encryption key**, and it signs nothing. That is why the roles table (§4) lists a proof purpose for every role but `messaging`.

### 3.1 Why one key must not do both

Ed25519 and X25519 are built on the same curve, and a private key of one can be converted into a private key of the other. The workspace's HPKE layer does that conversion today, and the first level-1 identities were minted that way. The design stops it at levels 2 and 3 (VTI-KEY-184), and asks new level-1 identities not to do it either, for three reasons:

- **One theft becomes two.** If the encryption key is computed from the signing key, whoever takes the signing key reads the traffic as well, and whoever reconstructs the signing key from a leaked encryption key forges. The two failures stay separate only if the keys do (VTI-KEY-114).
- **They rotate on different clocks.** An encryption key is rotated on a schedule to limit how much recorded traffic one key exposes. A signing key is rotated when custody changes or compromise is suspected. One key cannot follow both schedules.
- **They live in different places.** The encryption key must sit in the process that decrypts, which is the network-facing one. The most valuable signing key must not. Deriving one from the other puts them in the same place by construction.

### 3.2 How the transports use them

A reader who knows that "DIDComm authenticates the sender" may wonder why VTI still needs a separate signing key for traffic. The answer is what each transport proves, and to whom.

| Transport | Confidentiality | Sender authentication | Which role |
|---|---|---|---|
| **TSP** | HPKE, encrypted to the recipient's **`messaging`** key | An Ed25519 signature on every envelope, by the sender's **`operational`** key | both |
| **DIDComm v2 authcrypt** | ECDH-1PU, encrypted to the recipient's **`messaging`** key | Through the key agreement itself: the recipient, and only the recipient, learns that the sender's `messaging` key took part. No signature exists, so the recipient cannot show the message to anyone else as proof | `messaging` for the envelope; the Trust Task document inside is signed by **`operational`** (VTI-OPS-020, VTI-KEY-081) |
| **HTTPS** (last fallback) | TLS | A DID-signed binding, by **`operational`** | `operational` |

So an encryption key can authenticate a conversation, but only to the other party and only for that moment. A decision that a third party will rely on next year needs a signature, by a signing key whose custody matches that lifetime. That is the whole reason `messaging` can never issue a credential, and `attestation` is never on the wire path.

**The mediator sees none of this.** It forwards envelopes encrypted to the recipient's `messaging` key. It cannot read them and cannot forge them. The VTA's lack of an inbound surface depends on exactly this: the mediator is trusted to deliver, not to see.

### 3.3 Encryption keys that are not in the DID document

The design is about the keys a DID document publishes. A node also holds encryption keys that are never published and belong to no role:

- the storage key that encrypts its store at rest;
- the key that encrypts a backup;
- room file keys, and the HPKE keys of a `sealed_transfer`;
- audit-chain and session secrets.

VTI-KEY-114 says one thing about all of them: none may be derived from a signing key, and no signing key from them. They are otherwise out of scope here.

## 4. Roles

A *key role* is a named position a key occupies in an identity. It fixes four things (VTI-KEY-072):
- what the key may sign;
- the one verification relationship it may appear in;
- the proof purpose its proofs may carry;
- who may hold it.

One key has exactly one role (VTI-KEY-071), and key material is never reused across roles, nodes or services.

### 4.1 The five roles

| Role | Kind | Signs / used for | Relationship | Custody | Origin |
|---|---|---|---|---|---|
| `attestation` | signing | Decisions: every credential the node issues, status lists, endorsements (VTI-KEY-080) | `assertionMethod` only | **VTA only**. At level 3, never exportable and never in a backup | level 3: generated. Level 2: derived or generated |
| `operational` | signing | Traffic: Trust Task request/response, DIDComm/TSP signatures, invitations, audit checkpoints (VTI-KEY-081) | `authentication` only | may be held by the node's service process (VTI-KEY-114) | derived |
| `messaging` | **encryption** | Key agreement for TSP and DIDComm; signs nothing | `keyAgreement` only | may be held by the service process | derived, as native X25519 |
| `update` | signing | Entries in the DID's own history | **none** (VTI-KEY-093) | routine key: VTA only. Recovery key (level 3): **outside the VTA** | as `attestation` |
| `authenticator` | signing, held by a person | A person's WebAuthn assertions; never a Data Integrity proof | `authentication` only | the person's authenticator, on a persona DID (VTI-KEY-154/155) | the passkey |

An unknown role confers nothing (VTI-KEY-074). `capabilityInvocation` and `capabilityDelegation` are unused (VTI-KEY-075). A companion service signs as itself (VTI-KEY-076/077).

### 4.2 Why each role is its own key

The roles are not a taxonomy for its own sake. Each one exists because a stolen copy of it does a different amount of damage, for a different length of time, undone in a different way. Custody follows from that.

| Role | A stolen copy lets an attacker | The damage lasts | It is undone by | So the key is |
|---|---|---|---|---|
| `attestation` | Issue membership and role credentials, forge endorsements, **rewrite the status list** and re-admit everyone removed | Months to years: the credentials sit in holders' wallets and verifiers' caches, and most verifiers never contact the issuer | Revocation with a stated compromise time, re-signing every status list, re-issuing every credential in force, and every verifier re-resolving (VTI-KEY-126, 134, 149) | Held only by the VTA, signed through an oracle that constrains what it signs (VTI-VTA-004 to 007), changed only with preview-bound step-up and two approvers. At level 3, generated and in no backup |
| `operational` | Forge one Trust Task reply, invitation or audit checkpoint, as the node | Until the recipient's next check, which is immediate: traffic is verified live, by the party it was sent to, once | Rotation. No credential is affected, nothing is re-issued | Allowed in the service process, which needs it a thousand times a day. Rotated routinely with overlap |
| `messaging` | **Read** everything encrypted to the node, including traffic recorded before the theft. Forge nothing | Backwards without limit, forwards until rotation | Rotation, for the future only | Held where decryption happens, which is the service process. Rotated on a schedule. Never computed from a signing key, so a leaked signing key does not read traffic and a leaked encryption key does not forge |
| `update` | **Rewrite the identity**: publish new keys and new services, and lock the operator out. Everything above follows | Permanent, unless a key the attacker never reached can take the DID back | The pre-committed successor (routine), or the recovery key (level 3) | Routine key in the VTA only, with its successor committed in the log. Recovery key outside the VTA, with a witness that refuses any entry dropping it |
| `authenticator` | Pass as the person being present: step up, approve, sign in | Until the passkey is removed | Removing the passkey from the persona | Held only by the person's authenticator. Never by a VTA, and never on a service DID, so no VTA-held key can ever pass for the person |

Three consequences worth stating plainly:

- **`attestation` and `operational` are separated because of exposure, not importance.** The busiest key is the one an attacker reaches first. Keeping it from signing anything durable is the single largest gain in the design, and it costs nothing but a signing request from the service to its VTA.
- **`update` is separated from `attestation` because they answer different questions.** "What did this DID decide?" is answered by `attestation`. "Who is this DID?" is answered by `update`. A compromised `attestation` key is survivable by revocation. A compromised `update` key is survivable only by a key the attacker never had.
- **A role may hold more than one key at once.** The example document (§8) lists two `attestation` keys: a rotation in progress, where the new key is published before use and the old one keeps verifying until the horizon passes (VTI-KEY-122). Verifiers select by role, so both verify what each signed.

## 5. Key assurance levels

### 5.1 The levels

| Level | Name | Shape | Protects against | VTA lost | VTA compromised |
|---|---|---|---|---|---|
| **1** | single key | One signing key for everything; no `keyRoles`. Today's shape | — | restore from backup | identity lost |
| **2** | role-separated | `keyRoles`. The VTA holds the `attestation` and `update` keys, and **may** derive them from the seed and keep them in its own backup | **service compromise** | restore from backup | deactivate; create a successor |
| **3** | recoverable | Level 2, plus: `attestation` and `update` keys generated, in no backup, and protected at rest independently of the seed; a recovery key held by a recovery custodian outside the VTA; a witness enforcing it | service compromise, **backup theft or seed exposure**, **VTA compromise or loss** | recovery key | recovery key |

Every level is conformant (VTI-KEY-194). The specification recommends level 2 or higher for a VTC, a VTN and a VTA's own identity. It recommends level 3 for a VTC or VTN whose credentials confer authority on others, such as vetter grants or network listings (VTI-KEY-196). These are SHOULDs, so they decide nothing about conformance.

### 5.2 What each layer protects against

- **Role separation, with the VTA holding `attestation` and `update`**, protects against **service compromise** (T1).
  - The process that parses network input holds only traffic keys.
  - Its compromise yields a caller of the VTA's signing oracle, not the seal (VTI-KEY-111, 115).
  - This is level 2. It needs no new party and no new ceremony, and backups keep working. It is the largest gain for the least cost.
- **Generation, and exclusion from backups**, protects against **backup theft and seed exposure** (T3). Neither yields the seal or the DID.
- **A recovery key held outside the VTA** protects against **compromise of the VTA** (T2, given a witness) and **loss of the VTA** (T4).

**The recovery key was mandatory only because of the no-backup rule.** Once role keys are in no backup, a lost VTA loses them, and only a key held elsewhere can take the DID back. At level 2 the keys are in the backup, so a restore brings the identity back, and there is nothing for a recovery key to do against loss. Against VTA *compromise*, a level-2 identity is lost either way. That is what level 2 accepts.

Level 2 with a recovery key is deliberately **not** a level. It would carry the recovery key's cost without level 3's backup exclusion or witness, and a verifier could not tell it from level 2. `create` and `upgrade` refuse a recovery commitment at level 2.

### 5.3 Which requirements apply at which level

VTI-KEY-195 is the normative table. In short:

| Requirements | 1 | 2 | 3 |
|---|---|---|---|
| Binding roles, `keyRoles`, verifying by role (070–105) | — | ✓ | ✓ |
| VTA holds `attestation`/`update`; service process does not (110 holding, 111, 113, 115) | — | ✓ | ✓ |
| Generated, not exportable, no backup, KEK independent of seed (110 origin, 112, 116 origin, 118) | — | — | ✓ |
| Recovery commitment, custodian, one-use recovery key (116, 117, 119, 128, 205, 206) | — | — | ✓ |
| Witness enforcing level and recovery commitment (129) | — | SHOULD | **MUST** |
| Rotation and revocation by role (120–127, 132) | — (040–043) | ✓ | ✓ |
| Preview-bound approvals (180–183) | — | ✓ | ✓ |
| No secret derived from a signing key (114) | ✓ | ✓ | ✓ |
| No X25519 key computed from an Ed25519 key (184) | SHOULD, new identities | ✓ | ✓ |
| No passkey on a service DID (154) | ✓ | ✓ | ✓ |

### 5.4 The level is set per service (decided)

A level is a property of one DID, chosen when it is created or raised. But the *right* level depends on what the service does, and an operator should not have to work that out for every DID. Decided by the maintainer on 2026-10-31: **the default level, and a binding floor, come from the service's DID template.**

The template is already where a service's DID shape lives (`docs/02-vta/did-templates.md`), and its `defaults` map already has the precedent this needs: `"portable": false` is a hint that binds in one direction only, because a template can tighten what a caller asked for but never loosen it. The level follows the same rule:

```json
"defaults": { "keyAssurance": { "level": 2, "minimum": 1 } }
```

- **`level`** is the default a creation uses when the caller names none.
- **`minimum`** is binding: a creation below it is refused, with a message naming the flag that would raise it. A template cannot cap a level, so the caller may always go higher.
- The CLI resolves `--level` first, then the template's `level`, then `[dids] default_level` in the VTA's config for templates that say nothing, then 1. It prints the level it resolved and where it came from.
- An operator-uploaded template sets its own values. A template that says nothing behaves as today.
- A VTN template does not exist yet. When it does, its default is 3 (VTI-KEY-196).

Nothing normative changes: VTI-KEY-196 stays a SHOULD, and a verifier's policy still decides what it accepts. The template turns the specification's advice into the default an operator gets without reading it.

**Proposed defaults for the built-in templates.** These are for the maintainer to confirm.

| Template | Service | Default | Minimum | Why |
|---|---|---|---|---|
| `vtc-host` | a community | **2** | 1 | Its credentials and status lists are relied on by others. Level 1 stays allowed so an existing deployment pattern keeps working; 3 is the operator's choice for a community whose credentials confer authority |
| `trust-registry` | a registry | **2** | 1 | Its records are relied on without contacting it. 3 where listings confer authority |
| `dtg-witness` | a witness | **2** | 1 | Its proofs are what level 3 of other identities rests on |
| `ballot-box` | a voting service | **2** | 1 | Tallies and receipts are relied on after the fact |
| `didcomm-mediator` | a mediator | **1** | 1 | Confers no authority; relays what it cannot read |
| `push-gateway` | a push gateway | **1** | 1 | Same |
| `room-host`, `room` | a room host; a room's own profile | **1** | 1 | Rooms act as the member's persona; the host confers nothing |
| `ai-agent` | an integration | **1** | 1 | Acts within an ACL grant, which is revoked by removing the grant |
| `did-host-*` | generic hosting shapes | **1** | 1 | The shape says nothing about the use; `[dids] default_level` or `--level` decides |
| `vtc-group` | a community group | **1** | 1 | — |
| `swiyu-verifier` | a foreign-protocol identity | **1** | 1 | Its keys are fixed by the OpenID4VP profile; roles do not apply |
| `vta-admin`, `ai-agent-peer` | relationship DIDs | — | — | No level, by class (§2) |
| *(the VTA's own identity)* | the VTA | **2** | 1 | Set by the setup wizard, whichever shape it uses (VTI-KEY-196) |
| *(a VTN template, when added)* | a network | **3** | 2 | Listings confer authority |

## 6. How a verifier determines the level

This was the critical open point. The options were:

1. **Infer it from structure alone.**
   - `keyRoles` present means level 2, plus whatever implies level 3.
   - This **fails**. Persona DIDs carry `keyRoles` too. And level 3 is not visible: a recovery commitment in did:webvh's `nextKeyHashes` is a hash, indistinguishable from a second routine successor.
2. **Self-assertion alone.** A declared level, believed. This is free to forge.
3. **A structural marker for the recovery commitment, which witnesses check.** This makes level 3 checkable, but it needs a place to put the marker.
4. **A declared level, checked against verifiable structure, with the recovery commitment named in the declaration.** **Chosen.**

**The mechanism (VTI-KEY-197 to 199).** The document carries a top-level `keyAssurance` member:

```json
"keyAssurance": { "level": 3, "recoveryCommitment": "<exactly as it appears in nextKeyHashes>" }
```

- At level 2, it is `{ "level": 2 }`.
- At level 1 it is absent, or `{ "level": 1 }`, so today's DIDs need nothing.
- The JSON-LD term is `https://w3id.org/vti#keyAssurance` with `@type: @json`.

A verifier takes the declared level and **caps it at what the structure shows**:

| Declared | Capped down when |
|---|---|
| 2 or 3 | → 1 if the document has no `keyRoles`, or lists one method in two relationships |
| 3 | → 2 if any of these hold: `recoveryCommitment` is absent; it is not among the version's `nextKeyHashes`; it is the only one; the method has witnesses and the version is unwitnessed; or it changed from the previous version, and the change was neither authorized by the previous recovery key nor witnessed |
| any | → 1 for every version from the point where the history shows the level fell |

A verifier judges an artefact at the level where its *signing key* is bound, not at the current level (VTI-KEY-201).

**Why this mechanism.**
- One value is what a policy can apply to.
- Naming the recovery commitment is what lets a witness enforce it from the log alone, with no side declaration to the witness. It also lets a verifier check that the commitment is carried forward.
- It reveals which committed key is held elsewhere, which the level already implies. It reveals nothing about who holds it.
- A level that falls is treated as a compromise. That fails closed on the one change a compromised VTA would make to disarm recovery.

**What remains self-asserted.** A verifier cannot establish any of these from the document or the history:

- which process holds the `attestation` key, at levels 2 and 3;
- that the keys were generated, are in no backup, and are protected at rest under a KEK the seed cannot produce (level 3);
- where the recovery key is, and which kind of custodian holds it;
- that the witness is outside the VTA's boundary and applies the continuity policy.

So a level is **a checked structure plus an unchecked custody claim**. Evidence beyond that, such as TEE attestation or a witness policy statement, is an open question (§18).

## 7. Verifier policy

A verifier's policy sets a minimum level **per use** (VTI-KEY-200). Examples of what a policy might say (not normative):

| Use | Plausible minimum |
|---|---|
| Operational traffic (a Trust Task response, a DIDComm message) | 1 |
| A membership credential from a small community | 1 or 2 |
| A membership credential relied on for access to something valuable | 2 |
| A vetter grant, a role credential conferring administrative authority, a network listing | 3 |
| A status list | the issuer's level for the credential it governs |

The verifier refuses below its minimum. It must never treat a DID as a level its structure does not support. It may accept level 1. Our own verifiers (SDK, browser extension, openvtc, registries) need a configurable policy, with a sensible default (§19.4).

## 8. The DID document

Each key's role is stated twice:
- by the standard relationship, which generic DID tooling reads;
- by the top-level `keyRoles` map, which says which role was meant.

The level is stated once, in `keyAssurance`.

```json
{
  "id": "did:webvh:{SCID}:community.example",
  "verificationMethod": [
    { "id": "#z6Mkq…", "type": "Multikey", "publicKeyMultibase": "z6Mkq…" },
    { "id": "#z6Mkr…", "type": "Multikey", "publicKeyMultibase": "z6Mkr…" },
    { "id": "#z6Mkv…", "type": "Multikey", "publicKeyMultibase": "z6Mkv…" },
    { "id": "#z6LSb…", "type": "Multikey", "publicKeyMultibase": "z6LSb…" }
  ],
  "assertionMethod": ["#z6Mkq…", "#z6Mkr…"],
  "authentication": ["#z6Mkv…"],
  "keyAgreement":   ["#z6LSb…"],
  "keyRoles": {
    "attestation": ["#z6Mkq…", "#z6Mkr…"],
    "operational": ["#z6Mkv…"],
    "messaging":   ["#z6LSb…"]
  },
  "keyAssurance": { "level": 3, "recoveryCommitment": "QmRecoveryHash" }
}
```

Reading it: three Ed25519 signing keys (`z6Mk…`) and one X25519 encryption key (`z6LS…`). Two `attestation` keys because a rotation is in progress. No `update` key appears: the routine update key and the committed successors live in the did:webvh log's parameters, and the recovery commitment is one of the `nextKeyHashes` there.

The rules from the first design all stand, now at levels 2 and 3:
- every method is under exactly one role (VTI-KEY-090), in that role's relationship only (VTI-KEY-091);
- a verifier refuses only the method in doubt (VTI-KEY-092);
- `update` is never in `keyRoles` (VTI-KEY-093);
- keys are selected by role, never by fragment (VTI-KEY-094);
- `keyRoles` is a top-level member (VTI-KEY-095), with its JSON-LD term (VTI-KEY-096);
- fragments are derived from the key (VTI-KEY-150);
- proof sets are supported (VTI-KEY-103/104).

## 9. Protection boundaries and custody, by level

The **protection boundary** (VTI-KEY-118): two keys are in the same boundary whenever one compromise or one loss reaches both. That includes reaching them through a backup, a seed, a key derived from a seed, or credentials to the other's store.

| VTA kind | Boundaries | Why |
|---|---|---|
| Plain | 1 | Host, store and seed-backend credentials are all on one machine |
| Hardened | 1 | The store is encrypted, but under a key derived from the seed |
| TEE (Nitro) | 1, stronger | The host cannot read inside, but every key is inside the enclave |
| Mnemonic in a safe | protects against *loss* only | The running VTA holds the seed |

Every VTA is one boundary. Custody by level:

- **Level 2.**
  - The VTA holds `attestation` and `update` keys, and only the VTA signs with them.
  - They may be derived or generated, and may be in the VTA's own backup. They are in no other backup, in no VTC backup, and in no provisioning bundle (VTI-KEY-110, 112).
  - The store's own protection is sufficient. The preview warns `roleKeysInBackups`.
- **Level 3.**
  - The keys are generated, non-exportable, and in no backup.
  - At rest they are wrapped under a *role-key KEK* that is not derived from the seed and is in no backup (VTI-KEY-118):
    - TEE: a KMS data key bound to the measurement (`enclave`);
    - secret-manager backend: a second secret (`encryptedAtRest`);
    - plain config backend: a 0600 file (`software`), with a `protectionBelowPolicy` warning.
- **All levels.**
  - The service process holds only `operational` and `messaging` keys at levels 2 and 3.
  - No secret is derived from a signing key (VTI-KEY-114).
  - X25519 is derived as X25519 (VTI-KEY-184). For a new level-1 identity this is a SHOULD; existing DIDs keep what they have.

## 10. A community in operation

The sections above say what each key is. This one shows a community using them. The example is a VTC at level 3 with a threshold recovery custodian, because that exercises every part. A level-2 community is the same picture without the recovery group, and with the witness optional.

### 10.1 Who holds what

| Party | Where | Holds | Never holds |
|---|---|---|---|
| **The VTC service** | The network-facing process: Trust Tasks, rooms, the member portal, the admin console, elections | `operational` (signing) and `messaging` (encryption) for the community DID | any `attestation` or `update` key |
| **The community's VTA** | The VTA the VTC is provisioned on, run by the community's operator | `attestation` keys and the routine `update` key, generated, wrapped under the role-key KEK, in no backup. Its own seed, for its own identity and for the derived traffic keys it hands the VTC | the recovery key, or any way to derive it |
| **The witness** | A `vti-witness` outside the VTA's boundary; may be run by one of the recovery custodians | Its own witness key | anything of the community's |
| **The recovery group** | Three VTAs, operators A, B and C, each with its own seed, host and cloud account; FROST 2-of-3 | One share each of the recovery key. The whole key exists nowhere | anything else of the community's; a credential to each other's stores |
| **Members' VTAs** | Wherever members run them | Their own relationship DID for this community, and their credentials | — |
| **Verifiers** | Other communities, registries, the browser extension, third parties | Nothing. They resolve the community DID and its log | — |
| **The mediator** | A host service | Its own identity | the content of anything it relays |

Today the VTC holds the credential-signing key itself: the VTA mints the integration DID and the VTC stores the bundle and signs locally (`vtc-service/CLAUDE.md`, *VTC isn't the key authority*). At level 2 and above that changes to a signing request to the VTA (VTI-KEY-111). That is the one operational cost of level 2 (§21).

### 10.2 A normal day

| | What happens | Key used | Signed or encrypted | By whom |
|---|---|---|---|---|
| 1 | A member's VTA sends a join request over TSP, through the mediator | the community's `messaging` key | encrypted **to** the VTC; the envelope **signed** by the member's own key | the member's VTA |
| 2 | The VTC decrypts, verifies the member's signature, checks the applicant against policy, and answers | `messaging`, then `operational` | the reply is **signed** by `operational` | the VTC service |
| 3 | The member is admitted. The VTC asks its VTA to issue the membership credential | `attestation` | the credential is **signed** | **the VTA's signing oracle**, which checks the request is a credential of a kind the VTC may ask for (VTI-VTA-004 to 007), signs it, and audits it |
| 4 | The credential goes back to the member in a Trust Task response | `operational`, `messaging` | **signed** by `operational`; **encrypted to** the member's key | the VTC service |
| 5 | A member is removed. The VTC composes the new status list and asks the VTA to sign it. It is published for verifiers | `attestation` | **signed** | the VTA's signing oracle |
| 6 | Room messages, portal sessions, admin-console actions, an election: hundreds of Trust Tasks | `operational`, `messaging` | **signed** replies, **encrypted** envelopes | the VTC service, all day, with the VTA not involved |
| 7 | A verifier elsewhere checks a member's credential: resolves the community DID, selects the `attestation` key by role, verifies the proof, checks the status list, and establishes the level (3) against its policy | the public half of `attestation` | **verified** | the verifier, without contacting the community |
| 8 | Scheduled rotation of the `operational` key: the VTA publishes the new key in a log entry, the witness co-signs, the VTC starts using it after the validity period | routine `update` key | the log entry is **signed** by `update`, then by the witness | the VTA, then the witness |

Nothing in this day touches the recovery group. It receives a liveness challenge now and then (§12.2), and that is all.

### 10.3 A bad day

| Failure | What happens | Who acts |
|---|---|---|
| **The VTC service is compromised** | The attacker holds `operational` and `messaging`: they can answer Trust Tasks as the community, and read traffic to it, until the keys are rotated. They **cannot** issue a credential, touch the status list, or change the DID: the VTA's oracle refuses anything outside policy, and the attacker holds no `attestation` key to forge with. The operator revokes both traffic keys with a compromise time and redeploys the service | the operator, at the VTA |
| **The VTA's host dies** | At level 3 the `attestation` and `update` keys are gone with it. The operator stands up a fresh VTA and runs `vta/dids/recover`. Operators A and B each fetch the log, check the proposed entry themselves, and approve at their own VTA; FROST produces one Ed25519 signature by the recovery key; the witness verifies and co-signs. The DID now points at keys the new VTA generated. Status lists are re-signed and credentials re-issued where relying parties need the new keys | the operator, two custodians, the witness |
| **The VTA is compromised** | The attacker holds the routine `update` key and the `attestation` keys. They can issue credentials, and could try to publish an entry that drops the recovery commitment or lowers the level. **The witness refuses that entry**, so verifiers never see it. The operator revokes the `attestation` keys with a compromise time, and the recovery group signs the entry that moves the DID to a new VTA. Everything the old keys signed after the compromise time is refused by verifiers | the operator, two custodians, the witness |
| **A recovery custodian is lost** | Nothing is visible outside the group. The remaining participants run a refresh (§12.2), which replaces the lost share without changing the public key, and no log entry is needed. If the group ever falls below two for good, the operator replaces the recovery commitment, while the VTA still holds the routine authority | the custodians |
| **A member's passkey is stolen** | The thief can step up as that member until the passkey is removed from the member's persona. No community key is involved | the member |

What the picture shows is the point of the whole design: the keys that sign a thousand things a day sit where the attacks arrive, and the keys that sign the things people rely on for years sit one step back, behind an oracle, with a way back that no single machine controls.

## 11. Recovery custodians (level 3)

### 11.1 Kinds

VTI-KEY-205 allows three kinds of recovery custodian:

| Kind | What | How it signs | Wire (`RecoveryCustodianKind`) |
|---|---|---|---|
| **(a) Separately held key** | `pnm recovery-key`: a passphrase-encrypted file (Argon2id + AES-256-GCM), offline. A hardware token or a key service whose credentials no VTA of the identity holds also counts. So does a **printable recovery mnemonic from a seed the VTA never sees**. **Never** the VTA's own seed | Out of band. Air-gap form: `--recovery-key did:key:… --recovery-pop …` | `separateKey` |
| **(b) Second VTA** | Its own seed, operator and host. Holds the key with level-3 custody | Checks the change itself and asks its own operator (VTI-KEY-206). The request may be routed to its DID | `vta` |
| **(c) Threshold group of VTAs** | FROST, t-of-n (§12) | Every participant checks and asks its operator; t sign together | `thresholdGroup` |

The custodian kind is declared by the operator in `RecoveryCommitment.custodian`. It is kept in custody records and **never published** (VTI-KEY-150, 206). The VTA cannot verify the kind. It verifies the proof of possession over the `previewId`, and refuses a key it generated or can derive.

**The witness may be run by the custodian.** It is already outside the VTA's boundary, so level 3 adds one party, not two.

### 11.2 Why not use the BIP-32 seed for the recovery key?

The recovery key exists to survive **compromise of the VTA**, not just loss. A key derived from the VTA's seed cannot do that, for four reasons:

1. **The running VTA holds the seed.** An attacker holding the VTA derives the "recovery" key, appends an entry, commits their own key, and owns the identity. VTI-KEY-116 says the VTA must not hold, generate *or be able to derive* it.
2. **The seed is in every backup.** A leaked backup would leak the recovery key (VTI-KEY-118).
3. **A mnemonic in a safe protects against loss only.**
4. **Level-3 role keys are deliberately not seed-derived.** Building the DID's highest authority on the seed would undo that.

What works is BIP-32 from a **different** seed: a recovery mnemonic the VTA never sees, generated offline. The rule is not "no BIP-32". It is "not the VTA's own seed".

### 11.3 How an operator supplies a separately held key (decided)

Decided by the maintainer on 2026-10-30, and unchanged by this revision:

- **A custodian command:** `pnm recovery-key {generate,show,sign-commitment,sign-recovery}`.
  - It writes a passphrase-encrypted file where the operator says.
  - It prints the key as a `did:key` plus a digest.
  - It refuses any path under the VTA's data directory.
- **An air-gap form:** `pnm dids create` (and `pnm dids upgrade`) prints the `previewId` and the exact string to sign. It takes the signature back as `--recovery-key did:key:… --recovery-pop …`. `--recovery-key-file` signs in-process.
- **Hardware tokens** are deferred.

## 12. Threshold custody with FROST

### 12.1 What it is

A threshold custodian is n VTAs, each in its own boundary, holding shares of one Ed25519 key under **FROST(Ed25519, SHA-512)** (RFC 9591), with **2 ≤ t < n**. Any t of them sign together.
- **t ≥ 2:** no participant signs alone.
- **t < n:** the group survives losing one participant.

**FROST produces an ordinary Ed25519 signature that RFC 8032 verifies.** To did:webvh, a witness, the proof-of-possession check and a verifier, the group's key is one Ed25519 key. **No DID-method change is needed.** In `RecoveryCommitment` it is just `keyType: ed25519`, with `custodian: thresholdGroup`.

### 12.2 Security requirements (VTI-KEY-210 to 221)

| Concern | Requirement |
|---|---|
| **Key generation** | Distributed, **no dealer**, so the key never exists anywhere. Use the [FROST20] DKG with proofs of knowledge. Every participant verifies every proof, and every share against the sender's commitments. All participants compare a digest of what they received **before** accepting the group key, which defeats a participant who equivocates. RFC 9591 Appendix C (trusted dealer) is forbidden |
| **Checking before contributing** | Every participant fetches the history itself, computes the exact message (for did:webvh, the `eddsa-jcs-2022` proof input), and checks the entry as VTI-KEY-128 requires. It never signs a digest someone hands it. It asks its **own operator** to approve |
| **Nonces** | Generated as RFC 9591 specifies, from fresh randomness and the share. One signing only. Never persisted or backed up. Deleted on use, abort, expiry or restart. A commitment list missing its own entry, naming a participant twice, or shorter than t is refused. *A nonce reused on two messages yields the share* |
| **Identifiable abort** | The coordinator verifies every signature share against that participant's verification share before aggregating. It names a bad participant, audits the failure, tells every participant, and retries without it, using fresh nonces. FROST is not robust, but it is accountable |
| **Transport** | Trust Tasks VTA-to-VTA over **TSP, falling back to DIDComm authcrypt**, never REST. DKG and refresh shares are encrypted end to end. Each message comes from a participant of the group, and replays are refused |
| **Fewer than t reachable** | The operation waits. **No fallback**: no reconstruction, no dealer, no lowering t, no key outside the group. Liveness is checked regularly by signing a domain-separated challenge that is never a log entry. The group refreshes before only t remain. If fewer than t remain for good, the key is lost, and the operator replaces the recovery commitment (by quorum) while the VTA still holds the routine authority |
| **Refresh** | Changes shares, membership or t **without changing the public key**. No DID entry and no witness are involved. At least t current participants take part. New shares are verified. Old shares are deleted |
| **Backups** | Shares are excluded from backups and protected like a level-3 attestation key. A lost share is replaced by refresh, never restored |
| **Distinct boundaries** | See §12.3 |

### 12.3 What "a different protection boundary" means for operators

Each participant must have:
1. its own seed, store and host. For a VM or an enclave, that means a different host **and** a different cloud account.
2. no credentials reaching another participant's seed, store, secret backend or backups, nor those of the identity's VTA;
3. backups no other participant, and not the identity's VTA, can read;
4. **no subject able to approve signing at t or more participants.** This is an administrator, a delegate or any credential, and it is checked as a rule, not as advice.

Participants SHOULD also have different human operators or organisations, and different failure domains (provider, region).

Item 4 is the important one. One person approving at every participant reduces t ≥ 2 to one approver. With distinct operators, **the two-approver rule for replacing the recovery commitment (VTI-KEY-181) is enforced by the signature itself**, not by the VTA's policy.

### 12.4 Rejected: Shamir reconstruct-then-sign

Splitting the key with Shamir or SLIP-39, and reconstructing it to sign, is **not** a threshold custodian (VTI-KEY-220):
- **At the moment the key matters, it exists whole on one machine.** That machine's compromise yields it, and it may keep it.
- **Only that machine checks what is signed.** The t holders checked nothing; they handed over shares.
- **A dealer held the whole key at generation.**
- **A "fallback to reconstruct" when too few answer is the attack.** An adversary who can make participants unreachable chooses when the key exists in one place.

A Shamir split may still back up a separately held key, kind (a), as protection against losing the file. It is then declared `separateKey`, never `thresholdGroup`.

### 12.5 Where to use it

- **The recovery key:** recommended. It signs once in most identities' lives, so waiting for t operators costs little.
- **The routine update key:** MAY. It closes T2 without relying on the witness. But under did:webvh **every entry moves the update key** (reveal R(n+1), commit a fresh R(n+2)), so every change costs a **DKG plus a signing** across t VTAs. That suits identities that rarely change.
- **`attestation` keys:** **SHOULD NOT**, for four reasons:
  - they sign every credential and every status-list update, so issuance would stop whenever fewer than t operators answer;
  - signing rounds and fatal-if-reused nonces multiply by every credential issued;
  - every participant would have to parse and constrain every artefact (VTI-VTA-004 to 007);
  - their compromise is recoverable anyway, by revocation and re-issue.

### 12.6 Wire, and what is deferred

- **What changes now.**
  - `RecoveryCommitment.custodian` (kind, the custodian VTA's DID, participants, threshold) is added in the `_shared/0.1` schema, additively.
  - The PoP and the recovery proof are unchanged: a group signature is an Ed25519 signature.
- **Deferred.** The ceremony tasks are only outlined in CONVENTIONS §19. They are `vta/threshold/dkg/{commit,share,confirm}`, `sign/{request,commit,share}`, `refresh/*` and `liveness`. Each needs its own specification before implementation.

### 12.7 Post-quantum custody

**FROST cannot carry a post-quantum key.** It is a Schnorr scheme over a discrete-log group: shares, nonces and aggregation all live in that group, so a quantum computer that breaks Ed25519 breaks the FROST group key with it. There is no FROST for ML-DSA, and as of October 2026 there is no standard post-quantum threshold signature of any kind:

- **NIST's threshold process is open, not finished.** IR 8214C, the first call for multi-party threshold schemes, was finalised in January 2026. Preview talks ran through October 2026, and full submission packages are due at the end of 2026. A standard is years away.
- **Lattice threshold schemes exist, with their own signature type.** Ringtail (IEEE S&P 2025) is two-round and scales to many parties; Threshold Raccoon and the NIST-call entries Tanuki and TalonG are the same family. None produces a signature a FIPS 204 verifier accepts, so every verifier would need new code.
- **ML-DSA-compatible threshold signing is a 2026 preprint.** A FIPS 204-compatible scheme using a Shamir nonce DKG was posted in January 2026, and P-DualTS was previewed at NIST in October. Earlier attempts reached six signers. None is peer-reviewed or in an audited library.
- **Generic MPC over ML-DSA** is possible in principle and impractical here: rejection sampling makes each signature minutes of multi-party computation, and no one ships it.

**Where the quantum risk actually sits.** Signatures and encryption fail differently under a quantum adversary (§3). Traffic encrypted today to an X25519 `messaging` key can be recorded now and read later, so the `messaging` role is where a hybrid ML-KEM key matters first, and that is a transport question outside this note. A signature only needs to be unforgeable at the moment it is checked, so for signing keys the question is which key will still be relied on when a cryptographically relevant quantum computer exists. The **recovery key** is the extreme case: committed years ahead, used once, and the thing that takes the identity back. The `attestation` keys are next, through long-lived credentials. The `operational` key, checked live and rotated often, is the least exposed.

One part of the design is already quantum-safe: **the commitment.** `nextKeyHashes` holds a hash of the recovery key, which reveals nothing about it until it is used. What must be post-quantum is the signature made at recovery time, and nothing else.

**The plan, in three steps that never change the identifier:**

1. **Now: FROST over Ed25519, as §12 specifies.** The moment of recovery is classical today, and the commitment that protects the key until then is not.
2. **When a post-quantum side is wanted: a hybrid custodian, with the threshold enforced by policy rather than by the cryptography.** The `vtc-host` template already mints an Ed25519 key beside an ML-DSA-44 key and emits proof sets, so the pattern exists in the workspace. A hybrid recovery custodian is the FROST group key **plus one whole ML-DSA-44 key per custodian**. The recovery entry carries a proof set: the FROST signature **and** at least t ML-DSA proofs from the group's n keys, and the witness and every VTI verifier require both. Each custodian still fetches the history, checks the entry itself and approves at its own VTA (VTI-KEY-128, 206), so every operational property of §12.2 holds, including identifiable abort, since each ML-DSA proof names its signer. What is lost is the single-signature elegance: the post-quantum side reveals the group's size and threshold, which the FROST side hid (§17), and did:webvh's own log-entry proof stays `eddsa-jcs-2022`, because didwebvh 1.0 mandates it, so the ML-DSA proofs are checked by VTI verifiers and the witness beyond the method. Under did:webs the same thing is native: the `nt` threshold over whole keys, which may be post-quantum.
3. **Later: replace the post-quantum side with a true threshold scheme**, once one is standardised and in an audited implementation. `RecoveryCommitment` already carries `custodian: thresholdGroup` and a `keyType`, so a post-quantum key type is an additive change. And because the recovery key authorises its own replacement (§14), the move is one witnessed entry, not a new identity.

**Why not wait, or go hybrid from the start.** Waiting leaves identities with no recovery at all, against a threat that does not yet exist, when the commitment is already safe and the key can be swapped later. Going hybrid from the start costs every level-3 operator n post-quantum keys and a proof-set verifier before any verifier needs one. The design therefore makes step 2 an option on the custodian, not a requirement, and makes step 3 free.

**Hash-based keys** (SLH-DSA, XMSS, LMS) cannot be thresholded in practice, but a single SLH-DSA key is a sound post-quantum choice for a kind (a) separately held recovery key, and its hash commitment is no different from any other.

## 13. Rotation, retirement, revocation and recovery

This section is unchanged from the first design, for levels 2 and 3. At level 1, the general rotation rules apply (VTI-KEY-040 to 043).

| Change | What happens | In the document afterwards |
|---|---|---|
| **Rotate** (`attestation`, `operational`, `messaging`) | Publish first, at least the validity period before use (VTI-KEY-122). Staged → active → retiring → retired. Horizon `max(ttl, 24 h)` | old method removed |
| **Retire** | Planned. A retired `attestation` key is **destroyed** (VTI-KEY-125). At level 2, copies in backups persist until those backups expire | removed; `revoked` never set |
| **Revoke for compromise** | Compromise time stated. No overlap (VTI-KEY-121, 123) | kept with CID `revoked` for life (VTI-KEY-126/127) |
| **Rotate `update`** | Moves to the committed routine successor (VTI-KEY-124) | log changes |
| **VTA boundary compromised, level 3** | Rotate to the **recovery key** (`keys/revoke` `scope: boundary`) | — |
| **VTA boundary compromised, level 2** | No recovery key. **Deactivate** if the operator still can, and create a successor (`scope: boundary` is refused) | deactivated |
| **VTA lost, levels 1 and 2** | Restore the backup (`recover` is refused) | — |
| **VTA lost, level 3** | `vta/dids/recover` with the recovery custodian | — |
| **Replace the recovery commitment** | **Authorized by the current recovery key** (`keys/rotate` with `useRecoveryKey`). The quorum path only if that key is lost | — |

A `messaging` key is rotated on the same mechanics, with one difference in meaning: its revocation protects nothing already sent. Verifiers apply VTI-KEY-130 to 135, unchanged. At level 2, VTI-KEY-132 ("retirement bounds issuance") holds only as far as the VTA's backups and seed have not been taken. That is the risk a level-2-accepting verifier accepts.

## 14. Approvals

- **Preview-bound step-up** (VTI-KEY-180) is **MUST** for:
  - creating a level-3 identity;
  - **raising a level**;
  - changing `attestation` or `update` keys;
  - replacing the recovery commitment;
  - recovery.

  It is **SHOULD** for creating a level-2 identity. That creation commits nothing outside the VTA, and the level-1 path has no step-up at all, so a MUST would push operators down a level.
- **Quorums** (VTI-KEY-181):
  - A recovery commitment is replaced by an entry the **current recovery key** authorizes. The custodian's own check is the second approval. With a threshold custodian, the t participants' approvals are the quorum.
  - Only where the recovery key is lost does the replacement take **two approvers**, wherever two eligible approvers exist. The same applies to **raising to level 3**, which commits a recovery key for the first time, and is a choice an attacker would want to make.
  - Attestation and routine-update changes stay SHOULD-two.
- **Revocation is never blocked** (VTI-KEY-182). **Only the approver's own evidence counts** (VTI-KEY-183). Both are unchanged.

**Why the change to VTI-KEY-181.** A quorum the VTA counts is disarmed by a compromised VTA. A signature by the custodian is checked outside it, and a witness can verify it from the entry alone.

## 15. Level-1 identities and raising a level

**Level 1 is conformant** (VTI-KEY-146). The old "non-conformant, refuse, replace, deactivate" rules (VTI-KEY-146 to 148) are gone.

**Raising in place** (VTI-KEY-147) is `vta/dids/upgrade/1.0`. The draft spec PRs still say MUST retire or revoke; they need the amendment below. It works from level 1 to 2 or 3, or from 2 to 3, in one entry authorized by the current update authority. That entry:
1. mints **fresh** keys for every role whose custody tightens. From level 1, that is every role, plus a routine update key and its successor. From level 2 to 3, it is the `attestation` keys and the routine update key and successor.
2. says what happens to the replaced keys: `previousKeys: retire`, `revoke` or `keep` (required, because the choices have different effects on every credential in force);
3. declares the new level. At level 3, it also commits the recovery key and names a witness.

**The old key: retire or revoke is recommended, not required (decided 2026-10-31).** The first draft made retirement or revocation a MUST. The maintainer's decision is that it is a **SHOULD**: a raise is a custody change, not evidence of compromise, and forcing the old key out forces a re-issue of everything it signed, which is the cost that stops operators raising at all. So:

- **`retire`** (recommended): the key is removed with overlap, as any rotation (VTI-KEY-122). Credentials it signed stay valid as level-1 artefacts until they expire or are re-issued.
- **`revoke`**: where the key may have been exposed. A compromise time is stated, and every artefact after it is refused. Re-issue is then required (VTI-KEY-149).
- **`keep`**: the key stays in the document, bound as the **`operational`** key and nothing else. That is the role whose custody it already had: the service process held it. It may never become an `attestation` or `update` key at the new level, because its custody never matched those roles.

Keeping it is sound for the same reason in-place raising is sound (below): VTI-KEY-201 judges every artefact at the level where its signing key was bound. Whatever the old key signed before the raise is a level-1 artefact; whatever it signs after, as `operational`, is traffic. A verifier that requires level 2 for credentials refuses both; a level-1 verifier accepted both already. What the operator gives up by keeping it is only the clean cut: the key the service process held during level 1 is still the key it holds now.

**Why in-place raising is now sound, when the first design said it was not.** The first design's objections were true of the old key: it had operational custody, and it is not destroyed. But a raise never retrofits that key; it replaces it. VTI-KEY-201 judges an artefact at the level where its **signing key** is bound, and a raise keeps every attestation key to one level. So:
- whatever the old key signs stays a **level-1 artefact**, including something backdated by a thief after the raise;
- a verifier requiring level 2 refuses it;
- a level-1 verifier would have accepted that key anyway.

The update authority moves to keys the old key's holder never had. What a raise cannot certify is the past: if the old key was stolen before the raise, the thief may have acted first. That is true of every rotation, and it is what `previousKeys: revoke` is for.

**No lowering** (VTI-KEY-148). A lowered level is exactly what a compromised VTA would publish to disarm level 3. Forbidding it lets witnesses refuse the change, and lets verifiers treat a fall as compromise. To lower a level, create a new identity.

On a raise, every status list is re-signed at once. Credentials are re-issued where relying parties need the new level, and must be where the old keys were revoked (VTI-KEY-149).

## 16. Passkeys

A passkey is an `authenticator` key. It may sit on a **persona DID**, or on a relationship DID the person holds, in `authentication`, listed under `keyRoles.authenticator` (VTI-KEY-154, 191). It never sits on a service DID. A verifier accepts it only for WebAuthn assertions.

`operations/passkey_vms` changes: enrolment is allowed only on a persona (`vta-persona`). The persona's `keyRoles` lists only its passkeys.

## 17. Privacy

- `keyRoles` holds only role names and method IDs.
- `keyAssurance` holds only the level, plus at level 3 which commitment is the recovery one (VTI-KEY-150, 197).
- Nothing about custody, the custodian's kind or identity, host or operator is published. A FROST group's membership and threshold are never published; to the world it is one key.
- Per-relationship keys belong on relationship DIDs (VTI-KEY-151).
- A raise, like an `attestation` rotation, is a coarse timestamp (VTI-KEY-153).
- The mediator relays envelopes it cannot open (§3.2).

## 18. Open questions

**For the working group:**
1. **Custody evidence.** A level is a checked structure plus an unchecked custody claim. Should VTI define evidence, such as TEE attestation of the VTA, or a witness policy statement, for verifiers whose policy needs more?
2. **did:webs.** The extension routes (A) or (B) are as before. Under did:webs, level 3's recovery structure is *more* checkable (K alone satisfies `nt`), and the next-key threshold stands in for the witness.
3. **Witness verification of a quorum replacement.** When the recovery key is lost, the witness must be shown the quorum's approvals, but nothing tells it who is eligible. This needs a witness protocol, or a rule that a level-3 identity whose recovery key is lost falls back to a new identity.
4. **The level-1 key after a raise.** Decided on our side (§15): retire or revoke is a SHOULD, and the key may be kept as `operational`. A thief who had it can still forge level-1 artefacts, which is the risk level-1 verifiers already accept. The working group may want the default to be `retire`.
5. **A hold period on recovery.** Social-recovery wallets delay a guardian-initiated recovery by one to several days, during which the current key can cancel it (§19.2). VTI has no equivalent: a recovery entry takes effect when the witness co-signs it. A witness-enforced hold, during which the routine `update` key may veto and the operator is notified, would protect against a colluding custodian quorum at the cost of slower recovery. Should the witness profile offer it?
6. **CID `revoked`**, the **24-hour verifier cache cap** (VTI-KEY-134), the **w3id registrations** (`keyRoles`, `keyAssurance`) and **registry record proofs** (VTI-KEY-085) are unchanged from the first design.

**For the maintainer:**
7. **`create` at level 1.** `vta/dids/create/1.1` takes levels 2 and 3 only, and level 1 stays on the method-specific creation (`vta/webvh/dids/create`). That keeps today's path untouched, and keeps level 1 out of the key-role family. The cost is two creation tasks behind one `pnm dids create --level` command. The alternative is to accept level 1 in `create`.
8. **A threshold routine update key** under did:webvh costs a DKG per change. Should the webvh profile allow committing the same group key again, which would weaken pre-rotation? We say no.
9. **The defaults** our tooling ships: the per-template levels proposed in §5.4, and the verifier policy (§19.4).

## 19. Principles, precedents and the balance

### 19.1 The principles the design applies

The design follows the Saltzer and Schroeder principles, which are fifty years old and still the shortest statement of what a protection mechanism should look like:

| Principle | Where it shows |
|---|---|
| **Separation of privilege**: require two parties where one would do | Two approvers for `attestation` and `update` changes; the recovery key outside the VTA; a FROST group where the second party is enforced by the signature |
| **Least privilege** | The service process holds only the keys it uses every minute; the oracle signs only what policy allows |
| **Fail-safe defaults**: absence means the most restrictive reading | A missing or unverifiable level caps down, never up; an unknown role confers nothing; a lowered level reads as compromise; fewer than t custodians means wait, not fall back |
| **Economy of mechanism** | A FROST signature is an ordinary Ed25519 signature, so did:webvh, witnesses and verifiers change nothing; the level is one value capped by structure, not a new protocol |
| **Open design** | Nothing depends on custody being secret; what is published is exactly what a verifier needs and no more |
| **Psychological acceptability**: a mechanism people will use correctly | Three levels with plain names; nothing forced; warnings instead of refusals below the recommended level; one ceremony per decision, not per operation |

### 19.2 What the design borrows, and from where

None of the mechanisms here is new. Each has a well-worn precedent, and knowing the precedent says what to expect of it.

| Precedent | What it established | Where it appears here |
|---|---|---|
| **NIST SP 800-57, key management** | One key, one purpose. Signature keys and key-establishment keys are separate key types with separate lifetimes | §3; VTI-KEY-071, 114, 184 |
| **NIST SP 800-63, digital identity** | Assurance is graded (IAL, AAL, FAL), each level is legitimate, and the **relying party** chooses the level its risk needs. The provider does not decide for it | Levels 1 to 3, with each verifier setting its minimum per use (§5, §7) |
| **DNSSEC: KSK and ZSK** | A rarely changed key anchored above, and a routinely rolled online key below. The split is operational, not required by the protocol; a single-key scheme is a documented, reasonable choice for zones that do not need it (RFC 6781) | `update` and `attestation` above, `operational` below; level 1 as a legitimate choice |
| **TUF, the Update Framework** | Named roles with thresholds; the root role's keys offline; online automation keys never trusted for the decision a client ultimately acts on; short expiry for the volatile roles | Roles; an offline or threshold recovery key; `attestation` kept off the online path; routine rotation of `operational` |
| **Certificate authorities** | An offline root signs an online intermediate; the intermediate issues; transparency logs make every issuance visible | The VTA's `attestation` key behind an oracle; the witnessed did:webvh log |
| **Matrix cross-signing** | A master key that may be kept offline, device keys that are online, and a user-held recovery key. Its lesson is usability: recovery keys that people must keep get lost, and technical names confuse the people they protect | Why a second VTA and a FROST group are custodians alongside the offline key; why the levels have plain names |
| **Social-recovery wallets** | A daily key plus a guardian set with a threshold; recovery is delayed one to several days, during which the current key can cancel | The FROST recovery group; the hold period, raised as open question 5 |
| **did:webvh itself** | Pre-rotation commits the next key's hash before it is used; witnesses co-sign entries | The recovery commitment in `nextKeyHashes`; the witness as the enforcer at level 3 |

### 19.3 The balance: where simplicity won, and where security did

The design trades simplicity and usability against security and privacy in a small number of places. Each is a choice, and the reasoning is recorded so the working group can disagree with the choice rather than rediscover the question.

**Where simplicity and usability won:**

- **Level 1 stays conformant.** Security would say refuse it. Usability says a verifier that refuses every community running today will be bypassed. The verifier decides, per use.
- **Level 2 allows seed-derived, backed-up role keys.** A leaked backup still leaks them. In exchange, a restore brings everything back and no new party is needed, which is what makes level 2 reachable by every operator.
- **Step-up is a SHOULD for creating a level-2 identity.** A MUST would make level 2 harder to create than level 1, and push operators down.
- **A level is self-declared custody plus checked structure.** A custody-attestation protocol would be a project in itself. The checked part is what a compromised VTA would want to change; the unchecked part is what an honest operator states.
- **Threshold signing is for recovery only.** A FROST round per credential would stop issuance whenever t operators are not at their desks. The recovery key signs once in most identities' lives.
- **Raising a level is one ceremony on the same DID.** The first design required a new identifier, re-issue and deactivation. That cost was the reason nobody would have raised.

**Where security and privacy won:**

- **No lowering a level.** An operator who wants less protection creates a new identity. The alternative gives a compromised VTA the one move it needs.
- **No fallback when fewer than t custodians answer.** Availability loses to the attack it would enable.
- **Shamir reconstruct-then-sign is not a threshold custodian**, however convenient.
- **A persona still marks its passkeys.** One marker, because otherwise a VTA-held key can pass as the person.
- **Nothing about custody is published.** Not the custodian's kind, identity, host or operator, and not a FROST group's membership. A verifier learns the level and which commitment is the recovery one, and nothing else.
- **The recovery key authorizes its own replacement.** A VTA-counted quorum is simpler, and is disarmed by the one failure it exists for.

### 19.4 Two recommendations that follow

Both change a default, not a requirement, and both are for the maintainer (open question 9).

1. **Let the service's template set the level** (§5.4, decided). Level 2 costs no new party and no ceremony, so it is the right default wherever a service's decisions are relied on: a community, a registry, a witness, a ballot box, the VTA itself. Level 1 is the right default wherever nothing is: a mediator, a gateway, a room. "Secure by default where it is free, opt-in where it costs a party" is the rule every precedent above applies, and the template is what knows which case a service is. `--level 1` stays available where the template allows it, with a warning naming what level 1 does not survive.
2. **Ship the SDK verifier policy at level 1, with the recommended minimums one setting away.** A default above 1 would refuse every existing community on upgrade. A documented profile (`recommended`: 2 for membership credentials, 3 for authority-conferring ones) lets an operator raise it in one line.

A third, smaller one: **rehearse recovery.** The liveness challenge (§12.2) proves the custodians can sign. It does not prove the operator knows the procedure. `vta/dids/recover` should have a rehearsal mode that runs the whole ceremony against a challenge that is never a log entry, and records that it was run.

## 20. Benefits

| Before | After |
|---|---|
| One shape for every DID: all-or-nothing | Three DID classes. Service DIDs choose a level, and verifiers choose a minimum |
| Compromising the service process yields issuance, status-list rewrites and DID takeover | **At level 2**, it yields only traffic signing and traffic reading |
| A leaked backup or mnemonic is a leaked identity | **At level 3**, backups and the seed hold no `attestation` or `update` key |
| Losing or compromising the VTA is permanent | **At level 3**, recovery through a custodian: an offline key, a second VTA, or a FROST group |
| Recovery replacement guarded by a VTA-side quorum | Guarded by the recovery key itself, checked by the custodian and the witness. A FROST group enforces two approvers cryptographically |
| A claimed protection cannot be checked | A declared level, **capped by structure**. A lowered level is treated as compromise |
| Moving to key roles meant a new DID for every node, plus re-issue and deactivation | **Raise in place.** The same DID |
| A verifier cannot tell which key may issue credentials | At levels 2 and 3, a verifier enforces role plus relationship |
| A stolen signing key also reads traffic, and a stolen encryption key also forges | Signing and encryption keys are independent (VTI-KEY-114, 184) |
| Rotation indistinguishable from compromise | Planned rotation with overlap, versus revocation with a compromise time |
| Passkeys on infrastructure DIDs | Passkeys only on persona (or a person's relationship) DIDs, marked `authenticator` |

## 21. Implications and costs

**For operators:**
- **Nothing is forced.** Today's DIDs are level 1, and conformant.
- **Level 2 is cheap.** No new party, no ceremony, and backups restore everything. The cost is that the VTC must ask its VTA to sign every credential and status list (VTI-KEY-111). A VTA outage now pauses issuance and status-list refresh, not traffic: members keep talking, rooms keep running, and the status lists in verifiers' caches stay valid for their window.
- **Level 3 costs real work:**
  - a recovery custodian, arranged and kept separately;
  - a witness outside the VTA, which may be the custodian;
  - backups that no longer restore the seal: after a restore, recovery plus re-signing status lists plus re-issue (VTI-KEY-117);
  - a FROST custodian also needs t independent operators, available when needed.
- **Raising is one ceremony**, and the level can never go back down.
- **Approvals.** Changes of role keys at levels 2 and 3 go through previews, step-ups and quorums. Revocation stays one approval.

**For verifiers** (our code, the browser extension, openvtc, registries, third parties):
- Establish the level (VTI-KEY-199), and apply a per-use policy (VTI-KEY-200).
- At levels 2 and 3, select by `keyRoles` plus relationship. At level 1, select by relationship.
- Judge an artefact by its key's level (VTI-KEY-201).
- Honour `revoked`, and re-resolve within 24 h.
- **There is no compatibility cliff.** A verifier that never raises its minimum above 1 behaves as today.

**For members:** passkeys on infrastructure DIDs will be refused. Persona passkeys are now marked `authenticator`.

**For the code:**
- One new subsystem crate, `vta-key-roles`.
- A role-key KEK, for level 3 only.
- A plan store, and bound step-up ported from the VTC.
- The `vta/dids/*` family, including `upgrade`, with `previousKeys: keep`.
- `defaults.keyAssurance` in the DID template schema, the per-template values of §5.4, and the CLI's level resolution.
- Level determination and a policy in our verifiers.
- The VTC's issuance path moved from local signing to a signing request to its VTA.
- Later, the FROST custodian: a crate over an audited FROST implementation, plus the ceremony tasks.

## 22. Where the code stands, and the plan

The survey of today's code, and the build order, are in [key-roles-implementation.md](key-roles-implementation.md) (§1 and §3). That plan is revised for levels.

## References

- Saltzer, J. H. and Schroeder, M. D., *The Protection of Information in Computer Systems*, 1975.
- NIST SP 800-57 Part 1, *Recommendation for Key Management*; NIST SP 800-63, *Digital Identity Guidelines*.
- RFC 6781, *DNSSEC Operational Practices, Version 2*; RFC 8032 (EdDSA); RFC 9591 (FROST).
- The Update Framework specification, <https://theupdateframework.github.io/specification/>.
- Matrix MSC1756, *Cross-signing devices with device signing keys*.
- Buterin, V., *Why we need wide adoption of social recovery wallets*, 2021.
- did:webvh, <https://identity.foundation/didwebvh/>.
- NIST IR 8214C, *First Call for Multi-Party Threshold Schemes*, January 2026, and the MPTS 2026 / TCPT preview talks, <https://csrc.nist.gov/projects/threshold-cryptography>.
- Boschini et al., *Ringtail: Practical Two-Round Threshold Signatures from Learning with Errors*, IEEE S&P 2025, <https://eprint.iacr.org/2024/1113>.
- del Pino et al., *Threshold Raccoon*, Eurocrypt 2024; *FIPS 204-Compatible Threshold ML-DSA via Shamir Nonce DKG*, preprint, January 2026, <https://arxiv.org/abs/2601.20917>.
