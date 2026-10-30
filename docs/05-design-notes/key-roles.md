# Key roles: design

**Status:** design, revised 2026-10-30 to key assurance levels. The first design is merged (dtgwg-vti-spec#79, dtgwg-trust-tasks-tf#986) but has not been published for working-group review. This revision is proposed in dtgwg-vti-spec#82 and dtgwg-trust-tasks-tf#993, both drafts. The build order is in [key-roles-implementation.md](key-roles-implementation.md). **Implementation is paused:** no code has landed, and no step starts without the maintainer's go-ahead.

**Normative sources:**
- **The VTI specification**, chapter *Identity, DIDs and Key Management* (`spec/04-identity-keys.md`). The relevant sections run from *DID classes* through *Authenticator keys*: VTI-KEY-070 to 221.
- **The `vta/dids/*` Trust Task family:**
  - `vta/dids/_shared/0.1`: `CONVENTIONS.md`, `key-roles.schema.json` and `method-profiles/`;
  - `create/1.1`;
  - `upgrade/1.0`;
  - `update`, `keys/{list,add,rotate,retire,revoke}` and `recover`, at 1.0.

Where this note disagrees with either source, the source is right.

This note covers:
- why VTI needs key roles;
- which DIDs need them and how much;
- what the design is, what it costs, and what it changes for operators, members and verifiers.

It also records the decisions made on our side, and the questions left for the working group. A one-page visual summary is published separately.

### What changed in this revision

The first design was all-or-nothing:
- every VTA, VTC and VTN identity without key roles was **non-conformant**, and every verifier had to refuse its credentials;
- every key-role identity needed an external recovery key.

That design is replaced as follows:

- **DID classes.** Relationship, persona and service DIDs are distinguished (§2). Only service DIDs have levels.
- **Key assurance levels.** A service DID is at level 1, 2 or 3, chosen by its operator (§4). Every level is conformant, and **each verifier's policy** decides which level it accepts for each use (§6). Today's single-key DIDs are level 1, and nothing breaks.
- **The recovery key is mandatory only at level 3.** It was mandatory everywhere only because of the no-backup rule (§4.2).
- **A declared level, checked against structure.** This is how a verifier tells the levels apart (§5).
- **Threshold recovery custody.** A group of VTAs using FROST (RFC 9591) is added as a recovery custodian (§10).
- **Raising a level in place.** An identity is upgraded with one history entry, without a new identifier, and is never downgraded (§13).

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

## 3. Roles

A *key role* is a named position a key occupies in an identity. It fixes four things (VTI-KEY-072):
- what the key may sign;
- the one verification relationship it may appear in;
- the proof purpose its proofs may carry;
- who may hold it.

One key has exactly one role (VTI-KEY-071), and key material is never reused across roles, nodes or services.

| Role | Signs / used for | Relationship | Custody | Origin |
|---|---|---|---|---|
| `attestation` | Decisions: every credential the node issues, status lists, endorsements (VTI-KEY-080) | `assertionMethod` only | **VTA only**. At level 3, never exportable and never in a backup | level 3: generated. Level 2: derived or generated |
| `operational` | Traffic: Trust Task request/response, DIDComm/TSP signatures, invitations, audit checkpoints (VTI-KEY-081) | `authentication` only | may be held by the node's service process (VTI-KEY-114) | derived |
| `messaging` | Key agreement; signs nothing | `keyAgreement` only | may be held by the service process | derived, as native X25519 |
| `update` | Entries in the DID's own history | **none** (VTI-KEY-093) | routine key: VTA only. Recovery key (level 3): **outside the VTA** | as `attestation` |
| `authenticator` | A person's WebAuthn assertions; never a Data Integrity proof | `authentication` only | the person's authenticator, on a persona DID (VTI-KEY-154/155) | the passkey |

An unknown role confers nothing (VTI-KEY-074). `capabilityInvocation` and `capabilityDelegation` are unused (VTI-KEY-075). A companion service signs as itself (VTI-KEY-076/077).

## 4. Key assurance levels

### 4.1 The levels

| Level | Name | Shape | Protects against | VTA lost | VTA compromised |
|---|---|---|---|---|---|
| **1** | single key | One signing key for everything; no `keyRoles`. Today's shape | — | restore from backup | identity lost |
| **2** | role-separated | `keyRoles`. The VTA holds the `attestation` and `update` keys, and **may** derive them from the seed and keep them in its own backup | **service compromise** | restore from backup | deactivate; create a successor |
| **3** | recoverable | Level 2, plus: `attestation` and `update` keys generated, in no backup, and protected at rest independently of the seed; a recovery key held by a recovery custodian outside the VTA; a witness enforcing it | service compromise, **backup theft or seed exposure**, **VTA compromise or loss** | recovery key | recovery key |

Every level is conformant (VTI-KEY-194). The specification recommends level 2 or higher for a VTC, a VTN and a VTA's own identity. It recommends level 3 for a VTC or VTN whose credentials confer authority on others, such as vetter grants or network listings (VTI-KEY-196). These are SHOULDs, so they decide nothing about conformance.

### 4.2 What each layer protects against

- **Role separation, with the VTA holding `attestation` and `update`**, protects against **service compromise** (T1).
  - The process that parses network input holds only traffic keys.
  - Its compromise yields a caller of the VTA's signing oracle, not the seal (VTI-KEY-111, 115).
  - This is level 2. It needs no new party and no new ceremony, and backups keep working. It is the largest gain for the least cost.
- **Generation, and exclusion from backups**, protects against **backup theft and seed exposure** (T3). Neither yields the seal or the DID.
- **A recovery key held outside the VTA** protects against **compromise of the VTA** (T2, given a witness) and **loss of the VTA** (T4).

**The recovery key was mandatory only because of the no-backup rule.** Once role keys are in no backup, a lost VTA loses them, and only a key held elsewhere can take the DID back. At level 2 the keys are in the backup, so a restore brings the identity back, and there is nothing for a recovery key to do against loss. Against VTA *compromise*, a level-2 identity is lost either way. That is what level 2 accepts.

Level 2 with a recovery key is deliberately **not** a level. It would carry the recovery key's cost without level 3's backup exclusion or witness, and a verifier could not tell it from level 2. `create` and `upgrade` refuse a recovery commitment at level 2.

### 4.3 Which requirements apply at which level

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
| No passkey on a service DID (154) | ✓ | ✓ | ✓ |

## 5. How a verifier determines the level

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

So a level is **a checked structure plus an unchecked custody claim**. Evidence beyond that, such as TEE attestation or a witness policy statement, is an open question (§16).

## 6. Verifier policy

A verifier's policy sets a minimum level **per use** (VTI-KEY-200). Examples of what a policy might say (not normative):

| Use | Plausible minimum |
|---|---|
| Operational traffic (a Trust Task response, a DIDComm message) | 1 |
| A membership credential from a small community | 1 or 2 |
| A membership credential relied on for access to something valuable | 2 |
| A vetter grant, a role credential conferring administrative authority, a network listing | 3 |
| A status list | the issuer's level for the credential it governs |

The verifier refuses below its minimum. It must never treat a DID as a level its structure does not support. It may accept level 1. Our own verifiers (SDK, browser extension, openvtc, registries) need a configurable policy, with a sensible default.

## 7. The DID document

Each key's role is stated twice:
- by the standard relationship, which generic DID tooling reads;
- by the top-level `keyRoles` map, which says which role was meant.

The level is stated once, in `keyAssurance`.

```json
{
  "id": "did:webvh:{SCID}:community.example",
  "verificationMethod": [
    { "id": "#z6Mkq…", "type": "Multikey", "publicKeyMultibase": "z6Mkq…" },
    { "id": "#z2Sy…",  "type": "Multikey", "publicKeyMultibase": "z2Sy…" },
    { "id": "#z6Mkv…", "type": "Multikey", "publicKeyMultibase": "z6Mkv…" },
    { "id": "#z6LSb…", "type": "Multikey", "publicKeyMultibase": "z6LSb…" }
  ],
  "assertionMethod": ["#z6Mkq…", "#z2Sy…"],
  "authentication": ["#z6Mkv…"],
  "keyAgreement":   ["#z6LSb…"],
  "keyRoles": {
    "attestation": ["#z6Mkq…", "#z2Sy…"],
    "operational": ["#z6Mkv…"],
    "messaging":   ["#z6LSb…"]
  },
  "keyAssurance": { "level": 3, "recoveryCommitment": "QmRecoveryHash" }
}
```

The rules from the first design all stand, now at levels 2 and 3:
- every method is under exactly one role (VTI-KEY-090), in that role's relationship only (VTI-KEY-091);
- a verifier refuses only the method in doubt (VTI-KEY-092);
- `update` is never in `keyRoles` (VTI-KEY-093);
- keys are selected by role, never by fragment (VTI-KEY-094);
- `keyRoles` is a top-level member (VTI-KEY-095), with its JSON-LD term (VTI-KEY-096);
- fragments are derived from the key (VTI-KEY-150);
- proof sets are supported (VTI-KEY-103/104).

## 8. Protection boundaries and custody, by level

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

## 9. Recovery custodians (level 3)

### 9.1 Kinds

VTI-KEY-205 allows three kinds of recovery custodian:

| Kind | What | How it signs | Wire (`RecoveryCustodianKind`) |
|---|---|---|---|
| **(a) Separately held key** | `pnm recovery-key`: a passphrase-encrypted file (Argon2id + AES-256-GCM), offline. A hardware token or a key service whose credentials no VTA of the identity holds also counts. So does a **printable recovery mnemonic from a seed the VTA never sees**. **Never** the VTA's own seed | Out of band. Air-gap form: `--recovery-key did:key:… --recovery-pop …` | `separateKey` |
| **(b) Second VTA** | Its own seed, operator and host. Holds the key with level-3 custody | Checks the change itself and asks its own operator (VTI-KEY-206). The request may be routed to its DID | `vta` |
| **(c) Threshold group of VTAs** | FROST, t-of-n (§10) | Every participant checks and asks its operator; t sign together | `thresholdGroup` |

The custodian kind is declared by the operator in `RecoveryCommitment.custodian`. It is kept in custody records and **never published** (VTI-KEY-150, 206). The VTA cannot verify the kind. It verifies the proof of possession over the `previewId`, and refuses a key it generated or can derive.

**The witness may be run by the custodian.** It is already outside the VTA's boundary, so level 3 adds one party, not two.

### 9.2 Why not use the BIP-32 seed for the recovery key?

The recovery key exists to survive **compromise of the VTA**, not just loss. A key derived from the VTA's seed cannot do that, for four reasons:

1. **The running VTA holds the seed.** An attacker holding the VTA derives the "recovery" key, appends an entry, commits their own key, and owns the identity. VTI-KEY-116 says the VTA must not hold, generate *or be able to derive* it.
2. **The seed is in every backup.** A leaked backup would leak the recovery key (VTI-KEY-118).
3. **A mnemonic in a safe protects against loss only.**
4. **Level-3 role keys are deliberately not seed-derived.** Building the DID's highest authority on the seed would undo that.

What works is BIP-32 from a **different** seed: a recovery mnemonic the VTA never sees, generated offline. The rule is not "no BIP-32". It is "not the VTA's own seed".

### 9.3 How an operator supplies a separately held key (decided)

Decided by the maintainer on 2026-10-30, and unchanged by this revision:

- **A custodian command:** `pnm recovery-key {generate,show,sign-commitment,sign-recovery}`.
  - It writes a passphrase-encrypted file where the operator says.
  - It prints the key as a `did:key` plus a digest.
  - It refuses any path under the VTA's data directory.
- **An air-gap form:** `pnm dids create` (and `pnm dids upgrade`) prints the `previewId` and the exact string to sign. It takes the signature back as `--recovery-key did:key:… --recovery-pop …`. `--recovery-key-file` signs in-process.
- **Hardware tokens** are deferred.

## 10. Threshold custody with FROST

### 10.1 What it is

A threshold custodian is n VTAs, each in its own boundary, holding shares of one Ed25519 key under **FROST(Ed25519, SHA-512)** (RFC 9591), with **2 ≤ t < n**. Any t of them sign together.
- **t ≥ 2:** no participant signs alone.
- **t < n:** the group survives losing one participant.

**FROST produces an ordinary Ed25519 signature that RFC 8032 verifies.** To did:webvh, a witness, the proof-of-possession check and a verifier, the group's key is one Ed25519 key. **No DID-method change is needed.** In `RecoveryCommitment` it is just `keyType: ed25519`, with `custodian: thresholdGroup`.

### 10.2 Security requirements (VTI-KEY-210 to 221)

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
| **Distinct boundaries** | See §10.3 |

### 10.3 What "a different protection boundary" means for operators

Each participant must have:
1. its own seed, store and host. For a VM or an enclave, that means a different host **and** a different cloud account.
2. no credentials reaching another participant's seed, store, secret backend or backups, nor those of the identity's VTA;
3. backups no other participant, and not the identity's VTA, can read;
4. **no subject able to approve signing at t or more participants.** This is an administrator, a delegate or any credential, and it is checked as a rule, not as advice.

Participants SHOULD also have different human operators or organisations, and different failure domains (provider, region).

Item 4 is the important one. One person approving at every participant reduces t ≥ 2 to one approver. With distinct operators, **the two-approver rule for replacing the recovery commitment (VTI-KEY-181) is enforced by the signature itself**, not by the VTA's policy.

### 10.4 Rejected: Shamir reconstruct-then-sign

Splitting the key with Shamir or SLIP-39, and reconstructing it to sign, is **not** a threshold custodian (VTI-KEY-220):
- **At the moment the key matters, it exists whole on one machine.** That machine's compromise yields it, and it may keep it.
- **Only that machine checks what is signed.** The t holders checked nothing; they handed over shares.
- **A dealer held the whole key at generation.**
- **A "fallback to reconstruct" when too few answer is the attack.** An adversary who can make participants unreachable chooses when the key exists in one place.

A Shamir split may still back up a separately held key, kind (a), as protection against losing the file. It is then declared `separateKey`, never `thresholdGroup`.

### 10.5 Where to use it

- **The recovery key:** recommended. It signs once in most identities' lives, so waiting for t operators costs little.
- **The routine update key:** MAY. It closes T2 without relying on the witness. But under did:webvh **every entry moves the update key** (reveal R(n+1), commit a fresh R(n+2)), so every change costs a **DKG plus a signing** across t VTAs. That suits identities that rarely change.
- **`attestation` keys:** **SHOULD NOT**, for four reasons:
  - they sign every credential and every status-list update, so issuance would stop whenever fewer than t operators answer;
  - signing rounds and fatal-if-reused nonces multiply by every credential issued;
  - every participant would have to parse and constrain every artefact (VTI-VTA-004 to 007);
  - their compromise is recoverable anyway, by revocation and re-issue.

### 10.6 Wire, and what is deferred

- **What changes now.**
  - `RecoveryCommitment.custodian` (kind, the custodian VTA's DID, participants, threshold) is added in the `_shared/0.1` schema, additively.
  - The PoP and the recovery proof are unchanged: a group signature is an Ed25519 signature.
- **Deferred.** The ceremony tasks are only outlined in CONVENTIONS §19. They are `vta/threshold/dkg/{commit,share,confirm}`, `sign/{request,commit,share}`, `refresh/*` and `liveness`. Each needs its own specification before implementation.

## 11. Rotation, retirement, revocation and recovery

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

Verifiers apply VTI-KEY-130 to 135, unchanged. At level 2, VTI-KEY-132 ("retirement bounds issuance") holds only as far as the VTA's backups and seed have not been taken. That is the risk a level-2-accepting verifier accepts.

## 12. Approvals

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

## 13. Level-1 identities and raising a level

**Level 1 is conformant** (VTI-KEY-146). The old "non-conformant, refuse, replace, deactivate" rules (VTI-KEY-146 to 148) are gone.

**Raising in place** (VTI-KEY-147) is `vta/dids/upgrade/1.0`. It works from level 1 to 2 or 3, or from 2 to 3, in one entry authorized by the current update authority. That entry:
1. mints **fresh** keys for every role whose custody tightens. From level 1, that is every role, plus a routine update key and its successor. From level 2 to 3, it is the `attestation` keys and the routine update key and successor.
2. retires the replaced keys, or revokes them if they may have been exposed (`previousKeys` is required, because the two choices have opposite effects on every credential in force);
3. declares the new level. At level 3, it also commits the recovery key and names a witness.

**The level-1 key takes no role.** It signed attestations and was held by the service process. Making it the `operational` key would let anyone holding the old document keep accepting it for what it may no longer sign.

**Why in-place raising is now sound, when the first design said it was not.** The first design's objections were true of the old key: it had operational custody, and it is not destroyed. But a raise never retrofits that key; it replaces it. VTI-KEY-201 judges an artefact at the level where its **signing key** is bound, and a raise keeps every attestation key to one level. So:
- whatever the old key signs stays a **level-1 artefact**, including something backdated by a thief after the raise;
- a verifier requiring level 2 refuses it;
- a level-1 verifier would have accepted that key anyway.

The update authority moves to keys the old key's holder never had. What a raise cannot certify is the past: if the old key was stolen before the raise, the thief may have acted first. That is true of every rotation, and it is what `previousKeys: revoke` is for.

**No lowering** (VTI-KEY-148). A lowered level is exactly what a compromised VTA would publish to disarm level 3. Forbidding it lets witnesses refuse the change, and lets verifiers treat a fall as compromise. To lower a level, create a new identity.

On a raise, every status list is re-signed at once. Credentials are re-issued where relying parties need the new level, and must be where the old keys were revoked (VTI-KEY-149).

## 14. Passkeys

A passkey is an `authenticator` key. It may sit on a **persona DID**, or on a relationship DID the person holds, in `authentication`, listed under `keyRoles.authenticator` (VTI-KEY-154, 191). It never sits on a service DID. A verifier accepts it only for WebAuthn assertions.

`operations/passkey_vms` changes: enrolment is allowed only on a persona (`vta-persona`). The persona's `keyRoles` lists only its passkeys.

## 15. Privacy

- `keyRoles` holds only role names and method IDs.
- `keyAssurance` holds only the level, plus at level 3 which commitment is the recovery one (VTI-KEY-150, 197).
- Nothing about custody, the custodian's kind or identity, host or operator is published.
- Per-relationship keys belong on relationship DIDs (VTI-KEY-151).
- A raise, like an `attestation` rotation, is a coarse timestamp (VTI-KEY-153).

## 16. Open questions

**For the working group:**
1. **Custody evidence.** A level is a checked structure plus an unchecked custody claim. Should VTI define evidence, such as TEE attestation of the VTA, or a witness policy statement, for verifiers whose policy needs more?
2. **did:webs.** The extension routes (A) or (B) are as before. Under did:webs, level 3's recovery structure is *more* checkable (K alone satisfies `nt`), and the next-key threshold stands in for the witness.
3. **Witness verification of a quorum replacement.** When the recovery key is lost, the witness must be shown the quorum's approvals, but nothing tells it who is eligible. This needs a witness protocol, or a rule that a level-3 identity whose recovery key is lost falls back to a new identity.
4. **The level-1 key after a raise** is retired, not destroyed. A thief can still forge level-1 artefacts with it. That is the risk level-1 verifiers already accept. Should a raise revoke it by default?
5. **CID `revoked`**, the **24-hour verifier cache cap** (VTI-KEY-134), the **w3id registrations** (`keyRoles`, `keyAssurance`) and **registry record proofs** (VTI-KEY-085) are unchanged from the first design.

**For the maintainer:**
6. **`create` at level 1.** `vta/dids/create/1.1` takes levels 2 and 3 only, and level 1 stays on the method-specific creation (`vta/webvh/dids/create`). That keeps today's path untouched, and keeps level 1 out of the key-role family. The cost is two creation tasks behind one `pnm dids create --level` command. The alternative is to accept level 1 in `create`.
7. **A threshold routine update key** under did:webvh costs a DKG per change. Should the webvh profile allow committing the same group key again, which would weaken pre-rotation? We say no.
8. **The default verifier policy** our SDK ships (§6).

## 17. Benefits

| Before | After |
|---|---|
| One shape for every DID: all-or-nothing | Three DID classes. Service DIDs choose a level, and verifiers choose a minimum |
| Compromising the service process yields issuance, status-list rewrites and DID takeover | **At level 2**, it yields only traffic signing |
| A leaked backup or mnemonic is a leaked identity | **At level 3**, backups and the seed hold no `attestation` or `update` key |
| Losing or compromising the VTA is permanent | **At level 3**, recovery through a custodian: an offline key, a second VTA, or a FROST group |
| Recovery replacement guarded by a VTA-side quorum | Guarded by the recovery key itself, checked by the custodian and the witness. A FROST group enforces two approvers cryptographically |
| A claimed protection cannot be checked | A declared level, **capped by structure**. A lowered level is treated as compromise |
| Moving to key roles meant a new DID for every node, plus re-issue and deactivation | **Raise in place.** The same DID |
| A verifier cannot tell which key may issue credentials | At levels 2 and 3, a verifier enforces role plus relationship |
| Rotation indistinguishable from compromise | Planned rotation with overlap, versus revocation with a compromise time |
| Passkeys on infrastructure DIDs | Passkeys only on persona (or a person's relationship) DIDs, marked `authenticator` |

## 18. Implications and costs

**For operators:**
- **Nothing is forced.** Today's DIDs are level 1, and conformant.
- **Level 2 is cheap.** No new party, no ceremony, and backups restore everything. The cost is that the VTC must ask its VTA to sign every credential (VTI-KEY-111). A VTA outage now blocks issuance, not just administration.
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
- The `vta/dids/*` family, including `upgrade`.
- Level determination and a policy in our verifiers.
- Later, the FROST custodian: a crate over an audited FROST implementation, plus the ceremony tasks.

## 19. Where the code stands, and the plan

The survey of today's code, and the build order, are in [key-roles-implementation.md](key-roles-implementation.md) (§1 and §3). That plan is revised for levels.
