# Key roles: design

**Status:** design. The specification is merged (dtgwg-vti-spec#79, dtgwg-trust-tasks-tf#986). The build order is in [key-roles-implementation.md](key-roles-implementation.md). **Implementation is paused:** no code has landed, and no step starts without the maintainer's go-ahead.

**Normative sources:**
- **The VTI specification**, chapter *Identity, DIDs and Key Management* (`spec/04-identity-keys.md`), sections *Key roles* through *Authenticator keys*: VTI-KEY-070 to 184.
- **The `vta/dids/*` Trust Task family:** `vta/dids/_shared/0.1` (`CONVENTIONS.md`, `key-roles.schema.json`, `method-profiles/`), plus `create`, `update`, `keys/{list,add,rotate,retire,revoke}` and `recover`, all at 1.0.

Where this note disagrees with either source, the source is right.

This note says why VTI needs key roles, what the design is, what it costs and what it changes for operators, members and verifiers. It also records the decisions made on our side and the questions left for the working group. A one-page visual summary is published separately.

---

## 1. The problem

A VTA, a VTC or a VTN signs two very different kinds of thing with one DID.

| Kind | Examples | Who relies on it, and for how long |
|---|---|---|
| **Decisions** | membership credentials, role credentials, endorsements, **status lists** | Third parties, for months or years, usually without ever contacting the node |
| **Traffic** | Trust Task responses, DIDComm/TSP messages, invitations, audit checkpoints | The immediate recipient, once |

Today one Ed25519 key signs both. `create_did_webvh` mints one key into `authentication` and `assertionMethod`, and that same key is the did:webvh log's `updateKeys`. So:

1. **Compromising the most exposed process yields everything.** The service answers network traffic, so it is the most attacked process in the deployment. Whoever takes its key can issue membership credentials, forge role grants, and rewrite the community's status list. Rewriting the status list re-admits everyone the community has suspended or removed, silently and all at once.
2. **The same key controls the DID itself.** The log's update authority is the same key, so the attacker can also rotate the DID to keys of their choosing and lock the operator out. There is no way back.
3. **A verifier cannot tell which use was meant.** A key listed in both `assertionMethod` and `authentication` is authorized for both. Nothing in the document says "this key answers messages and must never issue credentials", so no verifier can refuse a credential signed by it.
4. **Everything derives from one seed.** Every key comes from one BIP-32 seed by path. The seed is in the VTA's store (encrypted only under a key that is itself derived from the seed) and in every backup. A leaked backup is a leaked identity.
5. **Rotation cannot say why.** `update/rotate.rs` replaces every method at once, keeps the fragment ids and re-derives successors from the same seed. A verifier cannot tell a routine rotation from a compromise. So it cannot know whether credentials signed by the old key yesterday are still good.

The specification's answer is to name the job each key does, give each job its own key, custody and verification relationship, and let verifiers enforce it.

## 2. Roles

A *key role* is a named position a key occupies in an identity. It fixes four things: what the key may sign, the one verification relationship it may appear in, the proof purpose its proofs may carry, and who may hold it (VTI-KEY-072). One key has exactly one role (VTI-KEY-071), and key material is never reused across roles, nodes or services.

| Role | Signs / used for | Relationship | Custody | Origin |
|---|---|---|---|---|
| `attestation` | Decisions: every credential the node issues, status lists, endorsements (VTI-KEY-080) | `assertionMethod` only | **VTA only**, generated (not derived), never exportable, never in a backup (VTI-KEY-110–112) | generated |
| `operational` | Traffic: Trust Task request/response, DIDComm/TSP signatures, invitations, audit checkpoints (VTI-KEY-081) | `authentication` only | may be held by the node's service process (VTI-KEY-114) | derived |
| `messaging` | Key agreement for encrypted transport; signs nothing | `keyAgreement` only | may be held by the service process | derived, as native X25519 |
| `update` | Entries in the DID's own history (did:webvh log) | **none**: it is never a verification method (VTI-KEY-093) | routine key: VTA only, like `attestation`. Recovery key: **outside the VTA** (VTI-KEY-116) | generated |
| `authenticator` | A person's WebAuthn passkey assertions: sign-in and step-up evidence; never a Data Integrity proof | `authentication` only | the person's own authenticator; only on that person's own identity, never on a node's (VTI-KEY-154/155) | the passkey |

Further rules:
- **`capabilityInvocation` and `capabilityDelegation`** are not used by any role, so a verifier must not rely on a key found only there (VTI-KEY-075).
- **An unknown role confers nothing** (VTI-KEY-074). A verifier that does not recognise a role must not fall back to whatever the relationship ordinarily means.
- **A service running beside a node signs as itself.** A forge bridge, a status-list host or a website host has its own DID and keys (VTI-KEY-076/077). Its keys never appear in the node's document. Any authority it holds is an ACL entry or a credential the node issues to it.

## 3. The DID document

Each key's role is stated twice: once by the standard relationship, which generic DID tooling reads, and once by a top-level `keyRoles` map, which says which role was meant.

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
  }
}
```

- **Every listed method appears in `keyRoles` under exactly one role** (VTI-KEY-090), and in the relationship that role requires, no other (VTI-KEY-091).
- **A verifier refuses the one method in doubt:** a method absent from `keyRoles`, listed under two roles, or listed in the wrong relationship (VTI-KEY-092). It does not refuse the whole document, so a misconfigured node stays reachable while it is fixed.
- **`update` is never in `keyRoles`.** The update authority lives where the method puts it: for did:webvh, the log's `updateKeys` and `nextKeyHashes` (VTI-KEY-093).
- **Keys are selected by role**, through `keyRoles` plus the relationship, never by fragment, position, type or algorithm (VTI-KEY-094). The fragment `#key-0` stops meaning anything.
- **`keyRoles` is a top-level member** (VTI-KEY-095), not a method parameter or a linked resource. Many resolvers drop method parameters, and a linked file is a second fetch whose absence would read as "no roles". For JSON-LD the term is `https://w3id.org/vti#keyRoles` as an `@index` map (VTI-KEY-096). The w3id registration is still open.
- **Fragments are derived from the key's multibase** (VTI-KEY-150). They reveal nothing about role, custody, host or operator.
- **More than one `attestation` key** (for example Ed25519 plus ML-DSA-44) lets the node sign a credential with a proof set (VTI-KEY-103). A verifier's policy may require the post-quantum proof (VTI-KEY-104).

## 4. Protection boundaries and custody

The central idea is the **protection boundary** (VTI-KEY-118): two keys are in the same boundary whenever one compromise or one loss reaches both. That includes reaching them through a backup, a seed, a key derived from a seed, or credentials one holds to the other's store.

What that means for each kind of VTA:

| VTA kind | Boundaries | Why |
|---|---|---|
| Plain | 1 | Host, store and seed backend credentials are all on one machine |
| Hardened | 1 | The store is encrypted, but under a key derived from the seed |
| TEE (Nitro) | 1, stronger | The host cannot read inside the enclave, but every key the enclave holds is inside it |
| Mnemonic in a safe | protects against *loss* only | The running VTA still holds the seed, so a compromise reaches every key derived from it |

Every VTA is, by itself, **one** protection boundary. The custody rules follow from that:

- **`attestation` and `update` keys are generated, not derived** (VTI-KEY-110, 116), and never exported or backed up (VTI-KEY-112). A leaked backup or an exported mnemonic therefore yields no ability to issue credentials or rewrite the DID.
- **At rest they are protected under a key that is not derived from the seed and is in no backup** (VTI-KEY-118). We call this the *role-key KEK*: a key-encryption key that wraps the role keys.
  - **TEE:** a KMS data key whose release is bound to the enclave measurement. Protection class `enclave`.
  - **Hardened / plain, with a secret-manager seed backend:** a second secret in the same backend under its own name. Protection class `encryptedAtRest`.
  - **Plain, with a config or plaintext seed backend:** a 0600 file beside the store. Protection class `software`, and every preview warns `protectionBelowPolicy`.

  Wrapped keys live in a new `role_keys` keyspace in `EXCLUDED_FROM_BACKUP`. After a restore, each lost role key is reported, and the remedy is recovery (§6), never the backup.
- **The service process holds only `operational` and `messaging` keys** (VTI-KEY-114). A VTC or VTN obtains every credential by a signing request to its VTA (VTI-KEY-111), which applies the usual signing-oracle checks. Compromising the service must not yield the ability to issue credentials or write the DID log, except by a request the VTA authorizes and records (VTI-KEY-115).
- **No secret is derived from a signing key, or used to derive one** (VTI-KEY-114). That covers storage keys, audit chain keys, enrolment secrets and session secrets.
- **The X25519 `messaging` key is derived as X25519**, not computed from an Ed25519 key (VTI-KEY-184). Today's birational conversion (`derive_x25519`) stays only for pre-role DIDs that already published it.

## 5. The recovery key

### 5.1 What it is

Every version of a key-role identity's history commits to two successors of the update authority (VTI-KEY-116):

- **The routine successor:** generated and held by the VTA. It is used for normal rotations.
- **The recovery key:** held by a **recovery custodian in a different protection boundary**. The VTA must not hold it, generate it, or be able to derive it.

For did:webvh, every log entry carries `nextKeyHashes = [hash(routine successor), hash(recovery key)]`. The VTA carries the recovery hash forward unchanged in every version (VTI-KEY-119). It changes only when the recovery key itself is used, or when a quorum approves replacing it (VTI-KEY-181). The VTA accepts a recovery commitment only with a **proof of possession bound to the change**: a signature by the recovery key over the VTA-computed `previewId`. A VTA refuses to create a key-role identity without one.

When a recovery happens, the VTA asks the custodian to sign one log entry. That entry reveals the recovery key, installs new `attestation` keys and a new routine update key, commits a **fresh** recovery key, and retires the lost `attestation` keys. If the old keys may have been exposed rather than destroyed, it revokes them instead (VTI-KEY-117, 128). A recovery key authorizes one entry only. The custodian must check the entry itself, not trust the requester's description of it (VTI-KEY-128).

### 5.2 Why not use the BIP-32 seed for the recovery key?

It is the obvious idea: the VTA already has a BIP-32 seed with a mnemonic the operator wrote down, so why not derive the recovery key at its own path and keep the mnemonic in a safe?

The recovery key exists to survive **compromise of the VTA**, not just loss of it, and a key derived from the VTA's seed cannot do that:

1. **The running VTA holds the seed.** It must, to derive every other key. An attacker who compromises the VTA reads the seed, derives the "recovery" path, and holds the recovery key too. Recovery would then be a race the attacker can win: they publish a log entry with the recovery key, commit a recovery key of their own, and the identity is theirs permanently. VTI-KEY-116 forbids this directly: the VTA must not hold, generate *or be able to derive* the recovery key.
2. **The seed is in every backup.** A leaked backup would leak the recovery key. VTI-KEY-118 counts "a seed, a key derived from a seed" as the same boundary.
3. **The mnemonic in a safe protects against loss only.** If the VTA's host dies, the mnemonic restores it. But a compromise needs a key the attacker could not have reached, and every key derived from a seed the VTA holds is reachable.
4. **The other keys are not seed-derived either.** `attestation` and `update` keys are deliberately generated rather than derived (VTI-KEY-110, 116), so that seed exposure does not yield them. Rebuilding the DID's highest authority on the seed would undo the reason for that.

What **does** work is BIP-32 from a **different** seed: a recovery mnemonic that the VTA never sees. It is generated on another machine (or offline), and only its public key and proofs of possession ever reach the VTA. That is a separate protection boundary, and the custodian tool (§5.3) may offer exactly that, a printable recovery mnemonic, as one way to hold the key. The rule is not "no BIP-32". The rule is "not the VTA's own seed".

Using the VTA's seed for everything else is still fine. `operational` and `messaging` keys remain seed-derived, which keeps deterministic recovery of the service's everyday keys. Those keys can only sign traffic, which is exactly why losing them to a seed leak is survivable.

### 5.3 How an operator supplies it (decided)

The specification fixes *what* the recovery key is: Ed25519, held in another boundary, with a proof of possession over the `previewId`. It does not say *how* an operator supplies it. Decision (maintainer, 2026-10-30):

- **A custodian command:** `pnm recovery-key {generate,show,sign-commitment,sign-recovery}`.
  - It keeps the key in a passphrase-encrypted file (Argon2id + AES-256-GCM, the backup's KDF) written wherever the operator says.
  - It prints the key as a `did:key`, plus a digest for the operator to record.
  - It refuses any path under the VTA's data directory.
- **An air-gap form:** `pnm dids create` runs the dry run and prints the `previewId` and the exact string to sign. It takes the result back as `--recovery-key did:key:… --recovery-pop …`. So the custodian can be an air-gapped machine, a second operator, or (later) a hardware token. `--recovery-key-file` signs in-process when the file is local.
- **Hardware tokens** (PIV, FIDO2 hmac-secret) are deferred; the two-flag form leaves room for them.

## 6. Rotation, retirement, revocation and recovery

The specification separates **planned rotation** from **revocation for compromise**, and records both in the DID's history so a verifier can tell them apart (VTI-KEY-120).

| Change | What happens | Overlap | In the document afterwards |
|---|---|---|---|
| **Rotate** (`attestation`, `operational`, `messaging`) | The new key is published first, at least the document's validity period (VTI-KEY-060) before first use, so caches see it (VTI-KEY-122). From first use, the old key no longer signs. | yes: staged → active → retiring → retired. Horizon `max(ttl, 24 h)` | the old method is removed |
| **Retire** | Planned removal. An `attestation` key is **destroyed** inside the boundary (VTI-KEY-125) | — | removed; `revoked` is **never** set (VTI-KEY-126) |
| **Revoke for compromise** | States the **compromise time**, or the key's first publication if that is unknown (VTI-KEY-121). Removed from every relationship and from `keyRoles` in the same entry (VTI-KEY-123) | **none** | kept in `verificationMethod` with CID `revoked: <compromise time>`, **for the life of the identity** (VTI-KEY-126/127) |
| **Rotate `update`** | Moves to the committed routine successor and commits a new one (VTI-KEY-124) | none | the log changes; the document does not |
| **Update key compromised, VTA boundary intact** | rotate to the routine successor | — | — |
| **VTA boundary may be compromised** | rotate to the **recovery key** (§5) | — | — |
| **No uncompromised committed key remains** | **deactivate** the DID and establish a successor identity (VTI-KEY-124) | — | deactivated |

Why the difference matters for verifiers (VTI-KEY-130–135):
- After a **retirement**, credentials signed before it remain valid.
- After a **revocation**, a verifier refuses anything signed by that key from the compromise time on (VTI-KEY-133), and re-resolves the signer's DID at most 24 h stale (VTI-KEY-134).
- Material whose signing time is attested only by the signer itself does not count as issued before a compromise (VTI-KEY-135).

Today's rotation (all keys at once, same ids, from the same seed, no overlap) can express none of this.

**Algorithms** (VTI-KEY-184): a successor keeps its predecessor's algorithm unless the request names another. The VTA never substitutes an algorithm silently, and refuses a change it cannot make with the requested one.

## 7. Approvals

These are changes that could hand over a community's authority, so they need more than a logged-in session.

- **Preview-bound step-up** (VTI-KEY-180). The VTA computes the complete resulting DID document, and every change to the update authority, as a **preview plan**. The operator's step-up gesture is bound to that preview's digest. Then the VTA applies **exactly** the previewed change, or nothing. A session elevation never satisfies this. It is required for:
  - creating a key-role identity;
  - adding, rotating, retiring or revoking an `attestation` or `update` key;
  - replacing the recovery commitment;
  - recovery.
- **Quorums** (VTI-KEY-181):
  - Replacing the recovery commitment **must** have two distinct approvers wherever two eligible approvers exist.
  - Adding, rotating or retiring an `attestation` key, or rotating a routine update key, **should** have two.
  - The initiator counts once at most.
- **Revocation is never blocked** (VTI-KEY-182). It needs at most one approval and supersedes any pending, staged or overlapping change to the same role. A context administrator can revoke `attestation`, `operational` and `messaging` keys. A compromise is a race, and the defender must never have to wait for a quorum to stop the bleeding.
- **Only the approver's own evidence counts** (VTI-KEY-183): a proof by a key of the approver's own DID, or an assertion by a passkey registered to the approver. These never count:
  - a console signing key, or any other delegated key;
  - a key of the identity being changed;
  - any node's key.

  This is the same rule as approve-response 0.7.

## 8. Which DID methods can carry key roles

A method must provide all of the following (VTI-KEY-170):
- a verifiable history with a change authority;
- commitment to **more than one** successor of that authority, so a routine key and a recovery key can both be committed;
- rotation without changing the identifier, plus deactivation;
- relationships the controller chooses, with the change authority in none of them;
- resolution of past versions;
- room in the document for `keyRoles` and `revoked`.

| Method | Eligible | Why |
|---|---|---|
| `did:webvh`, `did:scid:vh:1` | **yes** | Log with `updateKeys` and multi-hash `nextKeyHashes`, witnesses, past versions (VTI-KEY-173) |
| `did:webs` | **not yet** | The document is derived from the KERI KEL. Every key-state key lands in both `authentication` and `assertionMethod`, and there is no place for `keyRoles` or `revoked`. Needs an extension (the open issue below) |
| `did:key`, `did:jwk` | no | No history, no rotation |
| `did:peer` | no | No public history or past-version resolution |
| `did:web` | no | No verifiable history: whoever controls the web server controls the DID |

Whatever the chapter leaves to the method is stated in a **method profile**, and only there (VTI-KEY-172). The profiles ship with the Trust Task family (`vta/dids/_shared/0.1/method-profiles`). A request for an ineligible method is refused with `vta/dids:methodNotEligible`, and `details.missing` names the missing criteria. The refusal is a stated outcome, not a fall-through. The design stays method-neutral: a new method becomes usable by adding a profile, not by changing the role model.

## 9. Existing identities

**There is no in-place migration** (VTI-KEY-146–148; the earlier in-place migration, VTI-KEY-140–145, is withdrawn).
- A VTA, VTC or VTN DID without conformant `keyRoles` is **non-conformant**.
- A verifier must not accept an attestation artefact from it, whenever that artefact was issued (VTI-KEY-147).
- The remedy is a **new** identity created conformant. The node issues afresh from it, then deactivates the old one (VTI-KEY-148).

Why no migration: an in-place upgrade would leave the old key-of-all-trades in the history as an update authority, and credentials it signed indistinguishable from new ones. Starting fresh is the only state a verifier can check.

In this workspace, pre-role DIDs keep the `vta/webvh/dids/*` tasks until they are replaced. A key-role identity is refused on those tasks with `unsupportedVersion`, so it can only be changed through `vta/dids/*`.

## 10. Passkeys

A passkey is an `authenticator` key (VTI-KEY-154/155). It may appear only in **its holder's own** DID document, in `authentication`, bound to `authenticator`. It never appears on a VTA, VTC, VTN, service or integration DID, and the VTA refuses to enrol one there. A verifier accepts it only for a WebAuthn assertion (sign-in or step-up evidence), never for a Data Integrity proof and never for operational material, even though both kinds of key sit in `authentication`.

Today `operations/passkey_vms` enrols a passkey onto any VTA-minted did:webvh the caller administers, including the VTA's own. That changes: enrolment is allowed only on a persona identity, which is a `vta-persona` binding.

## 11. Privacy

- `keyRoles` holds only registered role names and method ids (VTI-KEY-150).
- Nothing about custody, host, operator, device or person behind a key is published, and fragment ids reveal nothing.
- A node's durable DID never lists a key that exists for one member, context or relationship. Such a key belongs to a pairwise identifier (VTI-KEY-151).
- For something only its recipient needs to believe, authenticated encryption under `messaging` is preferred to a signature, so the recipient holds no transferable proof (VTI-KEY-152).
- `attestation` rotation runs on the node's own schedule, never in step with a member joining or leaving, so the timing leaks nothing (VTI-KEY-153).

## 12. Benefits

| Before | After |
|---|---|
| Compromising the service process yields credential issuance, status-list rewrites and DID takeover | Compromising the service process yields **only traffic signing**. Credentials and the DID log need the VTA, by a request it authorizes and audits (VTI-KEY-115) |
| A leaked backup or mnemonic is a leaked identity | Backups and the seed contain **no** `attestation` or `update` key |
| Losing or compromising the VTA is permanent | **Recovery** via a key held elsewhere: one signed entry restores control and revokes what was lost |
| A verifier cannot tell which key may issue credentials | A verifier **enforces** it: role plus relationship, refuse anything else |
| Rotation is all keys at once, indistinguishable from compromise | Planned rotation with overlap, versus revocation with a compromise time; old credentials keep or lose validity correctly |
| A forged status list silently re-admits the removed | Status lists sign only under `attestation` keys the service process never holds |
| Passkeys can sit on infrastructure DIDs | Passkeys only on their holder's own identity, usable only for WebAuthn |
| One method's quirks are baked in | Method-neutral; a profile per method; ineligible methods refused with the reason |
| An approval could come from a console key | Only an approver's own key or passkey counts; quorum for the recovery commitment; revocation never waits |
| One algorithm | Proof sets (e.g. Ed25519 + ML-DSA) for a post-quantum path |

## 13. Implications and costs

**For operators:**
- **A recovery custodian is mandatory.** No key-role identity can be created until the operator supplies an external recovery key with a proof of possession (VTI-KEY-119). This is deliberate, and it is a deployment step that did not exist before: generate the key on a second machine or with a second operator, then store it and its passphrase like the mnemonic, but **separately** from the VTA.
- **Existing identities must be replaced, not upgraded.** Every VTA, VTC and VTN DID in use is pre-role. Each needs a new key-role DID, re-issuance of the credentials still in force, then deactivation of the old DID. Members, registries and relying parties have to learn the new DID.
- **Backups no longer restore everything.** After a restore, `attestation` and `update` keys are reported as lost, and the remedy is recovery with the custodian, then re-signing every status list at once and re-issuing the other credentials no later than renewal (VTI-KEY-117). Operators need to know this before they need it.
- **Changes to key roles are slower.** Previews, step-up gestures and quorums replace one-command rotation. Revocation stays one approval.
- **Plain mode is visibly weaker.** Without a secret manager or TEE, role keys are protected only by a 0600 file, and every preview says so.

**For a VTC or VTN:** the service process no longer holds a credential-signing key. Every credential becomes a signing request to the VTA. That is already the signing-oracle pattern, but it is now a requirement, and a VTA outage now blocks issuance, not just administration.

**For verifiers** (our own code, the browser extension, openvtc, registries, third parties):
- Select keys by `keyRoles` plus relationship, never by fragment.
- Refuse a credential not signed by an `attestation` key.
- Honour CID `revoked` with its compromise time.
- Re-resolve within 24 h.
- Refuse attestation artefacts from non-conformant (pre-role) DIDs once enforcement starts. This is the largest compatibility cliff in the design, and it needs a coordinated date.

**For members:** a passkey enrolled on an infrastructure DID will be refused. Persona passkeys are unaffected.

**For the code:** one new subsystem crate (`vta-key-roles`, decided 2026-10-30), a new keyspace outside backups, a new KEK per deployment kind, a preview/plan store with a sweeper, step-up bound to an operation ported from the VTC, the whole `vta/dids/*` family, and client commands. The webvh 1.0 tasks stay for pre-role identities. As a new published crate, `vta-key-roles` must be published to crates.io by hand once, and given a Trusted Publisher, before the first Release PR that contains it.

## 14. Open questions for the working group

1. **did:webs.** There are two routes:
   - (A) an extension that anchors role keys in the KEL and renders the key-state keys into no relationship (preferred);
   - (B) amend VTI-KEY-093 to tolerate key-state keys the method itself renders.

   Until one lands, did:webs is refused.
2. **did:webvh under VTA compromise.** The routine successor is in the VTA, so a compromised VTA can append an entry that drops the recovery commitment. Witness enforcement of continuity is only a SHOULD (VTI-KEY-129), and how a witness tells which hash is the recovery hash is a profile convention. Should this be a MUST for VTA, VTC and VTN identities?
3. **The deployment burden of VTI-KEY-119** (no identity without an external recovery key). It is intended; the WG should confirm.
4. **CID `revoked`** depends on generic Data Integrity verifiers honouring it.
5. **The 24-hour verifier cache cap** (VTI-KEY-134) is a proposal.
6. **The w3id registration** of `https://w3id.org/vti#keyRoles`.
7. **Registry records** (VTI-KEY-085): the registry query protocol has no member for a record's proof yet.

## 15. Where the code stands, and the plan

The survey of the current code (DID shape, update keys, seed-protected internal keys, birational X25519, all-at-once rotation, passkeys on any DID, step-up bound to an operation only in the VTC, `schemaVersion` 1–2 templates) and the 13-step build order are in [key-roles-implementation.md](key-roles-implementation.md) §1 and §3. Its decisions in §2 stand. Its open decision in §4 is now decided (§5.3 above).
