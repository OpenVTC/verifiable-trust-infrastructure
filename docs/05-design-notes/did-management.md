# DID management — one question, asked once, whatever the method

**Status:** decided 2026-11-17. Specified in dtgwg-trust-tasks-tf
(`vta/dids/{list,get,methods/list}/0.1`, `vta/dids/_shared/0.2`,
`vta/contexts/update-did/1.2`); implemented here in the order of §6.

## 1. The problem

A VTA holds DIDs of several methods — `did:webvh`, `did:scid:vh:1` (a view of a
webvh log), `did:webs` (a KERI AID), and `did:key` minted for holders,
integrations and context identities — and every one of them was reachable only
through a family named after its method. So a question that does not depend on
the method — *which DIDs does this agent hold in this context?* — had to be
asked once per method, by every client, and each client asked only the methods
it knew about. When a VTA's identities were all `did:webs`, the wallet's persona
picker, the console's DIDs pane and `pnm did-mgmt dids list` all reported none.
A fourth method would have added a fourth question to every client.

Inside the VTA the same shape repeated: about ten places chose a code path by
the DID's prefix, each with its own list of methods, and the two families had
drifted on rules that are not about the method at all (§4).

## 2. The split

**A question whose answer means the same for every method is asked once,
method-neutrally. An operation whose meaning differs by method stays in its
method's family.**

| Method-neutral (`vta/dids/*`) | Per method (`vta/webvh/*`, `vta/webs/*`) |
|---|---|
| `list/0.1`, `get/0.1` — the DIDs the caller may see, as one `DidSummary` record | `create` (the inputs differ: a webvh path mode, a KERI slot) |
| `methods/list/0.1` — which methods this VTA holds, lists and creates, and the tasks that serve each | `update`, `rotate-keys`, `realign-keys`, `register-with-server`, `delete` |
| `vta/contexts/update-did/1.2` — a context's DID, which must be one the VTA holds | the log or KEL (`get` with `includeLog`, `get` with the stream) |
| | hosting servers, agent names |

`vta/webvh/dids/list/1.0` and `vta/webs/dids/list/0.1` are **retired**,
superseded by `vta/dids/list`. Nothing is deployed, so the VTA, `pnm` and the
wallet cut over together; there is no window in which both are served.

`vta/dids` was already the method-neutral family — the key-role tasks
(levels 2 and 3) live there with per-method **profiles**. `list`, `get` and
`methods/list` are its first tasks that cover **every** identity, level 1
included; `_shared/0.2` scopes §3.1's `notKeyRoleIdentity` refusal to the
key-role tasks.

### The record

`DidSummary` carries what every method has: `did` (as presented), `method`,
`contextId`, `class` (absent where none was recorded), `level`, `primary`,
`deactivated`, `serverId`, `label`, `signingKeyId`, `keyAgreementKeyId`,
`alsoKnownAs`, `createdAt`, `updatedAt` — and `methodDetails`, an object keyed by
method name whose member each method profile defines (webvh: `scid`,
`portable`, `logEntryCount`, `mnemonic`; webs: `aid`, `sequenceNumber`, `slot`,
`keriCesrUrl`). A new method adds a profile, not a schema version.

`signingKeyId` is there because three clients were deriving it by resolving the
DID's document or scanning key ids by prefix: the VTA knows it, so it says it.

A `did:scid` is one row: the presented form in `did`, the webvh form in
`alsoKnownAs`. A `did:key` is listed when an active key record's id is
`did:key:<mb>#<mb>` — how `vta_keys::derive_and_store_did_key` writes it — in
that key's context. `did:peer` is not listed: the VTA keeps no record of one
(its secrets go into a sealed bundle), and `methods/list` says so, so a client
knows the list is not every identifier the VTA ever minted.

## 3. Engines

A `DidEngine` (`vta-service/src/operations/dids/`) is what holds and writes
DIDs of one kind, keyed by **how the authority is kept**, not by the DID
string's prefix: the webvh log engine serves `did:webvh` and `did:scid:vh:1`;
the KERI engine serves `did:webs`; the key engine serves `did:key`.

```rust
trait DidEngine {
    fn methods(&self) -> &'static [&'static str];
    fn owns(&self, did: &str) -> bool;
    async fn list(&self, filter, auth) -> Vec<DidSummary>;
    async fn get(&self, did) -> Option<DidSummary>;
    async fn own_document(&self, did) -> Document;
    async fn context_dids(&self, context) -> Vec<String>;
    async fn delete_for_context(&self, did, …);
    fn info(&self, config) -> MethodInfo;
}
```

`DidEngines` is built once at startup from the compiled features and the
runtime configuration. Every place that used to branch on a prefix asks
`engines.for_did(did)` instead. Per-method task handlers keep their own
operations; the engine is the seam for what is common.

The key-roles plan's `MethodProfile` ([key-roles-implementation.md](key-roles-implementation.md)
step 1) is the eligibility half of the same idea. It is added to the engine
(`fn profile()`) rather than kept as a second registry of methods.

## 4. One rule each, whatever the method

The review found the two families answering the same question differently.
Each is now one rule, in one place:

| Question | Was | Now |
|---|---|---|
| A DID in a context the caller cannot reach (get, update, rotate, realign, delete) | webvh: Forbidden; webs: NotFound | NotFound — existence is not disclosed |
| A list filtered to a context the caller cannot reach | webvh: empty; webs: Forbidden | An empty page (the registry's list rule) |
| May this DID be its context's DID? | webs create: class and node-identity checks; webvh create and `update-did`: none | One guard (`operations/dids/primary.rs`) for every create, provisioning and `update-did/1.2`, which also refuses a DID the VTA does not hold (`notHeld`) |
| Deleting a context | webvh DIDs deleted with host clean-up; webs rows purged locally, host slots left; the preview counted webvh only | Every engine's DIDs, through `delete_for_context`, counted in the preview |
| Host reconcile, retire-orphan, server remove | Compared the host against webvh records only — a webs slot looked like an orphan | Every engine's records |
| Deleting a context's DID | webvh refused; webs did not | Both refuse |

## 5. Deliberately not changed here

- **`setPrimary` defaults.** `vta/webvh/dids/create/1.2` defaults it to true and
  `vta/webs/dids/create/0.2` to false. Those are wire semantics; changing either
  needs a new create version. The guard above makes the difference safe — a
  default can no longer replace a node's own identity — but not uniform.
- **Deactivate versus delete.** A webvh delete removes the DID; a webs delete
  deactivates the AID and keeps the record. That follows the methods
  (a KEL can be ended, a webvh log can be deactivated too). Whether webvh should
  deactivate rather than delete is its own decision.
- **Listing `did:peer`.** It needs the VTA to keep a record it deliberately
  does not.

## 6. Order of work

| # | Where | What |
|---|---|---|
| 1 | VTI | This note. |
| 2 | dtgwg-trust-tasks-tf | `vta/dids/_shared/0.2`, `list`/`get`/`methods/list` 0.1, `vta/contexts/update-did/1.2`; retire the two per-method lists and `update-did` 1.0/1.1. |
| 3a | VTI | `DidEngine` and `DidEngines`; every prefix dispatch moved onto them. No wire change. |
| 3b | VTI | §4's rules. |
| 3c | VTI | The method-neutral tasks served; the retired ones removed. |
| 3d | VTI | `vta-sdk` `client/dids.rs`; `pnm dids {list,get,methods}`; `pnm`'s address book, server-delete dependents and context reprovision on the method-neutral list; `pnm contexts update --did` through `update-did`. |
| 4 | pnm-browser-plugin | The wallet and console on `vta/dids/*`; one DIDs table with a method column. |
