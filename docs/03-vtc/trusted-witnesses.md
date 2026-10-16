# Trusted witnesses

A **witness** is an independent party that watches one side of an exchange
present its relationship credential, and then issues a Verifiable Witness
Credential (VWC) saying so: a DTG `StatementCredential` under
`https://registry.trustoverip.org/dtg/vsc/witnessed/1`. Witnesses run as their
own host service ([`vti-witness`](../06-witness/README.md)), and a member's VTA
can be the witnessed party for them
([the VTA as a witnessed party](../02-vta/witness-party.md)).

Anyone can run a witness, so anyone can issue a VWC. A VWC that verifies shows
who signed it and that it was not altered. It does not show that this community
should believe it (VTI-CMP-030). So each community keeps a **list of the
witnesses it trusts**, and a VWC counts here only when its issuer is on it.

## What the list does

| | |
|---|---|
| **Default** | Empty. An empty list trusts **no** witness: no VWC counts until the community names one. |
| **Effect** | A VWC from a witness that is not listed counts for nothing, on every path that reads one. The VTC refuses it before any policy runs (`witness_binding.state = "untrustedWitness"`), so no policy can accept it. |
| **Where it applies** | The personhood assertion ([Personhood](personhood-and-graph.md#witness-credentials)); the ceremony facts of a join presentation; and the credentials a [join criterion](join-criteria.md)'s query can be met by. |
| **Entries** | A DID, compared exactly with the VWC's `issuer`, and an optional label. At most 64. |

A listed witness is necessary, not sufficient. A VWC also counts only when:

1. **The witnessing is shown to have completed.** The outcome evidence of the
   session the VWC cites travels with it, and pairs with it (below). Without it
   the VWC is `noOutcomeEvidence`; with evidence that does not pair it is
   `outcomeInvalid` (VTI-CMP-022, VTI-CMP-023).
2. **It names an edge this community holds.** Its digest recomputes to a
   relationship credential stored here (`bound`). The other digest states are
   in [Personhood](personhood-and-graph.md#witness-credentials).

The default personhood policy accepts only `bound`, which now means all three:
a trusted witness, a completed session, and a held edge.

## Setting the list

In `config.toml`:

```toml
[witnesses]
trusted = [
  { did = "did:webvh:QmScid…:witness.independent.example:a", label = "Independent witness A" },
  { did = "did:webvh:QmScid…:witness.other.example" },
]
```

Or at runtime, as the configuration key `witnesses.trusted`, through the signed
`config/patch/0.1` document (and `vtc/config/import/0.1`). The value is the same
list as JSON:

```json
{ "overrides": { "witnesses.trusted": [
  { "did": "did:webvh:QmScid…:witness.independent.example:a", "label": "Independent witness A" }
] } }
```

A patch replaces the whole list, and `[]` empties it. Once it is applied — which
takes other administrators' approval, below — it takes effect on the next VWC
the VTC reads, with no reload. `config/show/0.1` reports the list in force and
where it came from (`default`, `toml` or `db`).

The VTC refuses a list that is not an array of `{ "did", "label" }` objects, that
names something other than a bare DID (a `#key` fragment, a path), that lists a
DID twice, that gives a blank label or one over 128 characters, or that names
the community's own DID — a community never witnesses (VTI-KEY-007). A stored
value that cannot be read is treated as trusting no witness.

### Who may change it, and how it is recorded

Changing which witnesses a community trusts is a major trust change, so no
administrator makes it alone. Any runtime change to the list — adding a witness,
removing one, changing a label — goes through the
[administrator action list](admin-access.md):

1. The requester holds `vtc.config.admin` and sends the `config/patch` (or the
   confirming `vtc/config/import`).
2. The VTC asks for the requester's passkey gesture (or step-up approver), bound
   to that one document.
3. The patch is **parked** as an action of kind `config.witnesses.change`, and
   the requester is answered `202` with a `trust-task-next-step` naming it. The
   list is unchanged.
4. The community's other holders of `vtc.config.admin` (anyone whose approve
   scope reaches it, such as a least-privilege `approver`) see the list as it is
   and as it would be, and decide with `task-consent/decision`. The requester
   never approves, and one decline closes the action.
5. The approval that reaches the consent threshold applies the patch, after
   every check is re-run against the community as it is then. If the list
   changed in the meantime, the action is void and nothing is written.

Removing a witness parks too. It narrows what counts, but it can also take away
the evidence members' personhood rests on, and one administrator should not
decide that alone either. Reordering the same entries is not a change.

A patch that changes the list and also lowers the consent threshold is refused:
each needs its own consent, so send them as two patches.

In **single-administrator mode** (`[acl] single_admin_mode`, VTI-APV-022) there
is nobody else to ask. The requester's gesture bound to the patch stands in for
the consent, the change applies at once, and the waiver is audited at
`Critical` and shown in the console banner, as every other consent the mode
waives.

The rule implements VTI-CMP-090: a configuration change that alters trust
semantics attracts the same review as a code change, and for a community that
review is another administrator's. VTI-APV-023 states it for this list and for
what it feeds — the [join criteria](join-criteria.md#who-may-change-them) and
the personhood policy ([personhood-and-graph.md](personhood-and-graph.md)) —
both of which park the same way. Editing `[witnesses]` in `config.toml` is the
host operator's change, made outside the running VTC, like every other
host-only setting.

Every applied change is audited as a `ConfigChanged` row that carries the old and new
lists and the signer. The key is marked as one that alters trust semantics, and
each change is also logged at `warn` as such (VTI-CMP-090, VTI-CMP-092). The
audit trail is what reconstructs the list that governed a past decision
(VTI-CMP-091).

## Outcome evidence

A VWC cites the witnessing session it came from: `taskContext` names the
`witness/session` document, and `taskDigestMultibase` is its digest. The
citation does not show that the session finished. A session that was cancelled
cites the same way. The Trust Task framework (*Evidence That a Cited Exchange
Completed*) therefore asks for **outcome evidence**: the initiating document and
the terminal success document. For witnessing, those are the `witness/session`
document and the witness's `witness/session/submit#response`, at the version
the session was opened at.

The member presents both beside the VWC, in the
`vtc/members/personhood/assert/0.2` payload's own `outcomeEvidence`:

```json
{
  "did": "did:key:z6Mk…",
  "presentation": { "…": "the VP carrying the VWC" },
  "outcomeEvidence": [
    { "session": { "…": "the witness/session document" },
      "outcome": { "…": "the witness's submit #response" } }
  ]
}
```

This is the `evidence` object that `vta/witness/accept/0.2` returns, so a client
passes on what its VTA gave it, exactly as stored. Between 1 and 16 entries are
accepted (omit the member when no VWC is to count); anything else is
`malformedRequest`. An entry that pairs with no VWC in the presentation is
ignored. Only `assert/0.2` is served: 0.1 had no member for the evidence, and the
`ext["org.openvtc.witness"]` stop-gap that carried it is retired. The member sends
only the VWCs, and the evidence, it chose to present.

The VTC pairs an entry with the VWC whose `taskContext` is the entry's session
`id`, and checks:

1. the VWC's `taskDigestMultibase` is the digest of the session document;
2. the response is on the session's thread (`threadId` equals the session's
   `threadId`, or its `id` when it has none);
3. the response is the type the session document's own version declares —
   `witness/session/submit/0.2#response` for a `witness/session/0.2`,
   `/0.1#response` for a `witness/session/0.1`, never the other;
4. the response's proof verifies under the session's `recipient`, and that
   recipient is the VWC's issuer;
5. the session was opened by, and the response addressed to, the VWC's subject;
6. the response's `vwcDigestMultibase` is the digest of the VWC it delivers,
   proof included, and that VWC is the one presented.

The VTC never stores the evidence, and never treats a VWC as evidence that the
witnessing completed without it.

**What is not built yet:**

- **The join paths have no carriage for outcome evidence.** A join submission, a
  supplement and a credential-exchange presentation carry none. On those paths a
  VWC from a trusted witness is `noOutcomeEvidence`, so it meets no criterion.
- **There are no per-witness constraints.** Nothing yet limits a witness to
  some purposes or criteria. A community that wants one witness for personhood
  and another for joining says so in its policy, which may refuse a witness the
  list admits but never accept one it refuses.
