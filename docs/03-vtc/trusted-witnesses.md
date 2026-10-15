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

A patch replaces the whole list, and `[]` empties it. It takes effect on the
next VWC the VTC reads, with no reload. `config/show/0.1` reports the list in
force and where it came from (`default`, `toml` or `db`).

The VTC refuses a list that is not an array of `{ "did", "label" }` objects, that
names something other than a bare DID (a `#key` fragment, a path), that lists a
DID twice, that gives a blank label or one over 128 characters, or that names
the community's own DID — a community never witnesses (VTI-KEY-007). A stored
value that cannot be read is treated as trusting no witness.

### Who may change it, and how it is recorded

Changing the list takes `vtc.config.admin`, the capability every `config/patch`
takes. It does not go through the action list. A listed witness confers no
authority (VTI-VTC-022). It decides which evidence counts toward decisions that
other settings already make: a join criterion (`vtc.surface.admin`) and the
personhood policy (`vtc.policy.admin`), neither of which needs a second
administrator's consent. A criterion with `credentialIssuers: any` admits more
than any witness list can, so a stricter gate on the list would close nothing.

Every change is audited as a `ConfigChanged` row that carries the old and new
lists and the signer. The key is marked as one that alters trust semantics, and
each change is also logged at `warn` as such (VTI-CMP-090, VTI-CMP-092). The
audit trail is what reconstructs the list that governed a past decision
(VTI-CMP-091).

## Outcome evidence

A VWC cites the witnessing session it came from: `taskContext` names the
`witness/session/0.1` document, and `taskDigestMultibase` is its digest. The
citation does not show that the session finished. A session that was cancelled
cites the same way. The Trust Task framework (*Evidence That a Cited Exchange
Completed*) therefore asks for **outcome evidence**: the initiating document and
the terminal success document. For witnessing, those are the `witness/session`
document and the witness's `witness/session/submit/0.1#response`.

The member presents both beside the VWC, in the
`vtc/members/personhood/assert/0.1` payload:

```json
{
  "did": "did:key:z6Mk…",
  "presentation": { "…": "the VP carrying the VWC" },
  "ext": {
    "org.openvtc.witness": {
      "outcomeEvidence": [
        { "session": { "…": "the witness/session document" },
          "outcome": { "…": "the witness's submit #response" } }
      ]
    }
  }
}
```

This is the `evidence` object that `vta/witness/accept/0.1` returns, so a client
passes on what its VTA gave it. At most 16 entries are accepted. Any other
member of the `org.openvtc.witness` namespace is refused as `malformedRequest`.

The VTC pairs an entry with the VWC whose `taskContext` is the entry's session
`id`, and checks:

1. the VWC's `taskDigestMultibase` is the digest of the session document;
2. the response is on the session's thread (`threadId` equals the session's
   `threadId`, or its `id` when it has none);
3. the response is a `witness/session/submit/0.1#response`;
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
- **The carriage is an OpenVTC extension.** Like the witness's member link, it
  rides `ext` because no task defines a member for it. Other implementations
  will not send it, and the namespace is closed so the carriage can be replaced
  once it is standardised upstream.
- **There are no per-witness constraints.** Nothing yet limits a witness to
  some purposes or criteria. A community that wants one witness for personhood
  and another for joining says so in its policy, which may refuse a witness the
  list admits but never accept one it refuses.
