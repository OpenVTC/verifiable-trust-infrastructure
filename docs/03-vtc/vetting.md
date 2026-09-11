# Peer identity vetting

A community can require that an applicant be **vetted by existing members**
before joining: each vetter checks who the applicant is and signs a
**Vetting Statement**, and the applicant presents enough of them in its join
presentation. This replaces a web of trust with evidence the community can
count, without publishing who vouched for whom.

Design: OpenVTC `docs/design/vetting-process.md`. Wire types and verification:
`vta_sdk::protocols::vetting` and `vta_sdk::vetting`.

## Setting it up

### 1. Register the statement type

Statements are DTG `EndorsementCredential`s whose `endorsement.type` is
`https://firstperson.network/endorsements/identity-vetting/0.1`. Register it so
criteria may count it:

```json
{
  "type": "https://trusttasks.org/spec/vtc/endorsement-types/register/0.1",
  "payload": {
    "typeUri": "https://firstperson.network/endorsements/identity-vetting/0.1",
    "description": "A member verified this person's identity"
  }
}
```

### 2. Say what you require

Add a `vetting` object to an Accepts criterion (`POST /v1/schemas/accepts`).
Every number is **your** policy — there are no defaults:

```json
{
  "id": "kernel-developer",
  "description": "Two vetters, at least one in person",
  "query": { "credentials": [ { "id": "vetting", "format": "ldp_vc",
             "meta": { "type_values": ["EndorsementCredential"] } } ] },
  "vetting": {
    "version": "0.1",
    "statementType": "https://firstperson.network/endorsements/identity-vetting/0.1",
    "minStatements": 2,
    "minByMethod": { "inPerson": 1 },
    "acceptedMethods": ["inPerson", "video", "priorAcquaintance"],
    "requiredClaims": ["name.legal"],
    "maxStatementAge": "P120D",
    "eligibleVetters": { "role": "vetter" },
    "independence": {
      "maxByDeclaredRelationship": { "family": 0, "sameEmployer": 1 },
      "requireConsistentIdentityCommitment": true
    }
  }
}
```

The route refuses requirements no applicant could satisfy (`minStatements: 0`,
a method floor on a method you do not accept, a month-based duration) and a
`statementType` that is not registered.

What documentation a vetter accepts is **the vetter's decision**. Set
`acceptedDocumentClasses` only if the community needs a floor; a
`priorAcquaintance` statement with no documentation is exempt from it.

Applicants read the requirements from `vtc/join-requests/manifest/0.2`, which
adds `vetting` and a `requirementsDigest` to each criterion. `manifest/0.1` is
unchanged.

### 3. Name your vetters

A vetter is a **member holding the role `eligibleVetters.role` names**. For
`"vetter"`, grant the custom role `custom:vetter` through the usual ACL role
change. `"custom:vetter"` in the requirements is accepted too, as are the
standard role names.

## What the community checks at submit

For every identity-vetting statement in the join presentation
(`vtc-service/src/vetting/mod.rs`):

| Check | Not counted as |
|---|---|
| Proof by the issuer, type, bounded validity, strict endorsement body | `unverified` |
| Subject is the proven holder of the presentation | `subject-not-applicant` |
| Endorsement type is the criterion's `statementType` | `wrong-statement-type` |
| Issuer is a current member with the vetter role, who had joined before issuing, with an unexpired ACL entry | `issuer-not-vetter` |
| Statement is for this community | `wrong-community` |
| Method accepted; required claims verified; within `maxStatementAge`; documentation within any floor | `method-not-accepted`, `claim-not-verified`, `too-old`, `documentation-not-accepted` |
| One statement per vetter (the most recent) | `same-vetter` |

The criterion applied is the one whose current `requirementsDigest` the
applicant sent in `extensions.requirementsDigest`, otherwise the first vetting
criterion.

The count becomes `input.evidence.vetting` for the join policy:

```json
{
  "criterion_id": "kernel-developer",
  "requirements_digest": "z…",
  "applicant_digest_matches": true,
  "statements": [ { "id": "urn:uuid:…", "issuer": "did:…", "verified": true,
                    "eligible": true, "revoked": false, "method": "video",
                    "declared_relationship": "none", "counted": true, "failures": [] } ],
  "distinct_counted_vetters": 2,
  "by_method": { "inPerson": 1, "video": 1 },
  "commitments_consistent": true,
  "independence_ok": true,
  "invitation_required": false,
  "satisfied": true,
  "needs": []
}
```

## What the default policy decides

When `input.evidence.vetting` is present, admission waits on it — neither an
invitation nor a trusted credential bypasses it:

| Facts | Verdict |
|---|---|
| Statements carry different identity commitments | `refer` to `vetting-review` |
| Something still missing | `request_more`, needs `["vetting"]` |
| Enough, but a relationship cap is exceeded | `refer` to `vetting-review` |
| Met, but `invitation: required` and none presented | `request_more`, needs `["vetting:invitation"]` |
| Met, with a valid invitation | `allow` at the invited role |
| Met | `allow` as `member` |

A `request_more` whose needs contain `vetting` is expanded by the host into the
precise shortfall — `vetting:statements:<n>`, `vetting:method:<method>:<n>` — so
a policy authored in the visual editor, whose `with` is static, still tells the
applicant exactly what to gather. The conditions are available in the editor
under the same names.

Without vetting facts the default behaves exactly as before.

## Current limits

- Statements are counted on the VP-submit path. The credential-exchange
  `present` path does not count them yet.
- "Held the vetter role when issuing" is approximated by "holds it now and had
  joined by then" — the ACL keeps no role history, so a demoted vetter's
  statements stop counting.
- Distinct vetters are distinct member DIDs; one person holding two member DIDs
  would count twice.
- Statement withdrawal (`vtc/vetting/revoke-statement/0.1`) is recorded by the
  next change in this series; until then `revoked` is always `false`.
- `requirementsGrace` is not yet applied: an application gathered against
  superseded requirements is evaluated under the current ones, with
  `applicant_digest_matches: false` for a policy to act on.
