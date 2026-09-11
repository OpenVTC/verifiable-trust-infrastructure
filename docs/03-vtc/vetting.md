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

A vetter is a **member the community has named a vetter**. An admin does it
from the member's page in the admin console ("Grant vetter role"), or with
`vtc/vetting/vetters/grant/0.1` — `POST /v1/vetting/vetters` over REST, or the
same Trust Task document over DIDComm or TSP:

```json
{ "memberDid": "did:…", "validitySeconds": 31536000 }
```

The community issues the member a **vetter role credential**: an
`EndorsementCredential` with endorsement
`{ "type": "CommunityRole", "role": "vetter", "communityDid": "did:…" }`, a
`credentialStatus` on the community's revocation list, and a validity of one
year unless `validitySeconds` (one day to two years) says otherwise. It records
the grant, delivers the credential to the member, and answers with the grant:

```json
{ "endorsementId": "…", "credentialId": "urn:uuid:…",
  "validFrom": "…", "validUntil": "…" }
```

Only an admin may grant, and only to a current member. Granting again while the
member holds a live grant returns that grant. A grant is audited as
`VetterGranted`, with a `VecIssued` for the credential.

The vetter shows the credential to applicants: it answers a
`vetting/request/0.1` with an `eligibilityVp`, a presentation whose `nonce` is
the request's `id` and whose `domain` is the request's `joinDid`. The
applicant's client checks it with
`vta_sdk::vetting::eligibility::verify_eligibility_vp` — the presentation
answers its own request and holds a role credential this community signed for
that vetter — so the applicant knows before any session that the vetter's
statement will count.

`eligibleVetters.role` names the role the community's `CommunityRole` credential
carries — a bare token such as `"vetter"`: a letter, then letters, digits, `_` or
`-`, at most 128 characters. It is not an ACL role name, so a `custom:*` form is
refused.

Before it relies on the credential, the applicant's client checks it has not
been revoked with `vta_sdk::vetting::status::check_credential_status`: it
fetches the community's status list through a fetch function the client
supplies (the client owns the transport and its timeouts), verifies the list's
proof and that its issuer is the community, and reads the credential's bit —
`Active`, `Revoked`, or `Unknown` with the reason. `Unknown` is never treated
as `Active`.

To withdraw a vetter, revoke the grant like any endorsement: "Revoke vetter
role" in the console, or `DELETE /v1/credentials/endorsements/{endorsementId}`
(`vtc/endorsements/revoke/0.1`). A member's grants are revoked when they leave.
Either way the vetter's profile is deleted.

`GET /v1/vetting/vetters` lists every grant, newest first, for the console:

```json
{ "vetters": [ { "endorsementId": "…", "memberDid": "did:…", "credentialId": "urn:uuid:…",
                 "validFrom": "…", "validUntil": "…", "revoked": false, "live": true,
                 "origin": "manual",
                 "profile": { "listed": true, "displayName": "Carol M.", "country": "AT",
                              "languages": ["en", "de-AT"], "methods": ["inPerson"],
                              "eventCount": 1, "updatedAt": "…" } } ] }
```

`live` is unrevoked, unexpired and held by a current member; `origin` is
`manual` for an admin's grant and `auto` for one the sweep issued (below).

A vetter whose wallet lost the credential asks for it again with
`vtc/vetting/vetters/resend/0.1` (payload `{}`); an admin can do the same with
`POST /v1/vetting/vetters/{memberDid}/resend`. The community delivers the same
credential over `credential-exchange/issue` — nothing new is issued — and
answers `{ "credentialId": "…", "validUntil": "…" }`. A sender with no live
grant is refused with `vtc/vetting/vetters/resend:notGranted` (404 over admin
REST); a delivery that cannot be handed to the transport with `unavailable`
(503). A resend is audited as `VetterGrantResent`.

### 4. Let applicants find vetters

A vetter publishes a **profile** with `vtc/vetting/vetters/profile/0.1`, over
REST (`POST /v1/trust-tasks`), DIDComm or TSP. It replaces the whole profile:

```json
{
  "listed": true,
  "displayName": "Carol M.",
  "languages": ["en", "de-AT"],
  "location": { "country": "AT", "city": "Vienna" },
  "methods": ["inPerson", "video"],
  "acceptsDocumentation": ["passport", "nationalId", "none"],
  "availability": "Weekday evenings, Central European Time.",
  "contactHint": "Ask for a ticket at the kernel-vtc table at the meetup.",
  "events": [ { "name": "Kernel Maintainers Meetup 2026",
                "startDate": "2026-10-05", "endDate": "2026-10-07",
                "location": { "country": "AT", "city": "Vienna" } } ]
}
```

`languages`, `methods` (one to three), `acceptsDocumentation` and `events` are
required and may be empty (all but `methods`). An event lasts at most 31 days.
Only an active member holding a live vetter grant may publish; anyone else gets
`vtc/vetting/vetters/profile:notEligible`. A document older (`issuedAt`) than
the one the stored profile came from is refused with `malformedRequest`, so a
replayed copy cannot re-list a vetter who unlisted. `listed: false` keeps the
profile and removes it from listings. Publishing is audited as
`VetterProfileUpdated`; the profile is deleted — `VetterProfileDeleted` — when
the vetter's grant is revoked or they leave, and kept but unlisted while a
grant has merely expired.

Anyone the community can identify — a member, or an applicant with a DID —
finds vetters with `vtc/vetting/vetters/list/0.1`. An unidentified caller is
refused with `permissionDenied`. Every filter is optional and they combine:

| Filter | Matches |
|---|---|
| `language` | a listed tag equal to it, or starting with it and `-` (`de` matches `de-AT`), case-insensitively |
| `country` | `location.country` |
| `region`, `city` | `location.region`, `location.city`, case-insensitively |
| `method` | one of the vetter's `methods` |
| `eventFrom`, `eventTo`, `eventName` | one event, not yet ended, that overlaps the range (an open end is unbounded) and whose name contains `eventName` |
| `limit`, `cursor` | pages of 1–100 (50 by default); `cursor` is the previous page's `nextCursor`, sent with the same filters |

Only active members with a live grant and a listed profile appear, each with
its published profile (ended events left out), `vetterDid`, `grantValidUntil`
and `updatedAt` — nothing else. With an event filter the earliest matching
event comes first; otherwise vetters are ordered by `displayName` (vetters
without one last), then by DID, by code point.

A vetter hands out tickets as a QR code carrying a **ticket URI**, encoded and
decoded with `vta_sdk::vetting::ticket_uri`:

```text
vetting-ticket:?v=1&community=<pct-encoded DID>&vetter=<pct-encoded DID>&ticket=<ticketId>&secret=<base64url 32 bytes>
vetting-ticket:?v=1&community=<pct-encoded DID>&vetter=<pct-encoded DID>&code=K7QF-2M9X
```

A reader refuses an unknown `v`, a URI with both `ticket`/`secret` and `code`,
and any member that breaks the `vetting/request` patterns.

### 5. Name vetters automatically (optional)

A large community can let policy name its vetters. The `vetterEligibility`
policy purpose (Rego package `vtc.vetter_eligibility`, query
`data.vtc.vetter_eligibility.decision`) is evaluated for every active member by
a periodic sweep, with this input:

```json
{ "did": "did:…", "status": "active", "roles": ["member"], "tenureDays": 412,
  "admittedVia": "vetting", "underReview": false, "depth": 1 }
```

- `admittedVia` — `vetting` when the join request that admitted the member was
  satisfied by counted statements, else `invitation`, else `open` for any other
  join request, else `genesis` for a member not admitted through a join request.
- `underReview` — a statement that counted toward the member's admission has
  since been withdrawn.
- `depth` — `0` for a genesis member, one more than the shallowest counted
  vetter for a vetted one, `null` when unknown.

`{"effect": "allow"}` grants a member without a live grant (audited
`VetterAutoGranted`, with `VecIssued`); `{"effect": "deny"}` revokes the grants
**the sweep issued** — never an admin's. A policy that answers anything else
changes nothing and is counted as an error. The shipped default allows only
active `genesis` members who are not under review; who else is trusted to vet,
and after how long, is the community's call — upload a policy that says so
(`PUT /v1/policies`, purpose `vetterEligibility`).

The sweep is off until an admin turns it on:

```bash
curl -X PUT -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
     -d '{ "enabled": true, "sweepMinutes": 60, "validitySeconds": 31536000 }' \
     "$VTC_URL/v1/vetting/auto-grant"
```

`sweepMinutes` is 5–1440 (60 by default) and `validitySeconds` is within the
grant bounds (one year by default). `GET /v1/vetting/auto-grant` returns the
configuration and the last sweep — `{ "ranAt", "granted", "revoked", "errors" }`.
A configuration change is audited as `VetterAutoGrantConfigured` and each sweep
as `VetterAutoGrantSwept`. An admin who grants a member the sweep already named
adopts the grant: it becomes `manual`, and the sweep leaves it alone.

### 6. Brand the community (optional)

`PUT /v1/community/branding` (admin) sets how the community asks an applicant's
client to show it; `GET` reads it back:

```json
{ "displayName": "Linux Kernel", "accentColor": "#1a2b3c",
  "logoUrl": "https://kernel.example.org/logo.svg" }
```

Every member is optional; `displayName` is 1–128 characters, `accentColor`
`#rrggbb` (stored in lower case), `logoUrl` an https URL of at most 2048
characters. `join-requests/manifest/0.2` carries it as `branding` when any is
set. It is presentation only — `communityDid` identifies the community. Changes
are audited as `CommunityBrandingUpdated`.

### 7. Administer vetting from the command line

`cnm` drives the same admin REST routes. Every command needs a community-admin
session (`cnm auth login`) with a REST URL — pass `cnm --url https://<vtc>/v1 …`
when the session has none. Tables are the default; the global `--json` prints the
response instead, and `--full-display` prints DIDs and ids unshortened.

| Command | Route | Prints |
|---|---|---|
| `cnm vetting vetters list` | `GET /v1/vetting/vetters` | member, status (`live`, `revoked`, `expired`, `not member`), origin (`manual`/`auto`), valid until, endorsement id, profile summary |
| `cnm vetting vetters grant <memberDid> [--validity 180d]` | `POST /v1/vetting/vetters` | whether a grant was issued or an existing live one returned, its endorsement id, credential id and validity |
| `cnm vetting vetters revoke <endorsementId>` | `DELETE /v1/credentials/endorsements/{id}` | the revoked credential and when |
| `cnm vetting vetters resend <memberDid>` | `POST /v1/vetting/vetters/{memberDid}/resend` | the credential handed to the transport (not a delivery receipt) |
| `cnm vetting auto-grant show` | `GET /v1/vetting/auto-grant` | enabled, sweep interval, grant validity, last sweep |
| `cnm vetting auto-grant set [--enabled true] [--sweep-minutes 30] [--validity 365d]` | `PUT /v1/vetting/auto-grant` | the stored configuration |
| `cnm vetting branding show` | `GET /v1/community/branding` | display name, accent colour, logo URL |
| `cnm vetting branding set [--display-name …] [--accent-color '#1a2b3c'] [--logo-url …] [--clear logo-url]` | `PUT /v1/community/branding` | the stored branding |
| `cnm vetting revocations` | `GET /v1/vetting/revocations` | each withdrawal: when, vetter, statement, reason, review state, affected members |

Durations are `N[s|m|h|d|w]`; a grant is valid for one day to two years. `set`
reads the current value first and changes only the flags given, so
`--sweep-minutes 30` does not turn the sweep off. A refusal names the fix — an
unknown endorsement id points at `vetters list`, a resend with no live grant at
`vetters grant`, a non-member at approving their join request first.

### 8. Seed vetters from a PGP web of trust (optional)

A community with an existing OpenPGP web of trust — the Linux kernel's is the
case this was built for — can name its first vetters from it rather than one by
one:

```bash
cnm vetting bootstrap-pgp --keyring kernel-keyring.asc \
    --roots 'ABAF11C65A2970B130ABE3C479BE3E4300411886,647F28654894E3BD457199BE38DBBDC86092693E' \
    --max-depth 2 --links ./links --dry-run
```

**Inputs.**

- `--keyring` — every key that matters: the roots, the keys that certify, and
  the members' keys. Binary (`gpg --export > keyring.gpg`) or ASCII-armored;
  concatenated armored exports (`cat keys/*.asc > keyring.asc`) are fine, and a
  key exported twice is merged.
- `--roots` — the fingerprints trust starts from, as `gpg --fingerprint`
  prints them (40 hex digits; spaces allowed inside quotes). Short and long key
  ids are refused because they collide. A root must be in the keyring and not
  revoked or expired.
- `--max-depth` — how many certification hops from a root a member's key may
  be. `0` is the root keys only; `1` keys a root certified; `2` keys certified
  by those; and so on.
- `--links` — a directory of **link statements**, one per member. A statement
  ties a member's PGP key to their member DID, so the community never has to
  guess which key belongs to which member.

**Making a link.** The member signs one line with the key they want counted:

```bash
printf 'openvtc-link: %s\n' 'did:webvh:QmExample:kernel.example:alice' \
  | gpg --local-user <their-fingerprint> --digest-algo SHA256 --clearsign > alice.asc
```

and sends `alice.asc` to the admin, who collects the files in one directory. A
signing subkey is fine — the link counts for its primary key. Text around the
line is ignored; the signed text must carry exactly one `openvtc-link:` line.

**What counts.**

- A key is **usable** when a valid self-signature binds at least one user ID
  and it is neither revoked nor expired.
- Key A **certifies** key B when usable key A made a third-party certification
  of one of B's user IDs that verifies, is exportable, has not expired, is not
  dated in the future, and that A has not revoked. SHA-1 and RIPEMD-160
  certifications made after 2019-01-19 are not trusted (GnuPG's cut-off); MD5
  never is. Everything else is ignored, and the summary counts why.
- A key's **depth** is its fewest certification hops from any root.
- A **link** is trusted when it is a cleartext-signed message whose signature
  verifies with exactly one usable keyring key (the primary or a bound signing
  subkey), using SHA-256 or better. A DID claimed by more than one key, or a key
  linking more than one DID, is ambiguous: every link involved is refused.

**The plan.** `--dry-run` prints a summary (keys, certifications counted and
ignored, keys within reach) and one row per link:

| Column | |
|---|---|
| Member DID | the DID the statement links |
| Key | the key's id (`--full-display`: the fingerprint) |
| Primary User ID | as the key states it |
| Depth, Certification Path | hops from the nearest root, and the keys on the way |
| Action | `grant`; `already granted`; `too far` (unreachable, or beyond `--max-depth`); `not a member` (they must join first); `invalid link` (with the reason below the table) |

Check the plan, then run the same command without `--dry-run`. Every `grant`
row is granted (with `--validity` when given, one year otherwise) and the table
is printed again with each result. Grants are audited as any admin grant is. A
failed grant is reported and the rest continue; the command exits non-zero.
Running it again is safe: members already holding a live grant are skipped.
`--json` prints the summary and rows for a script.

The bootstrap names vetters once; it does not keep the web of trust in sync. A
key revoked later does not revoke the grant — revoke it with
`cnm vetting vetters revoke`.

## What the community checks at submit

For every identity-vetting statement in the join presentation
(`vtc-service/src/vetting/mod.rs`):

| Check | Not counted as |
|---|---|
| Proof by the issuer, type, bounded validity, strict endorsement body | `unverified` |
| Subject is the proven holder of the presentation | `subject-not-applicant` |
| Endorsement type is the criterion's `statementType` | `wrong-statement-type` |
| Issuer is a current member, admitted before issuing, holding a vetter grant recorded by the statement's `validFrom`, unexpired then, and not revoked | `issuer-not-vetter` |
| Statement is for this community | `wrong-community` |
| Method accepted; required claims verified; within `maxStatementAge`; documentation within any floor | `method-not-accepted`, `claim-not-verified`, `too-old`, `documentation-not-accepted` |
| One statement per vetter (the most recent) | `same-vetter` |

The criterion applied is the one whose current `requirementsDigest` the
applicant sent in `extensions.requirementsDigest`, otherwise the first vetting
criterion.

The facts are recorded beside the join request, and an admin reads them with
`GET /v1/join-requests/{id}/vetting` — the same facts in lowerCamelCase, each
statement with `withdrawnNow` (withdrawn since the decision), and `recordedAt`.
`vetting` is absent when no vetting criterion applied.

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

## Withdrawing a statement

A vetter withdraws a statement they issued with
`vtc/vetting/revoke-statement/0.1`:

```json
{ "statementId": "urn:uuid:…", "statementDigestMultibase": "z…", "reason": "mistake" }
```

The sender must be a member. The notice is keyed by the **authenticated sender**,
the statement id and the statement digest (compared on its decoded bytes), and
counts only against a presented statement with all three — so a notice can
only ever withdraw a statement its sender signed. A withdrawn statement reads as
`revoked` and fails with `revoked` in `input.evidence.vetting.statements`.
Repeating a notice returns the original `recordedAt`. The first notice is
audited as `VettingStatementRevoked`, and notices are part of a backup.

`GET /v1/vetting/revocations` lists every notice, newest first, with the
approved join requests that counted the statement (`affectedJoinRequests`), the
applicants among them who are still members (`affectedMembers`), and a
`reviewState` of `needsReview` when there are any, else `noAdmission`. A member
admitted on a withdrawn statement also reads `underReview: true` to the
automatic-grant policy.

## Current limits

- Statements are counted on the VP-submit path. The credential-exchange
  `present` path does not count them yet.
- A grant's revocation is read as it stands at submit, not as it stood when a
  statement was signed: withdrawing a vetter stops every statement they signed
  counting, including those signed while the grant stood. That errs toward not
  admitting.
- The applicant-side eligibility check and the status check are separate calls
  (`eligibility::verify_eligibility_vp`, then `status::check_credential_status`
  on its `credential_status()`); a revoked grant is always caught at the
  community regardless.
- Delivering the credential to the member at grant is best effort. The
  community's record is what counts statements, so a vetter whose wallet missed
  it is still counted, and can ask for it again. A grant recorded before grant
  credentials were kept cannot be resent (`notGranted`); revoke and grant again.
- `needsReview` on a withdrawal notice is advisory: nothing records that an
  admin reviewed the admission, and a withdrawal does not by itself suspend the
  membership.
- A listing is paged by position: a profile published or withdrawn between two
  pages can shift one entry across the page boundary.
- A member admitted through a join request whose vetting facts were not
  recorded (decided before recording, or a recording failure, which is logged)
  reads as `open` to the automatic-grant policy.
- Distinct vetters are distinct member DIDs; one person holding two member DIDs
  would count twice.
- Withdrawal notices are kept indefinitely — there is no retention sweep yet.
- A withdrawal after admission is recorded and audited but does not yet open a
  review of the membership it helped grant.
- `requirementsGrace` is not yet applied: an application gathered against
  superseded requirements is evaluated under the current ones, with
  `applicant_digest_matches: false` for a policy to act on.
