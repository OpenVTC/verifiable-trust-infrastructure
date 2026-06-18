# Handoff prompt for the openvtc tool — join is now a Trust Task flow

Give the prompt below to the openvtc tool's agent. It describes the new
join-request wire contract over **DIDComm** (the preferred transport, now
converted). REST conversion is in progress and will mirror the same document
shapes.

---

**Subject: The VTC join ceremony is now a Trust Task document flow — update your client**

The VTC no longer accepts bare join-request bodies or reply with DIDComm
problem-reports. Every join verb is now a **Trust Task document**
(`trust_tasks_rs::TrustTask`). Update your DIDComm join client as follows.

**1. URIs changed (now framework-canonical, with a `/spec/` segment).** Use:
- `https://trusttasks.org/openvtc/vtc/spec/join-requests/submit/1.0` — submit (the `request` verb)
- `https://trusttasks.org/openvtc/vtc/spec/join-requests/accept/1.0` — accept (reciprocal VMC)
- `https://trusttasks.org/openvtc/vtc/spec/join-requests/manifest/1.0` — manifest (public discovery)
- `https://trusttasks.org/openvtc/vtc/spec/join-requests/status/1.0` — status (applicant poll)

The old flat URIs (`…/openvtc/vtc/join-requests/submit/1.0`, no `/spec/`) are gone — they don't parse as a `TypeUri`.

**2. Send a TrustTask document, not a bare body.** Over DIDComm: set the message `type` to the verb URI, and put the **TrustTask document** in the message body. The document fields:
- `type`: the same verb URI.
- `id`: a fresh `urn:uuid:…`.
- `issuer`: your holder `did:key`. Over DIDComm this must equal your authcrypt sender DID (the VTC binds them); over DIDComm you do **not** need a document `proof` — the authcrypt envelope authenticates you.
- `recipient`: the VTC's DID. **Required** — the VTC rejects a document addressed to anyone else (`wrongRecipient`). This replaces the old `audience` field.
- `issuedAt` / `expiresAt`: set `expiresAt` to a near-future time. An expired document is rejected (`expired`). This replaces the old `created` freshness field.
- `payload`: the verb's body — for submit: `{ "vp": …, "registryConsent": bool, "extensions": … }` (the applicant DID is the `issuer`, no longer a payload field).

**3. Success reply is a `#response` document carrying a Verdict.** Type = the verb URI + `#response` (e.g. `…/submit/1.0#response`), threaded via `thid` to your request id. The submit payload is a Verdict:
```json
{ "requestId": "<uuid>", "verdict": { "effect": "allow|refer|requestMore|deny", "with": { … } } }
```
Branch on `verdict.effect`:
- `allow` — auto-admitted. `with.role`, and (over REST) `with.vmc` / `with.roleVec`. Over DIDComm the credentials arrive in a follow-up message.
- `refer` — queued for an admin decision. `with.queue`, `with.reason`. Poll `status` (or await an admin push).
- `requestMore` — present more evidence. `with.needs`, `with.presentationDefinition`.
- `deny` — the policy refused a *verified* request. `with.code`, `with.reason`.

**4. Failure is a `trust-task-error` document — NOT a problem-report, NOT a `deny` verdict.** When the request never reaches the policy (invalid VIC, expired, malformed, duplicate, wrong recipient), the reply is a framework error document (its `type` contains `trust-task-error`) with payload:
```json
{ "code": "<framework code>", "message": "<detail>" }
```
Key codes:
- `permissionDenied` — **invalid VIC** (wrong subject binding, expired, bad signature, revoked, missing credentialStatus), or any holder-auth failure. This is the invalid-VIC reject you asked about.
- `malformedRequest` — the payload didn't parse / the body isn't a Trust Task document.
- `taskFailed` — e.g. an open join request already exists for you (duplicate).
- `expired` / `wrongRecipient` — you set `expiresAt` in the past / `recipient` ≠ the VTC DID.

**What your client must do:**
- Branch on the reply **document `type`** first: `#response` (success → read the Verdict) vs `trust-task-error` (failure → read `code`). Do not look for a DIDComm `report-problem` message — join no longer emits one.
- Within a Verdict, branch on `verdict.effect`; treat `deny` as a *policy* refusal (your request was valid but refused), distinct from a `trust-task-error` (your request was rejected before policy).
- Match errors on the framework `code`, not on the human-readable `message`.
- Correlate every reply to its request via `thid`.
- On `permissionDenied` for an invalid VIC, do **not** auto-retry the same VIC — obtain a fresh/valid invitation first.
- Always set the document `recipient` to the VTC DID and a near-future `expiresAt`.

Please confirm your client (a) sends TrustTask documents with `recipient` + `expiresAt`, (b) branches on reply document `type` (`#response` vs `trust-task-error`), (c) reads the Verdict `effect` on success and the framework `code` on error, and (d) no longer expects DIDComm problem-reports for join.
