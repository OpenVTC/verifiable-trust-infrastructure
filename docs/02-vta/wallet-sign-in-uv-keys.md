# Wallet sign-in: the device's user-verification key

A wallet signs a member in to a community with two documents the VTA signs as
the member's persona through `vault/sign-trust-task`: `auth/oob/identify`
("I am this DID"), signed unattended, and `auth/oob/grant` ("let this browser
key act as me at this origin until `notAfter`"), signed **only** with the
device's user verification. The gate is
`vta-service/src/operations/vault/oob_sign_in.rs`.

The user verification comes from the device's **UV key**, enrolled with the
`org.openvtc.uv-key` extension on `device/register` or `device/heartbeat` and
recorded on the device's own ACL row. Every grant approval arrives under
`ext["org.openvtc.uv-consent"]` on the `vault/sign-trust-task` request. The
grant digest `D` is SHA-256 over the RFC 8785 form of the unsigned grant, as a
multibase multihash (`grant_digest`); a decision approves it with
`payloadDigest == challenge == D`.

## The five kinds

| Kind | Who holds it | Approval (`org.openvtc.uv-consent`) | What makes it user verification |
|---|---|---|---|
| `hardwareKey` | phone (Secure Enclave / StrongBox) | `{ decision }`, signed by the UV key | the OS uses the key only after a biometric |
| `prfSealedKey` | browser plugin, PRF passkey | `{ decision }`, signed by the UV key | the key is unsealed only by a PRF output the authenticator yields after UV |
| `webauthn` | a WebAuthn client | `{ decision }`, signed by the transport key, with a WebAuthn assertion as `evidence` | the assertion's UV flag |
| `vtaPin` | browser plugin, no PRF passkey | `{ decision, pinProof }`, decision signed by the transport key, no evidence | the PIN, checked by the VTA against a guess limit |
| `remoteApprover` | browser plugin, approving on the phone | `{ "remote": true }` | the phone's own biometric-gated approval |

Each kind is recorded as itself — in the binding, in the summary `device/list`
shows and in the audit row of every grant (`uvDecision.kind`) — so policy and
an auditor can tell a PIN from a passkey from a phone.

## `vtaPin` — a PIN the VTA checks

For browsers with no usable PRF authenticator (Linux Chromium without a
security key, password managers that offer passkeys without PRF).

**Enrolment.**

```json
{
  "kind": "vtaPin",
  "salt": "<base64url, 16..64 bytes>",
  "iterations": 600000,
  "verifier": "<base64url, exactly 32 bytes>",
  "hardwareBacked": false,
  "biometricGated": false
}
```

The browser derives `K = PBKDF2-HMAC-SHA256(utf8(NFC(pin)), salt, iterations,
32)` and sends `verifier = K`. The VTA refuses `iterations` outside
600 000..10 000 000, a salt outside 16..64 bytes, a verifier that is not 32
bytes, and either claim set to `true`. The VTA performs no PBKDF2 itself: it
keeps `K` and checks HMACs keyed by it.

**Approval.** `pinProof = base64url(HMAC-SHA256(K, utf8("org.openvtc.uv-pin/v1|" + D)))`,
beside a decision approving `D` signed by the device's transport key with no
`evidence`. The proof is compared in constant time.

**The guess limit** (`vta-service/src/operations/uv_pin.rs`):

- five consecutive wrong proofs lock the PIN for 15 minutes;
- each wrong proof after a lock has expired locks it again for twice as long
  as the last — 15 min, 30 min, 1 h, … capped at 24 h;
- while locked, a proof is refused **without being checked**;
- a correct proof resets the count and the doubling.

The state lives in the ACL keyspace beside the device's row (`uv-pin:<did>`,
outside the `acl:` prefix), keyed to the PIN's enrolment instant, and every
update is a conditional write against the row as read, so two guesses racing
each other both count and the count survives a restart. A malformed proof (not
32 bytes of base64url) is refused as `oobUvInvalid` and not counted: it says
nothing about the PIN.

| Refusal (`details.code`) | `details` |
|---|---|
| `oobUvPinWrong` | `attemptsRemaining` (before the next lock); `lockedUntil` too when this proof imposed a lock |
| `oobUvLocked` | `lockedUntil` (unix seconds) |

**The summary** (`ext["org.openvtc"].uvKey` on `device/list` and the register
response, and `ext["org.openvtc.uv-key"]` on every heartbeat response) carries
`kind`, `salt`, `iterations`, `failedAttempts` and `lockedUntil` (unix seconds,
or `null` when not locked), so a browser whose local state was cleared can
derive `K` again from the PIN. **The verifier is never returned, audited or
logged**: it is a newtype whose `Debug` prints `<redacted>`, and nothing that
serialises a summary or an audit row reads it.

**Changing or removing a PIN.** A heartbeat that replaces a `vtaPin` key with
any new key must carry

```json
"org.openvtc.uv-key-change": { "pinProof": "<HMAC-SHA256(K_old, utf8('org.openvtc.uv-pin/v1|change|' + sha256hex(JCS(new enrolment))))>" }
```

where the new enrolment is the `org.openvtc.uv-key` value exactly as sent. It
counts against the same limit. Refusals ride `details`:
`device:uvKeyChangeProofRequired` (no proof), `device:uvPinWrong`
(`attemptsRemaining`), `device:uvKeyLocked` (`lockedUntil`),
`device:uvKeyChangeProofInvalid` (malformed, not counted). Enrolling a PIN
where there is no UV key, or replacing a key of another kind, needs nothing
extra.

**A forgotten PIN** is not recoverable by design: a manager disables or wipes
the device (`device/disable`, `device/wipe`) and the browser registers again
as a new device.

### Threat model

- **A copied browser profile** carries the device's transport key, so it can
  sign decisions as the device. What it lacks is the PIN, and it cannot guess
  offline: `K` is never on the device after enrolment, and every guess must be
  an HMAC the VTA checks and counts. Five guesses, then a lock that doubles. A
  six-digit PIN is therefore safe against this attacker in a way it would not
  be if the browser held anything derived from it.
- **Malware in the running browser** can capture the PIN as it is typed and
  then approve as the member. A PIN is something the person knows, entered
  into the very software it protects against; it is weaker than a key a secure
  element or an authenticator holds. That is why it is a kind of its own.
- **The VTA holds `K`**, a password equivalent. The VTA already holds the
  member's keys; a VTA compromise is total either way.

## `remoteApprover` — approve on the phone

The browser names the member's phone (the iOS app, which already answers
`task-consent/request/0.1` with Face ID), and each grant is approved there.

**Enrolment.**

```json
{ "kind": "remoteApprover", "approver": "<DID of the phone>", "hardwareBacked": false, "biometricGated": false }
```

**Who may be named** (`operations::device::uv_approver_eligible`). A browser
must not be able to name a DID it controls — the approval would then be its
own. A browser device is often a context admin, and a context admin can create
ACL entries in its contexts and register them as devices, so neither "has an
ACL entry" nor "is a registered phone" is something it cannot forge. What it
cannot write is the operator's designation of an approver, so the approver
must:

1. not be the browser itself, and hold a live ACL entry (the phone app is
   enrolled with `pnm acl create --did <did:key> …`);
2. be **designated by the operator**: this browser's own `stepUpApprover`
   (set on the browser's entry by an administrator — an entry may not modify
   itself), or a member of an approver set (`pnm approvals approvers add`,
   super-admin only);
3. not have been created by the browser;
4. if it carries a device binding, be an active mobile or desktop companion —
   never another browser or a service. (The phone app registers no binding.)

The rule is re-checked on every approval: an approver the operator stops
designating stops approving.

**Listing the candidates.** A heartbeat carrying
`ext["org.openvtc.uv-approvers"] = {}` is answered with
`ext["org.openvtc.uv-approvers"] = { "approvers": [{ "did", "displayName"?, "formFactor"? }] }`
— the DIDs this device may name, for a picker. (`device/*` has no task for
this; a new Trust Task URI needs a published specification first.)

**Approval.**

1. The browser sends the grant with `ext["org.openvtc.uv-consent"] = { "remote": true }`.
2. The VTA raises a task-consent request **bound to the enrolled approver**
   for this grant digest (`PendingTaskConsent::bound_approver`), signs a
   `task-consent/request/0.1` — `taskType` the grant's type, `requester` the
   browser's DID, `origin` the grant's origin, `subject` the persona, and one
   effect, `signIn`: *"Sign in to `<origin>` from your browser `"<name>"`. That
   browser can then act as you on `<origin>` until `<time>`."* — and pushes it
   to the phone over the same path as every consent request. It refuses
   `oobUvPending` with `details.matchCode` (the code the phone's sheet shows,
   `vta_sdk::task_consent::match_code` of the request's salted digest) and
   `details.expiresAt` (unix seconds).
3. The browser polls by sending the same request again. A poll re-reads the
   same request; it never raises another or rings the phone again.
4. The phone answers with its ordinary `task-consent/decision/0.1`. The
   decision handler accepts it only from the bound approver, and only for the
   request whose challenge and salted digest it echoes; approval mints the
   usual single-use grant for the browser.
5. The next poll consumes that grant — after every other check has passed, so
   a refusal never burns it — and signs. The audit row records
   `uvDecision.kind = "remoteApprover"` and the phone's DID as signer.

| Refusal (`details.code`) | When |
|---|---|
| `oobUvPending` | asked, not yet answered (`matchCode`, `expiresAt`) |
| `oobUvDeclined` | the phone declined; stays declined for this grant |
| `oobUvExpired` | the request lapsed: 120 s, never past the grant's `notAfter` |

A decline and a lapse are remembered (`BoundRequestMark`, swept ten minutes
after the request's expiry), so a late poll reads "declined" or "expired"
rather than asking the phone again. A grant id that has been signed is never
put to the phone.

### Threat model

The approval is made on a separate device behind its own biometric, so a
compromised browser cannot approve on its own. What it can do is ask: the
phone shows the origin, the browser's name and the match code, and the person
compares the code with the one the browser shows.

## A known gap shared by the older kinds

`device/heartbeat` lets a device replace a `hardwareKey`, `prfSealedKey`,
`webauthn` or `remoteApprover` UV key with no proof from the current one: the
transport key alone authorises it. Whoever holds a copied profile can
therefore swap such a key for one it controls. Only `vtaPin` requires the
current factor (`org.openvtc.uv-key-change`), because without that the PIN's
guess limit would be trivially sidestepped.

## See also

- [Task consent (DTTE)](./task-consent.md) — the ceremony `remoteApprover` reuses.
- [Approvals](./approvals.md) — approver sets.
