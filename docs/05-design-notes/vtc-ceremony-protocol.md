# VTC Ceremony Trust Task Protocol — Generalized

**Status:** Design proposal (for review) · **Parent:** [`vtc-ceremony-pipeline.md`](./vtc-ceremony-pipeline.md)
**Depends on:** the Verdict (§4) and Facts (§3) of the pipeline doc, and the instances in
[`vtc-ceremony-catalog.md`](./vtc-ceremony-catalog.md).
**Purpose:** one wire pattern for *all* ceremonies. The choreography is the same; only the family name and the
effect payload differ.

> **Notation.** Bare `§N` references are to [`vtc-ceremony-pipeline.md`](./vtc-ceremony-pipeline.md). MVP
> references are written `vtc-mvp.md §N`.

---

## 1. Conventions (inherited from `vtc-mvp.md` §9.4)

- **URL form:** `https://trusttasks.org/openvtc/vtc/{family}/{verb}/{major}.{minor}` — `org = openvtc`,
  `domain = vtc`. One **family per ceremony** (`join-requests`, `departures`, `role-changes`, `directory`).
- **REST binding:** every request carries a `Trust-Task` header, exact-matched at attach time (mismatch → 415,
  missing → 400).
- **DIDComm binding:** the message `type` **is** the Trust Task URL.
- **Per-task artefacts:** `trust-tasks/{family}/{verb}/{maj}.{min}/{spec.md,schema.json}` + an `index.json`
  entry. Lifecycle Draft → Reviewing → Published → Deprecated; these ship at **Draft**.
- **Rate limit (`vtc-mvp.md` §9.6):** unauthenticated triggers use a per-sender-DID leaky bucket *before*
  evaluation.

---

## 2. The generic verb set

Every ceremony family draws from the **same** small verb set — most ceremonies use a subset.

| Verb | Kind | Used by | Meaning |
|---|---|---|---|
| `manifest` | read | evidence-bearing ceremonies | discover requirements: the Presentation Definition + human summary |
| `request` | request→**verdict** | all | open the ceremony; carries the actor's evidence; returns the Verdict |
| `present` | request→**verdict** | threaded ceremonies | continuation after `request_more`, same thread |
| `status` | read | threaded ceremonies | poll a thread in `Pending`/`Deferred` |
| `resolve` | request | ceremonies with `refer` | a human/quorum decision that advances a referred thread |
| `accept` | request | ceremonies with a reciprocal step | counter-sign (e.g. the join VMC → bidirectional edge) |

A **synchronous** ceremony (directory) uses only `request` and gets its result inline — no `present`/`status`.
A **threaded** ceremony (join) uses `manifest` + `request` + `present` + `status` + `accept`.

`Gather`, `Verify`, and `Evaluate` are **not** tasks — Gather is local; Verify + Evaluate run server-side inside
the `request`/`present` handler (§2 pipeline boundary).

---

## 3. The Verdict response (shared by `request` and `present`, every family)

One response shape across all ceremonies — the Verdict (§4) plus thread metadata:

```jsonc
{
  "thread_id":  "urn:uuid:…",        // present for threaded ceremonies; absent for synchronous ones
  "request_id": "…",
  "verdict": {
    "effect": "allow" | "deny" | "refer" | "request_more",
    "with": {
      // allow        → ceremony payload (role | disposition | fields | obligations) + host-added bundle_ref where issuance occurs
      // deny         → code, reason
      // refer        → queue, reason
      // request_more → needs, presentation_definition
    }
  }
}
```

`bundle_ref` (a sealed-transfer pointer) is **added by the host** on issuing ceremonies — it is not emitted by
the policy. Framework errors (malformed/expired/rate-limited/verification failure) use the `trust-task-error`
type (`vtc-mvp.md` §9.4 — exact URI TBD), **not** a `deny` verdict: `deny` means the policy refused; an error
means the request never reached the policy.

---

## 4. Per-ceremony families

| Family | Verbs | Trigger auth | Synchronous? |
|---|---|---|---|
| `join-requests/*` | `manifest`, `request` *(= the MVP `submit`)*, `present`, `status`, `accept` | inner VP (holder) + optional outer relayer | no (threaded) |
| `departures/*` | `request`, `status`, `resolve` | member session (self) **or** admin (involuntary) | usually one-shot |
| `role-changes/*` | `request`, `resolve` *(step-up / quorum)* | admin session + step-up | one-shot or short thread |
| `directory/*` | `query` *(a `request` alias)* | member session | **yes** (inline) |

> The existing `join-requests/submit/1.0` is this pattern's `request` verb for the join family; keep the URI,
> read it as `request`. New families follow the identical shape.

---

## 5. Threading, async, relayer ≠ holder

- **Thread** (`thread_id`) exists only for threaded ceremonies (§6 pipeline). `request` mints it; `present` /
  `status` / `resolve` / `accept` carry it. A thread is in one state (`Pending`/`Deferred`/terminal); terminal
  states reject further verbs with the error type. Bind `present` to `thread_id` **+** holder DID (anti-hijack).
- **Async** — `refer` parks the thread `Deferred`; `resolve` (or the existing admin REST surface) advances it.
  When the actor is DIDComm-reachable the host may **push** the follow-up; `status` poll is the universal
  fallback.
- **Relayer ≠ holder** (onion auth, reused from provision-integration): the **outer** envelope (REST bearer /
  DIDComm authcrypt) authenticates the *relayer* who carries the request; the **inner** VP authenticates the
  *holder*. Issued bundles are sealed to the holder — the relayer can't read them and can't forge the VP, so no
  privilege escalation. Enables air-gapped onboarding.

---

## 6. Sequence sketches

**Join — threaded, request_more then allow:**

```
Applicant ─join-requests/manifest (read)─▶ VTC ─▶ {PD}
Applicant ─join-requests/request {VP}────▶ VTC : verify → evaluate → request_more
Applicant ◀──── {verdict: request_more, presentation_definition} ────
Applicant ─join-requests/present {VP+more, thread}─▶ VTC : evaluate → allow
Applicant ◀──── {verdict: allow, bundle_ref} ──── ; then join-requests/accept (reciprocal VMC)
```

**Leave — one-shot, admin removal:**

```
Admin ─departures/request {subject, reason}─▶ VTC : verify(actor=admin) → evaluate → allow{disposition}
Admin ◀──── {verdict: allow, disposition: "Tombstone"} ────   # host revokes VMC, applies disposition, audits
```

**Directory — synchronous, no thread:**

```
Member ─directory/query {target, fields}─▶ VTC : verify → evaluate → allow{fields}
Member ◀──── {verdict: allow, fields: {did, role}} ────       # filtered projection, inline, no persistence
```

---

## 7. Deliverables (Draft)

New `trust-tasks/` entries, following the `vtc-mvp.md` §9.4 `spec.md` + `schema.json` + `index.json` convention,
shipped **with** the code that implements each verb:

```
join-requests/{manifest,present,status,accept}/1.0/   # request = existing submit, extend schema with the Verdict union
departures/{request,status,resolve}/1.0/
role-changes/{request,resolve}/1.0/
directory/query/1.0/
```

A shared `schema.json` fragment defines the Verdict union once and is referenced by every `request`/`present`
response — one source of truth for the wire shape across all ceremonies.

---

## 8. Open items

- **`manifest` / `.well-known` alias** for generic-wallet discovery without knowing the task surface — worth it?
- **`resolve` vs the existing REST admin surface** (`POST /v1/join-requests/{id}/{approve,reject}`,
  `vtc-mvp.md` §9.5) — `resolve` is the generalized form; keep both or migrate?
- **Synchronous-ceremony envelopes** — do `directory/query` results need the full Trust Task envelope, or a
  lighter read path? (Leaning: same envelope, exempt from threading fields.)
- **Per-family rate-limit tuning** — join (unauth) needs the tightest bucket; member-triggered ceremonies inherit
  session auth.
