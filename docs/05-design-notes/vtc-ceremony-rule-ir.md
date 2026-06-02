# VTC Ceremony Rule IR & Compiler

**Status:** Design proposal (for review) · **Parent:** [`vtc-ceremony-pipeline.md`](./vtc-ceremony-pipeline.md)
**Purpose:** The canonical vocabulary. Operators author a constrained **Rule IR** (a JSON AST); a deterministic
compiler emits Rego + a Presentation Definition + English + invariant checks. This document is the **single
source of truth** that the example policies ([`examples/`](./examples/)) and the interactive guide
([`vtc-ceremony-visual-guide.html`](./vtc-ceremony-visual-guide.html)) both derive from — keep them in sync with
this file.

> **Notation.** Bare `§N` references are to [`vtc-ceremony-pipeline.md`](./vtc-ceremony-pipeline.md). MVP
> references are written `vtc-mvp.md §N`.

---

## 1. The IR document

A policy is an **ordered list of routes** (first-match) for one purpose. The IR — not the Rego — is the
versioned source of truth (§8 of the pipeline doc), so diffs are semantic.

```jsonc
{
  "purpose": "phase2",               // matches a PolicyPurpose
  "routes": [
    { "name": "Invited by initiator",
      "listed": true,                // appears in the public manifest? (omit ⇒ true)
      "when": { "all": [ "has_valid_invitation",
                          { "invitation_issuer_has_role": "initiator" } ] },
      "then": { "effect": "allow", "with": { "role": "trustAnchor" } } },
    { "name": "Almost there",
      "when": { "all": [ "always" ] },
      "then": { "effect": "request_more", "with": { "needs": ["invitation:from-initiator"] } } }
  ]
  // the compiler ALWAYS appends a structural default: deny / no-matching-route
}
```

**Condition grammar** (`when`):

```
cond     := leaf | { "all": [cond, …] } | { "any": [cond, …] } | { "not": cond }
leaf     := "<id>"                       // no-arg condition, e.g. "has_valid_invitation"
          | { "<id>": <arg> }            // arg'd condition, e.g. { "holds_trusted": "WitnessCredential" }
```

`all` = AND, `any` = OR, `not` = negation. Leaves come from the vocabulary in §2.

---

## 2. Condition vocabulary

Conditions are **questions over already-verified Facts** (§3 of the pipeline doc). They never touch crypto — the
host resolved that in *Verify*. Each row gives the IR leaf, its argument, and the Rego it compiles to.

### 2.1 Shared (any purpose)

| IR leaf | Arg | Compiles to (Rego over `input`) |
|---|---|---|
| `always` | — | `true` |
| `actor_is_admin` | — | `input.actor.role == "admin"` |
| `actor_is_self` | — | `input.actor.did == input.subject.did` |
| `actor_is_initiator` | — | `input.actor.role == "initiator"` |
| `subject_is_admin` | — | `input.state.subject_member.role == "admin"` |
| `member_count_lt` | int | `input.context.member_count < <n>` |

**Admission ceremonies (Phases 1–4).** §2.2–§2.5 cover the four community-lifecycle admission phases
defined in *VTC Bootstrapping* (draft 03). Each phase has the same `actor`/`subject` shape (applicant is
both) and the same `allow.with.role` payload key; they differ in the credentials they require and the role
they grant. The privilege ceiling (§4) applies across the family — no admission route grants `admin`.

### 2.2 Phase 1 — Initiation (genesis)

The degenerate case: the **initiator** self-bootstraps a brand-new VTC. Per the VTC Bootstrapping spec,
Phase 1 policy is hardcoded in the **Personal Network Manager**; the VTA doesn't exist yet to evaluate
this IR. The vocabulary entry is kept for design completeness and to surface the layered-trust progression
that begins at "initiator".

| IR leaf | Arg | Compiles to |
|---|---|---|
| `actor_is_initiator` | — | *(shared, §2.1)* |

### 2.3 Phase 2 — Initiator invites community trust anchors

The initiator issues VICs granting role `trustAnchor`; presenters who hold a verified VIC issued by the
initiator are admitted as trust anchors.

| IR leaf | Arg | Compiles to |
|---|---|---|
| `has_valid_invitation` | — | `has_valid_invitation` *(helper)* |
| `invitation_issuer_has_role` | role str | `input.evidence.invitation.issuer_role == "<role>"` |

### 2.4 Phase 3 — Community trust anchors invite members

A trust anchor invites the applicant by issuing a VIC. Admission also requires a verified relationship
credential (VRC) issued by a **different** trust anchor — so admission is independently witnessed.

| IR leaf | Arg | Compiles to |
|---|---|---|
| `has_valid_invitation` | — | *(see §2.3)* |
| `invitation_issuer_has_role` | role str | *(see §2.3)* |
| `holds_credential_from_role` | `{ "type": <str>, "role": <str>, "min"?: <int>, "distinct_issuers"?: <bool>, "exclude_invitation_issuer"?: <bool> }` | helper-rule reference (see below) |

`holds_credential_from_role` compiles to one of two helper rules, both emitted once per `.rego` as needed:

```rego
# Distinct issuers of credentials matching (type, community role), all VERIFIED.
credential_distinct_issuer_count(t, role) := count({c.issuer |
  some c in input.evidence.presentation.credentials
  c.type == t
  c.issuer_trusted
  c.issuer_role_in_community == role
  c.status == "valid"
})

# Same, but excluding the VIC issuer (used by Phase 3 + Phase 4).
credential_distinct_issuer_count_excl_inviter(t, role) := count({c.issuer |
  some c in input.evidence.presentation.credentials
  c.type == t
  c.issuer_trusted
  c.issuer_role_in_community == role
  c.status == "valid"
  c.issuer != input.evidence.invitation.issuer
})
```

The compiler picks `_excl_inviter` when `exclude_invitation_issuer: true` is set on the leaf's argument.
Distinctness is by issuer DID — two credentials from the same issuer count as one. The
`issuer_role_in_community` field is populated by the Verify stage from a community-ACL lookup
(see [`vtc-ceremony-pipeline.md`](./vtc-ceremony-pipeline.md) §3).

### 2.5 Phase 4 — Members invite other members

A regular member invites the applicant via VIC. Admission also requires ≥2 verified relationship
credentials issued by **two other distinct** members (excluding the inviter) **plus** an identity
verification credential (IDVC) issued by an approved identity verification provider (IDVP). The IDVC is
just another credential in the presentation — its type is `IdentityVerificationCredential` and its issuer
holds `issuer_role_in_community == "identityVerificationProvider"`.

| IR leaf | Arg | Compiles to |
|---|---|---|
| `has_valid_invitation` | — | *(see §2.3)* |
| `invitation_issuer_has_role` | role str | *(see §2.3)* |
| `holds_credential_from_role` | `{ type, role, min?, distinct_issuers?, exclude_invitation_issuer? }` | *(see §2.4)* |

Phase 4 reuses the §2.4 leaves with different arguments — no new vocabulary.

### 2.6 Leave (evidence: request{disposition?, reason?})

| IR leaf | Arg | Compiles to |
|---|---|---|
| `actor_is_self` | — | *(shared)* |
| `actor_is_admin` | — | *(shared)* |
| `subject_is_admin` | — | *(shared)* |
| `disposition_requested` | — | `input.evidence.request.disposition` |

### 2.7 Directory (evidence: request{fields_requested})

| IR leaf | Arg | Compiles to |
|---|---|---|
| `viewer_is_admin` | — | `input.actor.role == "admin"` |
| `viewer_is_member` | — | `input.actor.authenticated == true` |

### 2.8 Role-change (evidence: request{target_role, step_up})

| IR leaf | Arg | Compiles to |
|---|---|---|
| `target_role_standard` | — | `input.evidence.request.target_role != "admin"` |
| `promotes_to_admin` | — | `input.evidence.request.target_role == "admin"` |
| `step_up_done` | — | `input.evidence.request.step_up == true` |

`allow.with.role` of `"$target"` → the requested `target_role` (compiler emits the `target_role` helper).
**Unlike the admission phases, role-change MAY grant `admin`** — it is the sanctioned promotion path,
gated by `step_up_done` (or M-of-N). No-last-admin on demotion stays host-enforced.

Adding a purpose = adding a vocabulary block here + an effect handler (§5 of the pipeline doc). The compiler and
combinator logic are unchanged.

---

## 3. Effect vocabulary (`then`)

Four effects (§4 of the pipeline doc). Only `allow` carries a purpose-specific `with` payload.

| `effect` | `with` payload | Compiles to |
|---|---|---|
| `allow` | `{ role }` \| `{ disposition }` \| `{ fields }` (+ `obligations`) | `{"effect":"allow","with":{…}}` |
| `deny` | `{ code, reason }` | `{"effect":"deny","with":{…}}` |
| `refer` | `{ queue, reason }` | `{"effect":"refer","with":{…}}` |
| `request_more` | `{ needs, presentation_definition }` | `{"effect":"request_more","with":{…}}` (PD from §5) |

---

## 4. Compile → Rego

Ordered first-match compiles to a single `decision` rule with an **`else` chain** (native Rego first-match),
backed by the structural-default deny. Helper rules are appended once.

```rego
package vtc.<purpose>
import future.keywords.if
import future.keywords.in

# structural totality (compiler-appended; operator cannot remove)
default decision := {"effect": "deny", "with": {"code": "no-matching-route"}}

# routes in priority order → else chain
decision := <then₁> if { <when₁> }
else := <then₂> if { <when₂> }
else := <thenₙ> if { <whenₙ> }

# helpers (emitted as used)
has_valid_invitation if { input.evidence.invitation.verified; not input.evidence.invitation.consumed }
credential_distinct_issuer_count(t, role) := count({c.issuer |
  some c in input.evidence.presentation.credentials
  c.type == t; c.issuer_trusted; c.issuer_role_in_community == role; c.status == "valid"
})
credential_distinct_issuer_count_excl_inviter(t, role) := count({c.issuer |
  some c in input.evidence.presentation.credentials
  c.type == t; c.issuer_trusted; c.issuer_role_in_community == role; c.status == "valid"
  c.issuer != input.evidence.invitation.issuer
})
target_role := input.evidence.request.target_role
disposition := input.evidence.request.disposition if { input.evidence.request.disposition } else := "PolicyDefault"
```

**Mapping rules**
- A route's `when` combinator → Rego conjunction (`all` → newline-separated expressions; `any` → a helper rule
  with multiple bodies; `not` → `not <expr>`).
- A route's `then` → the literal decision object.
- Routes emit in array order; the `else` chain makes the **first** matching route win.
- The appended `default decision` guarantees totality (§9 rail). It is unreachable whenever the last route is a
  catch-all (`when: ["always"]`) — which is the recommended final route — but always present as a backstop.

**Static invariant checks** (run at compile, fail the build):
- no `allow.with.role == "admin"` for **admission** purposes (`phase1`, `phase2`, `phase3`, `phase4`) —
  the privilege ceiling. Role-change is exempt by design (§2.8);
- every `when` leaf is in the purpose's vocabulary (no free Rego);
- a catch-all or default guarantees totality (always true by construction);
- purpose-specific checks (e.g. leave: no route may bypass the host's no-last-admin guard — enforced outside
  Rego, but the compiler warns if a route's effect assumes it).

---

## 5. Compile → Presentation Definition

For evidence-bearing purposes (join), the compiler unions the credential/invitation conditions of the **listed**
routes into a DIF Presentation Definition, one `submission_requirement` group per listed route (alternatives):

- `holds` / `holds_trusted` → an `input_descriptor` constraining `$.type`.
- `agreed` → an `input_descriptor` constraining `$.agreements.<tag>` to `true`.
- `has_valid_invitation` on an **unlisted** route → omitted (the invitation is the private signal).

Synchronous, non-evidence purposes (directory) produce no PD.

---

## 6. Compile → English

One line per route, in priority order, e.g.:

```
To join Acme in Phase 3 (community trust anchors invite members), the first matching route applies:
  P1 Trust-anchor vouched: a valid VIC from a community trust anchor AND a VRC from a DIFFERENT trust anchor → admitted as member
  P2 Almost there: anyone else → asked for the missing invitation / cross-anchor VRC
  ∎ default: → denied
```

---

## 7. Worked: the Phase 3 policy

The IR, the compiled Rego, and a sample-facts test vector for every active ceremony are in
[`examples/`](./examples/). Each `.rego` is exactly what this compiler emits from its `.ir.json`. Active
ceremonies:

- Admission: `phase1.ir.json` / `phase2.ir.json` / `phase3.ir.json` / `phase4.ir.json`
  (with their `.rego` and `facts.*.json` siblings)
- Member lifecycle: `leave.ir.json` / `role-change.ir.json` / `directory.ir.json`

Phase 3 is the most policy-rich admission phase: it composes `has_valid_invitation`,
`invitation_issuer_has_role`, and `holds_credential_from_role(excl_inviter)` into a single first-match
route. See [`examples/README.md`](./examples/README.md) for sample `input` documents and expected
verdicts, and how to run them with `regorus`/`opa`.

---

## 8. Adding a new ceremony

1. Add an evidence slot to Facts (§3 of the pipeline doc) if needed.
2. Add a vocabulary block here (§2) + the effect's `with` payload (§3).
3. Add an effect handler (the only purpose-specific code; §5 of the pipeline doc).
4. The IR editor, compiler, PD/English generators, versioning, and Trust Task protocol are inherited unchanged.
