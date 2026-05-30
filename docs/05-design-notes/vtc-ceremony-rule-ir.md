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
  "purpose": "join",                 // matches a PolicyPurpose
  "routes": [
    { "name": "Invitation",
      "listed": false,               // appears in the public manifest? (omit ⇒ true)
      "when": { "all": [ "has_valid_invitation" ] },
      "then": { "effect": "allow", "with": { "role": "member" } } },
    { "name": "Open review",
      "when": { "all": [ "always" ] },
      "then": { "effect": "refer", "with": { "queue": "moderator" } } }
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
| `subject_is_admin` | — | `input.state.subject_member.role == "admin"` |
| `member_count_lt` | int | `input.context.member_count < <n>` |

### 2.2 Join (evidence: invitation + presentation + agreements)

| IR leaf | Arg | Compiles to |
|---|---|---|
| `has_valid_invitation` | — | `has_valid_invitation` *(helper)* |
| `holds` | type str | `cred_held("<type>")` *(helper)* |
| `holds_trusted` | type str | `cred_trusted("<type>")` *(helper)* |
| `endorsements_gte` | int | `endorsement_count >= <n>` |
| `agreed` | tag str | `agreed("<tag>")` *(helper)* |

### 2.3 Leave (evidence: request{disposition?, reason?})

| IR leaf | Arg | Compiles to |
|---|---|---|
| `actor_is_self` | — | *(shared)* |
| `actor_is_admin` | — | *(shared)* |
| `subject_is_admin` | — | *(shared)* |
| `disposition_requested` | — | `input.evidence.request.disposition` |

### 2.4 Directory (evidence: request{fields_requested})

| IR leaf | Arg | Compiles to |
|---|---|---|
| `viewer_is_admin` | — | `input.actor.role == "admin"` |
| `viewer_is_member` | — | `input.actor.authenticated == true` |

### 2.5 Role-change (evidence: request{target_role, step_up})

| IR leaf | Arg | Compiles to |
|---|---|---|
| `target_role_standard` | — | `input.evidence.request.target_role != "admin"` |
| `promotes_to_admin` | — | `input.evidence.request.target_role == "admin"` |
| `step_up_done` | — | `input.evidence.request.step_up == true` |

`allow.with.role` of `"$target"` → the requested `target_role` (compiler emits the `target_role` helper).
**Unlike join, role-change MAY grant `admin`** — it is the sanctioned promotion path, gated by `step_up_done`
(or M-of-N). No-last-admin on demotion stays host-enforced.

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
cred_held(t) if { some c in input.evidence.presentation.credentials; c.type == t; c.status == "valid" }
cred_trusted(t) if { some c in input.evidence.presentation.credentials; c.type == t; c.issuer_trusted; c.status == "valid" }
endorsement_count := count([c | some c in input.evidence.presentation.credentials; c.type == "EndorsementCredential"])
has_valid_invitation if { input.evidence.invitation.verified; not input.evidence.invitation.consumed }
agreed(tag) if { input.evidence.request.agreements[tag] == true }
```

**Mapping rules**
- A route's `when` combinator → Rego conjunction (`all` → newline-separated expressions; `any` → a helper rule
  with multiple bodies; `not` → `not <expr>`).
- A route's `then` → the literal decision object.
- Routes emit in array order; the `else` chain makes the **first** matching route win.
- The appended `default decision` guarantees totality (§9 rail). It is unreachable whenever the last route is a
  catch-all (`when: ["always"]`) — which is the recommended final route — but always present as a backstop.

**Static invariant checks** (run at compile, fail the build):
- no `allow.with.role == "admin"` (privilege ceiling);
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
To join Acme, the first matching route applies:
  P1 Invitation (unlisted): hold a valid invitation → admitted as member
  P2 Verified human: a trusted WitnessCredential AND agree to the code of conduct → admitted as member
  P3 Almost there: a trusted WitnessCredential → asked for the code-of-conduct agreement
  P4 Open review: anyone else → sent to moderator review
  ∎ default: → denied
```

---

## 7. Worked: the Join policy

The IR, the compiled Rego, and a sample-facts test vector are in [`examples/`](./examples/):
`join.ir.json` → `join.rego`, plus `leave.ir.json`/`leave.rego` and `directory.ir.json`/`directory.rego`. Each
`.rego` is exactly what this compiler emits from its `.ir.json`. See [`examples/README.md`](./examples/README.md)
for sample `input` documents and expected verdicts, and how to run them with `regorus`/`opa`.

---

## 8. Adding a new ceremony

1. Add an evidence slot to Facts (§3 of the pipeline doc) if needed.
2. Add a vocabulary block here (§2) + the effect's `with` payload (§3).
3. Add an effect handler (the only purpose-specific code; §5 of the pipeline doc).
4. The IR editor, compiler, PD/English generators, versioning, and Trust Task protocol are inherited unchanged.
