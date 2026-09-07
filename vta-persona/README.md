# vta-persona

The holder's own identity, for a Verifiable Trust Agent: the attributes a person
keeps about themselves, the profiles that project over them, which face a given
trust context sees, and what other people have disclosed back.

Implements the `persona/*` Trust Task family
([spec](https://trusttasks.org/spec/persona/)), and is the fourth holder store
in a VTA — beside the secrets vault, the credential vault, and application
state.

## The one-way boundary

The design turns on a single property, and most of this crate exists to enforce
it.

The **attribute pool** and the **profiles** built over it are *agent-scoped*:
they sit above every trust context. Bindings, contacts, disclosure records and
context-local profiles are *context-scoped*.

**Nothing inside a context may read the pool.** The holder pushes a materialised
projection down; a context never pulls. So an application that shares one
context with another cannot enumerate the holder's other faces, and a
compromised one cannot ask "who else is this person".

That is enforced in four ways here, deliberately at different layers, because
each catches a case the others cannot:

| | |
|---|---|
| **Authorization** | Holder-scoped tasks require `Admin` *and* unrestricted scope. A guard reading "is this an administrator" passes for one scoped to a single context, who would then read every other context's identity data. |
| **Types** | `MaterialisedClaim` is a distinct type from `ResolvedClaim` with nowhere to put a pool identifier, so no future edit can leak one by forgetting to clear a field. |
| **Addressing** | Context-local profiles occupy their own key prefix rather than sharing the pool's with a flag. A filter can be got wrong; an address space cannot. |
| **The schema** | A context-local profile's entries admit a single `inline` member, so one cannot *name* a pool attribute at all. |

Editing a pool attribute refreshes every context bound to it — "edit once,
everywhere" — without opening a read path, because the write is initiated above
the boundary.

## Disclosure is two calls

`preview` says what would be revealed and to whom; `present` hands it over and
consumes a single-use token only `preview` mints. There is no one-call form, so
there is no code path to a disclosure that skipped the summary a human can be
shown.

Four things refuse rather than degrade, because a quietly smaller disclosure is
indistinguishable to a verifier from a holder who chose to share less:

- a renderer that cannot carry a requested claim fails at negotiation;
- an unknown renderer is refused, not defaulted;
- a claim that went stale between preview and present refuses the *whole*
  disclosure;
- an expired preview is refused rather than silently re-derived.

## Correlation

`correlation/analyze` reports how linkable a value would make the holder, and
encodes an inversion that is easy to get backwards: a credential presented
**whole** correlates *more* than a self-asserted value, because the issuer's
signature is byte-identical at every verifier — while a derived proof correlates
*less*, differing on every presentation. Severity is a function of value and
proof rung together, never of provenance alone.

The index is blinded: an HMAC over canonicalised JSON, keyed per agent, so the
store can say "you have used this value elsewhere" without holding a corpus of
the holder's values in a comparable form.

## Status

Early. The API will change. See
[`CHANGELOG.md`](https://github.com/OpenVTC/verifiable-trust-infrastructure/blob/main/vta-persona/CHANGELOG.md)
and the [workspace](https://github.com/OpenVTC/verifiable-trust-infrastructure)
for how it is used in a running agent.

## Licence

Apache-2.0
