# Hierarchical trust contexts

Status: design + in-progress (VTA first). Moves VTA trust contexts from a flat
set to a **folder / sub-folder tree**, with **folder-level admin authority** —
an admin of a parent context administers the whole subtree (create / remove
sub-contexts, and manage their ACL, keys, and data).

## Decisions

| Decision | Choice | Why |
|---|---|---|
| Hierarchy encoding | **The context identifier *is* its materialized path** (`acme/eng/team-a`) | Keeps the authorization gate **pure** — ancestry is a segment comparison on data already in the JWT, no store walk. See *Security rationale*. |
| Ancestry test | **Segment-aware** prefix (`is_ancestor_or_self`) | A raw `starts_with` is wrong: `acme` must NOT match `acme-evil`. Compare path *segments*. |
| Segment charset | Each segment is a [`validate_identifier`] value (`[A-Za-z0-9._-]`, ≤64 bytes) | `/` is the *only* separator and cannot appear in a segment → no `..` / slash-injection / empty-segment aliasing. |
| Admin cascade | **Full subtree authority** | "More sophisticated context management overall" — an admin of a parent manages everything beneath it. |
| Re-parenting (move a subtree) | **Disallowed initially** | The cost of a path-as-id model is that a move rewrites every descendant path + ACL ref. Rare; defer. |
| Scope | **VTA first, VTC follows** | The key / ACL / BIP-32 machinery lives in the VTA; mirror to the VTC after. |

## Security rationale (why path-encoded, not parent-pointer)

The user's lens was *"most secure in the long run as we add stricter ACL
management."* The authorization gate should be **pure, deterministic, and
auditable**, with no dependency that can fail-open. A path-encoded identifier
gives exactly that, where a parent-pointer model does not:

- **Pure gate, no fail-open.** `has_context_access` stays a string/segment
  comparison over `allowed_contexts` (already in the verified JWT). A
  parent-pointer model has to *walk the store* to resolve ancestry inside the
  security check — introducing: a store-error fail-open question, a DoS surface,
  **cycle** risk (A→B→A loops), and TOCTOU between resolution and use.
- **Scope is legible in the grant.** A grant for `acme/eng` self-evidently
  authorizes that subtree. With pointers you must reconstruct a graph to know
  what a grant covers — the opposite of auditable as rules get stricter.
- **Stricter checks stay pure.** "deny deeper than N", "no cross-subtree
  reference", "require a grant at each level" are all pure path operations
  rather than store walks.

The trade — cheap re-parenting + opaque ids — is worth losing for a gate with a
materially smaller attack surface. Re-parenting is disallowed for now.

## The path primitive (`vti-common::context_path`)

Pure, store-free, the security foundation. Thoroughly tested against
prefix-confusion and injection:

- `validate_context_path(path)` — non-empty; split on `/`; every segment a valid
  identifier; no empty / leading / trailing / doubled separators; depth ≤ MAX.
- `is_ancestor_or_self(ancestor, descendant)` — `descendant`'s segments start
  with `ancestor`'s segments (segment-aware; `acme` is **not** an ancestor of
  `acme-evil`). This is what the ACL gate calls.
- `parent_path(path) -> Option<&str>`, `depth(path) -> usize`.

## ACL gate

`AuthClaims::has_context_access(target)` becomes: super-admin, **or** any
`allowed_contexts` entry `is_ancestor_or_self` of `target`. For today's flat
(single-segment, childless) contexts this is **identical to the previous exact
match**, so it is behaviour-preserving until sub-contexts exist.

## BIP-32 nesting

A sub-context's derivation base nests under its parent's: parent
`m/26'/2'/<a>'` → child `m/26'/2'/<a>'/<b>'`, the path depth mirroring the
context depth. The per-parent child index is counter-allocated under the parent.
The context's immutable `base_path` stays the single source of truth for key
derivation (unchanged contract; just deeper).

## Slice plan

1. **Path primitive + ACL gate** (this lands first) — `context_path` module +
   `has_context_access`/`require_context` use `is_ancestor_or_self`. Pure,
   behaviour-preserving for flat contexts, exhaustively tested.
2. **Context model + nested creation** — `ContextRecord` carries its path +
   parent; `create_context` accepts a parent, validates the parent exists +
   caller is admin of it, allocates the nested BIP-32 base, enforces depth.
3. **Subtree operations** — delete (cascade / refuse-non-empty), list-subtree,
   and admin-of-parent authority over descendant ACL / keys.
4. **VTC** — mirror the relevant parts to the community/context surface.

   **Finding (on investigation):** the VTC is **not** the key authority — it
   never creates contexts or derives keys, and has **no `require_context`
   authorization gate**. It only *references* VTA context ids as ACL metadata
   (`VtcAclEntry.allowed_contexts`), used in a single place: the
   `GET /acl?context=…` list filter. So there is no context *model* to make
   hierarchical. The only consistent change is that list filter, which is now
   **ancestry-aware** (an entry scoped to an ancestor of the queried context is
   relevant to it), reusing `vti_common::context_path::is_ancestor_or_self`. The
   hierarchical-contexts feature is therefore **complete on the VTA**, where the
   context model, BIP-32 derivation, and authorization gate live.
