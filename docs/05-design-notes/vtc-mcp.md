# vtc-mcp — driving a VTC from an MCP host

Status: **proposed** (2026-11-06). Companion to the VTA bridge, `vta-mcp`
(`docs/02-vta/vta-mcp.md`), whose shape this note deliberately reuses. The
tracking issue is linked from the PR that lands this note.

## 0. Summary

There is no MCP surface for a Verifiable Trust Community today. `vta-mcp`
exposes a *VTA* to an MCP host; nothing exposes a *VTC*, so a member or an
administrator working with an AI assistant has no way to configure a
community, run its ceremonies or read its state except the console, `cnm`, or
hand-written code over `vtc-client`.

This note proposes `vtc-mcp`: a stdio MCP server, `publish = false`, that is
to a VTC what `vta-mcp` is to a VTA. It makes five decisions:

1. **The bridge is a native Trust Task client, over TSP first.** Every tool
   call becomes a signed Trust Task sent in-process through `vtc-client` on
   a mediated session — TSP where both DID documents advertise it, DIDComm
   otherwise, HTTPS only when the community advertises neither. It never
   runs a `cnm` or `pnm` command, and it never reads a CLI's stored login
   as its default identity.
2. **One generic tool reaches the whole surface.** `vtc_call` sends any pinned
   Trust Task by Type URI; `vtc_list_operations` is the catalog. The catalog is
   read from the vendored specification bundles in `vti-specs-vtc` and
   `vti-specs-rooms` — description, payload schema, error codes, document
   policy — not from hand-written strings, and every payload is checked
   against the pinned schema before it is sent.
3. **The bridge runs as exactly one identity, chosen by a ladder** — a member
   persona, or a dedicated agent entry at the VTC (an administrative role or
   a listed capability set), each on its own mediated session; a replayed
   `cnm` login over HTTPS exists only as a declared last resort — and never
   falls through from a half-configured rung to operator authority.
4. **The VTC stays the authority; the bridge adds a local per-operation
   guard**, the same one `vta-mcp` has, because an MCP host approves a tool
   and not a call. The guard and the call recorder move into a crate the two
   bridges share rather than being copied.
5. **VTC knowledge ships with the bridge** as MCP resources and prompts —
   the operator guides for groups, boards, elections, data rooms, vetting and
   admission, and one prompt per multi-step workflow — so an assistant knows
   the order of operations, which steps park on the action list, and what a
   member sees. Workflow-level tools wrap the common paths.

## 1. What exists

### 1.1 `vta-mcp`

`vta-mcp/` is an `rmcp` 3 stdio server. Two generic tools
(`vta_list_operations`, `vta_call`) cover the VTA's Trust Task surface and a
dozen typed conveniences wrap the common calls. Three things sit in front of
every call: the local guard (`guard.rs`: a verb-based risk classifier,
`--read-only`, `--allow` / `--deny` slug globs, and `--confirm
never|destructive|sensitive|always` via MCP elicitation), the recorder
(`observability.rs`: start and finish lines, a redacted ring buffer, an
optional JSONL audit file), and the VTA itself. The connect ladder is
`vta_sdk::agent_connect::AgentConnect`: a `did:webvh` secrets bundle, a
`did:key`, a bearer token, or a replayed `pnm` session, highest precedence
first, with a half-configured rung failing fast rather than falling through.
Tool annotations are asserted against the classifier in a test.

Everything in that paragraph is reusable. Only the catalog, the client and the
conveniences are VTA-specific.

### 1.2 `vtc-client`

`vtc-client/` is the VTC's client SDK. Every admin verb is a signed Trust
Task posted to `POST {base}/trust-tasks`, or sent over a mediated DIDComm /
TSP session when the client was built with `connect_didcomm` /
`connect_tsp` (features `didcomm` / `tsp`, which delegate the session to
`vta_sdk::client::VtaClient`). It has typed methods for the roster, the join
queue, members, policy, `acl/*`, boards, elections, rooms, git namespaces,
vetting, endorsements, relationships and backup.

Two gaps matter here:

- **No generic sender** (closed by phase 1, D2). The signed-document post was
  private (`VtcClient::post_document`); only elections and rooms exposed a raw
  `send_signed_document`. A bridge that can send *any* task needs a public,
  holder-agnostic `send_task(type_uri, payload)` that goes over the session
  when there is one and otherwise signs with the configured key.
- **Whole families have no client at all.** `vtc/groups/*`,
  `vtc/directory/*` and `vtc/notifications/*` are served by the VTC and
  driven by the admin console (`vtc-service/admin-ui/src/lib/groups.ts`) but
  have no `vtc-client` method and no `cnm` command. Groups were the first
  example asked for. Typed wrappers for every family would be a second copy
  of the specification; the generic sender plus the spec-sourced catalog is
  how the bridge reaches them.

### 1.3 `cnm-cli`

`cnm` is the operator's map of the surface — community, members, member,
vetting, access, consent, actions, git, boards, elections, rooms, networks,
storage, did-log, backup, audit, acl, did-templates. It is a reference for
what the surface is, not a dependency of the bridge and not something the
bridge runs: the bridge speaks Trust Tasks itself.

### 1.4 The specification bundles

`vti-specs-vtc/trust-tasks/vtc/**/*.bundle.json` (241 pinned versions) and
`vti-specs-rooms` (53) vendor each task's `typeUri`, `status`, `deprecation`
and `supersededBy`, the payload and response JSON Schemas (the payload
schema's `description` is the task's own prose, e.g. *"An administrator
creates a community group: the community's VTA mints the group's own DID
…"*), the declared `errorCodes`, and the document `policy` (proof, recipient,
`issuedAt`, size). `vti_specs::schema_index` answers for exactly these; a
Type URI it does not know is not pinned.

That is a complete, normative, machine-readable catalog already compiled into
every binary that depends on `vti-specs`. The bridge reads it; it writes no
descriptions of its own.

### 1.5 Authority at the VTC

The VTC has no contexts. Administrative authority is capability-based: an
entry holds a built-in role as a ceiling (`community-admin`, `moderator`,
`vetting-lead`, `repo-manager`, `credential-officer`, `auditor`, `approver`)
or a custom role, with explicit act scope and listed capabilities qualified by
resource (`docs/05-design-notes/vtc-admin-roles.md`). Every gate asks
`VtcAclEntry::can(capability, resource)`. `auth/whoami` names a caller's live
capabilities, and the console navigates by it. A member's authority is its
own key: the DID that joined, often a `did:webvh` persona minted by a VTA.

Several administrative writes do not complete on the call: they park on the
action list and wait for an approver (`vtc-action-list.md`, VTI-APV-018).
A bridge has to present "parked, awaiting approval" as an outcome, not a
failure.

## 2. Decisions

### D0. Native Trust Tasks, over TSP, then DIDComm, then HTTPS

The bridge is a Trust Task client. Every tool call — generic, convenience or
workflow — becomes one signed Trust Task document sent in-process by
`vtc-client`; there is no other kind of call. Three consequences:

- **No CLI underneath.** The bridge never spawns `cnm` or `pnm`, never
  parses their output, and does not take a CLI's stored login as its
  identity by default. A CLI is a different client of the same surface, not
  a layer the bridge sits on.
- **Transport follows the workspace rule** (TSP > DIDComm > REST). On
  connect the bridge reads the community's DID document and its own, and
  uses the highest-preference transport whose service `type` appears in
  both — `TSPTransport`, then `DIDCommMessaging`, then `VTARest`. The TSP leg
  rides the one mediator socket the DIDComm session already holds
  (`VtcClient::connect_tsp`); it is never a second socket. When the
  intersection is empty the bridge refuses with `NoMatchingProtocol`; it
  never downgrades past what the community advertises. `--transport
  auto|tsp|didcomm|rest` (`vta_sdk::TransportChoice`) pins one for
  diagnosis, and `vtc_status` reports which is in use.
- **HTTPS is the declared last resort**, for a community whose DID document
  advertises no messaging transport and for the one rung that has nothing
  else (D3, rung 3). Over HTTPS the document is still a signed Trust Task
  posted to the single document endpoint — never a bearer route, which the
  VTC does not serve behind any admin verb (#1641) — and `backup/*` is
  refused by the VTC there, so the catalog marks it session-only.

### D1. A separate crate, the same shape

`vtc-mcp/` (`publish = false`, stdio, `rmcp` 3) beside `vta-mcp/`, not a mode
of it. The two bridges have different clients, different catalogs, different
identity ladders and different operators. What they share — the risk
classifier, the guard, the confirm levels, the recorder, the annotation test —
moves to `vti-mcp-common` (`publish = false`), and `vta-mcp` is repointed at
it in the same change. Copying `guard.rs` would be a second thing to keep
correct; a policy fix in one bridge must reach the other.

The verb classifier (`classify`) already keys on the slug's last segment
(`list` / `show` → read-only, `create` / `update` → mutating, `delete` /
`purge` / `revoke` → destructive, `sign` / `release` → sensitive) and so
carries over. VTC-specific placements go in the shared table with a comment:
`backup/import` (it replaces the ACL) and the `acl/*/0.2` writes are
destructive or sensitive; `elections/certify`, `elections/tombstone`,
`members/admin-remove` and `rooms/*/prune` are destructive; `vetting/*`,
`endorsements/issue` and `credentials/*` are sensitive.

### D2. Generic by Type URI, catalogued from the specification

Tools:

| Tool | What it does | Risk |
|---|---|---|
| `vtc_list_operations` | Every pinned `vtc/*`, `rooms/*`, `auth/*`, `backup/*` task this bridge can send: slug, version, status and deprecation, description, the payload schema, declared error codes, risk class, **this bridge's policy decision**, and — when the identity is known — whether `auth/whoami` says the caller can send it | read-only |
| `vtc_call` | Send one task by Type URI with a JSON payload | *per operation* |
| `vtc_supported_tasks` | What the connected VTC actually serves (`trust-task-discovery/0.4`), glob-filterable | read-only |
| `vtc_whoami` | The bridge identity's entry: role, capabilities, act scope, member status | read-only |
| `vtc_status` | What this bridge is: identity, mode, transport, policy, counters, recent calls | read-only |

Rules for `vtc_call`:

- **Unpinned is refused.** A Type URI `vti_specs::schema_index` does not
  know is never sent, so a gate that reads `None` cannot fail open.
- **Checked before sending.** The payload is validated against the pinned
  payload schema (the same discipline as `read_checked` on receipt) and the
  reply is read against the response schema. A schema refusal names the
  property, so an assistant can correct its own call.
- **Deprecated versions warn, superseded versions refuse** unless `--allow`
  names them, read off the bundle's `deprecation` / `supersededBy`.
- **Errors are the VTC's.** A `trust-task-error` reply comes back with the
  declared code and message; the bridge adds the catalog's description of
  that code where the bundle has one. It never collapses a code into a
  string.
- **No retry in the bridge.** Over a session `VtaClient::idempotent` owns
  completion; over HTTPS the client's post is one attempt. The bridge is
  application code and holds no retry loop
  (`docs/05-design-notes/retry-and-idempotency.md`). No classification
  table is needed on the VTC side, and `vta_sdk::retry_safety` is not the
  place for one: that table is the VTA's dispatch-side dedup policy over the
  tasks the VTA serves. The VTC's receive pipeline claims every document's
  `id` before dispatching it and answers a redelivery with the recorded
  response, uniformly for every task, so what keeps a retry safe is the
  **same document** being resent — which is what the SDK's session retry
  does — never a per-task verdict.

**Landed (phase 1):** `VtcClient::send_task(type_uri, payload)` is the one
sender behind every admin verb, named by Type URI — over the mediated session
(TSP leg when enabled, else DIDComm) and only otherwise signed with the
configured `HolderKey` and posted; an unpinned or `#response` URI is
`VtcError::UnpinnedTask` and nothing is sent; the payload is checked against
the pinned schema first; the declared error codes and response size bound
come from the index. `VtcClient::discover(patterns)` asks
`trust-task-discovery/0.4` and `vtc_client::supported_type_uris` flattens the
answer; `VtcClient::transport()` reports the leg a call takes, for
`vtc_status`.

### D3. One identity, chosen by a ladder

| # | Mode | Flags | Transport | Authority |
|---|---|---|---|---|
| 1 | Member persona, `did:webvh` bundle | `--agent-secrets` + `--vtc-did` + `--mediator-did` | Mediated session: TSP, else DIDComm (D0) | **The member** (what a VTA-minted persona has) |
| 2 | Dedicated agent entry, `did:key` | `--agent-did` + `--agent-key` + `--vtc-did` + `--mediator-did` | Mediated session: TSP, else DIDComm (D0) | **The entry's role or listed capabilities.** Enrolled by an administrator with `acl/grant/0.2`, bounded by the granter's own holdings (§6.3 of the roles note); an `approver`-ceiling entry can approve, nothing more |
| 3 | Replayed `cnm` login | `--community <slug>` + `--allow-rest-session` | HTTPS, signed documents | **The operator.** Last resort for a community that advertises no messaging transport; `--confirm sensitive` is forced, the catalog hides `backup/*`, and `vtc_status` says so on every call |

Rungs 1 and 2 are the bridge. Rung 1 is what a person's own AI runs as: the
persona the VTA minted for them, holding its keys, on the mediator that
persona already uses. Rung 2 is what an administrator enrols for an
assistant they want bounded. Both are Trust Tasks over a mediated session,
the same as any other member of the community, so the VTC sees a sender it
can authenticate intrinsically and never a bearer. Rung 3 requires an
explicit opt-in flag precisely so that a bridge is never silently the
operator over REST; it is kept for the HTTPS-only community, not as a
convenience.

Rules carried over from `vta-mcp`, unchanged: the identity modes are mutually
exclusive; a half-configured rung fails naming the missing field and never
falls through to rung 3. The ladder is a VTC-side twin of `AgentConnect`
(`vtc_client::agent_connect`) rather than a parameterisation of it, because
the rungs differ: the two dedicated-identity rungs both ride the mediator,
and there is no bearer-token rung at all.

The bridge does not know whether it is "an admin bridge" or "a member
bridge". The entry it runs as decides; `vtc_whoami` reports it; the catalog
annotates each task with what that entry may send. An assistant asked to
"set up a group" by a member sees `vtc/groups/create` marked *not permitted*
and `vtc/groups/join` permitted, before it calls anything.

### D4. Approvals are an outcome

A write that parks on the action list returns the action id and the
approvers it waits on. `vtc_call` surfaces that as a structured
`{ "status": "parked", "action": … }` result, `vtc_actions_show` reads it
back, and the workflow prompts (D5) say up front which of their steps park.
An `approver`-ceiling bridge identity can decide actions with
`vtc_actions_decide` — the only write that identity has — which is the
pattern for a human's AI acting as a second administrator without holding
administration (APV-014).

### D5. Knowledge ships with the bridge

MCP has primitives for exactly this and the bridge uses all three:

- **Resources.** `vtc://guide/{groups,boards,elections,rooms,vetting,
  admission,directory,admin-access}` serve the operator guides from
  `docs/03-vtc/` (`groups.md`, `boards.md`, `elections.md`,
  `community-rooms.md`, `data-rooms-quickstart.md`, `vetting.md`,
  `join-criteria.md`, `member-directory.md`, `admin-access.md`) via
  `include_str!` — one source of truth, pinned at build to the binary's own
  version. Plus `vtc://operations` (the catalog), `vtc://whoami`,
  `vtc://status` and `vtc://calls/recent`, as `vta-mcp` has.
- **Prompts.** One per multi-step workflow, each an ordered list of the tasks
  to send, the preconditions to check first, which steps park on the action
  list, and what the member sees afterwards:

  | Prompt | Steps it orders |
  |---|---|
  | `setup-group` | `groups/create` (kind, join policy, visibility, whether it issues credentials) → `groups/managers/add` → bindings → the join or admit path for the first members |
  | `create-board` | `boards/create` → `boards/facilitators/add` → how members post and how a facilitator selects or hides a note |
  | `run-election` | `elections/create` with the manifest (`docs/03-vtc/elections.md`: questions, roll, trustees, ballot boxes) → open → `elections/close` → `elections/certify`; what a poll is in these terms |
  | `open-data-room` | `rooms/create` → access grants (room VACs) → `rooms/records/put` / files → who watches it and how an epoch is minted |
  | `admit-member` | join criteria → the join queue → `join/approve` or direct admission → the membership credential → what a new member can do first |
  | `grant-administration` | role ceilings → `acl/grant/0.2` → why it parks (APV-014) → the departed-granter review |

  Prompt text is short and procedural; it links the guide resource rather
  than restating it. A prompt is tested like the catalog: every task slug it
  names must be pinned.
- **Workflow tools.** Thin orchestrators for the same six flows
  (`group_setup`, `board_create`, `election_create`, `room_open`,
  `member_admit`, `admin_grant`), each sending its tasks through the same
  guard and recorder one at a time, stopping at the first refusal or parked
  step and reporting how far it got. They declare the Type URIs they send, so
  `--read-only` and `--deny` apply to them exactly as to `vtc_call`.

A Claude Code skill (`.claude/skills/vtc/` or a plugin) can wrap the same
prompts for hosts that read skills rather than MCP prompts; it links the same
guides and is not a second source.

### D6. The VTC is the authority

Nothing in the bridge grants access. The entry's role, capabilities, act
scope, the community's policy and the action list decide. The local guard
exists so that "always allow `vtc_call`" at the host does not make
`members/admin-remove` ride the same approval as `members/list`.

## 3. Rollout

| Phase | Deliverable | Where |
|---|---|---|
| 1 | **Done.** `VtcClient::send_task`, `discover`, `transport`; no retry table (see D2: the VTC dedups every task by document id) | `vtc-client` |
| 2 | `vti-mcp-common` extracted from `vta-mcp` (guard, confirm levels, recorder, annotation test), `vta-mcp` repointed | new crate, `vta-mcp` |
| 3 | `vtc-mcp`: ladder, transport selection by DID-document service type, guard, recorder, `vtc_list_operations` from the bundles, `vtc_call` with schema checks, `vtc_supported_tasks`, `vtc_whoami`, `vtc_status`, the five resources | new crate |
| 4 | The guide resources and the six prompts, with the pinned-slug test | `vtc-mcp` |
| 5 | The six workflow tools; `vtc_actions_show` / `vtc_actions_decide` | `vtc-mcp` |
| 6 | Operator page `docs/03-vtc/vtc-mcp.md`, a worked example, the skill | docs |

Phase 3 is usable on its own: a member or an administrator can drive every
pinned task from an assistant with nothing but the catalog. Phases 4 and 5
are what make the assistant good at it.

## 4. Open questions

- **Does the dedicated-agent rung need its own built-in role?** An `agent`
  ceiling (act as the granter, never grant, never approve) would make
  enrolling a bridge one command. The roles note's custom roles (§6.2) can
  express it today; whether it is common enough to build in is a maintainer
  call.
- **Is rung 3 worth keeping?** It exists for a community that advertises no
  messaging transport. If every community this workspace deploys advertises
  TSP or DIDComm, the rung is dead weight and a standing temptation to run
  as the operator; dropping it leaves the bridge with no REST path at all,
  which is the cleaner statement of D0.
- **Catalog size.** 294 pinned versions is a large tool description. The
  catalog tool takes a glob and a `summary` flag (slug, version, description,
  risk only) so an assistant can page it; the resource carries the full form.
