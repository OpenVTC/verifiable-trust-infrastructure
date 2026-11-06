# CLAUDE.md — vtc-mcp

Crate guidance. The workspace `CLAUDE.md` applies too.

## What this crate is

(The crate's full entry from the workspace `CLAUDE.md` crate map.)

MCP server bridging a Verifiable Trust Community to MCP tools over stdio, for a member's or an administrator's AI assistant. A native Trust Task client: every tool call is one signed document `vtc-client` sends in-process over the transport the community's DID document advertises (TSP > DIDComm > HTTPS, `VtcClient::connect_resolved`) — never a `cnm`/`pnm` subprocess, never a CLI's stored login. Two generic tools (`vtc_list_operations`, catalogued from the pinned specification bundles; `vtc_call`) plus discovery, whoami and status. Runs every call through the guard and recorder in `vti-mcp-common`. Docs: `docs/03-vtc/vtc-mcp.md` (operator page), `docs/05-design-notes/vtc-mcp.md` (design); the Claude Code skill is `skills/vtc-community/SKILL.md`. `publish = false`

## Rules

- **The catalog is the specification.** `vtc_list_operations` reads every
  entry — description, schema, error codes — from `vti_specs::schema_index`.
  Never hand-write a description of a task, and never add a typed wrapper
  per family: `vtc_call` over `VtcClient::send_task` is how every family is
  reached, the ones with no typed client (`vtc/groups/*`, `vtc/directory/*`,
  `vtc/notifications/*`) included.
- **Unpinned is refused.** A Type URI the index does not know is never sent
  (`VtcError::UnpinnedTask`); `None` from the index means "not pinned", never
  "nothing to check".
- **A session the community advertises is never replaced by HTTPS.** `auto`
  errors with what was advertised and what failed; `--transport rest` is the
  operator's explicit way to post signed documents for a diagnosis.
- **A parked operation is an outcome.** `VtcError::Parked` becomes a
  successful result with `status: "parked"` naming the action; it is never
  an error and never resent.
- **One identity, no fall-through.** Rung 1 (bundle) or rung 2 (`did:key`);
  both or half is an error; nothing serves degraded. There is no rung that
  replays an operator's login, and none is to be added.
- **Placement decisions live in `vti-mcp-common`.** This crate keeps what is
  the community bridge's alone: its tools, their annotations (asserted
  against the shared classifier), the ladder, the catalog.
- **The guides are the docs, embedded** (`src/guides.rs`, `include_str!` of
  `docs/03-vtc/*.md`): never a second description of the community. Editing
  a guide changes what this bridge serves at its next build; a guide moved or
  renamed breaks the build, which is the point.
- **A prompt names only pinned tasks.** Every slug in a workflow's steps or
  in backticks in its text is held to `vti_specs::schema_index` by
  `every_slug_a_prompt_names_is_pinned`. A prompt is procedural and short —
  preconditions, ordered steps, which park and for whom, what the member sees
  — and links the guide rather than restating it.
- **A workflow tool is a thin orchestrator** (`src/workflows.rs`): it sends
  the steps of one workflow in order, each through `begin` under its own
  Trust Task URI (so `--read-only`, `--deny` and `--confirm` apply per step),
  stops at the first step that is refused, parked, refused locally or
  declined, and returns how far it got. It takes a step's payload as the
  task's own JSON and derives only the identifiers later steps need from the
  answers; it never builds a payload the specification does not describe, and
  never retries. `every_workflow_uri_is_pinned` holds its URIs.
- **Deciding an action always asks the human.** `vtc_actions_decide` re-derives
  the action's summary from the payload that would run (`verify_action`),
  refuses on any mismatch, and puts the summary and match code in front of
  the operator through the host whatever `--confirm` says; no host, no
  decision. The decision is this identity vouching for someone else's
  authority (`task-consent/decision` is `Sensitive` in the shared table).
