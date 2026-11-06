# CLAUDE.md — vtc-mcp

Crate guidance. The workspace `CLAUDE.md` applies too.

## What this crate is

(The crate's full entry from the workspace `CLAUDE.md` crate map.)

MCP server bridging a Verifiable Trust Community to MCP tools over stdio, for a member's or an administrator's AI assistant. A native Trust Task client: every tool call is one signed document `vtc-client` sends in-process over the transport the community's DID document advertises (TSP > DIDComm > HTTPS, `VtcClient::connect_resolved`) — never a `cnm`/`pnm` subprocess, never a CLI's stored login. Two generic tools (`vtc_list_operations`, catalogued from the pinned specification bundles; `vtc_call`) plus discovery, whoami and status. Runs every call through the guard and recorder in `vti-mcp-common`. Design: `docs/05-design-notes/vtc-mcp.md`. `publish = false`

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
