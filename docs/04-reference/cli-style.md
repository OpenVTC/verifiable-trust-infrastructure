# CLI output style guide

Lightweight conventions the `pnm` and `cnm` CLIs (and any future
`vta_cli_common`-backed front-end) follow so operators see a consistent
surface. These exist to remove micro-decisions when adding new commands —
match the pattern that already works elsewhere in the workspace.

## Three output modes

Every user-facing command falls into exactly one of three modes:

### 1. List / search → ratatui table

For commands that return **multiple records** (`acl list`, `keys list`,
`contexts list`, `did-mgmt servers list`, `did-mgmt dids list`, `audit logs`,
`did-templates list`, `did-templates list-builtins`, …).

```text
┌─ Stored DID templates (global) (3) ──────────────────────────────────┐
│ Name             Kind              Required vars    Created          │
│                                                                       │
│ didcomm-mediator mediator          URL              2026-04-19 10:12 │
│ custom-agent     custom            URL, LABEL       2026-04-20 09:03 │
│ webvh-hosting    webvh-hosting     URL              2026-04-20 11:47 │
└───────────────────────────────────────────────────────────────────────┘
```

Rules:
- Bordered box, dim-grey border colour.
- Title format: `{Domain} ({count})` in the border.
- Bold white header row.
- Primary identifier column coloured cyan, metadata columns (created-by,
  timestamps, dim auxiliary text) in dark grey.
- Empty list → short plain-text message with a hint pointing at the
  scaffolding command (e.g. `create`, `init`) so operators aren't left
  guessing what to do next.

Implementation: use `ratatui::widgets::Table` composed manually, then
hand off to `vta_cli_common::render::print_widget(table, height)`.

### 2. Detail view → aligned key-value

For commands that return **one record** (`contexts get`, `keys get`,
`acl get`, `did-templates show`, `health`, `vta info`, …).

```text
ID:          my-app
Name:        My Application
DID:         did:webvh:example.com:abc
Base Path:   m/26'/2'/42'
Created At:  2026-04-19 10:12:33 +08:00
Updated At:  2026-04-20 09:03:11 +08:00
```

Rules:
- Labels on the left, values on the right, colon aligned within the
  block — use a fixed width matching the longest label.
- Missing optional fields render as `(not set)` or `—` (U+2014 em-dash),
  not blank.
- Timestamps in operator-local timezone with an ISO offset (use
  `vta_cli_common::duration::format_local_datetime`).
- A `--rendered` or `--raw` flag may emit pretty-printed JSON instead —
  useful for scripting (`jq` pipelines) or showing a DID document
  inside a template record. The decision is per-command, not workspace-
  wide.

### 3. Action → `✓`-prefixed confirmation

For commands that mutate state (`contexts create`, `keys revoke`,
`did-templates update`, …).

```text
✓ Created 'didcomm-mediator' (mediator) in global.
```

Rules:
- Green `✓` (U+2713) prefix, one short line on stdout.
- Subject in cyan, qualifier in dim grey inside parentheses where useful.
- Scope label (`global`, `context 'my-ctx'`) spelled out — don't make
  the operator guess where the change happened.
- Warnings that don't abort use a yellow `⚠` (U+26A0) prefix on stderr,
  with remediation hint lines indented two spaces.

## Removal verbs

A command that removes a record is named **`delete`**. Not `remove`, `forget`
or `disable` — one verb, so an operator never has to guess which synonym a
given subsystem picked.

- **Say what a delete leaves behind.** When `delete` is not a true, complete
  delete, the command prints a yellow `⚠` notice on stderr saying what remains
  and the command that removes it — or why it cannot be removed from here.
  Examples: `pnm vta delete` / `cnm community delete` forget the local
  connection and credential but leave the VTA's ACL entry (the notice prints
  the `acl delete <did>` that revokes it); `did-mgmt servers delete` drops the
  registry row but not the DIDs still registered against the server (the
  notice lists them); `vault delete` / `cred-vault delete` soft-delete by
  default (the notice gives the grace deadline, `restore`, and `--force`).
- **A bulk delete may keep a bulk name** — `wipe` (`pnm memory wipe`,
  `vta vault wipe`) or `delete-all` (`vta approvals delete-all`) — but its help
  text says it deletes every entry.
- **Keep the verb when the operation is not deletion.** `revoke` changes a key
  or credential's lifecycle state; `disable` / `enable` park and restore
  something that stays on record (`device disable`, `services * disable`,
  `did-mgmt agent-names disable`); `remove` edits a list inside a record that
  survives (`approvals remove`, `approvals approvers remove`) or releases a
  claim (`did-mgmt agent-names remove`); `cancel` stops a pending process
  (`services didcomm drain cancel`); `logout` ends a session.
- **Renames never break scripts.** The old name stays as a hidden clap
  `alias`; where the old name misdescribed the effect (`vta approvals
  disable`), it stays as a hidden subcommand that prints a note naming the new
  one. Trust Task URIs are specification names and are never renamed with the
  CLI (`spec/vta/webvh/servers/remove/1.0` stays).

## `--force` and `--yes`

- **`--yes` / `-y` skips a confirmation prompt**, and is the flag a
  non-interactive run passes to consent to a destructive command
  (`contexts delete`, `vta delete`, `community delete`, `memory wipe`,
  `vta vault wipe`, offline `vta did-mgmt dids delete`, `vta acl delete`). It
  never changes *what* is deleted.
- **On a delete, `--force` means "skip the soft delete"** — delete immediately
  and irreversibly — and only where a soft (recoverable) path exists
  (`vault delete --force`, `cred-vault delete --force`; `purge` is the same
  operation under its own name).
- Commands that took `--force` (or `-f`) to skip a prompt keep accepting it as
  a hidden alias of `--yes`, so existing scripts keep working. New commands do
  not add it.
- `--force` keeps its established, unrelated meanings outside deletion —
  replacing an existing output file or entry (`backup export --force`,
  `vta vault seed --force`), taking over a slot owned by another DID
  (`did-mgmt dids register --force`), skipping the pre-promotion handshake
  (`services didcomm {enable,update} --force`). Those are not prompt skips and are not affected by
  this rule.

## Error reporting

Never `eprintln!("Error: {e}")` from the top-level dispatch. Route
through `vta_cli_common::render::print_cli_error(&*e)` — it downcasts
to `VtaError` and emits actionable remediation hints for auth, network,
forbidden, validation, and server-error cases. Unknown error types fall
back to the raw message plus a `source()` chain walk.

## Colour codes

Import from `vta_cli_common::render`:

| Const   | Use                                          |
|---------|----------------------------------------------|
| `BOLD`  | Emphasis inside a line, used sparingly       |
| `CYAN`  | Primary identifiers (DIDs, names, key IDs)  |
| `GREEN` | `✓` success markers, active-state labels     |
| `YELLOW`| `⚠` warnings, tips                           |
| `RED`   | `✗` error markers, destructive warnings      |
| `DIM`   | Metadata, muted hints, help text             |
| `RESET` | Clear after every coloured segment           |

Every opening ANSI escape must be matched by `RESET` — don't trust the
terminal to pick the boundary up from the next coloured span.

## New commands

1. Pick the mode (list, detail, action).
2. Copy the shape from the closest existing command in the same mode.
3. Route errors through `print_cli_error`.
4. Match the help-text conventions in `docs/cli-help.md` (to come) — in
   particular `--context` semantics (filter / reference / lookup) must
   be spelled out on each command where the flag appears.
