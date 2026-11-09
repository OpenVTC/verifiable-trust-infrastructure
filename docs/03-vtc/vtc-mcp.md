# vtc-mcp — running or taking part in a community from an MCP host

`vtc-mcp` is a [Model Context Protocol](https://modelcontextprotocol.io) server
that exposes a Verifiable Trust Community as MCP tools, so an administrator's
or a member's AI assistant — Claude Code, Claude Desktop, an IDE, an agent
framework — can configure a community, run its ceremonies and read its state
with no custom integration code.

It is a **native Trust Task client, and the community is the authority**. Every
tool call becomes one signed Trust Task document, sent in-process over the
transport the community's DID document advertises, and the community decides
what happens. It never runs `cnm` or `pnm`, and it never takes a CLI's stored
login as its identity. This page is mostly about the consequences of those
sentences.

- Crate: `vtc-mcp/` (`publish = false`; build it yourself)
- Transport to the host: **stdio** — the host spawns the binary and speaks
  JSON-RPC over stdin/stdout
- Transport to the community: TSP, else DIDComm, else signed documents over
  HTTPS — read from the community's DID document (§4)
- Related: [vta-mcp](../02-vta/vta-mcp.md) (the same bridge for a VTA, whose
  guard this one shares), [administrators, roles and consent](admin-access.md),
  the design note `docs/05-design-notes/vtc-mcp.md`

---

## 1. What it exposes

Two generic tools cover the whole surface; the rest are the workflows the
operator guides describe, and the action list.

| Tool | What it does | Risk class |
|---|---|---|
| `vtc_list_operations` | The catalog of every Trust Task `vtc_call` can send — read from the pinned specification bundles, never hand-written: description, risk class, **this bridge's policy decision**, and (once the community has been asked) whether it serves the task. `detail: "full"` adds the payload schema and declared error codes | read-only |
| `vtc_call` | Send any pinned operation by Type URI with a JSON payload. A result with `status: "parked"` is not a failure (§2.3) | *per operation* |
| `vtc_supported_tasks` | What the connected community serves (`trust-task-discovery/0.4`) | read-only |
| `vtc_whoami` | What the community knows of this identity (`auth/whoami`), beside the configured identity | read-only |
| `vtc_status` | What this bridge is: identity, community, transport and whether it is reaching the community, how MCP is served, policy, counters, recent calls | read-only |
| `group_setup`, `board_create`, `election_create`, `room_open`, `member_admit`, `admin_grant`, `badge_create` | The workflows as thin orchestrators: each sends its steps in order, **every step through the bridge's policy under its own operation**, stops at the first step that is refused or parked, and reports how far it got with each step's answer | per step |
| `vtc_actions_list`, `vtc_actions_show` | The community's action list as this identity sees it; an action's summary re-derived from the payload that would run and verified, with the match code | read-only |
| `vtc_actions_decide` | Approve or deny a parked action as this identity. **Always** asks the operator, whatever `--confirm` says (§2.4) | sensitive |
| `vtc_actions_cancel` | Cancel an action this identity requested | mutating |

**Resources.** `vtc://status`, `vtc://operations` and `vtc://calls/recent`, as
`vta-mcp` has, plus the community's own operator guides — this documentation,
embedded at build time so the assistant reads the version the bridge was
built against:

| Resource | Guide |
|---|---|
| `vtc://guide/groups` | [Community groups](groups.md) |
| `vtc://guide/boards` | [Community boards](boards.md) |
| `vtc://guide/elections` | [Elections, polls and surveys](elections.md) |
| `vtc://guide/rooms`, `vtc://guide/rooms-quickstart` | [Community rooms](community-rooms.md), [Data rooms end to end](data-rooms-quickstart.md) |
| `vtc://guide/admission`, `vtc://guide/lifecycle`, `vtc://guide/vetting` | [Join criteria](join-criteria.md), [Membership lifecycle](community-lifecycle.md), [Vetting](vetting.md) |
| `vtc://guide/directory` | [Member directory](member-directory.md) |
| `vtc://guide/admin-access` | [Administrators, roles and consent](admin-access.md) |
| `vtc://guide/badges` | [Member badges](badges.md) |

**Prompts.** One per multi-step job, each an ordered brief: the preconditions
to check, the tasks to send in order, which of them **park** on the action
list and who approves, what the member sees afterwards, and the guides to read
first. Every task a prompt names is one `vtc_call` can send (a test holds each
to the pinned index).

| Prompt | Arguments (all optional) |
|---|---|
| `setup-group` | `name`, `purpose` |
| `create-board` | `title`, `audience` |
| `run-election` | `question`, `roll` |
| `open-data-room` | `label`, `members` |
| `admit-member` | `subject`, `role` |
| `grant-administration` | `subject`, `role` |
| `create-badge` | `name`, `kind` |
| `my-badges` | `code` |

Every tool carries MCP **tool annotations**; a test asserts each agrees with
the shared classifier's verdict on the operation the tool sends, so they cannot
drift.

---

## 2. The security model

### 2.1 Four layers, and which one is load-bearing

1. **Process spawn is the authentication boundary.** stdio means no listener
   and no authentication on the MCP channel itself: whoever can spawn the
   process, or read the host's MCP configuration, inherits the full standing of
   the configured identity. With `--listen` (§7.1) the boundary is the bearer
   token instead: whoever holds it, on this machine, inherits that standing.
2. **The identity decides whose standing that is.** Two rungs (§3), both a
   dedicated identity; there is no rung that replays an operator's login.
3. **The community is the policy decision point.** The entry's administrative
   role, its capabilities and their resource qualifiers, the community's own
   policies, and the action list (second-party consent) decide every call.
   None of that is reimplemented here.
4. **The bridge's own local policy** (§5) refuses or confirms individual
   operations before they are sent.

Layer 3 is the real one. Layers 1, 2 and 4 exist to keep its decisions
meaningful.

### 2.2 The gap layer 4 closes

**An MCP host approves a tool, not a call.** Once an operator answers "always
allow" to `vtc_call`, `vtc/members/admin-remove` rides the same approval as
`vtc/members/list`. The host cannot tell them apart; it sees one tool name. So
the per-operation decision is made here, where the URI is known — by the same
classifier `vta-mcp` uses (`vti-mcp-common`), which places every pinned Trust
Task as read-only, mutating, sensitive or destructive. The workflow tools send
each step under its own URI, so a workflow is gated exactly as the same steps
sent by hand.

### 2.3 Parked is an outcome

A write that needs other administrators' agreement — an authority-conferring
grant, a binding election, a referred admission, a group that carries
authority — is **parked** on the community's action list after the requester's
own step-up, and runs itself on the approval ([admin-access.md §3.2](admin-access.md)).
The bridge returns that as a *successful* call whose result says
`"status": "parked"` and names the action: nothing failed and nothing is to be
sent again. The prompts say up front which steps park; the workflow tools stop
there and report; `vtc_actions_show` follows it.

### 2.3a A step-up is yours, through a link

An authority-changing act — a grant, a role change, a join criterion — also
takes your own step-up, bound to that one operation (VTI-APV-015). The bridge
signs with a key you delegated, and a delegated key can redeem a step-up but
never make one. So when you hold a step-up approver, such as the browser
plugin's, the community hands the step-up to your wallet instead. The bridge
returns a *successful* call whose result says `"status": "stepUpRequired"` and
carries a `step-up` link (VTI-LNK-125 – VTI-LNK-131):

1. Open the link in your wallet, or scan it as a QR code. It expires within
   five minutes.
2. Your wallet reads the step-up from the community itself, signed by the
   community and addressed to you, together with the operation exactly as
   the bridge sent it. It checks that the two belong together, and shows you
   what will be done.
3. Approve there. Your wallet answers the community directly, as you; nothing
   comes back through the bridge.
4. Ask the assistant to send the identical call again. It goes through.

The link can be opened once. If it has expired or was used, the call is simply
sent again for a new one. A workflow tool stops at that step and reports the
link in its progress. Administrators whose only factor is a passkey get no
link; they finish the act in the console.

### 2.4 Deciding is vouching

`vtc_actions_decide` signs a `task-consent/decision` as this identity — the
same decision an administrator makes from the console, their wallet or `cnm`.
That is this identity vouching for someone else's authority, so the bridge
treats it apart from every other call: the action's summary is **re-derived
from the payload that would run** and refused on any mismatch, and the
operator is **always** asked to confirm through the host, shown the verified
title, effect and fields and the six-digit **match code** to compare with the
one the requester sees — whatever `--confirm` says. A host that cannot ask gets
a refusal, never an unconfirmed decision. The usual least-privilege shape is
an entry of the `approver` role (acts nowhere, approves as granted), which is
exactly what a human's assistant acting as a second administrator should hold.

### 2.5 What the bridge does not protect you from

- **A host that is itself compromised.** It holds the process; it holds the
  identity's standing. Scope the identity (§3), not the flags.
- **The identity being too wide.** `--read-only` on a bridge whose entry is a
  `community-admin` is one restart away from not being read-only. The
  community enforces the entry; the bridge enforces flags.
- **Text the community sends back.** A group's name, a board note, a card
  value and a room's profile are text other people wrote. The assistant must
  treat them as data, never as instructions; the bridge cannot make it.

### 2.6 Key material on the command line

`--agent-key` and an inline `--agent-secrets` JSON blob are readable by any
process on the machine. The flags stay supported and the bridge warns when it
sees one; prefer the matching `VTC_MCP_*` environment variable, or a file path
for `--agent-secrets`.

### 2.7 One agent key per community

An agent key is a DID every community it signs in to records — in its audit
trail, its list of your signing keys, its delegations. Two communities that
see the same agent DID can tell that the same assistant, and so the same
person, stands behind both: a correlation no protocol step prevents, and that
neither community can see on its own. Mint one key per community
(`vtc-mcp --mint-did-key`) and never point one at a second `--vtc-did`.

The bridge keeps a local note of the communities each agent DID was used with
(`$VTC_MCP_STATE_DIR`, else `$XDG_STATE_HOME/vtc-mcp`, else
`~/.local/state/vtc-mcp`; file `agent-communities.json`, owner-only, DIDs
only, never key material). When a key it has seen with one community is
pointed at another, it logs a warning and `vtc_whoami` / `vtc_status` carry it
as `keyReuseWarning`. It warns rather than refuses, since an operator may mean
it; `--no-key-reuse-check` (`VTC_MCP_NO_KEY_REUSE_CHECK`) turns the note off.

---

## 3. Identity

Exactly one, chosen by what is configured and never by falling through: both
given is an error, half of rung 2 is an error naming the missing field, and
neither serves in degraded mode (§6) so `vtc_status` can say what is wrong.

### 3.0 Your own assistant: sign in as yourself

For your own assistant, do not enrol anything. Give the bridge a key of its own
and sign it in through your wallet, exactly as the member portal and the
operator console sign you in:

```bash
vtc-mcp --mint-did-key            # keep privateKeyMultibase; enrol nothing
VTC_MCP_AGENT_KEY=z3u2… vtc-mcp --agent-did did:key:z6Mk… --vtc-did did:webvh:…
```

Then, in the session:

1. `vtc_sign_in` (with `audience: "admin"` for the operator console) opens a
   sign-in request signed by the bridge's key and returns the **trigger link**.
2. Open the link in the browser that holds your wallet, or scan it from a
   phone wallet. The wallet shows the community, the bridge as the starter
   (`vtc-mcp/<version>`), and a match number.
3. `vtc_sign_in_finish` answers with the same **match number**; approve in the
   wallet only if the two agree, then call it again for the session.

What you then hold, and nothing more:

- **As a member**, the bridge's key is delegated to sign the member portal's
  task families — the directory, boards, badges, … — as you, until the
  grant's expiry. The delegation confers nothing of its own: every document is
  read with your standing at that moment, and it never covers `auth`, `acl`,
  `consent`, `task-consent` or `confirm`.
- **As an administrator**, give the bridge's key a **signing-key delegation** of
  your identity — the same delegation the console's key holds. The wallet
  sign-in is not needed for this:

  1. `vtc_enrol_signing_key` with no arguments answers with the bridge's DID
     and how to sign the authorization.
  2. Sign it as the administrator. If your identity lives in your wallet,
     sign in to the console with the wallet and open **Console signing keys →
     Authorize another key**: give it the bridge's DID, a label and how many
     days (at most 30), and your wallet signs the authorization as you. Copy
     it, or download `authorization.json`. If `cnm` holds your
     administrative identity, it signs the same document offline:

     ```bash
     cnm access authorize-key did:key:z6Mk… --label "vtc-mcp" --expires 30d \
         --out ~/.config/vtc-mcp/authorization.json
     ```

  3. `vtc_enrol_signing_key` with `authorization` set to the JSON, or
     `authorization_file` set to the saved file. The bridge sends
     `auth/signing-key/enroll/0.2`, signed by its own key, with your
     authorization inside.

  From then on every document the bridge signs is authorized by your
  administrative standing, read at every call. The delegation creates no
  access-control entry, expires within 30 days, appears in the console's list
  of your signing keys, and is revoked on its own. It can never approve an
  action or answer a step-up: those stay with your own factor (§2.3a). The
  authorization is single-use, usable only by the key it names, and lapses an
  hour after it is signed unless sent.

  An `admin` wallet sign-in still works, and gives the bridge's key your
  console session so `vtc_whoami` answers for it; it confers no
  administrative writes on its own, and a console session idles out (15
  minutes by default) because a signed document does not refresh it.

The request presents the community portal's own origin and names the bridge
as its user agent; the protection the origin check gives — another website
cannot start a sign-in through your browser — is unaffected, and the wallet's
match number is what binds the approval to this bridge.

### 3.1 Rung 2 — a dedicated agent entry (an administrator's assistant)

The bridge speaks as an Ed25519 `did:key` an administrator enrolled, bounded
by the role ceiling or the listed capabilities of that entry. Minting the key
is the bridge's own job, so no key is ever handed from one person to another:

```bash
# 1. On the machine that will run the bridge: mint the identity. Keep the key.
vtc-mcp --mint-did-key
# {
#   "did": "did:key:z6Mk…",
#   "privateKeyMultibase": "z3u2…",
#   ...
# }

# 2. An administrator enrols the DID, least privilege. Three usual shapes:
#    an approver (acts nowhere, approves what it is granted to approve):
cnm access grant did:key:z6Mk… --admin-role approver --approve-only \
    --label "assistant (approver)" --expires 30d --reason "…"
#    a moderator narrowed to the join queue:
cnm access grant did:key:z6Mk… --admin-role moderator \
    --capability vtc.join.decide --label "assistant (joins)" --expires 30d --reason "…"
#    a group manager for one group:
cnm access grant did:key:z6Mk… --admin-role community-admin \
    --capability vtc.groups.manage@group:grp_… --label "assistant (gardeners)" --reason "…"

# 3. Run the bridge as that identity.
VTC_MCP_AGENT_KEY=z3u2… vtc-mcp \
    --agent-did did:key:z6Mk… \
    --vtc-did did:webvh:…:vtc.example.com
```

Granting an authority-conferring capability parks for another administrator's
consent, and every grant is bounded by the granter's own entry
([admin-access.md §1.2](admin-access.md)): the bridge can never hold more than
the person who enrolled it. An `--expires` keeps the enrolment from outliving
its use; `cnm access revoke` ends it.

### 3.2 Rung 1 — a member's own persona

A member runs the bridge as the persona they joined the community with: the
`did:webvh` their VTA minted, whose secrets bundle (`#key-0` signs, `#key-1`
decrypts) they hold — the `DidSecretsBundle` JSON a provisioned identity's
sealed bundle opens to ([provision-integration](../02-vta/provision-integration.md),
the `ai-agent-peer` template). The persona must be a member: it joined the
community through the join ceremony (which the bridge can submit as the
persona, `vtc/join-requests/submit`) or an administrator admitted it.

```bash
VTC_MCP_AGENT_SECRETS=/path/to/persona-bundle.json vtc-mcp \
    --vtc-did did:webvh:…:vtc.example.com
```

The bridge then has **the member's** standing and nothing more: it reads the
directory as that member sees it, proposes to boards, joins open groups,
accepts room offers, and asks the community what it serves. A member's
persona holds no administrative role, so the administrative tools answer
`permissionDenied` from the community — which is the community saying so, not
the bridge.

---

## 4. Transport

The community's DID document is authoritative for which protocols it speaks,
matched on service **type**: `TSPTransport`, `DIDCommMessaging`, `VTCRest`.
`auto` (the default) opens a TSP session where one is advertised (the TSP leg
of the one mediator socket, for a persona), else a DIDComm session, else posts
signed documents to the advertised HTTPS endpoint. **A session the community
advertises is never silently replaced by HTTPS**: when it cannot be opened the
bridge serves degraded, naming what was advertised and what failed.
`--transport tsp|didcomm` pins one; `--transport rest` posts signed documents
regardless, for a diagnosis. `vtc_status` reports which is in use.
`--vtc-url` supplies the HTTPS base only when the document advertises none.

---

## 5. Hardening flags

| Flag | Env | Effect |
|---|---|---|
| `--read-only` | `VTC_MCP_READ_ONLY` | Refuse anything not `read-only`, whatever the entry permits |
| `--allow <glob>` | `VTC_MCP_ALLOW` | Permit only these slug globs. Repeatable; comma-separated in the env var. When set, everything else is refused |
| `--deny <glob>` | `VTC_MCP_DENY` | Always refuse these. Checked **before** `--allow` |
| `--confirm <level>` | `VTC_MCP_CONFIRM` | Which classes need a human: `never`, `destructive` (default), `sensitive`, `always` |
| `--no-key-reuse-check` | `VTC_MCP_NO_KEY_REUSE_CHECK` | Keep no note of which community each agent key was used with, and so give no warning when one is reused (§2.7) |

Globs are `*`, a family (`vtc/groups/*`), or an exact slug, matched against
the part after `https://trusttasks.org/spec/`. Confirmation uses MCP
elicitation: the host shows a yes/no prompt naming the operation and its risk
class; read-only calls are never confirmed, and a host that cannot ask gets a
refusal, not a pass. Invalid policy values are fatal at startup; connectivity
failures are not (§6).

```bash
# A member's assistant that can only read.
vtc-mcp --agent-secrets persona.json --vtc-did … --read-only

# A groups manager's assistant: the groups family, confirm what moves authority.
vtc-mcp --agent-did … --vtc-did … --allow 'vtc/groups/*' --confirm sensitive

# An approver: nothing but the action list; deciding asks every time anyway.
vtc-mcp --agent-did … --vtc-did … --allow 'vtc/admin/actions/*,task-consent/*'
```

---

## 6. Seeing what it is doing

- **stderr** carries one start line and one finish line per call, with the
  tool, operation, risk class, policy decision, duration and outcome.
  `--log-level`, `--log-format text|json`; `RUST_LOG` wins when set.
- **`--audit-log <path>`** appends one redacted JSON record per call to an
  owner-only file.
- **`vtc_status` and `vtc://calls/recent`** answer from inside the session:
  the last hundred calls, redacted, without an audit file having been
  configured.
- **`connected` is earned, not latched.** It is true while the bridge has a
  session and no transport failure has happened since the community last
  answered; one failed call (the mediator unreachable, the socket gone and
  not reopened) turns it false, and the next answer — success, refusal or
  parked — turns it back. `transportHealth` gives `lastReachedAt`,
  `lastFailureAt` and `lastFailure`; `serving` says `stdio` or the `--listen`
  URL.
- **Redaction is an allowlist.** A string survives in a record only under a
  known identifier key (`groupId`, `subject`, `electionId`, …); anything else
  is elided, so a note or a card value never reaches a log.
- **Degraded mode.** A bridge that cannot connect — nothing configured, a
  half-configured rung, a community whose session could not be opened — still
  serves MCP: `vtc_status` reports the configuration it tried and every other
  tool returns that reason, rather than the host showing no tools at all.

---

## 7. Host configuration

```json
{
  "mcpServers": {
    "community": {
      "command": "vtc-mcp",
      "args": [
        "--agent-did", "did:key:z6Mk…",
        "--vtc-did", "did:webvh:…:vtc.example.com",
        "--confirm", "sensitive",
        "--audit-log", "/Users/me/.local/state/vtc-mcp/audit.jsonl"
      ],
      "env": { "VTC_MCP_AGENT_KEY": "z3u2…" }
    }
  }
}
```

Keep the key in `env`, not `args`. Every flag has a `VTC_MCP_*` environment
equivalent.

### 7.1 Several assistant sessions: one shared bridge (`--listen`)

A host started as above spawns its own bridge. Two of them with the same agent
key — two assistant sessions — is two mediator sockets for one DID, and the
mediator keeps one: each eviction is followed by a reconnect that evicts the
other, and a reply the mediator flushes onto the other process's socket is
deleted once written, so the call waiting for it fails though the community
did the work. Do not run the same key in two stdio bridges.

Run one bridge for the machine instead, and point every host at it:

```sh
# Once, as a long-running process (a launchd agent or systemd user unit):
VTC_MCP_AGENT_KEY=z3u2… vtc-mcp \
  --agent-did did:key:z6Mk… \
  --vtc-did did:webvh:…:vtc.example.com \
  --confirm sensitive \
  --listen 127.0.0.1:7465
# → serving MCP over loopback HTTP  url=http://127.0.0.1:7465/mcp
```

```json
{
  "mcpServers": {
    "community": {
      "type": "http",
      "url": "http://127.0.0.1:7465/mcp",
      "headers": { "Authorization": "Bearer ${VTC_MCP_LISTEN_TOKEN}" }
    }
  }
}
```

- **One session, every host.** The bridge holds one community session and
  gives each MCP session its own view of it; replies are routed to the request
  waiting for them however many hosts are calling. A confirmation (`--confirm`)
  or a decision is asked of the host that made the call. The guard, the audit
  log and an open wallet sign-in are the bridge's, shared by every host.
- **Loopback only.** Any other address is refused at startup.
- **A bearer token on every request.** `VTC_MCP_LISTEN_TOKEN` (at least 32
  characters), else the file `listen-token` in the state directory
  (`$VTC_MCP_STATE_DIR`, else `$XDG_STATE_HOME/vtc-mcp`, else
  `~/.local/state/vtc-mcp`), created owner-only on first start. A token file
  anyone else can read is refused. Give the hosts the same token, through the
  environment the host expands in `headers` — never written into a project's
  checked-in `.mcp.json`. Whoever holds it acts with the bridge's standing, so
  rotate it by deleting the file and restarting.
- **No browsers.** A request with an `Origin` header is refused, and the
  `Host` must be a loopback name, so a web page cannot reach the port.
- **Confirmations work over HTTP.** The bridge serves MCP up to `2025-11-25`:
  `2026-07-28` forbids the server-to-client request a confirmation is, so a
  host that asks for it is refused and falls back to a version that can ask
  you. After upgrading the bridge, reconnect the host once (`/mcp` in Claude
  Code) so it renegotiates.
- **Stops cleanly** on SIGINT or SIGTERM, closing every MCP session and then
  the community session.

**The skill.** `vtc-mcp/skills/vtc-community/SKILL.md` is a Claude Code skill
that teaches an assistant how to work through this bridge: start with status,
whoami and supported tasks; read the catalog's schema before a call; use the
prompt or workflow tool for a multi-step job; parked is not failed; read the
guide first. Copy it under `.claude/skills/` in a project, or
`~/.claude/skills/`, beside the server entry above.

---

## 8. A worked example: a new group, with a second administrator

An administrator's assistant, enrolled as in §3.1 with `vtc.groups.manage`.

1. **Orientation.** `vtc_status` says connected, over TSP, as `did:key:z6Mk…`.
   `vtc_supported_tasks` lists what the community serves; the catalog now
   marks each entry served or not. `vtc_whoami` answers the configured
   identity only — the community answers `auth/whoami` for a sign-in session's
   key, and this is not one.
2. **The brief.** The host loads the `setup-group` prompt with
   `name: Gardeners`. It lists the preconditions (`[groups]` configured, the
   capability held), the steps in order, and that `vtc/groups/bindings/add`
   with a `grants` binding parks.
3. **The shape.** `vtc_list_operations` with `patterns: ["vtc/groups/create"]`
   and `detail: "full"` gives the payload schema: `name`, `kind`, `visibility`,
   `showMembers`, `reason` required; `joinPolicy` for a static group.
4. **The flow.** `group_setup` with the create payload, one manager by directory
   entry id, and a `grants` binding conferring `vtc.invitations.manage`. The
   report lists `vtc/groups/create` ok with the new `groupId`,
   `vtc/groups/managers/add` ok, and `vtc/groups/bindings/add` **parked** with
   an action id — and stops, because what follows would add members to a group
   that now carries authority.
5. **The second administrator.** Their own assistant, enrolled as an
   `approver`, runs `vtc_actions_list` and sees the binding waiting.
   `vtc_actions_show` gives the verified summary — the group, the capability —
   and the match code; `vtc_actions_decide` with `approve: true` puts that
   summary and code in front of the person, who compares the code with the one
   the first administrator reads out, and confirms. The response says
   `granted`; the binding runs.
6. **Carrying on.** The first assistant sends `vtc/groups/members/add` by
   `vtc_call` for each member — now each parks too, as the group confers
   authority — and `vtc/groups/show` to read the result. Each step is in
   `vtc://calls/recent` and the audit file, redacted.

---

## 9. Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| The host lists **no tools** | The server exited before speaking MCP: a bad `--confirm` value or an unopenable `--audit-log` | Read the host's MCP server log; both are fatal by design |
| Every tool returns "not connected to its community" | Degraded mode (§6) | The message names what is missing or what failed; fix and restart |
| `no usable transport to <did>: the community advertises TSP but no session could be opened` | The advertised mediator did not answer | Fix the mediator; `--transport rest` posts signed documents for a diagnosis |
| `will not send <uri>: not a Trust Task version this client pins` | The URI is not in the pinned index | Take the URI from `vtc_list_operations`; a version the community serves but this build does not pin needs a newer build |
| `invalid request payload: does not conform to …` | The payload fails the task's schema, locally, before anything is sent | Read the schema with `detail: "full"`; an unset optional member is absent, never `null` |
| `permissionDenied` from the community | The entry does not hold the capability, or a member persona was asked an administrative task | `vtc_whoami`; ask the administrator who enrolled the entry |
| A result says `parked` | Second-party consent (§2.3) | Not an error; follow the action, do not resend |
| `this MCP host cannot ask you (it does not support elicitation)` | `--confirm`, or `vtc_actions_decide`, needs a prompt the host cannot show | `--confirm never` or `--allow` for ordinary steps; a decision has no such override — use a host that can ask |
| Calls fail or time out only while a **second assistant session** is open | Two stdio bridges on one agent key: two sockets for one DID (§7.1) | One bridge with `--listen`, or a separate key per session |
| `401` from the bridge's URL | No `Authorization: Bearer` header, or a different token | The host's `headers` must expand to the bridge's token (§7.1) |
| `--listen …: only a loopback address is served` | A non-loopback `--listen` address | `127.0.0.1:<port>` or `[::1]:<port>` |

---

## 10. What this is not

- **Not a policy engine.** The community holds that. The local guard gates on
  URI shape only.
- **Not a substitute for scoping the entry.** The flags bound a process; the
  entry bounds an identity.
- **Not a way round consent.** A parked action waits for a person who is not
  the requester; `vtc_actions_decide` is that person's assistant asking them,
  never deciding for them.
- **Not a wrapper around `cnm`.** It speaks Trust Tasks itself, over the
  transport the community advertises, as one identity it holds.

---

## 11. Not built yet

- **Approving someone else's action** is a decision signed by your own DID,
  which a delegated key may not sign: use the console, your wallet or
  `cnm consent approve`.
