### vta-service 0.14.23 / vta-cli-common 0.10.28 — the offline approvals break-glass (#915)

#914 retired `vta step-up`, which was the offline way out of an over-strict
`[auth.step_up]`. The lockout it recovered from did not go away — it moved. This
is the replacement, and the last open item from the trigger collapse.

Approvals are self-gating on purpose: `policy/*` is not exempt from the policy
gate, because two-person control over the gate *itself* is a feature. The cost is
a reachable, wire-unrecoverable lockout:

- a `consent` rule on `policy/upsert` whose approver set has rotated away;
- a rule that gates the very task you would use to remove it;
- a hand-authored Rego module that denies the `policy/delete` which would remove
  it;
- `enforcement = true` with no policy that decides — the gate default-denies, on
  purpose, and nothing on the wire can fix it.

#### New

```
vta approvals list                    # what this VTA requires, from the store
vta approvals remove <task-uri>       # drop one rule — the surgical fix
vta approvals disable                 # drop the row and every approver set
vta policy list [--show-module]       # hand-authored Rego
vta policy delete <id>
```

Same security model as every other `vta …` offline surface (`acl`, `keys`,
`services`, `vault`): direct fjall access, no auth ceremony, whoever holds the
filesystem holds this. Daemon must be stopped; not available in TEE.

#### Two choices worth stating

**Read-mostly.** There is no offline `require`. Adding a gate is never an
emergency, and a break-glass path that can install one is a way to plant a
control that never passed through the authenticated surface.

**`approvals list` names hand-authored modules.** The declarative view refuses to
show Rego it did not generate — a row whose module said something other than its
rules would make the printout a lie — but an operator diagnosing a lockout who
sees an empty rule list will otherwise conclude nothing is gating them. So the
listing names them and points at `vta policy list`.

#### Found while testing

The first draft was wrong in the same way twice: `list` and `disable` each parsed
the declarative row *before* acting, so neither worked on an unparseable row —
the state where every other command has already failed and this is all that is
left. `list` died with a bare serde error on the row it was being run to inspect;
`disable`, the hammer, refused to swing. Parsing is best-effort in both now:
`list` reports the row as unreadable and names the escape hatch, `disable`
deletes first and summarises only if it can.

Both surfaces render through one shared `render_model`, moved out of
`vta_cli_common::commands::approvals::cmd_list`. An operator diagnosing a lockout
is comparing what the offline command prints against what they remember
`pnm approvals list` printing; two implementations of "what does this VTA
require" would eventually disagree at exactly the moment that comparison matters.

Covered by seven unit tests over a real fjall store and four end-to-end tests
that drive the built `vta` binary against a real config file — the wiring, not
just the functions, because "correct function, subcommand never wired up" is a
failure an operator would otherwise discover mid-incident with no way in.

Docs: `docs/02-vta/approvals.md` §"If you lock yourself out" is now concrete
rather than a promise.
