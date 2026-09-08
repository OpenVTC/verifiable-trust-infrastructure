# Managing the claim-type registry

Every attribute a holder keeps has a **type** — `name.legal`, `phone.mobile`,
`profile.github` — and that type decides three things about the value:

| axis | what it governs |
| --- | --- |
| `sensitivity` | whether the value is sent at all to a listing that did not ask for sensitive values |
| `release` | what it takes to let the value leave — approved once, or approved again each time |
| `mask` | how a client draws it when it draws it at all |

The agent answers those questions from the **claim-type registry**, and serves
the whole table at `persona/claim-types/list` so clients resolve against *this*
agent's answers rather than a copy compiled into their own build.

## The core table is not yours to edit

It is transcribed from the published registry
(`specs/persona/_shared/0.1/claim-types.json`) into `vta-persona`, and it is the
same in every deployment. That is the point of it: `gov.id.passport` means the
same thing to your agent and to a verifier you have never met.

## Your own vocabulary is

Set `VTA_CLAIM_TYPE_EXTENSIONS` to a JSON file and the agent serves your rows
alongside the core ones:

```json
[
  { "type": "profile.github", "sensitivity": "normal", "release": "consent", "mask": "none" },
  { "type": "employer",       "sensitivity": "normal", "release": "consent", "mask": "none" }
]
```

The rows are the shape the agent serves, so you can copy one out of
`persona/claim-types/list`, change it, and put it back. The `{"entries": [...]}`
wrapper the served document uses is accepted too.

Without this, a token the published registry has never heard of resolves to the
**floor** — withheld from every listing, masked in full — because a vocabulary
nobody has reasoned about is exactly the one nobody should render in the clear.
Declaring it here *is* that reasoning.

## What you may declare

**Anything the core table does not cover.** This is what the file is for.

**Tightenings of anything it does.** You may decide that in your deployment an
`email.work` is worth withholding entirely. That takes nothing away from anyone.

**Not loosenings.** A row may not resolve looser on any axis than the core table
already resolves for that token — whether it names the token exactly
(`email.work`) or covers it through a family (`payment.giftCard`, under
`payment`). A deployment cannot declare a passport unremarkable, and cannot
escape a gated family by inventing a member of it.

**Not `x:` tokens.** The extension namespace is unregistered by construction and
every client implements it that way, so a row declaring one would be a row no
client would honour.

## Getting a row wrong does not stop the agent

A row that cannot be read, carries an unknown axis value, repeats another, or
loosens a core row **is refused on its own**. The rest of the file applies, and
the agent starts.

That is a deliberate change from the first version, which exited. Refusing to
boot is right for a laptop and wrong for a hosted agent: it takes out sessions,
credentials and mediation over a mis-typed claim type, and nobody is reading its
stderr anyway.

**A refused row is not a small thing, though, and it fails in two directions.**
The token resolves as if you had never declared it — from the core table, or the
floor. For a word the registry has never heard of, that is the *most* protective
answer and no harm is done. For a row that meant to **tighten** a core type, the
looser answer stays in force: the tightening you believe is in place is not.

Nothing can make that safe except somebody seeing it, so a refusal travels:

- one `ERROR` log line per refused row, naming the token and the reason;
- carried on `persona/claim-types/list` under `ext["org.openvtc.claim-types"]`,
  as `rejected: [{ type, reason }]`, so the holder's console can say so where a
  person is actually looking;
- and `fileError` in the same place when the file itself could not be read —
  a different sentence, because then *nothing* you declared is in force.

A misspelt member or value is refused rather than defaulted: `"hgih"` silently
reading as `normal` would look exactly like a rule that was working.

When rows load the agent logs the path, the applied count and the refused count.
If a value is masked and you do not know why, that line and
`persona/claim-types/list` are the two places to look.

## What this is not

**Not runtime administration.** The file is read once, at startup. Serving a new
admin task to edit the registry live needs a published task specification first
— the dispatcher refuses to serve a URI the registry does not declare — so it is
an upstream change before it is one here.

**Not a per-holder decision.** A holder can override `sensitivity` and `release`
on one of their own attributes, and that outranks whatever the registry says,
core or extension. The registry is the default for a *type*; the override is a
decision about one *value*.
