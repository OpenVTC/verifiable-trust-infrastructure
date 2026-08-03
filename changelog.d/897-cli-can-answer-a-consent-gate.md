### vta-sdk 0.21.6 / vta-cli-common 0.10.24 / vta-service 0.14.8 — a CLI can answer a consent gate (#897)

A `requireConsent` rule made the task it gates unreachable from the command
line. `pnm` printed

```
✗ Protocol error: trust task failed [taskFailed]: task failed: auth:consent_required
```

and exited. No digest, no instruction, no way to proceed — so an operator whose
policy gated `webvh/dids/update` could not manage those DIDs from the CLI at
all, however privileged. The browser extension implemented the approval loop;
nothing in Rust did.

A consent refusal is not a dead end. It is a question the VTA is holding an
answer for, and everything needed to answer it was already on the wire — the
SDK was throwing it away.

## The refusal is now something a caller can act on

`trust_task_error` folded every rejection into `VtaError::Protocol(String)`,
discarding `details`. `VtaError::ConsentRequired` now carries `payload_digest`,
`challenge`, `approver_set`, `min_approvals` and `exclude_requester`.

Detection keys on `details.reason`, which is where the gate puts the
machine-readable answer precisely so consumers do not key on the top-level
`code` (`taskFailed` for every gated task) or the free-text message.

## `excludeRequester` is now reported

The gate knew whether the requesting device may approve its own request and did
not say. Without it a CLI must blind-attempt a self-approval and read
`denied:requester_excluded` back, so it cannot tell the operator whether to
approve *here* or on *another device* — the one thing they need to know. The
field is added to the rejection details.

This reveals policy shape to a caller that has already authenticated and just
triggered the rule. It grants nothing; the gate still decides every approval.
The SDK defaults it to `true` when absent, so an older server produces "use
another device", which is correct wherever a second device exists.

## Waiting, without turning a refusal into a nag

`vta_cli_common::consent::with_consent` wraps a submit and waits. Shared with
the offline `vta` binary so both CLIs behave identically.

There is no read-only status surface for task-consent, so "approved yet?" can
only be asked by submitting again — and whether that is safe depends on state
in a way that is easy to get wrong:

- **Pending**: the gate recognises the payload, returns the *same* `challenge`,
  and deliberately does not re-notify. The push follows the question, not the
  submit. Polling cannot ring the approver's device.
- **Denied or lapsed**: the pending record is **deleted**. The next submit finds
  nothing, raises a *new* question, and pushes again.

So the loop stops the instant the challenge changes. Continuing would convert a
"no" into repeated prompts — the habituation attack the gate's own design notes
call out, where a prompt an attacker can summon on demand is worth more than one
they must wait for. One re-prompt after a denial is unavoidable without a
server-side status task; an unbounded stream is not.

The timeout is bounded because an operator is sitting at a terminal, and giving
up is not failure: the request stays pending, so re-running resumes on the same
challenge.

## Testing

- Five loop cases: approval lets the task through; an ungated task submits
  exactly once; **a changed challenge stops the loop** (asserting the call count,
  so a regression that keeps polling fails); the wait is bounded; a non-consent
  error propagates instead of reading as "still waiting".
- Three SDK cases from the gate's real rejection shape: the refusal carries what
  answering needs; an absent `excludeRequester` defaults to the restrictive
  reading; a non-consent failure with a `details` object stays a `Protocol`
  error, so the new variant cannot swallow unrelated rejections.

Note the SDK tests need `--features client` — the module is feature-gated, and
without it they compile out and pass vacuously. `--lib` alone reported an
unchanged 239.

## Scope

Remote approval only: the CLI shows the code and waits for a device. Letting the
CLI approve its own request needs a `task-consent/decision/0.1` signer, which
exists in no client crate; that is the single-operator posture
(`exclude_requester = false` with the CLI's DID in the approver set) and is
tracked separately. Wired into `did-mgmt dids edit` here; the helper is generic
and other gated commands can adopt it.
