# Security policy

## Reporting a vulnerability

Please report security problems **privately**, not in a public issue, pull
request or discussion.

Use GitHub's private vulnerability reporting on this repository: open the
**Security** tab, then **Report a vulnerability**. Only the maintainers can see
the report.

Include what you can of:

- the crate(s) and version, release name (e.g. `VTI-Eucalyptus`) or commit;
- what an attacker can do, and what they need first (a DID, an ACL entry, a
  network position, …);
- how to reproduce it: steps, a request, a test, or the code path read;
- where the behaviour departs from the
  [VTI specification](https://trustoverip.github.io/dtgwg-vti-spec/) or a
  Trust Task's specification, if it does;
- any disclosure date you are working to.

## What happens next

We acknowledge the report, confirm or dispute it with you in the private
advisory, and fix it — on `main` and on every supported release — before
anything is published. The advisory is published once a fixed version is
available, crediting you unless you ask us not to.

## Supported versions

Security fixes are backported to the named releases that are supported under
[RELEASES.md](RELEASES.md#support):

| Release | Supported |
|---|---|
| Fig | yes, once released |
| Eucalyptus | yes |
| Dogwood and earlier | no |

`main` (and the crates release-plz publishes from it) always receives the fix
first. The schedule table in [RELEASES.md](RELEASES.md#schedule) is the
authority on which releases are currently supported.
