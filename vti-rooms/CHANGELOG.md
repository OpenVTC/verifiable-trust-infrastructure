# Changelog

Notable changes to the published crates. Generated from conventional commits by
[git-cliff](https://git-cliff.org) when a release is cut — do not edit by hand.
## [0.1.2](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-rooms-v0.1.1...vti-rooms-v0.1.2) — 2026-09-07


### Fixed

- **rooms**: Authorize registering a room, which nothing did ([#1274](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1274))

`rooms/create/0.1` was the one verb neither host authorized. The document's
  proof was never verified on that path and the signer was never compared to
  `ownerDid`, so anyone who could reach the endpoint could register a room row
  naming any party as its owner - filling a host's store with rooms attributed
  to people who never agreed to own them, and taking identifiers from under
  their real owners. Every other verb verifies the proof and the authority
  chain; this one fell through because it is the one operation no chain can
  authorize, and the check it needed instead was never written.

  Create cannot be authorized by a chain: at the moment it runs the room has
  issued nothing, so no credential in the world speaks for it. What a host does
  have is the proof on the request, and that is what makes `ownerDid` a fact
  rather than a field anyone can fill with anyone. So the presenter must be the
  party they name as owner, and the room is then written from the authorization
  rather than from the payload.

  The decision lives in `vti_rooms::authz::authorize_create`, beside the chain
  authorization it complements, because a room host and a VTC disagreeing about
  who may register a room is exactly the class of drift that crate exists to
  prevent. It returns an `AuthorizedCreate` with no public constructor, so a
  handler that skips the check does not compile - the same typestate the rest
  of the family uses.

  What this deliberately does not do is prove control of the identifier. A
  party can still register a `roomId` they do not control while naming
  themselves owner, denying that id to its real owner on that host. The row
  confers nothing - every later verb needs credentials the real room issued -
  so it is a nuisance rather than a takeover, and bounding it is quota and
  access control, which is the availability row of the trust model. Proving
  control would mean the room signing its own registration, which would exclude
  every owner whose room key cannot sign a request document.

  Behaviour change for any caller that relayed a registration on an owner's
  behalf: there were none in the workspace, and the two hosts, their tests and
  the `data_room` example all already signed as the owner.



## [0.1.1](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-rooms-v0.1.0...vti-rooms-v0.1.1) — 2026-09-07

