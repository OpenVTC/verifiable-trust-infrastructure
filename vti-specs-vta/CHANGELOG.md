# Changelog

Notable changes to the published crates. Generated from conventional commits by
[git-cliff](https://git-cliff.org) when a release is cut — do not edit by hand.
## [0.5.2](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-specs-vta-v0.5.1...vti-specs-vta-v0.5.2) — 2026-11-05


### Added

- **elections**: Check a vote after close against the head the community kept (VTI-VOT-053) ([#2460](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2460))

The VTA kept each receipt and could check it against a head and an
  inclusion proof, but nothing ever handed it either after close. Now:

  - VTA: vta/pcs/voter/receipts/list/0.1 returns the receipts kept for an
    election, whole, and the ballot box recorded at registration.
    vta/pcs/voter/read/0.7 also signs vtc/elections/tombstones/show/0.1, so a
    member can read the heads a community keeps once the election's board is
    deleted (VTI-BRD-009). voter/receipt answers notIncluded for a head too
    small to hold the cast before it looks at a path (consumer item 7.2), as
    the ballot box gives no inclusion proof for one.
  - vta-sdk: pcs_voter_receipts_list(_json); pcs_voter_read_json sends 0.7 only
    for a tombstone read, so list and show keep working against an older VTA.
  - pnm elections verify <id>: reads the head the community kept at close
    (show, or the tombstone on electionUnknown), lists the receipts, fetches
    each cast's voting/board/inclusion from the ballot box over its own
    connection, unsigned, and has the VTA check it. A cast the head omits is
    printed in red and the command fails.
  - Member portal: "Check my vote in my wallet" on a closed or tallied
    election, for a wallet that offers checkVote. The wallet answers in its
    own window; the page is told nothing.
  - Docs: pcs-engine.md step 7, elections.md.

  Pins vta/pcs/voter/read 0.7 and vta/pcs/voter/receipts/list 0.1 from the
  Trust Task PR's registry build (read 0.2/0.3/0.6 take its new deprecation
  notes); lock reset to trusttasks.org.



## [0.5.1](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-specs-vta-v0.5.0...vti-specs-vta-v0.5.1) — 2026-11-04


## [0.5.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-specs-vta-v0.4.0...vti-specs-vta-v0.5.0) — 2026-11-04


### Added

- **vta**: Collection for the principal's identifiers — claims, the collector, collection by default off (VTI-NTF-080 – 093) ([#2421](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2421))

* feat(vti-specs): pin vta/collection/{claim,release,list} 0.1

  From trustoverip/dtgwg-trust-tasks-tf#1023 and #1024: a client's
  collection claim on a persona DID, its release, and the listing of who
  collects for each of a context's identifiers (VTI-NTF-080 – VTI-NTF-093).



## [0.4.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-specs-vta-v0.3.0...vti-specs-vta-v0.4.0) — 2026-11-03


### Added

- **vetting**: Recover or reset a lost hidden-vetting key (pcs-binding/show, pcs-binding/reset, vta/pcs/vetter/recover) ([#2406](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2406))

* feat(vtc): recover or reset a lost hidden-vetting key (pcs-binding/show, pcs-binding/reset)

  A vetter is bound to the PCS identifier of their first enrolment, and a
  second identifier is refused with pcs-root:identifierRebound. The binding
  was never cleared, so a vetter whose key was lost was locked out of hidden
  vetting for as long as they stayed a member; revoking and re-granting the
  role did not help.

  - vtc/vetting/vetters/pcs-binding/show/0.1: a member reads their own
    binding (identifier, enrolled labels, any pending reset), so their client
    can recover the matching key. Membership is the entitlement;
    notAMember otherwise.
  - vtc/vetting/vetters/pcs-binding/reset/0.1: an administrator holding
    vtc.vetting.manage (as vetters/grant) resets a member's binding with a
    reason. Idempotent; notBound for a member who never enrolled. Audited as
    HiddenVetterBindingReset, never with the identifier.
  - Enrolment after a reset: the recorded identifier cancels it
    (HiddenVetterResetCancelled); a new one is refused (identifierRebound)
    while any label the old one enrolled under is live, judged at each
    request against the caller's configuration and the stored one under the
    enrolment lock, and bound once none is (HiddenVetterRebound) with its
    labels afresh. The old labels are retired on the record.
  - vtc/vetting/hidden/publish refuses to make a retired label live again,
    checked before the consent gate and again under the enrolment lock
    before the write. publish/0.1 declares no code for it, so it is a
    validation refusal.
  - Admin console: a "Reset a hidden-vetting key" card under Vetting ->
    Vetters, shown when discovery lists the task.
  - EnrolmentRecord gains optional reset and retiredLabels members; rows
    without them read and write as before.

  The two specifications are pinned from a locally built registry ahead of
  their publication; trust-tasks.lock records that registry until they are
  re-pinned against trusttasks.org.

- **notifications**: Deposit to the VTA, a community's received notifications and relay decision, and four fixes (VTI-NTF-005, 034, 041, 047, 054 – 056, 070 – 074) ([#2405](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2405))

* feat(vti-specs): pin vta/notifications/deposit 0.1 and vtc/notifications/{list,show,relay} 0.1

  From trustoverip/dtgwg-trust-tasks-tf#1017: the client's hand-over of a
  notification received for a persona DID (vti-specs-vta), and a
  community's administrators' view and relay decision (vti-specs-vtc).
  notifications/notify and relay 0.1 changed in prose only; their pinned
  digests are unchanged.

- **notifications**: Notify/relay, the VTA's held notifications and the election notice (VTI-NTF-001 – 063) ([#2397](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2397))

* feat(notifications)!: notifications/notify + relay, the VTA's held notifications, and the election notice to a member party (VTI-NTF-001 – 063)

  Implements the Notifications chapter of the VTI specification
  (dtgwg-vti-spec #91, VTI-NTF-001 – 063, Appendix G `election`) over the
  tasks pinned from dtgwg-trust-tasks-tf #1012: notifications/notify/0.1 and
  notifications/relay/0.1 (vti-specs-core), vta/notifications/{list,show,
  dismiss}/0.1 (vti-specs-vta).

  - vta-sdk: `notifications::verify_delivery` -> `VerifiedDelivery`, the one
    way to a notification's members: every layer's type and pinned schema,
    each proof over the JSON as received as its own issuer, each forwarded
    document addressed to the relay carrying it, at most four relays,
    `relayable` honoured (VTI-NTF-042). TASK_* constants, retry_safety
    (notify/relay/dismiss RetrySafe, list/show ReadOnly), typed and `_json`
    client methods for list/show/dismiss.
  - VTA: notify/relay are counterparty tasks (zero-authority claim for a
    sender the ACL does not know); the stated acceptance policy
    (`[notifications]`: an ACL entry, an issuer of a membership credential or
    a party of a relationship credential held in the context, `accept_from`,
    `accept_any`) counts the delivering relayer, never the originator
    (VTI-NTF-030/031); one record per (addressee, originator, notificationId),
    higher revision replaces, dismissal kept (VTI-NTF-022); the same receipt
    whatever was done (VTI-NTF-023); bounds per originator and deliverer
    (VTI-NTF-033); held per context in the new `notifications` keyspace
    (backed up), listed/read/dismissed only with standing there
    (VTI-NTF-050 – 052); lapsed records swept after `retain_lapsed_days`.
  - VTC as originator: an election under a credential roll naming a member
    party is notified to that party once registered and withdrawn (higher
    revision) if cancelled or closed before voting closes (VTI-NTF-060/061);
    the notice is recorded before it is sent and queued on the durable member
    push by the election sweeper, its one sender.
  - VTC as recipient and relayer: notify/relay on the open door, verified and
    held by its stated policy in its own `notifications` keyspace (backed up);
    a relay engine that refuses a decision which has not acknowledged what
    the relay discloses (VTI-NTF-046), relays the document exactly as
    received to every member, keeps whom it relayed to until the period ends
    (30 days without one) and relays every later revision, withdrawals
    included, to them (VTI-NTF-044). No remote surface for the relay decision
    yet: the specification defines no administrator task for it.
  - pnm: `pnm notifications list|show|dismiss`.

- **voting**: Credential rolls proven at the ticket claim, and elections shown only to whom they concern (VTI-VOT-015 – 018, VTI-VOT-025 – 029) ([#2395](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2395))

* build(specs): pin the credential-roll and election-privacy task versions

  voting/_shared/0.4 and every task carrying it (dtgwg-trust-tasks-tf #1008,
  #1010, #1011): voting/election/register/0.4, show/0.4;
  vtc/elections/create/0.5, show/0.6, list/0.5, tickets/issue/0.3;
  vta/pcs/voter/register/0.5, voter/read/0.6, vote/0.4, vote-encrypted/0.5,
  trustee/{deal,justify,keys}/0.5, enrol/0.4, read/0.4. Older versions stay
  pinned.



## [0.3.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-specs-vta-v0.2.0...vti-specs-vta-v0.3.0) — 2026-11-02


### Added

- **voting**: TextReleaseThreshold may be as low as 1, disclosed below 10 (VTI-VOT-065) ([#2379](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2379))

* build(specs): pin voting/election register+show 0.3, vta/pcs voter/vote/trustee next versions, vtc/elections create 0.4 + show 0.3

  The voting/_shared/0.3 manifest lets textReleaseThreshold be as low as 1
  (VTI-VOT-065); every task carrying the manifest moves a version. The old
  versions stay pinned; their bundles take the registry's deprecation note.



## [0.2.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-specs-vta-v0.1.0...vti-specs-vta-v0.2.0) — 2026-10-30


### Added

- **vta**: Serve vta/webvh/dids/update/1.1 — list or remove an existing log's did:scid alias ([#2354](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2354))

* feat(vta)!: serve vta/webvh/dids/update/1.1 — list or remove an existing log's did:scid alias

  Every did:webvh log is also `did:scid:vh:1:<scid>`; the two forms are one
  subject only while the did:webvh document lists
  `did:scid:vh:1:<scid>?src=<source>` in `alsoKnownAs` (VTI-KEY-164).
  create/1.2 lists it at creation. update/1.1 (trustoverip/dtgwg-trust-tasks-tf#992)
  adds `scidAlsoKnownAs` so an operator can list or remove it on a log that
  already exists, without building the DID URL or sending a whole document.

  VTA (one handler serves 1.0 and 1.1; 1.1 extends 1.0):
  - `<source>` derived by `vta_sdk::did_scid::scid_forms` (`:` -> `/`,
    percent-encoding kept), applied to `document` or the current document.
    `true` appends unless listed and replaces a stale `src` in place; `false`
    removes every did:scid entry for the SCID.
  - `scidAliasRequired` when the VTA presents the identity as its did:scid
    (VTI-KEY-166): the `presented` flag create/1.2 records on the did:scid
    identity (`webvh_store::ScidIdentity`), or `vta_did` being this log's
    did:scid. Also refuses a supplied `document` that drops the alias, under
    1.0 too (as a validation error).
  - `noChange` when the resulting document and parameters equal the latest
    entry's: nothing published, no rotation.
  - Otherwise a document change: publishes and rotates the update key, so the
    task stays Destructive. The response reports `scidAlsoKnownAs` and
    `scidDidUrl`; 1.0 and rotate-keys responses are unchanged.
  - The did:scid identity record follows the published document, so the
    did:scid DID addresses the log exactly while the alias is listed.



## [0.1.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/releases/tag/vti-specs-vta-v0.1.0) — 2026-10-30


### Added

- **specs**: Generate the Trust Task wire types VTI pins, with trust-tasks-build ([#2340](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2340))

* feat(specs): generate the Trust Task wire types VTI pins, with trust-tasks-build

  trust-tasks-rs 0.36 deprecates every prebuilt trust_tasks_rs::specs module.
  Five new crates generate the versions VTI uses instead:

  - vti-specs-rooms, vti-specs-vta, vti-specs-vtc, vti-specs-core: each
    build.rs runs trust-tasks-build (.index(true)) over its own
    trust-tasks.lock and vendored bundles. Each version is pinned in exactly
    one crate, so a type is the same type across the workspace. rooms stands
    alone so vti-rooms-wasm compiles nothing else.
  - vti-specs: re-exports every family at its trust_tasks_rs::specs path and
    merges the four Type URI indexes (type_index::lookup) into a drop-in
    schema_index, plus is_pinned. Framework specs fall through to
    trust_tasks_rs::schema_index.
  - vta-sdk re-exports it as vta_sdk::specs.

  664 versions are pinned: every version module the workspace names, plus the
  Type URIs it sends or serves as strings (registry/*, did-management/*,
  push/provision, ...).

  spec_pin_census in vta-service and vtc-service fails on a dispatched,
  served, sent or TASK_* Type URI no crate pins: an unpinned URI answers None
  from the index, and the gates that read None as nothing to check fail open.

  Nothing moves to the new crates yet; the import rewrite follows.


