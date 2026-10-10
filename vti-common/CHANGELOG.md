# Changelog

Notable changes to the published crates. Generated from conventional commits by
[git-cliff](https://git-cliff.org) when a release is cut — do not edit by hand.
## [0.41.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-common-v0.40.0...vti-common-v0.41.0) — 2026-10-10


### Added

- **vtc**: Member portal, with wallet sign-in by trigger link ([#2007](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2007))

* feat(vtc): a member portal at /members, and a home page that explains the community

  Members could not sign in anywhere: VTC sign-in admitted administrators only,
  and every session it minted read as an admin session. This adds a member
  portal as a separate application from the console, with the separation
  enforced by the daemon rather than by what each page shows.

  Member portal (`crate::member_portal`, `routes::member_portal`):
  - Only an active member signs in — a live ACL entry that is not expired,
    suspended or an `application` entry, plus a member record that has not been
    removed — checked at challenge (VTI-SES-006/007 via the shared handler), at
    authentication, on every refresh and on every request (VTI-SES-020..022).
  - Sign-in by the browser wallet (SIOPv2 at `<origin>/v1/member/wallet`) or a
    portal passkey only. A passkey is added from the portal after a wallet
    sign-in; adding or removing one requires a wallet-proven session (`amr`
    contains `did`). Audited as the new `MemberPasskeyChanged` event.
  - Tokens carry audience `VTC-member` (`JwtKeys::for_audience`), so console
    extractors refuse them and the portal refuses console tokens.
  - Sessions and passkeys live in their own keyspaces (`member_sessions`,
    `member_passkeys`, excluded from backup), so a member who is also an
    administrator cannot redeem a portal refresh token or passkey at the console.
  - Cookies `vtc_member_session` / `vtc_member_refresh` are `Path=/v1/member`;
    `vtc_member_csrf` is the portal's own double-submit value, and the CSRF gate
    picks the cookie pair by path.
  - The portal is its own Vite bundle (`vite.members.config.ts`), baked by
    build.rs into `$OUT_DIR/member-ui-dist` and served at `/members/`; it loads
    no console code. In subdomain mode it is served on the API host.
  - The sign-in page carries manual install steps for the VTA Wallet extension
    (OpenVTC/vta-browser-plugin).

  Default landing page: rebuilt around a visitor who does not know what a VTC
  is — "Get started" at openvtc.net, member sign-in, capability cards (git
  across GitHub, Forgejo/Codeberg and Gitea, verifiable data rooms, access
  management, credentials, recognition), a quieter operator-console link, and
  the existing status panel. Fixes hidden status rows rendering empty.

  The step-up passkey route test now compares an unrouted response with the
  website fallback byte for byte; its old "no 'credentials' in the body" check
  tripped on the new landing page copy.

- **vta-sdk**: Wallet sign-in with a trigger link: sign auth/oob grants, enrol UV keys, advertise TrustTaskHTTPS and SignInPortal ([#1997](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1997))

* feat(vta-sdk)!: sign auth/oob/grant for assertionMethod (VTI-KEY-106)

  Adds `auth/oob/grant` to `ATTESTATION_SLUGS`, so `vault/sign-trust-task`
  signs a wallet sign-in grant for `assertionMethod`: the grant ("let this
  browser key act as me at this origin until notAfter") is the approving
  DID's attestation, which the service relies on to open a session, and it
  verifies the grant against `assertionMethod` (sign-in trigger-link
  contract C5, base design §10).

  `auth/oob/identify` stays operational and is signed for `authentication`,
  as the service verifies it; the other `auth/oob` documents are not
  attestations either. Both are pinned in the classifier tests.



### Fixed

- **vti-common**: Pooled enclave storage with atomic multi-step operations ([#1999](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1999))

* fix(vti-common): pool the enclave's vsock storage connections

  Inside a Nitro enclave every storage operation went through one vsock
  connection behind one mutex held for the whole round trip, so all storage
  I/O in the VTA ran strictly one operation at a time. Throughput of anything
  that touches storage was capped by the round-trip time, whatever the
  enclave's vCPU count: a keys/sign costs about ten round trips, and load
  tests saw the same ceiling (about 85 signs/s) with one and with two enclave
  vCPUs, with neither the enclave nor the parent CPU saturated.

  VsockStore now keeps a bounded pool of connections (up to 8). A request
  owns a connection for one complete round trip and returns it only after a
  full response; the parent's storage proxy already serves each connection in
  its own task, so independent operations now run in parallel. Each
  operation is still a single request, and the multi-step operations (swap,
  take_raw, move_if_unchanged) are no less atomic than before: the old lock
  was released between their steps too.

  This also fixes a latent correctness bug. The old code kept the shared
  connection after a cancelled request: if a request future was dropped
  after writing its request but before reading the response (a request
  timeout, a client disconnect), the next caller read the previous caller's
  response. A pooled connection that fails or is cancelled mid-round-trip is
  dropped instead of reused.

  The pool is transport-agnostic and compiled under `test` as well as
  `vsock-store`, so its tests run on every platform, not only Linux.



### Performance

- **audit**: Cache the active audit key per keyspace, failing closed ([#2004](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2004))

Every audited operation read the active audit key from storage twice: the
  `audit_key:active` marker, then the key it names. #1951 measured removing
  both reads at roughly +13-25% keys/sign throughput in a Nitro Enclave.

  Per-keyspace write tracking in the store (store/generation.rs), shared by
  every handle for a keyspace name:

  - A write begins before its request leaves (generation bumped, counted in
    flight) and ends when it completes or is dropped (bumped again).
  - A write that ends without a reply after its frame had completely left
    the enclave - transport failure, or its future dropped - marks the
    keyspace unknown: the parent may still apply it. A write that ends before
    its frame left (no connection, pool closed, write error) cannot have been
    applied, so it marks nothing. The pool reports which via a `sent` flag set
    in round_trip once the whole frame is written (request_tracked /
    request_once_tracked).
  - The unknown mark clears when a write that began after it completes, or
    after UNKNOWN_SETTLE (30 s) - longer than any plausible late apply of an
    abandoned frame; without it one timed-out write would switch the
    audit_key cache off until the next rotation.
  - Readers take a ticket before reading: none while a write is in flight or
    unknown, and a fresh read is cached only if its ticket is still current.
  - Vsock: both pool paths are tracked - `send` (request_tracked: plain ops,
    fallbacks, the restore's plain insert) and `send_atomic`
    (request_once_tracked: OP_TAKE, OP_INSERT_IF_ABSENT, OP_SWAP_IF_ABSENT,
    OP_MOVE_IF_EQUAL, the restore). Anything not a known read-only opcode is a
    write.
  - Local: each write's guard runs inside the blocking closure that writes, so
    its outcome is always known (a panic excepted).

- **vta-service**: Multi-core REST and direct vsock inbound, failing closed ([#2005](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2005))

* perf(vta-service): serve REST on one worker per CPU

  The REST server ran on its own current-thread tokio runtime, so every REST
  handler shared one thread and the VTA could use at most one CPU however
  many it had. In a Nitro enclave this showed as a 2-vCPU enclave half idle at
  its ceiling (47%/62% per vCPU), with storage replies waiting for that one
  thread to poll them.

  With more than one CPU the REST runtime is now multi-threaded, one worker
  per CPU. With one CPU it stays current-thread: a multi-threaded runtime was
  measurably worse there (1-vCPU enclave at 220 keys/sign per second: 463
  errors against 2).

  Measured alone on c6g.4xlarge with a 2-vCPU enclave, in builds with extra
  timing logging and an audit-key cache not in this series: at 320/s p95
  840 -> 71 ms. With this series as it stands, c6g.4xlarge saturates at about
  345/s with a 2-vCPU enclave and about 380 to 400/s with a 4-vCPU enclave.

  Review note: handlers that interleaved only at await points now also run in
  parallel. Existing non-atomic read-modify-write sequences were already racy
  across await points; this makes those races more likely.

- **storage**: Atomic take / insert-if-absent / swap / compare-and-move in the parent proxy ([#2003](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2003))

* perf(enclave-proxy): atomic take / insert-if-absent / swap / compare-and-move

  The enclave store's claims and moves were sequences of single operations
  over vsock: two round trips for a take or an insert-if-absent, three for a
  swap, four for a compare-and-move. The proxy now serves each as one
  operation (OP_TAKE, OP_INSERT_IF_ABSENT, OP_SWAP_IF_ABSENT,
  OP_MOVE_IF_EQUAL), advertised by OP_HELLO, under a per-keyspace lock held
  across its fjall steps. A plain mutex rather than fjall's transactional
  database: the critical sections are a few fjall calls with no await, and
  switching the database type would touch every operation.

  None needs plaintext. Values are ciphertext bound to (keyspace, key);
  OP_MOVE_IF_EQUAL compares the stored ciphertext with bytes the enclave has
  just read and compared in plaintext itself.

  Each reply frame now goes out in one write (it was two packets). A DID-log
  write through any of the new operations still lands on disk.



## [0.40.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-common-v0.39.0...vti-common-v0.40.0) — 2026-10-06


### Fixed

- **messaging**: A receive leg that stops delivering is reconnected, and the SDK alone deletes frames we cannot unpack ([#1979](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1979))

Adopt affinidi-messaging-sdk 0.33.2 and affinidi-messaging-delivery 0.1.20
  (affinidi-tdk-rs #927).



## [0.39.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-common-v0.38.0...vti-common-v0.39.0) — 2026-10-06


### Fixed

- **messaging**: A node that stops collecting its inbox is noticed, and its peers stop paying for it ([#1978](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1978))

* fix(messaging)!: a node that stops collecting its inbox is noticed, and its peers stop paying for it

  A message waits in its recipient's mediator inbox until the recipient deletes
  it, and while it waits it counts against its sender's per-peer quota
  (`limits.queue.peer`, 50). On 2026-10-05 two OpenVTC admin sessions stopped
  collecting: 49 VTA replies queued for each, and every further reply was refused
  `503 e.p.limits.queue.peer` while the VTA logged a bare "failed to send TSP
  reply" every 30 s. Sends worked; nothing came back. This makes that state
  visible from both ends and stops the stack making it worse. It needs nothing
  from an unreleased affinidi-tdk-rs.

- **vtc**: Handle inbound messages concurrently, so a bind's bridge reply is read ([#1973](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1973))

The VTC's messaging loop awaited each inbound frame's handler before
  reading the next. An operation that arrives by messaging and then waits
  on a messaging reply therefore waited on itself: `cnm git namespace
  bind` over TSP sends the bridge a beginBind job and waits up to 30 s for
  the answer, which arrives on the same stream and is not read until the
  handler gives up. Observed live: the bridge answered in ~20 ms, the
  mediator relayed it in 0-1 ms, and the VTC read it 30.1 s after the
  request — "TSP reply had no waiter" — while cnm reported "the bridge did
  not answer". Any inline bridge job reached over DIDComm or TSP is hit the
  same way.

  The loop now spawns each frame's handler, bounded at 32 in flight, as
  the VTA's inbound loop has since the same defect was fixed there. Per-
  sender ordering is kept where TSP needs it (a relationship-control frame
  is a barrier for its sender's later traffic, Keyring VTI-43): SenderOrder
  moves from vta-service to vti-common so both nodes share it, and
  vta-service re-exports it at its old path.

  The reader is factored into run_inbound_loop so it can be tested: a
  handler that waits on a later frame completes (it hangs, and the test
  fails at its 5 s bound, with the loop made serial again), and an invite
  is still handled before its sender's following task.

- **vtc**: A vetter who lost the enrolment answer is re-issued it, to the same identifier only ([#1972](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1972))

A vetter whose client lost the `vtc/vetting/vetters/pcs-root` answer
  before unblinding it was refused `alreadyEnrolled` on every re-ask: the
  community keeps only that a member enrolled, never the answer, so the
  vetter had no credential, tokens or tickets until the next label.



## [0.38.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-common-v0.37.2...vti-common-v0.38.0) — 2026-10-05


### Added

- **keys**: Serve keys/sign-sshsig — git commit signing without key export ([#1957](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1957))

did-git-sign exported its persona's key with keys/export-secret on every
  commit, because keys/sign cannot produce an SSHSIG signature: it frames
  caller bytes under the opaque-signing domain tag (VTI-VTA-003/007), which
  is the point of that hardening.

  keys/sign-sshsig/0.1 (trust-tasks-tf #732, trust-tasks-rs 0.27.6) takes a
  digest, a namespace and a hash algorithm. The VTA builds the
  PROTOCOL.sshsig signed data itself and signs it as ProtocolDefined, so the
  signature verifies as an SSHSIG statement in that namespace and as nothing
  else. It is gated on a new constrained capability under VTI-VTA-007,
  `sign-sshsig` (registered upstream as signSshsig), derived wherever `sign`
  is; `sign` is accepted in its place, and an entry narrowed to sign-sshsig
  alone cannot reach the generic oracle. Scope, the context signing policy
  and its daily quota apply through the same chokepoint as keys/sign, and
  the success is audited once as keys.sign-sshsig with the namespace and
  digest. The spec's declared codes are rendered: keys:invalidArgument for a
  digest of the wrong length or an algorithm the key cannot perform,
  keys/sign-sshsig:failedPrecondition for an inactive key.

- **vtc**: Hidden vetting (PCS) is turned off, read back and run with events from the console ([#1956](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1956))

* feat(vtc): hidden vetting (PCS) is turned off, read back and run with events from the console

  Completes the console's hidden-vetting surface on top of #1955, with the
  three tasks trust-tasks-tf #729 specified (trust-tasks-rs 0.27.5):

  - `vtc/vetting/hidden/withdraw/0.1` turns hidden vetting off for a criterion.
    Named vetting is untouched; enrolment rows and the spent-token ledger stay,
    so a later publish works with the same keys. Withdrawing a criterion with
    none is `withdrawn: false`, not an error.
  - `vtc/vetting/hidden/show/0.1` answers an administrator with the stored
    configuration — each event's `approvedBy` and `graceDays`, which the
    manifest leaves out — plus how many members are enrolled under each live
    vetter label and each event's demand against its floor. Counts only, never
    which members.
  - `vtc/vetting/hidden/publish/0.1` now holds the approval rules its draft
    states: a new or changed `approvedBy` must be the publishing signer
    (`approverNotSigner`) — it was an unchecked string, so an administrator
    could approve in anyone's name — and an approver who has asked to vet at the
    event is refused (`approverInEvent`). An approval already stored may be
    re-sent by anyone, so a re-publish keeps it.
  - Every publish and withdrawal is audited as `HiddenVettingChanged` (new
    `vti-common` audit variant; the enum is `#[non_exhaustive]`).



### Fixed

- **vtc**: Working in the admin console counts toward the idle timeout ([#1953](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1953))

The console signed out operators who were using it. The idle timeout
  (`auth.admin_idle_timeout`, 900s) is measured from `Session::last_seen`, and
  only a cookie-authenticated request through the `AuthClaims` extractor
  advanced it. Most of what the console sends is now a signed Trust Task
  document to `/v1/trust-tasks`, which authenticates by its proof and reads no
  session, so a busy operator stopped producing activity. Fifteen minutes after
  the last cookie-borne call the renewal was refused and the session-deadline
  watcher showed Login.

  Counting every signed document would be wrong the other way: the action
  badge, counts and banners post signed reads on timers, and an unattended tab
  would never time out. Only the console can tell input from a poll, so:

  - The console notes real input (pointerdown, keydown, wheel, touchstart) and
    sends `X-VTC-User-Activity` on a document posted within 60s of some
    (`admin-ui/src/lib/user-activity.ts`). Timers in an idle tab send none.
  - The route records activity only for a document that ran successfully, was
    verified as a known signer, and whose principal (the signer, or the
    administrator its console key acts for) owns the session the cookie names
    (`vti_common::auth::touch_cookie_session_for`, which authenticates the
    cookie exactly as the extractors do). A document signed by one identity
    cannot keep another's session alive, and a refused one counts for nothing.

  Renewals and timer-driven reads still never count, so the daemon still
  decides when an operator who walked away is signed out.



## [0.37.2](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-common-v0.37.1...vti-common-v0.37.2) — 2026-10-04


### Added

- **vtc**: A community serves governance/capability/* — members list its capability modules, administrators enable them, and the trust registry follows ([#1948](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1948))

* feat(vtc): a community serves governance/capability/* — members list its capability modules, administrators enable them, and the trust registry follows

  OpenVTC's Capabilities panel sends a signed governance/capability/list/0.1
  to the community's VTC DID over DIDComm or TSP, and the VTC answered
  unsupportedType: it only ever relayed git-trust writes outward. The VTC is
  the source of truth for which capability modules a community has enabled;
  its Trust Registry is a projection, whose own enable/disable are admin-only
  and only switch which record families it accepts.

  "Capability module" (a pluggable governance capability, git-trust first) is
  kept apart from ACL capabilities throughout: crate::capability_modules,
  trust_tasks::capability_module_tasks, AuditEvent::CapabilityModuleChanged.

  list/enable/disable 0.1 are served on the document spine (DISPATCHED_URIS),
  so DIDComm, TSP and HTTPS route them and discovery lists them; every reply,
  refusals included, is signed, addressed to the requester and threaded.

  - list answers members and administrators (an application entry and unknown
    DIDs get permissionDenied), filters on status as the registry does (absent
    means enabled), and answers the generated #response that
    trust-tasks-capability-client's parse_capability_reply reads. Admins
    holding vtc.config.admin also see each decision's projection in ext.
  - enable/disable need vtc.config.admin (VTI-ACL-030) and a step-up bound to
    the document (VTI-APV-015) — the destructive class. They do not park for
    consent: VTI-APV-018–020 / VTI-VTC-022 ask that of authority-conferring
    acts, and a module confers no ACL authority. config.authority defaults to
    the VTC DID and may name nothing else; any other config member is
    configInvalid rather than silently ignored. Declared codes
    unknownCapability, alreadyEnabled, configInvalid, notEnabled are emitted.

  The decision (version, config, enabledAt/By, generation, projection status)
  is persisted in the community keyspace first and audited; the new
  capability_modules::Projector then sends governance/capability/enable|
  disable as the registry's admin via TrustRegistryClient::
  project_capability_module (TSP > DIDComm selection, schema-checked payload).
  alreadyEnabled/notEnabled are success. Transient failures back off 5 s to
  1 h with jitter; a refusal is marked failed, audited once
  (projectionFailed), warned, and still retried at the cap so fixing the
  registry converges. Results are recorded only against the generation sent;
  no lock is held across the round trip.

  The git-trust manifest is a pinned copy of the registry's; enablement does
  not yet gate [hooks.git-trust] or the git-ns projection.



## [0.37.1](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-common-v0.37.0...vti-common-v0.37.1) — 2026-10-04


### Added

- **vtc**: A cooling-off suspends its subject, and single-administrator mode can remove now (VTI-APV-019, VTI-APV-022) ([#1944](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1944))

* feat(vtc): a cooling-off suspends its subject, and single-administrator mode can remove now (VTI-APV-019, VTI-APV-022)

  Removing another unrestricted administrator when nobody else can consent
  waits out a cooling-off (acl.removal_cooling_off, default 24 h). Until now
  the subject kept full authority for that whole window, and in
  single-administrator mode there was no way past it.

  Suspension (vtc-action-list.md §8.2). From the moment a cooling-off
  reduction is raised until it lands or is cancelled, the subject's entry
  authorizes nothing. The suspension is set on the entry wherever it is read
  (acl::storage::get_acl_entry / list_acl_entries), and VtcAclEntry::can,
  can_any and can_approve answer false for it, so every gate refuses without a
  per-handler check. The signed administrative door (resolve_admin_claims,
  console keys included), the git-ns door (acting_as), require_capability and
  ACL reads refuse with a message naming the action and when it lands. The
  subject can still sign in, read the action list (callerRole: subject) and
  cancel a request of its own; its event stream carries only actions and the
  mode banner. It approves and decides nothing, acknowledges nothing, and is no
  role assigner for the attrition guard; raising a cooling-off checks the guard
  as though the subject were already gone, and only one cooling-off runs on a
  subject at a time. Its sessions are revoked at suspension, as any reduction's
  are. The row is never changed, so cancelling restores it exactly. A
  suspended subject cannot raise a counter-removal, so the first to act wins
  outright; refuse_if_reduced_first stays as a backstop.

  The suspension is derived from the open action and kept beside the entry as
  a marker (suspended:<did> in the ACL keyspace). admin_actions::save writes
  it before an action that suspends and lifts it after one that no longer does
  (R2.1), so a crash can only over-restrict, and reconcile_suspensions settles
  either half at start (before serving), on every sweep, and after a restore.

  Remove now (vtc-action-list.md §8.5, single-administrator mode only). No new
  task: a reduction's payload carries ext["org.openvtc"].immediate =
  {confirm, actionId?}. confirm must be the subject's DID (or the action id
  being landed), checked before any gesture; the gesture is bound to the
  payload digest, which includes `immediate`, so a gesture for the delayed
  removal is never spent on the immediate one or the reverse (VTI-APV-015).
  Sending the same operation with `immediate` naming an open cooling-off lands
  it now. Refused without the mode (naming the cooling-off and that the mode
  is host-set), on a mismatched confirmation, without the gesture, and by the
  attrition guard. Audited Critical as SingleAdminMode reductionImmediate
  before the write, then AuthorityReducedUnopposed, and the subject is told.
  The landed cooling-off closes landedAfterCoolingOff with ext landedNow; a
  reduction that never waited enters the history with the same marker.

- **vtc**: A subject may relabel its own entry; single-administrator mode is one person under many identifiers (VTI-ACL-052, VTI-APV-022) ([#1941](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1941))

Implements trustoverip/dtgwg-vti-spec#54 and #55 (both merged).

  VTI-ACL-052 item 2 — a subject may change its own entry's label and
  nothing else, on every door that writes it (acl/update 0.1 and 0.2,
  acl/grant re-stating the same entry, vtc/members/update). No step-up: the
  label confers no authority (VTI-ACL-001). The change is audited as a
  MemberUpdated row naming the old and new label and `labelSetBySubject`,
  and the entry carries `label_set_by_subject` (serde-default false,
  cleared when anyone else sets the label), shown to other parties as
  `ext["org.openvtc"].labelSetBySubject` on acl/list and acl/show 0.2 — an
  ext member, so the published response schemas are untouched. A request
  that changes the label and anything else is refused whole. A subject's
  own write never re-affirms a delegation under review.

  VTI-ACL-052 item 3 (as widened by #55) — in single-administrator mode a
  subject whose entry has unrestricted act scope (granting::is_unrestricted:
  a community-admin acting everywhere with its full ceiling) may modify its
  own entry on acl/update/0.2 and acl/change-role/0.2. It takes the
  subject's step-up bound to the operation (VTI-APV-015) and a Critical
  SingleAdminMode{event: selfEditWaived} row written before the write
  (acl::single_admin::authorize_self_edit), and is refused if it would leave
  no live unrestricted entry (narrowing, demoting or shortening the life of
  the only one). Ending the subject's vtc.roles.assign is attrition-checked
  like any removal. Every other self-edit is refused as before, and the
  refusals now say what the subject may do instead.

  VTI-APV-022 ([#55](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/55)) — single-administrator mode waives second-party consent
  whether or not other administrators' entries exist: one person may hold
  an administrator entry per device, and the node cannot tell one person's
  identifiers from two people's. gesture_then_consent_for and the session
  door's require() no longer test for an empty approver set; git-ns rule 7
  is waived the same way (others_eligible is gone). A reduction of another
  administrator (VTI-APV-019) is not parked for a third party's consent in
  the mode: it takes the unopposed path — step-up, notice to the subject,
  Critical row — and keeps its cooling-off, which now lands in the mode even
  with a third administrator present (recheck_cooling_off and the sweeper's
  invalidation skip the "a third party can now consent" check).



## [0.37.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-common-v0.36.0...vti-common-v0.37.0) — 2026-10-04


### Added

- **vtc/git-ns**: Single-administrator mode waives git self-grant separation of duties ([#1936](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1936))

* feat(vtc/git-ns): single-administrator mode waives git self-grant separation of duties

  A community in single-administrator mode (VTI-APV-022, #1925) has one
  administrator. Fixed rule 7 of git-ns/right/grant/0.3 still refused every
  elevated self-grant, so `cnm git adopt <repo> --owner <own DID>` failed with
  git-ns:selfGrantNotAllowed. Break-glass left records nobody could ever ratify.

  Single-administrator mode now reaches rule 7. It uses the same discipline as
  the consent waiver (`git_ns::single_admin`):

  - Only where nobody else is eligible. `others_eligible` reuses
    `admin_consent::approvers_for` over the namespace's `git.ns.admin`. That
    covers the break-glass deciders and any approve scope reaching them. It also
    counts any other member whose git rights could make this grant (rules 1 and
    2). One eligible party, or the mode off, and the refusal stands.
  - Every path the rule covers: right/grant, repo/create (implied repo.create
    naming self as owner), repo/adopt naming self, namespace/reseat to self, and
    drift/resolve adopt for one's own account. The rules accept a `Waivable`
    token only for that exact actor, right and resource. Rules 1, 2 and 5, the
    granter-covers floor, the consent-class gate and policy all still apply.
  - Requires the requester's operation-bound step-up. This is the break-glass
    mechanism (`bound_step_up`), bound to the document actually signed (for an
    adoption, the drift/resolve document).
  - Writes a Critical `SingleAdminMode { event: selfGrantWaived }` audit row
    before the write. It names the rule, task, digest, git-ns action, right and
    resource. If the audit write fails, the operation is refused and nothing is
    recorded.
  - Marks the result. The record carries `singleAdmin { at, task }`, which is
    never published. The answer carries `ext.org.openvtc.selfGrantWaived`.
    git-ns/view 0.4/0.5 lists waived records under the same ext member. The ACL
    resource grant shows `selfGrantWaived: true`. A `gitNs.right.selfGrantWaived`
    activity item is written.
  - Counts for invariants. Waived records count toward the last-owner and
    last-admin invariants, unlike unratified break-glass.

- **vtc**: Custom roles, capability approver sets, admin-key rollover and capability-driven console (VTI-CLT-025 – 032, VTI-APV-018) ([#1927](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1927))

Phase C2 of role-based administration (docs/05-design-notes/vtc-admin-roles.md).

  Single-administrator mode (VTI-APV-022, #1925): ChangeRoles and RestoreBackup
  go through gesture_then_consent_for, so with the mode on and nobody else
  eligible they run on the requester's bound gesture, the waiver audited
  Critical; both are tested. A restore replaces the audit log, so its waiver row
  is written again into the restored log after the commit.

  Custom roles (§6.2). vtc/roles/{define,list,show,delete}/0.1 are served on the
  signed-document spine with the generated types. A role is a record in the acl
  keyspace (role:<name>, carried by a backup), resolved onto every entry read
  from its stored definition; an entry naming an undefined role confers nothing,
  sign-in included (VTI-ACL-011). define/delete take vtc.roles.assign +
  vtc.approvals.admin, the requester's bound gesture and the N-of-M consent of the
  other holders (new Act::ChangeRoles). A ceiling is bounded by what the requester
  and every approver hold and may approve (exceedsDefinerAuthority, VTI-ACL-042,
  -071); git.commit.sign is additive and never in a ceiling. delete is refused
  while any entry (expired ones too) or pending grant holds the role (inUse),
  counted and removed under the admin-set lock a custom-role grant commits under.

  Approver sets (§7). may_approve reads approve authority alone (VTI-ACL-040), so
  the least-privilege approver counts for every act (VTI-ACL-041); a test covers
  every Act.

  Departed-granter review (§6.3). A removed, narrowed or expired granter's
  grants become one acl.grants.review action for the holders who may approve
  vtc.roles.assign (the subjects excluded): approve re-affirms each grant the
  approver covers, decline withdraws at once, a lapse is withdrawn by the
  delegation sweeper (kept as the backstop; it now also notices expired
  granters).

  Key rollover. acl/swap-key/0.1 rolls the signer's own entry to a new key with
  exactly its authority (VTI-CLT-025 – 032, VTI-ACL-052): no console key, a
  required short-lived VP-JWT link proof from the new key addressed to the VTC,
  AclKeyRotated audited before one atomic move_if_unchanged, the member row and
  delegatedBy pointers following the key, old sessions revoked. A member's own
  rotation now re-points delegations too. cnm community continue rotates the
  granted key this way; cnm community rotate rotates a configured one
  (vtc-client: VtcClient::acl_swap_key). Note: VTI-ACL-054 – 058 (hand-off
  markers) are a different mechanism and are not implemented here.

  Backup restore. backup/finalize-import with confirm: true is previewed, then
  parked (Act::RestoreBackup) for the holders of vtc.backup.restore; approvers see
  the payload without its password, and the staged bundle is kept alive for the
  action's lifetime.

  Console. auth/whoami returns the caller's live capabilities (the published
  member) and ext["org.openvtc"].{adminRole, approves}; navigation and action
  buttons render per capability; a Roles page lists, defines and deletes roles
  through the action list; the new action kinds have pinned summary templates.

- **vtc**: Single-administrator mode, set at install, for communities with one administrator (VTI-APV-022) ([#1925](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1925))

A community run by one person has nobody to give second-party consent
  (VTI-APV-014, -018 - 020). Without this, its administrator could add a
  colleague or change an authority rule only through the offline break-glass.
  VTI-APV-022 lets a node run in single-administrator mode instead. This
  implements it at the VTC.

  - Config: `[acl] single_admin_mode` (default false). Host configuration
    only (item 1). It is read at start, kept out of the runtime registry,
    and refused by name by `config/patch` and `vtc/config/import`, with the
    host-side fix in the refusal. It is written to config.toml only when on.
  - Setup: `vtc setup --single-admin` (interactive and `--from`),
    `single_admin_mode = true` in the setup TOML, and an interactive
    "Run as a single-administrator community?" (default No). Setup warns when
    it is chosen beside `co_admin_did`, because the mode has no effect while
    that administrator is eligible.
  - Gate: where the approver set is empty and the mode is on, the consent
    gate neither refuses nor parks. The requester's operation-bound step-up
    (VTI-APV-015) stands in for the consent. Spending it writes a Critical
    `SingleAdminMode{consentWaived}` audit row naming the requirement, task,
    kind and digest. The row is written before the write, and a failure to
    audit refuses the operation. Once the write lands, the operation enters
    the action history marked `ext.org.openvtc.consentWaived`. A non-empty
    approver set parks exactly as before (item 2).
  - Reductions (VTI-APV-019) are unchanged and keep their cooling-off.
    Removing the subject at once would let one credential first remove the
    only other eligible party and then act on the waiver
    (vtc-action-list.md section 8.5).
  - Boot (item 4): Critical `inEffect` at every start with the mode on, and
    `enabled`/`disabled` when the value differs from the last start (stored in
    the install keyspace). A start that cannot audit does not proceed.
  - Visibility (item 3): `vtc/admin/actions/list` carries
    `ext.org.openvtc.singleAdminMode`. The console shows a permanent,
    non-dismissable banner on every page and a dashboard tile, and marks
    waived operations in Actions. `cnm actions list` prints a notice and marks
    waived operations.
  - Docs: admin-access section 2.1a, bootstrap runbook, non-interactive setup
    and example TOML, vtc-action-list section 8.5, vtc-admin-roles section 7,
    the infographic, and CLAUDE.md.

  Adds the `AuditEvent::SingleAdminMode` variant to vti-common. The enum is
  `#[non_exhaustive]`, so this is additive.

- **vtc**: Administration is role-based — capabilities, built-in roles and explicit act scope (VTI-ACL-030 – 037, VTI-APV-018) ([#1924](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1924))

Phase C1 of docs/05-design-notes/vtc-admin-roles.md. A VTC ACL entry no longer
  reads "admin with an empty context list" as unrestricted: it carries explicit
  administrative authority beside its community role.

  Model (vtc-service/src/acl/capability.rs, entry.rs)
  - VtcAclEntry gains adminRole (seven built-ins: community-admin, moderator,
    vetting-lead, repo-manager, credential-officer, auditor, approver; custom
    roles are a C2 placeholder), act all|none, capabilities ceiling|none|listed
    with resource qualifiers (git-ns, git-repo, policy, criterion) and additive
    grants, approve and approveCapabilities. Absent means none.
  - A typed registry of 20 capabilities with authority-conferring flags. The
    effective set is ceiling ∩ listed (plus additive), and every gate asks one
    question: entry.can(capability, resource). No authority list is tested
    with is_empty().

  Gates (§4)
  - Every require_super_admin / is_super_admin / "any admin" gate is replaced
    by the specific capability. Reads need any administrative role; writes need
    their capability. Console sign-in admits every administrative role. git-ns
    community-admin standing is git.ns.admin unqualified.
  - vtc/members/update refuses a move to or from a community role that implies
    an administrative role (moderator, issuer, admin) with adminRoleForbidden;
    acl/change-role carries the bound gesture for it.

  Consent (VTI-APV-018, -019, -009)
  - APV-014 generalises to any authority-conferring capability: approvers are
    holders of the same capability at a covering qualifier who may approve it;
    the requester (and, for a reduction, the subject) is excluded. A2's
    after_reduction, agreements, cooling-off, record_effect and notices are
    kept; actions record the capabilities at stake. An expiry put on or brought
    forward is a reduction of everything the entry holds. The last holder of
    vtc.roles.assign is never removed.

  Granting bounds (§6.3; VTI-ACL-031, -033, -042, -050, -053, -071)
  - A granter must hold each capability and vtc.roles.assign at a qualifier at
    least as wide, may confer approve only within its own, never past its own
    expiry, never to itself. delegatedBy is recorded. A departed or narrowed
    granter's grants go under review and are withdrawn after the action
    lifetime unless re-affirmed (review listing + sweeper, not an action-list
    item).

  Wire
  - acl/{grant,update,show,list,revoke,change-role}/0.2 are served with the
    generated trust_tasks_rs types beside 0.1, mapped per acl/_shared/0.2
    CONVENTIONS §8; an entry 0.1 cannot express is refused at 0.1. Six 0.2
    summary templates are pinned (Rust and console).

  Migration (§9)
  - At boot, before anything is authorized, every ACL row in the pre-role shape
    is rewritten in place with the same mapping a backup import uses. All rows
    are mapped before any is written, and each is one put, so a refusal or a
    crash leaves no half-migrated row. A second boot is a no-op. The run is
    audited once (new AuditEvent::AclMigrated, Critical: counts plus the
    context-scoped admins left with no administrative role), and those losses
    are raised as an acknowledge item for the remaining community-admins
    (VTI-VTC-023; new pinned template, urn:openvtc:vtc:operator:acl-migration).
    A row that cannot be mapped refuses the boot, naming the DID and the
    offline fix (vtc acl remove, which now removes an undecodable row, then
    vtc acl add). It is never dropped.
  - Backup import maps legacy rows: unrestricted admin -> community-admin,
    context-scoped admin -> no administrative role (listed for re-grant in the
    import report), moderator / issuer -> the matching role, custom -> none.
  - Install bootstrap and the co-admin are community-admins; offline
    `vtc acl add --role admin` writes a community-admin, and gains
    --admin-role and --capability cap[@resource]; --contexts is refused.

  Clients
  - vtc-client gains the 0.2 calls; cnm access list/show/grant/update use 0.2
    with --admin-role / --capability / --approve.
  - The console's Access control shows each entry's administrative role and
    capabilities, adds and edits with role and capability narrowing, and no
    longer calls a least-privilege entry "all" ([#746](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/746)).

- **vtc**: Operator writes need acknowledging, reductions notify and cool off, and execution survives a crash (VTI-VTC-023, VTI-APV-019) ([#1920](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1920))

Phase A2 of the administrator action list (docs/05-design-notes/vtc-action-list.md).

- **vtc**: An approver device can be an administrator's step-up factor (VTI-APV-015, VTI-APV-016) ([#1919](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1919))

An administrator who signs in with a VTA wallet holds no passkey at the
  community, so every operation behind the operation-bound step-up was refused
  for them. A step-up approver — an Ed25519 did:key bound to one subject as
  their step-up factor, such as the browser plugin's approver identity — can
  now answer it.

  - Gate: the inline request is auth/step-up/approve-request/0.4, accepting
    `approverSigned` (naming the subject's approvers) and/or `webauthn`.
    auth/step-up/approve-response/0.6 carries the approver's attest/0.1
    statement, verified as received against this service's own pending
    record; the answer itself must be signed by the subject's own DID, never
    a console key. Once a subject holds a dedicated factor (approver or
    step-up passkey) their session passkeys stop counting. Audited as
    OperationStepUpApproved with the evidence kind and approver DID.
  - Store: new backed-up keyspace `step_up_approvers`; one approver DID per
    subject, once (revoked DIDs are burned), at most five per subject,
    distinct from the subject's DID, DID-document keys and every console key,
    checked at enrolment and at every use (VTI-APV-015 as amended).
  - Enrolment on the signed-document spine, every binding resting on an anchor
    independent of the subject's signing key and audited with `enrolledVia`
    (VTI-APV-016): auth/step-up/approver/{invite,redeem/start,redeem/finish}
    (R2), enroll (R3, behind a factor already held, bound to the terms
    digest), list and revoke; vtc/install/claim/{start,finish}/0.3 (R1,
    claim under the token's DID verified against its live document, binding
    written at bootstrap); `vtc admin enrol-approver` (R4, offline invite,
    audited at boot as a break-glass).
  - Console: approverSigned via a feature-detected window.vtaWallet
    approveStepUp, falling back to WebAuthn; Approver devices card; member
    invite; redemption page.

- **vtc**: Consent-gated operations wait in an action list and complete on the N-th approval (VTI-APV-017) ([#1918](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1918))

A VTC operation that needs other administrators' approval -- an unrestricted
  grant (VTI-APV-014), a reduction of another unrestricted admin (VTI-APV-019),
  a lowered consent threshold (VTI-APV-020), an authority-policy change
  (VTI-VTC-022) -- is no longer refused with `auth:consent_required` and re-sent.
  Phase A1 of docs/05-design-notes/vtc-action-list.md.

  Once every other check passes and the requester's operation-bound step-up is
  spent (VTI-APV-015), the operation is parked as an action in the new
  `admin_actions` keyspace (excluded from backup: it binds the ACL as it stood on
  this host). The record keeps the requester's signed document verbatim, the
  payload, requester, step-up evidence, approver set, threshold, one challenge
  per approver, a state pin and its lifetime. The requester is answered
  `trust-task-next-step/0.1` (202, continuation `proceed`, expecting
  `vtc/admin/actions/show/0.1` with the action id) and never sends it again.

  Approvers decide with `task-consent/decision/0.1` or `/0.2`, signed by their
  own DID (a delegated console key is refused). The approval that reaches the
  threshold moves the action out of `open` under a lock -- so concurrent final
  approvals execute it once -- and dispatches the stored document through the
  handler it was submitted to, re-running every check against the community as
  it is then; the consent gate re-checks approver eligibility, threshold and
  state pin. It closes `completed`, or `failed` with nothing written. One deny
  closes it for everyone; the requester can cancel; it expires; it is
  invalidated when the requester loses authority, the pinned state moves, or the
  eligible approvers can no longer reach the threshold (VTI-APV-004/-005/-006/
  -007/-008/-009/-017). Freshness and replay are held once, at submission
  (VTI-OPS-024..027).

  decision/0.2 `webauthn` evidence is verified against the approver's passkeys
  with user verification required, as an additional factor. `approverSigned`
  evidence is refused (evidenceInvalid, approverSignedUnsupported) until the
  approver store lands.

  New config keys, runtime-patchable: acl.action_lifetime (72 h, 15 min-14 d),
  acl.action_max_open_per_requester (5, 1-20), acl.action_max_open (50,
  10-500), acl.action_decline_cooldown (1 h, 0-24 h). More than three actions by
  one requester in ten minutes writes a Critical `AdminActionBurst` audit row
  and flags approvers' cards; an approver may decide at most ten a minute
  (VTI-APV-021, section 7a.1).

  Summaries are templates as data (title/effect prose, JSON Pointer fields, a
  closed format set) keyed by (kind, typeUri), each pinned by digest in the
  build, with shared vectors run by the service and the console (VTI-APV-011,
  -013).

  Served on the signed-document spine: vtc/admin/actions/{list,show,cancel,
  acknowledge}/0.1 (acknowledge answers notAcknowledgeable until A2 raises
  acknowledge items), with conformance witnesses and declared-code witnesses.



### Fixed

- **vtc**: Removing an administrator, lowering the consent threshold and changing authority policy take a second party (VTI-APV-019, VTI-APV-020, VTI-VTC-022) ([#1917](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1917))

* fix(vtc)!: removing an administrator, lowering the consent threshold and changing authority policy take a second party (VTI-APV-019, VTI-APV-020, VTI-VTC-022)

  One unrestricted administrator could undo VTI-APV-014 alone: remove every
  other administrator one at a time, lower the consent threshold back to 1, and
  rewrite the policy that decides authority (vtc-action-list.md §8.1, holes 1-3).
  These are the stop-gaps of §7b, built on the consent machinery that already
  exists. Each is replaced by its action-list rule once that lands.

  1. Removals and demotions of an administrator take the requester's
     operation-bound step-up (VTI-APV-019). acl/revoke (removal and scope
     reduction), a downward acl/change-role, an acl/update or acl/grant rewrite
     that takes authority from a live admin (narrowed scopes, an expiry brought
     forward), and vtc/members/admin-remove of an admin all go through
     bound_step_up::redeem_or_request. When the subject is another live
     unrestricted admin they also take consent through admin_consent, from the
     unrestricted admins other than BOTH the requester and the subject (approver
     set `unrestricted-admins-except-subject`; the subject's decision is refused
     as notAnApprover). Where that set is empty (two unrestricted admins), the
     step-up suffices, and once the write lands it is audited as the new
     `AuthorityReducedUnopposed` event at AuditSeverity::Critical; a removal also
     sends the subject the signed removal notice. The attrition guards
     (check_attrition, lock_admin_set, last-admin) are unchanged and still run;
     attrition is also asked before the gesture so a stranded removal never asks
     for one. Removing an expired or non-admin entry is unchanged.
     vtc/members/update can no longer demote an admin (it has no operation to
     bind a gesture to) and names acl/change-role instead.

  2. Lowering acl.unrestricted_admin_consent_threshold, by config/patch or an
     applied vtc/config/import, takes the requester's step-up and consent at the
     threshold as it stands (VTI-APV-020), pinned to that value. Raising it, or
     leaving it unchanged, stays immediate; the meetable check is unchanged.

  3. policy/upsert/0.2 and policy/activate/0.1 require an unrestricted admin
     (require_super_admin), not any admin. For the purposes that decide authority
     (roleChange, removal, join, crossCommunityRoles, gitNamespace —
     PolicyPurpose::decides_authority) they also take the step-up and consent of
     another unrestricted admin (VTI-VTC-022). The upload and activation checks
     run before the gate, so a module that would be refused asks nobody.

  4. vtc/members/admin-remove applies acl/revoke's scope-cover check
     (caller_covers_target, VTI-ACL-050): an entry the actor cannot see answers
     as not found, one it does not fully cover is refused.

  admin_consent is generalised over an `Act` (GrantUnrestricted,
  ReduceUnrestricted, LowerThreshold, ChangeAuthorityPolicy) that decides the
  approvers, the refusal wording, what the approvers are shown and the state the
  consent is pinned to. require and gesture_then_consent keep their signatures
  and are Act::GrantUnrestricted, so APV-014 is unchanged. TaskError gains a
  StepUp variant so a gate deep in an operation refuses with the ceremony inline.



## [0.36.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-common-v0.35.1...vti-common-v0.36.0) — 2026-10-02


### Added

- **vtc**: Join criteria state their own admission (Keyring VTI-13) ([#1907](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1907))

A community's join criteria are its join rules, and the VTC now decides a
  submission by them as vtc/join-requests/submit/0.3 specifies
  (dtgwg-trust-tasks-tf#710, trust-tasks-rs 0.26.1). Nothing in the service
  assumes a criterion: open admission, review only, invitation only and any
  combination are all criteria an administrator registers.

  - Criteria (vtc/schemas/accepts/{register,list,show}/0.2) carry `admission`
    (automatic | review), an optional DCQL query with `credentialIssuers`
    (community | recognised | any), `invitationRequired` and `vetting`.
    `recognised` without a trust registry is `unsupportedRequirement`.
  - The manifest (vtc/join-requests/manifest/0.3) publishes them in the order
    the community decides by — registration order, kept on replacement.
  - A submission is decided under the criterion it names by digest, else the
    first it meets, else the first published. No criteria → `notAccepting`;
    an unpublished digest → `criterionUnknown`. Superseded versions are kept
    and govern while their `requirementsGrace` lasts.
  - The host verifies the presentation's embedded credentials (proof set,
    validity window, revocation, subject = applicant) and matches the query,
    applying DCQL `type_values`, which the matcher alone ignores.
  - The host holds the policy to the criterion: unmet → never admitted or
    referred (requestMore naming what is missing); met review → refer; met
    automatic → the policy's verdict. Policy may tighten, never loosen.
    The default join.rego follows the criterion.
  - A new community is seeded once with `invited` (automatic) →
    `member-credential` (automatic) → `review`.
  - The criterion and version that governed are recorded beside the request;
    a supplement re-decides under it.



## [0.35.1](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-common-v0.35.0...vti-common-v0.35.1) — 2026-10-02


## [0.35.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-common-v0.34.1...vti-common-v0.35.0) — 2026-10-02


## [0.34.1](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-common-v0.34.0...vti-common-v0.34.1) — 2026-10-02


### Fixed

- A TSP reply reaches a sender on another mediator ([#1894](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1894))

Both the VTC (`handle_tsp`) and the VTA (`handle_tsp` → `send_to`) answered
  an inbound TSP Trust Task by routing `[own_mediator, sender]`. That ends at a
  mediator that does not host a sender on another one, which refuses it. The
  request arrived and the answer never did. In the field: an OpenVTC persona
  on ic3-mediator joined a VTC on cpunks-mediator, the admin approved it, and
  the persona stayed Pending. Its submit receipt and every
  `join-requests/status` poll reply were refused at the VTC's mediator. #405
  fixed the same failure in the other direction.



## [0.34.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-common-v0.33.0...vti-common-v0.34.0) — 2026-10-01


## [0.33.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-common-v0.32.0...vti-common-v0.33.0) — 2026-10-01


## [0.32.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-common-v0.31.0...vti-common-v0.32.0) — 2026-10-01


### Fixed

- Take affinidi-messaging-sdk 0.31.1; the SDK routes a cross-mediator invite itself ([#1880](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1880))

affinidi-messaging-sdk 0.31.1 (affinidi-tdk-rs #913) routes a TSP
  relationship invite to a peer on another mediator through the mediator the
  peer's DID document names, and keeps a Delivery-Request-collected message's
  own id so a reply threads to it (VTI-49). The workspace floor moves to
  0.31.1, because ^0.31 resolving 0.31.0 would bring the cross-mediator
  refusal back.

  So the set_peer_mediator half of vti_common::tsp_route ([#1873](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1873)) is gone. It
  recorded the same DID-document mediator the SDK now reads.
  tsp_route::send_reestablishing stays: the SDK's own sends the payload along
  the route it is given, and [our_mediator, peer] cannot reach a peer on
  another mediator. vti_56_a_cold_relationship_with_a_cross_mediator_peer_forms
  now uses peers that name their mediator by DID, as a VTI-provisioned DID
  does, and holds both halves.

- A TSP relationship can be started with a peer on another mediator (VTI-56) ([#1873](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1873))

A node that starts a TSP relationship with a peer on another mediator had
  its invite refused by its own mediator (403 e.p.direct_delivery.denied,
  "must be relayed through a routing envelope"), every attempt. The SDK
  routes a control message across mediators only when it already knows the
  peer's mediator, learned from a routed invite from the peer or set with
  set_peer_mediator. An initiator has neither, and nothing here set it. That
  is why the Farm VTC's TSP push to a member on the other mediator never left
  its own mediator and fell back to DIDComm an hour later. The existing
  cross-mediator tests pre-form the relationship (relate_directly), so they
  never sent an invite.

- Keyring findings round — proof sets, verify-as-received, VTC delivery (VTI-44, VTI-45, VTI-50, VTI-56) ([#1868](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1868))

* fix(vta-cli-common): opening a bundle to inspect it keeps the request seed

  pnm, cnm and vta `bootstrap open` consumed the single-use request seed
  right after decrypting, even when they wrote nothing. The seed is the only
  key that opens the bundle, so inspecting a template bundle destroyed the
  integration's keys, and cnm's own follow-up hint (`cnm auth login
  --credential-bundle`) could never succeed (VTI-53).

  Inspection now opens with the seed kept and says where it is. pnm consumes
  it only after a successful --out write, so a refused bundle no longer costs
  a fresh request cycle either. open_armored_bundle_keeping_secret and
  consume_request_secret are now public.



## [0.31.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-common-v0.30.0...vti-common-v0.31.0) — 2026-09-30


### Added

- DTG Credentials v1 — role VACs, vetted/1 and witnessed/1 statements, IDVCs, issuerScope ([#1859](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1859))

* feat(vta-sdk)!: vetting statements are vetted/1 VSCs; role credentials are VACs

  Conform the SDK's vetting artifacts to the DTG Credentials Core
  Specification (v1 context, `issuerScope`) and the DTG VSC predicate
  registry, following the regenerated vetting specifications
  (dtgwg-trust-tasks-tf feat/dtg-vsc-conformance).

  Vetting Statement (vetting/session/0.1): no longer an
  EndorsementCredential. `sign_statement` builds a StatementCredential with
  `new_vetted_vsc` under `https://registry.trustoverip.org/dtg/vsc/vetted/1`;
  the body is `credentialSubject.object.value`, with no `type` member.
  `taskContext` and `taskDigestMultibase` are both read from the
  `vetting/session` document, which `StatementDraft::session` now carries
  in place of `task_context`, and `StatementDraft::issuer_scope` is
  `directed` or `public` (pairwise is refused by the profile).
  `verify_statement` parses through `dtg-credentials`, so the v1 context,
  the one-subtype rule and the profile are checked by the code that issues
  them; `VerifiedVettingStatement::check_against_session` binds a statement
  to the session document by id and task digest.

  - `IdentityVettingEndorsement` -> `VettedObjectValue` (no `type`; digests
    and commitment must be base58btc, as the registry schema requires).
  - `IDENTITY_VETTING_ENDORSEMENT_TYPE` -> `VETTED_PREDICATE`.
  - `VerifiedVettingStatement::endorsement()` -> `value()`; new
    `issuer_scope()`, `task_digest_multibase()`.

  Vetter role credential (vtc/vetting/vetters/grant/0.1, vetting/request/0.1):
  a community-issued VAC, `issuerScope` public, `authority` { scope:
  <community DID>, actions: ["role:vetter"], maxAttenuation: 0 }.
  `eligibility::community_role` -> `community_roles`, returning every
  `role:<name>` of a VAC the community issued in its own scope with no
  parent; `verify_eligibility_vp` parses the VAC strictly and refuses a
  non-public scope or an attenuation.

  - `COMMUNITY_ROLE_ENDORSEMENT_TYPE` removed; new `ROLE_ACTION_PREFIX`,
    `VETTER_ROLE_ACTION`, `role_action`, `role_of_action`.
  - `protocols::members::ENDORSEMENT_CREDENTIAL_TYPE` removed; new
    `AUTHORITY_CREDENTIAL_TYPE` and `STATEMENT_CREDENTIAL_TYPE`.
  - `VerdictWith::role_vec` -> `role_vac` (wire `roleVac`).

- **vtc-service**: Website content moves as signed Trust Tasks ([#1839](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1839))

* feat(vtc-service)!: the policy log and the community's DID log are signed Trust Tasks

  policy/{list,get,active,upsert,activate}, vtc/policies/test and
  did-management/did/register are served by the spine
  (trust_tasks::policy_tasks) on every transport, with the signer's ACL row
  as authority: Admin for the policy verbs, an unrestricted Admin for the
  DID log, as the bearer routes' AdminAuth and SuperAdminAuth asked.
  policy/activate refuses a purpose the revision does not decide. The
  console signs every policy call.

  Per-type document limits come from the specifications: size.rs reads the
  codegen'd maxDocumentBytes (schema_index::max_document_bytes_for) and keeps
  an interim entry only for policy/upsert and did/register, whose specs
  declare none yet. A raised limit applies to a served type only, and only
  when the claimed issuer holds a live ACL entry (or is a signing key
  delegated by one), looked up before verification. The HTTPS cap is the
  largest served limit; a refusal does not echo an oversized type.



### Fixed

- **vta-service**: Passkey-only step-up once a subject has enrolled one ([#1854](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1854))

A subject with an enrolled passkey verification method must complete
  step-up with a WebAuthn assertion only: mint no longer offers the
  did-signed gate for such an approver, and handle_approve_response
  refuses a did-signed (or evidence-absent) approve-response for one
  with noGate, even if a stale client sends it anyway. A subject with no
  passkey keeps the original did-signed-or-webauthn offer.

  Passkey enrolment also clears any elevation the subject reached
  without a passkey, so a stepped-up session from before enrolment can't
  outlive the switch to passkey-only.

  Along the way, wires the webauthn step-up gate's credential-id lookup
  to the enrolled DID's local WebVH document instead of the
  still-stubbed generic resolver enumeration, which otherwise made every
  webauthn step-up approve-response fail closed.



## [0.30.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-common-v0.29.1...vti-common-v0.30.0) — 2026-09-30


### Added

- **vtc-service**: The administrator's operational verbs are signed Trust Tasks ([#1824](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1824))

The trust-registry reconciler, the audit log, the runtime configuration,
  admin invites and the auth service's sessions are served by the spine
  (trust_tasks::admin_tasks) on every transport, with the signer's ACL row
  as authority: the role and scope questions the bearer extractors asked,
  and an invite's step-up bound to the document.

  auth/sessions/list/0.1 answers { sessions: [Session] } under the
  revocation's authority (caller_covers_target); auth/revoke-session/0.2
  is served on the spine, and a refused revocation by subject is audited
  (SessionRevocationRefused). The console's drift read moves to
  git-ns/view/0.5.

  The bearer routes are removed, except GET /v1/audit/verify, which
  vtc-client still calls.

- **trust-tasks**: Advertise the acceptance window over trust-task-discovery 0.3 (VTI-TRN-047) ([#1817](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1817))

Both VTI node types refuse a document more than ten minutes (plus 60 s of
  skew) past its issuedAt (VTI-OPS-024). A sender holding a document before
  delivery has to know that window to decide when to issue a new attempt
  instead, and until now the only way to know it was to share the constant.
  trust-task-discovery/0.3 (trust-tasks #677, trust-tasks-rs 0.24.4) lets a
  responder state it.

  - Raise the trust-tasks-rs floor to 0.24.4, the first release carrying
    discovery 0.3, and trust-tasks-capability-client with it. Only those two
    lockfile entries move.
  - vti-common: `trust_task::acceptance::AcceptanceWindow` and
    `VTI_ACCEPTANCE_WINDOW` (ACCEPTANCE_WINDOW + DEFAULT_SKEW). This is the one
    value the consumers apply (`freshness_policy()`), the responders advertise
    (`advertised()`, rounded down so it is never wider, VTI-TRN-047), and the
    push engine judges staleness by (`past_max_age`, `refuses`).
    `trust_task::discovery` has the pattern grammar and the 0.1/0.3 response
    builders, so both nodes answer the same way.
  - VTA: serves trust-task-discovery/0.3 next to 0.1, answering each in the
    version it was asked. The window goes at response level, since the VTA
    applies one window to everything it dispatches. The 0.1 frameworkVersion was
    "0.2", a stale copy of the framework crate's default. It is now "0.6",
    the MAJOR.MINOR of the 0.6.0 that 0.3 writes, so one responder no longer
    names two framework releases.
  - VTC: serves trust-task-discovery/0.3 for the first time. It answers
    identified callers only, as the VTA does, and lists the routing table itself
    (DISPATCHED_URIS plus the rooms and git-ns registrations).
  - Registrations: TASK_TRUST_TASK_DISCOVERY_0_3 in vta_sdk::trust_tasks and
    its task list, ReadOnly in retry_safety, the VTA dispatch table and its
    conformance witness (built from the real builder, not a literal), and the
    VTC DISPATCHED_URIS and its declared-URI census.
  - Push engine (VTI-TRN-045): its two staleness predicates now read
    VTI_ACCEPTANCE_WINDOW, the same value the nodes advertise, where before
    they combined two separate constants. It still reads no advertised window.
    A lookup would be a request/reply exchange, and every push is one-way.
    None of the recipients (approvers' devices, wallets, requesters) serves
    discovery. The window only matters when the recipient cannot answer. The
    engine never sees an `expired` refusal, so 0.3's "re-ask after an
    unexpected refusal" would have no trigger. The module docs and
    docs/05-design-notes/retry-and-idempotency.md say so. What remains of the
    spec's divergence F.3 is the producer side only.



### Fixed

- **vti-common**: Step-up gate reads the session's level, not the token's ([#1842](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1842))

A step-up (`auth/passkey/login/finish/0.2`, `purpose: stepUp`) elevates the
  session row and mints no new token; the spec has the caller's existing tokens
  pick the elevation up at introspection. `check_fresh_step_up` nonetheless
  required `claims.acr == "aal2"` from the JWT, so a session that signed in at
  aal1 (SIOPv2, DID-signed authenticate) kept an aal1 token for its whole life
  and could never satisfy any StepUpAuth / `elevation::verified` gate. In the VTC
  console that surfaced as "passkey verification did not complete" on enabling
  console signing, after the passkey ceremony had succeeded.

  The gate now checks the row's `acr` and the live elevation window. The window
  remains the authority: only a step-up writes it.



## [0.29.1](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-common-v0.29.0...vti-common-v0.29.1) — 2026-09-28


### Added

- **storage**: Optional Fjall memory settings for the VTA and VTC ([#1803](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1803))

Add STORAGE_FJALL_BLOCK_CACHE, STORAGE_FJALL_WRITE_BUFFER and
  STORAGE_FJALL_MAX_JOURNAL, plus a matching [fjall] config-file table, so
  an operator can keep fjall's block cache, buffered writes and startup
  journal replay inside a pod's Kubernetes memory limit.

  All three are optional and shared, unprefixed names for every consumer
  (vti_common::config::FjallTuning, apply_fjall_env_overrides). Unset
  leaves fjall's own defaults byte for byte; an env var overrides the
  config file; an invalid, zero, or absurdly small value is refused at
  startup naming the setting. Values accept a plain byte count or a
  suffixed size ("64MiB", "512MB", "1GiB").



## [0.29.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-common-v0.28.0...vti-common-v0.29.0) — 2026-09-27


### Fixed

- **push**: Re-issue a push as a new attempt once it outlives its freshness window ([#1799](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1799))

The push engine (vti_common::trust_task_push) signed a document once and
  sent the same bytes for the whole push deadline: within an attempt the
  outbox retries the hop for up to an hour, escalation and the never-queued
  re-queue resend record.document unchanged, and deadlines run to 24 h
  (credential-exchange) or 30 days (removal notice). Both VTI consumers
  refuse a document older than 10 min + 60 s skew as `expired`
  (freshness_policy, issuedAt required), so any delivery after ~11 minutes
  was silently refused at the far end, and a copy collected late by a
  reconnecting recipient was even recorded "delivered".

  Re-signing under the same id is ruled out by SPEC §4.3/§8.4: a re-stamped,
  re-signed document is a different document under a reused id, which the
  consumer's ReplayGuard (keyed on id + digest of the whole document, proof
  included) refuses as idConflict. expiresAt cannot help either:
  validate_freshness applies max_age to issuedAt regardless, and both
  consumers cap the replay record at issuedAt + max_age + skew by design;
  honouring a producer-chosen expiry would stretch an in-memory replay
  record and widen replay exposure across restarts.

  So the engine issues a SPEC §8.4 new attempt (trust_task_push::new_attempt:
  fresh id, fresh whole-second issuedAt, re-signed by the node through the new
  PushReissuer, kept in the original's thread, every other member including
  idempotencyKey unchanged) wherever it would otherwise put a document past
  its acceptance window on the wire: when queuing any attempt; when an attempt
  still waiting for hand-off crosses the window (superseded on the same
  transport, same window end); and when a copy is collected after the window
  plus skew (the recipient is online now and refused what it collected).
  A mediator-held copy is out of reach and not re-sent per window; bounded by
  MAX_REISSUES. The window is now one constant, trust_task::ACCEPTANCE_WINDOW,
  read by both consumers and the engine.

  Duplicate execution across attempts is what idempotencyKey is for
  (VTI-OPS-061/064): the credential-exchange push sites (VTA push_step, VTC
  push_document) now carry a key, and the VTA consumer now keys tasks the
  retry_safety catalogue does not classify, as VTI-OPS-062 requires; before,
  it skipped every counterparty credential-exchange step. Replay exposure is
  unchanged: same window, same replay record, and a byte-identical replay of
  a new attempt is still refused by id.

- **acl**: Offline provision-integration can write its admin grant again (VTI-ACL-053) ([#1792](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1792))

`vta bootstrap provision-integration` runs offline as the synthesised
  `cli:provision-integration` principal, and writes the integration's admin
  grant through `operations::acl::create_acl`. #1738 made `create_acl` bound
  every write by the caller's own stored entry and refuse a caller with none
  (VTI-ACL-053). The CLI principal never has an entry, so every offline
  first-time setup on vta-service 0.44.0 failed with:

      provision-integration: forbidden: cli:provision-integration has no ACL
      entry of its own, so there is no authority to bound this change by
      (VTI-ACL-001, VTI-ACL-053)

  The offline CLI is not a caller on the operation surface. It runs with the
  node stopped, as the OS account that holds the store and the seed, and the
  other offline writers (`vta acl create`, `vta import-did`) already store
  entries directly with nothing more to answer to. The specification now says
  so explicitly (dtgwg-vti-spec#46, "Offline writers" note under VTI-ACL-053).



## [0.28.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-common-v0.27.0...vti-common-v0.28.0) — 2026-09-27


### Added

- **attestation**: The TEE attestation reads are public Trust Tasks, over any transport ([#1776](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1776))

* feat(attestation)!: the TEE attestation reads are public Trust Tasks, over any transport

  A TEE VTA answered three attestation reads only as unauthenticated REST routes
  (`GET /attestation/status`, `GET`/`POST /attestation/report`,
  `POST /attestation/config-report`), plus a bare DIDComm protocol arm that
  nothing sent to. Under the rule that every remote API is a spec-first,
  spine-dispatched Trust Task reachable over TSP, DIDComm and HTTPS, they are now
  `vta/attestation/{status,report,config-report}/0.1` (trustoverip/
  dtgwg-trust-tasks-tf#654, trust-tasks-rs 0.23.2), dispatched on the spine.

  Public tasks
  - `vta_sdk::trust_tasks::PUBLIC_URIS` names the tasks a caller may send with no
    identity: no session, no ACL entry, no request proof. A verifier asks before
    it trusts the VTA; the nonce bound into the evidence is what makes a report
    its own, and every response is the VTA's signed operational document.
  - HTTPS: `/trust-tasks` takes an optional credential. An anonymous caller may
    send only a public task (anything else is 401), capped at 64 KB, and those
    requests are charged to the unauthenticated limiter — which charges only
    requests presenting no credential, decided by the extractor's own rule
    (`vti_common::auth::extractor::presents_credential`), so a junk header cannot
    move a request between the two classes.
  - DIDComm/TSP: a sender the ACL does not know gets a zero-authority claim for a
    public task, and `bind_document_to_sender` accepts it unsigned — the spec
    makes the request proof OPTIONAL and HTTPS accepts it unsigned, so refusing it
    here would make the requirement depend on the transport (VTI-OPS-021). An
    attached proof is still verified and bound.
  - A census (`every_public_task_is_proof_optional_and_read_only`) fails if a task
    whose spec requires a proof, or whose dispatch class changes state, discloses
    a secret or acts as its subject, is ever added to `PUBLIC_URIS`.

  Behaviour
  - `report` and `config-report` require a 32-byte verifier nonce; the cached,
    nonce-less report is not carried over — evidence nobody asked for is evidence
    anybody can replay.
  - Failures carry the specs' declared codes: `notAttested` (no provider),
    `noConfigSnapshot` (only the enclave front-end captures one),
    `evidenceUnavailable` (the platform refused a quote).
  - The VTA still requires `issuedAt` on every document (bounding its replay
    record), stricter than the spec; the deploy README examples send it.

  Removed (breaking)
  - The REST routes above and the DIDComm `firstperson.network/vta/1.0/
    attestation/*` arms, with their SDK constants; `TASK_ATTESTATION_{STATUS,
    REPORT}_1_0` become `TASK_ATTESTATION_{STATUS,REPORT,CONFIG_REPORT}_0_1` and
    leave `REST_ROUTED_URIS`.
  - The `TeeAttestation` DID-document service, which pointed at the REST route
    (user decision: removed, not re-pointed). `tee.embed_in_did` and
    `VTA_TEE_EMBED_IN_DID` are **refused** at config load as retired, naming the
    replacement, rather than silently ignored. The shipped Nitro configs drop the
    key; the deploy scripts' health hints point at `/health`.

- **vtc**: Step-up passkeys a member enrols through an admin's invite ([#1756](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1756))

* feat(vtc/git-ns): separation of duties and break-glass for elevated git rights

  Implements trustoverip/dtgwg-trust-tasks-tf#641.

  - Fixed rule 7: no elevated self-grant (git.ns.admin, git.repo.create,
    git.repo.own) through grant 0.1/0.3, drift adopt, repo/adopt or reseat;
    refused git-ns:selfGrantNotAllowed, naming cnm git break-glass.
  - git-ns/right/break-glass/0.1: grant authority, or a community admin on a
    headless namespace; always an operation-bound passkey step-up
    (acl::bound_step_up, whose spent mark now yields its evidence); mandatory
    justification; immediate, no expiry; flagged breakGlass on the record.
  - git-ns/right/ratify/0.1 and revoke 0.3: another administrator ratifies,
    bound to breakGlass.at; any community admin may revoke an unratified one,
    which policy cannot refuse. Unratified records do not count toward the
    last-owner and last-admin invariants.
  - Visibility no policy can turn off: AuditEvent::GitNsBreakGlass at
    AuditSeverity::Critical with the step-up evidence, activity items, a signed
    git-ns/right/break-glass-notice/0.1 to every community admin and ns admin,
    view 0.4, GET /v1/git-ns/break-glass, and breakGlass on the rights rows.
  - git_ns.rego settings: break_glass (enabled by default), a delay and a
    minimum justification; deny decisions on right.breakGlass and right.ratify.
  - cnm: git break-glass, git ratify and git break-glass-list; git view flags
    break-glass rights; grant and revoke move to 0.3.



### Fixed

- **sdk**: Holder signing picks its proof purpose, and Trust Task endpoints must be https ([#1791](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1791))

* fix(vault): sign-trust-task picks the proof purpose from the document type

  vault/sign-trust-task signed every document for assertionMethod. Under
  VTI-KEY-022/106 an operational Trust Task is signed for authentication, and
  relying parties that enforce it (the DID hosting control plane since
  affinidi-webvh-service#218) refused every task a proxy-login wallet session
  had the VTA sign.

  The VTA now decides the purpose from the envelope's type alone:
  assertionMethod only for the registry's attestation types
  (auth/step-up/approve-response, task-consent/decision, confirm/response),
  authentication for everything else, including their #response variants and
  a private registry's reuse of those slugs. The requester cannot choose it;
  a type that is not a Type URI is refused as envelopeInvalid.

- **vault**: Sign-trust-task picks the proof purpose from the document type ([#1788](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1788))

* fix(vault): sign-trust-task picks the proof purpose from the document type

  vault/sign-trust-task signed every document for assertionMethod. Under
  VTI-KEY-022/106 an operational Trust Task is signed for authentication, and
  relying parties that enforce it (the DID hosting control plane since
  affinidi-webvh-service#218) refused every task a proxy-login wallet session
  had the VTA sign.

  The VTA now decides the purpose from the envelope's type alone:
  assertionMethod only for the registry's attestation types
  (auth/step-up/approve-response, task-consent/decision, confirm/response),
  authentication for everything else, including their #response variants and
  a private registry's reuse of those slugs. The requester cannot choose it;
  a type that is not a Type URI is refused as envelopeInvalid.



## [0.27.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-common-v0.26.0...vti-common-v0.27.0) — 2026-09-26


### Added

- **vtc/git-ns**: Separation of duties and break-glass for elevated git rights ([#1745](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1745))

* feat(vtc-service): re-project git roles, and use the bridge's reported role map

  Implements two follow-ups to the configurable bridge role map (VGI #84),
  spec-first in trustoverip/dtgwg-trust-tasks-tf#639.

  git-ns/bridge/event 0.3 (roleMapReported)
  - Served beside 0.1 and 0.2; all three are read as 0.3 by one handler.
  - The report is refused malformedRequest when a map is unordered
    (own >= maintain >= commit, commit <= write) or lists a repository
    twice, and permissionDenied when a repos/stale resource lies outside
    the namespace. Otherwise it is kept on the namespace (git_ns::role_map),
    and only while the same bridge DID serves it.
  - Each stale active or orphaned repository has its roles digest
    forgotten, so the projector re-sends its complete desiredRoles without
    anyone asking. A repository leaves `stale` when a projectRoles job
    queued after the report succeeds.
  - drift/resolve adopt derives the right from the map: the lowest right
    whose role is the observed one. A revert weighs as revoking own when
    the role is at or above the one own projects to. Without a report the
    default map is assumed. A namespace admin gets no forge role under any
    map.

  git-ns/roles/reproject 0.1
  - Open to a community administrator, or to git.ns.admin on the namespace
    by explicit record. A repository owner is refused. Covers a namespace
    (every active or orphaned repository) or one repository. Normal consent
    class, policy action roles.reproject, audited as
    gitNs.roles.reprojected. Refused with manualMode or noForgeAccess.
  - `cnm git reproject <resource> [--reason]` and
    vtc-client git_ns_reproject.

  Console (Repos)
  - The namespace and repository rows carry the effective role map
    (roleMap, roleMapSource, roleMapStale).
  - The people tables show each person's effective forge role, and "no
    forge role" for a namespace admin.
  - Drift adopt and revert use projectedRight / driftRevertImpact over the
    repository's map. rightForForgeRole is removed.
  - Stale repositories are flagged, and the namespace card and repository
    header gain a "Re-project roles" button.

  Behaviour change: on a personal account a revert of collaborator write
  (or above) now weighs as revoking own, because write is the role own
  projects to there. Before, it weighed as revoking maintain.



### Security

- **acl**: No principal widens its own entry, and no grant exceeds its granter (VTI-ACL-052, VTI-ACL-053) ([#1738](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1738))

* security(acl)!: no principal widens its own entry, and no grant exceeds its granter (VTI-ACL-052, VTI-ACL-053)

  A context-scoped admin, such as a companion service's credential
  (`--role admin --contexts vgi-bridge`), could raise its own authority.
  `update_acl` had no self check and no test either way. Tests written
  against main confirm every case below. Adding a foreign context or
  raising the role was already refused. What went through was clearing
  any narrowing on the caller's own entry, and minting a sibling entry
  that carried none of it:

  - Self-update to clear its capability narrowing, drop its key filter,
    or extend its expiry. All three succeeded.
  - A create for another DID it controls, in the same context, with none
    of its own narrowing: full capabilities, no key filter, no expiry.
  - An update that cleared another entry's narrowing past what the caller
    itself held.
  - Self role change (`acl/change-role`).
  - Rotation (`acl/swap-key`) rebuilt the entry field by field. It dropped
    `expires_at`, `allowed_keys`, `approve_scope` and the step-up fields,
    so a one-hour bootstrap grant became permanent. It also dropped
    `created_by`. This violated VTI-CLT-029.
  - An initiator could grant approve authority it did not hold
    (VTI-ACL-042).
  - A context admin could update or delete an entry that also acts in a
    context it does not administer, because overlap was enough.

  VTA (`operations/acl.rs`, the choke point for REST, DIDComm, TSP and the
  Trust Task spine):

  - update and change-role refuse the caller's own entry (VTI-ACL-052).
    Delete already did.
  - create, update and change-role measure the resulting entry against
    the caller's stored entry (`validate_within_caller`, VTI-ACL-053). The
    entry must not exceed the caller's effective capabilities (additive
    ones stay under VTI-ACL-033), key filter, expiry, or confer authority
    (VTI-ACL-042). A caller with no live entry writes nothing.
  - update, change-role and delete require the caller to cover every
    context the entry acts or approves in, not just overlap
    (VTI-ACL-050 as tightened).
  - update re-runs the role and act-scope checks on the patched entry, so
    a role change alone cannot turn "nowhere" into "everywhere".
  - swap-key copies the entry exactly and only moves the subject. It
    refuses an expired entry (VTI-CLT-029).

  VTC (`routes/acl.rs`, `routes/admin/invites.rs`,
  `routes/members/update.rs`):

  - An `acl/grant` rewrite of your own entry is refused. Before, a re-grant
    with no `expiresAt` made a time-boxed admin permanent.
  - `acl/change-role` refuses your own entry in either direction; the
    ceremony already refused self-promotion.
  - `vtc/members/update` refuses a role or label change on your own entry.
  - Rewrite, change-role and revoke (including scoped revoke) require
    full coverage for every role, not only admin targets.
  - A grant cannot outlive the granter's expiry, and a granter with no
    live entry is refused.
  - `vtc/admin/invites/create` requires an unrestricted admin. It writes
    a community-wide admin entry, and a context admin could previously
    invite a DID it controls into one.



## [0.26.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-common-v0.25.0...vti-common-v0.26.0) — 2026-09-26


### Added

- **vta-service**: Sign operational documents with the operational key ([#1740](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1740))

* fix(vta-service)!: require a document proof bound to the sender on every DIDComm and TSP trust task

  A Trust Task that reaches the VTA or the VTC over an intrinsic-sender
  transport (DIDComm, TSP) is now accepted only when the document carries a
  Data Integrity proof that verifies as its `issuer`, and that issuer is the
  transport-reported sender. The transport's sender alone no longer
  authorizes anything (VTI-OPS-021/093).

- **vtc**: Install a co-admin, and audit the offline ACL break-glass (VTI-APV-014) ([#1750](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1750))

Last of four for VTI-APV-014. Since #1741, making anyone an unrestricted
  admin needs another unrestricted admin's consent. That left two gaps.

  A community installed with one unrestricted admin has nobody to consent, so
  it could only add a second offline. `vtc setup` now takes an optional
  `co_admin_did` (a prompt interactively) and refuses one equal to the first
  admin. The install bootstrap writes the co-admin as an unrestricted admin in
  the same step as the first, audited as `AclGranted` by `did:key:vtc-install`.
  The co-admin needs no passkey to consent, since a decision is a document its
  DID signs. It gets the empty admin sister record a promotion writes, so it can
  enrol a passkey later through an invite.

  The offline ACL writers are the way out when there are too few admins. They
  skip the step-up, the consent and the attrition rules by design, and they left
  no trace: `vtc acl add` and `remove`, `vtc create-did-key --admin` and `vtc
  admin invite`. Each now queues a record in the `install` keyspace in the same
  store session as the write. On its next boot the daemon writes an
  `AclBreakGlassWritten` audit row for each, under `did:key:vtc-break-glass`,
  naming the command, the change, the DID and the host. This is how the
  emergency-bootstrap marker already works, because the offline commands hold no
  audit writer.

  The new audit variant is additive (`AuditEvent` is `#[non_exhaustive]`).

- **vtc**: Acl/grant on the signed door, with a passkey gesture bound to the grant ([#1641](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1641)) ([#1718](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1718))

`acl/grant` is the first verb on the VTC's signed-document door that confers
  administrative authority, and the reason none had moved: conferring admin
  needs a passkey gesture, the bearer route reads that from the session's live
  elevation, and a signed document has no session. `admin_signer` builds its
  claims with an empty `session_id`, so the gate could only ever fail closed.

  The design (`vtc-operation-bound-step-up.md`, #1713) binds the gesture to the
  one operation instead, as VTI-APV-003 now permits and VTI-APV-015 describes
  (dtgwg-vti-spec#40), using the wire dtgwg-trust-tasks-tf#631 published in
  trust-tasks-rs 0.22.7:

  1. A signed `acl/grant` that would confer admin authority runs every check the
     bearer route runs — the same `plan_grant` — and then finds no gesture for
     `(acting admin, digest of type + payload)`. It starts a WebAuthn ceremony
     over the acting admin's own passkeys, parks it for 300 s, and refuses
     `permissionDenied` with the ceremony inline as `details.stepUpRequest`: an
     `approve-request/0.3` payload with `boundTo` (the digest salted with the
     challenge) and no `sessionId`. The spine releases the refused document's
     `id`.
  2. The admin answers with `auth/step-up/approve-response/0.4` carrying
     `webauthn` evidence. The assertion must verify against the parked ceremony,
     assert user verification, and come from a passkey registered to the acting
     admin. The answer is `recorded`; nothing is elevated.
  3. The identical document is sent again. The recorded gesture is removed before
     the grant commits, so it authorizes that grant once and nothing else.

  A console key acts as its admin, so it can sign the grant and redeem the
  gesture, but cannot make one: only a `webauthn` assertion records a gesture,
  and a `didSigned` or absent `evidence` is refused `noGate`. The bearer route is
  unchanged and keeps its session gate; the two doors now share `plan_grant` and
  `commit_grant` and differ only in where the gesture is read from.

  - `vtc-service/src/acl/bound_step_up.rs`: the digest (`vtc/step-up/v1\0`,
    length-prefixed URI and JCS payload, SHA-256 multihash), the pending and
    redeemable marks, and the TTL sweep. New keyspace `step_up_marks`, excluded
    from backup.
  - `vti-common`: `AuditEvent::OperationStepUpRecorded` names the task, the salted
    `boundTo` and the credential. `AuditEvent` is `#[non_exhaustive]`, so the
    variant is additive.
  - trust-tasks-rs floor raised to 0.22.7 for `approve-request/0.3` and
    `approve-response/0.4`.

  `tests/signed_step_up.rs` drives the loop with the soft authenticator and holds
  the refusals the design lists: a gesture for one grant does not authorize
  another, a spent gesture is gone, a challenge is answered once, a signature
  alone records nothing, a silent (non-UV) assertion and another admin's passkey
  are refused, a grant that confers nothing asks for no gesture, and a grant that
  would be refused anyway never asks.

  One difference from the design note, recorded in its new §8: the gate is not a
  spine step ahead of dispatch. Whether a grant needs a gesture depends on the
  entry it would replace, and a gesture must not be asked for a grant another
  check would refuse, so the verb calls the gate between `plan_grant` and
  `commit_grant`. The handler is transport-neutral, so REST, DIDComm and TSP
  still reach the same call.

  `acl/change-role` is next, then VTI-APV-014's second-party consent.



### Changed

- **vti-common**: Share the durable Trust Task push engine between nodes ([#1760](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1760))

#1754 gave the VTC a push engine that picks TSP > DIDComm > REST by what the
  recipient's DID document advertises. It records each push durably, queues one
  outbox attempt per transport, settles on delivery evidence and escalates when
  an attempt yields none (VTI-TRN-030, -040, -041, -042). The VTA's own pushes
  (`consent_request::push_one`) are still best-effort TSP followed by DIDComm,
  and to adopt the same model the engine has to live somewhere both nodes can
  reach.

  It moves unchanged to `vti_common::trust_task_push`. The node lends it what is
  its own through a `PushContext`: the records keyspace, the outbox, the
  resolver, its messaging handle and whether it can send TSP. The REST transport
  takes its HTTP client, so each node supplies its foreign-fetch profile.
  `vtc-service::member_push` is now that adapter, and its call sites are
  unchanged.

  The outbox transport ids keep their `member-push-*` values, so attempts queued
  before an upgrade still drain after it. `vti-common`'s `tsp` feature now also
  enables `affinidi-tdk/tsp` and `vta-sdk/tsp` for the TSP transport. That
  exposed two items in `vta-sdk` gated on `tsp` but used only with `client`,
  which are now gated on both.

  The VTA moving onto the engine is a follow-up.

- **vti-common**: Move the task-consent core out of vta-policy so the VTC can share it (VTI-APV-014) ([#1730](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1730))

VTI-APV-014 requires consent from a party other than the requester before
  anyone is granted unrestricted act scope. The VTC is to meet it with the same
  `task-consent/*` ceremony the VTA runs (VTI-VTC-020: one model, not a parallel
  one), but the ceremony's data layer lived in `vta-policy`, which the VTC cannot
  depend on. This moves it to `vti-common` first, so the VTC work that follows
  reuses it rather than copying it.

  - `vta-policy/src/consent.rs` -> `vti_common::task_consent` and
    `vta-policy/src/effects.rs` -> `vti_common::task_consent::effects`, moved
    with their history. `vta_policy::{consent, effects}` re-export them, so
    every existing path still resolves and the VTA's behaviour is unchanged.
  - `domain_digest(domain, type_uri, payload, salt)` exposes the digest
    construction for another domain tag. The VTC's operation-bound step-up
    carried a byte-for-byte copy of it under `vtc/step-up/v1\0`; it now calls
    this instead.
  - `digest_matches_its_pinned_vectors` pins both domains against vectors
    computed independently of this code, so the move provably changed no
    digest: a stored pending or grant, and a mark in flight, still resolve
    after an upgrade.
  - The `vta/task-consent/v1\0` tag is kept, since it keys the pendings and
    grants in flight. It separates this digest from others, not one node from
    another, because a pending never leaves the node that minted it.

  No wire change and no behaviour change.

- **vti-common**: Move the node-neutral backup transfer core out of vta-backup ([#1641](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1641)) ([#1721](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1721))

The community node needs the backup transfer the agent already has. A VTC
  backup, like any real node's, is too large for one Trust Task document, and the
  node-neutral `backup/*` family (trustoverip/dtgwg-trust-tasks-tf#633, released
  in trust-tasks-rs 0.22.7) is how it moves: a bundle, a manifest committed before
  any byte moves, chunks pulled and pushed by index, a finalize that checks the
  assembled bytes before trusting them.

  `vta-backup` implements all of that for `vta/backup/*`, but the VTC cannot
  depend on it — it pulls `vta-config`, `vta-keys`, `vta-support` and `vta-webvh`.
  Only a thin layer of it is the agent's: serializing the agent's state into an
  envelope, and applying one. The rest never asked what a bundle contains.

  So that rest moves to `vti_common::backup_transfer`, which both nodes already
  depend on for storage and auth:

  - `bundle_store` — the `BundleRecord` state machine, token minting and the
    constant-time token check (was `vta_backup::backup_bundle_store`);
  - `sweeper` — TTL expiry and retention (was `vta_backup::backup_bundle_sweeper`);
  - `chunked` — staging, the chunk plan, `get_chunk`, `initiate_import`,
    `put_chunk`, `finalize_precheck` and the per-DID rate limiter (was
    `vta_backup::ops::chunked`), plus `check_initiate` and a node-neutral chunked
    `complete_export`;
  - the ownership, kind, TTL and open-bundle-cap rules, and `abort`, from
    `vta_backup::ops::descriptors`.

  Files moved with `git mv`, so their history follows them. `vta-backup`
  re-exports every moved module under its old path, keeps `initiate_export`
  (which serializes the agent's state and hands the bytes to `stage_export`), and
  routes `abort_bundle` through the shared `abort`. No behaviour changes, and no
  public path in `vta-backup` disappears.

  `vti-common` gains `subtle`, and now declares the tokio `fs` and `io-util`
  features the moved code uses. `vta-backup` had used `tokio::fs` without
  declaring `fs`, building only by feature unification.

  The 32 moved tests run in `vti-common`, and `vta-backup`'s own suite (54) is
  unchanged. The VTC's `backup/*` handlers follow in the next change.



### Fixed

- **vta-service**: Require a document proof bound to the sender on every DIDComm and TSP trust task ([#1739](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1739))
- **vti-common**: Bind the authcrypt sender key id to the key used, before trusting a DIDComm sender ([#1732](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1732))

An authcrypt (ECDH-1PU) JWE names its sender key twice in the protected
  header: `skid` and `apu` (the PartyUInfo the key derivation is bound to). A
  conforming packer writes the same key id into both. The direct-unpack callers
  now require that the two agree, and that the key the unpack metadata reports is
  that same key, before a sender is trusted.

  - New `vti_common::auth::verify_authcrypt_header(raw_jwe)`: for an ECDH-1PU
    outer layer (JSON or compact serialization) requires `skid` to be a DID URL
    with a key fragment, `apu` to be present, and `BASE64URL-decode(apu)` to be
    exactly the `skid` bytes. Any other `alg` is refused, so authcrypt nested
    inside anoncrypt is not accepted on these paths.
  - `bind_authcrypt_sender(raw_jwe, message, metadata)` now takes the raw
    envelope and requires: the header check; an `authcrypt(plaintext)` or
    `authcrypt(sign(plaintext))` wrapping; `encrypted_from_kid == Some(skid)`;
    and `DID(from) == DID(skid)`.
  - Callers updated: VTA `/auth/`, `/auth/refresh`, vault unseal; VTC
    `/v1/auth/`, `/v1/wallet/auth/` and refresh.
  - New `vti-common` `test-support` feature with builders for authcrypt
    envelopes with a caller-chosen protected header; route tests on both
    services.



### Security

- **vta-sdk**: Verify a proof's key against its proofPurpose (VTI-KEY-022) ([#1752](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1752))

* security(vta-sdk)!: verify a proof's key against its proofPurpose (VTI-KEY-022)

  A verifier accepted any key the signer's DID document listed under
  verificationMethod, whatever the proof declared it was for. A key published
  only for keyAgreement, or authorised only to authenticate, could make an
  assertionMethod proof.

  vta-sdk adds ProofPurpose, PurposeVmResolver and PurposeBound.
  TrustTaskVmResolver now resolves a method only for one purpose, and only
  when all of these hold:
  - the resolved document is the DID's own;
  - the method is listed under the relationship the purpose names, by
    absolute DID URL, by relative fragment, or embedded. A reference resolves
    only against the top-level verificationMethod set;
  - the method's controller is the DID.

- **vta-service**: Require assertionMethod on an approver's decision ([#1757](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1757))

* fix(vta-service)!: require a document proof bound to the sender on every DIDComm and TSP trust task

  A Trust Task that reaches the VTA or the VTC over an intrinsic-sender
  transport (DIDComm, TSP) is now accepted only when the document carries a
  Data Integrity proof that verifies as its `issuer`, and that issuer is the
  transport-reported sender. The transport's sender alone no longer
  authorizes anything (VTI-OPS-021/093).

- **resolver**: One bounded DID-document cache per node, re-resolved once before a verification fails (VTI-KEY-134) ([#1737](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1737))

* security(resolver)!: one bounded DID-document cache per node, re-resolved once before a verification fails (VTI-KEY-134)

  The VTC ran two DID-document caches: the app resolver built in
  `init_auth`, and a second one the messaging TDK built for itself
  because it was given none. Both used the SDK defaults of a 300 s TTL and
  100 entries. Every DIDComm and TSP message on the mediator socket was
  checked against a cache the REST and Trust Task paths could not see or
  evict. Neither cache was ever refreshed when a verification failed, so
  a peer that rotated was refused as a forger until its entry aged out.

  Bounded TTL (key-roles, dtgwg-vti-spec #42: VTI-KEY-060/062/122/123/134):

  - A new `[did_cache]` section (`vti_common::config::DidCacheConfig`)
    holds `ttl_secs` (default 60, refused outside 1..=300) and `capacity`
    (default 1000). The VTA and the VTC read the same type.
  - The TTL is what bounds how long a key revoked for compromise keeps
    verifying: VTI-KEY-123 allows no overlap, and nothing else notices a
    removal. A new key does not wait on the TTL, because of the refresh
    below. 60 s caps the revocation window at a minute, for one resolution
    per active DID per minute. 300 s, the SDK default and the old
    behaviour, is the ceiling.
  - `vta_sdk::resolver::build_verifier_did_cache_config` builds it, with
    the webvh host policy the VTA already used. The VTC now uses that
    policy too, so the private-host opt-in reaches it as well.

  One cache:

  - The VTC messaging TDK is handed the app resolver.
  - The VTA already shared its resolver. Its fallback when there is no
    app resolver now gets the same bounds, not the SDK defaults.

  Re-resolve once, then fail closed (`vta_sdk::did_refresh`):

  - `resolve_for_vm`: when a cached document does not list the method a
    proof names, re-resolve it fresh once. This covers every Trust Task
    proof on both nodes (`TrustTaskVmResolver`) and the VTC credential/VP
    resolver (`DidVmResolver`).
  - `verify_trust_task_proof_with`: when verification fails and the
    signer's document came from the cache, evict it and verify once more.
    This covers a key id kept with its material replaced.
  - `unpack_refreshing_sender`: when an authcrypt unpack fails, evict the
    sender named in the protected header (`skid`) and retry once. It is
    used on the REST DIDComm auth and refresh paths of both nodes.
  - Each forced refresh is rate-limited per DID (5 s, with at most 4096
    DIDs tracked). A failing proof is something anyone can send, and
    without the limit each one would make this node fetch a third party's
    document.

- **vtc**: Unrestricted admin needs another admin's consent (VTI-APV-014) ([#1741](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1741))

* security(vtc)!: unrestricted admin needs another admin's consent (VTI-APV-014)

- **auth**: Retire the superseded refresh token when a DID logs in again ([#1683](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1683))

* security(auth)!: retire the superseded refresh token when a DID logs in again

  Rotation makes a stolen refresh token worth one use, and reuse detection
  notices it when it comes back. Neither could see a token that is never
  presented twice.

  `/auth/` is keyed per DID and overwrites `session:{did}`, but the reverse
  index is a separate `refresh:{hash}` row per token, and `/auth/refresh`
  authorises from that index alone — it never consults
  `session.refresh_token`. A login that merely added its own index row left
  the previous one live, so one account carried two working chains that
  shared no token: each refreshed into its own successor, no replay ever
  occurred, and detection never fired. A token stolen before a re-login kept
  working indefinitely and silently, alongside its owner's, and the one
  recovery step a user can take unaided — logging in again — did nothing to
  it.

  `handle_authenticate` now retires the outgoing token. It reads the prior
  session's `refresh_token` before `store_session` overwrites the row,
  removes that token's index entry with the atomic claim-and-delete (so two
  racing logins cannot both retire it, preserving VTI-SES-030), and leaves a
  tombstone in its place. Ordered after the new chain is durable, as on the
  rotation path; both writes log on error rather than failing a login that
  has already committed and minted its tokens.

  `RefreshTombstone` gains `cause` to record why a token was retired.
  `Superseded` is excluded from the innocent-retry grace window on purpose:
  that concession answers a lost rotation response, and a client that has
  just logged in holds its replacement. Honouring a replay there would have
  handed the new token to whoever replayed a pre-login theft — strictly worse
  than the gap being closed.

  Replaying a superseded token is refused and audited as
  `AuthAuditEvent::RefreshSuperseded` (`warn!`, `security_alert = true`), but
  the session is left running. Unlike reuse, the presented token is already
  dead — the login took its index — so revoking adds nothing against a thief,
  while the ordinary cause is a second device still holding what it was
  issued before the user signed in elsewhere. Killing the session there would
  sign out the client that is demonstrably current, and the re-login it
  forces would set the same trap again. The event still carries
  `security_alert` because a pre-login theft and a stale device are
  indistinguishable from the node's side; only an operator correlating them
  can say which it was.

  `cleanup_expired_sessions` now also sweeps `refresh:` entries that their
  session no longer names. Retirement fixes new logins but cannot reach
  entries already written, and those rows carry no TTL and are not inert: an
  orphan resolves again as soon as its DID has a session row, so it outlives
  a revocation and returns at the next login. The sweep is safe against a
  concurrent login or rotation because every writer stores the session row
  before its index entry, so an entry that disagrees with its row is stale
  rather than half-written.

  Also in this change: `RefreshReuseDetected` takes its `did` from the
  tombstone, so the alert names the account on the `SessionGone` path where
  the session row is absent by definition; the lost-response retry log
  carries `audit = true`, since a stable session id had left it
  indistinguishable from an ordinary rotation; and the module header no
  longer describes a delete-and-recreate the handler stopped doing.

  `refresh_reuse_grace` stays at 30s, now documented as a starting point
  rather than a ceiling — a client only discovers a lost response when its
  own HTTP timeout fires, so a deployment whose clients retry later than that
  may want 60s. It is a user-experience call, not a security one: the
  successor-unspent condition, not the clock, is what keeps the concession
  narrow. `0` still disables it entirely.

- **vta**: Session and consent operations are scoped to the caller's authority ([#1717](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1717))

Found by the scope sweep that followed FTL-29904 ([#1715](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1715)). Both surfaces
  checked the caller's role and never the subject or datum it acted on.

  Sessions (VTI-SES-043, VTI-ACL-050). Any admin could list every session on
  the VTA and end any of them, a super-admin's included, via
  `DELETE /auth/sessions?did=`, `DELETE /auth/sessions/{id}` and
  `auth/revoke-session`; initiators could list them all. Session management now
  follows ACL management: `operations::acl::may_manage_subject` answers "may
  this caller act on this subject" with the rule `acl/delete` applies (the
  caller itself, a super-admin, or a managing role that can see the subject's
  entry and is at least as privileged). A super-admin's entry names no context,
  so a scoped admin never reaches it; a subject with no entry belongs to no
  context and only a super-admin reaches it. `GET /auth/sessions` lists only
  the subjects the caller may manage. `auth/revoke-session` keeps its
  no-disclosure answer (revokedCount 0) and now also records a durable `denied`
  row when the session existed. `auth/sessions/list` was already self-only.

  Consent (VTI-CTX-001, VTI-CTX-002). Grants carried no context, so any admin
  could write a standing Allow for any subject (a decision with no challenge)
  or withdraw anyone's grant. `ConsentGrant` now records the context of the
  request it answers. `consent/revoke` needs authority over that context, or
  super-admin for a grant with none. A decision with no challenge writes a
  context-less grant and so needs a super-admin. A challenged decision with no
  bound approver and an empty request context now needs a super-admin, where it
  skipped the context check. `consent/request`'s `contextHint` must be a context
  the caller may act in.

  Every refusal is audited with outcome `denied` (VTI-AUD-003) and logged with
  `security_alert = true`.

- **workspace**: No type derives Debug over secret material ([#1711](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1711))

A derived `Debug` prints every field, so on a type holding a private key, a
  seed or mnemonic, a bearer or refresh token or a password it puts the secret
  into anything that formats the value — a `tracing` field, an `unwrap` or
  `expect` on an enclosing type, a test failure, a panic message. About 55 types
  across twelve crates did exactly that. It surfaced when `vtc-client` began
  holding an operator's key in a `HolderKey`, whose derived `Debug` printed it.

  Each now has a hand-written `Debug` that reports the secret as `<redacted>` —
  presence kept visible for an `Option` — and prints every other field as
  before, the idiom the workspace already used where someone had thought of it.
  Among them: `HolderKey`, `Session`, `ClientIdentity`, `CredentialBundle`,
  `SecretEntry`, `AgentConfig`, `AgentConnect`, `AuthResult`, the key-import and
  seed-rotation requests (mnemonic), `SeedRecord`, `MnemonicExportResponse`,
  `SecretsConfig` (seed, Vault token, AppRole secret id), `VaultSecret`, its
  `CustomField` values and secure notes, `TotpSeed`, the VTC install flow's
  ephemeral signing keys, setup tokens and install JWT, the VTC backup's signing
  bundle and password, mobile-core's X25519 and Ed25519 private keys, auth tokens
  and push tokens (including the Web Push auth secret), and vta-mcp's
  `--agent-key`/`--holder-key`/`--agent-secrets`.

  `Zeroizing<T>` is not a redaction — its `Debug` prints the inner value — so the
  fields wrapped in it were redacted too.

  `vta-sdk/tests/secret_debug_census.rs` keeps the class closed. It parses every
  workspace crate with `syn` and fails on a `#[derive(Debug)]` struct or enum
  whose field has a secret-sounding name (`*_key`, `*token*`, `*secret*`,
  `seed*`, `password`, `mnemonic`, `jwt`, and `secret_id` despite its `_id`)
  and a raw type (`String`, bytes, `Zeroizing<_>`, optionally in an `Option` or
  behind a reference). A field whose type is another workspace type inherits that
  type's `Debug`, which is checked where it is defined. What the name rule
  catches and is not a secret — a claim-type vocabulary token, a webvh path
  called `mnemonic`, the name of an entry in a secret store — is on a
  shrink-only list with what the field holds, and the census also refuses a
  stale entry and a walk that has stopped finding types.

  Not an API change: every type still implements `Debug`; only what it prints
  differs, and no test asserted on the old output.



## [0.25.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-common-v0.24.0...vti-common-v0.25.0) — 2026-09-24


### Chore

- **deps**: Messaging-sdk 0.27.1 + trust-tasks-rs 0.22.3; answer a mutual TSP cancel the SDK could not (Keyring VTI-38) ([#1693](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1693))

Raises the floors on top of #1690's 0.22.1 / 0.27.0 move: trust-tasks-rs and
  -proof to 0.22.3 (the git-ns family, enabled by all-specs; the rest of the
  trust-tasks-* line resolves to 0.22.3 too), affinidi-messaging-sdk to 0.27.1.
  The graph holds exactly one copy of each.

  `affinidi-messaging-sdk` becomes a workspace dependency (floor 0.27.1) in
  place of five hand-kept per-crate literals.

  SDK 0.27.1 answers a peer's §7.3 cancellation of a mutual relationship
  itself, and `reply_expected` now means "the answer is still owed", which is
  true only when that send failed. The VTA's and VTC's `handle_tsp_control`
  retried with `cancel_relationship`, which refuses `SendCancel` out of `None`
  (the relationship is already forgotten). That is the exact VTI-38 failure.
  They now use `TspOps::answer_cancellation`.



## [0.24.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-common-v0.23.1...vti-common-v0.24.0) — 2026-09-23


### Added

- **vtc**: A console signing key is a credential of the operator's admin DID ([#1692](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1692))

Server side of #1684, against the design note merged in #1685
  (`vtc-console-signing.md`, Option A). The admin console cannot author a signed
  Trust Task document, which is what keeps every bearer route #1641 would retire
  mounted — 34 of the 49 are console-reachable, including all four #1681 kept.

  A console signing key is a credential of the operator's existing admin DID, the
  way a passkey is. Not an identity of its own and not an ACL row: giving a
  console key its own admin row is self-promotion by a longer path, and #1658's
  `Invariant::SelfPromotion` (VTI-OPS-050) refuses it. What the VTC stores is a
  delegation — "console key K may act as admin DID D" — which confers no role.
  Authority remains D's ACL row, read at execution time, so the property #1681
  established (`admin_signer` never consults `sessions_ks`) survives intact.

  - `console_keys` keyspace, `console_key:<consoleDid>` → the delegation, and
    EXCLUDED_FROM_BACKUP. That exclusion is a security decision rather than
    housekeeping: a restore into a rebuilt host, a staging clone or different
    hands must not hand a browser profile the ability to sign as an administrator
    again.
  - Enrolment behind `AdminAuth` plus `acl::elevation::verified`, which reads the
    session row — a stolen session alone cannot leave a signing key behind. The
    subject is the proven caller and the body cannot name it, so self-targeted is
    the only case this surface can express. That inverts `acl/grant`'s rule
    deliberately: a delegation confers nothing, so there is nothing to promote,
    and it is a credential of your own identity.
  - `admin_signer` gains one step. A signer with no ACL row of its own may be a
    delegated console key, in which case the delegating admin's row is resolved,
    at execution time, as before. A signer that has a row is answered by that row,
    including when it refuses — tighter than the note's sketch, so a stale
    delegation cannot route around a demotion.
  - List and revoke on the passkey management model. Revocation tombstones the row
    (a burned key cannot be re-enrolled), takes effect on the next document, and
    needs no second factor: an operator who suspects a browser should not have to
    find their authenticator before disowning it.
  - `AdminConsoleKeyEnrolled` / `AdminConsoleKeyRevoked` audit events.

  No published Trust Task covers this. `device/register/0.1` registers a device as
  a consumer in its own right, with a granted `Capability` set — the shape
  VTI-OPS-050 refuses here — and `auth/passkey/*` is WebAuthn end to end. So the
  three routes are mounted without a Trust-Task binding, the same exemption
  `relationships::{suspend,restore}` carries, and `routes/admin/console_keys.rs`
  records what the upstream `auth/signing-key/{enroll,list,revoke}` family should
  be. The bodies here are already those payloads.

- **persona**: Worlds on the wire, and a narrow read of one attribute ([#1690](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1690))

Takes trust-tasks-rs 0.22, which has been unreachable since 0.21.21:
  affinidi-messaging-sdk required ^0.21.20 and `MediatorAcl` crosses that
  SDK's API, so a graph holding both versions failed to compile rather than
  merely carrying a duplicate. affinidi/affinidi-tdk-rs#885 moved the
  messaging crates; this takes the line they are now on. One
  `trust-tasks-rs`, one `affinidi-messaging-sdk`, one `affinidi-tdk`.

  **Worlds.** `persona/facet/*` is `persona/world/*`, `facetId` is
  `worldId`, and `correlation/analyze` takes a 1.1 for its three renamed
  members. `face` and `facet` shared a stem while naming different things —
  a projection of the pool, and an arrangement of those projections — and
  every UI had already resolved it by saying "world" on screen, which left
  the collision live for anyone reading both.

  The retired spellings stay routable for a release and answer in their own
  words: `facetId` for `worldId`, `facets` for `worlds`, `crossesFacets`
  for `crossesWorlds`. A document already issued against one still
  validates, and refusing it would break a caller for a rename that costs
  it nothing. The whole alias is marked for deletion in one commit.

  **`persona/attribute/get`.** Reading one value meant
  `persona/attribute/list` with a type prefix, filtered by the caller — so
  revealing one email address decrypted every email address the holder has,
  and the audit row recorded a listing of the pool rather than a decision
  about one fact. `PersonaStore::get_attribute` applies exactly what a
  listing applies: visibility, retention, credential re-derivation.
  `versionPurged` is distinct from `notFound` because the attribute is
  still there, and `retainedVersions` lets a holder see what purging would
  take away rather than deciding blind.

  Two latent defects, both found by the new tests:

  - `correlation/analyze/1.0` was already answering with 1.1's member
    names. Nothing noticed because 1.1 did not exist.
  - A world with no faces and no attributes serialised without `faceIds`
    and `attributeIds`, which its own response schema requires, so listing
    an empty one returned a 500. `skip_serializing_if` on a required
    member; no test had made an empty one.

  The `pf:` storage prefix is unchanged — it is an opaque key prefix, not
  the noun, and renaming it would orphan every world already stored.



## [0.23.1](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-common-v0.23.0...vti-common-v0.23.1) — 2026-09-23


### Fixed

- **auth**: Consume the challenge before minting, atomically ([#1664](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1664))

`handle_authenticate` read the challenge row, checked it was in
  `ChallengeSent`, then looked up the ACL and minted tokens, and only after
  all that deleted the row. Those are awaits, and the row stayed alive across
  them, so two interleaved presentations of the same signed envelope both
  passed the state check and both minted. Sequentially it was correct; under
  concurrency the single-use challenge was not single-use ([#1656](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1656)).

  Sessions coalesce per DID (last write wins, access token pinned by
  `token_id`), so an attacker who captured a correctly-addressed envelope and
  replayed it inside the freshness window while the holder signed in could win
  the race, hold the session as the holder, and supersede the holder's own
  access token.



## [0.23.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-common-v0.22.0...vti-common-v0.23.0) — 2026-09-22


### Added

- **backup**: A backup is the whole agent, and restores between plain, hardened and TEE VTAs ([#1655](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1655))

A backup now carries every row of every keyspace in vta_keyspaces::BACKED_UP
  (format vta-backup-v2) and restores into a plain, hardened or Nitro-enclave
  VTA from any of them. VTI-VTA-001, VTI-VTA-050, VTI-VTA-051, VTI-KEY-033.

- **vtc**: Deliver an invitation to the DID it admits — pushed as an offer, or as a QR ([#1648](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1648))

Keyring VTI-21 and VTI-32. `vtc/invitations/issue` returned the signed
  invitation to the inviter once and nothing carried it further, and the
  credential was too large for a QR code (the console said so).

  `vtc/invitations/deliver/0.1` (`POST /v1/invitations/deliver`, inviter
  roles) records a single-use OID4VCI offer for the invitation, bound to the
  invited DID and withdrawing any earlier one, then either sends it to that
  DID as a `credential-exchange/offer` over DIDComm (`message`; `noRoute`,
  422, when the DID advertises no DIDComm service) or returns it (`offer`).
  The offer names the credential rather than containing it, so it fits a QR
  code as an `openid-credential-offer://` link.

  The invitation is released only through `credential-exchange/request` with
  a key-binding proof by the invited DID's key, so a photographed code admits
  no one else. Two things that required:

  - Key-binding proofs now verify for a holder of any DID method: the `kid`
    resolves through the community's DID resolver (`DidVmResolver`), where
    the verifier refused anything but a `did:key`. `redeem` and
    `issue_on_request` take the resolver.
  - `POST /v1/credential-exchange/request` redeems over HTTPS, for an invitee
    with no messaging service. Unauthenticated, on the rate-limited unauth
    chain: the proof is the authority. It answers with the
    `credential-exchange/issue` payload a messaging binding sends on-thread.

  The signed invitation is kept on its registry row so it can be delivered
  later (never listed). Invitations issued before this cannot be delivered
  and say to reissue. The admin console gets Send and QR-offer buttons on
  each live invitation. AuditEvent::InvitationDelivered.



### Fixed

- **auth**: A signed REST sign-in must be addressed to the service that receives it ([#1646](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1646))


## [0.22.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-common-v0.21.0...vti-common-v0.22.0) — 2026-09-22


### Added

- **vtc**: A self-hosted community installs its own DID log over did-management/did/register ([#1632](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1632))

Keyring VTI-35. A community whose DID is `did:webvh:<scid>:<host>` serves
  its own did.jsonl, but the VTA holds the keys that extend it and cannot
  reach the community's copy, and the VTC keeps no VTA credential after
  setup. So an entry the VTA appends later — a TSP transport added to the
  community's services, a key rotated — had no way to the community except
  an operator copying the file by hand. (A community on a DID host needs
  none of this: the VTA publishes each entry to the host itself.)

  The VTC now answers `did-management/did/register/0.1` — the task a DID
  owner sends a DID host, where a second register with a longer log is an
  update — for its own DID at the root slot `.well-known`, over
  `POST /v1/admin/did/register` (super-admin). Before serving, it verifies
  the whole log (every entry's proof under the update keys in force, SCID,
  hash chain), that it is the community's own DID, and that every served
  entry survives unchanged as a prefix; then swaps the file atomically,
  with no restart. So an administrator's authority covers delivery only: a
  log the key holder did not sign, or one that moves the served log
  backwards, is refused whoever delivers it. The prefix rule is stricter
  than `register` alone and carries a consumer-minted code (SPEC §8.5).

  - `cnm did-log install --file did.jsonl`, fed by `pnm did-mgmt dids
    get-log`. It authenticates to the community directly, with the
    community's DID as the audience (`VtcClient::connect`), not through the
    profile's VTA session, whose audience is the VTA's DID — a VTC refuses
    that. The community DID comes from the log; the URL from its host.
  - `VtcClient::install_did_log`; `MockVtc::start_with` for a test VTC with
    a self-hosted DID; a live test authenticates and installs over HTTP.
  - AuditEvent::CommunityDidLogInstalled.
  - The redeploy hint for a DID the VTA manages but does not serve names
    the new command.

- **vtc**: Serve a member's credential bodies and show them in the admin console ([#1631](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1631))

`GET /v1/members/{did}/credentials`, bound to the now-published
  `vtc/members/credentials/0.1` (trustoverip/dtgwg-trust-tasks-tf#336,
  already in the locked trust-tasks-rs 0.21.11). AdminAuth. It reads the
  four fields #1213 keeps on the member row (`current_vmc`,
  `current_role_vec`, `member_vmc`, `member_vmc_bound`): no new storage and
  no new verification. `memberVmcBound` is the answer recorded at receipt,
  never recomputed.

  The response is the generated `specs::vtc::members::credentials::v0_1`
  type, documented through a new `vta_sdk::openapi::MemberCredentials01Response`
  wrapper. Bodies are carried as stored. `memberVmcReceivedAt` is only sent
  alongside `memberVmc`, because the spec says a maintainer MUST NOT send one
  without the other, and a row from before #1213 has the receipt time but no
  body.

  An unknown member gets a 404 whose body carries the spec's declared code,
  `vtc/members/credentials:notFound`, next to the usual `error` member.
  "Unknown" means what it means for `members/show`: no member row, or no ACL
  row, so a tombstoned member counts. A member who holds nothing gets a 200
  with every document absent and `memberVmcBound: false`, as the spec
  requires.

  The spec says a maintainer SHOULD record that the read happened, so every
  successful read writes a new `MemberCredentialsRead` audit event. The event
  names which documents were disclosed and never includes their contents.
  The audit write happens before the response. `AuditEvent` is
  `#[non_exhaustive]`, so the new variant does not break any consumer.

  A conformance witness checks the task. It builds its response with the
  handler's own `credentials_response`, over a row filled by the real
  `record_issued_credentials` / `record_member_vmc`, so it tests what the
  service sends rather than a hand-typed fixture.

- **acl**: `key-export` is its own capability, and minting a DID needs `KeyMint`, not admin ([#1619](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1619))

Keyring finding VTI-23: `webvh/dids/create` and `keys/export-secret` both checked
  for the admin role, so a least-privilege manager was impossible for the persona
  lifecycle — an `initiator` holds `KeyMint` and `Sign` and was refused both.

  ## Minting a DID: `KeyMint`

  Minting a DID mints its keys, which `initiator` is already trusted to do. The
  gate in `create_did_webvh` is now `KeyMint`, so a manager on `initiator` can mint
  personas. The context check is unchanged and still bounds *where*.

  It reads the caller's **entry**, so a narrowing that removes `KeyMint` stops the
  next call — the rule every capability gate has followed since #1279. That needs
  the ACL keyspace in `CreateDidWebvhDeps`, as `acl_ks: Option<&KeyspaceHandle>`:
  `Some` from both live constructors and from provisioning; `None` only for the
  offline CLI and first-boot setup, whose claims are synthesized under a DID that is
  deliberately in no ACL — so reading the store would find no entry and fall back to
  the role anyway. The gate is extracted as `ensure_may_mint` so it can be tested as
  the code that runs, rather than by a test that mirrors it.

  ## Exporting a key: a new `KeyExport` capability

  VTI-VTA-003 is normative here:

  > Where a VTA supports exporting derived key material, that export MUST be gated
  > by a capability distinct from the capability to use the key, and MUST be
  > audited.

  The admin-role check was not that. It coupled export to being an admin, so export
  could neither be granted below admin nor narrowed away from one. `KeyExport` is
  now the gate; scope and auditing inside `get_key_secret` are unchanged.

  **Only `admin` derives it.** That is deliberate, and it is the answer to the half
  of VTI-23 this does not grant. An `initiator` holds `Sign`, which is the signing
  oracle — its whole guarantee is that the key never leaves — and VTI-VTA-002 makes
  performing the operation the norm and exporting it the exception, because an
  exported key stays with whoever holds it after their authority is withdrawn. A
  manager that needs to act as a persona signs through the oracle.

  `KeyExport` is role-derived, not additive, so naming it on an `initiator` grants
  nothing. Making it both admin-derived *and* grantable would need a change to
  `effective_capabilities`' invariant (a capability is either derived or additive,
  never both), which was considered and not taken.

  ## One behaviour change to know about

  An admin who was **narrowed** under #1279 could export until now, because the
  role check ignored narrowing. Their stored set could not name `key-export` — it
  did not exist — so after this they cannot. That is the narrowing working as
  intended, closing the one power it could not previously restrict. Un-narrowed
  admins keep everything.

  `KeyExport` is not in the published `device/_shared/0.2` enum, and
  `PUBLISHED_CAPABILITIES` lists that enum positively, so it lands in `ext` as an
  ecosystem-local capability rather than leaking into a closed schema.

  ## Follow-up outside this repository

  The TS console keeps a hand-maintained copy of the role table
  (`acl-capabilities.json`, synced from this repo's `origin/main`). It must be
  re-synced after this merges, or it will under-report an admin's authority.

  ## Tests

  - Role table: admin derives `KeyExport`; no other role does; it narrows away
    from an admin; naming it on an initiator grants nothing.
  - `keys/export-secret`: an initiator is refused at the gate; an admin passes it;
    a narrowed admin is refused. The last is the one the old role floor would have
    let through — verified by restoring it.
  - `ensure_may_mint`: an initiator may mint; a reader may not; a narrowing
    without `KeyMint` stops the next mint — verified to fail when the entry is
    ignored; offline callers fall back to the role.



## [0.21.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-common-v0.20.2...vti-common-v0.21.0) — 2026-09-21


### Added

- **vtc**: A community can ask an applicant to tell it about themselves ([#1614](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1614))

Implements trustoverip/dtgwg-trust-tasks-tf#543 (trust-tasks-rs 0.21.9),
  design note docs/05-design-notes/persona-context-first.md §5.2. A join
  manifest could ask only for credentials, so a community wanting a
  display name had nothing to put on the "what's required" screen, and
  nothing connected the join ceremony to an applicant's persona.

  - Requested attributes are one community-level row beside the branding
    (`community/requested-attributes`, backed up with it), managed with
    admin GET/PUT /v1/community/requested-attributes (audited:
    CommunityRequestedAttributesUpdated, types added/removed only), and
    published as `requestedAttributes` on join-requests/manifest/0.2.
  - join-requests/submit/0.2 accepts `attributes`. Before anything is
    stored -- before the open-request dedup -- the answers are checked:
    a required type unanswered is attributesMissing, a type the manifest
    does not request is attributesUnrequested (refused, not trimmed), both
    with details.types. Accepted answers are stored on the request and
    returned by show/list as `attributes`. They are self-asserted and are
    never fed to the join policy.
  - Only the Trust Task form carries them: the legacy REST submit's holder
    signature covers a fixed member set that does not include them, so an
    answer there would be unsigned. A community that requires one refuses
    that route with attributesMissing.
  - VtcClient::requested_attributes / set_requested_attributes, and
    `cnm vetting ask show|set --require/--optional/--purpose/--nothing`.
  - vta_sdk::openapi gains JoinManifest02RequestedAttribute, rendered from
    the specification's own schema by JSON pointer (`Name@<pointer>`),
    because the spec declares the item inline; admin-ui openapi.json and
    wire.ts regenerated.



## [0.20.2](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-common-v0.20.1...vti-common-v0.20.2) — 2026-09-21


## [0.20.1](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-common-v0.20.0...vti-common-v0.20.1) — 2026-09-21


### Added

- **vtc**: Implement vtc/join-requests/supplement/0.1 — answer a deferral in place ([#1593](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1593))

Closes the second half of Keyring's KR-03, the one `join-requests/withdraw`
  ([#1591](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1591)) left open. A community that cannot decide a request on what it was
  given defers it and says what more it needs — and the applicant had nowhere to
  put the answer. The request stays open, the dedup guard refuses a second
  application, and the only exits were withdrawing (losing your place) or waiting
  for a retention sweep neither party controls. A deferral was a dead end dressed
  as a question.

  Spec'd upstream first (dtgwg-trust-tasks-tf #526, corrected by #531, shipped in
  trust-tasks-rs 0.21.6) and implemented here against the generated types.

  ## Submit and supplement now share one definition of every verdict effect

  `apply_verdict_to_request` is extracted out of `realize_join_verdict`, which
  could not be reused as-is because it opens with `JoinRequest::new` — it decides
  a request it is creating, and a supplement decides one that already exists. The
  extraction is the point rather than a tidy-up: an admission granted by a
  supplement must mean exactly what one granted by a submission means, and two
  copies of the effect table would eventually disagree.

  The response needs no such care because it is already shared —
  `outcome_to_verdict` and `verdict_response` are submit's, and a supplement's
  `{requestId, verdict}` *is* a submission's. A client reads both with one code
  path, which is why the spec chose that shape.

  ## Vetting travels in the presentation, and the first draft of the spec said otherwise

  `vetting_facts` reads attestations out of the VP's `verifiableCredential`
  array (`vetting_credentials(vp)`). The per-request `StoredVettingFacts` row
  looks like it contradicts that — it is keyed by request id and written on every
  submit — but nothing reads it into a decision: it serves the admin view, the
  vetter sweep, and tracing a withdrawn statement to the admissions it counted
  toward.

  So a supplement that omits the attestations is one with no vetting, and this
  implementation does not quietly carry the superseded ones forward. Doing so
  would decide the request on evidence the applicant is no longer presenting —
  the same defect as merging the two presentations, by a different route. #526
  asserted the opposite; I found it writing this code, and #531 corrected the
  specification.

  ## Other decisions

  **Only a deferred request.** A `Pending` one waits on the community, not the
  applicant; accepting evidence into it would replace what a maintainer is
  mid-review on, leaving the document they were reading no longer the one they
  were asked to decide. `notAwaitingEvidence`, with an annex naming the request.

  **An invitation presented now counts.** The policy re-runs over the whole new
  presentation, and a VIC in it is part of that presentation. Consumption routes
  through the extracted applier, so the burn happens once and on the same path a
  submission's does.

  **`JoinRequestSupplemented`, not `JoinRequestSubmitted`.** Nothing was
  submitted. Conflating them would make a community's audit trail report more
  applications than it received, and lose that an admission was granted on the
  second set of evidence. `AuditEvent` is `#[non_exhaustive]`, so additive.

  ## Tests

  Five, including a dispatcher-level one pinning all three spec-declared codes.
  The deferred-only guard was verified to fail its test when removed. The
  ownership test asserts the *rendered messages* of "not yours" and "does not
  exist" are equal, not merely that both refuse — equality is what makes the task
  useless as an id oracle.



## [0.20.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-common-v0.19.3...vti-common-v0.20.0) — 2026-09-20


### Added

- **vtc**: Add vtc/join-requests/withdraw/0.1 — the applicant closes their own request ([#1591](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1591))

Keyring finding KR-03. An applicant could open a join request and then had no
  way to close it. A `deferred` request — the community answered `requestMore` —
  was the sharp case: it stays open forever, the dedup guard in `submit_inner`
  keeps matching the row so no resubmission is possible, and the only exit was
  to ask a community admin to reject it, which records the wrong outcome for
  what is actually the applicant changing their mind. Nothing but the retention
  sweeper ever closed it, on a schedule neither party controls.

  The task was spec'd upstream first (dtgwg-trust-tasks-tf #518, shipped in
  trust-tasks-rs 0.21.5) and is implemented here against the generated types.
  Payload, response and the `withdrawn` status all come from
  `trust_tasks_rs::specs::vtc::join_requests::withdraw` — never a local copy.

  ## Authorization is ownership, not membership

  An applicant holds neither a role nor a capability; that is what they are
  applying for. So the entitlement is that the proven caller is the applicant
  recorded on the request. `resolve_holder` supplies the proof — authcrypt
  sender on DIDComm, document proof signer on REST — exactly as `self-remove`
  does.

  ## The two refusals are shaped differently on purpose

    * A request that does not exist and one belonging to somebody else both
      answer `notFound`. Separating them would let a caller probe whether a
      given request id exists on this community — the same enumeration-
      resistance reasoning the vault read paths use.
    * An already-decided request answers `alreadyDecided`, because the applicant
      is entitled to the outcome of their own request and no retry changes it.

  Both go out as the extended codes the spec declares rather than through the
  generic `AppError` → reject mapping, which flattens `NotFound` and `Gone` into
  a bare `taskFailed` carrying only English. Telling "nothing to withdraw" apart
  from "already decided" without parsing prose is the whole reason the spec
  declares two codes, so a dispatcher-level test pins them.

  ## requestId is optional

  For the same reason it is optional on the status poll: an applicant whose
  submit response was lost never received one, and the id-less form is all they
  have. A supplied id is preferred over inferring from the caller, as the spec
  requires.

  ## Where the applicant's reason goes

  To the audit log, not onto the row. `JoinRequest` is a canonically-typed wire
  shape with no member for it, and `decision` means *refusal* — writing it there
  would make a withdrawn request read as rejected.
  `AuditEvent::JoinRequestWithdrawn` carries the reason alongside the previous
  status, and is the one join event whose actor and subject are the same party.
  `AuditEvent` is `#[non_exhaustive]`, so the new variant is additive.

  ## Also, partially, KR-04

  The same defect seen from the other side: the duplicate-submit `Conflict` said
  "withdraw or await its decision" while naming neither the status nor any
  withdraw mechanism. It now names both — `pending` is waiting on the community
  and will move on its own, `deferred` is waiting on the applicant and is the
  case this task exists for.

  KR-04's remaining half is not in this PR and needs an upstream change first:
  making that refusal a *typed* answer requires a `requestAlreadyOpen` code on
  `vtc/join-requests/submit`, which declares no such code today. Likewise the
  second half of KR-03 — letting a deferred applicant supplement the existing
  request rather than open a second one — is a task that does not exist yet.
  Both are follow-ups.

  ## Dependency

  The `trust-tasks-rs` workspace requirement moves 0.21.4 -> 0.21.5 because
  `vta-sdk` re-exports the generated module in its public API, so a consumer
  resolving 0.21.4 would not build. The three unrelated lines in Cargo.lock
  (`syn`, two `base64`) are pre-existing drift between the committed lock and
  what cargo resolves — any `cargo update` of any package rewrites them.

  A conformance witness is added in `trust_tasks/conformance.rs`, projected
  through the same generated builder the handler returns through rather than
  transcribed.

- **vtc**: Keep an active admin signed in, and make the idle timeout settable ([#1586](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1586))

An admin was thrown out of the console on a hard cliff, with no warning and
  no way to change it. The cliff was also shorter than the config suggested
  and differed by sign-in door: passkey login mints at `acr=aal2`, and the
  aal2 access TTL is a third of the base, so the cookie died after 300s —
  of wall-clock, not idle time. Working continuously made no difference,
  because the request path never wrote to the session row. The first sign of
  expiry was a request failing.

  Tokens stay short and rotating. The idle timeout becomes a separate
  server-side policy measured on `Session.last_seen`:

  - `last_seen` advances on cookie-borne requests — the console doing
    something — and not on bearer ones, which are the CLIs and service
    integrations, have no idle timeout, and would otherwise pay a store
    write per call.
  - `handle_refresh` refuses once `now - last_seen` exceeds the configured
    timeout, with its own error rather than the generic "authentication
    failed" the other auth failures share. Reaching that point proves
    possession of a valid refresh token, so there is nobody left to withhold
    the reason from, and "you were away" sends an operator somewhere
    different from "your session hit its ceiling".
  - The console renews before expiry, single-flight, and re-probes `whoami`
    before declaring a session dead — rotation is atomic, so two tabs
    renewing together means one is refused on a perfectly live session.

  Refresh no longer resets `last_seen`. It used to set it to `now`, which
  would have made the timeout unreachable: the renewal timer would push the
  deadline out on every cycle. Rotating a token is the client's timer, not
  the operator. Safe for the sweeper, which judges refresh-bearing sessions
  by `refresh_expires_at` and never reads `last_seen`.

  `/v1/auth/refresh` is no longer CSRF-exempt. That exemption was sound only
  while the sole credential was a token in the request body, which an
  attacker cannot read. A refresh cookie the browser attaches automatically
  removes the property, and a forged cross-site refresh would rotate the
  victim's token away — a logout DoS. Body-token callers carry no session
  cookie and still pass unenforced, so SDK and CLI clients are unaffected.

  `auth.admin_idle_timeout` joins the runtime config registry, bounded
  60s-86400s by a new `U64Range` kind so a scripted `config/patch` is held to
  the same limits as the console. Save is PATCH + reload, because PATCH alone
  persists the override without touching the running config.



### Fixed

- **tsp**: Take the SDK's re-establish fix and drop the local copy ([#1588](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1588))

#1582 worked around a race inside `TspOps::send_reestablishing`: its readiness
  read and its `SendInvite` are two separate awaits on the relationship store, and
  the peer can move our half between them — its own invite arrives, `None` +
  `ReceiveInvite` leaves us `InviteReceived`, and `SendInvite` is legal only from
  `None`. The refused invite took the payload down with it, and the D6 recovery
  reported a peer that "did not answer" a request it had never been sent.

  The workaround was a local copy of the SDK's three steps with the tolerance
  added. `affinidi-messaging-sdk` 0.26.12 (affinidi-tdk-rs#838) does that re-read
  itself, so `TspTransport::send_reestablishing` delegates again and the local
  `invite_refusal_is_benign` and its tests are gone — one owner for the decision
  rather than two that can drift.

  Two things this bump settles beyond the deletion:

  - **`vtc-service` is fixed by it.** Its registry client
    (`registry::messaging::send_tsp`) calls the SDK's form directly and never had
    the workaround. #1582 left it alone because the syncer's backoff — the one
    retry owner on that path — re-sent through the transient failure, so it
    self-healed on the next attempt. Now it does not fail in the first place.
  - **The requirement names the patch: `0.26.12`, not `0.26`.** Every
    `affinidi-messaging-sdk` requirement in the workspace moves, because on `^0.26`
    a lockfile resolving 0.26.11 would put the race back with nothing local left to
    catch it. A floor that is load-bearing rather than tidy.

  What stays from #1582 is the part the SDK cannot fix: `recover_send_tsp` telling
  `Timeout`, `Cancelled` and `SendFailed(reason)` apart instead of reporting all
  three as a silent peer, and the `AnsweringPeer` harness recording what it
  received and sent. That is what made the upstream defect readable in one CI run,
  and it is VTA-side either way.

  Design note `tsp-relationship-recovery.md` D6a updated to say where the fix now
  lives.

- **rate-limit**: Key the per-IP limiter on trusted-proxy CIDRs, not a global XFF flag ([#1562](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1562))

* fix(rate-limit)!: key the per-IP limiter on trusted-proxy CIDRs, not a global XFF flag

  Replaces the boolean `trust_xff` flag with `trust_xff_cidrs: Vec<CIDR>` (VTA + VTC). The per-IP rate limiter now reads `X-Forwarded-For` only when the request's peer address falls inside an explicit trusted-proxy CIDR allowlist, keying on the rightmost entry.

  Fixes two issues with the old flag: an untrusted peer could forge a leading XFF entry to evade its own limit, and every request behind a trusted proxy shared one bucket — one client's burst could 429 unrelated clients.

  Breaking config change: replace `trust_xff = true/false` with `trust_xff_cidrs = ["<cidr>", ...]`.



## [0.19.3](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-common-v0.19.2...vti-common-v0.19.3) — 2026-09-18


### Added

- **vtc**: Let a community choose whether it answers the join manifest publicly ([#1563](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1563))

The join manifest is a public read by design — an applicant has to know
  what is asked of them before they disclose anything, which is the whole of
  informed non-application — and `POST /v1/trust-tasks` answers it with no
  session at all. That is what lets someone read a community's admission
  criteria on their very first join, when they have no messaging channel to
  ask over.

  It was also unconditional. A closed or invite-only community had no way to
  say "you can learn what we require once you are talking to us", short of
  not running the endpoint.

  `GET`/`PUT /v1/community/join-discovery` is that choice, with a "Joining"
  card on the console's Community profile page. Off refuses only a caller the
  community cannot name: an identified one — a signed Trust Task document
  over REST, or an authcrypt DIDComm sender — is answered exactly as before,
  because refusing those would break the join ceremony rather than close
  anything. The refusal says how to ask rather than only that it failed.

  The default is `true`. Every community answered before this existed, and a
  default of `false` would stop answering applicants who were being answered
  yesterday, for operators who never chose it — a setting that changes
  behaviour nobody opted into is a regression with a checkbox.

  Its own keyspace row, beside `branding`, rather than a member of the
  community profile: `vtc/community/profile/show/0.1` is a published schema
  with `additionalProperties: false` and `ProfileWithStatus` flattens the
  profile into its response, so a new profile member is a new member of a
  canonical answer this service is not the place to add. The conformance
  witness caught exactly that on the first attempt, which is what it is for.
  The profile is a published description of the community; this is an
  operational choice about how one endpoint behaves.

  Turning it off is its own audit event. "When did we stop publishing our
  admission criteria, and who decided?" is a question an operator is later
  asked, and a line in a profile field-diff is a poor answer.



## [0.19.2](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-common-v0.19.1...vti-common-v0.19.2) — 2026-09-18


## [0.19.1](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-common-v0.19.0...vti-common-v0.19.1) — 2026-09-17


### Added

- **tsp**: The VTC persists + answers TSP relationships and relates before sending to the registry (Rev 3 §7.2.2) ([#1543](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1543))

The VTC is a server like the VTA, but its TSP was half-wired: it drove the
  delivery layer yet built the ATM with a bare `ATMConfig::builder().build()`
  (in-memory relationship store, wiped on restart), its `handle_tsp` had no
  relationship-control answering arm, and `MessagingRegistryClient` sent Trust
  Tasks to the trust-registry with a plain `send_routed` and no relationship. So
  the registry §7.2.2-dropped every frame ("no relationship with ...trust-registry"),
  and a VTC restart would have dropped the registry's replies too.

  Bring the VTC to VTA parity:

    - Lift the durable relationship-store adapter (`KeyspaceRelationshipKv` +
      `maintenance_loop`) out of `vta-service` into a shared, feature-gated
      `vti_common::relationship_store`, alongside `VtiOutboxStore`. `vta-service`
      now re-exports it and keeps only its VTA-specific §7.2.2 drop telemetry.
    - Inject the store into the VTC ATM (`with_relationship_store`) over a new
      `tsp_relationships` keyspace — distinct from the VTC's social-graph
      `relationships`, and excluded from backup (transport state). Spawn the
      boot-enumerate + idle-eviction maintenance loop once at startup.
    - `handle_tsp` now answers `InboundKind::RelationshipControl` via a
      `decide_control` policy (accept an invite, record an accept, answer a
      cancel) — the ACL gate stays at the Trust Task layer.
    - `MessagingRegistryClient` sends over `send_reestablishing`: it forms the
      relationship (sends an invite) when readiness demands, then sends the
      payload (§3.6). A `TODO(D4)` marks the reply-timeout reset that belongs at
      the correlated-reply wait site.

  This is the sender-and-responder half of the same recovery work already landed
  in `vta-service` and the trust-registry. The `VtaClient`/`SessionStore` Auto
  path is a different client and was handled separately ([#1540](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1540)).



## [0.19.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-common-v0.18.9...vti-common-v0.19.0) — 2026-09-17


### Added

- **tsp**: Surface §7.2.2 relationship-gate drops as telemetry (D8) ([#1536](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1536))

The event that was invisible when the recovery workstream's incident happened — an inbound TSP application message dropped because the VTA holds no relationship with the sender — is now a queryable telemetry event, so a spike is an operational alarm rather than a scatter of error logs (design note tsp-relationship-recovery.md, D8).

  - vti-common: new TelemetryKind::TspRelationshipDropped (BREAKING — the enum is not non_exhaustive; carries a count field). No internal exhaustive match breaks — all sites construct.

  - vta-service build_messaging injects an Arc<AtomicU64> into the ATM via with_relationship_drop_counter (affinidi-messaging-sdk 0.26.7); the SDK gate increments it on every drop.

  - A drop_telemetry_loop spawned ONCE at server startup samples the counter each minute and records a TspRelationshipDropped event with the delta. Spawned beside the eviction sweep, not in build_messaging (which re-runs per reconnect).

  tsp-gated; non-tsp build unaffected. release-plz owns the version bump (the semver-report red is expected for the breaking variant).



## [0.18.9](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-common-v0.18.8...vti-common-v0.18.9) — 2026-09-16


## [0.18.8](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-common-v0.18.7...vti-common-v0.18.8) — 2026-09-16


## [0.18.7](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-common-v0.18.6...vti-common-v0.18.7) — 2026-09-16


## [0.18.6](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-common-v0.18.5...vti-common-v0.18.6) — 2026-09-15


## [0.18.5](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-common-v0.18.4...vti-common-v0.18.5) — 2026-09-12


## [0.18.4](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-common-v0.18.3...vti-common-v0.18.4) — 2026-09-10


### Added

- **audit**: Write the VTA's audit log as a hash chain ([#1420](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1420))

* feat(audit): write the VTA's audit log as a hash chain

  The sink writes envelopes through the shared writer rather than flat
  rows: each entry commits to its predecessor, and the actor and any
  DID-shaped target are committed under a keyed hash with the plaintext
  beside them, so an erasure can null the plaintext while the row stays
  correlatable and the chain still verifies.

  The chain opens with the creation of the key that chains it. The key is
  established on the first write — there is nothing to audit before a
  node can act, and a node cannot act before it has somewhere to record
  what it did — so the first entry is the record of that key coming into
  existence, committing to its id. A verifier reading from the start
  learns which key the entries after it are hashed under, from an entry
  hashed under that same key.

  The keyspace and the storage-key format are unchanged except for one
  addition. The seconds stay the leading field, because the retention
  sweep compares keys against a cutoff in that shape and a different
  leading field would make every chained row sort past every cutoff and
  never expire. The nanoseconds are new and are not optional: whole
  seconds put two entries written in the same second in uuid order, so a
  verifier reading in key order sees them out of chain order and reports
  a break in a chain that is intact — a false alarm indistinguishable
  from the thing it exists to detect. The tests found this rather than
  review.

  The read path now accepts both shapes. A reader that knows only one
  does not fail loudly; it skips what it cannot parse, so a reader that
  knew only the older shape would have reported a log that stops at the
  moment chaining began.

- **audit**: Give the VTA an audit key of its own ([#1419](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1419))

Two pieces, both inert until the sink uses them.

  ensure_initial_random establishes a key from the OS random source
  rather than from a seed. The key's job is to be a stable handle for
  actor and target identifiers — exist before the first write, stay
  retrievable while any envelope references it, be rotatable — and
  nothing about that requires it to be derivable. What derivation adds is
  a second copy of the key wherever the seed is, so a node whose recovery
  story is a mnemonic has an audit key that anyone holding the mnemonic
  can recompute. Since the commitment exists so an erasure can null the
  plaintext while the row stays correlatable, that makes the erasure
  reversible by brute force over the identifiers the node has seen.

  The cost is that the key is not regenerable, so the keyspace holding it
  joins the backed-up set. Without it a restored log still verifies as a
  chain and still says what happened, but no entry can be checked against
  a candidate identifier again.

  The keyspace is separate from the audit log because the two have
  opposite lifetimes: entries are erased when their retention expires,
  and a key must outlive every entry that references it. Neither cascades
  on a DID deletion, for the reason the audit log already does not.

- **audit**: Let the writer serve a keyspace that predates chaining ([#1413](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1413))

Two changes to AuditWriter, both needed before a VTA can use it and
  neither altering what a VTC does.

  The storage key becomes configurable. A keyspace that already holds
  rows has an ordering, and a writer that ignores it produces a log whose
  newest entry is not its last key — which breaks chain-head recovery and
  every reader that pages in key order. A VTA's audit keyspace is exactly
  that: it holds log:<zero-padded-epoch>:<uuid> rows, and those sort
  after an RFC 3339 timestamp. The default is unchanged, so a fresh
  keyspace needs nothing.

  Chain-head recovery walks back to the newest row that is an envelope
  rather than assuming the last row is one. Without it the first chained
  write against a VTA's keyspace fails, because the row beside it was
  written before the scheme existed. Deserialization is the test rather
  than the key, since the key format now belongs to the caller.

  Tests cover both: a pre-chain row does not stop the first chained write
  and the entry anchors at genesis, and a custom key still recovers the
  head across a restart so the second entry chains to the first.



### Changed

- **audit**: One construction point for the audit sink, and the prerequisites for chaining it ([#1412](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1412))

* refactor(audit): build the keyspace audit sink in one place

  The workspace built the same sink over the same keyspace in
  thirty-one places, including three times inside one function
  (run_create_did_webvh, which already had one in scope two hundred
  lines above the other two). Each was somewhere a later change to what
  a VTA's audit writes would have to be found and repeated.

  There is now one constructor, vta_audit::shared_keyspace_sink, and
  every caller goes through it. A server still takes its sink from
  AppState — that path was already correct, and its comment already said
  why. The factory is for the callers with no AppState to take one from:
  offline CLI commands, setup, sweepers and tests.

  No behaviour change. The next change to this subsystem — writing
  chained envelopes rather than flat rows — is now one edit instead of a
  search.



## [0.18.2](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-common-v0.18.1...vti-common-v0.18.2) — 2026-09-09


### Changed

- **sdk**: Move the Trust-Task proof verifier down from vti-common ([#1340](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1340))

Pure move plus re-exports; no behaviour changes. It exists so the next
  change can be small: `VtaClient` needs to verify the responses it receives,
  and the verifier it needs already exists one layer up where a client cannot
  reach it.

  `vti-common` was the right home while services verifying their *inbound*
  requests were the only consumer. A client verifying its *replies* is the
  same operation over the same document shape, and `vta-sdk` is the layer both
  can see.

  **The part worth not duplicating is the verification-method resolver.**
  Resolving one looks trivial and is not: a DID document may name its methods
  absolutely (`did:webvh:…:glenn#key-0`) or relatively (`#key-0`), while a
  proof always names them absolutely, so a resolver accepting only the
  spelling it expects refuses perfectly good documents from conforming peers.
  A second copy would drift, and drift in a verifier means refusing honest
  documents or accepting dishonest ones. Writing that copy is what this move
  avoids.

  Behind a new `proof-verify` feature rather than `client`, because
  `vti-common` takes `vta-sdk` with `default-features = false` and must not
  acquire reqwest to keep verifying. It adds no dependency to `vti-common` —
  that crate already depended on `affinidi-data-integrity` and the DID
  resolver directly. `client` enables it: a client that cannot verify its
  replies is the gap being closed.

  The resolver rides in the feature deliberately. Verification is only as good
  as the party it resolves — a `did:key` signer needs no I/O, and a
  `did:webvh` one, which is what a real agent is, cannot be verified without
  resolving its document.

  Call sites that used the module path (`vti_common::auth::di_proof::…`) now
  use the flat re-export, so there is one canonical path rather than an alias
  to go stale. Two doc comments naming the old location updated with them.

  `cargo clippy --workspace --all-targets` clean; `vta-service --lib` 1063
  passed; `vta-sdk` + `vti-common` suites pass, including the four resolver
  tests that moved with the code.



## [0.18.1](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-common-v0.18.0...vti-common-v0.18.1) — 2026-09-08


## [0.18.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-common-v0.17.0...vti-common-v0.18.0) — 2026-09-07


### Added

- **acl**: Enforce an entry's capabilities, and give an operator a way to set them ([#1279](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1279))


### Fixed

- **acl**: Let the role an agent runs as reach the room oracle ([#1275](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1275))

The room presentation oracle exists for one consumer: an agent holding
  strictly less than its human, asking its principal's VTA to mint a scoped
  presentation and to open what it cannot decrypt. `application` is the role
  such an agent runs as - `vta-agent-memory` grants exactly it - and it held
  neither `RoomPresent` nor `RoomOpen`, so the one consumer the oracle was
  built for could not call it.

  The gates are role-derived (`role_has_capability` reads the role and nothing
  else), so there was no way to grant the capability to a particular entry
  either. The workaround an operator reaches for is worse than the grant:
  running the agent as `initiator`, which carries `KeyMint` and `DeviceAdmin`
  besides.

  Neither capability widens what this role can do. `RoomPresent` mints a leaf
  attenuated from the principal's own room authority - one action, one room,
  four hours, bound to the caller - and the role already holds `Sign`, which is
  the principal's key over arbitrary bytes and therefore strictly more.
  `RoomOpen` decrypts a room record under a group key the VTA already holds,
  and the same role can already read the credential vault. `Reader` and
  `Monitor` get neither, and a test pins that: minting a credential on a
  principal's behalf is not a read.

  Also corrects two doc comments that described enforcement that does not
  exist. `AclEntry::capabilities` said the auth layer falls back to the
  role-derived set when it is empty, which reads as "and uses this set when it
  is not" - but no gate consults the field, the authenticated claims carry no
  capability set, and nothing over the wire can set it. It is read in exactly
  one place, to describe a registered device's authority in a binding listing.
  A reader who believed otherwise would think an entry was least-privileged
  when it holds everything its role does, so the field and
  `role_has_capability` now say what is true. Making it real means carrying the
  set in the claims and giving the ACL surface a way to set it - a separate
  change with its own design question about whether an entry's set may widen
  beyond its role or only narrow within it.



## [0.17.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-common-v0.16.2...vti-common-v0.17.0) — 2026-09-07


### Added

- **vti-common**: Make Capability and AuditEvent non-exhaustive ([#1262](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1262))

Both enums are designed to grow — `Capability` gains an entry whenever the agent
  gains a power worth gating separately, and `AuditEvent`'s own doc comment says
  variants arrive alongside the features that emit them. Neither was
  `#[non_exhaustive]`, so every one of those additions was a breaking change for
  anyone matching on them.

  That is not hypothetical. `MemoryRead`, `MemoryWrite`, `RoomPresent`, `RoomOpen`
  and `AuditEvent::RoomOperation` went out in vti-common 0.16.2 — a PATCH release —
  so a downstream exhaustive `match` stopped compiling on a routine `cargo update`,
  with the caret requirement picking it up automatically.

  The cost inside this workspace is zero: nothing here matches exhaustively on
  either type. Every reference constructs a variant as a value, and the only
  `match self` sits in `vti-common` itself, where the attribute has no effect.
  Checked before writing it, not after.

  Downstream code now needs a `_ =>` arm, and that is the point rather than the
  price. A capability a consumer has never heard of is precisely the one it must
  not silently treat as granted, and an audit event it cannot name still has to be
  recorded; a wildcard arm forces both decisions to be written down instead of
  being decided by a compile error at the wrong moment.

  Deliberately NOT applied to the sixteen `vta-sdk` wire structs that broke the
  same way when they gained `ext`. `#[non_exhaustive]` on a struct removes literal
  construction from outside the crate entirely — functional update with
  `..Default::default()` included, which is the part people assume still works — so
  all sixteen would need constructors or builders. That is a redesign of the public
  SDK surface, not cleanup, and the safety half is now covered anyway: a new field
  forces a breaking bump and #1256's guard makes that stick. Worth doing
  deliberately, in its own change.

  Breaking for external consumers, so this needs the minor slot (0.17.0) rather
  than a patch. The guard added in #1256 will now say so if the release proposes
  otherwise — which makes this its first live exercise of the failure path.



## [0.16.2](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-common-v0.16.1...vti-common-v0.16.2) — 2026-09-06


### Added

- **rooms**: A VTA joins a room, keeps up, and opens what it holds ([#1250](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1250))

Implements rooms/keys/{key-package,welcome,commit,open} - the delivery
  flow specified in dtgwg-trust-tasks-tf#355 and the decryption oracle from
  #349, on the custody layer from #1248. This is the piece that makes a
  data room readable by an agent that never holds a key.

  Four tasks, four different gates, and only one is a capability. The
  delivery three are inbound - a room's owner reaching this VTA - and an
  ACL of ours has no opinion about who a room's owner is. commit in
  particular is authorized INSIDE the group: MLS authenticates the
  committer as a member of the group we already hold, and a list we kept
  would be this service deciding who may commit to a room it is not part
  of. Only open is our own principal's agent asking us to decrypt, which is
  what a capability is for - RoomOpen, registered upstream in #351.

  The invitation is what makes a Welcome acceptable. A Welcome carries a
  group's secrets, so anyone able to reach a VTA could otherwise push group
  state into it. Joining a room is already a two-party act and the VIC is
  already the consent artefact; this is where that stops being ceremonial.
  Five checks, none optional - it parses as an invitation, its proof
  verifies, the issuer is the room, the subject is us, and it is live and
  unspent - and dropping any one leaves a way in. VerifiedInvitation is
  constructible only by the verifier, so a caller cannot reach consumption
  with something nobody checked.

  The invitation is consumed only AFTER the join succeeds. Burning it on a
  Welcome that then failed to process would strand the member: invitation
  spent, not in the room.

  Joining twice is refused rather than merged. Two group states for one
  room is a condition nothing downstream can resolve - open has no way to
  choose, and choosing wrong returns 'did not open' for a record the member
  can plainly see.

  open reports which epoch the VTA holds when a record is sealed under a
  later one. A member who missed a commit is stuck at their last epoch, and
  the raw symptom is 'this record does not open', which reads like
  corruption; naming the epoch turns it into 'a commit has not been
  delivered', which an operator can act on.

  Two keyspaces, both Cascade on DID deletion: room_groups holds group
  secrets and belongs at the same protection level as the key store, and
  room_invitations outlives the groups it admitted - while the member
  exists, a consumed invitation MUST survive leaving a room, or the same
  invitation would work twice.

  Four censuses had something to say. The MCP guard, where open and welcome
  are Sensitive (plaintext out, key material in) while key-package and
  commit are ordinary mutations. Retry safety, which produced four
  different answers and is the better for it: open is ReadOnly, commit is
  RetrySafe because the spec made replay a no-op precisely so delivery
  could retry, and key-package and welcome are Keyed - one leaves a second
  private half behind, the other cannot tell a lost reply from a completed
  join. Then the conformance witnesses and the namespace list.

  trust-tasks-rs 0.17.8 landed mid-build carrying #351, #354 and #355, so
  all four request types are generated rather than hand-written.

- **rooms**: The presentation oracle, so an agent never holds its human's credentials ([#1247](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1247))

Implements rooms/keys/present/0.1. The data-rooms design turns on a member
  equipping their agent with strictly less than they hold - a chain one link
  longer, conferring read for four hours, bound to one host - and nothing
  minted one. A member wanting to give an agent access had two options: hand
  over their own credentials, which is the outcome attenuation exists to
  prevent, or mint an attenuation by hand, which nobody does.

  So the agent asks, and the VTA mints. The VTA already holds the member's
  keys and is already in their trusted computing base; a host is not, which
  is why the host only ever sees the result.

  Four things a caller cannot obtain by asking, and each closes a way this
  could have quietly become the credential hand-off it replaces:

    More than the principal holds fails in attenuate, which refuses to
    widen - not at a policy check somebody could forget to write.

    A presentation covering everything is unreachable: action is required
    and exactly one action is conferred.

    A presentation made out to somebody else is unreachable: the leaf grants
    to the DID the transport authenticated, never one named in the payload.
    One minted for A is worthless to B even if B obtains it, because the
    presenter binding refuses it on the far side.

    A long-lived leaf is unreachable: the lifetime is a constant, not a
    request parameter. A caller that could ask for a year would be asking
    for the standing credential the oracle exists not to hand over.

  Gated on Capability::RoomPresent - registered upstream as roomPresent in
  dtgwg-trust-tasks-tf#351 - and deliberately not on Sign. An agent that may
  ask for a scoped, audience-bound presentation is not thereby an agent that
  may sign anything at all with its principal's key, and gating an oracle on
  the generic signing oracle grants strictly more than the task needs.

  The credentials are found by issuer, because a room issues its own - the
  same property the host verifies against, so a credential that would not
  verify there is not one this will present. Two authority credentials from
  one room is refused rather than resolved: picking the broader one hands
  out more than necessary, picking the narrower produces a presentation that
  fails at the host for reasons the caller cannot see.

  Five censuses had something to say, and all five were right. The
  conformance witness. The retry-safety classification - RetrySafe, because
  the oracle stores nothing and a retry mints a second leaf conferring
  exactly what the first did, on the same expiry; keying it would buy a
  dedup record against a harmless duplicate at the price of failing a retry
  the caller needs. The MCP guard, where it joins 'authority, moved' beside
  vta/credentials/issue: an MCP host approves a tool, so a blanket vta_call
  approval must not silently cover minting a presentation over its
  principal's standing. And the canonical-namespace list, which gains
  spec/rooms/ for exactly one URI - most of that family is a host's surface,
  and this is the one member a VTA serves.

- **rooms**: Audit every room operation, without learning who ([#1244](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1244))

Room operations wrote no audit entry at all. Every other consequential
  VTC surface does - join, members, credentials, backup - and the VTA has
  a census whose stated position is that a task which did its work and
  left no trace is a gap with no defensible reading. The rooms family was
  that gap.

  Reads are audited alongside writes, and on shared material they are the
  more interesting half: a write log says what a room contains, a read log
  says who has seen it, which is the question an incident review actually
  asks. Listing and fetching are distinct actions in the log - both are
   on the authority axis and different events to anyone reading it.

  The part worth the review time is which actor may be recorded.

  Every host has audit machinery and every one of them wants to write the
  acting party's DID into it. On a private room that single line hands the
  host the membership it was built never to learn - assembled one entry at
  a time by the component least able to notice it is doing so. It is a
  silent failure: nothing breaks, no test goes red, and the log looks
  exactly like an attributed room's.

  So the decision is a function in vti_rooms::audit rather than a judgement
  at each host's call sites, and AuditActor has no constructor that takes a
  DID unconditionally. On the disclosing tiers it carries the verified
  subject; on private it carries Member, which is true - the host verified
  a chain, so it knows a member acted - and is the most it may say. A test
  asserts the presenter appears nowhere in a private room's audit trail,
  including in the Debug rendering.

  for_operation takes the AuthorizedAction rather than a presenter string,
  so a host cannot record an actor for an operation it did not authorize,
  and cannot record a different actor from the one it did.

  The record key is recorded on every tier. An opaque key identifies a
  record without describing it, which is exactly why the schema requires
  opacity on the sealed tiers - and why a host logging a descriptive key
  would be logging content.

  Both hosts reach the same decision and differ only in where the trail
  goes. A VTC writes to its hash-chained audit keyspace; room-host has no
  chain and no business growing one - it is a delivery service, and an
  HMAC key store plus a hash chain is most of a community service again -
  so it emits tracing, where an operator's own pipeline collects it. A
  host that logged the DID because its own logging happened to be simpler
  would have handed itself the membership by the back door.

  A failed audit write is logged and swallowed. Refusing an operation that
  already succeeded turns an audit outage into a room outage and tells the
  caller their write failed when it did not; the chain's own hash makes a
  gap visible to a verifier, which is the right place to notice it.

- **acl**: Add MemoryRead/MemoryWrite and gate the memory tasks on them ([#1234](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1234))

There was no read-only grant on agent memory. The gate in
  trust_tasks/memory.rs was auth.require_context and nothing else, and a
  context is binary: any DID that could reach one could also write and
  delete every memory in it. So an operator could not give an agent
  read-only access to their own memory, and the --read-only flag in
  vta-mcp's guard is a client-side glob filter that a caller talking to the
  VTA directly never encounters.

  The published specification already assumes the split exists.
  specs/vta/memory/delete/0.1/spec.md reasons about "a VTA whose write
  capability is granted more freely than its read capability", and about
  callers holding write without read. There was no read capability and no
  write capability; there was a context. The ACL supplied nothing finer
  either - the act axis is (role, allowed_contexts) decoded to a
  three-valued ActScope, a where with no what.

  Adds Capability::{MemoryRead, MemoryWrite}, wires them through
  derived_capabilities_for_role, and gates the three handlers. Legacy rows
  carry no explicit capability set and fall back to the derived mapping, so
  the roles that write memory today keep writing it.

  Deliberate behaviour changes, both tightenings:

  - reader loses memory write. A read-only consumer of a context should not
    be able to rewrite the memories in it.
  - monitor loses memory access entirely. It is the least-privileged role
    and the Default for AuthClaims, precisely so a fixture that leaks past
    its expected reach lands somewhere harmless - which it did not, while
    memory was context-gated alone.

  application keeps both, deliberately and with a test saying why:
  vta-agent-memory grants exactly that role so the memory service is not
  the user, and every existing install would otherwise stop saving.

  The capability is checked before the context, so a caller missing it
  cannot use the reason text to probe which contexts exist.

  Note the canonical Capability enum in the trust-tasks registry
  (device/_shared/0.1) is already behind this crate - it carries neither
  sign-trust-task nor credential-write. A spec PR reconciling all four
  follows separately; this change does not widen that gap unilaterally so
  much as make it worth closing.

  Implements the orthogonal fix called out in
  docs/05-design-notes/data-rooms.md 11.1.



## [0.16.1](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-common-v0.16.0...vti-common-v0.16.1) — 2026-09-01


## [0.16.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-common-v0.15.0...vti-common-v0.16.0) — 2026-08-29


### Added

- **sdk**: Any DID that names a key may sign a Trust Task ([#1193](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1193))

A Trust Task proof could only be made by a `did:key`. That was never a policy
  anyone chose — it was the shape of two helpers, and it meant a provisioned
  integration could not dispatch any of the 210 proof-requiring Trust Tasks, over
  any transport, because every DID this workspace provisions is a `did:webvh`.

  The rule is now the obvious one: **any DID that can name a key may sign**. The
  DID method is not the authorization; resolving the verification method and
  checking the signature is. `did:key:z6Mk…#z6Mk…`,
  `did:webvh:<scid>:example.com:glenn#key-0` and `did:web:example.com#key-1` are
  all ordinary holders.

  What actually stood in the way:

  The signer took `(holder_did, private_key)` and *derived* the verification
  method as `<did>#<multibase>`. That derivation exists only for `did:key`, whose
  key is its identifier — a `did:webvh` document decides what its keys are
  called, so nothing can guess `#key-0`. A signer that takes only a DID
  structurally cannot serve any other method. `HolderKey` now carries the
  verification method; `HolderKey::from_did_key` keeps the derivation for the one
  method that has one, and refuses to invent one for the others.

  The verifier used `DidKeyResolver`, which refuses everything else.
  `TrustTaskVmResolver` resolves `did:key` locally and any other method through
  the configured DID cache, matching a proof's absolute `verificationMethod`
  against a document that may name it relatively. It is hoisted from the
  equivalent the VTC already had for credential verification.

  `ClientIdentity` gains `verification_method`, and `connect_didcomm_bundle{,_on}`
  build an identity from the bundle's own Ed25519 `SecretEntry` — whose `key_id`
  *is* the verification method the DID document publishes, so nothing is guessed.
  Those constructors passed `identity: None` deliberately; that reason is gone.

  Every verifying call site now takes a resolver: the VTA's dispatch spine, REST
  login, step-up and consent; the VTC's dispatch, REST login and relationships.
  Threading it is the half that makes the signer change real.



### Fixed

- **vti-common**: Gate the keyspace name on the feature that reads it ([#1190](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1190))

`cargo build -p pnm-cli` (and every other default-feature consumer) warned
  `field `name` is never read` on `LocalKeyspaceHandle`. The field is not
  unused — it is the keyspace name bound into the AES-GCM associated data, so
  a value cannot be relocated to another keyspace that shares the storage key
  and still authenticate. But every read of it builds an AAD, and all of them
  sit behind `#[cfg(feature = "encryption")]`, which is off by default. With
  the feature off there is genuinely nothing to read it.

  So it is now gated with the feature it serves, exactly as the sibling
  `encryption_key` field already is, and cfg'd at its one construction site.
  The alternative — carrying it unconditionally under an `allow(dead_code)` —
  would leave a security-relevant field looking like it might be doing
  something in builds where it cannot.

  No behaviour change in either configuration: with `encryption` on the field
  and its readers are unchanged; with it off nothing referenced the field.
  Verified warning-free on `cargo build --release -p pnm-cli` (defaults and
  `config-session`), `cargo check -p vti-common --all-features --all-targets`,
  and `cargo test -p vti-common --all-features` (476 passing).



## [0.15.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-common-v0.14.0...vti-common-v0.15.0) — 2026-08-28


### Added

- **vtc**: State artifact lifecycle precedence once, and apply it on read ([#1179](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1179))
- **tasks**: Catch up to the registry on vault 0.3, device/wipe 0.2 and credentials/issue 0.2 ([#1145](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1145))

Five of the six families vta-sdk lagged the registry on. The sixth,
  `provision/integration/0.3`, is not here: its response schema could never
  validate — `required` named a `digest` the 0.2→0.3 rename had already removed
  from `properties`, against `additionalProperties: false`. Fixed upstream in
  trustoverip/dtgwg-trust-tasks-tf#324; VTI adopts it once that publishes.

  **vault/{list,get,upsert} 0.3.** `AttachmentRef.sha256` — hex, with SHA-256
  pinned by an `^[0-9a-f]{64}$` pattern — becomes `digestMultibase`, a multibase
  multihash that names its own algorithm. Worth stating plainly: nothing in this
  service has ever constructed an `AttachmentRef`. Every site is `vec![]` and
  `vault/upsert` only carries forward whatever an entry already had, so the
  member has never reached the wire and this is a type-level rename today. The
  wire contract is what changes, and it changes so that moving off SHA-256 later
  is a value change rather than another schema revision.

  **device/wipe 0.2.** `cache-and-keys` → `cacheAndKeys`, the same recasing the
  rest of the device slice took. Its constant carried "No 0.2 spec exists
  upstream; this stays on 0.1" while `specs/device/wipe/0.2` had been published
  for some time. The replacement comment says so: a comment asserting an absence
  is a claim about the registry that nothing re-checks, and it is why nobody
  looked again.

  **vta/credentials/issue 0.2.** The request payload is unchanged. The response
  stops restating the shared `IssuedCredential` inline and composes it through
  `allOf` + `unevaluatedProperties` — same members, same required set, identical
  wire form. So the two versions share a dispatch arm rather than a transform.

  The edge-transform table goes from one wire URI per spec to a list.
  `vault/*` 0.3 differs from 0.2 only in `AttachmentRef`, which is not an enum
  value and not at any path the transform touches — so it down-converts to the
  same canonical handler by the same casing rules. Giving it its own row would
  have duplicated every path and left the two to be kept in step by hand.

  `upconvert_response` now answers as the version the caller *sent*. With several
  wire URIs per spec, retyping a response to a fixed one would be refused by a
  client validating against the version it asked for.

  Two guards needed widening, and both were right to fail first:

  * `superseded_tasks_are_dispatched` did not count an edge-transformed URI as
    served. Its premise is that a row whose counter can never move reads the same
    as "safe to retire" — but the counter *does* move for these, because
    `dispatch_trust_task_core` reads the superseded row from the URI as it
    arrived, before the down-convert. The successor half of the pair already
    accepted them.
  * the wire/deprecation parity test checked only the 0.1 hop. A spec accepting
    0.1, 0.2 and 0.3 needs a row per superseded version, or the middle one is
    retired on no evidence at all.

  `ALL_URIS` and `retry_safety` carry the four new URIs; the census caught their
  absence, which is what it is for.

- **vta**: Stop error messages from being a probing oracle ([#1130](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1130))

Framework 0.5.0 makes the message-sanitization rule normative for every code,
  not just `identityMismatch`: a `message` MUST NOT reveal consumer-internal
  state, the contested value of a mismatched party, or resolver, verifier, or
  key-status internals. Every rejection is emitted on the same path, to the same
  possibly-unauthenticated party, generally before any authorization decision has
  been reached.

  This service violated two of the three.

  `app_error_to_reject` passed `AppError::Internal`'s cause into the `message`
  verbatim, so a caller learned "ATM not configured — server cannot pack DIDComm
  envelopes" or "log entry has no update_keys" — the deployment's shape, its
  configuration, and which invariant just broke. The catch-all arm was the
  quieter half: it rendered whatever `Display` an error happened to have, so a
  variant added later would publish itself with nobody choosing to. Both now land
  on one fixed string and log the cause for the operator.

  `DiProofError`'s `Display` rendered the underlying verifier error, and that
  reaches the wire through `PermissionDenied`. A caller could read which
  cryptosuite ran and how verification failed. The detail moves to a `cause()`
  that is deliberately not reachable through `Display`, since the defect was that
  the wire rendering and the operator rendering were one function.

  `notFound`, `malformedRequest` and `permissionDenied` pass through unchanged:
  they describe the caller's own request back to it, which is not
  consumer-internal state.

  `an_internal_error_does_not_say_internal_error_twice` asserted the cause was on
  the wire. Its subject was a doubled prefix, which the fixed string also
  settles; it is now `an_internal_error_reveals_no_internal_state`, joined by
  `the_catch_all_arm_is_opaque_too`.



### Chore

- **deps**: Aes-gcm 0.11, and stop the nonce conversions panicking ([#1173](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1173))
- **sdk**: Release vta-sdk 0.30.0 for the added CreateKeyBody field ([#1156](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1156))

`CreateKeyBody` gained a `key_id` field while the crate stayed at 0.29.0.
  The struct is exhaustively constructible through the public API, so an
  existing literal no longer compiles — a breaking change under 0.x rules,
  which the semver report has been flagging as its one real finding
  (195 pass, 1 fail) since the field landed.

  Bumps the crate and the nineteen intra-workspace requirements that pin it,
  so `cargo check --workspace` still resolves the path copy and a consumer
  resolving from the registry gets a version that admits the break.



## [0.14.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-common-v0.13.2...vti-common-v0.14.0) — 2026-08-26


### Added

- **vtc**: Implement the VPC as the deliberate-correlation mechanism on an edge ([#1074](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1074))

* feat(vtc): implement the VPC as the deliberate-correlation mechanism on an edge

  `PersonaCredential` appeared nowhere in this repo and
  `DTGCredential::new_vpc` was never called, so the P-DID had no
  implementation and the word "persona" drifted onto the membership DID for
  want of anything to anchor it ([#1067](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1067)).

  What the absence cost, concretely. After the publish proof-of-possession
  change ([#1054](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1054)) a member had exactly two settings: publish under a pairwise
  relationship DID and correlate with nothing, or publish under the
  membership DID and correlate with everything, permanently, for anyone who
  retains the credential. DTG Credentials §Privacy Considerations 3 says
  correlation "should occur only through the holder's deliberate assertion of
  a persona (via a VPC) or an M-DID". The precise instrument was missing, so
  members had only the blunt one.

  This adds the VTC half of it: `POST` / `DELETE
  /v1/relationships/{id}/persona` (`vtc-service/src/routes/relationships.rs`).
  A VPC is an *annotation* credential — it creates no graph structure, it
  attaches to structure that already exists — so there is no "publish a VPC",
  only "attach this persona to that edge", and the annotation is stored on the
  edge row (`vtc-service/src/relationships/mod.rs`) rather than in a keyspace
  of its own. The P-DID surfaces on `GET /v1/relationships/graph` as
  `personaDid`, which is where the correlation becomes visible; an annotation
  nothing reads would leave #1067 in the state it describes.

  trustoverip/dtgwg-cred-spec#9 asks how a VPC binds to a specific
  relationship and is open. Nothing here answers it. A VPC names its persona
  (`issuer`) and the counterparty (`credentialSubject.id`) and not the
  relationship DID the persona used, so it does not identify an edge on its
  own.

  Rather than add a field to the credential and present that as the
  resolution, the binding is made at the request level:

  1. the caller names the edge by id in the URL;
  2. the caller proves control of that edge's `issuerDid`, with the same
     proof-of-possession construction publishing the edge required;
  3. the VPC's `credentialSubject.id` must equal the edge's `subjectDid`.

  (2) is what makes it safe — the only party who could have published this
  edge is the only party who can annotate it, so no new trust is extended.
  (3) is a consistency check, not a binding. If #9 lands an in-credential
  binding (a `digest` over the VRC, as the VWC already has), the endpoint can
  require it as well without changing the stored shape.

  Stated limitation: the spec says a VPC's subject is "typically the R-DID or
  M-DID used in the relationship". A VPC naming the counterparty's M-DID, on
  an edge whose `subjectDid` is their R-DID, fails check (3) and is rejected.
  That case is real and needs the same #9 answer; guessing would mean
  accepting a VPC naming a party the VTC cannot tie to the edge, which is the
  problem restated.

  - **No uniqueness check on the P-DID**, in direct contrast to the R-DID rule
    the publish path enforces unconditionally. A relationship DID that recurs
    across counterparties is a defect; a persona DID that recurs is the entire
    purpose of the credential.
  - **Detach is in scope.** A privacy mechanism that cannot be reversed is
    worse than none, so withdrawing a persona is as available as asserting one
    — and gated identically, or anyone could strip another member's persona.
    The two authorization `type` values are distinct so neither can stand in
    for the other.
  - **No `persona.rego`.** Attach is gated on a live member session plus proof
    of control of the edge's issuer. A community that already decides whether
    an edge may be published has not obviously earned a second say over what
    its issuer calls themselves. Additive if that is wrong.
  - **No P-DID secondary index.** "List every edge of persona P" is answerable
    from the admin graph; an enumeration surface deserves its own design
    rather than falling out of an index write.
  - **`new_vpc` is used in a wire-shape test, not a mint path**
    (`vtc-service/src/credentials/dtg.rs`). The VTC has no key that may
    legitimately sign a VPC — it is self-issued by a person — so there is no
    `issue_persona`. Pinning the catalog's VPC shape matters more here than
    for the credentials the VTC does mint: drift changes what we *accept*, and
    the failure mode is every conformant VPC in the ecosystem being rejected
    by a VTC that still compiles and still passes its own tests.
  - **Audit** (`VpcAttached` / `VpcDetached`, `vti-common/src/audit/event.rs`)
    records the P-DID with the authenticated member as actor — the same
    attribution decision, and the same accepted residual, as VRC publish. The
    `info!` on both paths carries the persona and not the member.

  `vtc/relationships/persona/0.1` is bound ahead of its publication in the
  upstream Trust Task registry and recorded in `UNPUBLISHED_CANONICAL_OK`
  (`vtc-service/tests/trust_task_manifest.rs`) — the first entry the
  `spec/vtc/` family has had. Deliberate: a payload schema authored now would
  encode this request-level binding as if #9 were closed.

  Design note: `docs/05-design-notes/vpc-persona-annotation.md`.

- **vtc**: Let a member publish a relationship edge without naming themselves in it ([#1061](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1061))

* feat(vtc)!: let a member publish a relationship edge without naming themselves in it

  Publishing a VRC required the credential's `issuer` to equal the caller's
  session DID. That one line is why a member's membership DID ends up inside
  the durable, publishable credential — and the community graph built from
  those credentials is a correlatable member-to-member edge set. DTG
  Credentials asks for the opposite: R-DIDs are RECOMMENDED, unique per
  counterparty "even within the same community", and M-DID edges are a
  bootstrapping allowance to migrate away from.

  The pin was conflating two properties. The first — the VRC was made by the
  party it names as issuer — is provided by the data-integrity proof and is
  untouched here. The second — the party publishing it is the party that
  issued it — is what the pin actually provided, and it is worth keeping:
  issuance and publication are different disclosures, and appearing in the
  community graph should be the issuer's disclosure to make, not that of
  whoever happens to hold a copy.

  So the pin is replaced rather than removed. The session proves community
  membership; a publish authorization signed by the issuing key proves control
  of it. Neither requires them to be the same string.

  The authorization binds to `{type, vrc-hash, aud, sessionId, issuedAt}`, each
  field covering a distinct replay: signatures made over other objects, other
  credentials, other communities, other members' sessions, and unbounded reuse
  within a live session. It is verified and dropped — never stored, logged or
  audited, because it carries `sessionId` and persisting that would rebuild the
  exact membership-to-relationship linkage pairwise identifiers exist to
  remove. Two tests assert that directly, on the stored row and on the audit
  store, since it is the kind of property a later debug log undoes silently.

  The subject-must-be-a-member check is dropped on the pairwise path. It is not
  merely unanswerable once the subject is an R-DID; DTG Credentials is explicit
  that "community membership is not a precondition for issuing, holding, or
  presenting a VRC". The subject's consent to the edge is their publication of
  the reciprocal VRC — the two-VRC edge model — not this community's assertion
  that they exist.

- **app-state**: A third store for versioned, namespaced application state ([#1051](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1051))

Applications built on a VTA have had nowhere to keep versioned metadata.
  Adds `vta/app-state/{get,put,list,delete,get-many,put-many}/1.0` — a store
  beside the secrets vault and the credential vault, for JSON an application
  owns and the VTA does not interpret.

  Records are addressed `(contextId, namespace, key)`. The namespace scopes one
  application so several tools can share a context without colliding, and is the
  seam a per-namespace grant would later use — which is why it is part of the
  address rather than a prefix convention on the key. In 1.0 a namespace is
  collision avoidance and NOT a trust boundary: an application with write access
  to a context reaches every namespace in it, and the `put` and `delete` specs
  say so normatively. Isolation means separate contexts.

  Deliberately not built on `vta/memory/*`. `MemoryItem` is `{key, value}` with
  nothing to hang a precondition on, and its `list` returns the whole context —
  but the argument that settles it is that "forget everything" has to stay a safe
  thing to ask an agent, which it cannot be if account state lives there.

  Three properties are why this is a store rather than a field on an existing one.

  **One counter per `(contextId, namespace)`, not per record.** A record's
  `version` is the counter value its most recent write took, so one number is
  simultaneously the optimistic-concurrency token `expectedVersion` compares
  against and the watermark `sinceVersion` compares against. A per-record counter
  serves the first but cannot serve the second — two records' counters are not
  comparable, so no single number means "everything after this point" — and would
  have forced a second sequence kept consistent by hand. The cost is that a
  record's version jumps by whatever its neighbours consumed, which the wire
  contract states: versions are opaque and monotonic, never an edit count.

  **A failed precondition returns the current version AND value.** A bare
  rejection obliges a re-read, and the re-read races the next write; the pattern
  has no fixed point under contention. Returning the winner's view removes the
  race rather than narrowing it, and the spec makes it normative.

  **Delete leaves a versioned tombstone, and the tombstones are reaped.** Without
  one, a consumer pulling from a watermark learns of every create and update and
  never of a deletion, so deleted records resurrect on its next rebuild.
  Retention is `app_state.tombstone_retention_days` (default 30, matching the
  vault's `grace_days`) — a destructive window is an operator's choice, not a
  constant — and `list` advertises the configured value, since a consumer
  schedules against that number. The sweeper runs from the storage thread beside
  the ACL/consent/vault sweepers.

  The sweeper reaps a *prefix*, not a set: each namespace walks its tombstones in
  version order and stops at the first still inside the window. Reaping a later
  tombstone while leaving an earlier one would make the reap watermark
  unstateable — no single number would describe what survives, which is precisely
  what `watermarkTooOld` has to be able to say. `0` days disables reaping, and
  that is enforced at the call site rather than as a zero cutoff, which would mean
  the opposite.

  Version reservation is fsynced and re-seals the TEE integrity manifest, for the
  reason `vti_common::store::counter` gives for BIP-32 counters: a counter
  surviving only in the journal buffer can be re-derived after a crash and reissue
  a used value. Here a reused version means two records collide on one `appv:`
  index key, so one disappears from the change feed and every incremental consumer
  misses that change permanently, silently. A batch reserves a block and pays one
  fsync rather than N; writes that then fail leave gaps, which are safe and
  tested.

  Retry safety: reads are `ReadOnly`, `delete` is `RetrySafe` (a second delete
  finds a tombstone and deliberately takes no new version, so a watcher sees
  nothing), and `put`/`put-many` are `Keyed` — a `put` without `expectedVersion`
  does not converge, and the class is per URI, not per payload.

  Blobs are deliberately out of scope in 1.0; adding a `blobRef` is additive.

  Concurrency is a process-local lock per namespace, not a store-layer
  compare-and-swap. fjall takes an exclusive database lock so two processes cannot
  share a store, and the vsock protocol has no atomic opcode — its
  `insert_if_absent`/`swap` are already non-atomic fallbacks. A CAS today would be
  atomic exactly where the lock suffices and a warn-and-fallback exactly where it
  would need to be real. Recorded in the design note with what would change that.

  Schemas published upstream as trustoverip/dtgwg-trust-tasks-tf#252 and #253;
  this depends on the released trust-tasks-rs 0.11.2, pinned to a minimum patch so
  an older resolve fails as a stale dependency rather than as unspecced URIs.
  Conformance witnesses cover all six URIs, so nothing enters
  `UNSPECCED_DISPATCHED_URIS`.



### Changed

- Delete the Verifiable-prefixed credential tags that were never DTG types ([#1071](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1071))

`VerifiableMembershipCredential` and `VerifiableEndorsementCredential` are not
  DTG credential types and never were. The specification defines seven concrete
  subtypes; neither is among them, and nothing in this stack has ever issued
  either. They survived as a name, a pair of literals and a compatibility shim,
  and between them they broke cross-community recognition for every real
  presentation ([#1062](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1062)).

  Four places, one cause.

  **The SDK constant.** `VERIFIABLE_MEMBERSHIP_CREDENTIAL_TYPE` held the value
  `"MembershipCredential"`, with a doc comment explaining that the prefix in the
  name was historical and the tag did not have it. A constant whose name
  disagrees with its value is an invitation, and it was taken: someone reading
  the name hand-rolled `"VerifiableEndorsementCredential"` into the recognition
  path, where it matched nothing. Renamed to `MEMBERSHIP_CREDENTIAL_TYPE`, and
  `ENDORSEMENT_CREDENTIAL_TYPE` added beside it so the VEC tag has a home rather
  than being a literal at the point of use.

  **The compatibility shim.** #1063 added `LEGACY_TYPE_TAGS`, accepting both
  prefixed tags from peers predating the catalog adoption. Nothing is published,
  so no such peer exists — and a reference implementation that accepts a type the
  specification does not define reintroduces exactly the drift the function it
  sits in was written to prevent. Removed; the test that pinned the behaviour now
  pins its refusal.

  **The audit trail.** Emitted envelopes recorded `credential_type:
  "VerifiableMembershipCredential"` / `"VerifiableEndorsementCredential"` — tags
  no credential ever carried, in the one record meant to be authoritative after
  the fact. They now record what was issued.

  **The policy input.** `issuer_member` / `subject_member` were carried alongside
  `issuer` / `subject` for operator policies written against the pre-#1061 shape.
  There are no deployed operator policies to preserve, and two spellings of one
  concept is how the concept drifts. The duplicates are gone and the surviving
  fields carry `is_current`.



### Fixed

- **vtc**: Follow the spec on every auth response, and close the conformance gate ([#1112](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1112))

* test(vtc)!: make response conformance fail the build

  Until now the layer reported and a green suite was not evidence of
  conformance — #1107's own memory note said to grep the run rather than trust
  the exit code, which is a signal nobody has to obey.

  A violation outside the allowlist now returns 500 with the schema error, so the
  test that provoked it fails on its own status assertion and prints the reason.
  Chosen over panicking in middleware, which surfaces at the call site as a
  transport error and says nothing about which task or why.

  The allowlist is eight `auth/*` tasks with ALLOWED_COUNT asserted beside them —
  the same discipline as KNOWN_DRIFT_COUNT, because the cheapest way to make a
  failing check pass is to add a line to a list nobody watches. An allowlisted
  violation is still reported, pinned by a test: a list that suppressed the
  evidence would mean rediscovering each entry before it could be closed.

  Two existing guards caught mistakes of mine on the first run. The allowlist
  named login/{start,finish}/0.1 where the service binds 0.2 — built from the
  violation output rather than the route mounts — and the manifest guard flagged a
  fake `trusttasks.org/spec/` URI in a new unit test, correctly, since binding
  such a URI asserts the registry serves it.

  Also retargets relationships/{list,graph} to the 0.2s from
  trustoverip/dtgwg-trust-tasks-tf#266, and fixes a seeder that wrote
  `seed-{uuid}` into `vrcDigestMultibase` — unique per row, and so a suite
  structurally blind to digest format.

  The VTC family is now clean; every remaining violation is `auth/*`.

- **vtc**: Speak the endorsement model the spec defines ([#1096](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1096))

The endorsement family — `issue`, `list`, `show` — spoke a different model
  from the one the spec defines. Three renames, one per row, and a request
  member that had been deliberately renamed away from the spec's name.

  | canonical `Endorsement` | this service sent |
  |---|---|
  | `endorsementId` | `id` |
  | `typeUri` | `endorsementType` |
  | `issued` | `createdAt` |
  | `subjectDid`, `statusListIndex`, `claim`, `revokedAt` | already matched |

  ## Mapping at the boundary, not renaming storage

  The stored `Endorsement` derives `Deserialize` and serialises `camelCase`,
  so `id` / `endorsementType` / `createdAt` are the on-disk keys of every row
  already written. Renaming those fields would rewrite the persisted fjall
  format and need a migration — for a naming problem that only exists on the
  wire.

  So `EndorsementRow` is a wire type mapping from the stored row, the same
  split `GenerationRow` uses ([#1095](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1095)). Storage keeps the names it has; the API
  publishes the names the spec gives.

- **common**: Send the pagination wrapper in camelCase, as the schemas always said ([#1078](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1078))

`Paginated<T>` carried no `rename_all`, so every list task sent `next_cursor`
  and `total_estimate` against published schemas that say `nextCursor` and
  `totalEstimate`. A direct R3.1 violation, and the same casing-drift class as
  #656/#658 — where an empty `allowed_contexts` silently minted a super-admin.

  Nothing caught it because nothing compared the two. The service sent one
  spelling, `vtc-client` mirrored the service rather than the schema, and the
  admin SPA typed its fields from the service too. All three agreed with each
  other and none agreed with the contract. The conformance witness added in
  #1076 is what finally put them side by side.

  Four consumers move together: the wrapper in `vti-common`, `vtc-client`'s
  `Page<T>`, and the `joinRequests` and `members` admin plugins. `audit.tsx`
  reads a `cursor` member of a different shape and is untouched.

  ## The count goes 33 → 32, not 33 → 28

  The witness refused 28 and accepted 32, which is the useful part of this
  change and the reason the module doc is rewritten rather than decremented.

  Five entries cited the wrapper. Only `relationships/list` becomes fully
  conforming, because it was the only one whose drift was the wrapper alone —
  its spec types `items` as free objects. The other four still diverge at row
  level (`createdByDid`, `vpClaims`, `MemberResponse` members) and keep their
  entries, now describing only what is left rather than restating a casing bug
  that is fixed.

  Closing a shared root cause moves four entries without closing them. A drift
  count that fell by five would have implied more progress than happened, and
  `known_drift_entries_still_diverge_where_they_say_they_do` is what stopped it
  saying so.



## [0.13.2](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-common-v0.13.1...vti-common-v0.13.2) — 2026-08-22


## [0.13.1](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-common-v0.13.0...vti-common-v0.13.1) — 2026-08-21


## [0.13.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-common-v0.12.2...vti-common-v0.13.0) — 2026-08-20


### Added

- **vta**: Dedup keyed Trust Tasks on an idempotency key ([#1011](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1011))

A client that retries a timed-out request is doing the right thing. The
  dangerous case is the one where the VTA processed it and only the reply
  was lost, because the retry then produces a second durable effect —
  `webvh/dids/create` being the sharp example, where auto-assigned paths
  mean the retry mints a *different* DID and the first stays published
  with nobody holding a reference to it.

  The existing `trust_tasks::replay` layer cannot catch that. It keys on
  `(actor, envelope-id)` and every SDK path mints a fresh `urn:uuid:` per
  attempt, so a genuine retry sails past it. Its own module docs name this
  work as the deliberate follow-up.

  ## Built on the store that was already here



### Fixed

- **tee**: Bootstrap 410 and vsock enotconn ([#1003](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1003))

* fix(tee): retry transient ENOTCONN on first vsock config-overlay read

  tokio-vsock can report a stream connected just before Nitro finishes the
  nonblocking handshake, so the very first read on a fresh vsock:5800
  connection to the parent config server can return ENOTCONN even though
  the parent is listening and ready. Retry only that specific transient
  error kind with a short delay; any other I/O error still fails closed
  immediately, and the existing overall READ_TIMEOUT deadline still
  bounds the whole fetch.

  Adds positive (retries ENOTCONN then succeeds) and negative (does not
  retry PermissionDenied) unit tests against the inner read loop.



## [0.12.2](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-common-v0.12.1...vti-common-v0.12.2) — 2026-08-18


## [0.12.1](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-common-v0.12.0...vti-common-v0.12.1) — 2026-08-17


## [0.12.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-common-v0.11.41...vti-common-v0.12.0) — 2026-08-16


### Added

- **vta-vault**: Resolve mdoc issuers against configured IACA trust anchors ([#987](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/987))

Answers the one question mdoc asks differently from every other credential
  format here: which key do I trust to have issued this?

  Every other format names its issuer as a DID, so receiving resolves that DID
  and verifies against whatever comes back — the VTA holds no list and there is
  no operator step. An mdoc has no issuer DID. It carries an X.509 chain in the
  issuerAuth COSE unprotected header (x5chain, label 33): a Document Signer
  certificate issued by an IACA. Verifying it means the VTA must already hold the
  roots it accepts, which is a trust store, not a lookup.

  The decision taken is a configured set of IACA root certificates — how
  production EUDI verifiers work, and what Member State trusted lists (ETSI TS
  119 612) distribute. It keeps X.509 at the boundary: nothing below this module
  learns certificates exist, and receive_mdoc still takes a plain resolved key.

  Validation is scoped to what ISO 18013-5 Annex B actually specifies — a
  two-level IACA to Document Signer hierarchy, so no general RFC 5280 path
  building. Checks the leaf issuer DN against a configured anchor subject, the
  leaf signature against that anchor key, the leaf validity window, that the
  anchor is a CA (a DS certificate configured by mistake cannot become a root),
  and keyUsage.digitalSignature where present.

  Deliberately not checked, both documented in the module: revocation (CRL/OCSP
  needs egress and an unavailability policy — its own decision), and the ISO mDL
  EKU 1.0.18013.5.1.2, which the EUDI PID profile does not share, so enforcing it
  would reject valid PID credentials as what looks exactly like a trust failure.

  Fails closed. An empty anchor set is an error, not permissive — mdoc is the one
  format whose issuer is not a resolvable DID, so there is no safe default. The
  config field defaults to empty, so an existing config still loads and an upgrade
  neither breaks a deployment nor silently starts trusting mdocs.

  Anchors are inline PEM in [vault] rather than file paths: an enclave has no
  convenient filesystem, and inline values are covered by the effective-config
  digest boot attestation commits to, so a verifier can see which issuers a TEE
  VTA was trusting when it was attested.

  x509-parser takes the verify-aws feature rather than the default verify, which
  pulls ring — ring currently only reaches this workspace through a
  dev-dependency, while aws-lc-rs is already a real dependency. Same crypto, no
  new production tree.



## [0.11.41](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-common-v0.11.40...vti-common-v0.11.41) — 2026-08-16


## [0.11.40](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-common-v0.11.39...vti-common-v0.11.40) — 2026-08-14


## [0.11.39](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-common-v0.11.38...vti-common-v0.11.39) — 2026-08-12


## [0.11.38](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-common-v0.11.37...vti-common-v0.11.38) — 2026-08-12

