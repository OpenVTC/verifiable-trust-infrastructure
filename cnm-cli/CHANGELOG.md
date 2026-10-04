# Changelog

Notable changes to the published crates. Generated from conventional commits by
[git-cliff](https://git-cliff.org) when a release is cut — do not edit by hand.
## [0.27.1](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/cnm-cli-v0.27.0...cnm-cli-v0.27.1) — 2026-10-04


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



## [0.27.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/cnm-cli-v0.26.0...cnm-cli-v0.27.0) — 2026-10-04


### Added

- **vtc/git-ns**: PR-open gate — close pull requests from openers the policy does not allow ([#1937](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1937))

* feat(vtc/git-ns): PR-open gate — close pull requests from openers the policy does not allow

  The VTC side of git-ns/bridge/event 0.4 (pullRequestOpened) and
  git-ns/bridge/job 0.5 (closePullRequest), trustoverip/dtgwg-trust-tasks-tf#723,
  published in trust-tasks-rs 0.27.3 (now the workspace floor).

  - bridge/event 0.4 is served (and so listed in trust-task-discovery) beside
    0.1-0.3, which are read as 0.4; every earlier event kind is unchanged.
  - On pullRequestOpened for a repository recorded active in a bridge-mode
    namespace, the author (matched by forge + id through account links) is
    checked against the gitNamespace policy's new settings: pr_open
    ("anyone" default | members | committers | maintainers | {"roles": [...]}),
    pr_open_overrides (per namespace / repository), pr_exempt (default
    ["dependabot[bot]"]), pr_close_message and pr_join_hint. Owners and
    maintainers (explicit or implied), the bridge's app account and exempt
    logins are always allowed; unlinked accounts only under "anyone". A reopen
    by an owner, maintainer or the bridge is an override; anyone else's
    re-checks the author.
  - A disallowed pull request gets a queued closePullRequest job whose message
    renders only {author} (login), {repo}, {community} and {join_hint}.
  - Jobs go as 0.5 to a bridge that lists 0.5 and as 0.4 to a 0.4-only bridge;
    closePullRequest never goes to a bridge without 0.5, whose namespace's
    administrators are told once (gitNs.pullRequest.gateUnenforced).
  - Only closes are recorded: the job (activity gitNs.job.closePullRequest) and,
    on a succeeded close, the audit row gitNs.pullRequest.closed
    {number, author login, level}. bridge/job/list 0.1 omits closePullRequest
    jobs, whose kind its JobKind enum does not yet name.

  Hygiene, not the merge gate: the required commit-trust check is unchanged and
  the gate fails open.

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

- **vtc**: Live admin console — a hint-only event stream over HTTPS (binding 0.3 streamed responses) ([#1932](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1932))

* feat(vtc): live admin console — a hint-only event stream over HTTPS (binding 0.3 streamed responses)

  An open admin console now holds one live channel per session:
  `vtc/admin/events/subscribe/0.1` POSTed as a signed document to the ordinary
  `/v1/trust-tasks` door with `Accept: text/event-stream, application/json;q=0.5`,
  answered as an HTTPS binding 0.3 §2.1 streamed response — the signed
  `#response` as the first SSE event, `vtc/admin/events/event/0.1` hints after it
  (one document per `data:` line, no `event:` field, SSE `id` = resume token,
  heartbeats as comments). No new route; every other task is unchanged.

  Hints only: `topic`, `at`, `resumeToken`, and `count` on actions /
  acknowledgements / joinRequests. Never a record, an id or a DID. The console
  reacts only by re-reading the topic's own signed read, so authorization stays
  on every read.

  VTC (`vtc-service/src/admin_events`, `trust_tasks/event_tasks.rs`):
  - a process-wide broadcast bus fed from the storage seams (action save/delete,
    join-request store/delete, member store/delete, ACL store/delete, config
    overrides, community profile); no row data travels on it;
  - effective topics = requested ∩ readable (joinRequests needs vtc.join.decide,
    config needs vtc.config.admin); standing re-checked on every ACL change,
    before every hint and once a heartbeat — a shrink ends the stream;
  - per-recipient digests so a change the caller's read would not show sends no
    hint; at most one hint per topic per second;
  - refusals stay JSON and open no stream (notAdministrator, streamUnavailable,
    tooManyStreams, permissionDenied, malformedRequest for a Last-Event-ID that
    disagrees with `since`); 5-minute issuedAt window; a replayed subscribe
    answers 204 (its response is never recorded for redelivery);
  - resume tokens are MAC'd, per-caller masked positions under a per-process
    key; unknown/foreign/expired `since` → `resumed: false`, never an error;
    in-memory history 10 min / 4096 changes;
  - the stream ends with the client, at shutdown, when the signer's ACL entry,
    console-key delegation or document expiresAt lapses, after an hour, or on a
    write stalled for 2× heartbeat; never a trust-task-error after the response;
  - caps: 5 concurrent streams per administrator, 256 in all;
  - hints are signed with the VTC key (proof RECOMMENDED);
  - no lock held across an await (R1.3).

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

- **vtc**: Trust-tasks 0.27 — cooling-off actions, the reduction-pending notice, offline-write records, and approver-device approvals ([#1922](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1922))

trust-tasks-rs 0.27.1 (trust-tasks-tf #719) specifies what the action list's
  A2 phase had to express by workaround. This adopts it.

  - trust-tasks-rs and its sibling crates move to 0.27.1, in lockstep with the
    TDK release built on it: affinidi-tdk 0.23, affinidi-messaging-sdk 0.33,
    affinidi-messaging-test-mediator 0.18 (mediator 0.37), and
    affinidi-messaging-mediator-{admin,tui} 0.8. The graph holds one
    trust-tasks-rs (and one trust-tasks-proof), so the mediator `MediatorAcl` is
    one type and no bridge is needed. 0.27.0's typed git-ns
    `ActivityItem.source` needed no change: the VTC builds that response from
    JSON, and its wire is unchanged.
  - `vtc/admin/actions/{list,show,cancel,acknowledge}/0.2` are served beside 0.1.
    At 0.2 a cooling-off (VTI-APV-019) is category `coolingOff` with `landsAt`
    and `cancellableBy: requester`, no threshold, expiry or approvers remaining,
    closes `landedAfterCoolingOff`, and its subject sees it as `callerRole:
    subject` in `all` and `history`, never `waitingForMe`. 0.1 keeps answering
    as before (`ext["org.openvtc"].coolingOff`, `thresholdMet`). A parked
    operation's next step expects show/0.2. vtc-client, cnm and the console use
    0.2; cnm and the console count down to `landsAt`.
  - A reduction parked for its cooling-off sends the subject
    `vtc/members/authority-reduction-pending-notice/0.1` (durable push). The
    landing still sends the authority-reduced notice (`unopposed`); a cancelled
    one reduces and sends nothing more. Landing never waits on delivery.
  - An operator's offline write (VTI-VTC-023), the emergency bootstrap
    included, is raised with `typeUri` the record type
    `vtc/operator/offline-write/0.1` and the record `{command, dids, host, at}`
    as payload, replacing the URN placeholder and four per-command templates
    with one pinned template. The emergency marker now records the recovery DID
    and the administrators it wiped. A document of the record type answers
    `unsupportedType`; the manifest census lists it as embedded-only.
  - The console approves with the admin's approver device through the plugin's
    `approveDecision` (vta-browser-plugin #293): the device signs a
    decision-purpose statement over the per-approver salted wire digest, and
    the wallet signs `task-consent/decision/0.2` carrying it as `approverSigned`
    evidence. Precedence: approver device, passkey, wallet signature alone,
    then the `cnm consent approve` guidance.
  - A crash between a `policy/upsert` revision write and its effect marker was
    reconciled `failed` although the revision existed, because the upsert moves
    no state pin (CLAUDE.md R2.1). An executing action's revision is now stored
    under an id derived from the action and execution
    (`admin_actions::policy_revision_id`), so the row is its own evidence.

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

- **cnm**: Setup onboards the personal VTA the way pnm does — self-minted key, grant, rotate ([#1923](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1923))

`cnm setup` used to require a sealed bundle from an administrator before cnm
  could touch the personal VTA. It now follows pnm's admin cold start: mint an
  ephemeral did:key, park it, print the grant routes (`vta import-did`,
  `admin_did` in setup.toml, `pnm acl create`), and on
  `cnm setup continue [<name>] [--vta-did <did>] [--vta-url <url>]` authenticate,
  which rotates to a fresh did:key over `acl/swap-key` and removes the temp DID's
  entry. A continue before the grant prints the routes and stays resumable.
  Non-interactive mode mirrors pnm ([#1753](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1753)): `cnm setup --name <name>
  [--overwrite]` and `continue --vta-did` each print one `{slug, admin_did,
  state}` line.

  Alternatives in the wizard:
  - "Bootstrap from your existing pnm session" when a pnm profile on this
    machine ($PNM_HOME honoured) is bound to the same VTA DID. pnm's config and
    session store are read only; pnm's key authenticates in memory once, over
    REST (so no mediator socket is taken from a running pnm), to grant cnm's
    own freshly minted key, which then rotates as above. The grant is an
    unrestricted admin: cnm creates a top-level context per community on the
    personal VTA, which the VTA gates on super-admin.
  - "I have a sealed bundle from an admin" — unchanged, digest pinned.

  Communities now get an admin identity each, so one operator's communities
  share no key. `cnm community add <name> [--vtc-did] [--vta-did] [--slug]
  [--overwrite]` mints a did:key for that community, parks it in
  `pending_communities` (not selectable by --community or as default until
  confirmed), and prints the VTC grant routes: `co_admin_did` in vtc setup,
  `vtc acl add` offline, or an existing admin's `cnm access grant` / console,
  noting the second-administrator approval an online unrestricted grant waits
  for. `cnm community continue <slug> [--vtc-did] [--vta-did]` confirms with a
  DI-signed authenticate to the VTC (VTC audience) before promoting the
  profile. The VTC has no key-rotation task (no acl/swap-key; a successor admin
  entry is itself an unrestricted grant needing a second admin's consent,
  VTI-APV-014), so the minted key is kept rather than a rotation invented.
  Reusing another community's key takes `--reuse-identity <community>` (or an
  explicit, warned choice in the wizard). `cnm community list` shows each
  community's identity and the pending ones; `delete` drops a pending one.
  Holding a community identity as a persona on the personal VTA is a follow-up.

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

- **cnm**: The community grant hint names the --admin-role flag that exists ([#1934](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1934))

`cnm community add` printed `cnm access grant <did> --role admin` for an
  existing administrator to run, but `cnm access grant` takes
  `--admin-role <role>` (role-based administration, #1924); `--role` does
  not exist, so the printed command failed. It now prints
  `--admin-role community-admin`, and the console hint names the admin role.



## [0.26.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/cnm-cli-v0.25.1...cnm-cli-v0.26.0) — 2026-10-02


## [0.25.1](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/cnm-cli-v0.25.0...cnm-cli-v0.25.1) — 2026-10-02


## [0.25.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/cnm-cli-v0.24.0...cnm-cli-v0.25.0) — 2026-10-02


## [0.24.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/cnm-cli-v0.23.0...cnm-cli-v0.24.0) — 2026-10-01


## [0.23.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/cnm-cli-v0.22.0...cnm-cli-v0.23.0) — 2026-10-01


## [0.22.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/cnm-cli-v0.21.0...cnm-cli-v0.22.0) — 2026-10-01


### Added

- **vtc**: Bind the community's own check to a uniqueness pseudonym server-side ([#1876](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1876))

A community enforcing `personhood.singleMembership` could not satisfy it with
  its own `vetted/1` identity check, because the statement has no member for a
  pseudonym. The binding now happens server-side, at issue.

  - `vtc/endorsements/issue/0.1` under `vetted/1` reads the payload extension
    `ext["org.openvtc.uniqueness"] = { "pseudonym": "<value>" }`. It is never
    written into the credential. The pseudonym is bound to the subject in the
    existing pseudonym store (`members::pseudonym::claim_for_statement`), which
    stores only the community-scoped salted digest. The claim row is tagged
    with the statement's endorsement id. The binding is made before anything is
    minted, and released again if minting fails.
  - A pseudonym already bound to another member refuses the issue with
    `AppError::Conflict`: `taskFailed` with `details.reason` `conflict`, the
    same collision semantics personhood assert already has. Nothing is minted.
    No declared `endorsements/issue` code fits a duplicate person, and
    `claimSchemaViolation` would tell the caller to fix a claim that is valid.
  - The extension is read only under `vetted/1`, and only as
    `{ "pseudonym": "<non-empty string>" }`. Anything else is
    `malformedRequest`.
  - At personhood assert under `singleMembership`, the community's own
    `vetted/1` statement about the member satisfies uniqueness only when the
    community holds a binding for that member DID (`pseudonym::is_bound`).
    Credentials from an accepted IDVP still use `credentialSubject.pseudonym`.
  - `vtc/endorsements/revoke/0.1` on a `vetted/1` row releases the binding it
    made (`pseudonym::release_for_statement`). A binding an outside provider's
    credential made is untagged and is kept. Purge still releases every binding
    of the member.
  - vtc-client gains `issue_endorsement_with_ext` (additive).
    `cnm member endorse` gains `--uniqueness-pseudonym`.

- Record the community's own identity check as a vetted/1 statement ([#1874](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1874))

* feat(vta-sdk)!: vetted/1 vetter-only members are optional and all-or-nothing

  Registry `vetted/1` (trustoverip/dtgwg-vsc-registry#24) admits the community
  itself as issuer of a statement recording its own identity check. Such a
  statement carries none of the three vetter-only members; a vetter's statement
  carries all three. The schema makes them all-or-nothing (`dependentRequired`).



### Fixed

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



## [0.21.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/cnm-cli-v0.20.0...cnm-cli-v0.21.0) — 2026-09-30


### Added

- **vta-service**: Retire superseded REST routes; pre-session auth moves to Trust Tasks ([#1858](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1858))

* feat(vta-service)!: retire superseded REST routes; auth family moves to Trust Tasks

  Deletes the ~56 REST routes `deprecation::SUPERSEDED` marked as superseded
  by a Trust Task (acl, audit, config, contexts, did_templates, keys, webvh
  servers/dids, POST /vta/restart, the /api/trust-tasks alt spelling) and the
  always-403 POST /attestation/mnemonic stub. The REST-route half of
  `deprecation.rs` (the SUPERSEDED table, mark_superseded middleware) is
  removed now that it's empty; the unrelated SUPERSEDED_TASKS (Trust-Task URI
  supersession) table is untouched.

  Pre-session auth (auth/challenge/0.1, auth/authenticate/{0.2,0.3},
  auth/refresh/0.2) moves onto `/trust-tasks`, dispatched by a new
  family-owned bypass (`trust_tasks::auth::owns`/`dispatch_pre_session`) that
  runs ahead of the ACL-gated pipeline on all three transports (REST,
  DIDComm, TSP) — mirroring affinidi-webvh-service's `trust_tasks_auth`
  pattern. The document's own proof (required on authenticate, absent on
  challenge/refresh) is the whole of the authority these four carry, so
  there is no session and no ACL pre-filter to apply. authenticate/refresh
  0.1 are retired outright (this is a test deployment); 0.2/0.3 add
  sessionKey and delegation fields this VTA declines with a typed refusal
  rather than silently ignoring.

  Kept as tested REST_EXCEPTIONS: POST /bootstrap/request, GET+POST
  /backup/blob/{bundle_id}, GET /openapi.json, GET /attestation/mnemonic,
  GET /metrics.

  Client-side (vta-sdk, vta-mobile-core) callers move onto the Trust-Task
  form; cnm-cli/pnm-cli/vta-mcp needed no changes (already Trust-Task only).

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



## [0.20.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/cnm-cli-v0.19.3...cnm-cli-v0.20.0) — 2026-09-30


### Added

- **vtc**: Member verbs served as signed Trust Tasks — callers wired, REST retired ([#1845](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1845))

* feat(vtc-client): member verbs — renew, rotate, personhood, relationships, endorsement issue

  Adds signed-door client methods for the batch-1 member-facing verbs
  vtc-service already dispatches on the spine (trust_tasks::member_tasks,
  #1809): renew, rotate-challenge/rotate, personhood/revoke,
  relationships/{list,publish,revoke}, and endorsements/issue. Every call
  rides POST /trust-tasks, matching the pattern vtc-client already uses for
  its other admin verbs.

- **vtc-client**: Every VTC call is a signed Trust Task ([#1840](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1840))

* feat(vtc-client)!: every VTC call is a signed Trust Task

- **vta**: Clear a context's DID with vta/contexts/update-did/1.1 ([#1828](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1828))

* feat(vta): clear a context's DID with vta/contexts/update-did/1.1

  Once a context had a DID it could be replaced but never removed:
  update-did/1.0 requires a non-empty `did`, and contexts/update only sets
  one. `webvh/dids/delete` refuses a DID a context still acts as and says
  "reassign it first", so a context's last DID could not be retired short
  of assigning another the operator did not want.

  Serve update-did/1.1 (trust-tasks `feat(vta/contexts/update-did): 1.1`)
  beside 1.0 through one handler. `did: null` clears — the record comes
  back with `did` absent, and clearing a context with no DID succeeds. A
  string `did` must be a DID; 1.1 is parsed into the generated
  `update_did::v1_1::Payload`, whose `PayloadDid` holds the pattern, and
  1.0 keeps its original body. 1.0 is listed as superseded by 1.1, and the
  legacy `PUT /contexts/{id}/did` now names 1.1 as its successor.

  - vta-sdk: `TASK_CONTEXTS_UPDATE_DID_1_1` (retry-safe);
    `update_context_did` sends 1.1; new `clear_context_did`.
  - pnm / cnm: `contexts update-did <id> --clear`, and
    `contexts update <id> --clear-did` (conflicts with `--did`), both on
    update-did so a context admin can do it.
  - The delete blocker offers both fixes and names update-did rather than
    contexts/update (super-admin only); its text also carried a run of
    literal spaces from an unjoined line wrap.

  Needs a trust-tasks-rs release carrying update_did::v1_1; see the TODO
  on the floor in Cargo.toml.



### Fixed

- **cnm-cli**: Send consent decisions over the resolved transport ([#1847](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1847))

cnm consent approve/deny authenticated to the VTC with a bearer-token
  REST session (vtc::connect), unlike every other signed Trust Task verb.
  Route it through vtc::connect_for_tasks instead, so a decision goes
  over TSP or DIDComm when the VTC advertises it, falling back to a
  signed document over HTTPS only when it doesn't (--transport pins one,
  same as cnm access/member/git/audit/did-log).



## [0.19.3](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/cnm-cli-v0.19.2...cnm-cli-v0.19.3) — 2026-09-28


## [0.19.2](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/cnm-cli-v0.19.1...cnm-cli-v0.19.2) — 2026-09-28


## [0.19.1](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/cnm-cli-v0.19.0...cnm-cli-v0.19.1) — 2026-09-27


## [0.19.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/cnm-cli-v0.18.0...cnm-cli-v0.19.0) — 2026-09-27


### Added

- **vtc-service**: Git-ns administrator reads as signed Trust Tasks ([#1781](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1781))

* feat(cnm,vtc-client): send cnm git Trust Tasks over TSP, DIDComm or HTTPS

  Every signed `cnm git` command now reaches the VTC over TSP when it
  advertises it, else DIDComm, else as a signed document over HTTPS, through
  one shared connect helper (`vtc::connect_for_tasks`, which `cnm backup`'s
  end-to-end connect now also uses). The global `--transport` flag pins a
  transport; the session is closed on every path out.

  vtc-client's git-ns calls go over the session when the client holds one.
  The document is signed and bound to its sender the same way on every
  transport: over a session the key must be the session's own DID, and a key
  naming another DID is refused before anything is sent. A session refusal
  comes back as `VtcError::Refused` carrying the trust-task-error document,
  so `task_error` and `step_up_request` read the code and details alike on
  every transport (VTI-OPS-021/093).

  vta-sdk gains `VtaClient::dispatch_trust_task_document`, which answers the
  whole reply document (refusals included) rather than its payload.

  The admin listings (namespace list, repos, view --admin, break-glass-list)
  are console projections with no git-ns Trust Task and stay HTTPS admin reads.

- **cnm**: Send cnm access Trust Tasks over TSP, DIDComm or HTTPS ([#1780](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1780))

* feat(cnm,vtc-client): send cnm git Trust Tasks over TSP, DIDComm or HTTPS

  Every signed `cnm git` command now reaches the VTC over TSP when it
  advertises it, else DIDComm, else as a signed document over HTTPS, through
  one shared connect helper (`vtc::connect_for_tasks`, which `cnm backup`'s
  end-to-end connect now also uses). The global `--transport` flag pins a
  transport; the session is closed on every path out.

  vtc-client's git-ns calls go over the session when the client holds one.
  The document is signed and bound to its sender the same way on every
  transport: over a session the key must be the session's own DID, and a key
  naming another DID is refused before anything is sent. A session refusal
  comes back as `VtcError::Refused` carrying the trust-task-error document,
  so `task_error` and `step_up_request` read the code and details alike on
  every transport (VTI-OPS-021/093).

  vta-sdk gains `VtaClient::dispatch_trust_task_document`, which answers the
  whole reply document (refusals included) rather than its payload.

  The admin listings (namespace list, repos, view --admin, break-glass-list)
  are console projections with no git-ns Trust Task and stay HTTPS admin reads.

- **cnm,vtc-client**: Send cnm git Trust Tasks over TSP, DIDComm or HTTPS ([#1778](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1778))

Every signed `cnm git` command now reaches the VTC over TSP when it
  advertises it, else DIDComm, else as a signed document over HTTPS, through
  one shared connect helper (`vtc::connect_for_tasks`, which `cnm backup`'s
  end-to-end connect now also uses). The global `--transport` flag pins a
  transport; the session is closed on every path out.

  vtc-client's git-ns calls go over the session when the client holds one.
  The document is signed and bound to its sender the same way on every
  transport: over a session the key must be the session's own DID, and a key
  naming another DID is refused before anything is sent. A session refusal
  comes back as `VtcError::Refused` carrying the trust-task-error document,
  so `task_error` and `step_up_request` read the code and details alike on
  every transport (VTI-OPS-021/093).

  vta-sdk gains `VtaClient::dispatch_trust_task_document`, which answers the
  whole reply document (refusals included) rather than its payload.

  The admin listings (namespace list, repos, view --admin, break-glass-list)
  are console projections with no git-ns Trust Task and stay HTTPS admin reads.

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

- **vtc**: Serve acl/{show,list,update,revoke} as Trust Tasks on the spine ([#1772](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1772))

* feat(vtc)!: serve acl/{show,list,update,revoke} as Trust Tasks on the spine

  The VTC served only acl/grant and acl/change-role as signed Trust Tasks;
  reading an entry, listing the ACL and revoking one existed only as bearer
  REST routes, so the VTI-ACL-050 full-cover check on revoke lived on one
  door and a community could not take authority away over TSP or DIDComm.

  Server (vtc-service)
  - acl/show, acl/list, acl/update and acl/revoke are dispatched by the
    spine (trust_tasks/acl_tasks.rs). Authority is the verified signer's ACL
    row at execution time; payloads are validated against the generated
    trust-tasks-rs schemas.
  - One code path: routes::acl::{list_entries, show_entry, revoke_entry,
    plan_update} are the operations; GET /v1/acl, GET and DELETE
    /v1/acl/{did} are thin adapters over them.
  - acl/update is planned by plan_grant with the role held fixed, so it
    inherits VTI-ACL-052 (no self-modification), VTI-ACL-050 (full cover)
    and VTI-ACL-053 (bounded by the granter). It refuses a missing entry
    (acl/update:notFound), a narrowing (acl/update:narrowingNotPermitted),
    a role (acl/update:roleChangeNotPermitted), and the VTA-only members
    allowedKeys/approve/stepUp. Widening an admin needs the bound passkey
    gesture, and community-wide authority another admin's consent, through
    the same gate acl/grant uses (settle_signed_gate).
  - acl/revoke emits acl/revoke:subjectNotPresent and
    acl/revoke:lastAuthorityProtected, and now revokes the subject's live
    sessions on a full removal too.
  - acl/list gains `direction` (acting-in, subtree, any).
  - acl/grant: restating an admin with a later or no expiry now counts as
    widening (needs the gesture); a rewrite that reduces authority revokes
    the subject's sessions; the audit row names the actual actor rather
    than the entry's original creator, and an update is audited as
    AclUpdated.



### Fixed

- **vtc-service**: A community backup travels only over DIDComm or TSP ([#1755](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1755))

* fix(vtc-service)!: a community backup travels only over DIDComm or TSP

  The backup request carries its password, and the backup carries the
  community's signing key bundle. Over REST both exist in plaintext wherever
  TLS terminates.

  - POST /v1/backup/export and /v1/backup/import always answer 403.
  - vtc/backup/export and backup/initiate-export, initiate-import and
    finalize-import are refused on the REST binding, after the super-admin
    check and before any state is serialized, a slot is opened or the
    password is used. The chunks are ciphertext and are unaffected.
  - The export audit row is still written before the envelope is returned,
    and a VTC with no audit trail now refuses to export instead of releasing
    the backup unrecorded.
  - vtc-client export_backup and import_backup use the backup/* chunked
    transfer over a DIDComm or TSP session, verifying every chunk and the
    whole, and refuse without a session.
  - cnm backup connects to the VTC over TSP, or DIDComm when the VTC
    advertises no TSP, and has no REST fallback.

  Implements trustoverip/dtgwg-trust-tasks-tf#646.



## [0.18.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/cnm-cli-v0.17.6...cnm-cli-v0.18.0) — 2026-09-26


### Added

- **vtc**: Git-ns/account/unlink and cnm git unlink ([#1746](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1746))

* fix(vtc): one forge account per member, and only current members' accounts count

  - Link uniqueness (git-ns/account/link item 4) was already enforced under
    the git-ns store lock. The check and the recording are now one step
    under the member-row lock too, and a regression test pins it: a
    second member completing a link to an already-linked forge id ends
    `failed` and the account stays with the first.
  - A departed member who held no git right kept their linked accounts for
    good: the link deletion sat after sweep_departures' early return for
    "no departed member held a right". It is now its own pass in the
    lifecycle sweep (git-ns/account/link, Consent/purpose: MUST delete it
    when the member leaves).
  - linked_accounts, which the role projection and drift adoption read,
    now holds only current members' accounts. A member whose access lapsed
    but who has not left keeps the account, so nobody else can link it,
    but it projects no role.
  - GET /v1/git-ns/accounts gains memberCurrent, and the console's Repos
    plugin no longer offers adoption for an account whose member is not
    current. The daemon already refused that adoption.

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

- **git-ns**: An adoption names the member who receives the right ([#1735](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1735))

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

- **vtc-service**: Re-project git roles, and use the bridge's reported role map ([#1736](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1736))

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



## [0.17.6](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/cnm-cli-v0.17.5...cnm-cli-v0.17.6) — 2026-09-26


### Added

- **vtc/git-ns**: A namespace admin gets no forge role; bridge jobs are git-ns/bridge/job 0.4 ([#1729](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1729))

* fix(vtc/git-ns): a namespace admin gets no forge role

  Role projection counted what git.ns.admin implies, so every namespace
  admin went to the bridge as git.repo.own on every repository, and the
  namespace-level projectRoles job listed them as organisation owners,
  which the bridge always refused notCapable.

  desiredRoles now carries, per person, the highest right recorded in their
  own name: own, maintain or commit.sign on the repository, or commit.sign
  on its namespace. A namespace admin with none of those is sent as
  git.ns.admin, which the bridge maps to no role, so a stale role it manages
  is taken off instead of left in place. An admin who is also an explicit
  owner is still sent as the owner. The namespace-level job is no longer
  sent, and a reseat no longer queues it.

  Drift follows: a roleChanged adoption compares against the projected
  right rather than the implied one, so a namespace admin's forge admin role
  can be adopted as own; and reverting a roleAdded role held by an admin
  with no right of their own drops them from desiredRoles and names them in
  removeAccounts only.

  The admin console's grant and reseat previews no longer say an ns.admin
  is projected onto the forge.

- **pnm**: Answer this VTA's consent requests from the CLI ([#1761](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1761))

A task under a `requires: consent` rule waits for its approver set, and only
  a device enrolled for the task-consent push could answer. `pnm` showed the
  requester the code and waited.

  `pnm consent {show,approve,deny} <file|->` is the approver's side. It takes
  the refusal the requester relays (the body, its `details`, or a bare request
  document) and picks the request addressed to this profile. It checks that
  this VTA signed it, that it is addressed to this approver and that it has
  not expired. Approving requires typing the requester's match code, or
  `--match-code`. The decision is dispatched as a Trust Task, which the client
  signs with the profile's key under assertionMethod.

  The operator-facing half is now shared with `cnm consent`: reading the
  input, what is shown, the code comparison, the report and the refusal
  hints, all in `vta_cli_common::consent_approve`. `cnm consent` moves onto
  it, keeping its VTC-specific hint for `permissionDenied`.

  Tested end to end in `delegated_consent_e2e`: a real VTA-signed request
  verifies through `vta_sdk::task_consent`. It is refused when it is
  addressed to someone else or has been tampered with, and the decision
  built from it is granted.

- **cnm**: Answer the community's consent requests from the CLI (VTI-APV-014) ([#1759](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1759))

Making or widening an unrestricted administrator at the VTC needs another
  unrestricted administrator's consent (VTI-APV-014), but only a device
  enrolled to handle the task-consent push could answer. An approver with a
  cnm profile had no way to sign a decision.

  `cnm consent {show,approve,deny} <file|->` takes the request the
  requester relays (the refusal body, its `details`, or a bare request
  document), picks the one addressed to this profile, and verifies it. The
  VTC must have signed it, it must be addressed to this approver, and it
  must not have expired. Approving requires typing the requester's match
  code (or `--match-code`); a mismatch sends nothing. The decision is
  signed with the profile's key under assertionMethod and posted to the
  document endpoint.

  The approver's shared half is a new `vta_sdk::task_consent` module:
  `match_code`, `ConsentRequest::verify` returning a
  `VerifiedConsentRequest` (the only type a decision can be built from),
  and `decision`. `vtc-client` gains `decide_task_consent`.

  It also fixes a mismatch between the two screens: the requester prompt
  in `vta_cli_common::consent` printed the whole `zQm…` digest as the
  "code", while approver devices show six hex characters of the decoded
  digest. Both now call `vta_sdk::task_consent::match_code`, and so does
  `vta-mobile-core`, which drops its copy.

  Tested end to end in `unrestricted_admin_consent`: a real VTC-signed
  request verifies through the SDK, is refused when it is addressed to
  someone else, comes from another issuer, or has been tampered with, and
  the decision built from it grants the consent.

- **cnm-cli**: Cnm git link — link a forge account to the profile's DID ([#1726](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1726))

* feat(cnm-cli): cnm git link — link a forge account to the profile's DID

  A member had no CLI way to link their forge account, so the bridge could
  never give them the forge role their git rights call for.

  `cnm git link --forge <host>` sends git-ns/account/link/0.1 signed as the
  community profile's DID, prints where to authorise (and GitHub's device
  code), then polls git-ns/account/link-status/0.1 every five seconds, as
  the specification asks, until the link is linked, expired or failed.
  `--status <linkId>` follows a link begun earlier, `--no-wait` returns
  after printing, and `--list` shows the accounts linked to this DID from
  git-ns/view/0.2's `accounts`. Refusals (`unsupportedForge`,
  `unknownLink`, a non-member) print the fix.

  vtc-client gains `git_ns_link_status`. There is no unlink: the
  specification defines no task for it, and linking again replaces the
  account on that forge.

- **vtc-service**: Git-ns drift/resolve, namespace/reseat, view 0.2 ([#1703](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1703))

* feat(vtc-service): git-ns drift/resolve, namespace/reseat, view 0.2

  Implements the git-ns tasks added in trust-tasks #625 and #627, on
  trust-tasks-rs 0.22.5.

  - git-ns/drift/resolve 0.1: an owner adopts a forge-side role as the
    git-ns/right/grant it is (same fixed rules, policy, consent class), or
    reverts a forge-side change through the bridge. Items are selected by
    type, account (role items) and observed (required to adopt). Every
    declared code: driftNotFound, notAdoptable, accountNotLinked,
    noMatchingRight, notRevertible, plus the family's codes.
  - git-ns/bridge/job 0.2: sent only for the revert of a roleAdded item
    (projectRoles with removeAccounts), in-line, so a bridge implementing
    only 0.1 is answered notRevertible; every other job stays 0.1.
  - git-ns/namespace/reseat 0.1: a community administrator grants a
    permanent git.ns.admin on a headless namespace to a current member,
    atomically with the headless check; notHeadless otherwise. The audit
    record keeps the statement and how earlier admin records ended.
  - git-ns/view 0.2 (served beside 0.1): the caller's own linked forge
    accounts, narrowed to the resource's forge.
  - git-ns/bridge/event 0.2 (served beside 0.1, same handler): a transfer
    detaches wherever it goes; an event any of whose resources, drift items
    included, lies outside its namespace is refused before anything is
    applied.
  - cnm: `cnm git drift resolve`, `cnm git reseat`; `cnm git view` asks for
    view 0.2. vtc-client gains the matching methods.
  - Default gitNamespace policy: namespace.reseat receives a right;
    drift.revert documented.



### Fixed

- **vtc-admin-ui,cnm-cli**: Shell quoting that is safe in fish, and reseat follow-ups ([#1723](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1723))

shellQuote (admin console) and shell_word (cnm) used POSIX '...'\''...'
  quoting. fish reads \' and \\ as escapes even inside single quotes, so a
  value such as  x\' ; echo INJECTED ; echo \  pasted into fish ran
  `echo INJECTED`. Both now single-quote runs without ' or \ and write each
  ' as "'" and each \ as "\\", which read back byte-exact in sh, bash, zsh
  and fish. A bare word may no longer start with = (zsh's =cmd expansion) or
  % (fish's %self), nor, in cnm, with -.

  Tests run the generated words through sh, bash and, where installed, zsh
  and fish, and assert every hostile value comes back byte-exact.

- **vtc-service**: Git-ns review follow-ups — adopt policy input, legacy revoke, reseat evidence ([#1714](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1714))

Follow-ups from the review of #1703.

  - The policy sees an adopted drift item as `right.grant` with
    `via: "drift.adopt"` (git-ns/drift/resolve, step 6), so a community can
    refuse every adoption and still grant. Default policy comment and docs
    say so.
  - right/revoke still accepts a subject that is not a DID-core DID when a
    recorded right names it — one granted before DID-core was enforced —
    so no right is left that nobody can take away. Grant, transfer, adopt
    and reseat still refuse one.
  - A reseat's evidence comes from the audit log: each earlier git.ns.admin
    record revoked (by whom, why — a revoke now records its reason),
    lapsed (when) or removed on departure (when), plus records not yet
    swept; holders are not named. The subject's own lapsed admin record is
    replaced rather than kept beside the new one.
  - drift/resolve adopt re-checks its item (observed value included) under
    the store lock the grant is written under; a changed item adopts
    nothing.
  - Two string literals that had lost their line continuation (the
    notHeadless message, cnm's --observed error) are fixed.
  - cnm sanitises the VTC's error code as well as its message; the
    notAdoptable hint for a lowering names revoke; the notRevertible hint
    covers manual mode and accounts the projection holds.



## [0.17.5](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/cnm-cli-v0.17.4...cnm-cli-v0.17.5) — 2026-09-24


## [0.17.4](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/cnm-cli-v0.17.3...cnm-cli-v0.17.4) — 2026-09-23


## [0.17.3](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/cnm-cli-v0.17.2...cnm-cli-v0.17.3) — 2026-09-23


## [0.17.2](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/cnm-cli-v0.17.1...cnm-cli-v0.17.2) — 2026-09-22


## [0.17.1](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/cnm-cli-v0.17.0...cnm-cli-v0.17.1) — 2026-09-22


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



### Fixed

- **cnm**: Vetting, audit and backup authenticate to a VTC with its own DID as audience ([#1637](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1637))

`cnm vetting`, `cnm audit verify` and `cnm backup` could not sign in to a
  VTC. All three took a token from `SessionStore::ensure_authenticated`, whose
  audience is not a parameter: it is always the session's bound *VTA* DID, and
  the DIDComm authenticate envelope it builds is encrypted to that DID's
  key-agreement key. A VTC holds only its own keys, cannot open the envelope,
  and refuses the login. `cnm vetting` then also built its `VtcClient` with the
  VTA's DID as the community's DID. main connected to the VTA first, so without
  `--url` the requests went to the VTA's REST URL too.

  They now authenticate the way `cnm did-log install` does ([#1632](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1632)):
  `VtcClient::connect(base, vtc_did, client_did, key)` with the profile's DID
  and key, and the VTC's DID as the audience. They are exempt from
  `requires_auth`, so no VTA connection is made first.

  Where the VTC's DID comes from: `--vtc-did` (env `CNM_VTC_DID`), else a new
  optional `vtc_did` on the community profile, set with
  `cnm community set-vtc <did>`. The DID is never read from the server (for
  example the VTC's `/health`): it is the audience the sign-in is signed for,
  and a server allowed to name it could name another community's DID and
  relay the signed document there. Discovery runs from DID to URL, as it does
  for a VTA: `--url` if given, otherwise the `VTCRest` service in the DID's
  document, matched on `type` and checked by the same endpoint guard as a
  VTA's advertised REST URL.

  The root cause is a generic "token for this base URL" helper sitting on a
  session bound to one audience. `cnm`'s `auth::ensure_authenticated` wrapper
  is removed, so nothing in `cnm` can reach the VTC through the VTA session
  again, and `SessionStore::ensure_authenticated` now documents that it
  authenticates to the session's VTA only. Nothing else in the workspace
  used `SessionStore` against a VTC.

  When the VTC refuses the sign-in, `cnm` prints the fix with the DID filled
  in: `vtc --config <config.toml> acl add --did <DID> --role admin --label cnm`,
  or Access control, Add entry in the console. A VTC answers every
  authentication failure the same way (VTI-SES-007), so the message names the
  usual cause rather than claiming it.

  Routing these through a live VTC exposed two more faults on the same paths,
  fixed here:
  - `cnm backup export` saved the `{ envelope }` response (the export shape
    since #1059) instead of the envelope, so the file printed `(none)` for
    its source DID and could not be imported. `VtcClient::export_backup`
    returns the envelope, and accepts a pre-#1059 bare one.
  - `cnm audit verify` read the signed-checkpoint result from the top level,
    but #1110 moved it under `ext["org.openvtc"]`. Every report therefore
    looked like it had no checkpoint result, and a truncated log that the
    community key contradicts passed as long as its hash chain did. It reads
    both places now, and fails on any checkpoint status it does not know
    rather than passing it.

  vtc-client gains `audit_verify`, `export_backup`, `import_backup`,
  `REST_SERVICE_TYPE` and `api_base_from_did_document`, plus the three task
  URIs. All are additive.



## [0.17.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/cnm-cli-v0.16.8...cnm-cli-v0.17.0) — 2026-09-21


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



## [0.16.8](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/cnm-cli-v0.16.7...cnm-cli-v0.16.8) — 2026-09-21


## [0.16.7](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/cnm-cli-v0.16.6...cnm-cli-v0.16.7) — 2026-09-21


## [0.16.6](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/cnm-cli-v0.16.5...cnm-cli-v0.16.6) — 2026-09-20


### Fixed

- **resolver**: Take the shared DID resolver instead of building one ([#1581](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1581))

* fix(resolver): take the shared DID resolver instead of building one

  Twelve call sites across `vta-service`, `cnm-cli` and `vtc-service` each
  constructed their own `DIDCacheClient`. A client owns its cache, so the
  same DID was fetched once per construction rather than once per process,
  and a `did:webvh` host saw a burst of requests for what is one logical
  operation — enough to earn a 429 from its own rate limiter.

  Every one of them built
  `DIDCacheConfigBuilder::default().with_host_policy(webvh_host_policy())`,
  which is byte-for-byte what `build_did_cache_config(None)` produces, so
  taking `shared_did_resolver_from_env()` preserves behaviour and collapses
  twelve caches into the one the SDK already keeps per runtime, sidecar URL
  and host policy.

  It also fixes a second problem those sites had: by calling
  `DIDCacheClient::new` directly they never read `PNM_RESOLVER_URL`, so an
  operator who had configured a resolver sidecar — the documented mitigation
  for exactly this load — did not get it on any of these paths. The env var
  existed to spare the SDK's public API, and these call sites went around
  it.

  Three sites are deliberately left alone, and each looks convertible:

  - `vtc-service/src/server.rs` and `room-host/src/main.rs` build a plain
    default with no host policy. Converting them would add
    `webvh_host_policy()` and change which hosts are permitted — a
    security-relevant change, not a caching one, and not one to make inside
    this change.
  - `pnm-cli/src/bootstrap.rs` passes `None` on purpose. Bootstrap resolves
    the DID locally so the operator verifies the SCID and signed log on
    their own machine rather than trusting a sidecar; that `None` is the
    trust boundary, not an oversight.

  Adds the test that was missing for the property all of this now rests on:
  that two callers on one runtime get one resolver. Sharing could have
  broken and every converted site would have quietly gone back to a private
  cache with nothing failing.

  Reported as VTI-19 by the Keyring wallet team, who saw one command fetch
  `/.well-known/did.jsonl` forty times in five minutes.



## [0.16.5](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/cnm-cli-v0.16.4...cnm-cli-v0.16.5) — 2026-09-18


## [0.16.4](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/cnm-cli-v0.16.3...cnm-cli-v0.16.4) — 2026-09-18


## [0.16.3](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/cnm-cli-v0.16.2...cnm-cli-v0.16.3) — 2026-09-17


## [0.16.2](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/cnm-cli-v0.16.1...cnm-cli-v0.16.2) — 2026-09-17


### Added

- **keys**: An operator can create a post-quantum key, and see which axis it protects ([#1535](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1535))

Two gaps, one of which made everything upstream unusable in practice.

  ## `keys create` could not make a PQC key

  The VTA has been able to derive ML-DSA-44 and ML-DSA-65 since the BIP-32 work
  landed, and since the derived key started carrying its own algorithm it records
  them correctly too. But the CLI matched exactly three strings:

      "ed25519" | "x25519" | "p256" => ..., other => Err("unknown key type")

  So every post-quantum capability in the stack sat behind a front door that could
  not ask for it. `--key-type mldsa44` now works.

  `keys import` deliberately still refuses them, and says why. The VTA validates
  imported key material per algorithm and has no ML-DSA checker, so offering it
  here would take an operator's private key and fail at the far end. The refusal
  names the gap and points at `keys create`, rather than the generic "expected
  ed25519, x25519, or p256" — which reads as "no such algorithm" and would send
  someone looking in the wrong place.

  ## "Is this post-quantum?" has no single answer

  `QuantumPosture` makes that structural rather than a matter of remembering.
  Signature resistance and confidentiality resistance are separate facts, they
  migrate on different timetables, and today the second is false almost
  everywhere: an identity can sign with ML-DSA-44 while still agreeing keys with
  X25519.

  Collapsing those into one badge is wrong in the direction that matters. A reader
  shown "post-quantum" for such an identity has been told its recorded traffic is
  safe from harvest-now-decrypt-later, and it is not. So every label names its
  axis — `mldsa44 (post-quantum signing)`, `x25519 (classical key agreement)` —
  and a test holds them to it.

  There is deliberately no `PostQuantumKeyAgreement` variant. Nothing a DID
  document publishes can answer that axis affirmatively today: the hybrid KEM this
  stack uses lives in the TSP transport, not in a verification method. Adding the
  variant before that is true would let a renderer claim something nothing can do.



## [0.16.1](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/cnm-cli-v0.16.0...cnm-cli-v0.16.1) — 2026-09-16


## [0.16.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/cnm-cli-v0.15.4...cnm-cli-v0.16.0) — 2026-09-16


### Added

- **vta-service**: Tune the VTA's rate limits at runtime ([#1519](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1519))

* feat(vta-service)!: tune the VTA's rate limits at runtime

  The per-IP limiters were tower_governor layers built once with the router, so
  changing a quota needed a config edit and a restart — exactly when an operator
  facing 429s can least afford one.

  The limiters are now our own axum middleware over governor's keyed limiter
  (already in the graph via tower_governor, whose spoof-safe client-IP key
  extractors are reused unchanged). The running service reads the four [server]
  quotas from the shared config on every request and swaps in fresh buckets when
  a quota changes; a change resets that limiter's buckets, and a patch that
  leaves a quota alone keeps them. trust_xff stays restart-only. The 429 contract
  is unchanged.

  rate_limit_interval_secs, rate_limit_burst, did_log_rate_limit_interval_secs
  and did_log_rate_limit_burst are registered in the config registry as mutable
  integer keys, applied live and persisted to config.toml: intervals 1-3600,
  bursts 1-10000, super-admin only, through config/patch like every other key.
  Their names come from vta_sdk::rate_limit, which the 429 hints also use.
  pnm and cnm `config update` gain --rate-limit-interval-secs,
  --rate-limit-burst, --did-log-rate-limit-interval-secs and
  --did-log-rate-limit-burst; `config get` shows the keys.

  Adds docs/02-vta/rate-limiting.md and links it from the docs index,
  non-interactive setup and the setup example.



### Fixed

- **cli**: Type rate-limit refusals on the hand-rolled bootstrap and VTC paths ([#1521](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1521))

pnm bootstrap connect, cnm backup, and cnm audit verify build their own error strings from the HTTP status instead of going through the SDK client, so a 429 read as a bare "request failed" — the same class #1511 fixed for the SDK paths. Map 429 to VtaError::RateLimited via rate_limited_from_http (headers captured before the body), so print_cli_error names which service limited, the wait, and how to tune it. On pnm bootstrap connect the limiter runs before the carve-out is touched, so a note says the one-shot first boot is not spent and retry after the wait is safe. The header/attribution parsing is covered by vta-sdk's rate_limit tests; this is the call-site wiring.



## [0.15.4](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/cnm-cli-v0.15.3...cnm-cli-v0.15.4) — 2026-09-16


### Added

- **cli**: Name removal commands `delete`, and say what a delete leaves behind ([#1513](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1513))

* feat(cli): name removal commands `delete`, and say what a delete leaves behind

  Removal commands across pnm, cnm and the offline vta CLI are named
  `delete`. Each old name stays accepted as a hidden alias, so no script
  breaks:

  - `did-mgmt servers remove` -> `did-mgmt servers delete` (pnm + vta)
  - `pnm vta remove` -> `pnm vta delete`
  - `cnm community remove` -> `cnm community delete` (gains --yes/-y)
  - `pnm memory forget` -> `pnm memory delete`
  - `vta approvals disable` -> `vta approvals delete-all` (`disable` still
    works and prints a note naming the new command)

  Where a delete is not complete, the command now says what remains and
  how to remove it: `vta delete` / `community delete` keep the VTA's ACL
  entry (the notice prints the `acl delete <did>` that revokes it);
  `servers delete` lists DIDs still registered against the server, whose
  logs stay hosted there; `vault delete` / `cred-vault delete` without
  --force name `purge` / `--force`.



## [0.15.3](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/cnm-cli-v0.15.2...cnm-cli-v0.15.3) — 2026-09-16


## [0.15.2](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/cnm-cli-v0.15.1...cnm-cli-v0.15.2) — 2026-09-15


## [0.15.1](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/cnm-cli-v0.15.0...cnm-cli-v0.15.1) — 2026-09-14


## [0.15.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/cnm-cli-v0.14.4...cnm-cli-v0.15.0) — 2026-09-12


### Security

- **resolver**: Refuse did:webvh resolution to non-public hosts by default ([#1448](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1448))


## [0.14.4](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/cnm-cli-v0.14.3...cnm-cli-v0.14.4) — 2026-09-10


## [0.14.2](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/cnm-cli-v0.14.1...cnm-cli-v0.14.2) — 2026-09-09


## [0.14.1](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/cnm-cli-v0.14.0...cnm-cli-v0.14.1) — 2026-09-08


## [0.14.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/cnm-cli-v0.13.6...cnm-cli-v0.14.0) — 2026-09-07


### Added

- **acl**: Create an entry already narrowed, rather than narrowing it after ([#1280](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1280))

#1279 left `acl/grant` refusing a capability narrowing and pointing at
  `acl update`, because taking one meant a fifteenth positional parameter on
  `create_acl`. Refusing was honest but it leaves a real window: between the
  grant and the narrowing the entry holds everything its role implies, and a
  subject that authenticates inside that window is authorized by what it found
  there.

  `create_acl` now takes a `CreateAclParams` struct - the shape `update_acl`
  already had - so the narrowing is one more named field rather than a
  fourteenth argument nobody can read at the call site. Test call sites state
  the two or three members they care about and default the rest instead of
  spelling every one to reach the last.

  The rule is the update path's, applied where the entry is born: a name the
  role does not carry is refused rather than dropped, an unknown name is
  refused, and neither leaves a row behind. `pnm acl create --capabilities
  memory-read,room-present` is now the form to prefer, and the agent runbook
  says so.

  Also echoes the stored narrowing from `acl create` and `acl show`, so the
  restriction can be read back from wherever it was set.

- **acl**: Enforce an entry's capabilities, and give an operator a way to set them ([#1279](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1279))


## [0.13.6](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/cnm-cli-v0.13.5...cnm-cli-v0.13.6) — 2026-09-07


## [0.13.5](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/cnm-cli-v0.13.4...cnm-cli-v0.13.5) — 2026-09-06


## [0.13.4](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/cnm-cli-v0.13.3...cnm-cli-v0.13.4) — 2026-09-06


## [0.13.3](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/cnm-cli-v0.13.2...cnm-cli-v0.13.3) — 2026-09-01


## [0.13.2](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/cnm-cli-v0.13.1...cnm-cli-v0.13.2) — 2026-08-29


## [0.13.1](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/cnm-cli-v0.13.0...cnm-cli-v0.13.1) — 2026-08-29


## [0.13.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/cnm-cli-v0.12.2...cnm-cli-v0.13.0) — 2026-08-28


### Fixed

- **sdk**: Give every authenticated client its identity, and adopt provision/integration 0.3 ([#1147](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1147))

#1146 made every producer sign, and left seven production paths building
  clients that cannot. Each authenticates, takes the token, and drops the DID and
  key on the floor — so every task they dispatch is refused for a missing
  `recipient` and `proof`. `SessionStore::connect` was fixed; nothing else was,
  because no test drives those paths against an enforcing VTA.



### Chore

- **sdk**: Release vta-sdk 0.30.0 for the added CreateKeyBody field ([#1156](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1156))

`CreateKeyBody` gained a `key_id` field while the crate stayed at 0.29.0.
  The struct is exhaustively constructible through the public API, so an
  existing literal no longer compiles — a breaking change under 0.x rules,
  which the semver report has been flagging as its one real finding
  (195 pass, 1 fail) since the field landed.

  Bumps the crate and the nineteen intra-workspace requirements that pin it,
  so `cargo check --workspace` still resolves the path copy and a consumer
  resolving from the registry gets a version that admits the break.



## [0.12.2](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/cnm-cli-v0.12.1...cnm-cli-v0.12.2) — 2026-08-26


## [0.12.1](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/cnm-cli-v0.12.0...cnm-cli-v0.12.1) — 2026-08-22


## [0.12.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/cnm-cli-v0.11.24...cnm-cli-v0.12.0) — 2026-08-21


### Fixed

- **sdk/cli**: A credential store that cannot be opened must not read as "never logged in" ([#1032](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1032))

All four binaries treated an unavailable OS credential store as a warning
  and carried on. What happened next was worse than a silent fallback:
  `KeyringBackend` stayed registered, every `Entry::new` returned
  `NoDefaultStore`, and `SessionBackend::load` swallowed it and returned
  `None` — so the tool behaved exactly as though the user had never logged
  in. A silent fallback at least stores something; this silently forgets.
  OpenVTC hit the user-facing end of it: a profile kept in the Linux kernel
  keyring did not survive a reboot, and the error told the user to check
  their network.

  The four call sites are byte-identical, but their consequences are not,
  so the fix is not:

  - `pnm` and `cnm` keep their session — the admin DID and its private key
    — in the credential store and nowhere else. They now exit at startup
    via `keyring_init::install_default_store_or_exit`, which is the whole
    point: there is nothing they can usefully do next.
  - `vta` and `vtc` never construct an SDK `SessionStore`; they use the
    fjall-backed `KeyspaceSessionStore`, and their keyring use is the seed
    store, one of eight `[secrets] backend` options. Which one is in play
    is not known until config loads, long after `main` starts, so hard
    failing there would break every deployment on aws/gcp/azure/vault/k8s
    running on a host with no credential store — the normal server shape.
    They get `warn_store_unavailable`, and `KeyringSeedStore` — which
    already failed closed — now says which subsystem broke rather than
    "failed to create keyring entry".

  The second half is `FileBackend`. `default_backend` ended in an
  `#[allow(unreachable_code)]` fallback into it whenever no backend feature
  was enabled, writing the admin private key to `sessions.json` as
  plaintext at the process umask, announced by a WARNING on every access —
  which is to say, invisible. `pnm`'s own bootstrap-secrets path has always
  used 0600; the inconsistency was inside one tool.

  That fallback is gone. A build with no session store gets `RefusingBackend`,
  which refuses to save rather than inventing somewhere to put a private
  key. `FileBackend` is now reachable only by explicit choice — the
  `config-session` feature, or `VTI_SECURE_STORE=file` at runtime — and
  creates its file at 0600 inside a 0700 directory *before* writing, since
  writing and then hardening leaves a window at the umask. An existing
  world-readable file from an older build is re-hardened on the next write.

  The runtime override exists because requiring a rebuild to run on a
  headless host creates pressure to disable the check rather than make a
  choice. It parses strictly: `os` or `file`, and anything else — including
  a near-miss like `plaintext` — resolves to neither and refuses. Asking
  for `os` on a build with no `keyring` feature refuses too, rather than
  quietly substituting a file.

  One explanation now serves every tool, in `vta_sdk::secure_store`, taking
  the error as `Display` so it is available without the `keyring` feature —
  OpenVTC renders the same text and honours the same override, which was
  the stated goal: identical secret handling across vta, pnm, openvtc and
  vtc, hard failure rather than a fallback to open text files.



## [0.11.24](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/cnm-cli-v0.11.23...cnm-cli-v0.11.24) — 2026-08-20


## [0.11.23](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/cnm-cli-v0.11.22...cnm-cli-v0.11.23) — 2026-08-18


## [0.11.22](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/cnm-cli-v0.11.21...cnm-cli-v0.11.22) — 2026-08-17


### Added

- **vta-keys**: Add non-extractable internal signing keys ([#995](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/995))

An ordinary VTA key is BIP-32 derived, so anyone holding the 24-word mnemonic
  can reconstruct it offline. That is what makes the VTA recoverable, and equally
  what makes "the operator cannot obtain this key" false — the second limb of what
  eIDAS calls sole control.

  An internal key is generated from the system CSPRNG, has no derivation path, and
  is never returned by any surface. The VTA acts only as a signing oracle for it.

  Deliberately not a flag on the imported-key path. That path wraps its secrets
  under a KEK derived from the master seed (derive_kek(seed, salt)), so a
  non-extractable flag on it would be decorative: the boundary it claims to
  enforce has already been walked around. Internal keys get their own keyspace,
  INTERNAL_KEYS, with no seed involvement at any point, and that keyspace is in
  EXCLUDED_FROM_BACKUP by design — a backup carrying it would be an export of keys
  the VTA promises never to export, and restoring it elsewhere would clone a
  signer.

  Refused for did:webvh log entries, enforced in code rather than left to
  guidance. WebVH is append-only and each entry is authorised by the update key
  the previous entry named; an unrecoverable update key means that if storage is
  lost the DID can never be updated again by anyone, permanently, and every
  integration pinned to it is stranded. Credentials can be re-issued, an
  append-only identity log cannot. Internal keys remain fine as a signing
  verificationMethod inside a published document, where loss costs the ability to
  produce new signatures rather than control of the identity.

  The export refusal is not a permission check — admin is not a bypass, because
  the value of the origin is that no caller holds this power. There are two
  refusals (an early return and an in-match arm); removing either leaves the other,
  and removing both does not compile, since the match over KeyOrigin becomes
  non-exhaustive. An export path cannot silently reopen.

  Operator surfaces carry the cost prominently: `pnm keys create --internal`
  prints what is lost and requires the operator to type a confirmation phrase
  rather than mash y, the response repeats the warning, and docs/02-vta/
  internal-keys.md covers when to use one, what actually protects it (enclave
  measurement + KMS, not a mnemonic), and the two things that genuinely destroy
  it.



## [0.11.21](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/cnm-cli-v0.11.20...cnm-cli-v0.11.21) — 2026-08-16


## [0.11.20](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/cnm-cli-v0.11.19...cnm-cli-v0.11.20) — 2026-08-16


## [0.11.19](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/cnm-cli-v0.11.18...cnm-cli-v0.11.19) — 2026-08-14


## [0.11.18](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/cnm-cli-v0.11.17...cnm-cli-v0.11.18) — 2026-08-14


## [0.11.17](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/cnm-cli-v0.11.16...cnm-cli-v0.11.17) — 2026-08-12


## [0.11.16](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/cnm-cli-v0.11.15...cnm-cli-v0.11.16) — 2026-08-12


## [0.11.15](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/cnm-cli-v0.11.14...cnm-cli-v0.11.15) — 2026-08-12

