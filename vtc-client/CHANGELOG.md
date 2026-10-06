# Changelog

Notable changes to the published crates. Generated from conventional commits by
[git-cliff](https://git-cliff.org) when a release is cut — do not edit by hand.
## [0.18.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vtc-client-v0.17.0...vtc-client-v0.18.0) — 2026-10-06


## [0.17.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vtc-client-v0.16.1...vtc-client-v0.17.0) — 2026-10-05


## [0.16.1](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vtc-client-v0.16.0...vtc-client-v0.16.1) — 2026-10-04


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



## [0.16.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vtc-client-v0.15.0...vtc-client-v0.16.0) — 2026-10-04


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



## [0.15.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vtc-client-v0.14.1...vtc-client-v0.15.0) — 2026-10-02


## [0.14.1](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vtc-client-v0.14.0...vtc-client-v0.14.1) — 2026-10-02


## [0.14.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vtc-client-v0.13.0...vtc-client-v0.14.0) — 2026-10-02


## [0.13.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vtc-client-v0.12.0...vtc-client-v0.13.0) — 2026-10-01


## [0.12.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vtc-client-v0.11.0...vtc-client-v0.12.0) — 2026-10-01


## [0.11.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vtc-client-v0.10.0...vtc-client-v0.11.0) — 2026-10-01


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



## [0.10.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vtc-client-v0.9.0...vtc-client-v0.10.0) — 2026-09-30


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



## [0.9.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vtc-client-v0.8.1...vtc-client-v0.9.0) — 2026-09-30


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



## [0.8.1](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vtc-client-v0.8.0...vtc-client-v0.8.1) — 2026-09-27


## [0.8.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vtc-client-v0.7.7...vtc-client-v0.8.0) — 2026-09-27


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



## [0.7.7](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vtc-client-v0.7.6...vtc-client-v0.7.7) — 2026-09-26


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



## [0.7.6](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vtc-client-v0.7.5...vtc-client-v0.7.6) — 2026-09-26


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



## [0.7.5](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vtc-client-v0.7.4...vtc-client-v0.7.5) — 2026-09-24


## [0.7.4](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vtc-client-v0.7.3...vtc-client-v0.7.4) — 2026-09-23


## [0.7.3](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vtc-client-v0.7.2...vtc-client-v0.7.3) — 2026-09-23


### Added

- **vtc**: A by-DID vetter status lookup ([#1671](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1671))

The vetter listing omits a vetter with no published profile and one whose
  grant was revoked in exactly the same way: both are simply absent. An
  applicant whose vetter went quiet could not tell which had happened, and a
  vetter could not check their own standing at all (Keyring VTI-Q3, #1651).

  `vtc/vetting/vetters/show/0.1` answers by DID with `live`, `revoked`,
  `expired` or `none`, the grant's id, the timestamp that ended or will end it,
  and — for a live grant — whether the vetter is listed. That last member is
  what separates "unlisted by choice" from "not a vetter".

  Served over `/v1/trust-tasks`, DIDComm and TSP for applicants and members,
  and as `POST /v1/vetting/vetters/show` for the console. `vtc-client` gains
  `show_vetter`.

  The live case goes through the same `live_grant` lookup the listing and every
  grant check use, so "live here" cannot drift from "live there". Where a grant
  is both revoked and expired the answer is `revoked`: the community
  withdrawing trust and a grant lapsing are different statements, and a vetter
  told `expired` would reasonably ask for a renewal.

  `CheckShape` on the response enforces what one object's schema cannot — which
  members belong to which status. A response saying `revoked` while carrying
  `validUntil` and no `revokedAt` reads as an expiry to a client branching on
  members rather than status.

  Requires trust-tasks-rs 0.21.21, which publishes the spec merged as
  trustoverip/dtgwg-trust-tasks-tf#603.



## [0.7.2](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vtc-client-v0.7.1...vtc-client-v0.7.2) — 2026-09-22


## [0.7.1](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vtc-client-v0.7.0...vtc-client-v0.7.1) — 2026-09-22


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



## [0.7.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vtc-client-v0.6.12...vtc-client-v0.7.0) — 2026-09-21


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



## [0.6.12](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vtc-client-v0.6.11...vtc-client-v0.6.12) — 2026-09-21


## [0.6.11](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vtc-client-v0.6.10...vtc-client-v0.6.11) — 2026-09-21


## [0.6.10](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vtc-client-v0.6.9...vtc-client-v0.6.10) — 2026-09-20


## [0.6.9](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vtc-client-v0.6.8...vtc-client-v0.6.9) — 2026-09-18


## [0.6.8](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vtc-client-v0.6.7...vtc-client-v0.6.8) — 2026-09-17


## [0.6.7](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vtc-client-v0.6.6...vtc-client-v0.6.7) — 2026-09-17


## [0.6.6](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vtc-client-v0.6.5...vtc-client-v0.6.6) — 2026-09-16


## [0.6.5](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vtc-client-v0.6.4...vtc-client-v0.6.5) — 2026-09-16


## [0.6.4](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vtc-client-v0.6.3...vtc-client-v0.6.4) — 2026-09-16


## [0.6.3](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vtc-client-v0.6.2...vtc-client-v0.6.3) — 2026-09-15


## [0.6.2](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vtc-client-v0.6.1...vtc-client-v0.6.2) — 2026-09-12


## [0.6.1](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vtc-client-v0.6.0...vtc-client-v0.6.1) — 2026-09-10


## [0.5.6](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vtc-client-v0.5.5...vtc-client-v0.5.6) — 2026-09-09


## [0.5.5](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vtc-client-v0.5.4...vtc-client-v0.5.5) — 2026-09-08


### Added

- **rooms**: Serve the epoch key chain, so a joining member can read the room ([#1314](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1314))

* feat(rooms): serve the epoch key chain, so a joining member can read the room

  Completes the mechanism #1300 built and #1305 made conformant. Wires the two
  Trust Tasks published in dtgwg-trust-tasks-tf#387.

  `rooms/epoch/mint` now carries the rung the advance produced. Minting is the
  only moment one party holds both the outgoing and incoming epoch keys, so it is
  the only call that can carry it — and a room that advances without one keeps
  working while silently losing the ability to read everything written before.

  `rooms/epoch/chain` serves the accumulated rungs, gated on `read`: reading the
  room and reading the parts written earlier are the same act. What leaves is
  ciphertext, since the key that opens a rung is a storage key no host holds — a
  caller with the whole chain and no epoch key learns only how many epochs the
  room has had, which its epoch number told them. That property is what lets a
  *host* answer this at all, rather than requiring the owner to be online whenever
  somebody joins.

  Both hosts implement both. Two MUSTs from the spec are enforced: a rung whose
  epoch does not match the advance is refused outright, and a rung already held
  for an epoch is never replaced — a second one is either a replay or a
  re-pointing of the room's history at key material of somebody else's choosing.

  The keyspace is BACKED_UP, and not optionally: a restore that brings back a
  room's records without its chain hands the members a room they can see the shape
  of and cannot read.

  ## What this does not finish

  A joined member's *agent* still cannot read history. `rooms/keys/open` resolves
  from the chain the member's VTA accrued by applying commits, and a joiner's is
  empty; no task delivers rungs into a VTA. The mechanism, the storage and the
  wire all exist — what is missing is the leg from a member's client into their
  own VTA, which needs another spec round. Recorded in the design note §12.2 and
  the operator guide rather than left implied by a passing demo.



## [0.5.4](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vtc-client-v0.5.3...vtc-client-v0.5.4) — 2026-09-07


### Added

- **rooms**: A member's CLI surface, driven through the oracle ([#1285](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1285))

Rooms had no CLI. Using one meant writing Rust against `vtc-client` or hand-
  building signed Trust Task documents, which is not a surface an operator has.
  `pnm rooms {create,list,get,put,curate,renew}` is that surface for a member.

  ## Two parties, never confused

  Every command talks to both and keeps them apart: the operator's **VTA** mints
  a presentation (`rooms/keys/present`) and opens sealed records
  (`rooms/keys/open`), and the room's **host** stores the bytes. The credentials
  the presentation is derived from and the group key that opens a record stay
  inside the VTA - this CLI holds neither at any point.

  That makes the CLI the oracle's first real consumer, and it works: a member
  who holds less than an action needs is refused by their own VTA, before
  anything reaches the host, which is the earlier and clearer of the two
  refusals.

  Each command mints its own presentation for exactly the action it performs -
  `read` for list/get, `write` for put, `curate` for curate, `admin` for renew.
  Caching one across commands would mean re-binding it (impossible without the
  VTA) or sending it unbound, which is a bearer token.

  ## Where the pieces had to live

  `vta-sdk` gains `room_present` / `room_open`, because those are calls to your
  own VTA. It cannot gain the room *wire types*: `vti-common` re-exports
  `vta_sdk::acl`, so `vta-sdk -> vti-rooms -> vti-common -> vta-sdk` is a cycle.
  So `vta-cli-common` takes `vtc-client`, which despite its name is the
  host-neutral room client - `room-host`'s own example drives itself with it. A
  second copy of the `rooms/*` wire types in the CLI is exactly the duplication
  that crate deleted.

  `vtc-client` gains `curate_record`, which nothing had implemented.

  ## What it deliberately cannot do

  **Write to a sealed room**: sealing needs the room's group key, and no task
  seals on a caller's behalf. **Issue credentials**: minting a VIC, VMC or VAC
  needs the room's own signing key, which is the owner's - a different party with
  different custody. Both are refused with the reason rather than half-served,
  and `get` translates the epoch-mismatch failure into "a commit has not been
  delivered", which is what it means and not what it reads like.

  Five tests on the two pure decisions: rebuilding a session from what the VTA
  minted (each missing member refused rather than defaulted, a subject binding
  surviving, a non-string chain link refused rather than silently shortening the
  chain), and the pin/unpin tri-state where absence must stay distinct from
  false.



## [0.5.3](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vtc-client-v0.5.2...vtc-client-v0.5.3) — 2026-09-07


## [0.5.2](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vtc-client-v0.5.1...vtc-client-v0.5.2) — 2026-09-06


### Added

- **rooms**: Succession, so a room outlives one person's availability ([#1251](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1251))

* feat(rooms): succession, so a room outlives one person's availability

  Implements `rooms/owner/transfer` and `rooms/owner/claim` (specs #359, #361,
  published in trust-tasks-rs 0.17.9) across `vti-rooms`, `vti-rooms-dtg`,
  `vtc-service`, `room-host` and `vtc-client`.

  Ownership is load-bearing for liveness, not just administration: a room's owner
  is its sole committer, so a room with no reachable owner cannot advance an epoch
  — and one that cannot advance an epoch cannot be renewed, cannot admit anyone,
  and lapses to read-only. Without succession, one person becoming unreachable
  ends a shared space.

  Transfer is the owner acting while present, gated on `admin`. Claim needs three
  things at once: a nomination the room itself issued naming this claimant, a room
  that has gone *dormant* rather than merely lapsed, and the claimant's own
  membership. Each closes a different route to a takeover.

  A nomination is a VAC granting `succeed` — deliberately a word no room task
  accepts, so it confers nothing at all while the owner is present. Keeping it out
  of the `Action` enum is what makes that structural rather than a matter of
  discipline: `authorize` cannot be handed it, so no later edit there can quietly
  turn a nomination into a working grant. Verification goes through
  `authority::verify_chain` so the property that matters — the chain reaches *the
  room* — comes from the library rather than a second hand-rolled copy.

  The defence against a hostile claim is the same act as ordinary use. An owner
  who was merely away defeats every pending claim by minting an epoch, which is
  what they would have done anyway; nothing has to be revoked and no dispute has
  to be raised. Hence dormancy rather than lapse — a window that opened the moment
  an epoch expired would make every holiday one.

  A claim does not renew the room. `set_owner` hands over a dormant room and
  leaves it dormant, so the new owner's first act is the one that proves they can
  perform it. A claim that silently renewed would hand the room to someone who
  might turn out to be unable to commit, with the room looking healthy until the
  next lapse a year later.

  Neither host checks that an incoming owner is a member of the MLS group, because
  neither can: a host holds no roster and no group state. Refusing what it cannot
  verify would fail every correct transfer, and treating its own ignorance as
  evidence would convert "I don't know" into "no". On claim the host uses the one
  signal it has — the VMC the room issued — and the spec is exact about what that
  proxy is worth.

  Three defects found on the way, fixed rather than worked around:

- **rooms**: Data rooms end to end — storage, dispatch, verification, MLS, and a host ([#1237](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1237))

* feat(rooms): the data-room storage layer

  A data room is a shared space whose access is governed by credentials the
  room itself issues. This lands the storage and its invariants; the
  Trust-Task dispatch that authorizes operations follows once rooms/* is
  published in the registry (trustoverip/dtgwg-trust-tasks-tf#346) - the
  dispatcher refuses a URI the published registry has no schema for, and
  growing the unspecced allowlist is the wrong fix.

  Written first so that the dispatch layer is a thin wrapper over settled
  behaviour rather than a place where storage decisions get made under time
  pressure.

  The row deliberately carries an owner, a visibility, an epoch and a
  retention period, and NO member list. Not omitted for now - there must not
  be one. The moment this service keeps a roster and consults it, three
  things stop being true at once: the room can no longer move to another
  host without reissuing credentials, this service becomes part of the
  room's membership definition, and a room whose contents we cannot read
  acquires a member list we can.

  Invariants enforced in the store rather than trusted to callers, each with
  a test:

  - An open room refuses ciphertext and a sealed room refuses cleartext, so
    a tier promise cannot be broken by a caller passing the wrong shape.
  - A private room refuses a recorded author: on that tier authorship
    belongs inside the sealed body where only members can read it.
  - A record sealed under a stale epoch is refused, because a reader holding
    the current key could not open it.
  - An epoch advances by exactly one. A gap would leave records sealed under
    an epoch nobody holds a key for; a repeat would let a removed member's
    key open material written after their removal, which is the whole point
    of advancing.
  - Versions are monotonic per room, not per record - one comparable number
    is what a sinceVersion watermark needs. A conflict carries the current
    version so a caller need not re-read, because between a bare rejection
    and the re-read the record can change again.
  - A listing returns tombstones to a watermark caller. Without that a
    puller learns of every create and update and never of a delete, so
    retracted records resurrect on its next full rebuild.
  - Retract and purge are separate verbs: a tombstone keeps the key, version
    and epoch so sync converges and the audit chain holds, and erasure is a
    distinct, higher-trust act.

  Keyspaces registered in ALL and BACKED_UP - the two must partition ALL
  exactly - with the census count moved to 27 and the matching AppState
  fields opened, so the documented ALL-matches-AppState invariant stays
  true rather than merely passing a length check.



### Changed

- **rooms**: Move the group-key and sealing layers into vti-rooms ([#1241](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1241))

A VTA must not depend on a VTC client, and rooms/keys/open needs both
  layers inside vta-service - the VTA is what holds the principal's keys
  and opens a record on an agent's behalf. Today they live in vtc-client,
  so that task could not be written at all without a layering inversion.

  vti-rooms is already the shared home for the parts of a room that are not
  a service, and it is where the ciphertext is stored. Putting the AEAD
  binding beside the storage layer that binds to it closes the other half
  of the argument: the associated data commits to roomId | key | version |
  epoch, and until now the code that seals and the code that stores those
  four fields were in different crates. That is how a binding drifts.

  Both live behind an mls feature, off by default, so a host that only
  stores ciphertext still compiles no OpenMLS.

  SealedRoom no longer holds a RoomSession. It holds the room id and the
  group - and the separation is the honest shape rather than a concession
  to the move: the credentials a caller presents travel to the host on
  every request, and the keys never travel anywhere. Pairing them made a
  client the only place a room could be opened.

  The move surfaced a duplication that was invisible while it compiled.
  vtc-client defined its own Visibility, AuthorityPresentation,
  SealedContent, CleartextContent and three response types, plus all five
  Type URI constants - identical to vti-rooms' and with nothing checking
  they stayed identical. The schema-conformance suite added with the open
  tier validates vti-rooms' copies against the published schemas and could
  not see the client's at all, so those could have drifted freely. They are
  re-exports now, which makes the suite cover both.

  RoomKeyError replaces VtcError for this layer, deliberately not
  vti_common::AppError: a record that does not open is a legitimate outcome
  with a specific meaning, and folding it into Internal would say 'this
  service is broken' about the one case the design most wants to be loud -
  a host relocated a record.



## [0.5.1](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vtc-client-v0.5.0...vtc-client-v0.5.1) — 2026-08-29


## [0.5.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vtc-client-v0.4.0...vtc-client-v0.5.0) — 2026-08-28


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



## [0.4.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vtc-client-v0.3.11...vtc-client-v0.4.0) — 2026-08-26


### Fixed

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



## [0.3.11](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vtc-client-v0.3.10...vtc-client-v0.3.11) — 2026-08-22


## [0.3.10](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vtc-client-v0.3.9...vtc-client-v0.3.10) — 2026-08-21


## [0.3.9](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vtc-client-v0.3.8...vtc-client-v0.3.9) — 2026-08-20


## [0.3.8](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vtc-client-v0.3.7...vtc-client-v0.3.8) — 2026-08-18


## [0.3.7](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vtc-client-v0.3.6...vtc-client-v0.3.7) — 2026-08-17


## [0.3.6](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vtc-client-v0.3.5...vtc-client-v0.3.6) — 2026-08-16


## [0.3.5](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vtc-client-v0.3.4...vtc-client-v0.3.5) — 2026-08-14


## [0.3.4](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vtc-client-v0.3.3...vtc-client-v0.3.4) — 2026-08-12


## [0.3.3](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vtc-client-v0.3.2...vtc-client-v0.3.3) — 2026-08-12


## [0.3.2](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vtc-client-v0.3.1...vtc-client-v0.3.2) — 2026-08-12

