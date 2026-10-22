//! What an approver is shown — **VTI-APV-011 / VTI-APV-013**, as data.
//!
//! Every action `kind` ships a **summary template**: a title and an effect in
//! prose, and named fields, each a JSON Pointer into the digested payload with
//! a format from a closed set (`docs/05-design-notes/vtc-action-list.md`
//! §7a.2). The community renders the summary by resolving each pointer against
//! the action's `payload`; a renderer (the console, `cnm`) re-derives every
//! field from that same payload and refuses the action on any mismatch, so
//! nothing an approver reads is something only the community asserted.
//!
//! One template per `(kind, typeUri)`, because one kind arrives through several
//! tasks whose payloads differ in shape: making someone an unrestricted
//! administrator is an `acl/grant` (`/entry/subject`) or an `acl/change-role`
//! (`/subject`). Each template's digest — SHA-256 over its RFC 8785
//! canonicalisation, as a multibase multihash — is **pinned in the build**
//! ([`PINNED`], checked by `every_template_matches_its_pin`), and the console
//! holds the same table, so the community cannot change what approvers are
//! shown for a kind without that change being visible.
//!
//! The title and effect carry `{field}` placeholders — prose, which a renderer
//! fills from the fields it re-derived, never from anything else.

use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

/// One displayed value: where it is in the payload, and how to show it.
#[derive(Debug, Clone, Copy)]
pub struct FieldDef {
    pub name: &'static str,
    /// RFC 6901 pointer into the action's `payload`.
    pub pointer: &'static str,
    /// One of the closed set: `did`, `capabilityList`, `duration`,
    /// `datetime`, `text`.
    pub format: &'static str,
}

/// A summary template.
#[derive(Debug, Clone, Copy)]
pub struct Template {
    pub kind: &'static str,
    pub type_uri: &'static str,
    pub title: &'static str,
    pub effect: &'static str,
    pub fields: &'static [FieldDef],
}

/// The action kinds this build raises.
pub const KIND_GRANT_AUTHORITY: &str = "acl.grant.authority";
pub const KIND_REDUCE_AUTHORITY: &str = "acl.reduce.authority";
pub const KIND_THRESHOLD_LOWER: &str = "config.threshold.lower";
/// Changing the trusted-witness list, `witnesses.trusted` (VTI-CMP-090).
pub const KIND_WITNESSES_CHANGE: &str = "config.witnesses.change";
pub const KIND_POLICY_AUTHORITY: &str = "policy.authority.change";
/// Registering, replacing or deleting a join criterion (VTI-APV-023).
pub const KIND_CRITERIA_CHANGE: &str = "join.criteria.change";
/// Replacing or activating the personhood policy (VTI-APV-023).
pub const KIND_POLICY_RECOGNITION: &str = "policy.recognition.change";
/// Publishing, changing or withdrawing hidden vetting on a join criterion
/// (VTI-APV-023).
pub const KIND_HIDDEN_VETTING_CHANGE: &str = "join.criteria.hiddenVetting";
/// Widening a member-directory field (VTI-DIR-024).
pub const KIND_DIRECTORY_FIELD_WIDEN: &str = "directory.field.widen";
/// Creating a binding election (VTI-VOT-081).
pub const KIND_ELECTION_BINDING_CREATE: &str = "election.binding.create";
pub const KIND_INVITE_CREATE: &str = "admin.invite.create";
/// An operator's offline write, raised for acknowledgement (VTI-VTC-023).
pub const KIND_OPERATOR_WRITE: &str = "operator.offlineWrite";
/// Defining or replacing a custom administrative role (`vtc-admin-roles.md`
/// §6.2).
pub const KIND_ROLE_DEFINE: &str = "acl.role.define";
/// Deleting a custom administrative role.
pub const KIND_ROLE_DELETE: &str = "acl.role.delete";
/// Restoring a backup, which replaces the ACL (`vtc-admin-roles.md` §7).
pub const KIND_BACKUP_RESTORE: &str = "backup.restore";
/// A departed granter's grants, for re-affirmation (`vtc-admin-roles.md` §6.3).
pub const KIND_GRANTS_REVIEW: &str = "acl.grants.review";

/// The record type a grants review is raised under. Not a Trust Task: the
/// community raises it itself, as it does the boot migration's item, and it is
/// never sent or dispatched.
pub const GRANTS_REVIEW_URI: &str = "urn:openvtc:vtc:acl:grants-review";

// ── Queue items (`vtc-action-list.md` §8.2, *Existing queues*) ──────────
//
// Each is an existing human decision surfaced in the action list as category
// `queue`. Like a grants review, the community raises it about a record, so its
// `typeUri` names a record type — never sent, never dispatched — and its
// payload is that record: what the decider is shown, and what the decision is
// executed against through the operation that always decided it.

/// An unratified git-ns break-glass, to ratify or revoke.
pub const KIND_BREAK_GLASS_REVIEW: &str = "gitNs.breakGlass.review";
/// A join request referred for review (`admission: review`).
pub const KIND_JOIN_REVIEW: &str = "member.join.review";
/// A withdrawn vetting statement a current membership rests on.
pub const KIND_VETTING_REVIEW: &str = "vetting.withdrawal.review";

/// A direct admission the `admission` policy referred for approval: adding a
/// member without a join request (`vtc/members/admit/0.1`).
pub const KIND_MEMBER_ADMIT: &str = "member.admit";
/// A direct admission the `admission` policy referred for approval: making an
/// existing ACL entry a membership (`vtc/members/make-membership/0.1`).
pub const KIND_MEMBER_MAKE_MEMBERSHIP: &str = "member.makeMembership";

/// Adding a storage config (`vtc/storage/configs/create/0.1`).
pub const KIND_STORAGE_CONFIG_CREATE: &str = "storage.config.create";
/// Changing a storage config (`vtc/storage/configs/update/0.1`).
pub const KIND_STORAGE_CONFIG_UPDATE: &str = "storage.config.update";
/// Setting a `sealed` storage config's credential (`vtc/storage/credentials/set/0.2`).
/// Approvers see the config and the sealed block's digest, never the credential.
pub const KIND_STORAGE_CREDENTIAL_SET: &str = "storage.credential.set";
/// Retiring a storage config (`vtc/storage/configs/retire/0.1`).
pub const KIND_STORAGE_CONFIG_RETIRE: &str = "storage.config.retire";
/// Pointing a room's new uploads at another config (`vtc/rooms/storage/assign/0.1`).
pub const KIND_ROOM_STORAGE_ASSIGN: &str = "rooms.storage.assign";
/// Moving a room's existing files onto its assigned config
/// (`vtc/rooms/storage/migrate/0.1`).
pub const KIND_ROOM_STORAGE_MIGRATE: &str = "rooms.storage.migrate";

/// The record type a break-glass review is raised under.
pub const BREAK_GLASS_REVIEW_URI: &str = "urn:openvtc:vtc:git-ns:break-glass-review";
/// The record type a join review is raised under.
pub const JOIN_REVIEW_URI: &str = "urn:openvtc:vtc:join:review";
/// The record type a vetting withdrawal review is raised under.
pub const VETTING_REVIEW_URI: &str = "urn:openvtc:vtc:vetting:withdrawal-review";

const ACL_GRANT: &str = "https://trusttasks.org/spec/acl/grant/0.1";
const ACL_UPDATE: &str = "https://trusttasks.org/spec/acl/update/0.1";
const ACL_CHANGE_ROLE: &str = "https://trusttasks.org/spec/acl/change-role/0.1";
pub(crate) const ACL_REVOKE: &str = "https://trusttasks.org/spec/acl/revoke/0.1";
const ACL_GRANT_V0_2: &str = "https://trusttasks.org/spec/acl/grant/0.2";
const ACL_UPDATE_V0_2: &str = "https://trusttasks.org/spec/acl/update/0.2";
const ACL_CHANGE_ROLE_V0_2: &str = "https://trusttasks.org/spec/acl/change-role/0.2";
const ACL_REVOKE_V0_2: &str = "https://trusttasks.org/spec/acl/revoke/0.2";
/// `vtc/operator/offline-write/0.1` — the record type an operator's offline
/// write is named by (VTI-VTC-023). Never sent; see
/// [`super::OPERATOR_OFFLINE_WRITE_URI`].
const OFFLINE_WRITE: &str = super::OPERATOR_OFFLINE_WRITE_URI;
const ACL_MIGRATION: &str = super::OPERATOR_ACL_MIGRATION_URI;
const INVITES_CREATE: &str = "https://trusttasks.org/spec/vtc/admin/invites/create/0.1";
const ADMIN_REMOVE: &str = "https://trusttasks.org/spec/vtc/members/admin-remove/0.1";
const CONFIG_PATCH: &str = "https://trusttasks.org/spec/config/patch/0.1";
const CONFIG_IMPORT: &str = "https://trusttasks.org/spec/vtc/config/import/0.1";
const POLICY_UPSERT: &str = "https://trusttasks.org/spec/policy/upsert/0.2";
const POLICY_ACTIVATE: &str = "https://trusttasks.org/spec/policy/activate/0.1";
const ACCEPTS_REGISTER: &str = crate::trust_tasks::surface_tasks::ACCEPTS_REGISTER_TYPE;
const ACCEPTS_DELETE: &str = crate::trust_tasks::surface_tasks::ACCEPTS_DELETE_TYPE;
/// `vtc/vetting/hidden/publish/0.1`, off the generated type rather than
/// `vetting::pcs_tasks`, which is compiled only with `vetting-pcs`: a build
/// without the feature still pins the template the console holds.
pub(crate) const HIDDEN_PUBLISH: &str =
    <trust_tasks_rs::specs::vtc::vetting::hidden::publish::v0_1::Payload as trust_tasks_rs::Payload>::TYPE_URI;
/// `vtc/vetting/hidden/withdraw/0.1`.
pub(crate) const HIDDEN_WITHDRAW: &str =
    <trust_tasks_rs::specs::vtc::vetting::hidden::withdraw::v0_1::Payload as trust_tasks_rs::Payload>::TYPE_URI;
const DIRECTORY_FIELDS_UPDATE: &str = crate::trust_tasks::directory_tasks::FIELDS_UPDATE_TYPE;
/// `vtc/elections/create/0.1`, off the generated type: a build without `voting`
/// still pins the template the console holds.
pub(crate) const ELECTIONS_CREATE: &str =
    <trust_tasks_rs::specs::vtc::elections::create::v0_1::Payload as trust_tasks_rs::Payload>::TYPE_URI;
const ROLES_DEFINE: &str = "https://trusttasks.org/spec/vtc/roles/define/0.1";
const ROLES_DELETE: &str = "https://trusttasks.org/spec/vtc/roles/delete/0.1";
const BACKUP_FINALIZE_IMPORT: &str = "https://trusttasks.org/spec/backup/finalize-import/0.1";
const MEMBERS_ADMIT: &str = crate::trust_tasks::admission_tasks::ADMIT_TYPE;
const MEMBERS_MAKE_MEMBERSHIP: &str = crate::trust_tasks::admission_tasks::MAKE_MEMBERSHIP_TYPE;
const STORAGE_CREATE: &str = crate::trust_tasks::storage_tasks::CREATE_TYPE;
const STORAGE_UPDATE: &str = crate::trust_tasks::storage_tasks::UPDATE_TYPE;
const STORAGE_RETIRE: &str = crate::trust_tasks::storage_tasks::RETIRE_TYPE;
const STORAGE_CREATE_V0_2: &str = crate::trust_tasks::storage_tasks::CREATE_V0_2_TYPE;
const STORAGE_UPDATE_V0_2: &str = crate::trust_tasks::storage_tasks::UPDATE_V0_2_TYPE;
const STORAGE_CREDENTIAL_SET: &str = crate::trust_tasks::storage_tasks::CREDENTIALS_SET_TYPE;
const ROOM_STORAGE_ASSIGN: &str = crate::trust_tasks::storage_tasks::ASSIGN_TYPE;
const ROOM_STORAGE_MIGRATE: &str = crate::trust_tasks::storage_tasks::MIGRATE_TYPE;
const GROUPS_MEMBERS_ADD: &str = crate::trust_tasks::group_tasks::MEMBERS_ADD_TYPE;
const GROUPS_MEMBERS_REMOVE: &str = crate::trust_tasks::group_tasks::MEMBERS_REMOVE_TYPE;
const GROUPS_BINDINGS_ADD: &str = crate::trust_tasks::group_tasks::BINDINGS_ADD_TYPE;
const GROUPS_BINDINGS_REMOVE: &str = crate::trust_tasks::group_tasks::BINDINGS_REMOVE_TYPE;
const GROUPS_DELETE: &str = crate::trust_tasks::group_tasks::DELETE_TYPE;

// A group carrying authority (VTI-DIR-104): its membership changes are grants
// and reductions of what it confers.
const GROUP_MEMBER_GRANT_EFFECT: &str = "The member {entryId} joins the group {groupId}, which \
                                         carries authority: what it confers is written onto \
                                         their access-control entry, within their role's \
                                         ceiling, for as long as they stay in it.";
const GROUP_BIND_EFFECT: &str = "Every member of the group {groupId} whose role admits it is given \
                                 {grants}{role} — now, and each member added later, for as long \
                                 as the binding stands.";
const GROUP_MEMBER_REDUCE_EFFECT: &str = "The member {entryId} leaves the group {groupId} and \
                                          loses what it gave them. They are not asked: a party \
                                          to a removal never decides it.";
const GROUP_UNBIND_EFFECT: &str = "Every member of the group {groupId} loses what the binding \
                                   {bindingId} gave them. They are not asked: a party to a \
                                   removal never decides it.";
const GROUP_DELETE_EFFECT: &str = "The group {groupId} is deleted, and every member loses what it \
                                   gave them. They are not asked: a party to a removal never \
                                   decides it.";

const STORAGE_CREATE_EFFECT: &str = "A new place this community can keep its members' room files: \
                                     {label} ({settings}). It takes rooms once one is assigned to \
                                     it, or at once if it becomes the default.";
const STORAGE_UPDATE_EFFECT: &str = "The storage config {configId} changes. Rooms assigned to it \
                                     store their new files under the new settings.";
const STORAGE_CREDENTIAL_SET_EFFECT: &str = "The storage config {configId} stores with a \
                                             long-lived credential this community keeps: the \
                                             one sealed in the block whose digest is {digest}, \
                                             replacing any before it. No administrator can read \
                                             it back; whoever operates the machine the community \
                                             runs on can.";
const STORAGE_RETIRE_EFFECT: &str = "The storage config {configId} takes no new rooms or uploads. \
                                     Files already on it stay readable until they are moved off.";
const ROOM_STORAGE_ASSIGN_EFFECT: &str = "Room {roomId}'s new files are stored on {configId}. \
                                          Files it already holds stay where they are.";
const ROOM_STORAGE_MIGRATE_EFFECT: &str = "Room {roomId}'s existing files are copied to the \
                                           storage config it is assigned to, checked against \
                                           what their uploaders committed to, and switched; \
                                           the old copies are deleted after the grace window. \
                                           On Walrus a deletion is a lapse, and ciphertext \
                                           stored there stays public.";

const fn f(name: &'static str, pointer: &'static str, format: &'static str) -> FieldDef {
    FieldDef {
        name,
        pointer,
        format,
    }
}

const GRANT_EFFECT: &str = "{subject} will be able to grant and remove any authority in this \
                            community, including yours.";
const REDUCE_EFFECT: &str = "{subject} loses unrestricted authority in this community. They are \
                             not asked: a party to a removal never decides it.";
// Role-based administration (`vtc-admin-roles.md` §7): what the capabilities
// at stake let their holder do.
const GRANT_CAPABILITY_EFFECT: &str = "{subject} will hold capabilities that create authority in \
                                       this community: they can grant, change or approve what \
                                       others hold.";
const REDUCE_CAPABILITY_EFFECT: &str = "{subject} loses capabilities that create authority in this \
                                        community. They are not asked: a party to a removal never \
                                        decides it.";
const THRESHOLD_EFFECT: &str = "Fewer administrators will be needed to make an unrestricted \
                                administrator — including the next one this requester asks for.";
const WITNESSES_EFFECT: &str = "The witnesses whose Verifiable Witness Credentials count as \
                                evidence in this community become exactly {witnesses}. A VWC from \
                                any witness not listed counts for nothing here, including ones \
                                members already hold.";
const DIRECTORY_WIDEN_EFFECT: &str = "Members' directory values in the field {key} may reach \
                                      further: a wider ceiling or default, a field searched or \
                                      counted, or one shown again. No member's own choice changes, \
                                      but every card that made none takes the new default.";
const ELECTION_CREATE_EFFECT: &str = "The community creates {electionId}, a binding election: its \
                                      result decides something in the community's name. Voting \
                                      runs from {votingOpens} to {votingCloses} at the ballot box \
                                      {ballotBox}, and the roll is {roll}.";
const POLICY_EFFECT: &str = "The rules that decide who holds authority in this community change.";
const RECOGNITION_POLICY_EFFECT: &str = "The rules that decide who this community recognises as a \
                                         person change — for joining, and for members whose \
                                         personhood it has already recognised.";
const CRITERION_REGISTER_EFFECT: &str = "Who may become a member of this community changes: \
                                         {id} becomes exactly what is shown, with admission \
                                         {admission} — automatic admits an applicant who meets \
                                         it, review refers them to an administrator. It replaces \
                                         any criterion of that name, keeping its place in the \
                                         order.";
const HIDDEN_PUBLISH_EFFECT: &str = "Who may become a member of this community changes: the \
                                     criterion {criterionId} can also be met by a hidden vetting \
                                     proof, which shows an applicant was vetted without naming \
                                     their vetters, under the vetter periods {livePeriods} and the \
                                     events shown. Publishing again replaces the parameters.";
const HIDDEN_WITHDRAW_EFFECT: &str = "Who may become a member of this community changes: the \
                                      criterion {criterionId} stops accepting a hidden vetting \
                                      proof. Its named vetting is unchanged, and vetters' \
                                      enrolments are kept for a later publish.";
const CRITERION_DELETE_EFFECT: &str = "Who may become a member of this community changes: \
                                       applicants can no longer join through {id}. Members \
                                       admitted through it keep their membership.";
const ACL_MIGRATION_EFFECT: &str = "This VTC ran {command} when it started on {host} at {at}. It \
                                    is already in effect: acknowledging records that you have \
                                    seen it, and changes nothing. Re-grant anyone who should keep \
                                    authority with acl/update.";
const OPERATOR_EFFECT: &str = "Written at {at}, while the service was stopped. It is already in \
                               effect: acknowledging records that you have seen it, and changes \
                               nothing.";
const ROLE_DEFINE_EFFECT: &str = "Anyone holding {name} may then hold at most {ceiling} and \
                                  approve at most {approveScope}. Replacing a role changes what \
                                  every holder may do at once.";
const ROLE_DELETE_EFFECT: &str = "The role {name} leaves this community's vocabulary. Nobody holds \
                                  it, so nobody's authority changes.";
const BACKUP_RESTORE_EFFECT: &str = "Every record in the backup replaces this community's — its \
                                     access control included, so who administers it afterwards \
                                     is whoever the backup says.";
const GRANTS_REVIEW_EFFECT: &str = "{granter} granted authority to {subjects} and no longer holds \
                                    it. Approving re-affirms those grants under your own \
                                    authority; declining, or letting this lapse, withdraws them.";
const BREAK_GLASS_REVIEW_EFFECT: &str = "{subject} gave themselves {right} on {resource} with no \
                                         one else, at {breakGlassAt}, saying: {justification}. It \
                                         is already in effect. Ratifying confirms it; revoking \
                                         takes it away. It never lapses into acceptance: it waits \
                                         until another administrator decides.";
const JOIN_REVIEW_EFFECT: &str = "{applicant} applied at {submittedAt} and was referred for a \
                                  decision. Approving admits them as a member and issues their \
                                  membership credentials; rejecting refuses the application.";
const MEMBER_ADMIT_EFFECT: &str = "{subject} becomes a member at once, holding {role}, with \
                                   membership credentials — without a join request, without \
                                   meeting this community's join criteria and without being \
                                   vetted.";
const MEMBER_MAKE_MEMBERSHIP_EFFECT: &str = "{subject} keeps exactly the role and authority their \
                                             access-control entry holds, and becomes a member: a \
                                             member record and membership credentials are \
                                             issued, without a join request.";
const VETTING_REVIEW_EFFECT: &str = "{issuer} withdrew the vetting statement {statementId}, which \
                                     {member}'s admission counted. Keeping the member records that \
                                     the admission stands; starting removal sends it through \
                                     vtc/members/admin-remove, which applies its own rules.";

/// Every template this build renders.
pub const TEMPLATES: &[Template] = &[
    Template {
        kind: KIND_GRANT_AUTHORITY,
        type_uri: GROUPS_MEMBERS_ADD,
        title: "Add {entryId} to the group {groupId}",
        effect: GROUP_MEMBER_GRANT_EFFECT,
        fields: &[
            f("groupId", "/groupId", "text"),
            f("entryId", "/entryId", "text"),
            f("reason", "/reason", "text"),
        ],
    },
    Template {
        kind: KIND_GRANT_AUTHORITY,
        type_uri: GROUPS_BINDINGS_ADD,
        title: "Give authority through the group {groupId}",
        effect: GROUP_BIND_EFFECT,
        fields: &[
            f("groupId", "/groupId", "text"),
            f("grants", "/binding/grants", "text"),
            f("role", "/binding/role", "text"),
            f("reason", "/reason", "text"),
        ],
    },
    Template {
        kind: KIND_REDUCE_AUTHORITY,
        type_uri: GROUPS_MEMBERS_REMOVE,
        title: "Remove {entryId} from the group {groupId}",
        effect: GROUP_MEMBER_REDUCE_EFFECT,
        fields: &[
            f("groupId", "/groupId", "text"),
            f("entryId", "/entryId", "text"),
            f("reason", "/reason", "text"),
        ],
    },
    Template {
        kind: KIND_REDUCE_AUTHORITY,
        type_uri: GROUPS_BINDINGS_REMOVE,
        title: "Stop giving authority through the group {groupId}",
        effect: GROUP_UNBIND_EFFECT,
        fields: &[
            f("groupId", "/groupId", "text"),
            f("bindingId", "/bindingId", "text"),
            f("reason", "/reason", "text"),
        ],
    },
    Template {
        kind: KIND_REDUCE_AUTHORITY,
        type_uri: GROUPS_DELETE,
        title: "Delete the group {groupId}",
        effect: GROUP_DELETE_EFFECT,
        fields: &[
            f("groupId", "/groupId", "text"),
            f("reason", "/reason", "text"),
        ],
    },
    Template {
        kind: KIND_GRANT_AUTHORITY,
        type_uri: ACL_GRANT_V0_2,
        title: "Make {subject} a {role}",
        effect: GRANT_CAPABILITY_EFFECT,
        fields: &[
            f("subject", "/entry/subject", "did"),
            f("role", "/entry/role", "text"),
            f("capabilities", "/entry/capabilities", "text"),
            f("expiresAt", "/entry/expiresAt", "datetime"),
        ],
    },
    Template {
        kind: KIND_GRANT_AUTHORITY,
        type_uri: ACL_UPDATE_V0_2,
        title: "Widen what {subject} holds",
        effect: GRANT_CAPABILITY_EFFECT,
        fields: &[
            f("subject", "/subject", "did"),
            f("capabilities", "/capabilities", "text"),
            f("expiresAt", "/expiresAt", "datetime"),
        ],
    },
    Template {
        kind: KIND_GRANT_AUTHORITY,
        type_uri: ACL_CHANGE_ROLE_V0_2,
        title: "Move {subject} from {fromRole} to {toRole}",
        effect: GRANT_CAPABILITY_EFFECT,
        fields: &[
            f("subject", "/subject", "did"),
            f("fromRole", "/fromRole", "text"),
            f("toRole", "/toRole", "text"),
        ],
    },
    Template {
        kind: KIND_REDUCE_AUTHORITY,
        type_uri: ACL_REVOKE_V0_2,
        title: "Revoke {subject}",
        effect: REDUCE_CAPABILITY_EFFECT,
        fields: &[
            f("subject", "/subject", "did"),
            f("revocation", "/revocation", "text"),
            f("reason", "/reason", "text"),
        ],
    },
    Template {
        kind: KIND_REDUCE_AUTHORITY,
        type_uri: ACL_UPDATE_V0_2,
        title: "Narrow what {subject} holds",
        effect: REDUCE_CAPABILITY_EFFECT,
        fields: &[
            f("subject", "/subject", "did"),
            f("capabilities", "/capabilities", "text"),
            f("expiresAt", "/expiresAt", "datetime"),
        ],
    },
    Template {
        kind: KIND_REDUCE_AUTHORITY,
        type_uri: ACL_CHANGE_ROLE_V0_2,
        title: "Move {subject} from {fromRole} to {toRole}",
        effect: REDUCE_CAPABILITY_EFFECT,
        fields: &[
            f("subject", "/subject", "did"),
            f("fromRole", "/fromRole", "text"),
            f("toRole", "/toRole", "text"),
        ],
    },
    Template {
        kind: KIND_GRANT_AUTHORITY,
        type_uri: ACL_GRANT,
        title: "Make {subject} an unrestricted administrator",
        effect: GRANT_EFFECT,
        fields: &[
            f("subject", "/entry/subject", "did"),
            f("role", "/entry/role", "text"),
            f("scopes", "/entry/scopes", "capabilityList"),
            f("expiresAt", "/entry/expiresAt", "datetime"),
        ],
    },
    Template {
        kind: KIND_GRANT_AUTHORITY,
        type_uri: ACL_UPDATE,
        title: "Widen {subject} to an unrestricted administrator",
        effect: GRANT_EFFECT,
        fields: &[
            f("subject", "/subject", "did"),
            f("scopes", "/scopes", "capabilityList"),
            f("expiresAt", "/expiresAt", "datetime"),
        ],
    },
    Template {
        kind: KIND_GRANT_AUTHORITY,
        type_uri: ACL_CHANGE_ROLE,
        title: "Promote {subject} from {fromRole} to unrestricted administrator",
        effect: GRANT_EFFECT,
        fields: &[
            f("subject", "/subject", "did"),
            f("fromRole", "/fromRole", "text"),
            f("toRole", "/toRole", "text"),
        ],
    },
    Template {
        kind: KIND_INVITE_CREATE,
        type_uri: INVITES_CREATE,
        title: "Invite {subject} to become an unrestricted administrator",
        effect: GRANT_EFFECT,
        fields: &[f("subject", "/did", "did"), f("label", "/label", "text")],
    },
    Template {
        kind: KIND_REDUCE_AUTHORITY,
        type_uri: ACL_REVOKE,
        title: "Remove unrestricted administrator {subject}",
        effect: REDUCE_EFFECT,
        fields: &[
            f("subject", "/subject", "did"),
            f("scopes", "/scopes", "capabilityList"),
            f("reason", "/reason", "text"),
        ],
    },
    Template {
        kind: KIND_REDUCE_AUTHORITY,
        type_uri: ACL_CHANGE_ROLE,
        title: "Demote unrestricted administrator {subject} to {toRole}",
        effect: REDUCE_EFFECT,
        fields: &[
            f("subject", "/subject", "did"),
            f("toRole", "/toRole", "text"),
        ],
    },
    Template {
        kind: KIND_REDUCE_AUTHORITY,
        type_uri: ACL_UPDATE,
        title: "Narrow unrestricted administrator {subject}",
        effect: REDUCE_EFFECT,
        fields: &[
            f("subject", "/subject", "did"),
            f("scopes", "/scopes", "capabilityList"),
            f("expiresAt", "/expiresAt", "datetime"),
        ],
    },
    Template {
        kind: KIND_REDUCE_AUTHORITY,
        type_uri: ACL_GRANT,
        title: "Rewrite unrestricted administrator {subject} as {role}",
        effect: REDUCE_EFFECT,
        fields: &[
            f("subject", "/entry/subject", "did"),
            f("role", "/entry/role", "text"),
            f("scopes", "/entry/scopes", "capabilityList"),
        ],
    },
    Template {
        kind: KIND_REDUCE_AUTHORITY,
        type_uri: ADMIN_REMOVE,
        title: "Remove unrestricted administrator {subject} from the community",
        effect: REDUCE_EFFECT,
        fields: &[
            f("subject", "/did", "did"),
            f("disposition", "/disposition", "text"),
            f("reason", "/reason", "text"),
        ],
    },
    Template {
        kind: KIND_THRESHOLD_LOWER,
        type_uri: CONFIG_PATCH,
        title: "Lower the unrestricted-administrator consent threshold to {threshold}",
        effect: THRESHOLD_EFFECT,
        fields: &[f(
            "threshold",
            "/overrides/acl.unrestricted_admin_consent_threshold",
            "text",
        )],
    },
    Template {
        kind: KIND_THRESHOLD_LOWER,
        type_uri: CONFIG_IMPORT,
        title: "Import a configuration that lowers the consent threshold to {threshold}",
        effect: THRESHOLD_EFFECT,
        fields: &[f(
            "threshold",
            "/document/configOverrides/acl.unrestricted_admin_consent_threshold",
            "text",
        )],
    },
    Template {
        kind: KIND_WITNESSES_CHANGE,
        type_uri: CONFIG_PATCH,
        title: "Change the witnesses this community trusts",
        effect: WITNESSES_EFFECT,
        fields: &[f("witnesses", "/overrides/witnesses.trusted", "text")],
    },
    Template {
        kind: KIND_WITNESSES_CHANGE,
        type_uri: CONFIG_IMPORT,
        title: "Import a configuration that changes the witnesses this community trusts",
        effect: WITNESSES_EFFECT,
        fields: &[f(
            "witnesses",
            "/document/configOverrides/witnesses.trusted",
            "text",
        )],
    },
    Template {
        kind: KIND_ELECTION_BINDING_CREATE,
        type_uri: ELECTIONS_CREATE,
        title: "Create the binding election {electionId}",
        effect: ELECTION_CREATE_EFFECT,
        fields: &[
            f("electionId", "/manifest/electionId", "text"),
            f("title", "/manifest/title", "text"),
            f("ballotBox", "/manifest/ballotBox", "did"),
            f("roll", "/manifest/roll/rule", "text"),
            f("votingOpens", "/manifest/votingOpens", "datetime"),
            f("votingCloses", "/manifest/votingCloses", "datetime"),
        ],
    },
    Template {
        kind: KIND_DIRECTORY_FIELD_WIDEN,
        type_uri: DIRECTORY_FIELDS_UPDATE,
        title: "Widen the directory field {key}",
        effect: DIRECTORY_WIDEN_EFFECT,
        fields: &[
            f("key", "/key", "text"),
            f("ceiling", "/ceiling", "text"),
            f("defaultVisibility", "/defaultVisibility", "text"),
            f("reason", "/reason", "text"),
        ],
    },
    Template {
        kind: KIND_POLICY_AUTHORITY,
        type_uri: POLICY_UPSERT,
        title: "Replace the policy {name}",
        effect: POLICY_EFFECT,
        fields: &[
            f("name", "/name", "text"),
            f("id", "/id", "text"),
            f("module", "/module", "text"),
        ],
    },
    Template {
        kind: KIND_POLICY_AUTHORITY,
        type_uri: POLICY_ACTIVATE,
        title: "Activate policy {id} for {purpose}",
        effect: POLICY_EFFECT,
        fields: &[f("id", "/id", "text"), f("purpose", "/purpose", "text")],
    },
    Template {
        kind: KIND_POLICY_RECOGNITION,
        type_uri: POLICY_UPSERT,
        title: "Replace the policy {name}",
        effect: RECOGNITION_POLICY_EFFECT,
        fields: &[
            f("name", "/name", "text"),
            f("id", "/id", "text"),
            f("module", "/module", "text"),
        ],
    },
    Template {
        kind: KIND_POLICY_RECOGNITION,
        type_uri: POLICY_ACTIVATE,
        title: "Activate policy {id} for {purpose}",
        effect: RECOGNITION_POLICY_EFFECT,
        fields: &[f("id", "/id", "text"), f("purpose", "/purpose", "text")],
    },
    Template {
        kind: KIND_CRITERIA_CHANGE,
        type_uri: ACCEPTS_REGISTER,
        title: "Register the join criterion {id}",
        effect: CRITERION_REGISTER_EFFECT,
        fields: &[
            f("id", "/id", "text"),
            f("admission", "/admission", "text"),
            f("query", "/query", "text"),
            f("credentialIssuers", "/credentialIssuers", "text"),
            f("invitationRequired", "/invitationRequired", "text"),
            f("vetting", "/vetting", "text"),
            f("description", "/description", "text"),
        ],
    },
    Template {
        kind: KIND_CRITERIA_CHANGE,
        type_uri: ACCEPTS_DELETE,
        title: "Remove the join criterion {id}",
        effect: CRITERION_DELETE_EFFECT,
        fields: &[f("id", "/id", "text")],
    },
    Template {
        kind: KIND_HIDDEN_VETTING_CHANGE,
        type_uri: HIDDEN_PUBLISH,
        title: "Turn on hidden vetting for the join criterion {criterionId}",
        effect: HIDDEN_PUBLISH_EFFECT,
        fields: &[
            f("criterionId", "/criterionId", "text"),
            f("livePeriods", "/livePeriods", "text"),
            f("liveTokenLabels", "/liveTokenLabels", "text"),
            f("dripPerTick", "/dripPerTick", "text"),
            f("tickLength", "/tickLength", "text"),
            f("events", "/events", "text"),
        ],
    },
    Template {
        kind: KIND_HIDDEN_VETTING_CHANGE,
        type_uri: HIDDEN_WITHDRAW,
        title: "Turn off hidden vetting for the join criterion {criterionId}",
        effect: HIDDEN_WITHDRAW_EFFECT,
        fields: &[f("criterionId", "/criterionId", "text")],
    },
    Template {
        kind: KIND_OPERATOR_WRITE,
        type_uri: OFFLINE_WRITE,
        title: "The operator ran {command} on {host}, changing access for {dids}",
        effect: OPERATOR_EFFECT,
        fields: &[
            f("command", "/command", "text"),
            f("dids", "/dids", "capabilityList"),
            f("host", "/host", "text"),
            f("at", "/at", "datetime"),
        ],
    },
    Template {
        kind: KIND_OPERATOR_WRITE,
        type_uri: ACL_MIGRATION,
        title: "Context-scoped administrators lost administrative authority when this VTC moved \
                to role-based administration",
        effect: ACL_MIGRATION_EFFECT,
        fields: &[
            f("command", "/command", "text"),
            f("host", "/operatorHost", "text"),
            f("at", "/invokedAt", "datetime"),
        ],
    },
    Template {
        kind: KIND_ROLE_DEFINE,
        type_uri: ROLES_DEFINE,
        title: "Define the administrative role {name}",
        effect: ROLE_DEFINE_EFFECT,
        fields: &[
            f("name", "/name", "text"),
            f("ceiling", "/ceiling", "text"),
            f("approveScope", "/approveScope", "text"),
            f("replaces", "/replaces", "text"),
            f("reason", "/reason", "text"),
        ],
    },
    Template {
        kind: KIND_ROLE_DELETE,
        type_uri: ROLES_DELETE,
        title: "Delete the administrative role {name}",
        effect: ROLE_DELETE_EFFECT,
        fields: &[f("name", "/name", "text"), f("reason", "/reason", "text")],
    },
    Template {
        kind: KIND_BACKUP_RESTORE,
        type_uri: BACKUP_FINALIZE_IMPORT,
        title: "Restore this community from backup {bundleId}",
        effect: BACKUP_RESTORE_EFFECT,
        fields: &[f("bundleId", "/bundleId", "text")],
    },
    Template {
        kind: KIND_STORAGE_CONFIG_CREATE,
        type_uri: STORAGE_CREATE,
        title: "Add the storage config {id}",
        effect: STORAGE_CREATE_EFFECT,
        fields: &[
            f("id", "/id", "text"),
            f("label", "/label", "text"),
            f("settings", "/settings", "text"),
            f("auth", "/auth", "text"),
            f("capacityBytes", "/capacityBytes", "text"),
            f("isDefault", "/isDefault", "text"),
            f("reason", "/reason", "text"),
        ],
    },
    Template {
        kind: KIND_STORAGE_CONFIG_UPDATE,
        type_uri: STORAGE_UPDATE,
        title: "Change the storage config {configId}",
        effect: STORAGE_UPDATE_EFFECT,
        fields: &[
            f("configId", "/configId", "text"),
            f("label", "/label", "text"),
            f("settings", "/settings", "text"),
            f("auth", "/auth", "text"),
            f("capacityBytes", "/capacityBytes", "text"),
            f("isDefault", "/isDefault", "text"),
            f("reason", "/reason", "text"),
        ],
    },
    Template {
        kind: KIND_STORAGE_CONFIG_CREATE,
        type_uri: STORAGE_CREATE_V0_2,
        title: "Add the storage config {id}",
        effect: STORAGE_CREATE_EFFECT,
        fields: &[
            f("id", "/id", "text"),
            f("label", "/label", "text"),
            f("settings", "/settings", "text"),
            f("auth", "/auth", "text"),
            f("capacityBytes", "/capacityBytes", "text"),
            f("isDefault", "/isDefault", "text"),
            f("reason", "/reason", "text"),
        ],
    },
    Template {
        kind: KIND_STORAGE_CONFIG_UPDATE,
        type_uri: STORAGE_UPDATE_V0_2,
        title: "Change the storage config {configId}",
        effect: STORAGE_UPDATE_EFFECT,
        fields: &[
            f("configId", "/configId", "text"),
            f("label", "/label", "text"),
            f("settings", "/settings", "text"),
            f("auth", "/auth", "text"),
            f("capacityBytes", "/capacityBytes", "text"),
            f("isDefault", "/isDefault", "text"),
            f("reason", "/reason", "text"),
        ],
    },
    Template {
        kind: KIND_STORAGE_CREDENTIAL_SET,
        type_uri: STORAGE_CREDENTIAL_SET,
        title: "Set the sealed credential of the storage config {configId}",
        effect: STORAGE_CREDENTIAL_SET_EFFECT,
        fields: &[
            f("configId", "/configId", "text"),
            f("digest", "/digestMultibase", "text"),
            f("reason", "/reason", "text"),
        ],
    },
    Template {
        kind: KIND_STORAGE_CONFIG_RETIRE,
        type_uri: STORAGE_RETIRE,
        title: "Retire the storage config {configId}",
        effect: STORAGE_RETIRE_EFFECT,
        fields: &[
            f("configId", "/configId", "text"),
            f("reason", "/reason", "text"),
        ],
    },
    Template {
        kind: KIND_ROOM_STORAGE_ASSIGN,
        type_uri: ROOM_STORAGE_ASSIGN,
        title: "Store room {roomId}'s new files on {configId}",
        effect: ROOM_STORAGE_ASSIGN_EFFECT,
        fields: &[
            f("roomId", "/roomId", "text"),
            f("configId", "/configId", "text"),
            f("reason", "/reason", "text"),
        ],
    },
    Template {
        kind: KIND_ROOM_STORAGE_MIGRATE,
        type_uri: ROOM_STORAGE_MIGRATE,
        title: "Move room {roomId}'s files to its assigned storage",
        effect: ROOM_STORAGE_MIGRATE_EFFECT,
        fields: &[
            f("roomId", "/roomId", "text"),
            f("maxBytesPerSecond", "/maxBytesPerSecond", "text"),
            f("reason", "/reason", "text"),
        ],
    },
    Template {
        kind: KIND_GRANTS_REVIEW,
        type_uri: GRANTS_REVIEW_URI,
        title: "Re-affirm or withdraw the grants {granter} made",
        effect: GRANTS_REVIEW_EFFECT,
        fields: &[
            f("granter", "/granter", "did"),
            f("subjects", "/subjects", "capabilityList"),
            f("deadline", "/deadline", "datetime"),
        ],
    },
    Template {
        kind: KIND_BREAK_GLASS_REVIEW,
        type_uri: BREAK_GLASS_REVIEW_URI,
        title: "Ratify or revoke the break-glass that gave {subject} {right} on {resource}",
        effect: BREAK_GLASS_REVIEW_EFFECT,
        fields: &[
            f("subject", "/subject", "did"),
            f("right", "/right", "text"),
            f("resource", "/resource", "text"),
            f("justification", "/justification", "text"),
            f("breakGlassAt", "/breakGlassAt", "datetime"),
        ],
    },
    Template {
        kind: KIND_JOIN_REVIEW,
        type_uri: JOIN_REVIEW_URI,
        title: "Admit or reject {applicant}",
        effect: JOIN_REVIEW_EFFECT,
        fields: &[
            f("applicant", "/applicant", "did"),
            f("requestId", "/requestId", "text"),
            f("submittedAt", "/submittedAt", "datetime"),
        ],
    },
    Template {
        kind: KIND_VETTING_REVIEW,
        type_uri: VETTING_REVIEW_URI,
        title: "Keep {member} or start their removal",
        effect: VETTING_REVIEW_EFFECT,
        fields: &[
            f("member", "/member", "did"),
            f("issuer", "/issuer", "did"),
            f("statementId", "/statementId", "text"),
            f("reason", "/reason", "text"),
            f("recordedAt", "/recordedAt", "datetime"),
        ],
    },
    Template {
        kind: KIND_MEMBER_ADMIT,
        type_uri: MEMBERS_ADMIT,
        title: "Add {subject} as a member, holding {role}",
        effect: MEMBER_ADMIT_EFFECT,
        fields: &[
            f("subject", "/subject", "did"),
            f("role", "/role", "text"),
            f("label", "/label", "text"),
            f("reason", "/reason", "text"),
        ],
    },
    Template {
        kind: KIND_MEMBER_MAKE_MEMBERSHIP,
        type_uri: MEMBERS_MAKE_MEMBERSHIP,
        title: "Make {subject}'s access-control entry a membership",
        effect: MEMBER_MAKE_MEMBERSHIP_EFFECT,
        fields: &[
            f("subject", "/subject", "did"),
            f("reason", "/reason", "text"),
        ],
    },
];

/// The digest of every template, pinned. A change to a template's prose,
/// pointers or formats changes its digest and fails
/// `every_template_matches_its_pin` until this table — and the console's copy
/// (`admin-ui/src/lib/action-summary.ts`) — is updated with it: what approvers
/// are shown cannot move silently.
pub const PINNED: &[(&str, &str, &str)] = &[
    (
        KIND_GRANT_AUTHORITY,
        GROUPS_MEMBERS_ADD,
        "zQmZr8mXvAph3Sxdxbv9ge82svqswrBn9xunstWKDsSD1tG",
    ),
    (
        KIND_GRANT_AUTHORITY,
        GROUPS_BINDINGS_ADD,
        "zQmXa9sTSnLan8LEf7QyEzavkt5doEHVz6jZ9c34Yg8bKi9",
    ),
    (
        KIND_REDUCE_AUTHORITY,
        GROUPS_MEMBERS_REMOVE,
        "zQmQVW9TAVk3kGCAiCwc7vvyhKCXYJobPYRxxfD9nphPMfi",
    ),
    (
        KIND_REDUCE_AUTHORITY,
        GROUPS_BINDINGS_REMOVE,
        "zQmPdSegnSr9GKnqAyFoiBrBQV4pHHHea4sQ9oKeyu1FsSq",
    ),
    (
        KIND_REDUCE_AUTHORITY,
        GROUPS_DELETE,
        "zQmemh2M3haEy21mKWDKRoaswuSUeD6oSRyjUKGwUSENWZz",
    ),
    (
        KIND_GRANT_AUTHORITY,
        ACL_GRANT_V0_2,
        "zQmNiciJtH7xnKdQUxEwp44mpbCrVt8tfBrt1XKg7VfAc71",
    ),
    (
        KIND_GRANT_AUTHORITY,
        ACL_UPDATE_V0_2,
        "zQmQBA6WoTVVo2wBJrmkJwTnefj6q1Hgwc2BWFTCCPpWnQT",
    ),
    (
        KIND_GRANT_AUTHORITY,
        ACL_CHANGE_ROLE_V0_2,
        "zQmVAPMeYXgX9bUi5HruaPFxBLsW1ZJNkbRss6VixMz48vt",
    ),
    (
        KIND_REDUCE_AUTHORITY,
        ACL_REVOKE_V0_2,
        "zQmfJss7J6uNUdyZPUC64BoJ971CdnTfgd6BVEQd7aFjYwD",
    ),
    (
        KIND_REDUCE_AUTHORITY,
        ACL_UPDATE_V0_2,
        "zQmNWjHGRwDCfUsvVFxx6o6eXczqjQTepMEKwkS3qqNo1N6",
    ),
    (
        KIND_REDUCE_AUTHORITY,
        ACL_CHANGE_ROLE_V0_2,
        "zQmaAjJC1L9w3pbUTEbWfhzfBdUpv8pofDZvL6mWSpU2eWk",
    ),
    (
        KIND_GRANT_AUTHORITY,
        ACL_GRANT,
        "zQmPrXgyRpZ57y4AekuZPspEkunnEbEhxvZuqrfoxrgsvr4",
    ),
    (
        KIND_GRANT_AUTHORITY,
        ACL_UPDATE,
        "zQmbvgey1akTyTq74Vhe4fuXGvpTKKTVw34mo3y4hVEKSEQ",
    ),
    (
        KIND_GRANT_AUTHORITY,
        ACL_CHANGE_ROLE,
        "zQmQX9Dx7cDqLtcoTNuDSWWo5nJTGecB9CqRLKgpd4es1c9",
    ),
    (
        KIND_INVITE_CREATE,
        INVITES_CREATE,
        "zQmSXC2GaMpizs4kKRhz4nBchZikWjqHAoeDfA5D7fVizgp",
    ),
    (
        KIND_REDUCE_AUTHORITY,
        ACL_REVOKE,
        "zQmbvSkPZnzCqq5idfR5DKfFyiHFRCeimT48C4c6jtZfG1Z",
    ),
    (
        KIND_REDUCE_AUTHORITY,
        ACL_CHANGE_ROLE,
        "zQmfHspRZaXfEPkeAyqcFkpgqYT2RCqXjjnXVZmFhsaJQcu",
    ),
    (
        KIND_REDUCE_AUTHORITY,
        ACL_UPDATE,
        "zQmXcYLQhsgDQEgDZuf2mvmkxDDKEd1c9C47tmRAGLofPgM",
    ),
    (
        KIND_REDUCE_AUTHORITY,
        ACL_GRANT,
        "zQmVrvxot9bAts7S22CfXQgqR8vC5aZHWQz97UjfMWveT7o",
    ),
    (
        KIND_REDUCE_AUTHORITY,
        ADMIN_REMOVE,
        "zQmc2FGMz27Bqiu3CPpy5BrVBWyst3RkfWhfk322QWzu6mR",
    ),
    (
        KIND_THRESHOLD_LOWER,
        CONFIG_PATCH,
        "zQmeGT7ztnicC5RScp86U5Yjq1s3vhtzZof8yYy6sWi9cYP",
    ),
    (
        KIND_THRESHOLD_LOWER,
        CONFIG_IMPORT,
        "zQmQ6yxgM1HYuJkY4RvQDYiB7NyfsFeAeYzcPnh6d5rrrPc",
    ),
    (
        KIND_WITNESSES_CHANGE,
        CONFIG_PATCH,
        "zQmYGMiMk9SpEJwJ7g4EpxKCourBJVRP6PnmHMzYccbQugH",
    ),
    (
        KIND_WITNESSES_CHANGE,
        CONFIG_IMPORT,
        "zQmathdofD8yrXDQ2AuSfsWwjjKdx9RdPkAnC2r7qdU79hc",
    ),
    (
        KIND_ELECTION_BINDING_CREATE,
        ELECTIONS_CREATE,
        "zQmRruPSiJx9JHEBJCdQiH1qXMTdqf2Dy6yL1WmUJqTU8mX",
    ),
    (
        KIND_DIRECTORY_FIELD_WIDEN,
        DIRECTORY_FIELDS_UPDATE,
        "zQmafxMMkTfH4kb9QgoUQEJtUs4tuZFvqM8nxhjEawj6vYZ",
    ),
    (
        KIND_POLICY_RECOGNITION,
        POLICY_UPSERT,
        "zQmT4hA8bE6Z1G2PDPPTvzH9ZTGrKdnyS3UBhhEXZkeDLhm",
    ),
    (
        KIND_POLICY_RECOGNITION,
        POLICY_ACTIVATE,
        "zQmSdYoQSJ79w1Di8LMr3QJKcjLt47c2DdH2F9gbfoLF6hv",
    ),
    (
        KIND_HIDDEN_VETTING_CHANGE,
        HIDDEN_PUBLISH,
        "zQmfB8sMNE5otp8D7uYDLeBuWhHfLHQUe3BPCVrwqNWyRDi",
    ),
    (
        KIND_HIDDEN_VETTING_CHANGE,
        HIDDEN_WITHDRAW,
        "zQmcN7gkKudstTLhhf5kKTrS6eoxNyS5hBkjSGzoK8nYcKL",
    ),
    (
        KIND_CRITERIA_CHANGE,
        ACCEPTS_REGISTER,
        "zQmbgGnKd4rpcj5dPZsKGTrL48wFiL5jGnyyUe9o3JcP5mr",
    ),
    (
        KIND_CRITERIA_CHANGE,
        ACCEPTS_DELETE,
        "zQmaKTFtV3fF3hBkeWwduWohd35nePzqcEvBP95HLa3e7Pu",
    ),
    (
        KIND_POLICY_AUTHORITY,
        POLICY_UPSERT,
        "zQma1zFb7cvRpSH7erp14W83wYZW5vP7cke1yLwcwQZdEie",
    ),
    (
        KIND_POLICY_AUTHORITY,
        POLICY_ACTIVATE,
        "zQmTqKd5UoQZfTy7giJU9KFWFyhUbqxAtr5XWoUB9BLncBL",
    ),
    (
        KIND_OPERATOR_WRITE,
        OFFLINE_WRITE,
        "zQmQZTPg2MeWt1C8oAvoLMGJNY9DpxvB6bRjvQwJT7ns9Ah",
    ),
    (
        KIND_OPERATOR_WRITE,
        ACL_MIGRATION,
        "zQmcx336K693LHuAKosCP9avuLZWauw1vome6VBxWBFDiqK",
    ),
    (
        KIND_ROLE_DEFINE,
        ROLES_DEFINE,
        "zQmf6erEaANYgarV9c8frmZSZ8R5XuomNdXxGNQ8FAZ2QUh",
    ),
    (
        KIND_ROLE_DELETE,
        ROLES_DELETE,
        "zQmNmqjjmZmPfvapiR91YcFDgXtg1xdAw3QNwaQemrEHL8U",
    ),
    (
        KIND_BACKUP_RESTORE,
        BACKUP_FINALIZE_IMPORT,
        "zQmY89pWbScF2Mj1B1tWXJrtKPyhqcWDJDiV8eKCTchKscE",
    ),
    (
        KIND_GRANTS_REVIEW,
        GRANTS_REVIEW_URI,
        "zQmes3QBrvXfxcwu7tyU7gk58b8RrLfrQiteFRJGCwDYS4S",
    ),
    (
        KIND_BREAK_GLASS_REVIEW,
        BREAK_GLASS_REVIEW_URI,
        "zQmc83acTt15e5rhcZi7TKnXt2NNBPB3zZ7cShQhbjvCkcP",
    ),
    (
        KIND_JOIN_REVIEW,
        JOIN_REVIEW_URI,
        "zQmaxhUVhRYpEsMxfAzJWuoHvzVKmcbKSmZ2JjG8kQaHzW1",
    ),
    (
        KIND_VETTING_REVIEW,
        VETTING_REVIEW_URI,
        "zQmcUNShH782uKh8YFnXsQ322vCS2Hs6U9tJv8SLABeKmBV",
    ),
    (
        KIND_MEMBER_ADMIT,
        MEMBERS_ADMIT,
        "zQmbYVQV8iyGc9pCgXB3mD1s7dYXRYEBmHNyHcQnEkeaH6C",
    ),
    (
        KIND_MEMBER_MAKE_MEMBERSHIP,
        MEMBERS_MAKE_MEMBERSHIP,
        "zQmYUPeQMYvpEnuBu9RCX4BSvQ5Nmpz4t2sRxKpyQpg6FVB",
    ),
    (
        KIND_STORAGE_CONFIG_CREATE,
        STORAGE_CREATE,
        "zQmbKUbMCxeKhULY9Ea5CL5SYQozDAE4ithNpnKx7jCQZAJ",
    ),
    (
        KIND_STORAGE_CONFIG_UPDATE,
        STORAGE_UPDATE,
        "zQmUr4boR7Uk2yrYFGFggoTMbcK33AVKA8DbZUKct3bbGqN",
    ),
    (
        KIND_STORAGE_CONFIG_RETIRE,
        STORAGE_RETIRE,
        "zQmW4jo3NSHqJGAeDeEPzJt1fUgdDAeAsur9ehhSCyA4bEh",
    ),
    (
        KIND_ROOM_STORAGE_ASSIGN,
        ROOM_STORAGE_ASSIGN,
        "zQmZWR9odGdRi5noLhZxgzSrNk3YRF5ZWH4JaNVBYMqMKja",
    ),
    (
        KIND_ROOM_STORAGE_MIGRATE,
        ROOM_STORAGE_MIGRATE,
        "zQmZamMHumTwGimMGYsuEGBoxvuYmEozzpkSStPjrZHrShX",
    ),
    (
        KIND_STORAGE_CONFIG_CREATE,
        STORAGE_CREATE_V0_2,
        "zQmSJcki3MwXF8HBUbPpwZScUm4HuzqomYhA825hYGLbmyN",
    ),
    (
        KIND_STORAGE_CONFIG_UPDATE,
        STORAGE_UPDATE_V0_2,
        "zQmbqMzuGGxuGv2dmp6qVDQnZTeGvJSYU93eg8JiaxdirAi",
    ),
    (
        KIND_STORAGE_CREDENTIAL_SET,
        STORAGE_CREDENTIAL_SET,
        "zQmTzhrbBfZEaijm2CMzMvNzeYzPBA4RW1DBJRWPTwJc3XL",
    ),
];

/// The template for `(kind, type_uri)`, if this build has one.
#[must_use]
pub fn template_for(kind: &str, type_uri: &str) -> Option<&'static Template> {
    TEMPLATES
        .iter()
        .find(|t| t.kind == kind && t.type_uri == type_uri)
}

/// A template as the JSON its digest is taken over.
#[must_use]
pub fn template_json(t: &Template) -> Value {
    let fields: Map<String, Value> = t
        .fields
        .iter()
        .map(|d| {
            (
                d.name.to_string(),
                json!({ "pointer": d.pointer, "format": d.format }),
            )
        })
        .collect();
    json!({
        "kind": t.kind,
        "typeUri": t.type_uri,
        "title": t.title,
        "effect": t.effect,
        "fields": fields,
    })
}

/// SHA-256 over the template's RFC 8785 canonical form, as a base58btc
/// multibase multihash — the `templateDigest` a renderer checks.
#[must_use]
pub fn template_digest(t: &Template) -> String {
    let canonical =
        serde_json_canonicalizer::to_string(&template_json(t)).expect("a template canonicalises");
    multihash(canonical.as_bytes())
}

/// SHA-256 of `bytes` as a base58btc multibase multihash (`0x12 0x20 …`).
#[must_use]
pub fn multihash(bytes: &[u8]) -> String {
    let mut mh = vec![0x12, 0x20];
    mh.extend_from_slice(&Sha256::digest(bytes));
    multibase::encode(multibase::Base::Base58Btc, mh)
}

/// `payloadDigest` on the wire: SHA-256 over the payload's RFC 8785
/// canonicalisation, as a multibase multihash — what an approver recomputes to
/// check that `payload` is what was parked.
pub fn payload_digest(payload: &Value) -> Result<String, vti_common::error::AppError> {
    let canonical = serde_json_canonicalizer::to_string(payload).map_err(|e| {
        vti_common::error::AppError::Internal(format!("payload JCS canonicalization failed: {e}"))
    })?;
    Ok(multihash(canonical.as_bytes()))
}

/// Render the `summary` member of an action for `(kind, type_uri)` over
/// `payload`: the template's prose, and each field's value read by its
/// pointer. A pointer into a member the payload does not carry reads `null`.
///
/// A pair this build has no template for — none is raised today — falls back
/// to one field holding the whole payload, so a renderer still shows exactly
/// what would run.
#[must_use]
pub fn render(kind: &str, type_uri: &str, payload: &Value) -> Value {
    let fallback;
    let t = match template_for(kind, type_uri) {
        Some(t) => t,
        None => {
            fallback = Template {
                kind: "unknown",
                type_uri: "unknown",
                title: "Run a parked operation",
                effect: "",
                fields: &[FieldDef {
                    name: "payload",
                    pointer: "",
                    format: "text",
                }],
            };
            &fallback
        }
    };
    let fields: Map<String, Value> = t
        .fields
        .iter()
        .map(|d| {
            (
                d.name.to_string(),
                json!({
                    "pointer": d.pointer,
                    "format": d.format,
                    "value": payload.pointer(d.pointer).cloned().unwrap_or(Value::Null),
                }),
            )
        })
        .collect();
    let mut summary = json!({
        "title": t.title,
        "fields": fields,
        "templateDigest": template_digest(t),
    });
    if !t.effect.is_empty() {
        summary["effect"] = json!(t.effect);
    }
    summary
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The pin: what approvers are shown for a kind cannot change without
    /// this table — and the console's copy — changing with it.
    #[test]
    fn every_template_matches_its_pin() {
        assert_eq!(TEMPLATES.len(), PINNED.len(), "one pin per template");
        let mut mismatched = Vec::new();
        for t in TEMPLATES {
            let pin = PINNED
                .iter()
                .find(|(k, u, _)| *k == t.kind && *u == t.type_uri)
                .unwrap_or_else(|| panic!("no pin for ({}, {})", t.kind, t.type_uri));
            let digest = template_digest(t);
            if digest != pin.2 {
                mismatched.push(format!("({}, {}) => {digest}", t.kind, t.type_uri));
            }
        }
        assert!(
            mismatched.is_empty(),
            "template digests changed — update PINNED and the console's copy:\n{}",
            mismatched.join("\n")
        );
    }

    /// The console holds its own copy of [`PINNED`] and refuses to render any
    /// action whose template it has no pin for, so a pin missing there makes
    /// that kind unapprovable from the console. Every server pin must appear
    /// in the console's table.
    #[test]
    fn the_console_pins_every_template() {
        let console = include_str!("../../admin-ui/src/lib/action-summary.ts");
        let mut missing = Vec::new();
        for (kind, type_uri, digest) in PINNED {
            // A template's digest covers its kind and type URI, so the digest
            // alone names the entry.
            if !console.contains(&format!("\"{digest}\"")) {
                missing.push(format!("({kind}, {type_uri}) => {digest}"));
            }
        }
        assert!(
            missing.is_empty(),
            "the console's PINNED_TEMPLATE_DIGESTS lacks:\n{}",
            missing.join("\n")
        );
    }

    /// The closed format set, and pointers a renderer can parse.
    #[test]
    fn every_field_uses_a_closed_format_and_a_valid_pointer() {
        const FORMATS: &[&str] = &["did", "capabilityList", "duration", "datetime", "text"];
        for t in TEMPLATES {
            for d in t.fields {
                assert!(FORMATS.contains(&d.format), "{}: {}", t.kind, d.format);
                assert!(
                    d.pointer.is_empty() || d.pointer.starts_with('/'),
                    "{}: {}",
                    t.kind,
                    d.pointer
                );
            }
            // Every placeholder names a field.
            for prose in [t.title, t.effect] {
                for part in prose.split('{').skip(1) {
                    let name = part.split('}').next().unwrap_or_default();
                    assert!(
                        t.fields.iter().any(|d| d.name == name),
                        "{}: placeholder {{{name}}} names no field",
                        t.kind
                    );
                }
            }
        }
    }

    /// The shared test vectors (`admin-ui/src/lib/action-summary.vectors.json`):
    /// the console runs the same file, so the two renderers agree on every one.
    #[test]
    fn the_shared_vectors_render_identically() {
        let vectors: Value = serde_json::from_str(include_str!(
            "../../admin-ui/src/lib/action-summary.vectors.json"
        ))
        .expect("vectors parse");
        for v in vectors.as_array().expect("an array") {
            let rendered = render(
                v["kind"].as_str().unwrap(),
                v["typeUri"].as_str().unwrap(),
                &v["payload"],
            );
            assert_eq!(rendered, v["summary"], "vector {}", v["name"]);
        }
    }
}
