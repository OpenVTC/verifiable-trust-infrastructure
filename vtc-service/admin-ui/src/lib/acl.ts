// The ACL, as signed Trust Task documents — the canonical `acl/*` family. The
// VTC serves it on no REST route: every verb is a document this browser signs
// with its console key and posts to `POST /v1/trust-tasks`.
//
// Administration is role-based (`docs/05-design-notes/vtc-admin-roles.md`):
// an entry holds an **administrative role** — a ceiling of capabilities —
// beside the community role its membership carries. The reads and the writes
// that state administrative authority speak `acl/*/0.2`, where every axis is
// explicit (`act`, `capabilities`, `approve`, `approveCapabilities`, `keys`)
// and the community role travels in `ext["org.openvtc"].communityRole`. The
// community-role move (`acl/change-role/0.1`) and the removal
// (`acl/revoke/0.1`) stay at 0.1.

import { postSignedRead } from "./api";
import { postSignedWithStepUp, type ConfirmGesture } from "./signed-act";

export const ACL_LIST_TASK = "https://trusttasks.org/spec/acl/list/0.2";
export const ACL_SHOW_TASK = "https://trusttasks.org/spec/acl/show/0.2";
export const ACL_GRANT_TASK = "https://trusttasks.org/spec/acl/grant/0.2";
export const ACL_UPDATE_TASK = "https://trusttasks.org/spec/acl/update/0.2";
export const ACL_CHANGE_ROLE_TASK = "https://trusttasks.org/spec/acl/change-role/0.1";
export const ACL_REVOKE_TASK = "https://trusttasks.org/spec/acl/revoke/0.1";

// ── the model, as the wire states it (`acl/_shared/0.2`) ─────────────────

/** An explicit act or approve scope. A community has no contexts. */
export type AuthorityScope = { scope: "all" } | { scope: "none" };

/** A capability, optionally qualified by a resource. */
export interface CapabilityGrant {
  capability: string;
  resource?: string;
  additive?: boolean;
}

/** The capabilities an entry holds (or may approve). Never an empty list. */
export type CapabilityScope =
  | { scope: "ceiling" }
  | { scope: "none" }
  | { scope: "listed"; grants: CapabilityGrant[] };

/** One `acl/_shared/0.2` AclEntry, as this community renders it. */
export interface AclEntry {
  subject: string;
  /** The administrative role, or `member` for none. */
  role: string;
  act: AuthorityScope;
  keys: { scope: "none" | "all" };
  capabilities: CapabilityScope;
  approve?: AuthorityScope;
  approveCapabilities?: CapabilityScope;
  label?: string;
  delegatedBy?: string;
  createdAt?: string;
  createdBy?: string;
  updatedAt?: string;
  updatedBy?: string;
  expiresAt?: string;
  ext?: {
    "org.openvtc"?: {
      communityRole?: string;
      delegationReview?: { granter: string; deadline: string };
    };
  };
}

export interface AclListResponse {
  entries: AclEntry[];
  truncated: boolean;
  cursor?: string;
}

/** `acl/list/0.2` payload. `resource` needs a `direction`. */
export interface AclListFilter {
  role?: string;
  capability?: string;
  resource?: string;
  direction?: "actingIn" | "subtree" | "any";
  subjectPrefix?: string;
  pageSize?: number;
  cursor?: string;
}

/** `acl/grant/0.2` payload: the entry, with no server-owned provenance. */
export interface AclGrantRequest {
  entry: {
    subject: string;
    role: string;
    act: AuthorityScope;
    keys: { scope: "none" };
    capabilities: CapabilityScope;
    approve: AuthorityScope;
    approveCapabilities?: CapabilityScope;
    label?: string;
    expiresAt?: string;
    ext?: { "org.openvtc": { communityRole: string } };
  };
  reason?: string;
}

/** `acl/update/0.2` payload: what to replace, nothing else. */
export interface AclUpdateRequest {
  subject: string;
  capabilities?: CapabilityScope;
  approve?: AuthorityScope;
  approveCapabilities?: CapabilityScope;
  label?: string | null;
  expiresAt?: string | null;
  reason?: string;
}

// ── the registry (`vtc-admin-roles.md` §4, §6.1) ─────────────────────────

/** What kind of resource a capability may be narrowed to, if any. */
export type QualifierKind = "git-ns" | "git-repo" | "policy" | "criterion";

export interface CapabilityInfo {
  id: string;
  gates: string;
  /** Holding it lets you create authority (granting needs other holders'
   *  consent, VTI-APV-018). */
  conferring: boolean;
  qualifiers: QualifierKind[];
}

export const CAPABILITIES: CapabilityInfo[] = [
  { id: "vtc.roles.assign", gates: "granting and removing roles and capabilities", conferring: true, qualifiers: ["git-ns", "git-repo", "policy", "criterion"] },
  { id: "vtc.approvals.admin", gates: "the approvals rule list", conferring: true, qualifiers: [] },
  { id: "vtc.policy.admin", gates: "uploading and activating policy", conferring: true, qualifiers: ["policy"] },
  { id: "vtc.config.admin", gates: "configuration (patch, import, reload, restart)", conferring: true, qualifiers: [] },
  { id: "vtc.backup.export", gates: "backup export", conferring: false, qualifiers: [] },
  { id: "vtc.backup.restore", gates: "backup import", conferring: true, qualifiers: [] },
  { id: "vtc.audit.read", gates: "reading and verifying the audit log", conferring: false, qualifiers: [] },
  { id: "vtc.did.admin", gates: "registering the community DID", conferring: true, qualifiers: [] },
  { id: "vtc.members.manage", gates: "suspending, removing and purging members", conferring: false, qualifiers: [] },
  { id: "vtc.join.decide", gates: "join review decisions", conferring: false, qualifiers: [] },
  { id: "vtc.invitations.manage", gates: "issuing and revoking invitations", conferring: false, qualifiers: [] },
  { id: "vtc.credentials.issue", gates: "issuing endorsements and personhood", conferring: false, qualifiers: [] },
  { id: "vtc.credentials.revoke", gates: "revoking endorsements and personhood", conferring: false, qualifiers: [] },
  { id: "vtc.vetting.manage", gates: "vetters, auto-grant and vetting review", conferring: false, qualifiers: ["criterion"] },
  { id: "vtc.surface.admin", gates: "profile, branding, website, schemas, join criteria", conferring: false, qualifiers: [] },
  { id: "vtc.registry.admin", gates: "registry sync and recognition", conferring: false, qualifiers: [] },
  { id: "vtc.sessions.revoke", gates: "revoking others' sessions and console keys", conferring: false, qualifiers: [] },
  { id: "git.ns.admin", gates: "administering a git namespace", conferring: true, qualifiers: ["git-ns"] },
  { id: "git.repo.manage", gates: "creating, adopting, archiving and transferring repositories", conferring: false, qualifiers: ["git-ns", "git-repo"] },
];

export interface AdminRoleInfo {
  id: string;
  title: string;
  /** The capabilities the role may hold. */
  ceiling: string[];
  /** Its ceiling is held only at a resource (`repo-manager`). */
  qualifiedOnly?: boolean;
  /** Acts nowhere; approves only (`approver`). */
  approveOnly?: boolean;
}

const VTC_CAPABILITIES = CAPABILITIES.filter((c) => c.id.startsWith("vtc.")).map((c) => c.id);

export const ADMIN_ROLES: AdminRoleInfo[] = [
  {
    id: "community-admin",
    title: "Community administrator",
    ceiling: [...VTC_CAPABILITIES, "git.ns.admin", "git.repo.manage"],
  },
  {
    id: "moderator",
    title: "Moderator",
    ceiling: ["vtc.members.manage", "vtc.join.decide", "vtc.invitations.manage"],
  },
  { id: "vetting-lead", title: "Vetting lead", ceiling: ["vtc.vetting.manage"] },
  {
    id: "repo-manager",
    title: "Repository manager",
    ceiling: ["git.repo.manage", "git.ns.admin"],
    qualifiedOnly: true,
  },
  {
    id: "credential-officer",
    title: "Credential officer",
    ceiling: ["vtc.credentials.issue", "vtc.credentials.revoke"],
  },
  { id: "auditor", title: "Auditor", ceiling: ["vtc.audit.read"] },
  { id: "approver", title: "Approver (approves only)", ceiling: [], approveOnly: true },
];

/** The 0.2 role string for an entry holding no administrative role. */
export const NO_ADMIN_ROLE = "member";

export const capabilityInfo = (id: string): CapabilityInfo | undefined =>
  CAPABILITIES.find((c) => c.id === id);

export const adminRoleInfo = (id: string): AdminRoleInfo | undefined =>
  ADMIN_ROLES.find((r) => r.id === id);

/** `cap` or `cap@resource`. */
export const grantLabel = (g: CapabilityGrant): string =>
  g.resource ? `${g.capability}@${g.resource}` : g.capability;

/**
 * What an entry may administer, in words — never one word for two different
 * authorities (the #746 class). "everything" only for a community
 * administrator acting with its full ceiling; "nothing" for an entry with no
 * administrative role or no capabilities; "approves only" for one that may
 * not act.
 */
export function describeAuthority(e: AclEntry): string {
  if (e.role === NO_ADMIN_ROLE) return "nothing";
  if (e.act.scope !== "all") {
    return e.approve?.scope === "all" ? "approves only" : "nothing";
  }
  switch (e.capabilities.scope) {
    case "none":
      return "nothing";
    case "ceiling":
      if (e.role === "community-admin") return "everything";
      return (adminRoleInfo(e.role)?.ceiling ?? []).join(", ") || "nothing";
    case "listed":
      return e.capabilities.grants.map(grantLabel).join(", ");
  }
}

/** The community role an entry's membership carries. */
export const communityRoleOf = (e: AclEntry): string =>
  e.ext?.["org.openvtc"]?.communityRole ?? "member";

// ── the verbs ────────────────────────────────────────────────────────────

/** One page of the entries. */
export const fetchAclPage = (filter: AclListFilter = {}): Promise<AclListResponse> =>
  postSignedRead<AclListResponse>(ACL_LIST_TASK, filter);

/** The longest walk [`fetchAllAcl`] makes before it says the list is too long. */
const MAX_ACL_PAGES = 100;

/**
 * Every entry, following the cursor to the end. A page that is truncated with
 * no cursor, or a list longer than the walk allows, is an error rather than a
 * partial list that reads as complete.
 */
export async function fetchAllAcl(filter: AclListFilter = {}): Promise<AclEntry[]> {
  const out: AclEntry[] = [];
  let cursor: string | undefined;
  for (let page = 0; page < MAX_ACL_PAGES; page++) {
    const body = await fetchAclPage({ ...filter, pageSize: 200, ...(cursor ? { cursor } : {}) });
    out.push(...body.entries);
    if (!body.truncated) return out;
    if (!body.cursor) {
      throw new Error("acl/list answered a truncated page with no cursor");
    }
    cursor = body.cursor;
  }
  throw new Error(`the ACL is longer than ${MAX_ACL_PAGES} pages; narrow the filter`);
}

/**
 * The `acl/grant/0.2` payload for a subject, an administrative role, and —
 * optionally — the capabilities to narrow it to (`cap` / `cap@resource`).
 * Blank optional members are omitted, never null.
 */
export function grantRequest(args: {
  subject: string;
  role: string;
  capabilities?: string[];
  approve?: boolean;
  label?: string;
  expiresAt?: string;
}): AclGrantRequest {
  const info = adminRoleInfo(args.role);
  const approveOnly = !!info?.approveOnly;
  const approve = approveOnly || !!args.approve;
  const listed = (args.capabilities ?? []).filter((c) => c.trim() !== "");
  const capabilities: CapabilityScope =
    args.role === NO_ADMIN_ROLE || approveOnly
      ? { scope: "none" }
      : listed.length > 0
        ? {
            scope: "listed",
            grants: listed.map((c) => {
              const at = c.indexOf("@");
              return at < 0
                ? { capability: c }
                : { capability: c.slice(0, at), resource: c.slice(at + 1) };
            }),
          }
        : { scope: "ceiling" };
  return {
    entry: {
      subject: args.subject,
      role: args.role,
      act: { scope: args.role === NO_ADMIN_ROLE || approveOnly ? "none" : "all" },
      keys: { scope: "none" },
      capabilities,
      approve: { scope: approve ? "all" : "none" },
      ...(approve ? { approveCapabilities: { scope: "ceiling" as const } } : {}),
      ...(args.label ? { label: args.label } : {}),
      ...(args.expiresAt ? { expiresAt: args.expiresAt } : {}),
    },
  };
}

/**
 * Grant (or re-state) an entry. Widening administrative authority may need a
 * passkey gesture, and granting an authority-conferring capability is parked
 * for its other holders' approval (VTI-APV-018) — thrown as a `ParkedAction`
 * (`lib/parked-action.ts`).
 */
export async function grantAcl(
  req: AclGrantRequest,
  confirmGesture: ConfirmGesture,
): Promise<AclEntry> {
  const body = await postSignedWithStepUp<{ entry: AclEntry }>(
    ACL_GRANT_TASK,
    req,
    confirmGesture,
  );
  return body.entry;
}

/**
 * Amend an entry: its capabilities, approve authority, label or expiry. A
 * narrowing of an administrator takes a passkey gesture bound to it, and
 * taking an authority-conferring capability away another holder's approval
 * (VTI-APV-019).
 */
export async function updateAcl(
  req: AclUpdateRequest,
  confirmGesture: ConfirmGesture,
): Promise<AclEntry> {
  const body = await postSignedWithStepUp<{ entry: AclEntry }>(
    ACL_UPDATE_TASK,
    req,
    confirmGesture,
  );
  return body.entry;
}

/**
 * Change an entry's **community** role (member, moderator, issuer, admin) —
 * with the administrative role it implies. `fromRole` is a compare-and-swap
 * guard. Promotion to `admin` confers `vtc.roles.assign` and is parked for
 * other administrators' approval; a demotion from it needs a gesture too
 * (VTI-APV-019).
 */
export async function changeAclRole(
  args: { subject: string; fromRole: string; toRole: string; reason?: string },
  confirmGesture: ConfirmGesture,
): Promise<{ subject: string; role: string }> {
  const body = await postSignedWithStepUp<{ entry: { subject: string; role: string } }>(
    ACL_CHANGE_ROLE_TASK,
    args,
    confirmGesture,
  );
  return body.entry;
}

/**
 * Remove an entry outright. Removing an administrator needs a passkey gesture
 * bound to this removal, and taking authority-conferring capabilities away
 * needs another holder's approval (VTI-APV-019), so it is parked and thrown
 * as a `ParkedAction`.
 */
export async function revokeAcl(subject: string, confirmGesture: ConfirmGesture): Promise<void> {
  await postSignedWithStepUp<{ entry: AclEntry | null }>(
    ACL_REVOKE_TASK,
    { subject },
    confirmGesture,
  );
}
