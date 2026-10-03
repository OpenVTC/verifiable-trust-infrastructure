// The community's administrative role vocabulary, as signed Trust Task
// documents — `vtc/roles/{list,show,define,delete}/0.1`
// (`docs/05-design-notes/vtc-admin-roles.md` §6.2).
//
// A role is a ceiling: the capabilities an entry holding it may hold, and the
// capabilities it may approve. Built-in roles are fixed by the VTC; a
// community defines more. The reads answer any administrator. Defining,
// replacing and deleting take `vtc.roles.assign` **and** `vtc.approvals.admin`,
// the requester's passkey gesture bound to the document, and the approval of
// other holders of both — so a write is parked as an action and thrown as a
// `ParkedAction` (`lib/parked-action.ts`), which the toast shows as sent for
// approval.

import { postSignedRead } from "./api";
import { postSignedWithStepUp, type ConfirmGesture } from "./signed-act";

export const ROLES_LIST_TASK = "https://trusttasks.org/spec/vtc/roles/list/0.1";
export const ROLES_SHOW_TASK = "https://trusttasks.org/spec/vtc/roles/show/0.1";
export const ROLES_DEFINE_TASK = "https://trusttasks.org/spec/vtc/roles/define/0.1";
export const ROLES_DELETE_TASK = "https://trusttasks.org/spec/vtc/roles/delete/0.1";

/** A capability, optionally qualified by a resource (`acl/_shared/0.2`). */
export interface CapabilityRef {
  capability: string;
  resource?: string;
}

/** `vtc/roles/_shared/0.1` RoleDefinition. */
export interface RoleDefinition {
  name: string;
  builtIn: boolean;
  description?: string;
  ceiling: CapabilityRef[];
  approveScope: CapabilityRef[];
  createdAt?: string;
  createdBy?: string;
  updatedAt?: string;
  updatedBy?: string;
}

export interface RoleDefineRequest {
  name: string;
  description?: string;
  ceiling: CapabilityRef[];
  approveScope: CapabilityRef[];
  replaces?: boolean;
  reason?: string;
}

/** The capabilities whoever defines or deletes a role must hold. */
export const ROLE_ADMIN_CAPABILITIES = ["vtc.roles.assign", "vtc.approvals.admin"] as const;

/** A role name as `vtc/roles/_shared/0.1` `RoleName` admits it. */
export const ROLE_NAME_PATTERN = /^[a-z][a-z0-9-]{0,63}$/;

export const capRefLabel = (r: CapabilityRef): string =>
  r.resource ? `${r.capability}@${r.resource}` : r.capability;

export async function listRoles(includeBuiltIn = true): Promise<RoleDefinition[]> {
  const body = await postSignedRead<{ roles: RoleDefinition[] }>(ROLES_LIST_TASK, {
    includeBuiltIn,
  });
  return body.roles;
}

export function showRole(name: string): Promise<{ role: RoleDefinition; holders?: number }> {
  return postSignedRead(ROLES_SHOW_TASK, { name });
}

/** Define (or, with `replaces`, replace) a custom role. Parked for approval. */
export async function defineRole(
  req: RoleDefineRequest,
  confirmGesture: ConfirmGesture,
): Promise<RoleDefinition> {
  const body = await postSignedWithStepUp<{ role: RoleDefinition }>(
    ROLES_DEFINE_TASK,
    req,
    confirmGesture,
  );
  return body.role;
}

/** Delete a custom role nobody holds. Parked for approval. */
export async function deleteRole(
  name: string,
  reason: string | undefined,
  confirmGesture: ConfirmGesture,
): Promise<void> {
  await postSignedWithStepUp<{ deleted: string }>(
    ROLES_DELETE_TASK,
    { name, ...(reason ? { reason } : {}) },
    confirmGesture,
  );
}
