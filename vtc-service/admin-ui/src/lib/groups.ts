// The community's groups, administered — `vtc/groups/*` (docs/03-vtc/groups.md).
//
// Every read is answered for the signer's own standing: a group they may not
// see is absent, and its members are listed only where the group shows them.
// Managers are appointed by an access-control grant (`managers/*`), never by a
// field of the group. Each group's identity is held by the community's VTA;
// nothing here sees a key or a credential.

import { postSignedRead, postSignedTrustTask } from "./api";
import { postSignedWithStepUp, type ConfirmGesture } from "./signed-act";
import type {
  Group,
  GroupBinding,
  GroupBindingsListResponse,
  GroupBindingsRemoveResponse,
  GroupCreatePayload,
  GroupJoinRequest,
  GroupListResponse,
  GroupManagersResponse,
  GroupMember,
  GroupMembersListResponse,
  GroupRequestsListResponse,
  GroupShowResponse,
  GroupUpdatePayload,
} from "./wire-types";

export const GROUPS_LIST_TASK = "https://trusttasks.org/spec/vtc/groups/list/0.1";
export const GROUPS_SHOW_TASK = "https://trusttasks.org/spec/vtc/groups/show/0.1";
export const GROUPS_CREATE_TASK = "https://trusttasks.org/spec/vtc/groups/create/0.1";
export const GROUPS_UPDATE_TASK = "https://trusttasks.org/spec/vtc/groups/update/0.1";
export const GROUPS_DELETE_TASK = "https://trusttasks.org/spec/vtc/groups/delete/0.1";
export const GROUPS_MEMBERS_LIST_TASK = "https://trusttasks.org/spec/vtc/groups/members/list/0.1";
export const GROUPS_MEMBERS_ADD_TASK = "https://trusttasks.org/spec/vtc/groups/members/add/0.1";
export const GROUPS_MEMBERS_REMOVE_TASK = "https://trusttasks.org/spec/vtc/groups/members/remove/0.1";
export const GROUPS_REQUESTS_LIST_TASK = "https://trusttasks.org/spec/vtc/groups/requests/list/0.1";
export const GROUPS_REQUESTS_DECIDE_TASK = "https://trusttasks.org/spec/vtc/groups/requests/decide/0.1";
export const GROUPS_MANAGERS_ADD_TASK = "https://trusttasks.org/spec/vtc/groups/managers/add/0.1";
export const GROUPS_MANAGERS_REMOVE_TASK = "https://trusttasks.org/spec/vtc/groups/managers/remove/0.1";
export const GROUPS_BINDINGS_ADD_TASK = "https://trusttasks.org/spec/vtc/groups/bindings/add/0.1";
export const GROUPS_BINDINGS_REMOVE_TASK = "https://trusttasks.org/spec/vtc/groups/bindings/remove/0.1";
export const GROUPS_BINDINGS_LIST_TASK = "https://trusttasks.org/spec/vtc/groups/bindings/list/0.1";

/** The capability that creates groups and manages every one. */
export const GROUPS_MANAGE = "vtc.groups.manage";

/** `groups/list`'s largest page (`list-limits.json`). */
const PAGE = 200;
/** How many pages a full read follows before it stops. */
const MAX_PAGES = 20;

export type Audience = "admins" | "groupMembers" | "members";
export type JoinPolicy = "closed" | "request" | "open";

export const AUDIENCES: { id: Audience; label: string }[] = [
  { id: "admins", label: "Its managers only" },
  { id: "groupMembers", label: "Its members and managers" },
  { id: "members", label: "Every member" },
];

export const JOIN_POLICIES: { id: JoinPolicy; label: string; help: string }[] = [
  { id: "closed", label: "Closed", help: "Its managers add its members." },
  { id: "request", label: "By request", help: "Members ask; a manager decides." },
  { id: "open", label: "Open", help: "Members join themselves." },
];

/** Whether `inner` is no wider than `outer`: `showMembers` never exceeds `visibility`. */
export function audienceWithin(inner: Audience, outer: Audience): boolean {
  const rank = { admins: 0, groupMembers: 1, members: 2 } as const;
  return rank[inner] <= rank[outer];
}

/** Every group the caller may see, a page at a time. */
export async function listGroups(): Promise<GroupListResponse["items"]> {
  const out: GroupListResponse["items"] = [];
  let cursor: string | undefined;
  for (let i = 0; i < MAX_PAGES; i++) {
    const page = await postSignedRead<GroupListResponse>(GROUPS_LIST_TASK, {
      limit: PAGE,
      ...(cursor ? { cursor } : {}),
    });
    out.push(...page.items);
    if (typeof page.nextCursor !== "string") break;
    cursor = page.nextCursor;
  }
  return out;
}

export async function showGroup(groupId: string): Promise<GroupShowResponse> {
  return postSignedRead<GroupShowResponse>(GROUPS_SHOW_TASK, { groupId });
}

export async function createGroup(payload: GroupCreatePayload): Promise<Group> {
  const body = await postSignedTrustTask<{ group: Group }>(GROUPS_CREATE_TASK, payload);
  return body.group;
}

export async function updateGroup(payload: GroupUpdatePayload): Promise<Group> {
  const body = await postSignedTrustTask<{ group: Group }>(GROUPS_UPDATE_TASK, payload);
  return body.group;
}

export async function deleteGroup(groupId: string, reason: string): Promise<void> {
  await postSignedTrustTask(GROUPS_DELETE_TASK, { groupId, reason });
}

/** A group's members, every page. */
export async function listGroupMembers(groupId: string): Promise<GroupMember[]> {
  const out: GroupMember[] = [];
  let cursor: string | undefined;
  for (let i = 0; i < MAX_PAGES; i++) {
    const page = await postSignedRead<GroupMembersListResponse>(GROUPS_MEMBERS_LIST_TASK, {
      groupId,
      limit: PAGE,
      ...(cursor ? { cursor } : {}),
    });
    out.push(...page.items);
    if (typeof page.nextCursor !== "string") break;
    cursor = page.nextCursor;
  }
  return out;
}

export async function addGroupMember(groupId: string, entryId: string): Promise<GroupMember> {
  const body = await postSignedTrustTask<{ member: GroupMember }>(GROUPS_MEMBERS_ADD_TASK, {
    groupId,
    entryId,
  });
  return body.member;
}

export async function removeGroupMember(groupId: string, entryId: string): Promise<void> {
  await postSignedTrustTask(GROUPS_MEMBERS_REMOVE_TASK, { groupId, entryId });
}

/** Pending requests to the groups the caller manages, or to one of them. */
export async function listGroupRequests(
  groupId?: string,
): Promise<GroupRequestsListResponse["items"]> {
  const page = await postSignedRead<GroupRequestsListResponse>(GROUPS_REQUESTS_LIST_TASK, {
    limit: PAGE,
    ...(groupId ? { groupId } : {}),
  });
  return page.items;
}

export async function decideGroupRequest(
  requestId: string,
  decision: "approve" | "decline",
  reason?: string,
): Promise<GroupJoinRequest> {
  const body = await postSignedTrustTask<{ request: GroupJoinRequest }>(
    GROUPS_REQUESTS_DECIDE_TASK,
    { requestId, decision, ...(reason ? { reason } : {}) },
  );
  return body.request;
}

export async function addGroupManager(groupId: string, entryId: string): Promise<string[]> {
  const body = await postSignedTrustTask<GroupManagersResponse>(GROUPS_MANAGERS_ADD_TASK, {
    groupId,
    entryId,
  });
  return body.managers;
}

export async function removeGroupManager(groupId: string, entryId: string): Promise<string[]> {
  const body = await postSignedTrustTask<GroupManagersResponse>(GROUPS_MANAGERS_REMOVE_TASK, {
    groupId,
    entryId,
  });
  return body.managers;
}

// ── Bindings (`vtc/groups/bindings/*`): room bindings only ─────────────────

/** A room binding's terms, as `bindings/add` takes them. */
export interface RoomBindingSpec {
  kind: "room";
  roomId: string;
  actions: ("read" | "write" | "curate")[];
  /** Whole days, as an ISO 8601 duration: `P30D`. */
  validFor: string;
}

/** A group's bindings — to its managers only. */
export async function listGroupBindings(groupId: string): Promise<GroupBinding[]> {
  const body = await postSignedRead<GroupBindingsListResponse>(GROUPS_BINDINGS_LIST_TASK, {
    groupId,
  });
  return body.items;
}

/** Bind a group to a community room, after the requester's bound gesture. */
export async function addGroupBinding(
  groupId: string,
  binding: RoomBindingSpec,
  reason: string,
  confirmGesture: ConfirmGesture,
): Promise<GroupBinding> {
  const body = await postSignedWithStepUp<{ binding: GroupBinding }>(
    GROUPS_BINDINGS_ADD_TASK,
    { groupId, binding, reason },
    confirmGesture,
  );
  return body.binding;
}

/** End a binding, after the requester's bound gesture: `removing` while what only it
 *  covered is withdrawn, `removed` once nothing was. */
export async function removeGroupBinding(
  groupId: string,
  bindingId: string,
  reason: string,
  confirmGesture: ConfirmGesture,
): Promise<GroupBindingsRemoveResponse> {
  return postSignedWithStepUp<GroupBindingsRemoveResponse>(
    GROUPS_BINDINGS_REMOVE_TASK,
    { groupId, bindingId, reason },
    confirmGesture,
  );
}
