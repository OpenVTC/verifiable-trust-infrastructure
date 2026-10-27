// The community's groups, as a member reads and joins them (`vtc/groups/*`).
//
// Signed by this browser's portal key for the member, which the member
// delegated `vtc/groups` to at sign-in, exactly as the directory pages are.
// Every answer is the member's own view: a group they may not see is absent,
// and its members are listed only where the group shows them.

import type {
  GroupJoinRequest,
  GroupListResponse,
  GroupMember,
  GroupMembersListResponse,
  GroupShowResponse,
} from "@/lib/wire-types";

import { send } from "./directory-api";

export const GROUPS_LIST_TASK = "https://trusttasks.org/spec/vtc/groups/list/0.1";
export const GROUPS_SHOW_TASK = "https://trusttasks.org/spec/vtc/groups/show/0.1";
export const GROUPS_MEMBERS_LIST_TASK = "https://trusttasks.org/spec/vtc/groups/members/list/0.1";
export const GROUPS_JOIN_TASK = "https://trusttasks.org/spec/vtc/groups/join/0.1";
export const GROUPS_LEAVE_TASK = "https://trusttasks.org/spec/vtc/groups/leave/0.1";

export const listGroups = () => send<GroupListResponse>(GROUPS_LIST_TASK, { limit: 100 });
export const showGroup = (groupId: string) =>
  send<GroupShowResponse>(GROUPS_SHOW_TASK, { groupId });
export const listMembers = (groupId: string) =>
  send<GroupMembersListResponse>(GROUPS_MEMBERS_LIST_TASK, { groupId, limit: 100 });

export interface JoinAnswer {
  outcome: "joined" | "requested" | "optOutWithdrawn";
  member?: GroupMember;
  request?: GroupJoinRequest;
}

export const joinGroup = (groupId: string, message?: string) =>
  send<JoinAnswer>(GROUPS_JOIN_TASK, { groupId, ...(message ? { message } : {}) });
export const leaveGroup = (groupId: string) =>
  send<{ state: string }>(GROUPS_LEAVE_TASK, { groupId });
