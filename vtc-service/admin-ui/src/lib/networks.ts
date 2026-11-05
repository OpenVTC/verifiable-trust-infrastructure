// The community's memberships of Verifiable Trust Networks — `vtc/networks/*/0.2`
// (docs/03-vtc/networks.md).
//
// A network may list this community without asking (VTI-VTN-010); the listing becomes
// membership only when an administrator here acknowledges it (VTI-VTN-013). `join` is that
// acknowledgement, and the credential exchange: the community verifies the network's
// listing of it, registers a group for each of the network's roles, signs the
// acknowledgement of the network's membership offer, and verifies the grant the network
// answers with. `repudiate` rejects a listing; `leave` departs by repudiating the grant.
//
// Each write makes the community sign a statement to a third party, so the VTC asks for
// the administrator's step-up bound to the one document. It runs every check that would
// refuse the act first — the network answers as the DID named, it lists this community,
// every role it requires has a group — so a join that would fail costs no gesture.

import { postSignedRead } from "./api";
import { postSignedWithStepUp, type ConfirmGesture } from "./signed-act";
import type {
  NetworkJoinPayload,
  NetworkJoinResponse,
  NetworkLeaveResponse,
  NetworkMembership,
  NetworkRepudiateResponse,
  NetworkRoleAssignment,
  NetworksListResponse,
  NetworksShowResponse,
} from "./wire-types";

export const NETWORKS_LIST_TASK = "https://trusttasks.org/spec/vtc/networks/list/0.2";
export const NETWORKS_SHOW_TASK = "https://trusttasks.org/spec/vtc/networks/show/0.2";
export const NETWORKS_JOIN_TASK = "https://trusttasks.org/spec/vtc/networks/join/0.2";
export const NETWORKS_LEAVE_TASK = "https://trusttasks.org/spec/vtc/networks/leave/0.2";
export const NETWORKS_REPUDIATE_TASK = "https://trusttasks.org/spec/vtc/networks/repudiate/0.2";

/** Where the console mounts this page, under its `/admin` base. A network's
 *  invitation links here as `/admin/networks?join=<url>&network=<did>`. */
export const NETWORKS_PATH = "/networks";

export const networkKeys = {
  all: ["networks"] as const,
  list: ["networks", "list"] as const,
  show: (did: string) => ["networks", "show", did] as const,
};

/** `list`'s largest page. */
const PAGE = 100;
/** How many pages a full read follows before it stops. */
const MAX_PAGES = 20;

/** Every membership, a page at a time. */
export async function listNetworks(): Promise<NetworkMembership[]> {
  const out: NetworkMembership[] = [];
  let cursor: string | undefined;
  for (let i = 0; i < MAX_PAGES; i++) {
    const page = await postSignedRead<NetworksListResponse>(NETWORKS_LIST_TASK, {
      limit: PAGE,
      ...(cursor ? { cursor } : {}),
    });
    out.push(...page.items);
    if (!page.nextCursor) break;
    cursor = page.nextCursor;
  }
  return out;
}

export async function showNetwork(network: string): Promise<NetworkMembership> {
  return (await postSignedRead<NetworksShowResponse>(NETWORKS_SHOW_TASK, { network })).membership;
}

export async function joinNetwork(
  payload: NetworkJoinPayload,
  gesture: ConfirmGesture,
): Promise<NetworkMembership> {
  return (await postSignedWithStepUp<NetworkJoinResponse>(NETWORKS_JOIN_TASK, payload, gesture))
    .membership;
}

export async function leaveNetwork(
  network: string,
  reason: string,
  gesture: ConfirmGesture,
): Promise<NetworkMembership> {
  const payload = { network, ...(reason.trim() ? { reason: reason.trim() } : {}) };
  return (await postSignedWithStepUp<NetworkLeaveResponse>(NETWORKS_LEAVE_TASK, payload, gesture))
    .membership;
}

export async function repudiateNetwork(
  url: string,
  network: string,
  reason: string,
  gesture: ConfirmGesture,
): Promise<NetworkMembership> {
  const payload = { url, network, ...(reason.trim() ? { reason: reason.trim() } : {}) };
  return (
    await postSignedWithStepUp<NetworkRepudiateResponse>(NETWORKS_REPUDIATE_TASK, payload, gesture)
  ).membership;
}

/** What a network's invitation link carries: `?join=<network url>&network=<did>`. */
export function invitationOf(params: URLSearchParams): { url: string; network: string } | null {
  const url = params.get("join")?.trim() ?? "";
  const network = params.get("network")?.trim() ?? "";
  return url || network ? { url, network } : null;
}

/** A role row as the form holds it. */
export interface RoleRow {
  role: string;
  groupId: string;
}

const ROLE = /^[a-z0-9_-]{1,64}$/;
const DID = /^did:[a-z0-9]+:.+$/;

/** What is wrong with the form, field by field; empty when it can be sent. */
export function joinDraftErrors(
  url: string,
  network: string,
  rows: RoleRow[],
): Partial<Record<"url" | "network" | "roles", string>> {
  const out: Partial<Record<"url" | "network" | "roles", string>> = {};
  try {
    const u = new URL(url.trim());
    if (u.protocol !== "https:") out.url = "The network's URL must be https://.";
  } catch {
    out.url = "The network's URL, as its administrators gave it.";
  }
  if (!DID.test(network.trim())) out.network = "The network's DID, as its invitation names it.";
  const named = rows.filter((r) => r.role.trim() || r.groupId);
  if (named.some((r) => !ROLE.test(r.role.trim()))) {
    out.roles = "A role is lowercase letters, digits, - and _.";
  } else if (named.some((r) => !r.groupId)) {
    out.roles = "Pick a group for every role.";
  } else if (new Set(named.map((r) => r.role.trim())).size !== named.length) {
    out.roles = "Each role once.";
  }
  return out;
}

/** The `join` payload the form builds. Rows left blank are dropped. */
export function joinPayload(url: string, network: string, rows: RoleRow[]): NetworkJoinPayload {
  const groups: NetworkRoleAssignment[] = rows
    .filter((r) => r.role.trim() && r.groupId)
    .map((r) => ({ role: r.role.trim(), groupId: r.groupId }));
  return {
    url: url.trim().replace(/\/+$/, ""),
    network: network.trim(),
    ...(groups.length ? { groups } : {}),
  };
}

/** The role a `roleUnassigned` refusal names: the network requires a group for it. */
export function unassignedRoleOf(err: unknown): string | null {
  const e = err as { code?: unknown; details?: { role?: unknown } } | null;
  if (typeof e?.code !== "string" || !e.code.endsWith(":roleUnassigned")) return null;
  return typeof e.details?.role === "string" ? e.details.role : null;
}

/** What a refusal of a network write means, in words an administrator can act on. */
export function networkRefusal(err: unknown): string | null {
  const code = (err as { code?: unknown } | null)?.code;
  if (typeof code !== "string") return null;
  const local = code.slice(code.lastIndexOf(":") + 1);
  switch (local) {
    case "notListed":
      return "That network does not list this community yet. Ask its administrators to list (invite) it first.";
    case "networkMismatch":
      return "The network at that URL answers as a different DID. Check both against the invitation.";
    case "unknownGroup":
      return "A group picked has no identity of its own yet. Pick a group with a DID.";
    case "networkRefused":
      return "The network refused the request.";
    case "isMember":
      return "This community is a member of that network: leave it instead.";
    case "notMember":
      return "This community is not a member of that network.";
    default:
      return null;
  }
}

export const STATE_LABEL: Record<NetworkMembership["state"], string> = {
  acknowledged: "Member",
  repudiated: "Listing rejected",
  departed: "Left",
};
