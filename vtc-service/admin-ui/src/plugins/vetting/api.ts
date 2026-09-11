// Vetting admin API — what the vetting panels, the join-request detail and the
// dashboard read and write.
//
// Three of these routes carry a Trust Task binding and are called with it:
// grant, resend, and the vetter listing. The rest are admin REST the daemon
// mounts with no binding, because no published task describes them — the grant
// listing, automatic grants, withdrawal notices, a join request's vetting facts
// and community branding — so they go through the `*Exempt` helpers instead of
// borrowing a task URI that names something else.

import {
  deleteJson,
  getJson,
  getJsonExempt,
  postJson,
  putJsonExempt,
} from "@/lib/api";
import type {
  AutoGrantConfig,
  AutoGrantStatus,
  CommunityBranding,
  JoinManifest,
  JoinRequestsPage,
  ManifestCriterion,
  JoinRequestVettingResponse,
  MemberRow,
  MembersPage,
  VetterGrantList,
  VetterGrantResponse,
  VetterGrantRow,
  VetterListBody,
  VetterListResponse,
  VetterResendResponse,
  VettingRevocationList,
  VettingRevocationRow,
} from "@/lib/wire-types";

const TASK_VETTER_GRANT =
  "https://trusttasks.org/spec/vtc/vetting/vetters/grant/0.1";
const TASK_VETTER_RESEND =
  "https://trusttasks.org/spec/vtc/vetting/vetters/resend/0.1";
const TASK_VETTER_LIST =
  "https://trusttasks.org/spec/vtc/vetting/vetters/list/0.1";
const TASK_ENDORSEMENT_REVOKE =
  "https://trusttasks.org/spec/vtc/endorsements/revoke/0.1";
const TASK_MEMBERS_LIST = "https://trusttasks.org/spec/vtc/members/list/0.1";
const TASK_JOIN_REQUESTS_LIST =
  "https://trusttasks.org/spec/vtc/join-requests/list/0.1";
export const TASK_MANIFEST_V0_2 =
  "https://trusttasks.org/spec/vtc/join-requests/manifest/0.2";

/** Query keys. Everything under `["vetting"]` is refreshed after a change. */
export const vettingKeys = {
  grants: ["vetting", "grants"] as const,
  autoGrant: ["vetting", "auto-grant"] as const,
  revocations: ["vetting", "revocations"] as const,
  manifest: ["vetting", "manifest"] as const,
  activeMembers: ["vetting", "active-members"] as const,
  pendingWithVetting: ["vetting", "pending-with-vetting"] as const,
  listing: (body: VetterListBody, cursor: string | null) =>
    ["vetting", "listing", body, cursor] as const,
  joinRequest: (id: string) => ["join-request-vetting", id] as const,
  branding: ["community-branding"] as const,
};

// ── Grants ──────────────────────────────────────────────────────────────

export async function fetchGrants(): Promise<VetterGrantRow[]> {
  const body = await getJsonExempt<VetterGrantList>("/v1/vetting/vetters");
  return body.vetters;
}

export const grantVetter = (args: {
  memberDid: string;
  validitySeconds: number;
}): Promise<VetterGrantResponse> =>
  postJson<VetterGrantResponse>("/v1/vetting/vetters", args, {
    trustTask: TASK_VETTER_GRANT,
  });

/** A grant is withdrawn like any endorsement. */
export const revokeGrant = (endorsementId: string): Promise<unknown> =>
  deleteJson<unknown>(
    `/v1/credentials/endorsements/${encodeURIComponent(endorsementId)}`,
    { trustTask: TASK_ENDORSEMENT_REVOKE },
  );

export const resendGrant = (memberDid: string): Promise<VetterResendResponse> =>
  postJson<VetterResendResponse>(
    `/v1/vetting/vetters/${encodeURIComponent(memberDid)}/resend`,
    undefined,
    { trustTask: TASK_VETTER_RESEND },
  );

const MAX_MEMBER_PAGES = 10;

/** Current members, for choosing whom to name a vetter. */
export async function fetchActiveMembers(): Promise<MemberRow[]> {
  const members: MemberRow[] = [];
  let cursor: string | null = null;
  for (let page = 0; page < MAX_MEMBER_PAGES; page++) {
    const q = new URLSearchParams({ limit: "200" });
    if (cursor) q.set("cursor", cursor);
    const body: MembersPage = await getJson<MembersPage>(
      `/v1/members?${q.toString()}`,
      { trustTask: TASK_MEMBERS_LIST },
    );
    members.push(...body.items);
    cursor = body.nextCursor ?? null;
    if (!cursor) break;
  }
  return members;
}

// ── The public listing ──────────────────────────────────────────────────

export const fetchListing = (body: VetterListBody): Promise<VetterListResponse> =>
  postJson<VetterListResponse>("/v1/vetting/vetters/list", body, {
    trustTask: TASK_VETTER_LIST,
    requires: ["vetters"],
  });

// ── Automatic grants, withdrawals, join-request facts, branding ─────────

export const fetchAutoGrant = (): Promise<AutoGrantStatus> =>
  getJsonExempt<AutoGrantStatus>("/v1/vetting/auto-grant");

export const saveAutoGrant = (config: AutoGrantConfig): Promise<AutoGrantStatus> =>
  putJsonExempt<AutoGrantStatus>("/v1/vetting/auto-grant", config);

export async function fetchRevocations(): Promise<VettingRevocationRow[]> {
  const body = await getJsonExempt<VettingRevocationList>(
    "/v1/vetting/revocations",
  );
  return body.revocations;
}

export const fetchJoinRequestVetting = (
  id: string,
): Promise<JoinRequestVettingResponse> =>
  getJsonExempt<JoinRequestVettingResponse>(
    `/v1/join-requests/${encodeURIComponent(id)}/vetting`,
  );

export const fetchBranding = (): Promise<CommunityBranding> =>
  getJsonExempt<CommunityBranding>("/v1/community/branding");

export const saveBranding = (branding: CommunityBranding): Promise<CommunityBranding> =>
  putJsonExempt<CommunityBranding>("/v1/community/branding", branding);

export interface PendingWithVetting {
  /** Pending join requests on the first page that carry vetting facts. */
  count: number;
  /** More pending requests exist than were checked. */
  more: boolean;
}

/**
 * Pending join requests that were decided on vetting facts and now wait for an
 * admin. The request list does not say which carry facts, so the first page
 * of pending requests is checked one by one — bounded at 50 reads.
 */
export async function fetchPendingWithVetting(): Promise<PendingWithVetting> {
  const page = await getJson<JoinRequestsPage>(
    "/v1/join-requests?status=pending&limit=50",
    { trustTask: TASK_JOIN_REQUESTS_LIST },
  );
  const withFacts = await Promise.all(
    page.items.map((r) =>
      fetchJoinRequestVetting(r.id).then(
        (res) => Boolean(res.vetting),
        () => false,
      ),
    ),
  );
  return {
    count: withFacts.filter(Boolean).length,
    more: Boolean(page.nextCursor),
  };
}

// ── The join manifest ───────────────────────────────────────────────────

export type { JoinManifest, ManifestCriterion };

/**
 * `join-requests/manifest/0.2` as applicants receive it — each criterion with
 * its vetting requirements and `requirementsDigest` — from the admin route that
 * answers under the same task. The shape is the manifest specification's own.
 */
export const fetchManifest = (): Promise<JoinManifest> =>
  getJson<JoinManifest>("/v1/join-requests/manifest", {
    trustTask: TASK_MANIFEST_V0_2,
    requires: ["criteria"],
  });
