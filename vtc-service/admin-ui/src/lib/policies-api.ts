// Policy API + types — shared by the Ceremonies surface.
//
// A policy is a versioned Rego module keyed by `purpose`. Four
// purposes are first-class ceremonies (directory / join / removal /
// roleChange); the rest are policy-only purposes the daemon ships
// defaults for. The Ceremonies plugin manages all of them.

import { getJson, postJson } from "@/lib/api";

const TRUST_TASK_POLICIES =
  "https://trusttasks.org/openvtc/vtc/policies/upload/1.0";
const TRUST_TASK_ACTIVATE =
  "https://trusttasks.org/openvtc/vtc/policies/activate/1.0";

export const ALL_PURPOSES = [
  "join",
  "removal",
  "personhood",
  "registry",
  "directory",
  "roleDefinitions",
  "crossCommunityRoles",
  "crossCommunityRelationships",
  "relationships",
  "roleChange",
] as const;

export type Purpose = (typeof ALL_PURPOSES)[number];

/// Purposes that are first-class ceremonies (have a flow + simulator).
export const CEREMONY_PURPOSES: Purpose[] = [
  "directory",
  "join",
  "removal",
  "roleChange",
];

/// Everything else — policy-only purposes (no ceremony wiring yet).
export const OTHER_PURPOSES: Purpose[] = ALL_PURPOSES.filter(
  (p) => !CEREMONY_PURPOSES.includes(p),
);

export interface PolicyRow {
  id: string;
  purpose: Purpose;
  regoSource: string;
  sha256: string;
  activatedAt: string | null;
  authorDid: string;
  createdAt: string;
  version: number;
  isActive: boolean;
}

export interface PoliciesPage {
  items: PolicyRow[];
  next_cursor: string | null;
}

export async function fetchPolicies(purpose: Purpose): Promise<PoliciesPage> {
  return getJson<PoliciesPage>(`/v1/policies?purpose=${purpose}&limit=100`, {
    trustTask: TRUST_TASK_POLICIES,
  });
}

export async function fetchActivePolicy(
  purpose: Purpose,
): Promise<PolicyRow | null> {
  const page = await getJson<PoliciesPage>(
    `/v1/policies?purpose=${purpose}&status=active&limit=1`,
    { trustTask: TRUST_TASK_POLICIES },
  );
  return page.items.find((p) => p.isActive) ?? page.items[0] ?? null;
}

export async function uploadPolicy(args: {
  purpose: Purpose;
  regoSource: string;
}): Promise<PolicyRow> {
  return postJson<PolicyRow>(
    "/v1/policies",
    { purpose: args.purpose, regoSource: args.regoSource },
    { trustTask: TRUST_TASK_POLICIES },
  );
}

export async function activatePolicy(id: string): Promise<unknown> {
  return postJson<unknown>(`/v1/policies/${id}/activate`, undefined, {
    trustTask: TRUST_TASK_ACTIVATE,
  });
}
