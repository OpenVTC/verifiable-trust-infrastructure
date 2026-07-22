// Policy API + types — shared by the Ceremonies surface.
//
// A policy is a versioned Rego module keyed by `purpose`. Four
// purposes are first-class ceremonies (directory / join / removal /
// roleChange); the rest are policy-only purposes the daemon ships
// defaults for. The Ceremonies plugin manages all of them.

import { getJson, postJson } from "@/lib/api";

// One canonical task per verb (the shared upload/1.0 mount was retired
// in phase 2a).
const TRUST_TASK_LIST = "https://trusttasks.org/spec/policy/list/0.2";
const TRUST_TASK_UPSERT = "https://trusttasks.org/spec/policy/upsert/0.2";
const TRUST_TASK_ACTIVE = "https://trusttasks.org/spec/policy/active/0.1";
const TRUST_TASK_ACTIVATE = "https://trusttasks.org/spec/policy/activate/0.1";

/// Ecosystem `ext` member carrying the intrinsic purpose. Canonical
/// treats a module as purpose-agnostic; this maintainer does not (the
/// purpose is fixed by the module's Rego package), so it travels here.
const PURPOSE_EXT = "org.openvtc.purpose";

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

// Canonical PolicyModule. Maintainer-specific fields (purpose, source
// hash, author) ride in `ext` because the canonical type is
// `additionalProperties: false`.
export interface PolicyRow {
  id: string;
  name: string;
  module: string;
  version: number;
  createdAt: string;
  updatedAt: string;
  ext?: {
    "org.openvtc.purpose"?: Purpose;
    "org.openvtc.sha256"?: string;
    "org.openvtc.authorDid"?: string;
  };
}

export interface PoliciesPage {
  policies: PolicyRow[];
  truncated: boolean;
  cursor?: string | null;
}

/// The purpose a module serves, read from its `ext`.
export function policyPurpose(p: PolicyRow): Purpose | undefined {
  return p.ext?.[PURPOSE_EXT];
}

export async function fetchPolicies(purpose: Purpose): Promise<PoliciesPage> {
  return getJson<PoliciesPage>(
    `/v1/policies?purpose=${purpose}&pageSize=100`,
    { trustTask: TRUST_TASK_LIST },
  );
}

interface ActiveBindingsResponse {
  bindings: { purpose: Purpose; policy: PolicyRow }[];
}

export async function fetchActivePolicy(
  purpose: Purpose,
): Promise<PolicyRow | null> {
  // Activeness is now its own canonical task rather than a flag on the
  // module — a module carries no isActive field.
  const res = await getJson<ActiveBindingsResponse>(
    `/v1/policies/active?purpose=${purpose}`,
    { trustTask: TRUST_TASK_ACTIVE },
  );
  return res.bindings.find((b) => b.purpose === purpose)?.policy ?? null;
}

interface UpsertResponse {
  policy: PolicyRow;
  created: boolean;
}

export async function uploadPolicy(args: {
  purpose: Purpose;
  regoSource: string;
}): Promise<PolicyRow> {
  const res = await postJson<UpsertResponse>(
    "/v1/policies",
    {
      name: args.purpose,
      module: args.regoSource,
      ext: { [PURPOSE_EXT]: args.purpose },
    },
    { trustTask: TRUST_TASK_UPSERT },
  );
  return res.policy;
}

export async function activatePolicy(id: string): Promise<unknown> {
  return postJson<unknown>(`/v1/policies/${id}/activate`, undefined, {
    trustTask: TRUST_TASK_ACTIVATE,
  });
}
