// Policy API + types — shared by the Ceremonies surface.
//
// A policy is a versioned Rego module keyed by `purpose`. Four
// purposes are first-class ceremonies (directory / join / removal /
// roleChange); the rest are policy-only purposes the daemon ships
// defaults for. The Ceremonies plugin manages all of them.

import { getJson, postJson } from "@/lib/api";
import type { PolicyPurpose } from "@/lib/wire-types";

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

/**
 * Every purpose, in the order the console shows them.
 *
 * **Derived from the daemon, not described beside it.** This was a hand-written
 * literal and it had already drifted: it named ten purposes while the daemon
 * served eleven, so the `rooms` policy — which decides whether this community
 * lends its disk to a data room, and whose shipped default **denies** the
 * private tier — had no tab in the console and could not be read, tested or
 * replaced from here. Nothing failed. The tab was simply absent, which is the
 * quietest way for a policy to go unmanaged.
 *
 * The `Record<Purpose, true>` is what stops it happening again: a purpose added
 * to the Rust enum reaches `wire.ts` on the next `wire:generate`, and this
 * object then fails to compile until someone places it. Ordering is the
 * object's, so a new purpose lands where it is put rather than at the end.
 */
export type Purpose = PolicyPurpose;

const PURPOSE_ORDER: Record<Purpose, true> = {
  join: true,
  removal: true,
  personhood: true,
  registry: true,
  directory: true,
  roleDefinitions: true,
  crossCommunityRoles: true,
  crossCommunityRelationships: true,
  relationships: true,
  roleChange: true,
  rooms: true,
  vetterEligibility: true,
};

export const ALL_PURPOSES = Object.keys(PURPOSE_ORDER) as Purpose[];

/**
 * The Rego package a purpose's policy must be compiled into — this console's
 * mirror of `PolicyPurpose::expected_package`, which the daemon checks at
 * upload *and* at activation, because a module in the wrong package compiles
 * cleanly and then silently denies every request for that purpose.
 *
 * Every shipped policy in `vtc-service/policies/default/` is the snake_case of
 * its camelCase purpose, so that is the rule rather than a list of exceptions:
 * `roleChange` → `vtc.role_change`, `vetterEligibility` →
 * `vtc.vetter_eligibility`.
 */
export function pkgFor(purpose: Purpose): string {
  return `vtc.${purpose.replace(/[A-Z]/g, (c) => `_${c.toLowerCase()}`)}`;
}

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

// ---------------------------------------------------------------------------
// Evaluating a policy — the dry-run, and the probes the Flow view is built
// from. Both go through `POST /v1/policies/{id}/test`, which recompiles and
// evaluates the stored module without touching the active pointer.
// ---------------------------------------------------------------------------

const TRUST_TASK_TEST = "https://trusttasks.org/spec/vtc/policies/test/0.1";

/** What the pipeline's four-valued `decision` rule returns. */
export interface Verdict {
  effect: string;
  with?: Record<string, unknown>;
}

interface PolicyTestResult {
  result?: { result?: { expressions?: { value?: unknown }[] }[] };
}

/**
 * The decision inside regorus' `QueryResults`, or null when the module yields
 * none — which is what a pre-pipeline boolean `allow` policy looks like from
 * here, and worth telling an operator rather than drawing as an empty chart.
 */
export function pluckDecision(resp: PolicyTestResult): Verdict | null {
  const value = resp.result?.result?.[0]?.expressions?.[0]?.value;
  if (!value || typeof value !== "object") return null;
  const v = value as Record<string, unknown>;
  if (typeof v.effect !== "string") return null;
  return { effect: v.effect, with: v.with as Record<string, unknown> | undefined };
}

/** Evaluate one input against a stored policy revision. */
export async function evaluatePolicy(
  policyId: string,
  pkg: string,
  input: unknown,
): Promise<Verdict | null> {
  const resp = await postJson<PolicyTestResult>(
    `/v1/policies/${encodeURIComponent(policyId)}/test`,
    { query: `data.${pkg}.decision`, input },
    { trustTask: TRUST_TASK_TEST },
  );
  return pluckDecision(resp);
}

/**
 * Evaluate many inputs, a few at a time.
 *
 * The daemon recompiles per call, so these are independent and cheap
 * individually; the cap is about not opening thirty connections at once from a
 * console page, not about the daemon's cost.
 */
export async function evaluateMany(
  policyId: string,
  pkg: string,
  inputs: unknown[],
  concurrency = 6,
): Promise<(Verdict | null)[]> {
  const out: (Verdict | null)[] = new Array(inputs.length);
  let next = 0;
  const worker = async () => {
    for (;;) {
      const i = next++;
      if (i >= inputs.length) return;
      out[i] = await evaluatePolicy(policyId, pkg, inputs[i]);
    }
  };
  await Promise.all(
    Array.from({ length: Math.min(concurrency, inputs.length) }, worker),
  );
  return out;
}
