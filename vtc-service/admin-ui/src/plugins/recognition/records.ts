// How a trust record reads to an operator. The wire carries TRQP's four-part
// key; these say what each combination means in this community.

import { postSignedRead } from "@/lib/api";
import type { RegistryRecordRow, RegistryRecordsResponse } from "@/lib/wire-types";

import { rightLabel } from "../repos/model";

const REGISTRY_RECORDS_TASK = "https://trusttasks.org/spec/vtc/registry/records/list/0.1";

/** Records read per page, and the most pages read, by `fetchAllRegistryRecords`. */
const REGISTRY_RECORDS_PAGE = 200;
const MAX_REGISTRY_RECORD_PAGES = 25;

/**
 * Every trust record in one view, page by page — memberships and git rights
 * alike — so the Recognition page can search and filter all of them.
 * `truncated` when the page cap stopped it short.
 */
export async function fetchAllRegistryRecords(
  source: "registry" | "local",
): Promise<{ source: string; items: RegistryRecordRow[]; truncated: boolean }> {
  const items: RegistryRecordRow[] = [];
  let cursor: string | null = null;
  let answered: string = source;
  for (let page = 0; page < MAX_REGISTRY_RECORD_PAGES; page++) {
    const body: RegistryRecordsResponse = await postSignedRead<RegistryRecordsResponse>(
      REGISTRY_RECORDS_TASK,
      { source, limit: REGISTRY_RECORDS_PAGE, ...(cursor ? { cursor } : {}) },
    );
    answered = body.source;
    items.push(...body.items);
    cursor = typeof body.nextCursor === "string" && body.nextCursor ? body.nextCursor : null;
    if (!cursor) return { source: answered, items, truncated: false };
  }
  return { source: answered, items, truncated: true };
}

/** A membership record's action and resource (`registry::RECOGNISE_ACTION`,
 *  `registry::TRUST_GRAPH_RESOURCE` in vtc-service). */
export const RECOGNISE_ACTION = "recognise";
export const TRUST_GRAPH_RESOURCE = "trust-graph";

/** Membership, a git right, or something this console does not name. */
export type RecordKind = "membership" | "git" | "other";

export function recordKind(r: RegistryRecordRow): RecordKind {
  if (r.action === RECOGNISE_ACTION && r.resource === TRUST_GRAPH_RESOURCE) return "membership";
  if (r.action.startsWith("git.")) return "git";
  return "other";
}

export function recordKindLabel(kind: RecordKind | string): string {
  switch (kind) {
    case "membership":
      return "Membership";
    case "git":
      return "Git right";
    default:
      return "Other";
  }
}

/** One line on what the record means. */
export function recordMeaning(r: RegistryRecordRow): string {
  switch (recordKind(r)) {
    case "membership":
      return "member of this community";
    case "git": {
      const label = rightLabel(r.action);
      const repo = r.resource.split("/").length >= 3;
      return `${label.toLowerCase()} on this ${repo ? "repository" : "namespace"}`;
    }
    default:
      return r.recordType;
  }
}
