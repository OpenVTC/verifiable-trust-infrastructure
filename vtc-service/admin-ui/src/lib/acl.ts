// The ACL, as signed Trust Task documents — the canonical `acl/*` family. The
// VTC serves it on no REST route: every verb is a document this browser signs
// with its console key and posts to `POST /v1/trust-tasks`.
//
// The responses are the daemon's own types, published in its OpenAPI document
// for exactly this (`routes::ApiDoc`); the request payloads are the family's
// (`acl/list`, `acl/grant`, …), written here beside the calls that send them.

import { postSignedRead } from "./api";
import { postSignedWithStepUp, type ConfirmGesture } from "./signed-act";
import type { AclEntry, AclEntryEnvelope, AclListResponse } from "./wire-types";

export type { AclEntry, AclListResponse };

export const ACL_LIST_TASK = "https://trusttasks.org/spec/acl/list/0.1";
export const ACL_SHOW_TASK = "https://trusttasks.org/spec/acl/show/0.1";
export const ACL_GRANT_TASK = "https://trusttasks.org/spec/acl/grant/0.1";
export const ACL_CHANGE_ROLE_TASK = "https://trusttasks.org/spec/acl/change-role/0.1";
export const ACL_REVOKE_TASK = "https://trusttasks.org/spec/acl/revoke/0.1";

/** `acl/list/0.1` payload. */
export interface AclListFilter {
  role?: string;
  scope?: string;
  direction?: "acting-in" | "subtree" | "any";
  subjectPrefix?: string;
  pageSize?: number;
  cursor?: string;
}

/** `acl/grant/0.1` payload: the entry, with no server-owned provenance. */
export interface AclGrantRequest {
  entry: {
    subject: string;
    role: string;
    label?: string | null;
    scopes: string[];
    expiresAt?: string | null;
  };
  reason?: string;
}

/** One page of the entries this operator may see. */
export const fetchAclPage = (filter: AclListFilter = {}): Promise<AclListResponse> =>
  postSignedRead<AclListResponse>(ACL_LIST_TASK, filter);

/** The longest walk [`fetchAllAcl`] makes before it says the list is too long. */
const MAX_ACL_PAGES = 100;

/**
 * Every entry this operator may see, following the cursor to the end. A page
 * that is truncated with no cursor, or a list longer than the walk allows, is
 * an error rather than a partial list that reads as complete.
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
 * Grant (or re-state) an entry. Granting `admin` may need a passkey gesture,
 * and making an unrestricted admin is parked for other administrators'
 * approval (VTI-APV-014) — thrown as a `ParkedAction` (`lib/parked-action.ts`).
 */
export async function grantAcl(
  req: AclGrantRequest,
  confirmGesture: ConfirmGesture,
): Promise<AclEntry> {
  const body = await postSignedWithStepUp<AclEntryEnvelope>(
    ACL_GRANT_TASK,
    req,
    confirmGesture,
  );
  return body.entry;
}

/**
 * Change an entry's role. `fromRole` is a compare-and-swap guard: the role on
 * screen is a read, and the VTC refuses the change if the row has moved since.
 * Promotion to `admin` may need a passkey gesture, and so does a demotion
 * from `admin` (VTI-APV-019). Making or unmaking an unrestricted admin is
 * parked for other administrators' approval and thrown as a `ParkedAction`.
 */
export async function changeAclRole(
  args: { subject: string; fromRole: string; toRole: string; reason?: string },
  confirmGesture: ConfirmGesture,
): Promise<AclEntry> {
  const body = await postSignedWithStepUp<AclEntryEnvelope>(
    ACL_CHANGE_ROLE_TASK,
    args,
    confirmGesture,
  );
  return body.entry;
}

/**
 * Remove an entry outright. Removing an administrator needs a passkey gesture
 * bound to this removal, and removing another unrestricted administrator also
 * needs the approval of an administrator who is neither of you (VTI-APV-019),
 * so it is parked and thrown as a `ParkedAction`.
 */
export async function revokeAcl(subject: string, confirmGesture: ConfirmGesture): Promise<void> {
  await postSignedWithStepUp<{ entry: AclEntry | null }>(
    ACL_REVOKE_TASK,
    { subject },
    confirmGesture,
  );
}
