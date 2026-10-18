// The member directory, administered — `vtc/directory/*`
// (docs/03-vtc/member-directory.md).
//
// The schema is the community's: every administrator reads it, and a holder of
// `vtc.directory.admin` defines, changes and retires fields. A change that
// **widens** a field — a higher ceiling or default, searchable, a facet,
// re-enabled, no longer required — takes the requester's passkey gesture and
// is parked for the other holders' approval (VTI-DIR-024), so it is sent
// through `postSignedWithStepUp` and may come back as a `ParkedAction`.
//
// Cards are the members': an administrator reads every entry whole, and
// writes only the values of `admin`-sourced fields (`card/assert`). Nothing
// here changes what a member chose to show.

import { postSignedRead, postSignedTrustTask } from "./api";
import { postSignedWithStepUp, type ConfirmGesture } from "./signed-act";
import type {
  DirectoryCardAssertPayload,
  DirectoryCardAssertResponse,
  DirectoryEntriesListPayload,
  DirectoryEntriesListResponse,
  DirectoryEntriesShowResponse,
  DirectoryFieldDefinition,
  DirectoryFieldInput,
  DirectoryFieldsListResponse,
  DirectoryFieldsUpdatePayload,
} from "./wire-types";

export const FIELDS_LIST_TASK = "https://trusttasks.org/spec/vtc/directory/fields/list/0.1";
export const FIELDS_DEFINE_TASK = "https://trusttasks.org/spec/vtc/directory/fields/define/0.1";
export const FIELDS_UPDATE_TASK = "https://trusttasks.org/spec/vtc/directory/fields/update/0.1";
export const FIELDS_RETIRE_TASK = "https://trusttasks.org/spec/vtc/directory/fields/retire/0.1";
export const CARD_ASSERT_TASK = "https://trusttasks.org/spec/vtc/directory/card/assert/0.1";
export const ENTRIES_LIST_TASK = "https://trusttasks.org/spec/vtc/directory/entries/list/0.1";
export const ENTRIES_SHOW_TASK = "https://trusttasks.org/spec/vtc/directory/entries/show/0.1";

/** Who may administer the directory's schema and its asserted values. */
export const DIRECTORY_ADMIN = "vtc.directory.admin";

export type Audience = DirectoryFieldDefinition["ceiling"];
export type FieldType = DirectoryFieldDefinition["type"];

/** The audiences, narrowest first, with what each means. */
export const AUDIENCES: readonly { id: Audience; label: string; hint: string }[] = [
  { id: "admins", label: "Administrators", hint: "holders of vtc.directory.admin" },
  { id: "groups", label: "Group members", hint: "members sharing a community group" },
  { id: "connections", label: "Connections", hint: "members with a verified relationship" },
  { id: "members", label: "Members", hint: "every active member" },
  { id: "public", label: "Public", hint: "anyone, on the member's own published card" },
];

/** Whether every viewer of `inner` is a viewer of `outer`. `groups` and
 *  `connections` do not cover each other — the daemon's `Audience::within`. */
export function within(inner: Audience, outer: Audience): boolean {
  if (inner === outer || inner === "admins") return true;
  if ((inner === "groups" || inner === "connections") && (outer === "members" || outer === "public"))
    return true;
  return inner === "members" && outer === "public";
}

/** Whether a change from `before` to `after` would widen the field, and so be
 *  parked for approval — the daemon's `FieldChange::widens`. Shown before the
 *  change is sent, never relied on: the daemon decides. */
export function widens(before: DirectoryFieldDefinition, after: DirectoryFieldDefinition): boolean {
  return (
    !within(after.ceiling, before.ceiling) ||
    !within(after.defaultVisibility, before.defaultVisibility) ||
    (after.searchable && !before.searchable) ||
    (after.facet && !before.facet) ||
    (after.state === "active" && before.state !== "active") ||
    (!after.required && before.required)
  );
}

export const FIELD_TYPES: readonly FieldType[] = [
  "text",
  "longText",
  "url",
  "email",
  "phone",
  "enum",
  "multiEnum",
  "date",
  "country",
  "did",
];

/** A community field's key: reverse-DNS, as `FieldKey` admits it. */
export const COMMUNITY_KEY_PATTERN = /^([a-z][a-z0-9-]*\.)+[a-z][a-zA-Z0-9]{0,63}$/;

export async function listFields(includeRetired = false): Promise<DirectoryFieldsListResponse> {
  return postSignedRead<DirectoryFieldsListResponse>(FIELDS_LIST_TASK, { includeRetired });
}

export async function defineField(
  field: DirectoryFieldInput,
  reason?: string,
): Promise<DirectoryFieldDefinition> {
  const body = await postSignedTrustTask<{ field: DirectoryFieldDefinition }>(
    FIELDS_DEFINE_TASK,
    { field, ...(reason ? { reason } : {}) },
  );
  return body.field;
}

/** Change a field. A widening is parked: the gesture is asked for, and the
 *  call throws a `ParkedAction` once it is sent for approval. */
export async function updateField(
  change: DirectoryFieldsUpdatePayload,
  confirmGesture: ConfirmGesture,
): Promise<DirectoryFieldDefinition> {
  const body = await postSignedWithStepUp<{ field: DirectoryFieldDefinition }>(
    FIELDS_UPDATE_TASK,
    change,
    confirmGesture,
  );
  return body.field;
}

export async function retireField(key: string, reason: string): Promise<DirectoryFieldDefinition> {
  const body = await postSignedTrustTask<{ field: DirectoryFieldDefinition }>(
    FIELDS_RETIRE_TASK,
    { key, reason },
  );
  return body.field;
}

export async function listEntries(
  query: DirectoryEntriesListPayload,
): Promise<DirectoryEntriesListResponse> {
  return postSignedRead<DirectoryEntriesListResponse>(ENTRIES_LIST_TASK, query);
}

export async function showEntry(entryId: string): Promise<DirectoryEntriesShowResponse> {
  return postSignedRead<DirectoryEntriesShowResponse>(ENTRIES_SHOW_TASK, { entryId });
}

export async function showEntryByDid(did: string): Promise<DirectoryEntriesShowResponse> {
  return postSignedRead<DirectoryEntriesShowResponse>(ENTRIES_SHOW_TASK, { did });
}

export async function assertValues(
  payload: DirectoryCardAssertPayload,
): Promise<DirectoryCardAssertResponse> {
  return postSignedTrustTask<DirectoryCardAssertResponse>(CARD_ASSERT_TASK, payload);
}
