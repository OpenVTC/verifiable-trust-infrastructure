// The page-size ceilings of the listings the console calls.
//
// Each listing's specification caps its `limit` with a JSON Schema `maximum`,
// and the VTC refuses a document over it as `malformedRequest` — the shape of
// the admission-criteria bug (#1921), where a 200 against a maximum of 50 left
// the Admission page empty. The console has no schema package, so the maxima
// are pinned in `list-limits.json`; `vtc-service`'s
// `console_list_limits_match_the_specifications` test compares every entry to
// the generated `trust_tasks_rs::schema_index` schema, and fails on any
// listing the console names whose schema caps `limit` but has no entry here,
// so the table cannot drift from the specifications. `list-limits.test.ts`
// holds every call site to it.

import table from "./list-limits.json";

/** Type URI → the `limit` maximum its payload schema declares. */
export const LIST_LIMIT_MAX: Readonly<Record<string, number>> = table;

/** A signed listing asked for a page over its specification's maximum. */
export class ListLimitError extends Error {
  constructor(
    readonly typeUri: string,
    readonly limit: number,
    readonly maximum: number,
  ) {
    super(
      `The console asked ${typeUri} for ${limit} items a page; its specification allows at most ${maximum}.`,
    );
    this.name = "ListLimitError";
  }
}

/**
 * Throw [`ListLimitError`] when `payload.limit` exceeds `typeUri`'s pinned
 * maximum. Called before a signed document is built, so an over-limit page is
 * a console defect named as one rather than a `malformedRequest` from the VTC.
 */
export function assertWithinListLimit(typeUri: string, payload: unknown): void {
  const maximum = LIST_LIMIT_MAX[typeUri];
  if (maximum === undefined || typeof payload !== "object" || payload === null) return;
  const limit = (payload as { limit?: unknown }).limit;
  if (typeof limit === "number" && limit > maximum) {
    throw new ListLimitError(typeUri, limit, maximum);
  }
}
