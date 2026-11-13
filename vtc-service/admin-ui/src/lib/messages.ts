// What an error says, for both bundles (the console and the member portal).
//
// One function in place of a dozen copies of `e?.message ?? String(e)`, which
// disagreed at the edges (#2617): an `ApiError` is a plain object, not an
// `Error`, so `e instanceof Error ? e.message : String(e)` read it as
// "[object Object]", and `e?.message ?? …` let an empty message through.

/** An error's own message, when it carries a non-empty one; otherwise the
 *  value as a string. Never throws. */
export function messageOf(err: unknown): string {
  if (err && typeof err === "object" && "message" in err) {
    const message = (err as { message: unknown }).message;
    if (typeof message === "string" && message) return message;
  }
  try {
    return String(err);
  } catch {
    return "Unknown error";
  }
}
