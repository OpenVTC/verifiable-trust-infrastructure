// The whole lucide set, in a module of its own so the builder loads it only when
// someone searches or browses: the sixteen icons it offers first stay in the
// main bundle. With it, the words lucide files each icon under (`lucide-static`,
// pinned to the same release as `lucide-react`), so "insect" finds the bug.

import { icons } from "lucide-react";
import kebabTags from "lucide-static/tags.json";

export { icons };

/** `alarm-clock-check` as lucide-react names it: `AlarmClockCheck`. */
function pascal(kebab: string): string {
  return kebab
    .split("-")
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join("");
}

/** Each icon's tags, keyed as `icons` is. */
export const tags: Record<string, readonly string[]> = Object.fromEntries(
  Object.entries(kebabTags as Record<string, string[]>).map(([k, v]) => [pascal(k), v]),
);
