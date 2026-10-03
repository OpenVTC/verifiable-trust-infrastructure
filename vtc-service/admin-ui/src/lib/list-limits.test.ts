/// <reference types="vite/client" />

// Every page size the console asks a signed listing for is within that
// listing's specification maximum.
//
// The admission-criteria page asked `vtc/schemas/accepts/list/0.2` for 200
// rows against a maximum of 50, and the VTC refused every read (#1921). This
// is the census that would have caught it: each place a `limit` is put into a
// signed read, the listing it goes to, and where its value comes from. The
// values are read from the source, so raising a page-size constant past its
// listing's maximum fails here; a new `limit` anywhere fails until it is
// listed. The maxima are `list-limits.json`, which `vtc-service`'s
// `console_list_limits_match_the_specifications` test holds to the generated
// schemas.

import { describe, expect, it } from "vitest";

import { assertWithinListLimit, LIST_LIMIT_MAX, ListLimitError } from "./list-limits";

const SOURCES = import.meta.glob<string>("/src/**/*.{ts,tsx}", {
  query: "?raw",
  import: "default",
  eager: true,
});

/** Source by path under `src/`, without tests and generated wire types. */
const FILES: Record<string, string> = Object.fromEntries(
  Object.entries(SOURCES)
    .map(([path, text]) => [path.replace(/^\/src\//, ""), text] as const)
    .filter(
      ([path]) =>
        !/\.test\.tsx?$/.test(path) &&
        !path.startsWith("test/") &&
        path !== "lib/list-limits.ts" && // the guard itself, which sends nothing
        path !== "lib/wire.ts" &&
        path !== "lib/wire-types.ts",
    ),
);

const T = "https://trusttasks.org/spec";
const ACTIONS = `${T}/vtc/admin/actions/list/0.2`;
const JOINS = `${T}/vtc/join-requests/list/0.1`;
const MEMBERS = `${T}/vtc/members/list/0.1`;
const ENDORSEMENTS = `${T}/vtc/endorsements/list/0.1`;
const ENDORSEMENT_TYPES = `${T}/vtc/endorsement-types/list/0.1`;
const ROOMS = `${T}/vtc/rooms/list/0.1`;
const ACCEPTS = `${T}/vtc/schemas/accepts/list/0.2`;
const GRANTS = `${T}/vtc/vetting/vetters/grants/list/0.1`;
const REVOCATIONS = `${T}/vtc/vetting/revocations/list/0.1`;
const VETTERS = `${T}/vtc/vetting/vetters/list/0.1`;
const ACTIVITY = `${T}/git-ns/activity/list/0.1`;

interface Site {
  /** The file, under `src/`. */
  file: string;
  /** Text that occurs in it: the `limit` (or the wrapper call) this entry is. */
  site: string;
  /** The listing it reaches. */
  uri: string;
  /** Where that URI is written, when not in `file`. */
  uriFile?: string;
  /** What the limit's value comes from: number literals, or constants. */
  from: string[];
  /** Where those constants are declared, when not in `file`. */
  fromFile?: string;
}

const SITES: Site[] = [
  // The action list: the page, and the badge's one-row read.
  { file: "plugins/actions.tsx", site: "listActions({ view, limit: PAGE_SIZE", uri: ACTIONS, uriFile: "lib/actions-api.ts", from: ["PAGE_SIZE"] },
  // `listActions` passes its caller's limit through; each call is listed.
  { file: "lib/actions-api.ts", site: "payload.limit = query.limit", uri: ACTIONS, from: [] },
  { file: "lib/actions-api.ts", site: 'listActions({ view: "waitingForMe", limit: 1 })', uri: ACTIONS, from: ["1"] },
  // Join requests.
  { file: "plugins/joinRequests.tsx", site: "limit: params.limit", uri: JOINS, from: ["limit"] },
  { file: "plugins/joinRequests.tsx", site: "{ status, cursor, limit }", uri: JOINS, from: ["limit"] },
  { file: "plugins/vetting/api.ts", site: 'status: "pending",\n    limit: 50,', uri: JOINS, from: ["50"] },
  { file: "lib/community-counts.ts", site: "limit: COUNT_PAGE_SIZE", uri: JOINS, from: ["COUNT_PAGE_SIZE"] },
  // Members.
  { file: "lib/community-counts.ts", site: "limit: COUNT_PAGE_SIZE", uri: MEMBERS, from: ["COUNT_PAGE_SIZE"] },
  { file: "plugins/members.tsx", site: "limit: params.limit", uri: MEMBERS, from: ["limit"] },
  { file: "plugins/members.tsx", site: "        limit,\n      }),", uri: MEMBERS, from: ["limit"] },
  { file: "plugins/vetting/api.ts", site: "TASK_MEMBERS_LIST, {\n      limit: 200,", uri: MEMBERS, from: ["200"] },
  { file: "plugins/repos/api.ts", site: "limit: MEMBERS_PAGE", uri: MEMBERS, from: ["MEMBERS_PAGE"] },
  { file: "lib/names.ts", site: "(MEMBERS_TASK, { limit: 200 })", uri: MEMBERS, from: ["200"] },
  // Endorsements and their types.
  { file: "plugins/members.tsx", site: "{ limit: 200, ...(cursor ? { cursor } : {}) }", uri: ENDORSEMENTS, from: ["200"] },
  { file: "plugins/vetting/api.ts", site: "{ limit: 200, ...(cursor ? { cursor } : {}) }", uri: ENDORSEMENT_TYPES, from: ["200"] },
  // Rooms.
  { file: "plugins/rooms.tsx", site: "{ limit: 100, ...(cursor ? { cursor } : {}) }", uri: ROOMS, from: ["100"] },
  // Git-namespace activity.
  { file: "plugins/repos/api.ts", site: "{ namespace, limit }", uri: ACTIVITY, from: ["limit"] },
  // The vetting listings walked by `allItems(task, pageSize)`.
  { file: "plugins/vetting/api.ts", site: "limit: pageSize", uri: GRANTS, from: ["PAGE_SIZE_100"] },
  { file: "plugins/vetting/api.ts", site: "allItems<VetterGrantRow>(TASK_GRANTS_LIST)", uri: GRANTS, from: ["PAGE_SIZE_100"] },
  { file: "plugins/vetting/api.ts", site: "allItems<VettingRevocationRow>(TASK_REVOCATIONS_LIST)", uri: REVOCATIONS, from: ["PAGE_SIZE_100"] },
  { file: "plugins/vetting/api.ts", site: "allItems<AcceptsCriterion>(TASK_ACCEPTS_LIST, ACCEPTS_PAGE_SIZE)", uri: ACCEPTS, from: ["ACCEPTS_PAGE_SIZE"] },
  // The registry preview's page-size picker, sent through `fetchListing`.
  { file: "plugins/vetting/RegistryPreview.tsx", site: "limit: DEFAULT_PAGE_SIZE", uri: VETTERS, uriFile: "plugins/vetting/api.ts", from: ["DEFAULT_PAGE_SIZE", "PAGE_SIZES"] },
  { file: "plugins/vetting/RegistryPreview.tsx", site: "{ ...body, limit }", uri: VETTERS, uriFile: "plugins/vetting/api.ts", from: ["DEFAULT_PAGE_SIZE", "PAGE_SIZES"] },
  { file: "plugins/vetting/RegistryPreview.tsx", site: "setApplied({ limit })", uri: VETTERS, uriFile: "plugins/vetting/api.ts", from: ["DEFAULT_PAGE_SIZE", "PAGE_SIZES"] },
  { file: "plugins/vetting/RegistryPreview.tsx", site: "fetchListing(cursor ? { ...applied, cursor } : applied)", uri: VETTERS, uriFile: "plugins/vetting/api.ts", from: ["DEFAULT_PAGE_SIZE", "PAGE_SIZES"] },
];

/** Functions that put a caller's page size into a signed listing: every call
 *  to one is a census entry of its own. */
const WRAPPERS = ["allItems", "listActions", "fetchListing"];

/** Strip comments, so prose about limits is not counted as one. */
function code(text: string): string {
  return text.replace(/\/\*[\s\S]*?\*\//g, "").replace(/(^|[^:"'`])\/\/.*$/gm, "$1");
}

/** Lines putting a `limit` into a payload: `limit: x`, `{ limit }`, `.limit =`. */
function limitLines(text: string): string[] {
  return code(text)
    .split("\n")
    .filter((l) => !/=\{\s*limit\s*\}/.test(l)) // a JSX attribute, not a payload
    .filter(
      (l) =>
        /\blimit\s*:\s*(?!number\b)\S/.test(l) ||
        /(^|[{,])\s*limit\s*[,}]/.test(l) ||
        /\.limit\s*=[^=]/.test(l),
    );
}

/** Calls to a wrapper (its definition excluded). */
function wrapperCalls(text: string, name: string): number {
  const all = code(text).match(new RegExp(`\\b${name}\\s*(<[^>(]*>)?\\(`, "g")) ?? [];
  const defs = code(text).match(new RegExp(`function\\s+${name}\\b`, "g")) ?? [];
  return all.length - defs.length;
}

/** The numbers `token` stands for in `text`. */
function resolve(text: string, token: string): number[] {
  if (/^\d+$/.test(token)) return [Number(token)];
  const scalar = new RegExp(`\\b${token}\\s*(?::\\s*number\\s*)?=\\s*(\\d+)\\b`, "g");
  const values = [...text.matchAll(scalar)].map((m) => Number(m[1]));
  const array = new RegExp(`\\bconst\\s+${token}\\s*=\\s*\\[([\\d,\\s]+)\\]`).exec(text);
  if (array) values.push(...array[1]!.split(",").map((s) => Number(s.trim())));
  return values;
}

describe("the list-limit census", () => {
  it("lists every listing it checks in the pinned table", () => {
    for (const s of SITES) {
      expect(LIST_LIMIT_MAX[s.uri], `${s.uri} has no pinned maximum`).toBeTypeOf("number");
    }
  });

  it.each(SITES)("$file: `$site` → $uri is within its maximum", (s) => {
    const text = FILES[s.file];
    expect(text, `${s.file} not found`).toBeTypeOf("string");
    expect(text!.includes(s.site), `${s.file} no longer contains \`${s.site}\``).toBe(true);
    const uriText = FILES[s.uriFile ?? s.file]!;
    expect(uriText.includes(`"${s.uri}"`), `${s.uri} is not named in ${s.uriFile ?? s.file}`).toBe(true);
    const fromText = FILES[s.fromFile ?? s.file]!;
    const max = LIST_LIMIT_MAX[s.uri]!;
    for (const token of s.from) {
      const values = resolve(fromText, token);
      expect(values.length, `could not resolve \`${token}\` in ${s.file}`).toBeGreaterThan(0);
      for (const v of values) {
        expect(v, `${s.file}: \`${token}\` = ${v} against ${s.uri}`).toBeGreaterThanOrEqual(1);
        expect(v, `${s.file}: \`${token}\` = ${v} exceeds ${s.uri}'s maximum`).toBeLessThanOrEqual(max);
      }
    }
  });

  it("covers every limit the console sends, file by file", () => {
    for (const [file, text] of Object.entries(FILES)) {
      const found = limitLines(text).length;
      const listed = new Set(
        SITES.filter((s) => s.file === file && limitLines(s.site).length > 0).map((s) => s.site),
      ).size;
      expect(found, `${file} sets ${found} limit(s) but the census lists ${listed}`).toBe(listed);
    }
  });

  it("covers every call to a page-size wrapper", () => {
    for (const [file, text] of Object.entries(FILES)) {
      for (const name of WRAPPERS) {
        const calls = wrapperCalls(text, name);
        const call = new RegExp(`\\b${name}\\s*(<[^>(]*>)?\\(`);
        const listed = new Set(
          SITES.filter((s) => s.file === file && call.test(s.site)).map((s) => s.site),
        ).size;
        expect(calls, `${file} calls ${name} ${calls} time(s); the census lists ${listed}`).toBe(listed);
      }
    }
  });

  it("reads a page-size constant's value from the source", () => {
    // The admission-criteria read as it was before #1921 resolves to 200,
    // which the check above holds against accepts/list's 50.
    const before = "const ACCEPTS_PAGE_SIZE = 200;";
    expect(resolve(before, "ACCEPTS_PAGE_SIZE")).toEqual([200]);
    expect(resolve("const PAGE_SIZES = [10, 25, 500];", "PAGE_SIZES")).toEqual([10, 25, 500]);
    expect(resolve("(namespace: string, limit = 100) =>", "limit")).toEqual([100]);
    expect(LIST_LIMIT_MAX[ACCEPTS]).toBe(50);
  });
});

describe("assertWithinListLimit", () => {
  it("refuses a page over the listing's maximum, before anything is signed", () => {
    expect(() => assertWithinListLimit(ACCEPTS, { limit: 200 })).toThrow(ListLimitError);
    expect(() => assertWithinListLimit(ACCEPTS, { limit: 50 })).not.toThrow();
  });

  it("leaves alone a payload with no limit, and a task with no pinned maximum", () => {
    expect(() => assertWithinListLimit(ACCEPTS, {})).not.toThrow();
    expect(() => assertWithinListLimit(`${T}/vtc/members/show/0.1`, { limit: 10_000 })).not.toThrow();
  });
});
