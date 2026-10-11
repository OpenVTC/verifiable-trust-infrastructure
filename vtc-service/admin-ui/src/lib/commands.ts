// What the command palette (`components/CommandPalette.tsx`) offers, and how
// it ranks them against what the operator typed. Pure, so it is tested
// without rendering anything.
//
// Two kinds of command:
//
// - **Screens**: every plugin the viewer can see — built-in and third-party
//   alike, sidebar and account menu — straight from the registry
//   (`registerPlugin`). A plugin registered after boot appears the next time
//   the palette renders; it needs no field of its own to be listed.
// - **Actions**: a short list of things operators do often. Each names the
//   screen it needs (`requires`), and is offered only when that screen is
//   visible to the viewer, so the palette never offers what the nav hides.
//   The VTC still decides every operation; this is placement, like the nav.
//
// Plus two built from the query itself: search the members for it, and, when
// it is a DID, open that member.

import type { PluginManifest } from "@/plugin-api";

export type CommandKind = "screen" | "action";

export interface Command {
  readonly id: string;
  readonly kind: CommandKind;
  readonly label: string;
  /** A second line: where a screen sits, or what an action does. */
  readonly hint?: string;
  /** More words it answers to ("people" for Members). Never shown. */
  readonly keywords?: readonly string[];
  /** The plugin, for a screen (its icon). */
  readonly plugin?: PluginManifest;
  /** Where it goes, for a command that navigates. */
  readonly to?: string;
  /** What it does, for one that does not (or does more than navigate). */
  readonly run?: () => void;
}

export interface ScreenSource {
  readonly plugin: PluginManifest;
  /** The nav group heading it sits under ("Membership", "More", "Account"). */
  readonly group: string;
}

/** Words some screens also answer to, by plugin id. */
const SCREEN_KEYWORDS: Record<string, readonly string[]> = {
  dashboard: ["home", "overview", "health", "status"],
  actions: ["approvals", "inbox", "approve", "consent", "pending"],
  audit: ["log", "history", "events"],
  "join-requests": ["applications", "applicants", "admit"],
  members: ["people", "community", "directory"],
  invitations: ["invite", "vic"],
  vetting: ["vetters", "criteria", "requirements"],
  relationships: ["graph", "trust", "vrc"],
  ceremonies: ["ceremonies", "rego", "rules", "policy"],
  roles: ["permissions", "capabilities"],
  acl: ["acl", "administrators", "admins", "permissions", "access"],
  sessions: ["sign out", "logins", "revoke"],
  profile: ["branding", "name", "logo", "website"],
  recognition: ["registry", "cross-community", "trust registry"],
  rooms: ["data rooms", "files"],
  repos: ["git", "repositories", "forge", "github"],
  "my-passkeys": ["passkey", "webauthn", "security key"],
  "console-keys": ["signing key", "renew", "browser key"],
};

/** The screens, in nav order. */
export function screenCommands(sources: readonly ScreenSource[]): Command[] {
  return sources.map(({ plugin, group }) => ({
    id: `screen:${plugin.id}`,
    kind: "screen",
    label: plugin.label,
    hint: group,
    keywords: [group, ...(SCREEN_KEYWORDS[plugin.id] ?? [])],
    plugin,
    to: plugin.path,
  }));
}

/** A common action: offered when the screen with `requires` is visible. */
export interface ActionSpec {
  readonly id: string;
  readonly label: string;
  readonly hint?: string;
  readonly keywords?: readonly string[];
  /** The plugin id this needs; absent: always offered. */
  readonly requires?: string;
  readonly to?: string;
  readonly run?: () => void;
}

/** The built-in actions that only navigate. The shell adds the ones that run
 *  something (theme, sign out, reload plugins) with their callbacks. */
export const NAVIGATION_ACTIONS: readonly ActionSpec[] = [
  {
    id: "review-actions",
    label: "Review actions waiting for you",
    hint: "Actions · Waiting for me",
    keywords: ["approve", "decline", "inbox", "consent"],
    requires: "actions",
    to: "/actions?tab=waitingForMe",
  },
  {
    id: "add-member",
    label: "Add a member",
    hint: "Admit a DID directly, under the admission policy",
    keywords: ["admit", "new member", "member"],
    requires: "members",
    to: "/members?add=1",
  },
  {
    id: "invite-member",
    label: "Invite a member",
    hint: "Issue an invitation credential",
    keywords: ["invitation", "vic", "new member"],
    requires: "invitations",
    to: "/invitations",
  },
  {
    id: "decide-joins",
    label: "Decide join requests",
    hint: "Join requests",
    keywords: ["approve", "applications", "admit"],
    requires: "join-requests",
    to: "/join-requests",
  },
  {
    id: "add-acl-entry",
    label: "Add an access-control entry",
    hint: "Grant an administrative role",
    keywords: ["grant", "admin", "acl", "administrator"],
    requires: "acl",
    to: "/acl?add=1",
  },
  {
    id: "invite-admin",
    label: "Invite an administrator",
    hint: "Access control · Admin invites",
    keywords: ["admin invite", "install url", "acl"],
    requires: "acl",
    to: "/acl?invite=1",
  },
  {
    id: "renew-signing-key",
    label: "Renew this browser's signing key",
    hint: "Signing keys",
    keywords: ["console key", "expires", "renew"],
    requires: "console-keys",
    to: "/console-keys",
  },
];

/** The actions the viewer can use, given the plugin ids they can see. */
export function actionCommands(
  specs: readonly ActionSpec[],
  visible: ReadonlySet<string>,
): Command[] {
  return specs
    .filter((s) => !s.requires || visible.has(s.requires))
    .map((s) => ({
      id: `action:${s.id}`,
      kind: "action",
      label: s.label,
      hint: s.hint,
      keywords: s.keywords,
      to: s.to,
      run: s.run,
    }));
}

/** Commands made from the query: search the members for it, and open a DID. */
export function queryCommands(query: string, visible: ReadonlySet<string>): Command[] {
  const q = query.trim();
  if (!q || !visible.has("members")) return [];
  const out: Command[] = [];
  if (/^did:[a-z0-9]+:\S+$/i.test(q)) {
    out.push({
      id: "query:open-did",
      kind: "action",
      label: `Open member ${q}`,
      hint: "Members",
      to: `/members/${encodeURIComponent(q)}`,
    });
  }
  out.push({
    id: "query:search-members",
    kind: "action",
    label: `Search members for “${q}”`,
    hint: "Name, DID, role or forge login",
    to: `/members?q=${encodeURIComponent(q)}`,
  });
  return out;
}

// ── Ranking ───────────────────────────────────────────────────────────

const norm = (s: string) => s.toLowerCase().normalize("NFKD").replace(/[̀-ͯ]/g, "");

/**
 * How well one term matches one text: a prefix of the whole beats a prefix of
 * a word, which beats a substring, which beats the letters in order ("acl" in
 * "Access control"). `null`: no match.
 */
export function termScore(term: string, text: string): number | null {
  const t = norm(text);
  const q = norm(term);
  if (!q) return 0;
  if (t.startsWith(q)) return 100 - Math.min(20, t.length - q.length) / 2;
  const words = t.split(/[^\p{L}\p{N}]+/u).filter(Boolean);
  if (words.some((w) => w.startsWith(q))) return 70;
  if (t.includes(q)) return 50;
  // Initials: "ac" for "Access control", "jr" for "Join requests".
  const initials = words.map((w) => w[0]).join("");
  if (initials.startsWith(q)) return 60;
  // Letters in order, scored by how tightly they sit.
  let at = -1;
  let span = 0;
  for (const ch of q) {
    const next = t.indexOf(ch, at + 1);
    if (next < 0) return null;
    if (at >= 0) span += next - at - 1;
    at = next;
  }
  return Math.max(1, 30 - span);
}

/** A command's score for a whole query (every term must match its label,
 *  hint or keywords), or `null`. The label counts most. */
export function commandScore(command: Command, query: string): number | null {
  const terms = query.trim().split(/\s+/).filter(Boolean);
  if (terms.length === 0) return 0;
  // A query-made command already is the query; keep it, below a real match.
  if (command.id.startsWith("query:")) return 1;
  let total = 0;
  for (const term of terms) {
    const label = termScore(term, command.label);
    const hint = command.hint ? termScore(term, command.hint) : null;
    const keyword = Math.max(
      -1,
      ...(command.keywords ?? []).map((k) => termScore(term, k) ?? -1),
    );
    const best = Math.max(
      label ?? -1,
      hint !== null ? hint * 0.5 : -1,
      keyword >= 0 ? keyword * 0.6 : -1,
    );
    if (best < 0) return null;
    total += best;
  }
  return total;
}

/**
 * The commands matching `query`, best first; with no query, all of them in
 * the order given (screens in nav order, then actions). Stable for ties.
 */
export function filterCommands(commands: readonly Command[], query: string): Command[] {
  if (!query.trim()) return [...commands];
  return commands
    .map((c, i) => ({ c, i, s: commandScore(c, query) }))
    .filter((x): x is { c: Command; i: number; s: number } => x.s !== null)
    .sort((a, b) => b.s - a.s || a.i - b.i)
    .map((x) => x.c);
}

/** ⌘K on Apple platforms, Ctrl+K elsewhere — for the hint shown beside it. */
export function paletteShortcutLabel(
  platform: string = typeof navigator === "undefined" ? "" : navigator.platform,
): string {
  return /mac|iphone|ipad|ipod/i.test(platform) ? "⌘K" : "Ctrl K";
}

/** Whether a key event is the palette's shortcut: ⌘K or Ctrl+K, no Alt/Shift. */
export function isPaletteShortcut(e: {
  key: string;
  metaKey: boolean;
  ctrlKey: boolean;
  altKey: boolean;
  shiftKey: boolean;
}): boolean {
  return (
    (e.key === "k" || e.key === "K") &&
    (e.metaKey || e.ctrlKey) &&
    !e.altKey &&
    !e.shiftKey
  );
}
