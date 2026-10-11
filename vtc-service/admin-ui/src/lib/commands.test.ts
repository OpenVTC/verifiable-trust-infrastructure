import { describe, expect, it } from "vitest";

import {
  NAVIGATION_ACTIONS,
  actionCommands,
  commandScore,
  filterCommands,
  isPaletteShortcut,
  paletteShortcutLabel,
  queryCommands,
  screenCommands,
  termScore,
  type Command,
} from "@/lib/commands";
import type { PluginManifest } from "@/plugin-api";

const plugin = (id: string, label: string, path = `/${id}`): PluginManifest => ({
  id,
  label,
  path,
  reactComponent: () => null,
});

const SCREENS = screenCommands([
  { plugin: plugin("dashboard", "Dashboard", "/"), group: "Overview" },
  { plugin: plugin("members", "Members"), group: "Membership" },
  { plugin: plugin("join-requests", "Join requests"), group: "Membership" },
  { plugin: plugin("acl", "Access control"), group: "Governance" },
  { plugin: plugin("weather", "Weather station"), group: "More" },
]);

const labels = (cs: Command[]) => cs.map((c) => c.label);

describe("termScore", () => {
  it("ranks a prefix over a word start over a substring over letters in order", () => {
    const prefix = termScore("acc", "Access control")!;
    const word = termScore("con", "Access control")!;
    const sub = termScore("ntro", "Access control")!;
    const loose = termScore("acl", "Access control")!;
    expect(prefix).toBeGreaterThan(word);
    expect(word).toBeGreaterThan(sub);
    expect(sub).toBeGreaterThan(loose);
    expect(loose).toBeGreaterThan(0);
  });

  it("matches initials, ignores case and accents, and refuses letters out of order", () => {
    expect(termScore("jr", "Join requests")).not.toBeNull();
    expect(termScore("JOIN", "join requests")).not.toBeNull();
    expect(termScore("resume", "Résumé")).not.toBeNull();
    expect(termScore("lca", "Access control")).toBeNull();
  });
});

describe("filterCommands", () => {
  it("returns everything, in the order given, for an empty query", () => {
    expect(labels(filterCommands(SCREENS, "  "))).toEqual(labels(SCREENS));
  });

  it("puts the best match first", () => {
    expect(labels(filterCommands(SCREENS, "mem"))[0]).toBe("Members");
    expect(labels(filterCommands(SCREENS, "acl"))[0]).toBe("Access control");
  });

  it("finds a screen by a word it answers to, or by its nav group", () => {
    expect(labels(filterCommands(SCREENS, "people"))).toEqual(["Members"]);
    expect(labels(filterCommands(SCREENS, "membership"))).toContain("Join requests");
  });

  it("lists a plugin registered by a third party, which names no keywords", () => {
    expect(labels(filterCommands(SCREENS, "weather"))).toEqual(["Weather station"]);
  });

  it("needs every term to match", () => {
    expect(labels(filterCommands(SCREENS, "join req"))).toEqual(["Join requests"]);
    expect(filterCommands(SCREENS, "join zzz")).toEqual([]);
  });

  it("scores the label above a keyword", () => {
    const viaLabel = commandScore(SCREENS[1]!, "members")!;
    const viaKeyword = commandScore(SCREENS[1]!, "people")!;
    expect(viaLabel).toBeGreaterThan(viaKeyword);
  });
});

describe("actionCommands", () => {
  it("offers an action only when the screen it needs is visible", () => {
    const onlyMembers = labels(actionCommands(NAVIGATION_ACTIONS, new Set(["members"])));
    expect(onlyMembers).toContain("Add a member");
    expect(onlyMembers).not.toContain("Invite a member");
    expect(onlyMembers).not.toContain("Add an access-control entry");
    const always = actionCommands([{ id: "x", label: "Sign out", run: () => {} }], new Set());
    expect(labels(always)).toEqual(["Sign out"]);
  });

  it("navigates to the routes the screens already have", () => {
    const all = actionCommands(NAVIGATION_ACTIONS, new Set(NAVIGATION_ACTIONS.map((a) => a.requires!)));
    expect(all.find((a) => a.label === "Add a member")?.to).toBe("/members?add=1");
    expect(all.find((a) => a.label === "Review actions waiting for you")?.to).toBe(
      "/actions?tab=waitingForMe",
    );
  });
});

describe("queryCommands", () => {
  const members = new Set(["members"]);

  it("offers a member search for any query, and opens a DID directly", () => {
    expect(labels(queryCommands("ada", members))).toEqual(["Search members for “ada”"]);
    const did = "did:webvh:Qm123:example.org:ada";
    const cs = queryCommands(did, members);
    expect(cs[0]!.label).toBe(`Open member ${did}`);
    expect(cs[0]!.to).toBe(`/members/${encodeURIComponent(did)}`);
    expect(cs[1]!.to).toBe(`/members?q=${encodeURIComponent(did)}`);
  });

  it("offers neither without the Members screen, or without a query", () => {
    expect(queryCommands("ada", new Set())).toEqual([]);
    expect(queryCommands("  ", members)).toEqual([]);
  });
});

describe("the shortcut", () => {
  const key = (over: Partial<Parameters<typeof isPaletteShortcut>[0]>) => ({
    key: "k",
    metaKey: false,
    ctrlKey: false,
    altKey: false,
    shiftKey: false,
    ...over,
  });

  it("is ⌘K or Ctrl+K, and nothing else", () => {
    expect(isPaletteShortcut(key({ metaKey: true }))).toBe(true);
    expect(isPaletteShortcut(key({ ctrlKey: true }))).toBe(true);
    expect(isPaletteShortcut(key({ ctrlKey: true, key: "K" }))).toBe(true);
    expect(isPaletteShortcut(key({}))).toBe(false);
    expect(isPaletteShortcut(key({ ctrlKey: true, shiftKey: true }))).toBe(false);
    expect(isPaletteShortcut(key({ ctrlKey: true, key: "j" }))).toBe(false);
  });

  it("is labelled for the platform", () => {
    expect(paletteShortcutLabel("MacIntel")).toBe("⌘K");
    expect(paletteShortcutLabel("Win32")).toBe("Ctrl K");
  });
});
