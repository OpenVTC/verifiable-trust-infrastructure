import { describe, expect, it } from "vitest";

import { COMMUNITY_KEY_PATTERN, widens, within } from "@/lib/directory";
import type { DirectoryFieldDefinition } from "@/lib/wire-types";

const bio: DirectoryFieldDefinition = {
  key: "bio",
  label: "About",
  type: "longText",
  source: "member",
  base: true,
  required: false,
  ceiling: "public",
  defaultVisibility: "admins",
  searchable: false,
  facet: false,
  order: 40,
  state: "active",
};

describe("audiences mirror the daemon's order", () => {
  it("does not order groups and connections", () => {
    expect(within("groups", "connections")).toBe(false);
    expect(within("connections", "groups")).toBe(false);
    expect(within("groups", "members")).toBe(true);
    expect(within("admins", "groups")).toBe(true);
    expect(within("public", "members")).toBe(false);
  });
});

describe("a change that widens is told apart", () => {
  it("narrowing does not widen", () => {
    expect(widens(bio, { ...bio, ceiling: "members" })).toBe(false);
    expect(widens(bio, { ...bio, state: "disabled" })).toBe(false);
  });
  it("a wider default, search, a facet, re-enabling or dropping a requirement widens", () => {
    expect(widens(bio, { ...bio, defaultVisibility: "members" })).toBe(true);
    expect(widens(bio, { ...bio, searchable: true })).toBe(true);
    expect(widens({ ...bio, state: "disabled" }, bio)).toBe(true);
    expect(widens({ ...bio, required: true }, bio)).toBe(true);
  });
});

describe("community keys", () => {
  it("are reverse-DNS, as the daemon requires", () => {
    expect(COMMUNITY_KEY_PATTERN.test("org.example.employer")).toBe(true);
    expect(COMMUNITY_KEY_PATTERN.test("employer")).toBe(false);
    expect(COMMUNITY_KEY_PATTERN.test("org.example.one-more")).toBe(false);
  });
});
