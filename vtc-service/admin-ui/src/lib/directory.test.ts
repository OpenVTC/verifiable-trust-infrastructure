import { describe, expect, it } from "vitest";

import {
  COMMUNITY_KEY_PATTERN,
  describeDisclosure,
  durationWords,
  widens,
  within,
} from "@/lib/directory";
import type { DirectoryDisclosure, DirectoryFieldDefinition } from "@/lib/wire-types";

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

// The spec's own small example (vtc/join-requests/manifest/0.4).
const statement: DirectoryDisclosure = {
  fields: [
    { key: "displayName", label: "Name", type: "text", source: "member", ceiling: "members", defaultVisibility: "members", searchable: true },
    { key: "bio", label: "About", type: "longText", source: "member", ceiling: "members", defaultVisibility: "admins", searchable: false },
    { key: "role", label: "Role", type: "text", source: "derived", ceiling: "members", defaultVisibility: "members", searchable: false },
  ],
  newCard: { listing: "listed", search: "byName" },
  membershipIdentifiers: "admins",
  adminNotes: false,
  externalCards: false,
  statementDigest: "zQmcPXnjL36U7nmj7oDPBuCSzdUd15C5aquDWkT4YGMDHge",
};

describe("the disclosure statement in words", () => {
  it("says what a new card shows, and to whom", () => {
    const words = describeDisclosure(statement);
    expect(words[0]).toBe("A new member's Name and Role are seen by other members until they change it.");
    expect(words).toContain(
      "Everything else on a new card is seen by administrators only until its member chooses otherwise.",
    );
    expect(words).toContain("The DID a member joins with is seen by administrators only.");
    expect(words).toContain("Administrators keep no notes about members.");
    expect(words).toContain("No card is ever published outside the community.");
    expect(words.some((w) => w.includes("group"))).toBe(false);
  });

  it("states every feature the community has", () => {
    const words = describeDisclosure({
      ...statement,
      fields: [
        ...statement.fields,
        { key: "org.example.chapter", label: "Chapter", type: "enum", source: "admin", ceiling: "members", defaultVisibility: "admins", searchable: false, facet: true },
      ],
      membershipIdentifiers: "public",
      adminNotes: true,
      groups: { credentialValidity: "P30D" },
      externalCards: true,
    });
    expect(words).toContain("The community writes Chapter itself; members read it and cannot change it.");
    expect(words).toContain(
      "The DID a member joins with is seen by administrators only, unless the member chooses to show it to anyone, outside the community too.",
    );
    expect(words).toContain("Administrators may keep notes about members. Notes never appear on a card.");
    expect(words.find((w) => w.includes("group"))).toContain("valid for 30 days at a time");
    expect(words).toContain(
      "A member may publish their card beyond the community; it is off until they turn it on.",
    );
  });

  it("puts whole days and weeks into words and leaves the rest as given", () => {
    expect(durationWords("P30D")).toBe("30 days");
    expect(durationWords("P2W")).toBe("14 days");
    expect(durationWords("P1D")).toBe("1 day");
    expect(durationWords("PT12H")).toBe("PT12H");
  });
});
