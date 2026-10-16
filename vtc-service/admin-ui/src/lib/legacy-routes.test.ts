import { describe, expect, it } from "vitest";

import { legacyTarget } from "@/lib/legacy-routes";

describe("legacyTarget", () => {
  it("sends Storage and Room usage to their Data rooms tabs", () => {
    expect(legacyTarget("/storage")).toBe("/rooms/storage");
    expect(legacyTarget("/storage/")).toBe("/rooms/storage");
    expect(legacyTarget("/room-usage")).toBe("/rooms/usage");
  });

  it("carries a storage location's identifier, still encoded, and the query", () => {
    expect(legacyTarget("/storage/eu%20s3", "?x=1", "#top")).toBe("/rooms/storage/eu%20s3?x=1#top");
    expect(legacyTarget("/storage", "?create=1")).toBe("/rooms/storage?create=1");
  });

  it("leaves everything else alone, including a path that merely starts alike", () => {
    expect(legacyTarget("/rooms")).toBeNull();
    expect(legacyTarget("/storage-old")).toBeNull();
    expect(legacyTarget("/room-usages")).toBeNull();
  });
});
