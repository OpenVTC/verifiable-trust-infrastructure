// "Remove now" in single-administrator mode (vtc-action-list.md §8.5): what
// the console adds to a reduction's payload, and which confirmations it takes.

import { describe, expect, it } from "vitest";

import { immediateConfirmMatches, withImmediate } from "./immediate";

describe("withImmediate", () => {
  it("adds ext.org.openvtc.immediate and keeps everything else", () => {
    const payload = {
      subject: "did:example:b",
      reason: "left",
      ext: { "org.openvtc": { communityRole: "admin" }, "com.example": { x: 1 } },
    };
    expect(withImmediate(payload, " did:example:b ", "act-1")).toEqual({
      subject: "did:example:b",
      reason: "left",
      ext: {
        "org.openvtc": {
          communityRole: "admin",
          immediate: { confirm: "did:example:b", actionId: "act-1" },
        },
        "com.example": { x: 1 },
      },
    });
    // The original is untouched: the delayed operation stays what it was.
    expect(payload.ext["org.openvtc"]).toEqual({ communityRole: "admin" });
  });

  it("names no action when landing none", () => {
    expect(withImmediate({ subject: "did:example:b" }, "did:example:b")).toEqual({
      subject: "did:example:b",
      ext: { "org.openvtc": { immediate: { confirm: "did:example:b" } } },
    });
  });
});

describe("immediateConfirmMatches", () => {
  it("takes the subject's DID, or the action's id when landing one", () => {
    expect(immediateConfirmMatches("did:example:b", "did:example:b")).toBe(true);
    expect(immediateConfirmMatches(" did:example:b\n", "did:example:b")).toBe(true);
    expect(immediateConfirmMatches("act-1", "did:example:b")).toBe(false);
    expect(immediateConfirmMatches("act-1", "did:example:b", "act-1")).toBe(true);
    expect(immediateConfirmMatches("did:example:c", "did:example:b", "act-1")).toBe(false);
    expect(immediateConfirmMatches("", undefined, "act-1")).toBe(false);
  });
});
