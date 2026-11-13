import { describe, expect, it } from "vitest";

import { messageOf } from "./messages";

describe("messageOf (#2617)", () => {
  it("reads the message of an Error and of a plain ApiError object", () => {
    expect(messageOf(new Error("refused"))).toBe("refused");
    expect(messageOf({ status: 403, message: "not yours" })).toBe("not yours");
  });

  it("falls back to the value as a string, never to an empty message", () => {
    expect(messageOf({ status: 500, message: "" })).toBe("[object Object]");
    expect(messageOf("plain")).toBe("plain");
    expect(messageOf(undefined)).toBe("undefined");
  });
});
