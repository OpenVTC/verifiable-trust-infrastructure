import { describe, expect, it } from "vitest";

import { pendingFoot, skipMessage } from "./pending";

const NOW = Date.parse("2026-10-16T16:45:00Z");

describe("pendingFoot", () => {
  it("names the oldest due job when one is due", () => {
    expect(pendingFoot(125, { count: 3 }, NOW)).toBe("oldest 2m");
  });

  it("is nothing waiting when the queue is empty", () => {
    expect(pendingFoot(null, { count: 0 }, NOW)).toBe("nothing waiting");
    expect(pendingFoot(undefined, undefined, NOW)).toBe("nothing waiting");
  });

  it("says jobs backing off are retrying, and when the first moves", () => {
    expect(
      pendingFoot(
        null,
        { count: 4, nextAttemptAt: "2026-10-16T16:57:30Z" },
        NOW,
      ),
    ).toBe("4 retrying — next in 12m");
  });

  it("says a retry is due once its time has passed", () => {
    expect(
      pendingFoot(null, { count: 1, nextAttemptAt: "2026-10-16T16:44:00Z" }, NOW),
    ).toBe("1 retrying — next attempt due");
  });
});

describe("skipMessage", () => {
  it("names each retry/0.2 skip reason", () => {
    const id = "1f2e3d4c-5b6a-4798-8765-43210fedcba9";
    expect(skipMessage(id, "notFound")).toMatch(/^Job 1f2e3d4c… is gone/);
    expect(skipMessage(id, "inFlight")).toMatch(/being sent/);
    expect(skipMessage(id, "held")).toMatch(/never sent early/);
  });
});
