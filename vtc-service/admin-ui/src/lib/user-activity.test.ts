// The console tells the daemon which signed documents the operator caused,
// so working in the console counts toward the idle timeout and a timer's
// poll does not.

import { afterEach, describe, expect, it } from "vitest";

import { postSignedTrustTask } from "./api";
import { forgetConsoleKey, generateConsoleKey, resetConsoleKeyCacheForTests } from "./console-key";
import {
  ACTIVE_WINDOW_MS,
  noteUserInput,
  operatorIsActive,
  resetUserActivityForTests,
  USER_ACTIVITY_HEADER,
} from "./user-activity";
import { mockFetch } from "@/test/render";

const VTC_DID = "did:webvh:QmScid:community.example:vtc";
const SHOW = "https://trusttasks.org/spec/config/show/0.1";

afterEach(async () => {
  resetUserActivityForTests();
  await forgetConsoleKey();
  resetConsoleKeyCacheForTests();
});

describe("operatorIsActive", () => {
  it("is false before any input", () => {
    expect(operatorIsActive()).toBe(false);
  });

  it("holds for the window after input, then lapses", () => {
    noteUserInput(1_000_000);
    expect(operatorIsActive(1_000_000 + ACTIVE_WINDOW_MS - 1)).toBe(true);
    expect(operatorIsActive(1_000_000 + ACTIVE_WINDOW_MS)).toBe(false);
  });
});

async function postAndReadHeader(): Promise<string | null> {
  await generateConsoleKey();
  const requests = mockFetch([
    {
      method: "GET",
      path: "/health",
      body: { status: "ok", version: "t", vtc_did: VTC_DID },
    },
    {
      method: "POST",
      path: "/v1/trust-tasks",
      body: {
        id: "urn:uuid:response",
        type: `${SHOW}#response`,
        issuer: VTC_DID,
        recipient: "did:key:zConsole",
        issuedAt: "2026-10-05T10:15:01Z",
        threadId: "urn:uuid:request",
        payload: { fields: [] },
      },
    },
  ]);
  await postSignedTrustTask(SHOW, {});
  const sent = requests.find((r) => r.url === "/v1/trust-tasks");
  expect(sent).toBeDefined();
  return sent!.headers.get(USER_ACTIVITY_HEADER);
}

describe("signed documents", () => {
  it("carry the activity header while the operator is giving input", async () => {
    noteUserInput();
    expect(await postAndReadHeader()).toBe("1");
  });

  it("do not when nobody has touched the console, as a timer's poll would not", async () => {
    expect(await postAndReadHeader()).toBeNull();
  });

  it("stop carrying it once input is older than the window", async () => {
    noteUserInput(Date.now() - ACTIVE_WINDOW_MS - 1);
    expect(await postAndReadHeader()).toBeNull();
  });
});
