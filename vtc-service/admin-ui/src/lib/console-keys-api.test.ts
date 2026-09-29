// Enrolment and revocation, as sequences of requests rather than as clicks.
//
// The thing worth asserting is the *order*: the passkey gesture happens before
// the POST that writes the delegation, and the `consoleDid` posted is the one
// this browser can actually sign with.

import { afterEach, describe, expect, it, vi } from "vitest";

import {
  enrolThisBrowser,
  isStepUpRequired,
  listConsoleKeys,
  revokeConsoleKey,
} from "./console-keys-api";
import {
  forgetConsoleKey,
  generateConsoleKey,
  loadConsoleKey,
  resetConsoleKeyCacheForTests,
} from "./console-key";
import { mockFetch, type MockRoute, type RecordedRequest } from "@/test/render";

const ADMIN_DID = "did:webvh:QmScid:community.example:alice";

afterEach(async () => {
  await forgetConsoleKey();
  resetConsoleKeyCacheForTests();
  vi.unstubAllGlobals();
});

/** A passkey that always says yes, so the step-up is a step and not a wall. */
function stubAuthenticator(): void {
  vi.stubGlobal("navigator", {
    ...globalThis.navigator,
    credentials: {
      get: () =>
        Promise.resolve({
          id: "cred",
          rawId: new Uint8Array([1]).buffer,
          type: "public-key",
          response: {
            authenticatorData: new Uint8Array([2]).buffer,
            clientDataJSON: new Uint8Array([3]).buffer,
            signature: new Uint8Array([4]).buffer,
            userHandle: null,
          },
        }),
    },
  });
}

const STEP_UP_ROUTES: MockRoute[] = [
  {
    method: "POST",
    path: "/v1/auth/passkey-login/start",
    body: { authId: "auth-1", options: { challenge: "AAAA", allowCredentials: [] } },
  },
  { method: "POST", path: "/v1/auth/passkey-login/finish", body: {} },
];

function consoleKeyRow(consoleDid: string, patch: Record<string, unknown> = {}) {
  return {
    consoleDid,
    adminDid: ADMIN_DID,
    createdAt: "2026-09-23T10:00:00Z",
    active: true,
    ...patch,
  };
}

describe("enrolment", () => {
  it("runs the passkey gesture first, then posts the key this browser holds", async () => {
    stubAuthenticator();
    const requests: RecordedRequest[] = mockFetch([
      ...STEP_UP_ROUTES,
      {
        method: "POST",
        path: "/v1/admin/console-keys",
        status: 201,
        body: ({ body }) =>
          consoleKeyRow((body as { consoleDid: string }).consoleDid, {
            label: "Work laptop",
          }),
      },
    ]);

    const enrolled = await enrolThisBrowser("  Work laptop  ");

    // The key exists in this browser and is the one that was enrolled.
    const held = await loadConsoleKey();
    expect(held).not.toBeNull();
    expect(enrolled.consoleDid).toBe(held!.consoleDid);

    const paths = requests.map((r) => `${r.method} ${r.url}`);
    expect(paths).toEqual([
      "POST /v1/auth/passkey-login/start",
      "POST /v1/auth/passkey-login/finish",
      "POST /v1/admin/console-keys",
    ]);

    // The gesture is what stops a stolen session leaving a signing key behind,
    // so it must precede the write rather than follow a caught refusal.
    const enrol = requests.at(-1)!;
    expect(enrol.body).toEqual({
      consoleDid: held!.consoleDid,
      label: "Work laptop",
    });
    // There is no `adminDid` member on this surface and there must not be one:
    // the delegation is always written against the proven caller.
    expect(Object.keys(enrol.body as object)).not.toContain("adminDid");
  });

  it("omits an empty label rather than sending one", async () => {
    stubAuthenticator();
    const requests = mockFetch([
      ...STEP_UP_ROUTES,
      {
        method: "POST",
        path: "/v1/admin/console-keys",
        status: 201,
        body: ({ body }) => consoleKeyRow((body as { consoleDid: string }).consoleDid),
      },
    ]);
    await enrolThisBrowser("   ");
    expect(requests.at(-1)!.body).toEqual({
      consoleDid: (await loadConsoleKey())!.consoleDid,
    });
  });

  it("reuses the key this browser already holds rather than minting a second", async () => {
    stubAuthenticator();
    const existing = await generateConsoleKey();
    const requests = mockFetch([
      ...STEP_UP_ROUTES,
      {
        method: "POST",
        path: "/v1/admin/console-keys",
        status: 201,
        body: ({ body }) => consoleKeyRow((body as { consoleDid: string }).consoleDid),
      },
    ]);
    const enrolled = await enrolThisBrowser();
    expect(enrolled.consoleDid).toBe(existing.consoleDid);
    expect((requests.at(-1)!.body as { consoleDid: string }).consoleDid).toBe(
      existing.consoleDid,
    );
  });

  it("does not write a delegation when the operator refuses the passkey", async () => {
    vi.stubGlobal("navigator", {
      ...globalThis.navigator,
      credentials: { get: () => Promise.reject(new Error("NotAllowedError")) },
    });
    const requests = mockFetch([
      ...STEP_UP_ROUTES,
      { method: "POST", path: "/v1/admin/console-keys", status: 201, body: {} },
    ]);

    await expect(enrolThisBrowser()).rejects.toThrow();
    expect(requests.map((r) => r.url)).not.toContain("/v1/admin/console-keys");
  });

  it("recognises the daemon's step-up refusal for what it is", async () => {
    // A 403 here means two different things, and only the body says which:
    // `step_up_required` is "do the ceremony and retry"; anything else is a
    // real permission failure and retrying will not help.
    expect(isStepUpRequired({ status: 403, message: "step_up_required" })).toBe(true);
    expect(isStepUpRequired({ status: 403, message: "auth:step_up_required" })).toBe(
      true,
    );
    expect(isStepUpRequired({ status: 403, message: "Caller is not an admin" })).toBe(
      false,
    );
  });
});

describe("listing", () => {
  it("returns the rows as the daemon computed them, `active` included", async () => {
    mockFetch([
      {
        method: "GET",
        path: "/v1/admin/console-keys",
        body: {
          consoleKeys: [
            consoleKeyRow("did:key:zA"),
            consoleKeyRow("did:key:zB", {
              active: false,
              revokedAt: "2026-09-22T09:00:00Z",
            }),
          ],
        },
      },
    ]);
    const keys = await listConsoleKeys();
    expect(keys.map((k) => [k.consoleDid, k.active])).toEqual([
      ["did:key:zA", true],
      ["did:key:zB", false],
    ]);
  });
});

describe("revocation", () => {
  it("needs no second factor, and forgets the local key when it is this browser's", async () => {
    // Requiring a gesture to *withdraw* a credential is a gate that protects
    // the attacker. And keeping the local key after revoking it would leave a
    // browser signing documents the daemon refuses, which an operator meets as
    // a console that has quietly stopped working.
    const key = await generateConsoleKey();
    const requests = mockFetch([
      { method: "DELETE", path: `/v1/admin/console-keys/${encodeURIComponent(key.consoleDid)}`, body: {} },
    ]);

    await revokeConsoleKey(key.consoleDid);

    expect(requests.map((r) => r.method)).toEqual(["DELETE"]);
    resetConsoleKeyCacheForTests();
    expect(await loadConsoleKey()).toBeNull();
  });

  it("leaves this browser's key alone when revoking another browser's", async () => {
    const key = await generateConsoleKey();
    mockFetch([
      { method: "DELETE", path: "/v1/admin/console-keys/did%3Akey%3AzOther", body: {} },
    ]);

    await revokeConsoleKey("did:key:zOther");

    resetConsoleKeyCacheForTests();
    expect((await loadConsoleKey())?.consoleDid).toBe(key.consoleDid);
  });
});
