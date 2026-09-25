// Members' step-up passkeys: the invite token read from the URL fragment, and
// the order of the redemption's ceremonies.

import { afterEach, describe, expect, it, vi } from "vitest";

import { redeemFinish, tokenFromHash } from "./step-up-passkeys";
import type { StepUpPasskeyRedeemStarted } from "./wire-types";
import { mockFetch } from "@/test/render";

afterEach(() => vi.unstubAllGlobals());

const TOKEN = "sup_0123456789abcdef0123456789abcdef";

describe("tokenFromHash", () => {
  it("reads the token from the fragment, and nothing that is not one", () => {
    expect(tokenFromHash(`#token=${TOKEN}`)).toBe(TOKEN);
    expect(tokenFromHash("")).toBeNull();
    expect(tokenFromHash("#token=short")).toBeNull();
    expect(tokenFromHash(`#request=${TOKEN}`)).toBeNull();
  });
});

function fakeCredentials(order: string[]) {
  const cred = {
    id: "AQID",
    rawId: new Uint8Array([1, 2, 3]).buffer,
    type: "public-key",
    response: {
      clientDataJSON: new Uint8Array([1]).buffer,
      authenticatorData: new Uint8Array([2]).buffer,
      signature: new Uint8Array([3]).buffer,
      attestationObject: new Uint8Array([4]).buffer,
      userHandle: null,
    },
    getClientExtensionResults: () => ({}),
  };
  return {
    get: vi.fn(async () => {
      order.push("get");
      return cred;
    }),
    create: vi.fn(async () => {
      order.push("create");
      return cred;
    }),
  };
}

const STARTED = {
  enrollmentId: "e-1",
  subject: "did:webvh:QmCarol:carol.dev",
  purpose: "stepUp",
  options: {
    challenge: "Y2hhbGxlbmdlLWNyZWF0ZQ",
    rp: { id: "community.example", name: "VTC" },
    user: { id: "dXNlcg", name: "carol", displayName: "carol" },
    pubKeyCredParams: [{ type: "public-key", alg: -8 }],
  },
  expiresAt: "2026-09-25T12:05:00Z",
} as unknown as StepUpPasskeyRedeemStarted;

describe("redeemFinish", () => {
  it("creates the passkey and sends it, with no gesture when none is held", async () => {
    const requests = mockFetch([
      { method: "POST", path: "/v1/step-up-passkeys/redeem/finish", body: { credentialId: "01" } },
    ]);
    const order: string[] = [];
    await redeemFinish(STARTED, "Laptop", fakeCredentials(order));
    expect(order).toEqual(["create"]);
    const body = requests.find((r) => r.url === "/v1/step-up-passkeys/redeem/finish")!.body as Record<
      string,
      unknown
    >;
    expect(body.enrollmentId).toBe("e-1");
    expect(body.deviceLabel).toBe("Laptop");
    expect(body).not.toHaveProperty("uvCredential");
  });

  it("asks the passkey already held first, and sends both", async () => {
    const requests = mockFetch([
      { method: "POST", path: "/v1/step-up-passkeys/redeem/finish", body: { credentialId: "01" } },
    ]);
    const order: string[] = [];
    await redeemFinish(
      {
        ...STARTED,
        uvOptions: { challenge: "Y2hhbGxlbmdlLWdldA", allowCredentials: [{ type: "public-key", id: "AQID" }] },
      } as unknown as StepUpPasskeyRedeemStarted,
      undefined,
      fakeCredentials(order),
    );
    expect(order).toEqual(["get", "create"]);
    const body = requests.find((r) => r.url === "/v1/step-up-passkeys/redeem/finish")!.body as Record<
      string,
      unknown
    >;
    expect(body).toHaveProperty("uvCredential");
  });
});
