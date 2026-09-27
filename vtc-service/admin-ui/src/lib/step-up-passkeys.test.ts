// Members' step-up passkeys: what the enrol page reads from its fragment, and
// the redemption's finish — its ceremonies' order, and that it is the
// `redeem/finish` Trust Task on the document endpoint.

import { afterEach, describe, expect, it, vi } from "vitest";

import {
  enrollmentFromHash,
  REDEEM_FINISH_TASK,
  redeemCommand,
  redeemFinish,
  tokenFromHash,
  type RedeemStarted,
} from "./step-up-passkeys";
import { bufferToBase64url } from "./webauthn";
import { mockFetch } from "@/test/render";

afterEach(() => vi.unstubAllGlobals());

const TOKEN = "sup_0123456789abcdef0123456789abcdef";
const VTC_DID = "did:webvh:QmScid:community.example:vtc";

describe("tokenFromHash", () => {
  it("reads the token from the fragment, and nothing that is not one", () => {
    expect(tokenFromHash(`#token=${TOKEN}`)).toBe(TOKEN);
    expect(tokenFromHash("")).toBeNull();
    expect(tokenFromHash("#token=short")).toBeNull();
    expect(tokenFromHash(`#request=${TOKEN}`)).toBeNull();
    expect(tokenFromHash(`#token=${TOKEN}'`)).toBeNull();
  });
});

describe("the redemption cnm hands over", () => {
  const encode = (v: unknown) =>
    bufferToBase64url(new TextEncoder().encode(JSON.stringify(v)).buffer as ArrayBuffer);

  it("reads the redeem/start response from #enrollment=, and nothing that is not one", () => {
    expect(enrollmentFromHash(`#enrollment=${encode(STARTED)}`)).toEqual(STARTED);
    expect(enrollmentFromHash("")).toBeNull();
    expect(enrollmentFromHash("#enrollment=not+base64")).toBeNull();
    expect(enrollmentFromHash(`#enrollment=${encode({ ...STARTED, purpose: "session" })}`)).toBeNull();
    expect(enrollmentFromHash(`#enrollment=${encode({ enrollmentId: "e" })}`)).toBeNull();
  });

  it("tells the member the cnm command that signs the start", () => {
    expect(redeemCommand(`https://vtc.example/admin/enrol-step-up#token=${TOKEN}`)).toBe(
      `cnm git enrol-step-up-passkey 'https://vtc.example/admin/enrol-step-up#token=${TOKEN}'`,
    );
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
} as unknown as RedeemStarted;

describe("redeemFinish", () => {
  it("creates the passkey and sends it, with no gesture when none is held", async () => {
    const requests = mockFetch([
      { path: "/health", body: { status: "ok", version: "t", vtc_did: VTC_DID } },
      {
        method: "POST",
        path: "/v1/trust-tasks",
        body: { type: `${REDEEM_FINISH_TASK}#response`, payload: { credentialId: "01" } },
      },
    ]);
    const order: string[] = [];
    await redeemFinish(STARTED, "Laptop", fakeCredentials(order));
    expect(order).toEqual(["create"]);
    const doc = requests.find((r) => r.url === "/v1/trust-tasks")!.body as Record<string, unknown>;
    expect(doc.type).toBe(REDEEM_FINISH_TASK);
    expect(doc.recipient).toBe(VTC_DID);
    const body = doc.payload as Record<string, unknown>;
    expect(body.enrollmentId).toBe("e-1");
    expect(body.deviceLabel).toBe("Laptop");
    expect(body).not.toHaveProperty("uvCredential");
  });

  it("asks the passkey already held first, and sends both", async () => {
    const requests = mockFetch([
      { path: "/health", body: { status: "ok", version: "t", vtc_did: VTC_DID } },
      {
        method: "POST",
        path: "/v1/trust-tasks",
        body: { type: `${REDEEM_FINISH_TASK}#response`, payload: { credentialId: "01" } },
      },
    ]);
    const order: string[] = [];
    await redeemFinish(
      {
        ...STARTED,
        uvOptions: { challenge: "Y2hhbGxlbmdlLWdldA", allowCredentials: [{ type: "public-key", id: "AQID" }] },
      } as unknown as RedeemStarted,
      undefined,
      fakeCredentials(order),
    );
    expect(order).toEqual(["get", "create"]);
    const doc = requests.find((r) => r.url === "/v1/trust-tasks")!.body as Record<string, unknown>;
    expect(doc.type).toBe(REDEEM_FINISH_TASK);
    expect(doc.recipient).toBe(VTC_DID);
    const body = doc.payload as Record<string, unknown>;
    expect(body).toHaveProperty("uvCredential");
  });
});
