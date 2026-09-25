// The operation-bound step-up: reading the request off a refusal, carrying it
// in a URL fragment from `cnm`, and the approve-response the console sends.

import { afterEach, describe, expect, it, vi } from "vitest";

import {
  answerStepUp,
  APPROVE_RESPONSE_URI,
  decodeStepUpRequest,
  encodeStepUpRequest,
  stepUpRequestOf,
  type StepUpRequest,
} from "./bound-step-up";
import type { SignedTrustTaskDocument } from "./console-key";
import { forgetConsoleKey, generateConsoleKey, resetConsoleKeyCacheForTests } from "./console-key";
import { mockFetch } from "@/test/render";

const VTC_DID = "did:webvh:QmScid:community.example:vtc";
const ADMIN = "did:webvh:QmAlice:alice.dev";
const CHALLENGE = "c2FtcGxlLWNoYWxsZW5nZS0xMjM0NQ";

const REQUEST: StepUpRequest = {
  subject: ADMIN,
  challenge: CHALLENGE,
  boundTo: "zBoundDigest",
  reason: "Break glass: git.repo.own on github.com/acme/docs — “CVE fix”",
  targetAcr: "aal2",
  acceptableEvidence: ["webauthn"],
  webauthn: {
    challenge: CHALLENGE,
    allowCredentials: [{ type: "public-key", id: "AQID" }],
    userVerification: "required",
    rpId: "community.example",
  },
  ttl: 300,
};

afterEach(async () => {
  await forgetConsoleKey();
  resetConsoleKeyCacheForTests();
  vi.unstubAllGlobals();
});

describe("reading a step-up request", () => {
  it("finds it in a refusal's details, and nowhere else", () => {
    expect(stepUpRequestOf({ status: 403, message: "x", details: { stepUpRequest: REQUEST } })).toEqual(
      REQUEST,
    );
    expect(stepUpRequestOf({ status: 403, message: "x" })).toBeNull();
    expect(stepUpRequestOf({ details: { stepUpRequest: { subject: ADMIN } } })).toBeNull();
    expect(stepUpRequestOf({ details: { stepUpRequest: { ...REQUEST, challenge: "short" } } })).toBeNull();
    expect(stepUpRequestOf(null)).toBeNull();
  });

  it("round-trips through the #request= fragment cnm prints, unicode included", () => {
    const hash = `#request=${encodeStepUpRequest(REQUEST)}`;
    expect(hash).toMatch(/^#request=[A-Za-z0-9_-]+$/);
    expect(decodeStepUpRequest(hash)).toEqual(REQUEST);
  });

  it("reads nothing from a fragment that is absent, malformed or not a request", () => {
    expect(decodeStepUpRequest("")).toBeNull();
    expect(decodeStepUpRequest("#request=")).toBeNull();
    expect(decodeStepUpRequest("#request=not+base64url")).toBeNull();
    const notJson = btoa("{not json").replace(/=+$/, "").replace(/\+/g, "-").replace(/\//g, "_");
    expect(decodeStepUpRequest(`#request=${notJson}`)).toBeNull();
    const notRequest = btoa(JSON.stringify({ hello: "world" })).replace(/=+$/, "");
    expect(decodeStepUpRequest(`#request=${notRequest}`)).toBeNull();
  });
});

function fakeCredentials() {
  const buf = (s: string) => new TextEncoder().encode(s).buffer as ArrayBuffer;
  const get = vi.fn(async () => ({
    id: "AQID",
    rawId: buf("\u0001\u0002\u0003"),
    type: "public-key",
    response: {
      authenticatorData: buf("authdata"),
      clientDataJSON: buf("clientdata"),
      signature: buf("sig"),
      userHandle: null,
    },
  }));
  return { get } as unknown as Pick<CredentialsContainer, "get"> & { get: typeof get };
}

describe("answering a step-up", () => {
  it("asks the passkey over the request's own challenge and sends the approve-response", async () => {
    await generateConsoleKey();
    const requests = mockFetch([
      { path: "/health", body: { status: "ok", version: "t", vtc_did: VTC_DID } },
      {
        method: "POST",
        path: "/v1/trust-tasks",
        body: { type: `${APPROVE_RESPONSE_URI}#response`, payload: { status: "recorded", boundTo: "zBoundDigest" } },
      },
    ]);
    const creds = fakeCredentials();
    const ack = await answerStepUp(REQUEST, creds);
    expect(ack.status).toBe("recorded");

    const opts = (creds.get.mock.calls[0] as unknown as [CredentialRequestOptions])[0].publicKey!;
    expect(new Uint8Array(opts.challenge as ArrayBuffer)).toEqual(
      new Uint8Array(Uint8Array.from(atob(CHALLENGE.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0))),
    );
    expect(opts.userVerification).toBe("required");

    const doc = requests.find((r) => r.url === "/v1/trust-tasks")!.body as SignedTrustTaskDocument;
    expect(doc.type).toBe(APPROVE_RESPONSE_URI);
    expect(doc.payload).toMatchObject({
      subject: ADMIN,
      challenge: CHALLENGE,
      decision: "approved",
      evidence: { kind: "webauthn", assertion: { id: "AQID", type: "public-key" } },
    });
    // A bound step-up carries no session.
    expect(doc.payload).not.toHaveProperty("sessionId");
  });

  it("refuses options whose challenge is not the request's, before asking for a gesture", async () => {
    const creds = fakeCredentials();
    await expect(
      answerStepUp({ ...REQUEST, webauthn: { ...REQUEST.webauthn!, challenge: "b3RoZXItY2hhbGxlbmdlLXh4eA" } }, creds),
    ).rejects.toThrow(/does not match/);
    expect(creds.get).not.toHaveBeenCalled();
  });

  it("answers unsigned from a browser with no console key — a member's step-up passkey", async () => {
    // No generateConsoleKey(): a member who is no console user.
    const requests = mockFetch([
      { path: "/health", body: { status: "ok", version: "t", vtc_did: VTC_DID } },
      {
        method: "POST",
        path: "/v1/trust-tasks",
        body: { type: `${APPROVE_RESPONSE_URI}#response`, payload: { status: "recorded", boundTo: "zBoundDigest" } },
      },
    ]);
    const ack = await answerStepUp(REQUEST, fakeCredentials());
    expect(ack.status).toBe("recorded");
    const doc = requests.find((r) => r.url === "/v1/trust-tasks")!.body as Record<string, unknown>;
    expect(doc).not.toHaveProperty("proof");
    expect(doc.issuer).toBe(ADMIN);
    expect(doc.recipient).toBe(VTC_DID);
  });

  it("reports a gesture the VTC did not record", async () => {
    await generateConsoleKey();
    mockFetch([
      { path: "/health", body: { status: "ok", version: "t", vtc_did: VTC_DID } },
      {
        method: "POST",
        path: "/v1/trust-tasks",
        body: { payload: { status: "rejected", reason: "challenge expired" } },
      },
    ]);
    await expect(answerStepUp(REQUEST, fakeCredentials())).rejects.toThrow(/challenge expired/);
  });
});
