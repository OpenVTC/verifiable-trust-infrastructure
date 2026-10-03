// The operation-bound step-up: reading the request off a refusal, carrying it
// in a URL fragment from `cnm`, and the approve-response the console sends.

import { afterEach, describe, expect, it, vi } from "vitest";

import {
  ANSWER_CODE_PREFIX,
  answerCodeOf,
  answerableHere,
  answerStepUp,
  APPROVE_RESPONSE_URI,
  APPROVE_RESPONSE_V0_6_URI,
  runStepUpCeremony,
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
    // Unsigned, naming the subject: the console key is a delegation, and a
    // delegated key is never accepted as an approver's attestation — the
    // passkey assertion is the gate.
    expect(doc).not.toHaveProperty("proof");
    expect(doc.issuer).toBe(ADMIN);
  });

  it("refuses options whose challenge is not the request's, before asking for a gesture", async () => {
    const creds = fakeCredentials();
    await expect(
      answerStepUp({ ...REQUEST, webauthn: { ...REQUEST.webauthn!, challenge: "b3RoZXItY2hhbGxlbmdlLXh4eA" } }, creds),
    ).rejects.toThrow(/does not match/);
    expect(creds.get).not.toHaveBeenCalled();
  });

  it("hands the assertion to cnm as one answer-code line", async () => {
    const credential = await runStepUpCeremony(REQUEST, fakeCredentials());
    const code = answerCodeOf(credential);
    expect(code.startsWith(ANSWER_CODE_PREFIX)).toBe(true);
    const parts = code.slice(ANSWER_CODE_PREFIX.length).split(".");
    // rawId, authenticatorData, clientDataJSON, signature — no userHandle.
    expect(parts).toHaveLength(4);
    expect(parts.every((p) => /^[A-Za-z0-9_-]+$/.test(p))).toBe(true);
    expect(parts[0]).toBe("AQID");
    expect(code).not.toMatch(/\s/);
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

describe("answering with a step-up approver (approve-response 0.6)", () => {
  const APPROVER = "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH";
  const OPERATION = {
    type: "https://trusttasks.org/spec/acl/grant/0.1",
    payload: { entry: { subject: "did:key:z6MkBob", role: "admin", scopes: [] } },
  };
  const APPROVER_REQUEST: StepUpRequest = {
    subject: ADMIN,
    challenge: CHALLENGE,
    boundTo: "zBoundDigest",
    reason: "Grant the administrator role to did:key:z6MkBob",
    accepts: ["approverSigned", "webauthn"],
    approvers: [APPROVER],
    webauthn: REQUEST.webauthn,
    ttl: 300,
  };
  const STATEMENT = {
    id: "urn:uuid:statement-1",
    type: "https://trusttasks.org/spec/auth/step-up/approver/attest/0.1",
    issuer: APPROVER,
    recipient: VTC_DID,
    issuedAt: "2026-10-02T09:00:00Z",
    payload: {
      purpose: "stepUp",
      subject: ADMIN,
      audience: VTC_DID,
      challenge: CHALLENGE,
      boundTo: "zBoundDigest",
    },
    proof: { type: "DataIntegrityProof", verificationMethod: `${APPROVER}#${APPROVER.slice(8)}` },
  };

  function installWallet(withApprover: boolean) {
    const approveStepUp = vi.fn(async () => ({ statement: STATEMENT, approverDid: APPROVER }));
    const signTrustTask = vi.fn(
      async ({ envelope, asDid }: { envelope: Record<string, unknown>; asDid?: string }) => ({
        signedEnvelope: {
          ...envelope,
          proof: {
            type: "DataIntegrityProof",
            proofPurpose: "assertionMethod",
            verificationMethod: `${asDid}#key-1`,
          },
        },
        holderDid: asDid!,
      }),
    );
    (window as unknown as { vtaWallet: unknown }).vtaWallet = {
      login: vi.fn(),
      signTrustTask,
      ...(withApprover ? { approveStepUp } : {}),
    };
    return { approveStepUp, signTrustTask };
  }

  afterEach(() => {
    delete (window as unknown as { vtaWallet?: unknown }).vtaWallet;
  });

  it("has the plugin's approver sign, and the wallet sign the answer as the subject", async () => {
    const { approveStepUp, signTrustTask } = installWallet(true);
    const requests = mockFetch([
      { path: "/health", body: { status: "ok", version: "t", vtc_did: VTC_DID } },
      {
        method: "POST",
        path: "/v1/trust-tasks",
        body: { payload: { status: "recorded", boundTo: "zBoundDigest" } },
      },
    ]);
    const creds = fakeCredentials();
    const ack = await answerStepUp(APPROVER_REQUEST, creds, OPERATION);
    expect(ack.status).toBe("recorded");
    // No passkey ceremony: the approver is the factor.
    expect(creds.get).not.toHaveBeenCalled();
    // The plugin is handed the operation, so it can recompute `boundTo`.
    expect(approveStepUp).toHaveBeenCalledWith({
      request: APPROVER_REQUEST,
      operation: OPERATION,
      audience: VTC_DID,
    });
    // Signed by the wallet as the subject's own DID — never a console key.
    expect(signTrustTask.mock.calls[0]?.[0].asDid).toBe(ADMIN);

    const doc = requests.find((r) => r.url === "/v1/trust-tasks")!.body as SignedTrustTaskDocument;
    expect(doc.type).toBe(APPROVE_RESPONSE_V0_6_URI);
    expect(doc.issuer).toBe(ADMIN);
    expect(doc.recipient).toBe(VTC_DID);
    expect(doc.proof.verificationMethod).toBe(`${ADMIN}#key-1`);
    expect(doc.payload).toEqual({
      subject: ADMIN,
      challenge: CHALLENGE,
      decision: "approved",
      evidence: { kind: "approverSigned", statement: STATEMENT },
    });
  });

  it("refuses an approver the request did not name", async () => {
    installWallet(true);
    mockFetch([{ path: "/health", body: { status: "ok", version: "t", vtc_did: VTC_DID } }]);
    await expect(
      answerStepUp(
        { ...APPROVER_REQUEST, approvers: ["did:key:z6MkOther"] },
        fakeCredentials(),
        OPERATION,
      ),
    ).rejects.toThrow(/not one this community/);
  });

  it("falls back to the passkey when the plugin cannot answer", async () => {
    await generateConsoleKey();
    installWallet(false);
    const requests = mockFetch([
      { path: "/health", body: { status: "ok", version: "t", vtc_did: VTC_DID } },
      {
        method: "POST",
        path: "/v1/trust-tasks",
        body: { payload: { status: "recorded", boundTo: "zBoundDigest" } },
      },
    ]);
    const creds = fakeCredentials();
    await answerStepUp(APPROVER_REQUEST, creds, OPERATION);
    expect(creds.get).toHaveBeenCalledTimes(1);
    const doc = requests.find((r) => r.url === "/v1/trust-tasks")!.body as SignedTrustTaskDocument;
    expect(doc.type).toBe(APPROVE_RESPONSE_URI);
    expect((doc.payload as { evidence: { kind: string } }).evidence.kind).toBe("webauthn");
  });

  it("says which routes exist when nothing here can answer", async () => {
    const creds = fakeCredentials();
    const onlyApprover: StepUpRequest = {
      ...APPROVER_REQUEST,
      accepts: ["approverSigned"],
      webauthn: undefined,
    };
    await expect(answerStepUp(onlyApprover, creds, OPERATION)).rejects.toThrow(
      /Invite to enrol an approver[\s\S]*vtc admin enrol-approver --did/,
    );
    expect(creds.get).not.toHaveBeenCalled();
  });

  it("reads 0.4's accepts and 0.3's acceptableEvidence alike", () => {
    const bare = { ...REQUEST, acceptableEvidence: undefined };
    expect(answerableHere({ ...bare, accepts: ["webauthn"] })).toBe(true);
    expect(answerableHere({ ...bare, accepts: ["approverSigned"] })).toBe(false);
    expect(answerableHere(REQUEST)).toBe(true);
  });
});
