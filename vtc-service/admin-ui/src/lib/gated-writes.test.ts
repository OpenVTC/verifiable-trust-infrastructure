// The writes a second party now guards — removing an administrator from the
// community (VTI-APV-019), changing a policy that decides authority
// (VTI-VTC-022), lowering the consent threshold (VTI-APV-020). Each goes
// through the same step-up path the grant and promotion do: a refusal carrying
// `details.stepUpRequest` asks the operator, records the gesture and re-sends
// the identical document; a refusal pending consent is explained, never shown
// as `auth:consent_required`.

import { beforeEach, describe, expect, it, vi } from "vitest";

import type { ApiError } from "./api";
import { postSignedDocument, postSignedTrustTask } from "./api";
import { answerStepUp, type StepUpRequest } from "./bound-step-up";
import { saveConfig } from "./config-api";
import type { SignedTrustTaskDocument } from "./console-key";
import { MEMBERS_ADMIN_REMOVE_TASK, adminRemoveMember } from "./member-removal";
import { activatePolicy, uploadPolicy } from "./policies-api";

vi.mock("./api", async (original) => ({
  ...(await original<typeof import("./api")>()),
  postSignedTrustTask: vi.fn(),
  postSignedDocument: vi.fn(),
}));
vi.mock("./bound-step-up", async (original) => ({
  ...(await original<typeof import("./bound-step-up")>()),
  answerStepUp: vi.fn(),
}));

const BOB = "did:key:z6MkBob";
const STEP_UP: StepUpRequest = {
  subject: "did:key:z6MkOperator",
  challenge: "c".repeat(32),
  boundTo: "urn:sha256:op",
  reason: "Confirm",
};
const SIGNED = { type: "x", proof: {} } as unknown as SignedTrustTaskDocument;
const stepUpRefusal = (): ApiError => ({
  status: 403,
  message: "a passkey gesture bound to this operation is required",
  code: "permissionDenied",
  details: { stepUpRequest: STEP_UP },
  document: SIGNED,
});
const consentRefusal = (): ApiError => ({
  status: 422,
  message: "auth:consent_required",
  code: "taskFailed",
  details: { reason: "auth:consent_required" },
});
const CONSENT_EXPLAINED = /Another unrestricted administrator has to approve this first/;

beforeEach(() => {
  vi.mocked(postSignedTrustTask).mockReset();
  vi.mocked(postSignedDocument).mockReset();
  vi.mocked(answerStepUp).mockReset();
});

/** The gesture is asked for, recorded, and the same document re-sent. */
function gestureThen(outcome: "ok" | "consent", value: unknown = {}) {
  vi.mocked(postSignedTrustTask).mockRejectedValueOnce(stepUpRefusal());
  vi.mocked(answerStepUp).mockResolvedValueOnce({ status: "recorded" });
  if (outcome === "ok") vi.mocked(postSignedDocument).mockResolvedValueOnce(value);
  else vi.mocked(postSignedDocument).mockRejectedValueOnce(consentRefusal());
}

function expectGestureMade(confirm: ReturnType<typeof vi.fn>) {
  expect(confirm).toHaveBeenCalledWith(STEP_UP);
  expect(vi.mocked(answerStepUp)).toHaveBeenCalledWith(STEP_UP);
  expect(vi.mocked(postSignedDocument)).toHaveBeenCalledWith(SIGNED);
}

describe("vtc/members/admin-remove (VTI-APV-019)", () => {
  it("removes an ordinary member without asking", async () => {
    vi.mocked(postSignedTrustTask).mockResolvedValueOnce({});
    const confirm = vi.fn();
    await adminRemoveMember({ did: BOB, reason: "" }, confirm);
    expect(vi.mocked(postSignedTrustTask)).toHaveBeenCalledWith(MEMBERS_ADMIN_REMOVE_TASK, {
      did: BOB,
    });
    expect(confirm).not.toHaveBeenCalled();
  });

  it("asks for the gesture removing an administrator", async () => {
    gestureThen("ok");
    const confirm = vi.fn(async () => true);
    await adminRemoveMember({ did: BOB, reason: "rotation" }, confirm);
    expect(vi.mocked(postSignedTrustTask)).toHaveBeenCalledWith(MEMBERS_ADMIN_REMOVE_TASK, {
      did: BOB,
      reason: "rotation",
    });
    expectGestureMade(confirm);
  });

  it("explains a removal waiting on a third administrator's consent", async () => {
    gestureThen("consent");
    await expect(adminRemoveMember({ did: BOB, reason: "" }, async () => true)).rejects.toThrow(
      CONSENT_EXPLAINED,
    );
  });
});

describe("policy/upsert and policy/activate (VTI-VTC-022)", () => {
  it("asks for the gesture uploading an authority policy", async () => {
    gestureThen("ok", { policy: { id: "p1" }, created: true });
    const confirm = vi.fn(async () => true);
    const got = await uploadPolicy({ purpose: "removal", regoSource: "package vtc.removal" }, confirm);
    expect(got).toEqual({ id: "p1" });
    expectGestureMade(confirm);
  });

  it("explains an upload waiting on another administrator's consent", async () => {
    gestureThen("consent");
    await expect(
      uploadPolicy({ purpose: "join", regoSource: "package vtc.join" }, async () => true),
    ).rejects.toThrow(CONSENT_EXPLAINED);
  });

  it("asks for the gesture activating, and explains the consent", async () => {
    gestureThen("consent");
    const confirm = vi.fn(async () => true);
    await expect(activatePolicy("p1", "removal", confirm)).rejects.toThrow(CONSENT_EXPLAINED);
    expectGestureMade(confirm);
  });

  it("changes a community rule without asking", async () => {
    vi.mocked(postSignedTrustTask).mockResolvedValueOnce({ activated: "p2" });
    const confirm = vi.fn();
    await activatePolicy("p2", "directory", confirm);
    expect(confirm).not.toHaveBeenCalled();
  });
});

describe("config/patch lowering the consent threshold (VTI-APV-020)", () => {
  const KEY = "acl.unrestricted_admin_consent_threshold";

  it("asks for the gesture and explains the consent", async () => {
    gestureThen("consent");
    const confirm = vi.fn(async () => true);
    await expect(saveConfig({ [KEY]: 1 }, confirm)).rejects.toThrow(CONSENT_EXPLAINED);
    expectGestureMade(confirm);
  });

  it("saves once both are given", async () => {
    gestureThen("ok", { applied: [], pendingRestart: [], rejected: [] });
    const got = await saveConfig({ [KEY]: 1 }, async () => true);
    expect(got.rejected).toEqual([]);
  });
});
