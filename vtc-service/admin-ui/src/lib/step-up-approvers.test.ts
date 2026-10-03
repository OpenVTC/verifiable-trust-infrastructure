// Step-up approvers: the self-service terms digest, and the list / revoke /
// invite helpers as the cards call them.

import { beforeEach, describe, expect, it, vi } from "vitest";

import { postSignedDocument, postSignedTrustTask } from "./api";
import { answerStepUp } from "./bound-step-up";
import {
  APPROVER_INVITE_TASK,
  APPROVER_LIST_TASK,
  APPROVER_REVOKE_TASK,
  approverErrorMessage,
  fetchApprovers,
  inviteApprover,
  revokeApprover,
  termsDigest,
} from "./step-up-approvers";

vi.mock("./api", async (original) => ({
  ...(await original<typeof import("./api")>()),
  postSignedTrustTask: vi.fn(),
  postSignedDocument: vi.fn(),
}));
vi.mock("./bound-step-up", async (original) => ({
  ...(await original<typeof import("./bound-step-up")>()),
  answerStepUp: vi.fn(),
}));

const ALICE = "did:webvh:QmAliceScid4:wallet.example:alice";
const APPROVER = "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH";

beforeEach(() => {
  vi.mocked(postSignedTrustTask).mockReset();
  vi.mocked(postSignedDocument).mockReset();
  vi.mocked(answerStepUp).mockReset();
});

describe("the self-service terms digest", () => {
  // A pinned vector, computed once from the construction
  // `enroll/0.1` defines — `"z" + base58btc(0x12 0x20 ‖ SHA-256(UTF-8(JCS({type,
  // subject, challenge, terms}))))` — which the VTC recomputes identically
  // (`step_up_approver::terms_digest`). A change here is a wire change.
  const TERMS = {
    approverDid: "did:key:z6MktwupdmLXVVqTzCw4i46r4uGyosGXRnR3XjN4Zq7oMMsw",
    label: "Browser plugin — new laptop",
    replaces: APPROVER,
  };
  const CHALLENGE = "Um90YXRlQXBwcm92ZXJOb25jZTk4NzY1NA";
  const PINNED = "zQmf4btNkvextciSMXxYrSktWXTaMK7di3hzUV187tZHoHZ";

  it("matches its pinned vector", async () => {
    expect(await termsDigest(ALICE, CHALLENGE, TERMS)).toBe(PINNED);
  });

  it("never covers the statement, and binds the subject and the challenge", async () => {
    expect(await termsDigest(ALICE, CHALLENGE, { ...TERMS, statement: { any: "thing" } })).toBe(
      PINNED,
    );
    expect(await termsDigest("did:key:z6MkSomeoneElse", CHALLENGE, TERMS)).not.toBe(PINNED);
    expect(await termsDigest(ALICE, `${CHALLENGE}x`, TERMS)).not.toBe(PINNED);
    expect(await termsDigest(ALICE, CHALLENGE, { ...TERMS, label: "other" })).not.toBe(PINNED);
  });
});

describe("the approver tasks", () => {
  it("lists one's own with an empty payload, and a member's by subject", async () => {
    vi.mocked(postSignedTrustTask).mockResolvedValue({ approvers: [] });
    await fetchApprovers();
    await fetchApprovers(ALICE);
    expect(vi.mocked(postSignedTrustTask).mock.calls).toEqual([
      [APPROVER_LIST_TASK, {}],
      [APPROVER_LIST_TASK, { subject: ALICE }],
    ]);
  });

  const STEP_UP = {
    subject: "did:key:z6MkAdmin",
    challenge: "c".repeat(32),
    boundTo: "zBound",
    reason: "Revoke an approver",
    accepts: ["webauthn"],
    webauthn: { challenge: "c".repeat(32) },
  };
  const refusedFor = (type: string, payload: unknown) => ({
    status: 403,
    message: "step-up",
    code: "permissionDenied",
    details: { stepUpRequest: STEP_UP },
    document: { type, payload, proof: {} },
  });

  it("revokes behind the caller's bound step-up, re-sending the same document", async () => {
    const payload = { approverDid: APPROVER, subject: ALICE, reason: "Laptop lost" };
    vi.mocked(postSignedTrustTask).mockRejectedValue(refusedFor(APPROVER_REVOKE_TASK, payload));
    vi.mocked(postSignedDocument).mockResolvedValue({ remainingApprovers: 0 });
    const confirm = vi.fn(async () => true);
    const out = await revokeApprover(
      { approverDid: APPROVER, subject: ALICE, reason: "Laptop lost" },
      confirm,
    );
    expect(out).toEqual({ remainingApprovers: 0 });
    expect(postSignedTrustTask).toHaveBeenCalledWith(APPROVER_REVOKE_TASK, payload);
    expect(confirm).toHaveBeenCalledWith(STEP_UP);
    expect(answerStepUp).toHaveBeenCalledWith(STEP_UP, undefined, {
      type: APPROVER_REVOKE_TASK,
      payload,
    });
    expect(vi.mocked(postSignedDocument).mock.calls[0]?.[0]).toMatchObject({
      type: APPROVER_REVOKE_TASK,
    });
  });

  it("invites with a label and a lifetime, and nothing when the admin declines", async () => {
    const payload = { subject: ALICE, label: "Browser plugin", ttl: 900 };
    vi.mocked(postSignedTrustTask).mockRejectedValue(refusedFor(APPROVER_INVITE_TASK, payload));
    await expect(
      inviteApprover({ subject: ALICE, label: "Browser plugin", ttl: 900 }, async () => false),
    ).rejects.toThrow(/declined/);
    expect(postSignedTrustTask).toHaveBeenCalledWith(APPROVER_INVITE_TASK, payload);
    expect(answerStepUp).not.toHaveBeenCalled();
    expect(postSignedDocument).not.toHaveBeenCalled();
  });

  it("explains the codes the family declares", () => {
    expect(
      approverErrorMessage({
        status: 422,
        message: "x",
        code: "auth/step-up/approver/redeem/start:codeMismatch",
        details: { attemptsRemaining: 3 },
      }),
    ).toBe("The claim code is wrong. 3 attempts left.");
    expect(
      approverErrorMessage({ status: 422, message: "x", code: "auth/step-up/approver/invite:selfInvite" }),
    ).toMatch(/another administrator/);
    expect(approverErrorMessage({ status: 500, message: "boom" })).toBe("boom");
  });
});
