// The ACL verbs as signed documents: what each sends, how the listing pages,
// and how an act that needs a passkey gesture is confirmed and re-sent.

import { beforeEach, describe, expect, it, vi } from "vitest";

import type { ApiError } from "./api";
import { postSignedDocument, postSignedRead, postSignedTrustTask } from "./api";
import {
  ACL_CHANGE_ROLE_TASK,
  ACL_GRANT_TASK,
  ACL_LIST_TASK,
  ACL_REVOKE_TASK,
  changeAclRole,
  fetchAllAcl,
  grantAcl,
  revokeAcl,
} from "./acl";
import { answerStepUp, type StepUpRequest } from "./bound-step-up";
import type { SignedTrustTaskDocument } from "./console-key";
import { GestureDeclinedError, explainConsent } from "./signed-act";

vi.mock("./api", async (original) => ({
  ...(await original<typeof import("./api")>()),
  postSignedRead: vi.fn(),
  postSignedTrustTask: vi.fn(),
  postSignedDocument: vi.fn(),
}));
vi.mock("./bound-step-up", async (original) => ({
  ...(await original<typeof import("./bound-step-up")>()),
  answerStepUp: vi.fn(),
}));

const ALICE = "did:key:z6MkAlice";
const entry = (subject: string, role = "member") => ({ subject, role, scopes: [] });

const STEP_UP: StepUpRequest = {
  subject: "did:key:z6MkOperator",
  challenge: "c".repeat(32),
  boundTo: "urn:sha256:grant",
  reason: "Grant admin to Alice",
};
const SIGNED = { type: ACL_GRANT_TASK, proof: {} } as unknown as SignedTrustTaskDocument;
const stepUpRefusal = (): ApiError => ({
  status: 403,
  message: "a passkey gesture is required",
  code: "permissionDenied",
  details: { stepUpRequest: STEP_UP },
  document: SIGNED,
});

beforeEach(() => {
  vi.mocked(postSignedRead).mockReset();
  vi.mocked(postSignedTrustTask).mockReset();
  vi.mocked(postSignedDocument).mockReset();
  vi.mocked(answerStepUp).mockReset();
});

describe("acl/list", () => {
  it("follows the cursor to the end", async () => {
    vi.mocked(postSignedRead)
      .mockResolvedValueOnce({ entries: [entry("a")], truncated: true, cursor: "next" })
      .mockResolvedValueOnce({ entries: [entry("b")], truncated: false });
    const all = await fetchAllAcl({ scope: "ops" });
    expect(all.map((e) => e.subject)).toEqual(["a", "b"]);
    expect(vi.mocked(postSignedRead).mock.calls).toEqual([
      [ACL_LIST_TASK, { scope: "ops", pageSize: 200 }],
      [ACL_LIST_TASK, { scope: "ops", pageSize: 200, cursor: "next" }],
    ]);
  });

  it("refuses a truncated page with no cursor rather than return part of the list", async () => {
    vi.mocked(postSignedRead).mockResolvedValueOnce({ entries: [entry("a")], truncated: true });
    await expect(fetchAllAcl()).rejects.toThrow(/truncated page with no cursor/);
  });
});

describe("acl/revoke", () => {
  it("names the subject", async () => {
    vi.mocked(postSignedTrustTask).mockResolvedValueOnce({ entry: null });
    await revokeAcl(ALICE);
    expect(vi.mocked(postSignedTrustTask)).toHaveBeenCalledWith(ACL_REVOKE_TASK, {
      subject: ALICE,
    });
  });
});

describe("an act that needs a passkey gesture", () => {
  it("is sent once when no gesture is asked for", async () => {
    vi.mocked(postSignedTrustTask).mockResolvedValueOnce({ entry: entry(ALICE) });
    const confirm = vi.fn();
    const got = await grantAcl({ entry: { subject: ALICE, role: "member", scopes: [] } }, confirm);
    expect(got.subject).toBe(ALICE);
    expect(confirm).not.toHaveBeenCalled();
    expect(vi.mocked(answerStepUp)).not.toHaveBeenCalled();
  });

  it("asks the operator, records the gesture, and re-sends the same signed document", async () => {
    vi.mocked(postSignedTrustTask).mockRejectedValueOnce(stepUpRefusal());
    vi.mocked(answerStepUp).mockResolvedValueOnce({ status: "recorded" });
    vi.mocked(postSignedDocument).mockResolvedValueOnce({ entry: entry(ALICE, "admin") });
    const confirm = vi.fn(async () => true);

    const got = await changeAclRole(
      { subject: ALICE, fromRole: "member", toRole: "admin" },
      confirm,
    );

    expect(got.role).toBe("admin");
    expect(vi.mocked(postSignedTrustTask)).toHaveBeenCalledWith(ACL_CHANGE_ROLE_TASK, {
      subject: ALICE,
      fromRole: "member",
      toRole: "admin",
    });
    expect(confirm).toHaveBeenCalledWith(STEP_UP);
    expect(vi.mocked(answerStepUp)).toHaveBeenCalledWith(STEP_UP);
    // The identical document, not a freshly signed one.
    expect(vi.mocked(postSignedDocument)).toHaveBeenCalledWith(SIGNED);
  });

  it("sends nothing more when the operator declines", async () => {
    vi.mocked(postSignedTrustTask).mockRejectedValueOnce(stepUpRefusal());
    await expect(
      grantAcl({ entry: { subject: ALICE, role: "admin", scopes: [] } }, async () => false),
    ).rejects.toBeInstanceOf(GestureDeclinedError);
    expect(vi.mocked(answerStepUp)).not.toHaveBeenCalled();
    expect(vi.mocked(postSignedDocument)).not.toHaveBeenCalled();
  });

  it("passes any other refusal through unchanged", async () => {
    const refused: ApiError = { status: 403, message: "no", code: "permissionDenied" };
    vi.mocked(postSignedTrustTask).mockRejectedValueOnce(refused);
    await expect(
      grantAcl({ entry: { subject: ALICE, role: "admin", scopes: [] } }, async () => true),
    ).rejects.toBe(refused);
  });

  it("explains a refusal pending another administrator's consent", async () => {
    const refused: ApiError = {
      status: 422,
      message: "auth:consent_required",
      code: "taskFailed",
      details: { reason: "auth:consent_required" },
    };
    await expect(explainConsent(Promise.reject(refused))).rejects.toThrow(
      /Another unrestricted administrator has to approve this first/,
    );
  });
});
