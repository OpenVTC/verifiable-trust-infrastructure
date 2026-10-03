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
import { GestureDeclinedError, ParkedAction } from "./signed-act";

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

// What the signed door throws for a `trust-task-next-step` reply: the act was
// accepted and parked for other administrators' approval.
const parked = (): ParkedAction =>
  new ParkedAction({
    actionId: "act-1",
    message: "Sent for approval — 1 of 2 unrestricted administrator(s) must approve within 72 hours.",
    threshold: 1,
    approvers: 2,
  });

describe("acl/revoke", () => {
  it("names the subject, and asks nothing when no gesture is needed", async () => {
    vi.mocked(postSignedTrustTask).mockResolvedValueOnce({ entry: null });
    const confirm = vi.fn();
    await revokeAcl(ALICE, confirm);
    expect(vi.mocked(postSignedTrustTask)).toHaveBeenCalledWith(ACL_REVOKE_TASK, {
      subject: ALICE,
    });
    expect(confirm).not.toHaveBeenCalled();
  });

  // VTI-APV-019: removing an administrator takes a gesture bound to it.
  it("asks for the gesture removing an administrator, then re-sends the same document", async () => {
    vi.mocked(postSignedTrustTask).mockRejectedValueOnce(stepUpRefusal());
    vi.mocked(answerStepUp).mockResolvedValueOnce({ status: "recorded" });
    vi.mocked(postSignedDocument).mockResolvedValueOnce({ entry: null });
    const confirm = vi.fn(async () => true);

    await revokeAcl(ALICE, confirm);

    expect(confirm).toHaveBeenCalledWith(STEP_UP);
    expect(vi.mocked(answerStepUp)).toHaveBeenCalledWith(
    STEP_UP,
    undefined,
    expect.objectContaining({ type: expect.any(String) }),
  );
    expect(vi.mocked(postSignedDocument)).toHaveBeenCalledWith(SIGNED);
  });

  // …and removing another unrestricted one is parked for a third
  // administrator's approval: no refusal, no re-send.
  it("surfaces a removal parked for another administrator's approval", async () => {
    vi.mocked(postSignedTrustTask).mockRejectedValueOnce(stepUpRefusal());
    vi.mocked(answerStepUp).mockResolvedValueOnce({ status: "recorded" });
    vi.mocked(postSignedDocument).mockRejectedValueOnce(parked());

    const err = await revokeAcl(ALICE, async () => true).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ParkedAction);
    expect((err as ParkedAction).actionId).toBe("act-1");
    expect((err as ParkedAction).message).toMatch(/^Sent for approval/);
    // Sent once after the gesture, never again.
    expect(vi.mocked(postSignedDocument)).toHaveBeenCalledTimes(1);
  });
});

describe("acl/change-role, demoting an administrator", () => {
  it("asks for the gesture, then surfaces the parked action", async () => {
    vi.mocked(postSignedTrustTask).mockRejectedValueOnce(stepUpRefusal());
    vi.mocked(answerStepUp).mockResolvedValueOnce({ status: "recorded" });
    vi.mocked(postSignedDocument).mockRejectedValueOnce(parked());
    const confirm = vi.fn(async () => true);

    await expect(
      changeAclRole({ subject: ALICE, fromRole: "admin", toRole: "member" }, confirm),
    ).rejects.toBeInstanceOf(ParkedAction);
    expect(confirm).toHaveBeenCalledWith(STEP_UP);
    expect(vi.mocked(postSignedTrustTask)).toHaveBeenCalledWith(ACL_CHANGE_ROLE_TASK, {
      subject: ALICE,
      fromRole: "admin",
      toRole: "member",
    });
  });

  it("goes through once both are given", async () => {
    vi.mocked(postSignedTrustTask).mockRejectedValueOnce(stepUpRefusal());
    vi.mocked(answerStepUp).mockResolvedValueOnce({ status: "recorded" });
    vi.mocked(postSignedDocument).mockResolvedValueOnce({ entry: entry(ALICE, "member") });

    const got = await changeAclRole(
      { subject: ALICE, fromRole: "admin", toRole: "member" },
      async () => true,
    );
    expect(got.role).toBe("member");
    expect(vi.mocked(postSignedDocument)).toHaveBeenCalledWith(SIGNED);
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
    expect(vi.mocked(answerStepUp)).toHaveBeenCalledWith(
    STEP_UP,
    undefined,
    expect.objectContaining({ type: expect.any(String) }),
  );
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

  it("passes a grant parked for approval through as a ParkedAction", async () => {
    vi.mocked(postSignedTrustTask).mockRejectedValueOnce(parked());
    await expect(
      grantAcl({ entry: { subject: ALICE, role: "admin", scopes: [] } }, async () => true),
    ).rejects.toBeInstanceOf(ParkedAction);
  });
});
