// A consent-gated act the VTC parks as an administrator action answers HTTP
// 202 with a `trust-task-next-step` document. The signed door throws it as a
// `ParkedAction` (never returns it as the task's response), and the toast
// shows it as a success linking to the action — not as the old
// `auth:consent_required` error.

import { afterEach, describe, expect, it, vi } from "vitest";
import { createElement, useEffect } from "react";
import { render, screen } from "@testing-library/react";

import { postSignedDocument } from "./api";
import type { SignedTrustTaskDocument } from "./console-key";
import {
  ACTIONS_SHOW_TASK,
  NEXT_STEP_TYPE,
  ParkedAction,
  actionPath,
  parkedActionFromDocument,
  parkedOf,
} from "./parked-action";
import { ToastProvider, useToast } from "./toast";

const MESSAGE =
  "Sent for approval — 1 of 2 unrestricted administrator(s) must approve within 72 hours.";

const nextStep = (overrides: Record<string, unknown> = {}) => ({
  id: "urn:uuid:reply",
  type: NEXT_STEP_TYPE,
  payload: {
    continuation: "proceed",
    expects: [
      { typeUri: ACTIONS_SHOW_TASK, hint: { actionId: "act-9" }, reason: "await approval" },
    ],
    inResponseTo: { id: "urn:uuid:req", typeUri: "https://trusttasks.org/spec/acl/grant/0.1" },
    message: MESSAGE,
    ext: {
      "org.openvtc": {
        actionId: "act-9",
        kind: "acl.grant.authority",
        threshold: 1,
        approvers: 2,
        approvals: 0,
        expiresAt: "2026-10-05T10:00:00Z",
      },
    },
    ...overrides,
  },
});

const SIGNED = {
  id: "urn:uuid:req",
  type: "https://trusttasks.org/spec/acl/grant/0.1",
  issuer: "did:key:z6MkConsole",
  recipient: "did:webvh:x:vtc",
  issuedAt: "2026-10-02T10:00:00Z",
  payload: {},
  proof: { verificationMethod: "did:key:z6MkConsole#k" },
} as unknown as SignedTrustTaskDocument;

afterEach(() => {
  window.history.replaceState({}, "", "/");
});

describe("recognising the next-step reply", () => {
  it("reads the action id, counts and the VTC's own sentence", () => {
    const parked = parkedActionFromDocument(nextStep())!;
    expect(parked).toBeInstanceOf(ParkedAction);
    expect(parked.actionId).toBe("act-9");
    expect(parked.message).toBe(MESSAGE);
    expect(parked.threshold).toBe(1);
    expect(parked.approvers).toBe(2);
    expect(parked.kind).toBe("acl.grant.authority");
    expect(parked.typeUri).toBe("https://trusttasks.org/spec/acl/grant/0.1");
    expect(parked.path).toBe("/actions?action=act-9");
  });

  it("falls back to the expects hint, and to a sentence of its own", () => {
    const parked = parkedActionFromDocument(nextStep({ ext: {}, message: undefined }))!;
    expect(parked.actionId).toBe("act-9");
    expect(parked.message).toMatch(/^Sent for approval/);
  });

  it("ignores anything that is not a next-step reply naming an action", () => {
    expect(parkedActionFromDocument({ type: "x", payload: {} })).toBeNull();
    expect(parkedActionFromDocument(nextStep({ ext: {}, expects: [] }))).toBeNull();
    expect(parkedActionFromDocument(null)).toBeNull();
    expect(parkedOf(new Error("x"))).toBeNull();
  });

  it("escapes the action id in its path", () => {
    expect(actionPath("a b&c")).toBe("/actions?action=a%20b%26c");
  });
});

describe("the signed door", () => {
  it("throws a 202 next-step reply as a ParkedAction, sending once", async () => {
    const fetchMock = vi.fn(
      async () =>
        new Response(JSON.stringify(nextStep()), {
          status: 202,
          headers: { "Content-Type": "application/json" },
        }),
    );
    vi.stubGlobal("fetch", fetchMock);
    const err = await postSignedDocument(SIGNED).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ParkedAction);
    expect((err as ParkedAction).actionId).toBe("act-9");
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("still returns an ordinary response's payload", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(
        async () =>
          new Response(JSON.stringify({ type: "x#response", payload: { ok: 1 } }), {
            status: 200,
          }),
      ),
    );
    await expect(postSignedDocument(SIGNED)).resolves.toEqual({ ok: 1 });
  });
});

describe("the success notice", () => {
  function Fire({ err }: { err: unknown }) {
    const toast = useToast();
    useEffect(() => toast.pushFromError(err, "Create failed"), [err, toast]);
    return null;
  }

  it("shows a parked act as a success with a link to the action", async () => {
    render(
      createElement(ToastProvider, null, createElement(Fire, { err: parkedActionFromDocument(nextStep()) })),
    );
    const toast = await screen.findByRole("status");
    expect(toast.className).toContain("toast-success");
    expect(toast.textContent).toContain(MESSAGE);
    expect(toast.textContent).not.toContain("Create failed");
    const link = screen.getByRole("link", { name: "View the action" });
    expect(link.getAttribute("href")).toBe("/admin/actions?action=act-9");
    link.click();
    expect(window.location.pathname + window.location.search).toBe("/admin/actions?action=act-9");
  });

  it("still shows a real error as an error", async () => {
    render(
      createElement(ToastProvider, null, createElement(Fire, { err: { status: 403, message: "no" } })),
    );
    const toast = await screen.findByRole("alert");
    expect(toast.textContent).toContain("Create failed: no (403)");
  });
});
