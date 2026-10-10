// The trigger-link sign-in page: the code is a link to the same text (C2), the
// number shows once claimed, the session is confirmed before use, and the
// code hides on `visibilitychange` without cancelling (C9).

import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { encodeFrom, epochOf, triggerLink } from "./oob";
import { WalletSignIn } from "./WalletSignIn";

const VTC = "did:webvh:QmScid:vtc.example.com";
const CFG = { vtcDid: VTC, linkHost: "link.trustoverip.org", flow: "/vti/flow/sign-in/0.1" };
const RID = "AAAAAAAAAAAAAAAAAAAAAA";

const json = (status: number, body: unknown) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });

const err = (code: string, details: Record<string, unknown> = {}) =>
  json(422, {
    type: "https://trusttasks.org/spec/trust-task-error/0.5",
    payload: { code, message: code, details },
  });

/** Scripted answers for each `redeem` poll, in order; the last repeats. */
function stubService(redeems: Array<() => Response>) {
  const posted: Array<{ type: string; payload: unknown; proofPurpose: string }> = [];
  let poll = 0;
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = typeof input === "string" ? input : input.toString();
      if (url.endsWith("/v1/member/sign-in/config")) return json(200, CFG);
      if (url.endsWith("/v1/member/sign-out")) return new Response(null, { status: 204 });
      const doc = JSON.parse(String(init?.body));
      posted.push({ type: doc.type, payload: doc.payload, proofPurpose: doc.proof.proofPurpose });
      if (doc.type.endsWith("/request/0.1")) {
        return json(200, {
          type: `${doc.type}#response`,
          payload: { requestId: RID, claimDeadline: Math.floor(Date.now() / 1000) + 120 },
        });
      }
      if (doc.type.endsWith("/redeem/0.1")) {
        const next = redeems[Math.min(poll, redeems.length - 1)]!;
        poll += 1;
        return next();
      }
      return json(200, { type: `${doc.type}#response`, payload: { status: "cancelled" } });
    }),
  );
  return posted;
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("wallet sign-in", () => {
  it("builds the contract's trigger link", () => {
    expect(encodeFrom("a&b=c#d%e")).toBe("a%26b%3Dc%23d%25e");
    expect(triggerLink(CFG, RID, 1760000000)).toBe(
      `https://link.trustoverip.org/t#_from=${VTC}&_id=${RID}&_exp=1760000000&_type=/vti/flow/sign-in/0.1`,
    );
    expect(epochOf(1760000000)).toBe(1760000000);
    expect(epochOf("2025-10-09T08:53:20Z")).toBeNull();
  });

  it("shows a clickable code, then the number, then asks 'Continue as …?'", async () => {
    const posted = stubService([
      () => err("auth/oob/redeem:pending", { state: "claimed", matchNumber: "47" }),
      // Later polls stay open.
      () => new Promise<Response>(() => {}) as unknown as Response,
    ]);
    const onSignedIn = vi.fn();
    render(<WalletSignIn onSignedIn={onSignedIn} communityName="Acme" />);
    fireEvent.click(screen.getByRole("button", { name: /show sign-in code/i }));

    await screen.findByText(/your number is/i);
    expect(screen.getByText("47")).toBeTruthy();
    expect(posted[0]!.type).toMatch(/auth\/oob\/request\/0\.1$/);
    expect(posted[0]!.payload).toEqual({ purpose: "login", mode: "scan" });
    expect(posted[0]!.proofPurpose).toBe("authentication");
    expect(posted[1]!.type).toMatch(/auth\/oob\/redeem\/0\.1$/);
    expect(posted[1]!.payload).toEqual({ requestId: RID });
  });

  it("wraps the code in a link to the same https text, and hides it on visibilitychange", async () => {
    stubService([() => new Promise<Response>(() => {}) as unknown as Response]);
    render(<WalletSignIn onSignedIn={() => {}} />);
    fireEvent.click(screen.getByRole("button", { name: /show sign-in code/i }));
    const img = await screen.findByRole("img", { name: /sign-in code/i });
    const link = img.closest("a")!;
    expect(link.getAttribute("href")).toBe(
      `https://link.trustoverip.org/t#_from=${VTC}&_id=${RID}&_exp=${link
        .getAttribute("href")!
        .match(/_exp=(\d+)/)![1]}&_type=/vti/flow/sign-in/0.1`,
    );

    // Hidden tab: the code goes; the request is not cancelled.
    Object.defineProperty(document, "visibilityState", { value: "hidden", configurable: true });
    act(() => {
      document.dispatchEvent(new Event("visibilitychange"));
    });
    expect(screen.queryByRole("img", { name: /sign-in code/i })).toBeNull();
    Object.defineProperty(document, "visibilityState", { value: "visible", configurable: true });
    fireEvent.click(screen.getByRole("button", { name: /show the code again/i }));
    expect(await screen.findByRole("img", { name: /sign-in code/i })).toBeTruthy();
  });

  it("confirms the identity before use, and 'Not me' signs out", async () => {
    stubService([
      () =>
        json(200, {
          type: "https://trusttasks.org/spec/auth/oob/redeem/0.1#response",
          payload: {
            subject: "did:webvh:x:alice",
            displayName: "Alice",
            notAfter: Math.floor(Date.now() / 1000) + 3600,
            amr: ["did", "oob", "uv"],
          },
        }),
    ]);
    const onSignedIn = vi.fn();
    render(<WalletSignIn onSignedIn={onSignedIn} />);
    fireEvent.click(screen.getByRole("button", { name: /show sign-in code/i }));
    await screen.findByText(/continue as/i);
    expect(screen.getByText("Alice")).toBeTruthy();
    expect(onSignedIn).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole("button", { name: /not me/i }));
    await waitFor(() =>
      expect(screen.getByRole("button", { name: /show sign-in code/i })).toBeTruthy(),
    );
    expect(onSignedIn).not.toHaveBeenCalled();
  });

  it("tells a cancelled sign-in from a declined one", async () => {
    stubService([() => err("auth/oob/redeem:declined", { state: "cancelled" })]);
    render(<WalletSignIn onSignedIn={() => {}} />);
    fireEvent.click(screen.getByRole("button", { name: /show sign-in code/i }));
    expect(await screen.findByText(/sign-in was cancelled/i)).toBeTruthy();
    expect(screen.getByRole("button", { name: /get a new code/i })).toBeTruthy();
  });

  it("shows an expired code as expired", async () => {
    stubService([() => err("auth/oob/redeem:requestExpired")]);
    render(<WalletSignIn onSignedIn={() => {}} />);
    fireEvent.click(screen.getByRole("button", { name: /show sign-in code/i }));
    expect(await screen.findByText(/code expired/i)).toBeTruthy();
  });
});
