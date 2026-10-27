// The trigger-link sign-in page: the code shows unasked and is a link to the
// same text (C2), an unclaimed code is renewed only while the tab is in view,
// the number shows once claimed with the attributes the plugin reads (C11),
// the session is confirmed before use, and the code hides on
// `visibilitychange` without cancelling (C9). The confirm is skipped only for
// the identity this browser last continued as.

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

    await screen.findByText(/your number is/i);
    const number = screen.getByText("47");
    expect(number.getAttribute("data-oob-request-id")).toBe(RID);
    expect(number.getAttribute("data-oob-match-number")).toBe("47");
    expect(posted[0]!.type).toMatch(/auth\/oob\/request\/0\.1$/);
    expect(posted[0]!.payload).toEqual({ purpose: "login", mode: "scan" });
    expect(posted[0]!.proofPurpose).toBe("authentication");
    expect(posted[1]!.type).toMatch(/auth\/oob\/redeem\/0\.1$/);
    expect(posted[1]!.payload).toEqual({ requestId: RID });
  });

  it("wraps the code in a link to the same https text, and hides it on visibilitychange", async () => {
    stubService([() => new Promise<Response>(() => {}) as unknown as Response]);
    render(<WalletSignIn onSignedIn={() => {}} />);
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
    await screen.findByText(/continue as/i);
    expect(screen.getByText("Alice")).toBeTruthy();
    expect(onSignedIn).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole("button", { name: /not me/i }));
    // Signed out, and a fresh code is on its way for the right person.
    await waitFor(() =>
      expect(vi.mocked(fetch).mock.calls.some(([u]) => String(u).endsWith("/sign-out"))).toBe(true),
    );
    await screen.findByText(/continue as/i);
    expect(onSignedIn).not.toHaveBeenCalled();
  });

  it("lets a browser straight in as the identity it last continued as, and asks for any other", async () => {
    const redeemed = (subject: string, displayName: string) => () =>
      json(200, {
        type: "https://trusttasks.org/spec/auth/oob/redeem/0.1#response",
        payload: {
          subject,
          displayName,
          notAfter: Math.floor(Date.now() / 1000) + 3600,
          amr: ["did", "oob", "uv"],
        },
      });
    const store = new Map<string, string>();
    vi.stubGlobal("localStorage", {
      getItem: (k: string) => store.get(k) ?? null,
      setItem: (k: string, v: string) => void store.set(k, v),
      removeItem: (k: string) => void store.delete(k),
    });

    // First time: asked, and Continue remembers Alice.
    stubService([redeemed("did:webvh:x:alice", "Alice")]);
    const first = vi.fn();
    const a = render(<WalletSignIn onSignedIn={first} />);
    fireEvent.click(await screen.findByRole("button", { name: /^continue$/i }));
    expect(first).toHaveBeenCalledTimes(1);
    a.unmount();

    // Alice again: no question.
    stubService([redeemed("did:webvh:x:alice", "Alice")]);
    const second = vi.fn();
    const b = render(<WalletSignIn onSignedIn={second} />);
    await waitFor(() => expect(second).toHaveBeenCalledTimes(1));
    expect(screen.queryByText(/continue as/i)).toBeNull();
    b.unmount();

    // Someone else signing this browser in (T4): asked, and Not me keeps Alice.
    stubService([redeemed("did:webvh:x:mallory", "Mallory")]);
    const third = vi.fn();
    render(<WalletSignIn onSignedIn={third} />);
    await screen.findByText(/continue as/i);
    expect(screen.getByText("Mallory")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: /not me/i }));
    await screen.findByText(/continue as/i);
    expect(third).not.toHaveBeenCalled();
    expect([...store.values()]).toEqual(["did:webvh:x:alice"]);
  });

  it("tells a cancelled sign-in from a declined one", async () => {
    stubService([() => err("auth/oob/redeem:declined", { state: "cancelled" })]);
    render(<WalletSignIn onSignedIn={() => {}} />);
    expect(await screen.findByText(/sign-in was cancelled/i)).toBeTruthy();
    expect(screen.getByRole("button", { name: /get a new code/i })).toBeTruthy();
  });

  it("shows a claimed code that expires as expired", async () => {
    stubService([
      () => err("auth/oob/redeem:pending", { state: "claimed", matchNumber: "47" }),
      () => err("auth/oob/redeem:requestExpired"),
    ]);
    render(<WalletSignIn onSignedIn={() => {}} />);
    expect(await screen.findByText(/code expired/i)).toBeTruthy();
  });

  it("ends a code that dies at once as expired rather than making code after code", async () => {
    const posted = stubService([() => err("auth/oob/redeem:requestExpired")]);
    render(<WalletSignIn onSignedIn={() => {}} />);
    expect(await screen.findByText(/code expired/i)).toBeTruthy();
    expect(posted.filter((p) => p.type.endsWith("/request/0.1"))).toHaveLength(1);
  });

  describe("renewing an unclaimed code", () => {
    const setVisibility = (state: "visible" | "hidden") => {
      Object.defineProperty(document, "visibilityState", { value: state, configurable: true });
      act(() => {
        document.dispatchEvent(new Event("visibilitychange"));
      });
    };
    const requests = (posted: Array<{ type: string }>) =>
      posted.filter((p) => p.type.endsWith("/request/0.1")).length;
    const redeems = (posted: Array<{ type: string }>) =>
      posted.filter((p) => p.type.endsWith("/redeem/0.1")).length;
    /** Let pending promises and effects run out. */
    const settle = () => act(() => new Promise<void>((r) => setTimeout(r, 20)));

    /** A first redeem the test ends with `requestExpired`; later ones hang. */
    function stubExpiring() {
      let expire!: () => void;
      const first = new Promise<Response>((r) => {
        expire = () => r(err("auth/oob/redeem:requestExpired"));
      });
      const posted = stubService([
        () => first as unknown as Response,
        () => new Promise<Response>(() => {}) as unknown as Response,
      ]);
      return { posted, expire };
    }

    afterEach(() => {
      Object.defineProperty(document, "visibilityState", { value: "visible", configurable: true });
      vi.restoreAllMocks();
    });

    it("makes a new code when the old one lapses while the tab is in view", async () => {
      const t0 = Date.now();
      const now = vi.spyOn(Date, "now").mockReturnValue(t0);
      const { posted, expire } = stubExpiring();
      render(<WalletSignIn onSignedIn={() => {}} />);
      await screen.findByRole("img", { name: /sign-in code/i });
      expect(requests(posted)).toBe(1);

      now.mockReturnValue(t0 + 121_000);
      expire();
      await waitFor(() => expect(requests(posted)).toBe(2));
      expect(await screen.findByRole("img", { name: /sign-in code/i })).toBeTruthy();
      await settle();
      expect(requests(posted)).toBe(2);
      expect(screen.queryByText(/code expired/i)).toBeNull();
    });

    it("makes no code in a hidden tab, and one when it comes back", async () => {
      const t0 = Date.now();
      const now = vi.spyOn(Date, "now").mockReturnValue(t0);
      const { posted, expire } = stubExpiring();
      render(<WalletSignIn onSignedIn={() => {}} />);
      await screen.findByRole("img", { name: /sign-in code/i });

      setVisibility("hidden");
      now.mockReturnValue(t0 + 121_000);
      expire();
      // The lapsed code is gone and no new one is asked for while hidden.
      await waitFor(() => expect(redeems(posted)).toBe(1));
      await settle();
      expect(screen.queryByRole("img", { name: /sign-in code/i })).toBeNull();
      expect(screen.queryByRole("button", { name: /show the code again/i })).toBeNull();
      expect(requests(posted)).toBe(1);

      setVisibility("visible");
      await waitFor(() => expect(requests(posted)).toBe(2));
      expect(await screen.findByRole("img", { name: /sign-in code/i })).toBeTruthy();
    });

    it("waits for a tab opened in the background before making the first code", async () => {
      Object.defineProperty(document, "visibilityState", { value: "hidden", configurable: true });
      const posted = stubService([() => new Promise<Response>(() => {}) as unknown as Response]);
      render(<WalletSignIn onSignedIn={() => {}} />);
      await waitFor(() => expect(fetch).toHaveBeenCalled());
      await settle();
      expect(requests(posted)).toBe(0);

      setVisibility("visible");
      expect(await screen.findByRole("img", { name: /sign-in code/i })).toBeTruthy();
      await settle();
      expect(requests(posted)).toBe(1);
    });
  });

  describe("when the community's DID document can't support it", () => {
    const stubConfig = (didDocument: unknown) =>
      vi.stubGlobal(
        "fetch",
        vi.fn(async () => json(200, { ...CFG, didDocument })),
      );

    it("names the missing services instead of offering a code", async () => {
      stubConfig({ status: "missing", missing: ["SignInPortal"] });
      render(<WalletSignIn onSignedIn={() => {}} />);
      expect(await screen.findByText(/isn't available here yet/i)).toBeTruthy();
      expect(screen.getByText(/doesn't list SignInPortal/)).toBeTruthy();
      expect(screen.queryByText(/getting a code/i)).toBeNull();
      expect(screen.queryByRole("img", { name: /sign-in code/i })).toBeNull();
    });

    it("lists every missing service", async () => {
      stubConfig({ status: "missing", missing: ["TrustTaskHTTPS", "SignInPortal"] });
      render(<WalletSignIn onSignedIn={() => {}} />);
      expect(
        await screen.findByText(/doesn't list TrustTaskHTTPS or SignInPortal/),
      ).toBeTruthy();
    });

    it("still offers wallet sign-in when the check is unknown or absent", async () => {
      for (const didDocument of [{ status: "unknown" }, { status: "ok" }, undefined]) {
        stubConfig(didDocument);
        const { unmount } = render(<WalletSignIn onSignedIn={() => {}} />);
        // The config came back usable, so a code is asked for at once.
        await waitFor(() => expect(vi.mocked(fetch).mock.calls.length).toBeGreaterThan(1));
        expect(screen.queryByText(/isn't available here yet/i)).toBeNull();
        unmount();
        vi.unstubAllGlobals();
      }
    });
  });

  describe("when a rate limit refuses", () => {
    /** A limiter's `429` (`routing::rate_limit`): not a trust-task reply. */
    const limited = () =>
      new Response(
        JSON.stringify({
          error: "rate_limited",
          limiter: "sign-in-address",
          message: "too many",
          retryAfterSecs: 1,
        }),
        { status: 429, headers: { "Content-Type": "application/json", "Retry-After": "1" } },
      );

    /** Config and request answers scripted in order (the last repeats);
     *  redeem as given. */
    function stubWith(opts: {
      configs?: Array<() => Response>;
      requests?: Array<() => Response>;
      redeems?: Array<() => Response>;
    }) {
      const count = { config: 0, request: 0, redeem: 0 };
      const pick = (list: Array<() => Response> | undefined, n: number, dflt: () => Response) =>
        list ? list[Math.min(n, list.length - 1)]!() : dflt();
      vi.stubGlobal(
        "fetch",
        vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
          const url = typeof input === "string" ? input : input.toString();
          if (url.endsWith("/v1/member/sign-in/config")) {
            return pick(opts.configs, count.config++, () => json(200, CFG));
          }
          const doc = JSON.parse(String(init?.body));
          if (doc.type.endsWith("/request/0.1")) {
            return pick(opts.requests, count.request++, () =>
              json(200, {
                type: `${doc.type}#response`,
                payload: { requestId: RID, claimDeadline: Math.floor(Date.now() / 1000) + 120 },
              }),
            );
          }
          if (doc.type.endsWith("/redeem/0.1")) {
            return pick(
              opts.redeems,
              count.redeem++,
              () => new Promise<Response>(() => {}) as unknown as Response,
            );
          }
          return json(200, { type: `${doc.type}#response`, payload: { status: "cancelled" } });
        }),
      );
      return count;
    }

    it("waits out a 429 on a poll and carries on to the number", async () => {
      const count = stubWith({
        redeems: [
          limited,
          () => err("auth/oob/redeem:pending", { state: "claimed", matchNumber: "47" }),
          () => new Promise<Response>(() => {}) as unknown as Response,
        ],
      });
      render(<WalletSignIn onSignedIn={() => {}} />);
      await screen.findByText(/your number is/i, undefined, { timeout: 4000 });
      expect(screen.getByText("47").getAttribute("data-oob-match-number")).toBe("47");
      expect(screen.queryByText(/429/)).toBeNull();
      expect(count.redeem).toBeGreaterThanOrEqual(2);
    });

    it("retries a code request a 429 refused", async () => {
      const count = stubWith({
        requests: [
          limited,
          () =>
            json(200, {
              type: "https://trusttasks.org/spec/auth/oob/request/0.1#response",
              payload: { requestId: RID, claimDeadline: Math.floor(Date.now() / 1000) + 120 },
            }),
        ],
      });
      render(<WalletSignIn onSignedIn={() => {}} />);
      expect(
        await screen.findByRole("img", { name: /sign-in code/i }, { timeout: 4000 }),
      ).toBeTruthy();
      expect(count.request).toBe(2);
      expect(screen.queryByText(/429/)).toBeNull();
    });

    it("says so in words, never '429', when the code request stays refused", async () => {
      stubWith({ requests: [limited] });
      render(<WalletSignIn onSignedIn={() => {}} />);
      expect(
        await screen.findByText(/too many sign-in attempts from this network/i, undefined, {
          timeout: 6000,
        }),
      ).toBeTruthy();
      expect(screen.queryByText(/^429$/)).toBeNull();
    }, 10_000);

    it("retries the config on load, then makes the code", async () => {
      const count = stubWith({ configs: [limited, () => json(200, CFG)] });
      render(<WalletSignIn onSignedIn={() => {}} />);
      expect(
        await screen.findByRole("img", { name: /sign-in code/i }, { timeout: 4000 }),
      ).toBeTruthy();
      expect(count.config).toBe(2);
    });

    it("gives the reason and 'Try again' when the config stays unreadable", async () => {
      const count = stubWith({ configs: [limited] });
      render(<WalletSignIn onSignedIn={() => {}} />);
      expect(
        await screen.findByText(/too many sign-in attempts from this network/i, undefined, {
          timeout: 6000,
        }),
      ).toBeTruthy();
      expect(count.config).toBe(3);
      expect(screen.queryByRole("button", { name: /show sign-in code/i })).toBeNull();
      // Try again reads it afresh and, once it answers, makes the code.
      stubWith({});
      fireEvent.click(screen.getByRole("button", { name: /try again/i }));
      expect(await screen.findByRole("img", { name: /sign-in code/i })).toBeTruthy();
    }, 10_000);
  });
});
