// The member portal: what a signed-out visitor sees, what a member sees, and
// that its client never sends the console's credentials.

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { memberCsrfToken, postMember } from "./api";
import { Portal } from "./Portal";

type Handler = (url: string, init?: RequestInit) => Response;

function stubFetch(handler: Handler) {
  const calls: { url: string; init?: RequestInit }[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = typeof input === "string" ? input : input.toString();
      calls.push({ url, init });
      return handler(url, init);
    }),
  );
  return calls;
}

const json = (status: number, body: unknown) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });

function renderPortal() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <Portal />
    </QueryClientProvider>,
  );
}

const ME = {
  did: "did:key:z6MkMember",
  sessionId: "s1",
  accessExpiresAt: 0,
  amr: ["did"],
  joinedAt: "2026-09-01T00:00:00Z",
  role: "member",
  personhood: false,
  canManagePasskeys: true,
  community: { name: "Acme Guild", logoUrl: null, did: "did:webvh:x:acme" },
};

describe("member portal", () => {
  beforeEach(() => {
    delete (window as { vtaWallet?: unknown }).vtaWallet;
  });
  afterEach(() => {
    document.cookie = "vtc_member_csrf=; Max-Age=0; Path=/";
    document.cookie = "csrf=; Max-Age=0; Path=/";
  });

  it("shows sign-in and the install guide to a visitor with no wallet", async () => {
    stubFetch((url) =>
      url.endsWith("/public-profile")
        ? json(200, { name: "Acme Guild" })
        : json(401, { message: "not signed in" }),
    );
    renderPortal();

    expect(
      await screen.findByRole("heading", { name: /sign in to acme guild/i }),
    ).toBeTruthy();
    const wallet = screen.getByRole("button", { name: /sign in with vta wallet/i });
    expect((wallet as HTMLButtonElement).disabled).toBe(true);
    expect(screen.getByRole("button", { name: /sign in with a passkey/i })).toBeTruthy();
    // No wallet: the manual-install guide is open, and points at the repo.
    const guide = screen.getByText(/install the vta wallet browser extension/i)
      .closest("details") as HTMLDetailsElement;
    expect(guide.open).toBe(true);
    expect(
      screen.getByRole("link", { name: /openvtc\/vta-browser-plugin/i }).getAttribute("href"),
    ).toBe("https://github.com/OpenVTC/vta-browser-plugin");
  });

  it("enables wallet sign-in and folds the guide away when the wallet is present", async () => {
    (window as { vtaWallet?: unknown }).vtaWallet = { login: vi.fn() };
    stubFetch(() => json(401, {}));
    renderPortal();
    const wallet = await screen.findByRole("button", { name: /sign in with vta wallet/i });
    expect((wallet as HTMLButtonElement).disabled).toBe(false);
    const guide = screen.getByText(/install the vta wallet browser extension/i)
      .closest("details") as HTMLDetailsElement;
    expect(guide.open).toBe(false);
  });

  it("shows a member their membership once signed in", async () => {
    stubFetch((url) => {
      if (url === "/v1/member/me") return json(200, ME);
      if (url === "/v1/member/passkeys") return json(200, []);
      return json(404, {});
    });
    renderPortal();
    expect(await screen.findByRole("heading", { name: /welcome back/i })).toBeTruthy();
    // In the top bar and on the membership card.
    expect(screen.getAllByText("did:key:z6MkMember").length).toBeGreaterThan(0);
    expect(screen.getByText("Active")).toBeTruthy();
    await waitFor(() => expect(screen.getByText(/no passkeys yet/i)).toBeTruthy());
    expect(screen.getByRole("button", { name: /add a passkey/i })).toBeTruthy();
  });

  it("treats a 403 (no longer an active member) as signed out", async () => {
    stubFetch((url) =>
      url === "/v1/member/me" ? json(403, { message: "not an active member" }) : json(401, {}),
    );
    renderPortal();
    expect(
      await screen.findByRole("button", { name: /sign in with a passkey/i }),
    ).toBeTruthy();
  });
});

describe("member api client", () => {
  afterEach(() => {
    document.cookie = "vtc_member_csrf=; Max-Age=0; Path=/";
    document.cookie = "csrf=; Max-Age=0; Path=/";
  });

  it("mirrors the member CSRF cookie, never the console's", async () => {
    document.cookie = "csrf=console-value; Path=/";
    expect(memberCsrfToken()).toBeNull();
    document.cookie = "vtc_member_csrf=member-value; Path=/";
    expect(memberCsrfToken()).toBe("member-value");

    const calls = stubFetch(() => new Response(null, { status: 204 }));
    await postMember("/v1/member/sign-out");
    const headers = new Headers(calls[0]!.init?.headers);
    expect(headers.get("X-CSRF-Token")).toBe("member-value");
  });

  it("renews once on a 401 and retries", async () => {
    let meCalls = 0;
    const calls = stubFetch((url) => {
      if (url === "/v1/member/auth/refresh") return json(200, {});
      meCalls += 1;
      return meCalls === 1 ? json(401, {}) : json(200, { ok: true });
    });
    await expect(postMember("/v1/member/session", {})).resolves.toEqual({ ok: true });
    expect(calls.map((c) => c.url)).toEqual([
      "/v1/member/session",
      "/v1/member/auth/refresh",
      "/v1/member/session",
    ]);
  });
});
