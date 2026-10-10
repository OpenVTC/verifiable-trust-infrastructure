// The member portal: what a signed-out visitor sees, what a member sees, and
// that its client never sends the console's credentials.

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
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

  it("offers wallet sign-in first and keeps the legacy extension behind 'Using an older wallet?'", async () => {
    stubFetch((url) =>
      url.endsWith("/public-profile")
        ? json(200, { name: "Acme Guild" })
        : json(401, { message: "not signed in" }),
    );
    renderPortal();

    expect(
      await screen.findByRole("heading", { name: /sign in to acme guild/i }),
    ).toBeTruthy();
    const vta = screen.getByRole("button", { name: /sign in with your vta/i });
    expect((vta as HTMLButtonElement).disabled).toBe(true);
    // No self-issued wallet sign-in: it would present the extension's did:key.
    expect(screen.queryByRole("button", { name: /browser's wallet/i })).toBeNull();
    expect(screen.getByRole("button", { name: /sign in with a passkey/i })).toBeTruthy();
    // The trigger-link sign-in is the first option (contract C7).
    const options = screen.getAllByRole("button").map((b) => b.textContent ?? "");
    expect(options[0]).toMatch(/show sign-in code/i);
    // SIOPv2 is legacy: folded behind "Using an older wallet?", and the
    // extension's install guide with it.
    const legacy = screen.getByText(/using an older wallet\?/i).closest("details") as HTMLDetailsElement;
    expect(legacy.open).toBe(false);
    expect(legacy.contains(vta)).toBe(true);
    const guide = screen.getByText(/install the vta wallet browser extension/i)
      .closest("details") as HTMLDetailsElement;
    expect(legacy.contains(guide)).toBe(true);
    expect(
      screen.getByRole("link", { name: /openvtc\/vta-browser-plugin/i }).getAttribute("href"),
    ).toBe("https://github.com/OpenVTC/vta-browser-plugin");
  });

  it("enables VTA sign-in and folds the guide away when the wallet can proxy", async () => {
    (window as { vtaWallet?: unknown }).vtaWallet = {
      login: vi.fn(),
      walletProfile: vi.fn(),
      proxyLogin: vi.fn(),
    };
    stubFetch(() => json(401, {}));
    renderPortal();
    const vta = await screen.findByRole("button", { name: /sign in with your vta/i });
    expect((vta as HTMLButtonElement).disabled).toBe(false);
    const guide = screen.getByText(/install the vta wallet browser extension/i)
      .closest("details") as HTMLDetailsElement;
    expect(guide.open).toBe(false);
  });

  it("keeps VTA sign-in off for a wallet that can only self-issue", async () => {
    (window as { vtaWallet?: unknown }).vtaWallet = { login: vi.fn() };
    stubFetch(() => json(401, {}));
    renderPortal();
    const vta = await screen.findByRole("button", { name: /sign in with your vta/i });
    expect((vta as HTMLButtonElement).disabled).toBe(true);
  });

  it("signs in as the VTA persona, never the wallet's own key", async () => {
    const persona = "did:webvh:abc:example.com:alice";
    const login = vi.fn();
    const walletProfile = vi.fn(async () => ({ did: persona, entryId: "e1", bound: false }));
    const proxyLogin = vi.fn(async () => ({
      sessionBlob: { headers: [{ name: "Authorization", value: "Bearer ID.TOKEN.SIG" }] },
    }));
    (window as { vtaWallet?: unknown }).vtaWallet = { login, walletProfile, proxyLogin };

    let signedIn = false;
    const calls = stubFetch((url) => {
      if (url === "/v1/member/me") return signedIn ? json(200, ME) : json(401, {});
      if (url === "/v1/member/passkeys") return json(200, []);
      if (url === "/health") return json(200, { vtc_did: "did:webvh:x:acme" });
      if (url.endsWith("/v1/member/wallet/auth/challenge"))
        return json(200, { challenge: "nonce-1", sessionId: "s1" });
      if (url.endsWith("/v1/member/wallet/auth/"))
        return json(200, { session: { id: "s1" }, tokens: { accessToken: "AT", refreshToken: "RT" } });
      if (url === "/v1/member/session") {
        signedIn = true;
        return new Response(null, { status: 204 });
      }
      return json(404, {});
    });
    renderPortal();
    fireEvent.click(await screen.findByRole("button", { name: /sign in with your vta/i }));
    expect(await screen.findByRole("heading", { name: /welcome back/i })).toBeTruthy();

    expect(login).not.toHaveBeenCalled();
    expect(walletProfile).toHaveBeenCalledWith({ target: { kind: "did", did: "did:webvh:x:acme" } });
    expect(proxyLogin).toHaveBeenCalledWith({
      entryId: "e1",
      nonce: "nonce-1",
      target: { kind: "did", did: "did:webvh:x:acme" },
    });
    const body = (suffix: string) =>
      JSON.parse(String(calls.find((c) => c.url.endsWith(suffix))!.init!.body));
    expect(body("/wallet/auth/challenge")).toEqual({ did: persona });
    expect(body("/wallet/auth/").payload).toEqual({ id_token: "ID.TOKEN.SIG", session_id: "s1" });
    expect(body("/v1/member/session")).toEqual({ accessToken: "AT", refreshToken: "RT" });
  });

  it("names the DID the VTA presented when the community refuses it", async () => {
    const persona = "did:webvh:abc:example.com:alice";
    (window as { vtaWallet?: unknown }).vtaWallet = {
      walletProfile: vi.fn(async () => ({ did: persona, entryId: "e1", bound: false })),
      proxyLogin: vi.fn(async () => ({
        sessionBlob: { headers: [{ name: "Authorization", value: "Bearer T" }] },
      })),
    };
    stubFetch((url) => {
      if (url === "/health") return json(200, { vtc_did: "did:webvh:x:acme" });
      if (url.endsWith("/wallet/auth/challenge"))
        return json(200, { challenge: "n", sessionId: "s1" });
      if (url.endsWith("/wallet/auth/")) return json(403, { message: "not an active member" });
      return json(401, {});
    });
    renderPortal();
    fireEvent.click(await screen.findByRole("button", { name: /sign in with your vta/i }));
    expect((await screen.findByText(/your vta signed in as/i)).querySelector("code")!.getAttribute("title")).toBe(persona);
  });

  it("signs in as an identity the member picks from the wallet", async () => {
    const vtc = "did:webvh:x:acme";
    const glenn = "did:webvh:QmcGecpMypWjgCM8sGA9Fvi8guAy2SNHU661XBNbrFHJgA:webvh.storm.ws:glenn-vta";
    const donald = "did:webvh:QmV9swrHHt2XoMKpqL6XJVCvQDwNvvDyKPHCRJZurkSXjd:webvh.storm.ws:donald-duck";
    const walletProfile = vi.fn();
    const vaultList = vi.fn(async () => ({
      truncated: false,
      entries: [
        { id: "a", label: "GG VTA", principalDid: glenn },
        { id: "b", label: "Donald", principalDid: donald },
        { id: "c", label: "No DID" },
      ],
    }));
    const proxyLogin = vi.fn(async () => ({
      sessionBlob: { headers: [{ name: "Authorization", value: "Bearer T" }] },
    }));
    (window as { vtaWallet?: unknown }).vtaWallet = { walletProfile, proxyLogin, vaultList };

    let signedIn = false;
    const calls = stubFetch((url) => {
      if (url === "/v1/member/me") return signedIn ? json(200, ME) : json(401, {});
      if (url === "/v1/member/passkeys") return json(200, []);
      if (url === "/health") return json(200, { vtc_did: vtc });
      if (url.endsWith("/wallet/auth/challenge")) return json(200, { challenge: "n", sessionId: "s1" });
      if (url.endsWith("/wallet/auth/"))
        return json(200, { session: { id: "s1" }, tokens: { accessToken: "AT" } });
      if (url === "/v1/member/session") {
        signedIn = true;
        return new Response(null, { status: 204 });
      }
      return json(404, {});
    });
    renderPortal();
    fireEvent.click(await screen.findByRole("button", { name: /different identity/i }));

    // Label and abbreviated DID; the entry with no DID is not offered.
    const pick = await screen.findByRole("button", { name: /donald/i });
    expect(pick.getAttribute("title")).toBe(donald);
    expect(screen.getByText("did:webvh:QmV9swrHHt…:…storm.ws:donald-duck")).toBeTruthy();
    expect(screen.queryByRole("button", { name: /no did/i })).toBeNull();
    expect(vaultList).toHaveBeenCalledWith({ targetDid: vtc, secretKind: "didSelfIssued" });

    fireEvent.click(pick);
    expect(await screen.findByRole("heading", { name: /welcome back/i })).toBeTruthy();
    expect(walletProfile).not.toHaveBeenCalled();
    expect(proxyLogin).toHaveBeenCalledWith({ entryId: "b", nonce: "n", target: { kind: "did", did: vtc } });
    const challenge = calls.find((c) => c.url.endsWith("/wallet/auth/challenge"))!;
    expect(JSON.parse(String(challenge.init!.body))).toEqual({ did: donald });
  });

  it("offers a different identity after a refusal", async () => {
    const persona = "did:webvh:QmcGecpMypWjgCM8sGA9Fvi8guAy2SNHU661XBNbrFHJgA:webvh.storm.ws:glenn-vta";
    (window as { vtaWallet?: unknown }).vtaWallet = {
      walletProfile: vi.fn(async () => ({ did: persona, entryId: "a", bound: false })),
      proxyLogin: vi.fn(async () => ({
        sessionBlob: { headers: [{ name: "Authorization", value: "Bearer T" }] },
      })),
      vaultList: vi.fn(async () => ({ truncated: false, entries: [] })),
    };
    stubFetch((url) => {
      if (url === "/health") return json(200, { vtc_did: "did:webvh:x:acme" });
      if (url.endsWith("/wallet/auth/challenge")) return json(200, { challenge: "n", sessionId: "s1" });
      if (url.endsWith("/wallet/auth/")) return json(403, { message: "not an active member" });
      return json(401, {});
    });
    renderPortal();
    fireEvent.click(await screen.findByRole("button", { name: /sign in with your vta/i }));
    const alert = await screen.findByRole("alert");
    expect(alert.querySelector("code")!.getAttribute("title")).toBe(persona);
    fireEvent.click(
      Array.from(alert.querySelectorAll("button")).find((b) => /different identity/i.test(b.textContent ?? ""))!,
    );
    expect(await screen.findByText(/no other identities set up/i)).toBeTruthy();
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
