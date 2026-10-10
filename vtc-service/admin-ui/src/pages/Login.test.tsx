// The operator console's login page: the community's sign-in look, the
// wallet sign-in first (asking for the console's session), then the passkey,
// then the deprecated SIOPv2 buttons behind "Using an older wallet?", and a
// way back to the community's home page.

import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { afterEach, describe, expect, it, vi } from "vitest";

import { Login } from "./Login";

const VTC = "did:webvh:QmScid:vtc.example.com";
const CFG = { vtcDid: VTC, linkHost: "link.trustoverip.org", flow: "/vti/flow/sign-in/0.1" };
const RID = "AAAAAAAAAAAAAAAAAAAAAA";

const json = (status: number, body: unknown) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });

/** The unauthenticated reads the page makes, and the trust-task door. */
function stubDaemon(onTrustTask?: (doc: { type: string; payload: unknown }) => Response) {
  const posted: Array<{ type: string; payload: unknown }> = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = typeof input === "string" ? input : input.toString();
      if (url.endsWith("/health")) return json(200, { status: "ok", version: "x", vtc_did: VTC });
      if (url.endsWith("/v1/community/public-profile")) {
        return json(200, { name: "Acme Guild", logoUrl: null, communityDid: VTC });
      }
      if (url.endsWith("/v1/member/sign-in/config")) return json(200, CFG);
      if (url.endsWith("/v1/trust-tasks")) {
        const doc = JSON.parse(String(init?.body));
        posted.push({ type: doc.type, payload: doc.payload });
        if (onTrustTask) return onTrustTask(doc);
      }
      return new Promise<Response>(() => {});
    }),
  );
  return posted;
}

function renderLogin() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <Login />
    </QueryClientProvider>,
  );
}

/** `a` comes before `b` in the document. */
function before(a: Element, b: Element): boolean {
  return Boolean(a.compareDocumentPosition(b) & Node.DOCUMENT_POSITION_FOLLOWING);
}

afterEach(() => {
  delete (window as { vtaWallet?: unknown }).vtaWallet;
});

describe("operator console login", () => {
  it("is the community's sign-in page, for the operator console", async () => {
    stubDaemon();
    const { container } = renderLogin();
    expect(container.querySelector(".vtc-signin")).toBeTruthy();
    expect(screen.getAllByText(/^operator console$/i).length).toBeGreaterThan(0);
    expect(
      await screen.findByRole("heading", {
        level: 1,
        name: "Sign in to Acme Guild — operator console",
      }),
    ).toBeTruthy();
    // The top bar's brand is the community, linking home.
    const brand = container.querySelector("a.brand")!;
    expect(brand.getAttribute("href")).toBe("/");
    expect(brand.textContent).toContain("Acme Guild");
  });

  it("offers the wallet first, then the passkey, then the older wallets", () => {
    stubDaemon();
    renderLogin();
    const wallet = screen.getByRole("heading", { name: /sign in with your wallet/i });
    const code = screen.getByRole("button", { name: /show sign-in code/i });
    const passkey = screen.getByRole("button", { name: /sign in with a passkey/i });
    const older = screen.getByText("Using an older wallet?");
    expect(before(wallet, code)).toBe(true);
    expect(before(code, passkey)).toBe(true);
    expect(before(passkey, older)).toBe(true);
  });

  it("keeps both SIOPv2 wallet buttons, unchanged, behind the disclosure", () => {
    (window as { vtaWallet?: unknown }).vtaWallet = {
      login: vi.fn(),
      walletProfile: vi.fn(),
      proxyLogin: vi.fn(),
      vaultList: vi.fn(),
    };
    stubDaemon();
    const { container } = renderLogin();
    const details = container.querySelector("details.legacy-signin") as HTMLDetailsElement;
    expect(details).toBeTruthy();
    expect(details.open).toBe(false);
    const inside = within(details);
    const browserWallet = inside.getByRole("button", {
      name: /sign in with this browser's wallet/i,
      hidden: true,
    });
    const vtaIdentity = inside.getByRole("button", {
      name: /sign in as a vta identity/i,
      hidden: true,
    });
    expect(browserWallet).toBeTruthy();
    expect(vtaIdentity).toBeTruthy();
    // Each still says which identity it presents.
    expect(inside.getByText(/its\s+own key/i)).toBeTruthy();
    expect(inside.getByText(/your vta signs as the identity bound to this community/i)).toBeTruthy();
    // And neither is outside it.
    for (const b of [browserWallet, vtaIdentity]) {
      expect(details.contains(b)).toBe(true);
    }
  });

  it("links back to the community's home page and to the member portal", async () => {
    stubDaemon();
    renderLogin();
    const home = await screen.findByRole("link", { name: /back to acme guild/i });
    expect(home.getAttribute("href")).toBe("/");
    const portal = screen.getByRole("link", { name: /member portal/i });
    expect(portal.getAttribute("href")).toBe("/members/");
    expect(screen.getByText(/not an operator\?/i)).toBeTruthy();
  });

  it("asks the community for an operator-console session", async () => {
    const posted = stubDaemon((doc) => {
      if (doc.type.endsWith("/request/0.1")) {
        return json(200, {
          type: `${doc.type}#response`,
          payload: {
            requestId: RID,
            claimDeadline: Math.floor(Date.now() / 1000) + 120,
            ext: { "org.openvtc.session": { audience: "admin" } },
          },
        });
      }
      return new Promise<Response>(() => {}) as unknown as Response;
    });
    renderLogin();
    fireEvent.click(screen.getByRole("button", { name: /show sign-in code/i }));
    expect(
      await screen.findByRole("img", { name: /acme guild operator console/i }),
    ).toBeTruthy();
    expect(posted[0]!.payload).toEqual({
      purpose: "login",
      mode: "scan",
      ext: { "org.openvtc.session": { audience: "admin" } },
    });
  });

  it("tells an identity that is not an administrator so", async () => {
    stubDaemon((doc) => {
      if (doc.type.endsWith("/request/0.1")) {
        return json(200, {
          type: `${doc.type}#response`,
          payload: {
            requestId: RID,
            claimDeadline: Math.floor(Date.now() / 1000) + 120,
            ext: { "org.openvtc.session": { audience: "admin" } },
          },
        });
      }
      return json(422, {
        type: "https://trusttasks.org/spec/trust-task-error/0.5",
        payload: {
          code: "auth/oob/redeem:declined",
          message: "This identity isn't an administrator of this community.",
          details: { state: "declined", reason: "notAnAdmin" },
        },
      });
    });
    renderLogin();
    fireEvent.click(screen.getByRole("button", { name: /show sign-in code/i }));
    await waitFor(() =>
      expect(
        screen.getByText("This identity isn't an administrator of this community."),
      ).toBeTruthy(),
    );
  });

  it("refuses to show a code when the community ignores the console audience", async () => {
    stubDaemon((doc) =>
      json(200, {
        type: `${doc.type}#response`,
        // A VTC that predates the extension: no `ext` echoed.
        payload: { requestId: RID, claimDeadline: Math.floor(Date.now() / 1000) + 120 },
      }),
    );
    renderLogin();
    fireEvent.click(screen.getByRole("button", { name: /show sign-in code/i }));
    expect(
      await screen.findByText(/doesn't offer wallet sign-in to the operator console/i),
    ).toBeTruthy();
    expect(screen.queryByRole("img", { name: /sign-in code/i })).toBeNull();
  });
});
