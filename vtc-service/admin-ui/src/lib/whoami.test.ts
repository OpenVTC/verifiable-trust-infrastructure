// `whoami` as the console now asks it (#1641): a signed `auth/whoami/0.1`
// from the browser session key a sign-in bound, never a cookie-borne GET.

import { afterEach, describe, expect, it, vi } from "vitest";

import { fetchWhoami, probeSession } from "./api";
import {
  adoptBrowserSessionKey,
  forgetBrowserSessionKey,
  mintBrowserSessionKey,
  resetConsoleKeyCacheForTests,
} from "./console-key";
import { resetSession, sessionExpiry } from "./session";

const VTC_DID = "did:webvh:QmScid:community.example";
const WHOAMI = "https://trusttasks.org/spec/auth/whoami/0.1";

interface Sent {
  url: string;
  body: Record<string, unknown> | null;
}

function stubDaemon(whoamiStatus = 200, refreshOk = true): Sent[] {
  const sent: Sent[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string, init?: RequestInit) => {
      const body = typeof init?.body === "string" ? JSON.parse(init.body) : null;
      sent.push({ url, body });
      if (url.endsWith("/health")) {
        return new Response(JSON.stringify({ status: "ok", vtc_did: VTC_DID }));
      }
      if (url === "/v1/trust-tasks") {
        return whoamiStatus === 200
          ? new Response(
              JSON.stringify({
                type: `${WHOAMI}#response`,
                payload: {
                  session: { id: "s1", subject: "did:key:z6MkAdmin", issuedAt: "x", expiresAt: "y" },
                  roles: ["admin"],
                  scopes: [],
                },
              }),
            )
          : new Response(JSON.stringify({ payload: { code: "permissionDenied" } }), {
              status: whoamiStatus,
            });
      }
      if (url === "/v1/auth/refresh") {
        return refreshOk
          ? new Response(JSON.stringify({ session: { expiresAt: "2099-01-01T00:00:00Z" } }))
          : new Response("{}", { status: 401 });
      }
      return new Response("{}", { status: 404 });
    }),
  );
  return sent;
}

afterEach(async () => {
  vi.unstubAllGlobals();
  await forgetBrowserSessionKey();
  resetConsoleKeyCacheForTests();
  resetSession();
});

describe("whoami", () => {
  it("is a document signed by the browser session key, not a GET", async () => {
    const key = await mintBrowserSessionKey();
    await adoptBrowserSessionKey(key);
    const sent = stubDaemon();

    const who = await fetchWhoami();
    expect(who.session.subject).toBe("did:key:z6MkAdmin");

    const doc = sent.find((s) => s.url === "/v1/trust-tasks")!.body!;
    expect(doc.type).toBe(WHOAMI);
    expect(doc.issuer).toBe(key.consoleDid);
    expect(doc.recipient).toBe(VTC_DID);
    expect((doc.proof as { proofPurpose: string }).proofPurpose).toBe("authentication");
    expect(sent.some((s) => s.url.includes("/v1/auth/whoami"))).toBe(false);
  });

  it("reads as signed out on a browser with no session key", async () => {
    const sent = stubDaemon();
    await expect(probeSession()).resolves.toBeNull();
    expect(sent.some((s) => s.url === "/v1/trust-tasks")).toBe(false);
  });

  it("reads as signed out when the VTC refuses the key", async () => {
    await adoptBrowserSessionKey(await mintBrowserSessionKey());
    stubDaemon(403);
    await expect(probeSession()).resolves.toBeNull();
  });

  it("learns the access cookie's expiry by renewing, and is signed out if refused", async () => {
    await adoptBrowserSessionKey(await mintBrowserSessionKey());
    stubDaemon(200, true);
    await expect(probeSession()).resolves.not.toBeNull();
    expect(sessionExpiry()).toBe(Math.floor(Date.parse("2099-01-01T00:00:00Z") / 1000));

    resetSession();
    stubDaemon(200, false);
    await expect(probeSession()).resolves.toBeNull();
  });
});
