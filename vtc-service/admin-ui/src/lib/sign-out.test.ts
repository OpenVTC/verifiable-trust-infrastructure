// Sign-out from a console that sat idle past its access token.
//
// The browser has dropped the session cookie by then, and a daemon that
// predates the fix answers 401. The operator asked to be signed out and is
// signed out, so that must not surface as "Sign-out failed" — nor fire the
// session-expired event that would toast an expiry over it.

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { signOut } from "./api";
import { sessionExpiry, setSessionExpiry } from "./session";

describe("signOut", () => {
  const fetchMock = vi.fn();
  const expired = vi.fn();

  beforeEach(() => {
    vi.stubGlobal("fetch", fetchMock);
    window.addEventListener("vtc-session-expired", expired);
    document.cookie = "csrf=tok";
    setSessionExpiry(Math.floor(Date.now() / 1000) - 10);
  });

  afterEach(() => {
    window.removeEventListener("vtc-session-expired", expired);
    vi.unstubAllGlobals();
    fetchMock.mockReset();
    expired.mockReset();
  });

  it("posts once, with the CSRF header, and renews nothing first", async () => {
    fetchMock.mockResolvedValue(new Response(null, { status: 204 }));
    await signOut();
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [path, init] = fetchMock.mock.calls[0]!;
    expect(path).toBe("/v1/auth/sign-out");
    expect(new Headers(init.headers).get("X-CSRF-Token")).toBe("tok");
    expect(sessionExpiry()).toBeNull();
  });

  it("treats a 401 as already signed out", async () => {
    fetchMock.mockResolvedValue(
      new Response(JSON.stringify({ error: "missing or invalid Authorization header" }), {
        status: 401,
      }),
    );
    await expect(signOut()).resolves.toBeUndefined();
    expect(expired).not.toHaveBeenCalled();
    expect(sessionExpiry()).toBeNull();
  });

  it("still reports a failure that left the cookies in place", async () => {
    fetchMock.mockResolvedValue(
      new Response(JSON.stringify({ error: "csrf token mismatch" }), { status: 403 }),
    );
    await expect(signOut()).rejects.toMatchObject({ status: 403 });
    expect(sessionExpiry()).toBeNull();
  });
});
