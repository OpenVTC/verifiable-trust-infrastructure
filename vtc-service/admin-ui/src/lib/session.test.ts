import { beforeEach, describe, expect, it, vi } from "vitest";

import {
  renewIfNeeded,
  resetSession,
  sessionExpiry,
  setSessionExpiry,
} from "@/lib/session";

const NOW = 1_800_000_000_000; // ms

function atEpoch(secs: number) {
  vi.setSystemTime(secs * 1000);
}

describe("session renewal", () => {
  beforeEach(() => {
    resetSession();
    vi.useFakeTimers();
    vi.setSystemTime(NOW);
  });

  it("does nothing until an expiry is known", async () => {
    const renew = vi.fn();
    await renewIfNeeded(renew);
    // Before `whoami` runs, the console has no session to keep alive —
    // and the login ceremony's own calls must not trigger a renewal.
    expect(renew).not.toHaveBeenCalled();
  });

  it("leaves a token with plenty of life alone", async () => {
    setSessionExpiry(NOW / 1000 + 600);
    const renew = vi.fn().mockResolvedValue(null);
    await renewIfNeeded(renew);
    expect(renew).not.toHaveBeenCalled();
  });

  it("renews once the token is close to expiring", async () => {
    setSessionExpiry(NOW / 1000 + 30);
    const renew = vi.fn().mockResolvedValue(NOW / 1000 + 900);
    await renewIfNeeded(renew);
    expect(renew).toHaveBeenCalledTimes(1);
    expect(sessionExpiry()).toBe(NOW / 1000 + 900);
  });

  it("renews once for concurrent callers", async () => {
    setSessionExpiry(NOW / 1000 + 30);
    let release: (v: number) => void = () => {};
    const renew = vi.fn(
      () => new Promise<number>((res) => { release = res; }),
    );

    const a = renewIfNeeded(renew);
    const b = renewIfNeeded(renew);
    const c = renewIfNeeded(renew);
    release(NOW / 1000 + 900);
    await Promise.all([a, b, c]);

    // Not just a dedupe nicety: refresh rotates the token and the daemon
    // claims the old one atomically, so a second in-flight renewal would
    // present a token the first had already consumed and be rejected.
    expect(renew).toHaveBeenCalledTimes(1);
  });

  it("does not spin when renewal keeps failing", async () => {
    setSessionExpiry(NOW / 1000 + 30);
    const renew = vi.fn().mockRejectedValue(new Error("nope"));

    await renewIfNeeded(renew);
    await renewIfNeeded(renew);
    await renewIfNeeded(renew);

    // The retry gap holds the second and third back; without it every
    // request on a dead session would fire its own renewal.
    expect(renew).toHaveBeenCalledTimes(1);
  });

  it("swallows a failed renewal rather than throwing at the caller", async () => {
    setSessionExpiry(NOW / 1000 + 30);
    const renew = vi.fn().mockRejectedValue(new Error("nope"));
    // The caller's own request is what should surface a broken session,
    // with the status and path that actually failed.
    await expect(renewIfNeeded(renew)).resolves.toBeUndefined();
  });

  it("accepts the RFC3339 string whoami returns", () => {
    setSessionExpiry("2027-01-15T10:30:00Z");
    expect(sessionExpiry()).toBe(
      Math.floor(new Date("2027-01-15T10:30:00Z").getTime() / 1000),
    );
  });

  it("forgets everything on reset", () => {
    setSessionExpiry(NOW / 1000 + 600);
    resetSession();
    expect(sessionExpiry()).toBeNull();
  });

  it("stops renewing once the daemon refuses", async () => {
    atEpoch(NOW / 1000);
    setSessionExpiry(NOW / 1000 + 30);
    // `null` is how the daemon's refusal reaches us — an idled-out
    // session, a rotated-away token, a revoked ACL entry.
    const renew = vi.fn().mockResolvedValue(null);
    await renewIfNeeded(renew);
    expect(renew).toHaveBeenCalledTimes(1);
    // The expiry is left where it was, so the next request 401s and the
    // shell's expiry handler takes over.
    expect(sessionExpiry()).toBe(NOW / 1000 + 30);
  });
});
