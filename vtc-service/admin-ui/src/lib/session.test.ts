import { beforeEach, describe, expect, it, vi } from "vitest";

import {
  renewIfNeeded,
  resetSession,
  sessionExpiry,
  setSessionExpiry,
  watchSessionDeadline,
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

// An idle console has no requests to hang renewal on, so the deadline is
// watched on a timer. The daemon still decides: a refused renewal leaves the
// deadline where it was and the console is told it passed.
describe("session deadline watch", () => {
  const T0 = NOW / 1000;

  beforeEach(() => {
    resetSession();
    vi.useFakeTimers();
    vi.setSystemTime(NOW);
  });

  it("schedules nothing while no expiry is known", async () => {
    const renew = vi.fn();
    const expired = vi.fn();
    const stop = watchSessionDeadline(renew, expired);
    await vi.advanceTimersByTimeAsync(3_600_000);
    expect(renew).not.toHaveBeenCalled();
    expect(expired).not.toHaveBeenCalled();
    stop();
  });

  it("renews ahead of the deadline, and keeps doing so while the daemon agrees", async () => {
    setSessionExpiry(T0 + 300);
    const renew = vi.fn(async () => Math.floor(Date.now() / 1000) + 300);
    const expired = vi.fn();
    const stop = watchSessionDeadline(renew, expired);

    await vi.advanceTimersByTimeAsync(239_000);
    expect(renew).not.toHaveBeenCalled();
    await vi.advanceTimersByTimeAsync(1_000);
    expect(renew).toHaveBeenCalledTimes(1);
    expect(sessionExpiry()).toBe(T0 + 240 + 300);

    await vi.advanceTimersByTimeAsync(240_000);
    expect(renew).toHaveBeenCalledTimes(2);
    expect(expired).not.toHaveBeenCalled();
    stop();
  });

  it("reports the deadline once the daemon refuses to renew", async () => {
    setSessionExpiry(T0 + 300);
    // An idled-out session: the daemon answers every renewal with no.
    const renew = vi.fn().mockResolvedValue(null);
    const expired = vi.fn();
    const stop = watchSessionDeadline(renew, expired);

    await vi.advanceTimersByTimeAsync(299_000);
    expect(expired).not.toHaveBeenCalled();
    await vi.advanceTimersByTimeAsync(2_000);
    expect(expired).toHaveBeenCalledTimes(1);

    // And it stops there rather than reporting on a loop.
    await vi.advanceTimersByTimeAsync(600_000);
    expect(expired).toHaveBeenCalledTimes(1);
    stop();
  });

  it("renews at once when it starts inside the renewal window", async () => {
    setSessionExpiry(T0 + 30);
    const renew = vi.fn(async () => T0 + 330);
    const stop = watchSessionDeadline(renew, vi.fn());
    await vi.advanceTimersByTimeAsync(0);
    expect(renew).toHaveBeenCalledTimes(1);
    stop();
  });

  it("does nothing once cancelled", async () => {
    setSessionExpiry(T0 + 300);
    const renew = vi.fn().mockResolvedValue(null);
    const expired = vi.fn();
    watchSessionDeadline(renew, expired)();
    await vi.advanceTimersByTimeAsync(3_600_000);
    expect(renew).not.toHaveBeenCalled();
    expect(expired).not.toHaveBeenCalled();
  });
});
