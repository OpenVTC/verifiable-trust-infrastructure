// Enrolment, listing and revocation as the signed documents they send.
//
// The things worth asserting: the enrolment names the key this browser can
// actually sign with and the identity the session belongs to, it goes through
// the bound step-up (`postSignedWithStepUp`), and a browser with no enrolled
// key lists nothing rather than failing.

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("./api", async (original) => ({
  ...(await original<typeof import("./api")>()),
  fetchWhoami: vi.fn(),
  postSignedRead: vi.fn(),
  postSignedTrustTask: vi.fn(),
}));
vi.mock("./signed-act", async (original) => ({
  ...(await original<typeof import("./signed-act")>()),
  postSignedWithStepUp: vi.fn(),
}));

import { fetchWhoami, postSignedRead, postSignedTrustTask } from "./api";
import { postSignedWithStepUp } from "./signed-act";
import {
  TASK_SIGNING_KEY_ENROLL,
  TASK_SIGNING_KEY_LIST,
  TASK_SIGNING_KEY_REVOKE,
  enrolThisBrowser,
  listConsoleKeys,
  revokeConsoleKey,
} from "./console-keys-api";
import {
  forgetConsoleKey,
  generateConsoleKey,
  loadConsoleKey,
  resetConsoleKeyCacheForTests,
} from "./console-key";

const ADMIN_DID = "did:webvh:QmScid:community.example:alice";
const yes = async () => true;

function signingKey(did: string, patch: Record<string, unknown> = {}) {
  return {
    signingKeyDid: did,
    identityDid: ADMIN_DID,
    scope: "console",
    createdAt: "2026-09-23T10:00:00Z",
    expiresAt: "2026-10-23T10:00:00Z",
    active: true,
    ...patch,
  };
}

beforeEach(() => {
  vi.mocked(fetchWhoami).mockResolvedValue({
    session: { subject: ADMIN_DID },
  } as unknown as Awaited<ReturnType<typeof fetchWhoami>>);
});

afterEach(async () => {
  await forgetConsoleKey();
  resetConsoleKeyCacheForTests();
  vi.mocked(postSignedRead).mockReset();
  vi.mocked(postSignedTrustTask).mockReset();
  vi.mocked(postSignedWithStepUp).mockReset();
});

describe("enrolment", () => {
  it("names this browser's key and the session's identity, through the bound step-up", async () => {
    vi.mocked(postSignedWithStepUp).mockImplementation(async (_t, payload) => ({
      signingKey: signingKey((payload as { signingKeyDid: string }).signingKeyDid, {
        deviceLabel: "Work laptop",
      }),
    }));
    const enrolled = await enrolThisBrowser("  Work laptop  ", yes);
    const held = await loadConsoleKey();
    expect(held).not.toBeNull();
    const [task, payload, gesture] = vi.mocked(postSignedWithStepUp).mock.calls[0]!;
    expect(task).toBe(TASK_SIGNING_KEY_ENROLL);
    expect(payload).toEqual({
      signingKeyDid: held!.consoleDid,
      identityDid: ADMIN_DID,
      scope: "console",
      deviceLabel: "Work laptop",
    });
    expect(gesture).toBe(yes);
    expect(enrolled).toMatchObject({
      consoleDid: held!.consoleDid,
      adminDid: ADMIN_DID,
      label: "Work laptop",
      active: true,
    });
  });

  it("omits an empty label, and reuses the key this browser already holds", async () => {
    const existing = await generateConsoleKey();
    vi.mocked(postSignedWithStepUp).mockResolvedValue({ signingKey: signingKey(existing.consoleDid) });
    await enrolThisBrowser("   ", yes);
    const payload = vi.mocked(postSignedWithStepUp).mock.calls[0]![1] as Record<string, unknown>;
    expect(payload.signingKeyDid).toBe(existing.consoleDid);
    expect("deviceLabel" in payload).toBe(false);
  });
});

describe("listing", () => {
  it("lists nothing, and sends nothing, from a browser with no key", async () => {
    expect(await listConsoleKeys()).toEqual([]);
    expect(postSignedRead).not.toHaveBeenCalled();
  });

  it("returns the identity's keys as the daemon computed them", async () => {
    const key = await generateConsoleKey();
    vi.mocked(postSignedRead).mockResolvedValue({
      signingKeys: [signingKey(key.consoleDid), signingKey("did:key:z6MkOld", { active: false, revokedAt: "2026-09-24T00:00:00Z" })],
    });
    const keys = await listConsoleKeys();
    expect(vi.mocked(postSignedRead).mock.calls[0]![0]).toBe(TASK_SIGNING_KEY_LIST);
    expect(keys.map((k) => [k.consoleDid, k.active])).toEqual([
      [key.consoleDid, true],
      ["did:key:z6MkOld", false],
    ]);
  });

  it("lists nothing when this browser's key speaks for nobody", async () => {
    await generateConsoleKey();
    vi.mocked(postSignedRead).mockRejectedValue({ status: 403, code: "permissionDenied", message: "x" });
    expect(await listConsoleKeys()).toEqual([]);
  });
});

describe("revocation", () => {
  it("forgets the local key when it is this browser's, and not otherwise", async () => {
    const key = await generateConsoleKey();
    vi.mocked(postSignedTrustTask).mockResolvedValue({});
    await revokeConsoleKey("did:key:z6MkAnotherBrowser");
    expect(await loadConsoleKey()).not.toBeNull();
    await revokeConsoleKey(key.consoleDid);
    expect(vi.mocked(postSignedTrustTask).mock.calls[1]).toEqual([
      TASK_SIGNING_KEY_REVOKE,
      { signingKeyDid: key.consoleDid },
    ]);
    expect(await loadConsoleKey()).toBeNull();
  });
});
