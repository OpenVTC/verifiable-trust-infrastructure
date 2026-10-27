// An administrator's own passkeys as the signed documents they send (#1641).
//
// What matters: every call is a signed Trust Task (no `/v1/admin/passkeys`
// bearer route), the payloads use the published member names
// (`enrollmentId`, `credential`, `uvCredential`, `deviceLabel`,
// `credentialId`, `revocationId`), and the step-up assertion always rides the
// finish.

import { afterEach, describe, expect, it, vi } from "vitest";

vi.mock("./api", async (original) => ({
  ...(await original<typeof import("./api")>()),
  postSignedRead: vi.fn(),
  postSignedTrustTask: vi.fn(),
}));
vi.mock("./webauthn", async (original) => ({
  ...(await original<typeof import("./webauthn")>()),
  decodePublicKeyOptions: vi.fn((o: unknown) => o),
  serializeAssertion: vi.fn(() => ({ kind: "assertion" })),
  serializeRegistration: vi.fn(() => ({ kind: "registration" })),
}));

import { postSignedRead, postSignedTrustTask } from "./api";
import {
  TRUST_TASK_ENROLL_FINISH,
  TRUST_TASK_ENROLL_START,
  TRUST_TASK_LIST,
  TRUST_TASK_REVOKE_FINISH,
  TRUST_TASK_REVOKE_START,
  fetchPasskeys,
  registerPasskey,
  revokePasskey,
} from "./my-passkeys-api";

const credential = {} as PublicKeyCredential;
const credentials = {
  create: vi.fn(async () => credential),
  get: vi.fn(async () => credential),
} as unknown as Pick<CredentialsContainer, "create" | "get">;

afterEach(() => {
  vi.mocked(postSignedRead).mockReset();
  vi.mocked(postSignedTrustTask).mockReset();
});

describe("my passkeys", () => {
  it("lists with a signed read", async () => {
    vi.mocked(postSignedRead).mockResolvedValue({ credentials: [] });
    await expect(fetchPasskeys()).resolves.toEqual({ credentials: [] });
    expect(postSignedRead).toHaveBeenCalledWith(TRUST_TASK_LIST, {});
  });

  it("registers with both ceremonies' results, signed, under the published names", async () => {
    vi.mocked(postSignedTrustTask).mockImplementation(async (type) => {
      if (type === TRUST_TASK_ENROLL_START) {
        return {
          enrollmentId: "enr-1",
          options: { challenge: "c1" },
          uvOptions: { challenge: "c2" },
        };
      }
      return {};
    });

    await registerPasskey({ label: "YubiKey" }, credentials);

    expect(postSignedTrustTask).toHaveBeenNthCalledWith(1, TRUST_TASK_ENROLL_START, {});
    expect(postSignedTrustTask).toHaveBeenNthCalledWith(2, TRUST_TASK_ENROLL_FINISH, {
      enrollmentId: "enr-1",
      credential: { kind: "registration" },
      uvCredential: { kind: "assertion" },
      deviceLabel: "YubiKey",
    });
  });

  it("refuses a start that is missing the step-up challenge before any ceremony", async () => {
    vi.mocked(postSignedTrustTask).mockResolvedValue({
      enrollmentId: "enr-1",
      options: { challenge: "c1" },
    });
    await expect(registerPasskey({ label: "" }, credentials)).rejects.toThrow(/uvOptions/);
    expect(postSignedTrustTask).toHaveBeenCalledTimes(1);
  });

  it("revokes with the step-up assertion, signed", async () => {
    vi.mocked(postSignedTrustTask).mockImplementation(async (type) =>
      type === TRUST_TASK_REVOKE_START
        ? { revocationId: "rev-1", uvOptions: { challenge: "c" } }
        : {},
    );

    await revokePasskey({ credentialId: "abcd" }, credentials);

    expect(postSignedTrustTask).toHaveBeenNthCalledWith(1, TRUST_TASK_REVOKE_START, {
      credentialId: "abcd",
    });
    expect(postSignedTrustTask).toHaveBeenNthCalledWith(2, TRUST_TASK_REVOKE_FINISH, {
      revocationId: "rev-1",
      uvCredential: { kind: "assertion" },
    });
  });
});
