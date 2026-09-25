import { describe, expect, it } from "vitest";

import type { WhoamiResponse } from "@/lib/api";
import { isSuperAdmin } from "@/lib/viewer";

const who = (roles: string[], scopes: string[]): WhoamiResponse => ({
  session: {
    id: "sess_1",
    subject: "did:key:z6Mk",
    issuedAt: "2026-09-01T00:00:00Z",
    expiresAt: "2026-09-01T00:05:00Z",
  },
  roles,
  scopes,
});

describe("isSuperAdmin", () => {
  it("is the admin role with no context restriction", () => {
    expect(isSuperAdmin(who(["admin"], []))).toBe(true);
    expect(isSuperAdmin(who(["admin"], ["ctx-a"]))).toBe(false);
    expect(isSuperAdmin(who(["initiator"], []))).toBe(false);
    expect(isSuperAdmin(null)).toBe(false);
    expect(isSuperAdmin(undefined)).toBe(false);
  });
});
