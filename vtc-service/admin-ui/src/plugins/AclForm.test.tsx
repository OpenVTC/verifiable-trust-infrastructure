import { fireEvent, screen, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { Acl } from "@/plugins/acl";
import {
  mockFetch,
  renderWithProviders,
  sentPayloads,
  taskRoute,
} from "@/test/render";

// The grant is a signed document; the stand-in sends it unsigned so the table
// below answers it without a console key.
vi.mock("@/lib/api", async (original) => ({
  ...(await original<typeof import("@/lib/api")>()),
  postSignedRead: (await import("@/test/signed-read")).unsignedRead,
  postSignedTrustTask: (await import("@/test/signed-read")).unsignedTask,
}));
vi.mock("@/lib/signed-act", async (original) => ({
  ...(await original<typeof import("@/lib/signed-act")>()),
  postSignedWithStepUp: (await import("@/test/signed-read")).unsignedTask,
}));

const GRANT = "https://trusttasks.org/spec/acl/grant/0.1";
const LIST = "https://trusttasks.org/spec/acl/list/0.1";

// The payload schema types `label` and `expiresAt` as strings, so a blank
// optional field must be absent from the request, never `null` (a 400).
describe("New ACL entry — blank optional fields", () => {
  it("omits label and expiresAt rather than sending null", async () => {
    const requests = mockFetch([
      taskRoute(LIST, { entries: [], truncated: false }),
      taskRoute(GRANT, {
        entry: { subject: "did:example:test", role: "member", scopes: [] },
      }),
    ]);
    renderWithProviders(<Acl />, { route: "/acl", path: "/acl" });

    fireEvent.click(await screen.findByRole("button", { name: /add entry/i }));
    const did = await screen.findByPlaceholderText("did:key:z6Mk…");
    fireEvent.change(did, { target: { value: "did:example:test" } });
    fireEvent.click(screen.getByRole("button", { name: /create entry/i }));

    await waitFor(() => expect(sentPayloads(requests, GRANT)).toHaveLength(1));
    const payload = (
      sentPayloads(requests, GRANT) as { entry: Record<string, unknown> }[]
    )[0]!;
    expect(payload.entry).toEqual({
      subject: "did:example:test",
      role: "member",
      scopes: [],
    });
    expect("label" in payload.entry).toBe(false);
    expect("expiresAt" in payload.entry).toBe(false);
  });
});
