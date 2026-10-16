import { fireEvent, screen, waitFor, within } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { DataRooms } from "@/plugins/dataRooms";
import {
  NAME_BOOK_ROUTES,
  mockFetch,
  renderWithProviders,
  sentPayloads,
  taskRoute,
  whoamiWith,
} from "@/test/render";

// The room reads and the limit override are signed documents; the stand-ins
// send them unsigned so the tables below answer them.
vi.mock("@/lib/api", async (original) => ({
  ...(await original<typeof import("@/lib/api")>()),
  postSignedRead: (await import("@/test/signed-read")).unsignedRead,
  postSignedTrustTask: (await import("@/test/signed-read")).unsignedTask,
}));

const LIST = "https://trusttasks.org/spec/vtc/rooms/list/0.1";
const GET = "https://trusttasks.org/spec/vtc/rooms/get/0.1";
const USAGE = "https://trusttasks.org/spec/vtc/rooms/usage/0.1";
const LIMITS_SET = "https://trusttasks.org/spec/vtc/rooms/limits/set/0.1";

/** A did:web with a port: its `%3A` must reach the VTC as sent. */
const ROOM_ID = "did:web:rooms.example.com%3A8443:board";
const OWNER = "did:key:z6MkOwner";
const MEMBER = "did:key:z6MkMember";

const hostedRoom = (visibility: "open" | "attributed" | "private") => ({
  roomId: ROOM_ID,
  ownerDid: OWNER,
  visibility,
  retentionPolicy: "chained",
  epoch: 3,
  lifecycle: "live",
  retentionDays: 30,
  createdAt: 1_760_000_000,
  updatedAt: 1_760_000_000,
});

const roomGet = (visibility: "open" | "attributed" | "private" = "attributed") => ({
  room: hostedRoom(visibility),
  storage: { configId: "local", earlierConfigs: [{ configId: "old-s3", files: 2, bytes: 2048 }] },
  limits: {
    limits: { filesEnabled: true, room: { maxBytes: 1_000_000, maxFiles: 10 }, member: {} },
    roomSource: "override",
    memberSource: "default",
    hostCeilingBytes: 104_857_600,
  },
  usage: {
    room: { files: 9, bytes: 500_000, reservedBytes: 0 },
    orphans: { files: 1, bytes: 300 },
  },
  largestBlobs: [{ size: 400_000, configId: "local", createdAt: "2026-10-01T00:00:00Z" }],
  membersWithUsage: 1,
});

const usageRow = (over: Record<string, unknown>) => ({
  files: 0,
  bytes: 0,
  reservedBytes: 0,
  uploads: 0,
  downloads: 0,
  egressBytes: 0,
  ...over,
});

const usageAnswer = (payload: unknown) => {
  const p = payload as { groupBy: string };
  const items =
    p.groupBy === "member"
      ? [usageRow({ member: MEMBER, files: 4, bytes: 200_000, limits: { maxBytes: 250_000 } })]
      : p.groupBy === "day"
        ? [usageRow({ date: "2026-10-14", bytes: 500_000, uploads: 2 })]
        : p.groupBy === "storageConfig"
          ? [usageRow({ storageConfig: "local", bytes: 950, capacityBytes: 1000 })]
          : [
              usageRow({
                roomId: ROOM_ID,
                storageConfig: "local",
                files: 9,
                bytes: 500_000,
                limits: { maxBytes: 1_000_000, maxFiles: 10 },
              }),
            ];
  return { asOf: "2026-10-14T10:00:00Z", from: "2026-09-15", to: "2026-10-14", items };
};

const detailRoutes = (visibility?: "open" | "attributed" | "private") => [
  ...NAME_BOOK_ROUTES,
  taskRoute(GET, roomGet(visibility)),
  taskRoute(USAGE, usageAnswer),
  taskRoute(LIMITS_SET, {
    roomId: ROOM_ID,
    target: { kind: "room" },
    limits: roomGet().limits,
    usage: { files: 9, bytes: 500_000, reservedBytes: 0 },
    overLimit: true,
  }),
];

/** A holder of `vtc.rooms.admin`: every tab of Data rooms. */
const ROOMS_ADMIN = whoamiWith(["vtc.rooms.admin"]);

/** Mount Data rooms at `route`, as the shell mounts it, for `whoami`. */
const mount = (route: string, whoami = ROOMS_ADMIN) =>
  renderWithProviders(<DataRooms />, { route, path: "/rooms/*", whoami });

const openDetail = () => mount(`/rooms/r/${encodeURIComponent(ROOM_ID)}`);

describe("Rooms list", () => {
  it("links each room to its own page", async () => {
    mockFetch([...NAME_BOOK_ROUTES, taskRoute(LIST, { items: [hostedRoom("open")] })]);
    mount("/rooms");
    const link = await screen.findByRole("link", { name: /did:web/ });
    expect(link.getAttribute("href")).toBe(`/rooms/r/${encodeURIComponent(ROOM_ID)}`);
  });
});

describe("Room detail", () => {
  it("reads the room by the identifier exactly as minted", async () => {
    const requests = mockFetch(detailRoutes());
    openDetail();
    expect(await screen.findByText(ROOM_ID)).toBeTruthy();
    expect(sentPayloads(requests, GET)).toEqual([{ roomId: ROOM_ID }]);
  });

  it("shows storage, limits with their source, and sizes only", async () => {
    mockFetch(detailRoutes());
    openDetail();
    expect(await screen.findByText("Still on earlier storage")).toBeTruthy();
    expect(screen.getByText("old-s3")).toBeTruthy();
    expect(screen.getByText("override")).toBeTruthy();
    expect(screen.getByText("community default")).toBeTruthy();
    // 9 of 10 files is the fuller of the two limits.
    expect(screen.getByText("90% used")).toBeTruthy();
    expect(screen.getByText(/does not know what they are called/)).toBeTruthy();
    expect(screen.queryByRole("button", { name: /download/i })).toBeNull();
  });

  it("lists members' usage on an attributed room, saying what the host sees", async () => {
    const requests = mockFetch(detailRoutes("attributed"));
    openDetail();
    expect(await screen.findByText("Members' usage")).toBeTruthy();
    expect(screen.getByText(/not a membership roster/)).toBeTruthy();
    await screen.findByText("200 KB");
    expect(
      sentPayloads(requests, USAGE).some(
        (p) => (p as { groupBy: string }).groupBy === "member",
      ),
    ).toBe(true);
  });

  it("asks nothing per member of a private room", async () => {
    const requests = mockFetch(detailRoutes("private"));
    openDetail();
    await screen.findByText("Activity");
    expect(screen.queryByText("Members' usage")).toBeNull();
    expect(
      sentPayloads(requests, USAGE).every((p) => (p as { groupBy: string }).groupBy === "day"),
    ).toBe(true);
  });

  it("overrides the room's limits with a reason, exactly as typed", async () => {
    const requests = mockFetch(detailRoutes());
    openDetail();
    const row = (await screen.findByText("The room")).closest("tr")!;
    fireEvent.click(within(row).getByRole("button", { name: "Change" }));

    // Pre-filled exactly, so re-saving changes nothing it was not asked to.
    expect((screen.getByLabelText(/Most space/) as HTMLInputElement).value).toBe("1 MB");
    fireEvent.change(screen.getByLabelText(/Most space/), { target: { value: "2 GB" } });
    fireEvent.change(screen.getByLabelText(/Largest file/), { target: { value: "200 MB" } });
    expect(screen.getByText(/the host's ceiling on one file/)).toBeTruthy();
    expect(
      (screen.getByRole("button", { name: "Save limits" }) as HTMLButtonElement).disabled,
    ).toBe(true);

    fireEvent.change(screen.getByLabelText(/Largest file/), { target: { value: "50 MB" } });
    fireEvent.change(screen.getByLabelText(/^Reason/), { target: { value: "board archive" } });
    fireEvent.click(screen.getByRole("button", { name: "Save limits" }));

    await waitFor(() => expect(sentPayloads(requests, LIMITS_SET)).toHaveLength(1));
    expect(sentPayloads(requests, LIMITS_SET)[0]).toEqual({
      roomId: ROOM_ID,
      target: { kind: "room" },
      reason: "board archive",
      limits: { maxFiles: 10, maxBytes: 2_000_000_000, maxFileBytes: 50_000_000 },
    });
    // The answer said the room is already over: nothing deleted, uploads refused.
    expect(await screen.findByText(/Nothing is deleted/)).toBeTruthy();
  });

  it("clears a member's override and nothing else", async () => {
    const requests = mockFetch(detailRoutes());
    openDetail();
    fireEvent.click(await screen.findByRole("button", { name: "Override" }));
    fireEvent.click(screen.getByLabelText(/Clear the override/));
    fireEvent.change(screen.getByLabelText(/^Reason/), { target: { value: "back to default" } });
    fireEvent.click(screen.getByRole("button", { name: "Clear override" }));
    await waitFor(() => expect(sentPayloads(requests, LIMITS_SET)).toHaveLength(1));
    expect(sentPayloads(requests, LIMITS_SET)[0]).toEqual({
      roomId: ROOM_ID,
      target: { kind: "member", member: MEMBER },
      reason: "back to default",
      clear: true,
    });
  });

  it("pauses uploads without touching a limit", async () => {
    const requests = mockFetch(detailRoutes());
    openDetail();
    fireEvent.click(await screen.findByRole("button", { name: "Pause new uploads" }));
    fireEvent.change(screen.getByLabelText("Reason"), { target: { value: "abuse report" } });
    fireEvent.click(screen.getByRole("button", { name: "Pause uploads" }));
    await waitFor(() => expect(sentPayloads(requests, LIMITS_SET)).toHaveLength(1));
    expect(sentPayloads(requests, LIMITS_SET)[0]).toEqual({
      roomId: ROOM_ID,
      target: { kind: "room" },
      filesEnabled: false,
      reason: "abuse report",
    });
  });

  it("says a missing room is missing, and a failed read is a failure", async () => {
    mockFetch([
      ...NAME_BOOK_ROUTES,
      taskRoute(GET, { code: "vtc/rooms/get:notFound", message: "no such room" }, 404),
    ]);
    openDetail();
    expect(await screen.findByText(/hosts no room with that identifier/)).toBeTruthy();
  });
});

describe("Room usage", () => {
  it("flags rooms and storage near a limit", async () => {
    mockFetch([...NAME_BOOK_ROUTES, taskRoute(USAGE, usageAnswer)]);
    mount("/rooms/usage");
    const near = (await screen.findByText("Near a limit")).closest("section")!;
    // The room: 9 of 10 files. The storage: 950 of 1000 bytes.
    expect(within(near).getByText("90%")).toBeTruthy();
    expect(within(near).getByText("95%")).toBeTruthy();
  });

  it("regroups by member with the range, and says private rooms are left out", async () => {
    const requests = mockFetch([...NAME_BOOK_ROUTES, taskRoute(USAGE, usageAnswer)]);
    mount("/rooms/usage");
    await screen.findByText("Near a limit");
    fireEvent.click(screen.getByRole("tab", { name: "Members" }));
    expect(await screen.findByText(/attributed to nobody, by design/)).toBeTruthy();
    await waitFor(() =>
      expect(
        sentPayloads(requests, USAGE).some((p) => {
          const q = p as { groupBy: string; filter?: { from?: string; to?: string } };
          return q.groupBy === "member" && q.filter?.from !== undefined && q.filter?.to !== undefined;
        }),
      ).toBe(true),
    );
  });

  it("exports what it shows as CSV", async () => {
    mockFetch([...NAME_BOOK_ROUTES, taskRoute(USAGE, usageAnswer)]);
    const created: Blob[] = [];
    const createObjectURL = vi.fn((b: Blob) => {
      created.push(b);
      return "blob:x";
    });
    vi.stubGlobal("URL", Object.assign(URL, { createObjectURL, revokeObjectURL: vi.fn() }));
    const click = vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => {});
    mount("/rooms/usage");
    const exportButton = await screen.findByRole("button", { name: /Export CSV/ });
    await waitFor(() => expect((exportButton as HTMLButtonElement).disabled).toBe(false));
    fireEvent.click(exportButton);
    expect(click).toHaveBeenCalled();
    // jsdom's Blob has no `text()`; FileReader is what it does have.
    const text = await new Promise<string>((resolve) => {
      const reader = new FileReader();
      reader.onload = () => resolve(reader.result as string);
      reader.readAsText(created[0]!);
    });
    expect(text.split("\r\n")[0]).toMatch(/^roomId,storageConfig,files,bytes/);
    expect(text).toContain(ROOM_ID);
    click.mockRestore();
  });
});
