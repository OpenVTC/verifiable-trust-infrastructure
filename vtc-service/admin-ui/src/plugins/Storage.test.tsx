import { fireEvent, screen, waitFor, within } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { NEXT_STEP_TYPE } from "@/lib/parked-action";
import { DataRooms } from "@/plugins/dataRooms";
import { createPayload, draftErrors, updatePayload } from "@/plugins/storage/ConfigForm";
import type { StorageConfigRecord } from "@/lib/wire-types";
import {
  NAME_BOOK_ROUTES,
  renderWithProviders,
  mockFetch,
  sentPayloads,
  taskRoute,
  type MockRoute,
  whoamiWith,
} from "@/test/render";

// Signed reads and the step-up writes are sent unsigned, so the tables below
// answer them; the passkey gesture is not part of what these tests hold.
vi.mock("@/lib/api", async (original) => ({
  ...(await original<typeof import("@/lib/api")>()),
  postSignedRead: (await import("@/test/signed-read")).unsignedRead,
  postSignedTrustTask: (await import("@/test/signed-read")).unsignedTask,
}));
vi.mock("@/lib/signed-act", async (original) => ({
  ...(await original<typeof import("@/lib/signed-act")>()),
  postSignedWithStepUp: (await import("@/test/signed-read")).unsignedTask,
}));

const T = "https://trusttasks.org/spec";
const LIST = `${T}/vtc/storage/configs/list/0.2`;
const GET = `${T}/vtc/storage/configs/get/0.2`;
const CREATE = `${T}/vtc/storage/configs/create/0.2`;
const RETIRE = `${T}/vtc/storage/configs/retire/0.1`;
const PROBE = `${T}/vtc/storage/configs/probe/0.1`;
const ASSIGN = `${T}/vtc/rooms/storage/assign/0.1`;
const MIGRATE = `${T}/vtc/rooms/storage/migrate/0.2`;
const ROOMS_GET = `${T}/vtc/rooms/get/0.2`;
const ROOMS_LIST = `${T}/vtc/rooms/list/0.1`;
const USAGE = `${T}/vtc/rooms/usage/0.1`;

const ROOM_ID = "did:web:rooms.example.com:board";

/** Mount Data rooms at `route`, as the shell mounts it, for a holder of
 *  `vtc.rooms.admin`. */
const mount = (route: string) =>
  renderWithProviders(<DataRooms />, {
    route,
    path: "/rooms/*",
    whoami: whoamiWith(["vtc.rooms.admin"]),
  });

const local: StorageConfigRecord = {
  id: "local",
  label: "This host",
  settings: { kind: "local", root: "/var/lib/vtc/room-blobs" },
  state: "active",
  isDefault: true,
  createdBy: "did:key:z6MkA",
  createdAt: "2026-10-01T00:00:00Z",
};
const s3: StorageConfigRecord = {
  id: "eu-s3",
  label: "EU — S3",
  settings: { kind: "s3", bucket: "vtc-rooms", region: "eu-west-1", prefix: "prod/" },
  auth: { mode: "vta-account", context: "community", account: "eu-s3" },
  capacityBytes: 1_000_000,
  state: "active",
  createdBy: "did:key:z6MkA",
  createdAt: "2026-10-02T00:00:00Z",
};
const facts = (over: Record<string, unknown> = {}) => ({
  rooms: 0,
  files: 0,
  bytes: 0,
  pendingDeleteBytes: 0,
  credential: { status: "none" },
  health: {},
  ...over,
});
const items = [
  { config: local, facts: facts({ rooms: 2, files: 3, bytes: 3000 }) },
  {
    config: s3,
    facts: facts({
      bytes: 850_000,
      credential: { status: "required" },
    }),
  },
];

/** The VTC's answer to a parked act: 202 with a next-step document. */
const parked = (task: string): MockRoute => ({
  method: "POST",
  path: "/v1/trust-tasks",
  task,
  status: 202,
  body: () => ({
    type: NEXT_STEP_TYPE,
    payload: {
      message: "Sent for approval — 1 of 1 administrator(s) must approve within 72 hours.",
      ext: { "org.openvtc": { actionId: "act-9" } },
    },
  }),
});

const draft = (over: Record<string, unknown> = {}) => ({
  id: "eu-s3",
  label: "EU — S3",
  kind: "s3" as const,
  root: "",
  bucket: "vtc-rooms",
  region: "eu-west-1",
  endpoint: "",
  prefix: "",
  pathStyle: false,
  mode: "vta-account" as "vta-account" | "ambient" | "sealed",
  roleArn: "",
  context: "community",
  account: "eu-s3",
  capacity: "",
  isDefault: false,
  reason: "new bucket",
  ...over,
});

describe("the config form's rules", () => {
  it("accepts a complete S3 draft and builds the spec's payload, with no secret", () => {
    const d = draft({ prefix: "prod/", capacity: "500 GB", endpoint: "https://r2.example" });
    expect(draftErrors(d, false)).toEqual({});
    expect(createPayload(d)).toEqual({
      id: "eu-s3",
      label: "EU — S3",
      reason: "new bucket",
      settings: {
        kind: "s3",
        bucket: "vtc-rooms",
        region: "eu-west-1",
        endpoint: "https://r2.example",
        prefix: "prod/",
      },
      auth: { mode: "vta-account", context: "community", account: "eu-s3" },
      capacityBytes: 500_000_000_000,
    });
  });

  it("refuses what the VTC would refuse", () => {
    const e = draftErrors(
      draft({
        id: "EU_S3",
        bucket: "x",
        endpoint: "http://insecure",
        prefix: "Prod",
        account: "",
        reason: " ",
      }),
      false,
    );
    expect(Object.keys(e).sort()).toEqual(["account", "bucket", "endpoint", "id", "prefix", "reason"]);
    expect(draftErrors(draft({ kind: "local", root: "relative/dir" }), false).root).toBeTruthy();
  });

  it("builds ambient and sealed configs, for S3 and Cloud Storage, with no secret", () => {
    const role = "arn:aws:iam::123456789012:role/rooms-writer";
    const ambient = draft({ mode: "ambient", roleArn: role, context: "", account: "" });
    expect(draftErrors(ambient, false)).toEqual({});
    expect(createPayload(ambient).auth).toEqual({ mode: "ambient", roleArn: role });
    expect(createPayload(draft({ mode: "ambient", roleArn: "" })).auth).toEqual({ mode: "ambient" });
    expect(draftErrors(draft({ mode: "ambient", roleArn: "not-an-arn" }), false).roleArn).toBeTruthy();
    // The machine's own identity reaches AWS only.
    expect(draftErrors(draft({ mode: "ambient", endpoint: "https://r2.example" }), false).endpoint).toBeTruthy();

    const gcs = draft({ kind: "gcs", mode: "sealed", bucket: "rooms_eu", region: "", context: "", account: "" });
    expect(draftErrors(gcs, false)).toEqual({});
    expect(createPayload(gcs)).toMatchObject({
      settings: { kind: "gcs", bucket: "rooms_eu" },
      auth: { mode: "sealed" },
    });
    // Cloud Storage has no VTA account model.
    expect(draftErrors(draft({ kind: "gcs", mode: "vta-account" }), false).mode).toBeTruthy();
    expect(JSON.stringify(createPayload(gcs))).not.toMatch(/secret|private/i);
  });

  it("moves a config off a mode the host withdrew", () => {
    const ambientConfig: StorageConfigRecord = { ...s3, auth: { mode: "ambient" } };
    const d = draft({ mode: "vta-account", context: "community", account: "eu-s3", reason: "host withdrew ambient" });
    expect(updatePayload(d, ambientConfig)).toEqual({
      configId: "eu-s3",
      reason: "host withdrew ambient",
      auth: { mode: "vta-account", context: "community", account: "eu-s3" },
    });
  });

  it("sends only what changed, and never clears the default", () => {
    const d = draft({ label: "EU — S3", capacity: "2 MB", isDefault: false, reason: "grow" });
    expect(updatePayload(d, s3)).toEqual({
      configId: "eu-s3",
      reason: "grow",
      capacityBytes: 2_000_000,
    });
    expect(updatePayload(draft({ isDefault: false }), local)).not.toHaveProperty("isDefault");
  });
});

describe("Storage list", () => {
  it("lists a config whose mode the host withdrew among those needing attention", async () => {
    const withdrawn = {
      config: { ...s3, id: "eu-amb", auth: { mode: "ambient" as const } },
      facts: facts({ credential: { status: "notAllowed" } }),
    };
    mockFetch([...NAME_BOOK_ROUTES, taskRoute(LIST, { items: [items[0], withdrawn] })]);
    mount("/rooms/storage");
    const attention = (await screen.findByText("Needs a credential")).closest("section")!;
    expect(within(attention).getByText("eu-amb")).toBeTruthy();
    expect(within(attention).getByText(/a mode this community.s host no longer permits/)).toBeTruthy();
  });

  it("labels a sealed config as no protection against the machine's operator", async () => {
    const sealed = {
      config: { ...s3, id: "r2-archive", auth: { mode: "sealed" as const } },
      facts: facts({
        credential: { status: "sealed", fingerprint: "zQmT5NvUtoM5nWFfrQdVrFtvGfKFmG7AHE8P34isapyhCxX", setAt: "2026-10-10T10:30:00Z" },
      }),
      assignedRooms: [],
      assignedRoomsTruncated: false,
    };
    mockFetch([...NAME_BOOK_ROUTES, taskRoute(GET, sealed)]);
    mount("/rooms/storage/r2-archive");
    expect(await screen.findByText(/whoever operates the machine/)).toBeTruthy();
    expect(screen.getByText(/cnm storage credentials set --config r2-archive/)).toBeTruthy();
  });

  it("lists configs needing a credential first, and never a credential", async () => {
    mockFetch([...NAME_BOOK_ROUTES, taskRoute(LIST, { items })]);
    mount("/rooms/storage");
    const attention = (await screen.findByText("Needs a credential")).closest("section")!;
    expect(within(attention).getByText("eu-s3")).toBeTruthy();
    expect(within(attention).getByText("credential required")).toBeTruthy();
    // 850 KB of a 1 MB capacity.
    expect(within(attention).getByText("85%")).toBeTruthy();
    expect(screen.getByText("default")).toBeTruthy();
    expect(screen.getByText("none needed")).toBeTruthy();
  });

  it("sends a new config for approval and says so", async () => {
    const requests = mockFetch([...NAME_BOOK_ROUTES, taskRoute(LIST, { items }), parked(CREATE)]);
    mount("/rooms/storage?create=1");
    fireEvent.change(await screen.findByLabelText(/^Identifier/), { target: { value: "r2" } });
    fireEvent.change(screen.getByLabelText(/^Label/), { target: { value: "R2" } });
    fireEvent.change(screen.getByLabelText(/^VTA context/), { target: { value: "community" } });
    fireEvent.change(screen.getByLabelText(/^VTA account/), { target: { value: "r2" } });
    fireEvent.change(screen.getByLabelText(/^Bucket/), { target: { value: "rooms-r2" } });
    fireEvent.change(screen.getByLabelText(/^Region/), { target: { value: "auto" } });
    fireEvent.change(screen.getByLabelText(/^Reason/), { target: { value: "cheaper egress" } });
    fireEvent.click(screen.getByRole("button", { name: "Send for approval" }));

    expect(await screen.findByText("Sent for approval")).toBeTruthy();
    expect(screen.getByRole("link", { name: "View the action" }).getAttribute("href")).toContain(
      "act-9",
    );
    expect(sentPayloads(requests, CREATE)).toEqual([
      {
        id: "r2",
        label: "R2",
        reason: "cheaper egress",
        settings: { kind: "s3", bucket: "rooms-r2", region: "auto" },
        auth: { mode: "vta-account", context: "community", account: "r2" },
      },
    ]);
  });
});

describe("Storage config page", () => {
  const getRoutes = (record: StorageConfigRecord, f = facts()) => [
    ...NAME_BOOK_ROUTES,
    taskRoute(GET, { config: record, facts: f, assignedRooms: [ROOM_ID] }),
    taskRoute(PROBE, {
      configId: record.id,
      ok: false,
      probedAt: "2026-10-14T10:00:00Z",
      steps: [
        { step: "authenticate", ok: true, durationMs: 12 },
        { step: "put", ok: false, durationMs: 40, error: "AccessDenied" },
      ],
    }),
    parked(RETIRE),
  ];

  it("probes and shows each step", async () => {
    const requests = mockFetch(getRoutes(s3));
    mount("/rooms/storage/eu-s3");
    fireEvent.click(await screen.findByRole("button", { name: "Probe now" }));
    expect(await screen.findByText("AccessDenied")).toBeTruthy();
    expect(sentPayloads(requests, PROBE)).toEqual([{ configId: "eu-s3", includeWrite: true }]);
  });

  it("will not offer to retire the default", async () => {
    mockFetch(getRoutes(local));
    mount("/rooms/storage/local");
    expect(await screen.findByText("Make another location the default first.")).toBeTruthy();
    expect(screen.queryByRole("button", { name: /^Retire/ })).toBeNull();
  });

  it("retires an unused config, for approval, with a reason", async () => {
    const requests = mockFetch(getRoutes(s3));
    mount("/rooms/storage/eu-s3");
    fireEvent.click(await screen.findByRole("button", { name: "Retire eu-s3" }));
    fireEvent.change(screen.getByLabelText("Reason"), { target: { value: "moving to R2" } });
    fireEvent.click(screen.getByRole("button", { name: "Send for approval" }));
    expect(await screen.findByText("Sent for approval")).toBeTruthy();
    expect(sentPayloads(requests, RETIRE)).toEqual([{ configId: "eu-s3", reason: "moving to R2" }]);
  });
});

describe("a room's storage", () => {
  const roomGet = {
    room: {
      roomId: ROOM_ID,
      ownerDid: "did:key:z6MkOwner",
      visibility: "private",
      retentionPolicy: "chained",
      epoch: 1,
      lifecycle: "live",
      retentionDays: 30,
      createdAt: 1_760_000_000,
      updatedAt: 1_760_000_000,
    },
    storage: { configId: "local", earlierConfigs: [] },
    limits: { limits: { filesEnabled: true }, roomSource: "default", memberSource: "default" },
    usage: { room: { files: 0, bytes: 0, reservedBytes: 0 }, orphans: { files: 0, bytes: 0 } },
  };

  it("sends new uploads elsewhere, offering only other active configs", async () => {
    const requests = mockFetch([
      ...NAME_BOOK_ROUTES,
      taskRoute(ROOMS_GET, roomGet),
      taskRoute(USAGE, { asOf: "x", from: "2026-09-15", to: "2026-10-14", items: [] }),
      taskRoute(LIST, { items }),
      parked(ASSIGN),
    ]);
    mount(`/rooms/r/${encodeURIComponent(ROOM_ID)}`);
    fireEvent.click(await screen.findByRole("button", { name: "Send new uploads to other storage" }));
    const select = (await screen.findByLabelText("Storage")) as HTMLSelectElement;
    expect([...select.options].map((o) => o.value)).toEqual(["", "eu-s3"]);
    fireEvent.change(select, { target: { value: "eu-s3" } });
    fireEvent.change(screen.getByLabelText("Reason"), { target: { value: "bigger bucket" } });
    fireEvent.click(screen.getByRole("button", { name: "Send for approval" }));
    expect(await screen.findByText("Sent for approval")).toBeTruthy();
    expect(sentPayloads(requests, ASSIGN)).toEqual([
      { roomId: ROOM_ID, configId: "eu-s3", reason: "bigger bucket" },
    ]);
  });

  const onEarlier = {
    ...roomGet,
    storage: {
      configId: "eu-s3",
      earlierConfigs: [{ configId: "local", files: 3, bytes: 3000 }],
    },
  };

  it("moves the existing files for approval, with a reason and a rate", async () => {
    const requests = mockFetch([
      ...NAME_BOOK_ROUTES,
      taskRoute(ROOMS_GET, onEarlier),
      taskRoute(USAGE, { asOf: "x", from: "2026-09-15", to: "2026-10-14", items: [] }),
      taskRoute(LIST, { items }),
      parked(MIGRATE),
    ]);
    mount(`/rooms/r/${encodeURIComponent(ROOM_ID)}`);
    fireEvent.click(await screen.findByRole("button", { name: "Move existing files to eu-s3" }));
    fireEvent.change(screen.getByLabelText("Reason"), { target: { value: "retiring local" } });
    fireEvent.change(screen.getByLabelText("At most (MiB per second, optional)"), {
      target: { value: "2" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Send for approval" }));
    expect(await screen.findByText("Sent for approval")).toBeTruthy();
    expect(sentPayloads(requests, MIGRATE)).toEqual([
      { roomId: ROOM_ID, reason: "retiring local", maxBytesPerSecond: 2 * 1024 * 1024 },
    ]);
  });

  it("shows a paused move's progress and resumes it", async () => {
    const migration = {
      migrationId: "6f1c2b3a-4d5e-4f60-8172-93a4b5c6d7e8",
      toConfig: "eu-s3",
      state: "paused",
      totalFiles: 3,
      totalBytes: 3000,
      doneFiles: 1,
      doneBytes: 1000,
      pausedCause: "destination",
      lastError: "put to eu-s3: 503 SlowDown",
      nextAttemptAt: "2026-10-10T14:30:00Z",
    };
    const requests = mockFetch([
      ...NAME_BOOK_ROUTES,
      taskRoute(ROOMS_GET, { ...onEarlier, storage: { ...onEarlier.storage, migration } }),
      taskRoute(USAGE, { asOf: "x", from: "2026-09-15", to: "2026-10-14", items: [] }),
      taskRoute(MIGRATE, {
        ...migration,
        state: "running",
        roomId: ROOM_ID,
        toConfig: "eu-s3",
        fromConfigs: ["local"],
      }),
    ]);
    mount(`/rooms/r/${encodeURIComponent(ROOM_ID)}`);
    expect(
      await screen.findByText(/Paused moving existing files to eu-s3: 1 of 3 files/),
    ).toBeTruthy();
    // Why, what failed, and that the community tries again by itself.
    expect(screen.getByText(/The destination kept refusing the files/)).toBeTruthy();
    expect(screen.getByText(/put to eu-s3: 503 SlowDown/)).toBeTruthy();
    expect(screen.getByText(/tries again by itself/)).toBeTruthy();
    // No second move is offered while one is paused.
    expect(screen.queryByRole("button", { name: "Move existing files to eu-s3" })).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "Resume now" }));
    await waitFor(() => expect(sentPayloads(requests, MIGRATE)).toHaveLength(1));
    expect(sentPayloads(requests, MIGRATE)[0]).toMatchObject({ roomId: ROOM_ID });
  });

  const reassigned = {
    ...roomGet,
    storage: {
      configId: "us-s3",
      earlierConfigs: [{ configId: "local", files: 3, bytes: 3000 }],
    },
  };

  it("says a reassigned room's move keeps its destination", async () => {
    const migration = {
      migrationId: "6f1c2b3a-4d5e-4f60-8172-93a4b5c6d7e8",
      toConfig: "eu-s3",
      state: "running",
      totalFiles: 3,
      totalBytes: 3000,
      doneFiles: 1,
      doneBytes: 1000,
    };
    mockFetch([
      ...NAME_BOOK_ROUTES,
      taskRoute(ROOMS_GET, { ...reassigned, storage: { ...reassigned.storage, migration } }),
      taskRoute(USAGE, { asOf: "x", from: "2026-09-15", to: "2026-10-14", items: [] }),
    ]);
    mount(`/rooms/r/${encodeURIComponent(ROOM_ID)}`);
    expect(await screen.findByText(/Moving existing files to eu-s3: 1 of 3 files/)).toBeTruthy();
    expect(screen.getByText(/This move keeps\s+going to/)).toBeTruthy();
    expect(screen.queryByRole("button", { name: "Move existing files to us-s3" })).toBeNull();
  });

  it("shows a queued move as waiting its turn", async () => {
    const migration = {
      migrationId: "6f1c2b3a-4d5e-4f60-8172-93a4b5c6d7e8",
      toConfig: "us-s3",
      state: "queued",
      totalFiles: 3,
      totalBytes: 3000,
      doneFiles: 0,
      doneBytes: 0,
    };
    mockFetch([
      ...NAME_BOOK_ROUTES,
      taskRoute(ROOMS_GET, { ...reassigned, storage: { ...reassigned.storage, migration } }),
      taskRoute(USAGE, { asOf: "x", from: "2026-09-15", to: "2026-10-14", items: [] }),
    ]);
    mount(`/rooms/r/${encodeURIComponent(ROOM_ID)}`);
    expect(await screen.findByText(/Waiting to move existing files to us-s3/)).toBeTruthy();
    expect(screen.getByText(/this one starts\s+when it finishes/)).toBeTruthy();
    expect(screen.queryByRole("button", { name: "Move existing files to us-s3" })).toBeNull();
  });
});

describe("the rooms' defaults", () => {
  it("shows what the configuration holds every room to, and where to change it", async () => {
    mockFetch([
      ...NAME_BOOK_ROUTES,
      taskRoute(ROOMS_LIST, {
        items: [],
        ext: {
          "org.openvtc": {
            roomFiles: {
              enabled: true,
              defaults: {
                room: { maxFiles: 10_000, maxBytes: 5_000_000_000, maxFileBytes: 100_000_000 },
                member: { maxFiles: 2_000, maxBytes: 1_000_000_000 },
              },
              maxFileBytes: 1_073_741_824,
              orphanGraceHours: 168,
            },
          },
        },
      }),
      taskRoute("https://trusttasks.org/spec/vtc/policies/list/0.1", { items: [] }),
    ]);
    mount("/rooms");
    const card = (await screen.findByText("Defaults")).closest("section")!;
    expect(within(card).getByText("10,000 files, 5.0 GB in all, 100 MB a file")).toBeTruthy();
    expect(within(card).getByText(/168 hours/)).toBeTruthy();
    expect(within(card).getByText("[rooms.files.member]")).toBeTruthy();
  });

  it("shows no defaults while files are off", async () => {
    mockFetch([
      ...NAME_BOOK_ROUTES,
      taskRoute(ROOMS_LIST, { items: [], ext: { "org.openvtc": { roomFiles: { enabled: false } } } }),
    ]);
    mount("/rooms");
    await screen.findByText("Room files are off");
    await waitFor(() => expect(screen.queryByText("Defaults")).toBeNull());
  });
});
