import { beforeEach, describe, expect, it, vi } from "vitest";

import { postSignedRead } from "./api";
import {
  ROOMS_USAGE_TASK,
  csvCell,
  fetchUsage,
  fillDays,
  formatBytes,
  fullness,
  exactBytes,
  parseBytes,
  parseCount,
  rangeEnding,
  thresholdOf,
  usageCsv,
} from "./rooms-api";
import type { RoomsUsageRow } from "./wire-types";

vi.mock("./api", async (original) => ({
  ...(await original<typeof import("./api")>()),
  postSignedRead: vi.fn(),
}));

const row = (over: Partial<RoomsUsageRow> = {}): RoomsUsageRow => ({
  files: 0,
  bytes: 0,
  reservedBytes: 0,
  uploads: 0,
  downloads: 0,
  egressBytes: 0,
  ...over,
});

beforeEach(() => vi.mocked(postSignedRead).mockReset());

describe("fetchUsage", () => {
  it("re-sends the identical query with each page's cursor", async () => {
    vi.mocked(postSignedRead)
      .mockResolvedValueOnce({
        asOf: "2026-10-14T10:00:00Z",
        from: "2026-09-15",
        to: "2026-10-14",
        items: [row({ roomId: "r1" })],
        nextCursor: "c1",
      })
      .mockResolvedValueOnce({
        asOf: "2026-10-14T10:00:01Z",
        from: "2026-09-15",
        to: "2026-10-14",
        items: [row({ roomId: "r2" })],
      });
    const filter = { from: "2026-09-15", to: "2026-10-14" };
    const sort = { by: "bytes" as const, order: "desc" as const };
    const report = await fetchUsage({ groupBy: "room", filter, sort });

    expect(report.items.map((r) => r.roomId)).toEqual(["r1", "r2"]);
    expect(report.truncated).toBe(false);
    expect(report.asOf).toBe("2026-10-14T10:00:00Z");
    const calls = vi.mocked(postSignedRead).mock.calls;
    expect(calls[0]).toEqual([ROOMS_USAGE_TASK, { groupBy: "room", limit: 100, filter, sort }]);
    expect(calls[1]).toEqual([
      ROOMS_USAGE_TASK,
      { groupBy: "room", limit: 100, filter, sort, cursor: "c1" },
    ]);
  });

  it("stops at the page cap and says so", async () => {
    vi.mocked(postSignedRead).mockResolvedValue({
      asOf: "x",
      from: "a",
      to: "b",
      items: [row()],
      nextCursor: "more",
    });
    const report = await fetchUsage({ groupBy: "day" });
    expect(report.truncated).toBe(true);
    expect(report.items).toHaveLength(10);
  });
});

describe("dates", () => {
  it("a 30-day range ends today and includes it", () => {
    expect(rangeEnding(30, new Date("2026-10-14T23:59:00Z"))).toEqual({
      from: "2026-09-15",
      to: "2026-10-14",
    });
    expect(rangeEnding(1, new Date("2026-10-14T00:00:00Z"))).toEqual({
      from: "2026-10-14",
      to: "2026-10-14",
    });
  });

  it("fills every day, a missing one as null, across a month end", () => {
    const days = fillDays(
      [row({ date: "2026-09-30", bytes: 5 }), row({ date: "2026-10-02", bytes: 7 })],
      "2026-09-30",
      "2026-10-02",
    );
    expect(days.map((d) => [d.date, d.row?.bytes ?? null])).toEqual([
      ["2026-09-30", 5],
      ["2026-10-01", null],
      ["2026-10-02", 7],
    ]);
  });
});

describe("limits", () => {
  it("is the fuller of bytes and files, reserved bytes included", () => {
    expect(
      fullness({ files: 1, bytes: 600, reservedBytes: 200 }, { maxBytes: 1000, maxFiles: 10 }),
    ).toBeCloseTo(0.8);
    expect(fullness({ files: 9, bytes: 0 }, { maxBytes: 1000, maxFiles: 10 })).toBeCloseTo(0.9);
  });

  it("has no fullness without a limit, and is full at a zero limit", () => {
    expect(fullness({ files: 3, bytes: 3 }, undefined)).toBeNull();
    expect(fullness({ files: 3, bytes: 3 }, { maxFileBytes: 10 })).toBeNull();
    expect(fullness({ files: 0, bytes: 0 }, { maxFiles: 0 })).toBe(1);
  });

  it("bands at 80, 95 and 100 percent", () => {
    expect(thresholdOf(null)).toBeNull();
    expect(thresholdOf(0.79)).toBeNull();
    expect(thresholdOf(0.8)).toBe(80);
    expect(thresholdOf(0.95)).toBe(95);
    expect(thresholdOf(1.2)).toBe(100);
  });
});

describe("formatBytes", () => {
  it("picks the unit", () => {
    expect(formatBytes(0)).toBe("0 B");
    expect(formatBytes(999)).toBe("999 B");
    expect(formatBytes(1_500)).toBe("1.5 KB");
    expect(formatBytes(1_200_000_000)).toBe("1.2 GB");
    expect(formatBytes(250_000_000)).toBe("250 MB");
  });
});

describe("parsing what an administrator types", () => {
  it("reads sizes with and without a unit", () => {
    expect(parseBytes("")).toBeUndefined();
    expect(parseBytes(" 1024 ")).toBe(1024);
    expect(parseBytes("500 MB")).toBe(500_000_000);
    expect(parseBytes("1.5gb")).toBe(1_500_000_000);
    expect(parseBytes("1 GiB")).toBe(1_073_741_824);
    expect(parseBytes("0")).toBe(0);
  });

  it("refuses what is not a size", () => {
    expect(parseBytes("-1")).toBeNull();
    expect(parseBytes("5 parsecs")).toBeNull();
    expect(parseBytes("1e9")).toBeNull();
    expect(parseBytes("lots")).toBeNull();
  });

  it("states a size exactly, so a pre-filled form saves it unchanged", () => {
    for (const n of [5_000_000_000, 2 ** 30, 1_572_864, 1536, 999, 0]) {
      expect(parseBytes(exactBytes(n))).toBe(n);
    }
    expect(exactBytes(5_000_000_000)).toBe("5 GB");
    expect(exactBytes(2 ** 30)).toBe("1 GiB");
    expect(exactBytes(1_500_000)).toBe("1500 KB");
    expect(exactBytes(1001)).toBe("1001");
  });

  it("reads whole counts only", () => {
    expect(parseCount("")).toBeUndefined();
    expect(parseCount("12")).toBe(12);
    expect(parseCount("1.5")).toBeNull();
    expect(parseCount("-3")).toBeNull();
  });
});

describe("CSV", () => {
  it("guards a cell a spreadsheet would run as a formula", () => {
    expect(csvCell("=HYPERLINK(\"x\")")).toBe("\"'=HYPERLINK(\"\"x\"\")\"");
    expect(csvCell("+1")).toBe("'+1");
    expect(csvCell("@sum")).toBe("'@sum");
    expect(csvCell("did:key:z6Mk")).toBe("did:key:z6Mk");
    expect(csvCell(-5)).toBe("-5");
    expect(csvCell(undefined)).toBe("");
  });

  it("quotes commas, quotes and line breaks", () => {
    expect(csvCell("a,b")).toBe('"a,b"');
    expect(csvCell("a\nb")).toBe('"a\nb"');
  });

  it("writes a room report with each room's config and limits", () => {
    const csv = usageCsv("room", [
      row({
        roomId: "did:web:rooms.example:a",
        storageConfig: "eu-s3",
        files: 2,
        bytes: 300,
        limits: { maxBytes: 1000 },
      }),
    ]);
    expect(csv).toBe(
      "roomId,storageConfig,files,bytes,reservedBytes,uploads,downloads,egressBytes,maxFiles,maxBytes,maxFileBytes\r\n" +
        "did:web:rooms.example:a,eu-s3,2,300,0,0,0,0,,1000,\r\n",
    );
  });

  it("writes capacity only for a storage-config report", () => {
    const csv = usageCsv("storageConfig", [row({ storageConfig: "local", capacityBytes: 9 })]);
    expect(csv.split("\r\n")[0]).toMatch(/,capacityBytes$/);
    expect(csv.split("\r\n")[1]).toMatch(/,9$/);
    expect(usageCsv("day", []).split("\r\n")[0]).not.toMatch(/capacityBytes|storageConfig/);
  });
});
