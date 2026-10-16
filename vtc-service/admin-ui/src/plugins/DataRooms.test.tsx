import { render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter, Route, Routes, useLocation } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";

import { LegacyRedirect } from "@/components/LegacyRedirect";
import { getPlugins } from "@/plugin-api";
import { registerBuiltinPlugins } from "@/plugins";
import { DATA_ROOMS_CAPABILITIES, DATA_ROOMS_TABS, DataRooms } from "@/plugins/dataRooms";
import {
  NAME_BOOK_ROUTES,
  mockFetch,
  renderWithProviders,
  sentPayloads,
  taskRoute,
  whoamiWith,
} from "@/test/render";

vi.mock("@/lib/api", async (original) => ({
  ...(await original<typeof import("@/lib/api")>()),
  postSignedRead: (await import("@/test/signed-read")).unsignedRead,
  postSignedTrustTask: (await import("@/test/signed-read")).unsignedTask,
}));

const T = "https://trusttasks.org/spec";
const ROOMS_LIST = `${T}/vtc/rooms/list/0.1`;
const ROOMS_GET = `${T}/vtc/rooms/get/0.1`;
const USAGE = `${T}/vtc/rooms/usage/0.1`;
const STORAGE_LIST = `${T}/vtc/storage/configs/list/0.1`;

/** A did:web with a port: its `%3A` must survive every redirect. */
const ROOM_ID = "did:web:rooms.example.com%3A8443:board";

const ROOMS_ADMIN = whoamiWith(["vtc.rooms.admin"]);

/** Where the router ended up. */
function Where() {
  const { pathname, search } = useLocation();
  return <output data-testid="where">{`${pathname}${search}`}</output>;
}

const where = () => screen.getByTestId("where").textContent;

const mount = (route: string, whoami = ROOMS_ADMIN) =>
  renderWithProviders(
    <>
      <DataRooms />
      <Where />
    </>,
    { route, path: "/rooms/*", whoami },
  );

const routes = () => [
  ...NAME_BOOK_ROUTES,
  taskRoute(ROOMS_LIST, { items: [] }),
  taskRoute(USAGE, { asOf: "2026-10-14T10:00:00Z", from: "2026-09-15", to: "2026-10-14", items: [] }),
  taskRoute(STORAGE_LIST, { items: [] }),
  taskRoute(ROOMS_GET, { code: "vtc/rooms/get:notFound", message: "no such room" }, 404),
];

describe("Data rooms — one menu entry, three tabs", () => {
  it("registers a single Data rooms entry, gated on what its tabs need", () => {
    registerBuiltinPlugins();
    const all = getPlugins();
    expect(all.filter((p) => ["storage", "room-usage"].includes(p.id))).toEqual([]);
    const rooms = all.find((p) => p.id === "rooms")!;
    expect(rooms.label).toBe("Data rooms");
    expect(rooms.path).toBe("/rooms");
    expect(rooms.capabilities).toEqual(DATA_ROOMS_CAPABILITIES);
    expect(DATA_ROOMS_CAPABILITIES).toEqual(["vtc.rooms.admin"]);
    expect(DATA_ROOMS_TABS.map((t) => t.label)).toEqual(["Rooms", "Usage", "Storage"]);
  });

  it("shows the tabs as links, the open one current", async () => {
    mockFetch(routes());
    mount("/rooms/usage");
    const nav = screen.getByRole("navigation", { name: "Data rooms sections" });
    const links = [...nav.querySelectorAll("a")];
    expect(links.map((a) => [a.textContent, a.getAttribute("href")])).toEqual([
      ["Rooms", "/rooms"],
      ["Usage", "/rooms/usage"],
      ["Storage", "/rooms/storage"],
    ]);
    expect(links[1]!.getAttribute("aria-current")).toBe("page");
    expect(links[0]!.getAttribute("aria-current")).toBeNull();
    expect(await screen.findByText("Nothing stored and nothing read in this range.")).toBeTruthy();
  });

  it("puts the Storage tab's New storage in the page header", async () => {
    mockFetch(routes());
    mount("/rooms/storage");
    expect(await screen.findByText("No storage yet")).toBeTruthy();
    expect(screen.getByRole("button", { name: "New storage" })).toBeTruthy();
  });

  it("opens a room under r/, so a room called usage is a room and not the tab", async () => {
    const requests = mockFetch(routes());
    mount("/rooms/r/usage");
    expect(await screen.findByText("This community hosts no room with that identifier.")).toBeTruthy();
    expect(sentPayloads(requests, ROOMS_GET)).toEqual([{ roomId: "usage" }]);
    expect(screen.queryByRole("navigation", { name: "Data rooms sections" })).toBeNull();
  });

  it("redirects a room link from before the tabs, keeping its identifier as encoded", async () => {
    const requests = mockFetch(routes());
    const enc = encodeURIComponent(ROOM_ID);
    mount(`/rooms/${enc}`);
    await waitFor(() => expect(where()).toBe(`/rooms/r/${enc}`));
    await waitFor(() => expect(sentPayloads(requests, ROOMS_GET)).toEqual([{ roomId: ROOM_ID }]));
  });

  it("offers a viewer without vtc.rooms.admin no tab and reads nothing", async () => {
    const requests = mockFetch(routes());
    mount("/rooms", whoamiWith(["vtc.members.manage"]));
    expect(await screen.findByText(/which your access-control entry does not hold/)).toBeTruthy();
    expect(screen.queryByRole("navigation", { name: "Data rooms sections" })).toBeNull();
    expect(sentPayloads(requests, ROOMS_LIST)).toEqual([]);
  });

  it("gates a room's page as its tab is", async () => {
    const requests = mockFetch(routes());
    mount(`/rooms/r/${encodeURIComponent(ROOM_ID)}`, whoamiWith([]));
    expect(await screen.findByText(/which your access-control entry does not hold/)).toBeTruthy();
    expect(sentPayloads(requests, ROOMS_GET)).toEqual([]);
  });
});

describe("the old Storage and Room usage routes", () => {
  const follow = (route: string) =>
    render(
      <MemoryRouter initialEntries={[route]}>
        <Routes>
          <Route path="/storage/*" element={<LegacyRedirect />} />
          <Route path="/room-usage/*" element={<LegacyRedirect />} />
          <Route path="*" element={<Where />} />
        </Routes>
      </MemoryRouter>,
    );

  it.each([
    ["/storage", "/rooms/storage"],
    ["/storage?create=1", "/rooms/storage?create=1"],
    ["/storage/eu-s3", "/rooms/storage/eu-s3"],
    ["/room-usage", "/rooms/usage"],
  ])("sends %s to %s", (from, to) => {
    follow(from);
    expect(where()).toBe(to);
  });
});
