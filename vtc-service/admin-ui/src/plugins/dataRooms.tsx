// Data rooms — one page for everything this community does about the rooms it
// hosts, with a tab per part: the rooms themselves, how much they store and
// read back, where their files are kept — and the rooms it owns itself.
//
//   /rooms                      Rooms tab   (`rooms.tsx`)
//   /rooms/usage                Usage tab   (`roomUsage.tsx`)
//   /rooms/storage              Storage tab (`storage.tsx`)
//   /rooms/storage/<configId>   one storage location
//   /rooms/r/<roomId>           one room    (`rooms/RoomDetail.tsx`)
//   /rooms/community            Community rooms tab (`rooms/CommunityRooms.tsx`)
//   /rooms/community/<roomId>   one room the community owns
//                               (`rooms/CommunityRoomDetail.tsx`)
//
// A room's page sits under `r/` because a room's identifier is whatever its
// owner minted — nothing makes it a DID, so a bare `/rooms/<roomId>` could be
// `/rooms/usage`. The bare form, which links made before the tabs still use,
// is redirected to `r/` (`LegacyRoomRedirect`); the old top-level `/storage`
// and `/room-usage` are redirected by the shell (`lib/legacy-routes.ts`).
//
// ## Gating, per tab
//
// Each tab names the capabilities it needs, like a plugin does, and is shown
// only to a viewer holding one of them; a room's page and a storage location's
// page are gated as their tab is. The menu entry is visible to a holder of any
// tab's capability (`DATA_ROOMS_CAPABILITIES`, which `plugins/index.ts`
// registers), so a tab for a different authority — Community rooms, on
// `vtc.rooms.manage` (the owner's authority, not the host's) — is one entry in
// `DATA_ROOMS_TABS` and a route here, and its holders get the menu entry
// without being shown the others. As with the nav, this is a hint: the VTC
// decides every operation.

import type { ComponentType, ReactNode } from "react";
import { Navigate, Outlet, Route, Routes, useLocation } from "react-router-dom";

import { PageHeader } from "@/components/PageHeader";
import { TabLinks } from "@/components/Tabs";
import { holds, useCapabilities } from "@/lib/viewer";

import { RoomsList } from "./rooms";
import { CommunityRoomDetail } from "./rooms/CommunityRoomDetail";
import { CommunityRoomsList, NewCommunityRoomButton } from "./rooms/CommunityRooms";
import { RoomDetail } from "./rooms/RoomDetail";
import { COMMUNITY_PATH, ROOMS_PATH, STORAGE_PATH, USAGE_PATH } from "./rooms/shared";
import { RoomUsage } from "./roomUsage";
import { ConfigDetail, NewStorageButton, StorageList } from "./storage";

export type DataRoomsTabId = "rooms" | "usage" | "storage" | "community";

export interface DataRoomsTab {
  readonly id: DataRoomsTabId;
  readonly label: string;
  /** The tab's route, absolute. */
  readonly path: string;
  /** Shown when the viewer holds **any** of these, at any qualifier — the
   *  same rule as a plugin's `capabilities` (`lib/viewer.ts` `pluginVisible`). */
  readonly capabilities: readonly string[];
  /** The page header's lead while this tab is open. */
  readonly lead: ReactNode;
  /** The page header's primary action while this tab is open. */
  readonly actions?: ComponentType;
  readonly body: ComponentType;
}

/** The tabs, in the order they are shown. The first the viewer may see is the
 *  one `/rooms` opens on. */
export const DATA_ROOMS_TABS: readonly DataRoomsTab[] = [
  {
    id: "rooms",
    label: "Rooms",
    path: ROOMS_PATH,
    // The host's authority over rooms (`vtc/rooms/*` admin reads), never a room's.
    capabilities: ["vtc.rooms.admin"],
    lead: (
      <>
        Rooms this community stores. It cannot read their records and holds no member
        list — both by construction — so this is the row and nothing derived from a
        room&rsquo;s contents. The owner is shown at every tier, including private,
        because they are the party a quota or reclamation notice has to reach.
      </>
    ),
    body: RoomsList,
  },
  {
    id: "usage",
    label: "Usage",
    path: USAGE_PATH,
    capabilities: ["vtc.rooms.admin"],
    lead: "How much this community stores for its rooms and how much is read back. Sizes and counts only: it cannot read the rooms' records or file names.",
    body: RoomUsage,
  },
  {
    id: "storage",
    label: "Storage",
    path: STORAGE_PATH,
    capabilities: ["vtc.rooms.admin"],
    lead: "Where this community keeps its rooms' files. Each room's new uploads go to one storage location; every file remembers where it was written, so moving a room strands nothing.",
    actions: NewStorageButton,
    body: StorageList,
  },
  {
    id: "community",
    label: "Community rooms",
    path: COMMUNITY_PATH,
    // The owner's authority over the rooms the community itself owns.
    capabilities: ["vtc.rooms.manage"],
    lead: "Rooms this community owns — the board's papers, a working group's drafts, a members' library — run by its administrators and outliving any of them. The community's VTA holds each room's keys; you decide who is offered a place.",
    actions: NewCommunityRoomButton,
    body: CommunityRoomsList,
  },
];

/** What the Data rooms menu entry is gated on: any tab's capabilities. */
export const DATA_ROOMS_CAPABILITIES: readonly string[] = [
  ...new Set(DATA_ROOMS_TABS.flatMap((t) => t.capabilities)),
];

function tabOf(id: DataRoomsTabId): DataRoomsTab {
  return DATA_ROOMS_TABS.find((t) => t.id === id)!;
}

/** Whether `caps` shows `tab`. */
export function tabVisible(caps: ReadonlyArray<string>, tab: DataRoomsTab): boolean {
  return tab.capabilities.some((c) => holds(caps, c, "*"));
}

function useVisibleTabs(): DataRoomsTab[] {
  const caps = useCapabilities();
  return DATA_ROOMS_TABS.filter((t) => tabVisible(caps, t));
}

export function DataRooms() {
  return (
    <Routes>
      <Route element={<TabbedPage />}>
        <Route index element={<TabBody id="rooms" />} />
        <Route path="usage" element={<TabBody id="usage" />} />
        <Route path="storage" element={<TabBody id="storage" />} />
        <Route path="community" element={<TabBody id="community" />} />
      </Route>
      <Route
        path="community/:roomId"
        element={
          <Gated id="community">
            <CommunityRoomDetail />
          </Gated>
        }
      />
      <Route
        path="storage/:configId"
        element={
          <Gated id="storage">
            <ConfigDetail />
          </Gated>
        }
      />
      <Route path="r" element={<Navigate to={ROOMS_PATH} replace />} />
      <Route
        path="r/:roomId"
        element={
          <Gated id="rooms">
            <RoomDetail />
          </Gated>
        }
      />
      <Route path=":roomId" element={<LegacyRoomRedirect />} />
      <Route path="*" element={<Navigate to={ROOMS_PATH} replace />} />
    </Routes>
  );
}

/** Which tab the location is on. */
function currentTab(pathname: string): DataRoomsTab {
  if (pathname === USAGE_PATH) return tabOf("usage");
  if (pathname === STORAGE_PATH) return tabOf("storage");
  if (pathname === COMMUNITY_PATH) return tabOf("community");
  return tabOf("rooms");
}

/** The page header and the tab strip, around the open tab. */
function TabbedPage() {
  const { pathname } = useLocation();
  const visible = useVisibleTabs();
  const tab = currentTab(pathname.replace(/\/+$/, ""));
  const shown = visible.some((t) => t.id === tab.id);
  const Actions = shown ? tab.actions : undefined;
  return (
    <section className="page">
      <PageHeader lead={shown ? tab.lead : undefined} actions={Actions && <Actions />} />
      {visible.length > 1 && (
        <TabLinks
          label="Data rooms sections"
          items={visible.map((t) => ({
            id: t.id,
            label: t.label,
            to: t.path,
            end: t.path === ROOMS_PATH,
          }))}
        />
      )}
      <Outlet />
    </section>
  );
}

/** A tab's content, or — for a viewer who cannot see it — the first tab they
 *  can, or a word on what it needs. */
function TabBody({ id }: { id: DataRoomsTabId }) {
  const visible = useVisibleTabs();
  const tab = tabOf(id);
  if (visible.some((t) => t.id === id)) {
    const Body = tab.body;
    return <Body />;
  }
  if (id === "rooms" && visible[0]) return <Navigate to={visible[0].path} replace />;
  return <NotHeld tab={tab} />;
}

/** A sub-page gated as its tab is. */
function Gated({ id, children }: { id: DataRoomsTabId; children: ReactNode }) {
  const caps = useCapabilities();
  const tab = tabOf(id);
  if (tabVisible(caps, tab)) return <>{children}</>;
  return (
    <section className="page">
      <PageHeader />
      <NotHeld tab={tab} />
    </section>
  );
}

function NotHeld({ tab }: { tab: DataRoomsTab }) {
  return (
    <section className="card">
      <p className="muted">
        {tab.label} needs {tab.capabilities.map((c) => <code key={c}>{c}</code>)}, which
        your access-control entry does not hold.
      </p>
    </section>
  );
}

/**
 * `/rooms/<roomId>`, as room links were before the tabs, to `/rooms/r/<roomId>`.
 * Taken from the location, still encoded, rather than from the decoded param:
 * re-encoding a decoded identifier could change it (a `did:web` port's `%3A`).
 */
function LegacyRoomRedirect() {
  const { pathname, search, hash } = useLocation();
  const segment = pathname.slice(ROOMS_PATH.length + 1);
  return <Navigate to={`${ROOMS_PATH}/r/${segment}${search}${hash}`} replace />;
}
