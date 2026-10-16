// The portal's data-room pages, against a fake wallet.
//
// The page holds nothing of a room: what it shows comes from the member's
// wallet (`window.vtaWallet.rooms`), and every write goes back through it. What
// is pinned here is what the page asks for and how it reads the answers — the
// community's own DID on every call, an adverse listing shown as a banner and
// never as a shorter list, a file that will not fit refused before the wallet is
// asked, and the portal's server never asked about a room.

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { RoomPage, RoomsPage, downloadName } from "./Rooms";
import { routeOf } from "./Portal";
import { fileWontFit, type RoomInfo, type WalletRooms } from "./wallet-rooms";

const HOST = "did:webvh:QmHost:acme.example";
const ROOM = "did:webvh:QmRoom:rooms.example";
const MEMBER = "did:webvh:QmAlice:people.example";

const INFO: RoomInfo = {
  roomId: ROOM,
  visibility: "attributed",
  epoch: 3,
  member: MEMBER,
  limits: { filesEnabled: true, room: { maxFileBytes: 1_000_000, maxBytes: 10_000_000 } },
  usage: { room: { files: 1, bytes: 2000 }, member: { usage: { files: 1, bytes: 2000 }, limits: { maxBytes: 5_000_000 } } },
};

function fakeWallet(over: Partial<WalletRooms> = {}): WalletRooms & { calls: { method: string; args: unknown }[] } {
  const calls: { method: string; args: unknown }[] = [];
  const rec = (method: string, value: unknown) =>
    vi.fn(async (args: unknown) => {
      calls.push({ method, args });
      return value;
    });
  return Object.assign(
    {
      list: rec("list", { rooms: [] }),
      choose: rec("choose", {
        rooms: [{ roomId: ROOM, held: true, epoch: 3, earliestReadableEpoch: 1, sharedAt: "2026-10-16T00:00:00Z", expiresAt: "2026-11-15T00:00:00Z" }],
        refused: [{ roomId: "did:webvh:QmSecret:rooms.example", reason: "not shared: it is a private room" }],
      }),
      forget: rec("forget", { forgotten: true }),
      info: rec("info", INFO),
      browse: rec("browse", {
        records: [{ key: "k1", version: 2, updatedAt: "2026-10-16T00:00:00Z", author: MEMBER }],
        complete: true,
        verification: { count: "match", priorRoots: "noneHeld", anchor: "none" },
      }),
      read: rec("read", {
        key: "k1",
        version: 2,
        status: "active",
        updatedAt: "2026-10-16T00:00:00Z",
        author: MEMBER,
        title: "Term sheet",
        body: "<img src=x onerror=alert(1)>",
        file: { name: "terms.pdf", size: 1234, mediaType: "application/pdf" },
        sealed: true,
        verification: {},
      }),
      putNote: rec("putNote", { key: "k2", version: 3 }),
      getFile: rec("getFile", { file: { name: "terms.pdf", size: 3 }, author: MEMBER, version: 2, blob: new Blob(["abc"]) }),
      putFile: rec("putFile", { key: "k3", version: 4, size: 3 }),
    },
    over,
    { calls },
  );
}

function renderWith(node: React.ReactNode) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(<QueryClientProvider client={qc}>{node}</QueryClientProvider>);
}

describe("data rooms in the portal", () => {
  let fetchSpy: ReturnType<typeof vi.fn>;
  beforeEach(() => {
    fetchSpy = vi.fn(async () => new Response("{}", { status: 404 }));
    vi.stubGlobal("fetch", fetchSpy);
  });
  afterEach(() => {
    delete (window as { vtaWallet?: unknown }).vtaWallet;
    vi.unstubAllGlobals();
  });

  it("without a wallet, says where rooms live instead of failing", () => {
    renderWith(<RoomsPage hostDid={HOST} />);
    expect(screen.getByText("Your rooms are in your wallet")).toBeTruthy();
  });

  it("lists only what the wallet shares, and sharing goes through the wallet", async () => {
    const wallet = fakeWallet();
    (window as { vtaWallet?: unknown }).vtaWallet = { rooms: wallet };
    renderWith(<RoomsPage hostDid={HOST} />);
    await screen.findByText(/You have not shared any rooms/);
    fireEvent.click(screen.getByRole("button", { name: /Share rooms/ }));
    await screen.findByText(/private room/);
    expect(wallet.calls.map((c) => c.method)).toEqual(["list", "choose"]);
    expect(wallet.calls.every((c) => (c.args as { hostDid: string }).hostDid === HOST)).toBe(true);
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("asks the wallet to share as the member signed in here, and says whom each room is shared as", async () => {
    const wallet = fakeWallet({
      choose: vi.fn(async () => ({
        rooms: [
          {
            roomId: ROOM,
            member: MEMBER,
            held: true,
            epoch: 3,
            earliestReadableEpoch: 3,
            sharedAt: "2026-10-16T00:00:00Z",
            expiresAt: "2026-11-15T00:00:00Z",
          },
        ],
        refused: [],
      })),
    });
    (window as { vtaWallet?: unknown }).vtaWallet = { rooms: wallet };
    renderWith(<RoomsPage hostDid={HOST} member={MEMBER} />);
    await screen.findByText(/You have not shared any rooms/);
    fireEvent.click(screen.getByRole("button", { name: /Share rooms/ }));
    await screen.findByText(/as you/);
    expect(wallet.choose).toHaveBeenCalledWith({ hostDid: HOST, member: MEMBER });
  });

  it("a refusal for a room held as two identities says how to fix it", async () => {
    const wallet = fakeWallet({
      choose: vi.fn(async () => ({
        rooms: [],
        refused: [
          {
            roomId: ROOM,
            reason:
              "the community could not confirm it holds this room: you may act as 2 members of room; " +
              "name the one you mean in the document's `issuer` (rooms/keys/act:principalAmbiguous)",
          },
        ],
      })),
    });
    (window as { vtaWallet?: unknown }).vtaWallet = { rooms: wallet };
    renderWith(<RoomsPage hostDid={HOST} member={MEMBER} />);
    await screen.findByText(/You have not shared any rooms/);
    fireEvent.click(screen.getByRole("button", { name: /Share rooms/ }));
    await screen.findByText(/holds this room as more than one identity/);
    expect(screen.getByText(/tick the room as the identity you signed in here with/)).toBeTruthy();
  });

  it("a community's room is titled by its name, its DID beneath; a member's own room by its DID", async () => {
    const OWN = "did:webvh:QmMine:rooms.example";
    const shared = { held: true, epoch: 3, earliestReadableEpoch: 1, sharedAt: "2026-10-16T00:00:00Z", expiresAt: "2026-11-15T00:00:00Z" };
    const wallet = fakeWallet({
      list: vi.fn(async () => ({
        rooms: [
          { roomId: ROOM, member: MEMBER, label: "Board pack", visibility: "attributed", ...shared },
          { roomId: OWN, member: MEMBER, ...shared },
        ],
      })),
    });
    (window as { vtaWallet?: unknown }).vtaWallet = { rooms: wallet };
    renderWith(<RoomsPage hostDid={HOST} member={MEMBER} />);
    const name = await screen.findByText("Board pack");
    expect(name.closest("a")?.getAttribute("href")).toBe(`#/rooms/${encodeURIComponent(ROOM)}`);
    expect(screen.getByTitle(ROOM)).toBeTruthy();
    expect(screen.getByText("did:webvh:QmMine:rooms.example")).toBeTruthy();
  });

  it("a community room's page is headed by its name, and a wallet without names leaves the DID", async () => {
    const shared = { held: true, sharedAt: "2026-10-16T00:00:00Z", expiresAt: "2026-11-15T00:00:00Z" };
    const named = fakeWallet({ list: vi.fn(async () => ({ rooms: [{ roomId: ROOM, label: "Board pack", ...shared }] })) });
    (window as { vtaWallet?: unknown }).vtaWallet = { rooms: named };
    const { unmount } = renderWith(<RoomPage hostDid={HOST} roomId={ROOM} />);
    expect((await screen.findByRole("heading", { level: 1, name: "Board pack" })).textContent).toBe("Board pack");
    expect(screen.getByTitle(ROOM).textContent).toBe(ROOM);
    unmount();

    const older = fakeWallet({ list: vi.fn(async () => ({ rooms: [{ roomId: ROOM, ...shared }] })) });
    (window as { vtaWallet?: unknown }).vtaWallet = { rooms: older };
    renderWith(<RoomPage hostDid={HOST} roomId={ROOM} />);
    await screen.findByText("Term sheet");
    expect(screen.getByRole("heading", { level: 1 }).textContent).toBe(ROOM);
  });

  // ── Offers ──

  const OFFER = {
    roomId: ROOM,
    member: MEMBER,
    label: "Board pack",
    visibility: "private",
    actions: ["read", "write"],
    validUntil: "2027-10-01T00:00:00Z",
    offeredAt: "2026-10-14T10:00:00Z",
    state: "open" as const,
    inProgress: false,
  };

  it("a wallet without offers support shows no offers card and is never asked", async () => {
    const wallet = fakeWallet();
    (window as { vtaWallet?: unknown }).vtaWallet = { rooms: wallet };
    renderWith(<RoomsPage hostDid={HOST} member={MEMBER} />);
    await screen.findByText(/You have not shared any rooms/);
    expect(screen.queryByText("Offers from this community")).toBeNull();
  });

  it("lists the community's offers through the wallet, and accepting is asked of the wallet as the offer's identity", async () => {
    const wallet = fakeWallet({
      offers: vi.fn(async () => ({ offers: [OFFER, { ...OFFER, roomId: "did:webvh:QmOld:rooms.example", label: "Old", state: "accepted" as const }] })),
      acceptOffer: vi.fn(async () => ({ roomId: ROOM, member: MEMBER, visibility: "private", joined: true, epoch: 2, resumed: false })),
    });
    (window as { vtaWallet?: unknown }).vtaWallet = { rooms: wallet };
    renderWith(<RoomsPage hostDid={HOST} member={MEMBER} />);
    await screen.findByText("Board pack");
    expect(screen.queryByText("Old")).toBeNull();
    expect(screen.getByText(/as you/)).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: /Accept/ }));
    await screen.findByText(/Joined Board pack/);
    expect(wallet.acceptOffer).toHaveBeenCalledWith({ hostDid: HOST, roomId: ROOM, member: MEMBER });

    // Then it can be shared here, pre-ticked in the wallet's window.
    fireEvent.click(screen.getByRole("button", { name: /Share it here/ }));
    await waitFor(() => expect(wallet.choose).toHaveBeenCalledWith({ hostDid: HOST, suggest: ROOM, member: MEMBER }));
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("a member who declines in the wallet sees the offer stays open, not an error", async () => {
    const wallet = fakeWallet({
      offers: vi.fn(async () => ({ offers: [OFFER] })),
      acceptOffer: vi.fn(async () => {
        throw new Error("the member declined the offer here; it stays open");
      }),
    });
    (window as { vtaWallet?: unknown }).vtaWallet = { rooms: wallet };
    renderWith(<RoomsPage hostDid={HOST} member={MEMBER} />);
    await screen.findByText("Board pack");
    fireEvent.click(screen.getByRole("button", { name: /Accept/ }));
    await screen.findByText(/The offer stays open/);
    expect(screen.queryByRole("alert")).toBeNull();
  });

  it("a wallet not yet allowed to reach the community says where to allow it", async () => {
    const wallet = fakeWallet({ offers: vi.fn(async () => ({ offers: [], needsOrigin: "https://acme.example" })), acceptOffer: vi.fn() });
    (window as { vtaWallet?: unknown }).vtaWallet = { rooms: wallet };
    renderWith(<RoomsPage hostDid={HOST} />);
    await screen.findByText(/has not been allowed to reach this community/);
  });

  it("a room shows its records, opens one as text, and never renders a member's words as markup", async () => {
    const wallet = fakeWallet();
    (window as { vtaWallet?: unknown }).vtaWallet = { rooms: wallet };
    renderWith(<RoomPage hostDid={HOST} roomId={ROOM} />);
    await screen.findByText("Term sheet");
    fireEvent.click(screen.getByRole("button", { name: /Term sheet/ }));
    await screen.findByText("<img src=x onerror=alert(1)>");
    expect(document.querySelector("img[src='x']")).toBeNull();
    expect(screen.getByRole("button", { name: /Download/ })).toBeTruthy();
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("a listing the host contradicts is a banner, not a quietly shorter list", async () => {
    const wallet = fakeWallet({
      browse: vi.fn(async () => ({ records: [], complete: true, verification: { count: "short" } })),
    });
    (window as { vtaWallet?: unknown }).vtaWallet = { rooms: wallet };
    renderWith(<RoomPage hostDid={HOST} roomId={ROOM} />);
    await screen.findByText(/withheld from you/);
  });

  it("a note goes to the wallet, which confirms it with the member", async () => {
    const wallet = fakeWallet();
    (window as { vtaWallet?: unknown }).vtaWallet = { rooms: wallet };
    renderWith(<RoomPage hostDid={HOST} roomId={ROOM} />);
    await screen.findByText("Add to this room");
    fireEvent.change(screen.getByLabelText("Title"), { target: { value: "Pricing" } });
    fireEvent.change(screen.getByLabelText("Note"), { target: { value: "Hold." } });
    fireEvent.click(screen.getByRole("button", { name: /Add note/ }));
    await screen.findByText("Note added.");
    await waitFor(() => expect(wallet.calls.find((c) => c.method === "putNote")?.args).toEqual({ hostDid: HOST, roomId: ROOM, title: "Pricing", body: "Hold." }));
  });

  it("a room that does not open says why", async () => {
    const wallet = fakeWallet({ info: vi.fn(async () => { throw new Error("has not been given that room"); }) });
    (window as { vtaWallet?: unknown }).vtaWallet = { rooms: wallet };
    renderWith(<RoomPage hostDid={HOST} roomId={ROOM} />);
    await screen.findByText(/has not been given that room/);
  });
});

describe("what fits", () => {
  it("names the limit that a file breaks, and who can raise it", () => {
    expect(fileWontFit(INFO, 10)).toBeNull();
    expect(fileWontFit(INFO, 2_000_000)).toMatch(/up to 1.0 MB/);
    expect(fileWontFit({ ...INFO, usage: { ...INFO.usage, member: { usage: { files: 1, bytes: 4_999_000 }, limits: { maxBytes: 5_000_000 } } } }, 10_000)).toMatch(/owner can raise/);
    expect(fileWontFit({ ...INFO, visibility: "open" }, 10)).toMatch(/open/);
    expect(fileWontFit({ ...INFO, limits: { ...INFO.limits, filesEnabled: false } }, 10)).toMatch(/does not accept files/);
  });

  it("a file name another member chose cannot choose a path", () => {
    expect(downloadName("../../.bashrc")).toBe("bashrc");
    expect(downloadName("..\\evil.exe")).toBe("evil.exe");
    expect(downloadName("")).toBe("room-file");
  });

  it("routes from the hash", () => {
    expect(routeOf("#/rooms")).toEqual({ page: "rooms" });
    expect(routeOf(`#/rooms/${encodeURIComponent(ROOM)}`)).toEqual({ page: "room", roomId: ROOM });
    expect(routeOf("#/rooms/not-a-did")).toEqual({ page: "home" });
    expect(routeOf("#/rooms/%E0%A4%A")).toEqual({ page: "home" });
    expect(routeOf("")).toEqual({ page: "home" });
  });
});
