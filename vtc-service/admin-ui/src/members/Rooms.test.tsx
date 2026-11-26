// The portal's data-room pages, against a fake wallet.
//
// The page holds nothing of a room: what it shows comes from the member's
// wallet (`window.vtaWallet.rooms`), and every write goes back through it. What
// is pinned here is what the page asks for and how it reads the answers — the
// community's own DID on every call, an adverse listing shown as a banner and
// never as a shorter list, a file that will not fit refused before the wallet is
// asked, and the portal's server never asked about a room.

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { ConfirmDialogProvider } from "@/components/ConfirmDialog";
import { act, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// The directory, asked who a room's authors are: by default it shows nobody
// (no portal key), as in a session that never signed in with the wallet.
const directory = vi.hoisted(() => ({ send: vi.fn() }));
vi.mock("./directory-api", async (actual) => {
  const real = await actual<typeof import("./directory-api")>();
  return {
    ...real,
    send: directory.send,
    // The module's own reads call its internal `send`: route the picture read through the mock too.
    getImage: (entryId: string, field: string, sha256: string) =>
      directory.send("https://trusttasks.org/spec/vtc/directory/images/get/0.1", { entryId, field, sha256 }),
  };
});

import { DirectoryError } from "./directory-api";
import { RoomPage, RoomsPage, downloadName } from "./Rooms";
import { routeOf } from "./Portal";
import { fileWontFit, type RoomInfo, type RoomWatchEvent, type WalletRooms } from "./wallet-rooms";

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
  return render(<QueryClientProvider client={qc}><ConfirmDialogProvider look="portal">{node}</ConfirmDialogProvider></QueryClientProvider>);
}

describe("data rooms in the portal", () => {
  let fetchSpy: ReturnType<typeof vi.fn>;
  beforeEach(() => {
    fetchSpy = vi.fn(async () => new Response("{}", { status: 404 }));
    vi.stubGlobal("fetch", fetchSpy);
    directory.send.mockReset();
    directory.send.mockRejectedValue(new DirectoryError("noKey", "no key"));
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

  it("an open room is shown as open, never as an epoch it does not have", async () => {
    const shared = { sharedAt: "2026-10-16T00:00:00Z", expiresAt: "2026-11-15T00:00:00Z" };
    const wallet = fakeWallet({
      list: vi.fn(async () => ({
        rooms: [{ roomId: ROOM, label: "Public Data Room", visibility: "open", held: true, member: MEMBER, ...shared }],
      })),
    });
    (window as { vtaWallet?: unknown }).vtaWallet = { rooms: wallet };
    const { unmount } = renderWith(<RoomsPage hostDid={HOST} member={MEMBER} />);
    expect(await screen.findByText(/open room · as you/)).toBeTruthy();
    expect(screen.queryByText(/epoch/)).toBeNull();
    unmount();

    // Left: no keys to blame.
    const left = fakeWallet({
      list: vi.fn(async () => ({
        rooms: [{ roomId: ROOM, label: "Public Data Room", visibility: "open", held: false, member: MEMBER, ...shared }],
      })),
    });
    (window as { vtaWallet?: unknown }).vtaWallet = { rooms: left };
    renderWith(<RoomsPage hostDid={HOST} member={MEMBER} />);
    expect(await screen.findByText(/you are no longer in this room/)).toBeTruthy();
    expect(screen.queryByText(/keys/)).toBeNull();
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
    state: "offered" as const,
  };

  it("a wallet without offers support shows no offers card and is never asked", async () => {
    const wallet = fakeWallet();
    (window as { vtaWallet?: unknown }).vtaWallet = { rooms: wallet };
    renderWith(<RoomsPage hostDid={HOST} member={MEMBER} />);
    await screen.findByText(/You have not shared any rooms/);
    expect(screen.queryByText("Rooms from this community")).toBeNull();
  });

  it("lists the community's offers through the wallet, and accepting is asked of the wallet as the offer's identity", async () => {
    const wallet = fakeWallet({
      offers: vi.fn(async () => ({ offers: [OFFER, { ...OFFER, roomId: "did:webvh:QmOld:rooms.example", label: "Old", state: "joined" as const }] })),
      acceptOffer: vi.fn(async () => ({ roomId: ROOM, member: MEMBER, visibility: "private", joined: true, epoch: 2, resumed: false })),
    });
    (window as { vtaWallet?: unknown }).vtaWallet = { rooms: wallet };
    renderWith(<RoomsPage hostDid={HOST} member={MEMBER} />);
    await screen.findByText("Board pack");
    // A room joined anywhere is listed as joined — the same as the member's other surfaces show it.
    expect(screen.getByText("Old")).toBeTruthy();
    expect(screen.getByText(/as you · joined/)).toBeTruthy();
    expect(screen.getAllByRole("button", { name: /Accept/ })).toHaveLength(1);
    fireEvent.click(screen.getByRole("button", { name: /Accept/ }));
    await screen.findByText(/Joined Board pack/);
    expect(wallet.acceptOffer).toHaveBeenCalledWith({ hostDid: HOST, roomId: ROOM, member: MEMBER });

    // Then it opens here: shared through the wallet's window, pre-ticked, and then shown.
    const notice = screen.getByRole("status");
    expect(notice.className).toContain("alert-info");
    fireEvent.click(within(notice).getByRole("button", { name: /Open it here/ }));
    await waitFor(() => expect(wallet.choose).toHaveBeenCalledWith({ hostDid: HOST, suggest: ROOM, member: MEMBER }));
    await waitFor(() => expect(window.location.hash).toBe(`#/rooms/${encodeURIComponent(ROOM)}`));
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("a joined room already shared here opens directly, and the acceptance notice gives way to its row", async () => {
    let state: "offered" | "joined" = "offered";
    const wallet = fakeWallet({
      list: vi.fn(async () => ({
        rooms: [{ roomId: ROOM, held: true, epoch: 3, earliestReadableEpoch: 1, sharedAt: "2026-10-16T00:00:00Z", expiresAt: "2026-11-15T00:00:00Z" }],
      })),
      offers: vi.fn(async () => ({ offers: [{ ...OFFER, state }] })),
      acceptOffer: vi.fn(async () => {
        state = "joined";
        return { roomId: ROOM, member: MEMBER, visibility: "private", joined: true, epoch: 2, resumed: false };
      }),
    });
    (window as { vtaWallet?: unknown }).vtaWallet = { rooms: wallet };
    renderWith(<RoomsPage hostDid={HOST} member={MEMBER} />);
    fireEvent.click(await screen.findByRole("button", { name: /Accept/ }));
    await screen.findByText(/as you · joined/);
    // One way to open it, not two: no notice repeating the row.
    expect(screen.queryByText(/Joined Board pack/)).toBeNull();
    const open = screen.getByRole("link", { name: "Open" });
    expect(open.getAttribute("href")).toBe(`#/rooms/${encodeURIComponent(ROOM)}`);
    expect(screen.queryByRole("button", { name: /Open it here|Share it here/ })).toBeNull();
    expect(wallet.choose).not.toHaveBeenCalled();
  });

  it("a record its agent cannot open says why, in a member's words, beside the agent's", async () => {
    const wallet = fakeWallet({
      read: vi.fn(async () => {
        throw new Error(
          "rooms/keys/read:cannotOpen: record is sealed under epoch 3 and this VTA holds the room at epoch 2; a commit has not been delivered",
        );
      }),
    });
    (window as { vtaWallet?: unknown }).vtaWallet = { rooms: wallet };
    renderWith(<RoomPage hostDid={HOST} roomId={ROOM} />);
    const title = await screen.findByText("Waiting for a room update");
    expect(screen.queryByText("Did not open")).toBeNull();
    fireEvent.click(title.closest("button")!);
    await screen.findByText(/does not have that change yet/);
    expect(screen.getByText(/a commit has not been delivered/)).toBeTruthy();
    expect(screen.queryByRole("alert")).toBeNull();
  });

  it("shows what an offered room is for, as text and never as markup", async () => {
    const wallet = fakeWallet({
      offers: vi.fn(async () => ({
        offers: [
          { ...OFFER, description: "Papers for the board <img src=x onerror=alert(1)>" },
          { ...OFFER, roomId: "did:webvh:QmBare:rooms.example", label: "No words" },
        ],
      })),
      acceptOffer: vi.fn(),
    });
    (window as { vtaWallet?: unknown }).vtaWallet = { rooms: wallet };
    renderWith(<RoomsPage hostDid={HOST} member={MEMBER} />);
    await screen.findByText("Papers for the board <img src=x onerror=alert(1)>");
    expect(document.querySelector("img[src='x']")).toBeNull();
    expect(screen.getByText("No words")).toBeTruthy();
  });

  it("an acceptance begun anywhere is finished here; one too old to finish says who can help", async () => {
    const wallet = fakeWallet({
      offers: vi.fn(async () => ({
        offers: [
          { ...OFFER, state: "unfinished" as const, repeatAcceptUntil: "2026-10-24T10:00:00Z" },
          { ...OFFER, roomId: "did:webvh:QmStale:rooms.example", label: "Stale", state: "needsReadmission" as const },
        ],
      })),
      acceptOffer: vi.fn(async () => ({ roomId: ROOM, member: MEMBER, visibility: "private", joined: true, resumed: true })),
    });
    (window as { vtaWallet?: unknown }).vtaWallet = { rooms: wallet };
    renderWith(<RoomsPage hostDid={HOST} member={MEMBER} />);
    await screen.findByText("Board pack");
    expect(screen.getByText(/accepted, not finished/)).toBeTruthy();
    expect(screen.getByText(/needs re-admission/)).toBeTruthy();
    expect(screen.getByText(/re-admit you/)).toBeTruthy();
    expect(screen.getAllByRole("button", { name: /Finish accepting|Accept/ })).toHaveLength(1);
    fireEvent.click(screen.getByRole("button", { name: /Finish accepting/ }));
    await screen.findByText(/Joined Board pack/);
  });

  it("a room the community archived, closed or is removing says so, in a member's words", async () => {
    const wallet = fakeWallet({
      offers: vi.fn(async () => ({
        offers: [
          { ...OFFER, state: "joined" as const, roomState: "archived" as const, roomAccess: "readOnly" as const },
          {
            ...OFFER,
            roomId: "did:webvh:QmClosed:rooms.example",
            label: "Closed",
            state: "suspended" as const,
            roomState: "archived" as const,
            roomAccess: "noAccess" as const,
          },
          {
            ...OFFER,
            roomId: "did:webvh:QmGoing:rooms.example",
            label: "Going",
            state: "suspended" as const,
            roomState: "removalScheduled" as const,
            roomAccess: "noAccess" as const,
            purgeAt: "2099-01-01T00:00:00Z",
          },
          // A wallet reading memberships/list 0.1 says nothing of the room's state.
          { ...OFFER, roomId: "did:webvh:QmPlain:rooms.example", label: "Plain", state: "joined" as const },
        ],
      })),
      acceptOffer: vi.fn(),
    });
    (window as { vtaWallet?: unknown }).vtaWallet = { rooms: wallet };
    renderWith(<RoomsPage hostDid={HOST} member={MEMBER} />);
    await screen.findByText("Closed");
    expect(screen.getByText(/joined · read-only/)).toBeTruthy();
    expect(screen.getByText(/you can still read it, but nothing new can be added/)).toBeTruthy();
    expect(screen.getAllByText(/closed for now/).length).toBeGreaterThan(0);
    expect(screen.getByText(/You are restored if it reopens/)).toBeTruthy();
    expect(screen.getByText(/removal scheduled/)).toBeTruthy();
    expect(screen.getByText(/deleted on that date unless the removal is cancelled/)).toBeTruthy();
    // No accept for any of them.
    expect(screen.queryByRole("button", { name: /Accept/ })).toBeNull();
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

  // A room used for chat is shown as the conversation the wallet assembled by
  // the reading rules — the same reading Keyring and the wallet's console show.
  const ALBERTO = "did:webvh:QmAlberto:people.example:alberto";
  const CHAT = {
    records: [
      {
        key: "m1", version: 1, shown: "message" as const, author: ALBERTO, body: "Hi",
        written: { at: "2026-11-17T22:54:00Z" }, orderAt: "2026-11-17T22:54:00Z", orderedBy: "writtenAt" as const,
        reactions: [{ value: "👍", count: 1, authors: [MEMBER] }],
      },
      {
        key: "m2", version: 2, shown: "message" as const, author: MEMBER, body: "<b>Test</b> message",
        replyTo: { key: "m1", available: true },
        written: { at: "2026-11-24T17:18:00Z" }, orderAt: "2026-11-24T17:18:00Z", orderedBy: "writtenAt" as const,
        reactions: [],
      },
      {
        key: "k1", version: 3, shown: "note" as const, author: MEMBER, title: "test1", body: "a note",
        written: { at: "2026-11-24T17:19:00Z" }, orderAt: "2026-11-24T17:19:00Z", orderedBy: "writtenAt" as const,
        reactions: [],
      },
      {
        key: "gone", version: 4, shown: "withdrawn" as const,
        written: {}, orderAt: "2026-11-24T17:20:00Z", orderedBy: "createdAt" as const, reactions: [],
      },
    ],
    names: { [ALBERTO]: "Alberto Leon" },
    complete: true,
    verification: { count: "match" },
  };

  it("a room used for chat reads as a chat: who said what, under their own names, notes as small cards", async () => {
    const wallet = fakeWallet({ conversation: vi.fn(async () => CHAT) });
    (window as { vtaWallet?: unknown }).vtaWallet = { rooms: wallet };
    renderWith(<RoomPage hostDid={HOST} roomId={ROOM} />);
    await screen.findByRole("list", { name: "Messages" });
    // The chat is the page: the room is its heading, and there is no records list.
    expect(screen.getByRole("heading", { level: 1 })).toBeTruthy();
    expect(screen.queryByRole("heading", { name: "Records" })).toBeNull();
    expect(screen.queryByText("Add to this room")).toBeNull();
    // Another member by the name they gave themselves, said to be theirs; the member as You.
    expect(screen.getAllByText("Alberto Leon").length).toBeGreaterThan(0);
    expect(screen.getByText("(their own name)")).toBeTruthy();
    expect(screen.getByText("You")).toBeTruthy();
    expect(screen.getByText("Hi")).toBeTruthy();
    expect(screen.getByText("👍 1")).toBeTruthy();
    expect(screen.getByText("Alberto Leon: Hi")).toBeTruthy();
    // A member's words are text, never markup.
    expect(screen.getByText("<b>Test</b> message")).toBeTruthy();
    expect(screen.getByText("Message withdrawn by its author")).toBeTruthy();
    // No message is read one by one: the wallet assembled the room.
    expect(wallet.calls.map((c) => c.method)).not.toContain("browse");
    // A note opens in the drawer beside the conversation, read through the wallet.
    fireEvent.click(screen.getByRole("button", { name: "Open" }));
    const drawer = await screen.findByRole("complementary", { name: "Opened record" });
    await within(drawer).findByRole("heading", { name: "Term sheet" });
    expect(wallet.calls.some((c) => c.method === "read" && (c.args as { key: string }).key === "k1")).toBe(true);
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  // Authors the room gives no name: the directory's name where it shows one, else the DID, marked.
  const CAROL = "did:webvh:QmCarol:people.example:airport-electric";
  const DAVE = "did:webvh:QmDave:people.example:tiger-phrase";
  const UNNAMED = {
    ...CHAT,
    records: [
      { ...CHAT.records[0]!, key: "c1", author: CAROL, body: "Hey", reactions: [{ value: "👍", count: 1, authors: [DAVE] }] },
      { ...CHAT.records[0]!, key: "d1", author: DAVE, body: "Hello", reactions: [] },
      { ...CHAT.records[0]!, key: "a1", author: ALBERTO, body: "Hi all", reactions: [] },
    ],
  };
  const QUERY = "https://trusttasks.org/spec/vtc/directory/query/0.2";
  const QUERY_V1 = "https://trusttasks.org/spec/vtc/directory/query/0.1";
  const IMAGES_GET = "https://trusttasks.org/spec/vtc/directory/images/get/0.1";
  const WALL = "https://trusttasks.org/spec/vtc/badges/wall/show/0.1";

  it("an author the room gives no name is named as the directory shows them, else by a DID marked as one", async () => {
    directory.send.mockImplementation(async (type: string, p: { subject: string }) => {
      if (type === QUERY && p.subject === CAROL) {
        return { subject: CAROL, fields: { displayName: "Carol Chen", pronouns: "she/her", role: "member" } };
      }
      throw new DirectoryError("notFound", "no directory entry for that DID is visible to this caller");
    });
    const wallet = fakeWallet({ conversation: vi.fn(async () => UNNAMED) });
    (window as { vtaWallet?: unknown }).vtaWallet = { rooms: wallet };
    renderWith(<RoomPage hostDid={HOST} roomId={ROOM} />);
    const carol = await screen.findByRole("button", { name: "Carol Chen" });
    // The DID the directory shows no name for stays a DID, and says so.
    const dave = screen.getByRole("button", { name: /tiger-phrase/ });
    expect(within(dave).getByText("DID")).toBeTruthy();
    // The room's own name comes first: the directory is not asked about Alberto.
    expect(screen.getByRole("button", { name: "Alberto Leon" })).toBeTruthy();
    const asked = directory.send.mock.calls.map((c) => (c[1] as { subject: string }).subject).sort();
    // The member's own DID too, for "you post as": their own card is theirs to read.
    expect(asked).toEqual([CAROL, DAVE, MEMBER].sort());
    expect(directory.send.mock.calls.every((c) => c[0] === QUERY)).toBe(true);
    // Hovering opens the member's card.
    fireEvent.mouseEnter(carol.parentElement!);
    const card = screen.getByRole("group", { name: "About Carol Chen" });
    expect(within(card).getByText("she/her")).toBeTruthy();
    expect(within(card).getByText("Role: member")).toBeTruthy();
    expect(within(card).getByText(CAROL)).toBeTruthy();
    expect(within(card).getByRole("button", { name: "Copy DID" })).toBeTruthy();
    expect(within(card).queryByText(/As the community's directory shows them/)).toBeNull();
    fireEvent.mouseLeave(carol.parentElement!);
    expect(screen.queryByRole("group", { name: "About Carol Chen" })).toBeNull();
    // A DID's card says the directory showed nothing, and gives the whole DID.
    fireEvent.click(dave);
    const daveCard = screen.getByRole("group", { name: /About/ });
    expect(within(daveCard).getByText(/shows you no card/)).toBeTruthy();
    expect(within(daveCard).getByText(DAVE)).toBeTruthy();
  });

  it("a member's card shows their picture, read by the entry the directory names, their bio and badges, and opens their full card", async () => {
    const bytes = new TextEncoder().encode("a picture");
    const digest = await crypto.subtle.digest("SHA-256", bytes);
    const sha256 = Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, "0")).join("");
    const data = btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    const ENTRY = "dir_carolcarolcarol01";
    directory.send.mockImplementation(async (type: string, p: Record<string, unknown>) => {
      if (type === QUERY && p.subject === CAROL) {
        return {
          subject: CAROL,
          entryId: ENTRY,
          fields: {
            displayName: "Carol Chen",
            bio: "Runs the <b>board</b> papers and the members' library. " + "x".repeat(200),
            avatar: { sha256, mediaType: "image/png" },
          },
        };
      }
      if (type === IMAGES_GET && p.entryId === ENTRY && p.field === "avatar" && p.sha256 === sha256) {
        return { data, image: { sha256, mediaType: "image/png" } };
      }
      if (type === WALL && p.entryId === ENTRY) {
        return {
          entries: [
            { badge: { badgeId: "b1", name: "Bug Hunter" }, count: 1, pinned: true, since: "2026-11-17T00:00:00Z" },
            { badge: { badgeId: "b2", name: "Helping Hand" }, count: 2, pinned: false, since: "2026-11-17T00:00:00Z" },
          ],
          visibility: "members",
        };
      }
      throw new DirectoryError("notFound", "no directory entry for that DID is visible to this caller");
    });
    const wallet = fakeWallet({ conversation: vi.fn(async () => UNNAMED) });
    (window as { vtaWallet?: unknown }).vtaWallet = { rooms: wallet };
    renderWith(<RoomPage hostDid={HOST} roomId={ROOM} />);
    const carol = await screen.findByRole("button", { name: "Carol Chen" });
    // The chat's avatar is her picture, digest-checked, read through the projection by her entry.
    await waitFor(() => expect(document.querySelector(`img.chat-avatar-face[src^="data:image/png"]`)).not.toBeNull());
    expect(directory.send.mock.calls.some((c) => c[0] === IMAGES_GET && (c[1] as { entryId: string }).entryId === ENTRY)).toBe(true);
    fireEvent.click(carol);
    const card = screen.getByRole("group", { name: "About Carol Chen" });
    // Her bio is text, never markup, and cut short.
    expect(within(card).getByText(/^Runs the <b>board<\/b> papers/).textContent!.endsWith("…")).toBe(true);
    expect(card.querySelector("b b")).toBeNull();
    // Her badges, read only once the card opened.
    expect(await within(card).findByText("Bug Hunter")).toBeTruthy();
    expect(within(card).getByText("Helping Hand ×2")).toBeTruthy();
    expect(within(card).getByRole("link", { name: /Open card/ }).getAttribute("href")).toBe(`#/directory/${ENTRY}`);
    fireEvent.click(carol);
    // Dave, whom the directory does not show, keeps a figure and no link.
    fireEvent.click(screen.getByRole("button", { name: /tiger-phrase/ }));
    const daveCard = screen.getByRole("group", { name: /About .*tiger-phrase/ });
    expect(within(daveCard).queryByRole("link", { name: /Open card/ })).toBeNull();
  });

  it("a community older than query 0.2 is asked at 0.1, and its card has no picture or link", async () => {
    directory.send.mockImplementation(async (type: string, p: Record<string, unknown>) => {
      if (type === QUERY) throw new DirectoryError("unsupportedType", "not served");
      if (type === QUERY_V1 && p.subject === CAROL) {
        return { subject: CAROL, fields: { displayName: "Carol Chen", avatar: { sha256: "0".repeat(64), mediaType: "image/png" } } };
      }
      throw new DirectoryError("notFound", "no directory entry for that DID is visible to this caller");
    });
    const wallet = fakeWallet({ conversation: vi.fn(async () => UNNAMED) });
    (window as { vtaWallet?: unknown }).vtaWallet = { rooms: wallet };
    renderWith(<RoomPage hostDid={HOST} roomId={ROOM} />);
    const carol = await screen.findByRole("button", { name: "Carol Chen" });
    fireEvent.click(carol);
    const card = screen.getByRole("group", { name: "About Carol Chen" });
    expect(within(card).getByText("CC")).toBeTruthy();
    expect(within(card).queryByRole("link", { name: /Open card/ })).toBeNull();
    expect(directory.send.mock.calls.some((c) => c[0] === IMAGES_GET || c[0] === WALL)).toBe(false);
  });

  it("a private room's authors are never looked up: that would tell the community who writes there", async () => {
    const wallet = fakeWallet({
      info: vi.fn(async () => ({ ...INFO, visibility: "private" })),
      conversation: vi.fn(async () => UNNAMED),
    });
    (window as { vtaWallet?: unknown }).vtaWallet = { rooms: wallet };
    renderWith(<RoomPage hostDid={HOST} roomId={ROOM} />);
    await screen.findByRole("button", { name: /airport-electric/ });
    expect(directory.send).not.toHaveBeenCalled();
  });

  it("a run of messages by one author carries their name and initials once", async () => {
    const at = (m: number) => new Date(Date.UTC(2026, 10, 24, 12, m)).toISOString();
    const run = {
      ...CHAT,
      records: [
        { ...CHAT.records[0]!, key: "r1", body: "one", written: { at: at(0) }, orderAt: at(0), reactions: [] },
        { ...CHAT.records[0]!, key: "r2", body: "two", written: { at: at(1) }, orderAt: at(1), reactions: [] },
        { ...CHAT.records[0]!, key: "r3", body: "three", written: { at: at(30) }, orderAt: at(30), reactions: [] },
      ],
    };
    const wallet = fakeWallet({ conversation: vi.fn(async () => run) });
    (window as { vtaWallet?: unknown }).vtaWallet = { rooms: wallet };
    renderWith(<RoomPage hostDid={HOST} roomId={ROOM} />);
    await screen.findByText("three");
    // Two within five minutes are one run; the third, half an hour later, starts another.
    expect(screen.getAllByRole("button", { name: "Alberto Leon" })).toHaveLength(2);
    const items = screen.getAllByRole("listitem").filter((li) => li.classList.contains("chat-msg"));
    expect(items.map((li) => li.classList.contains("first"))).toEqual([true, false, true]);
  });

  it("the room's details are folded under About: its DID, who the member posts as, its epoch and storage", async () => {
    const wallet = fakeWallet({ conversation: vi.fn(async () => CHAT) });
    (window as { vtaWallet?: unknown }).vtaWallet = { rooms: wallet };
    renderWith(<RoomPage hostDid={HOST} roomId={ROOM} />);
    await screen.findByRole("list", { name: "Messages" });
    const about = screen.getByText("About this room").closest("details")!;
    expect(about.open).toBe(false);
    expect(within(about).getByText(ROOM)).toBeTruthy();
    expect(within(about).getByText("You post as")).toBeTruthy();
    expect(within(about).getByText("3")).toBeTruthy();
    expect(screen.getByText(/The community sees who added what/)).toBeTruthy();
  });

  it("the docked composer sends a message on Enter, takes a note behind its toggle, and a file by the paperclip", async () => {
    const wallet = fakeWallet({
      conversation: vi.fn(async () => CHAT),
      putMessage: vi.fn(async () => ({ key: "m9", version: 9 })),
    });
    (window as { vtaWallet?: unknown }).vtaWallet = { rooms: wallet };
    renderWith(<RoomPage hostDid={HOST} roomId={ROOM} />);
    const box = await screen.findByLabelText("Message");
    fireEvent.change(box, { target: { value: "Hello room" } });
    fireEvent.keyDown(box, { key: "Enter" });
    await screen.findByText("Message sent.");
    expect(wallet.putMessage).toHaveBeenCalledWith({ hostDid: HOST, roomId: ROOM, body: "Hello room" });
    // A note: its own small form, then back to the message.
    fireEvent.click(screen.getByRole("button", { name: "Write a note" }));
    fireEvent.change(screen.getByLabelText("Title"), { target: { value: "Agenda" } });
    fireEvent.change(screen.getByLabelText("Note"), { target: { value: "1. Budget" } });
    fireEvent.click(screen.getByRole("button", { name: /Add note/ }));
    await screen.findByText("Note added.");
    expect(wallet.calls.find((c) => c.method === "putNote")?.args).toEqual({
      hostDid: HOST,
      roomId: ROOM,
      title: "Agenda",
      body: "1. Budget",
    });
    expect(screen.getByLabelText("Message")).toBeTruthy();
    // A file: chosen, shown, then added through the wallet.
    const f = new File(["abc"], "plan.txt", { type: "text/plain" });
    fireEvent.change(screen.getByLabelText("Choose a file"), { target: { files: [f] } });
    fireEvent.click(await screen.findByRole("button", { name: "Add file" }));
    await screen.findByText("File added.");
    expect(wallet.calls.some((c) => c.method === "putFile")).toBe(true);
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  // Replying, reacting and staying current, through a wallet that does all three.
  const notListedError = () => Object.assign(new Error("the room's profile does not list inReplyTo"), { code: "recordMembersNotListed" });
  function answeringWallet(over: Partial<WalletRooms> = {}) {
    return fakeWallet({
      conversation: vi.fn(async () => CHAT),
      putMessage: vi.fn(async () => ({ key: "m9", version: 9 })),
      react: vi.fn(async () => ({ key: "r1", version: 10 })),
      unreact: vi.fn(async () => ({ withdrawn: 1 })),
      ...over,
    });
  }

  it("a reply names what it answers above the box, and is sent with it", async () => {
    const wallet = answeringWallet();
    (window as { vtaWallet?: unknown }).vtaWallet = { rooms: wallet };
    renderWith(<RoomPage hostDid={HOST} roomId={ROOM} />);
    await screen.findByRole("list", { name: "Messages" });
    // Alberto's "Hi" is the first message; its Reply action is the first.
    fireEvent.click(screen.getAllByRole("button", { name: "Reply" })[0]!);
    expect(screen.getByText(/Replying to/).textContent).toContain("Alberto Leon");
    const box = screen.getByLabelText("Message");
    fireEvent.change(box, { target: { value: "Hello back" } });
    fireEvent.keyDown(box, { key: "Enter" });
    await screen.findByText("Message sent.");
    expect(wallet.putMessage).toHaveBeenCalledWith({
      hostDid: HOST,
      roomId: ROOM,
      body: "Hello back",
      replyTo: { key: "m1", version: 1 },
    });
    // Sent: the reply is cleared.
    expect(screen.queryByText(/Replying to/)).toBeNull();
    // Cancelling one sends a plain message.
    fireEvent.click(screen.getAllByRole("button", { name: "Reply" })[0]!);
    fireEvent.click(screen.getByRole("button", { name: "Cancel the reply" }));
    expect(screen.queryByText(/Replying to/)).toBeNull();
  });

  it("a room that takes no replies says so, offers the words as a plain message, and stops offering replies", async () => {
    const putMessage = vi
      .fn()
      .mockRejectedValueOnce(notListedError())
      .mockResolvedValue({ key: "m9", version: 9 });
    const wallet = answeringWallet({ putMessage });
    (window as { vtaWallet?: unknown }).vtaWallet = { rooms: wallet };
    renderWith(<RoomPage hostDid={HOST} roomId={ROOM} />);
    await screen.findByRole("list", { name: "Messages" });
    fireEvent.click(screen.getAllByRole("button", { name: "Reply" })[0]!);
    const box = screen.getByLabelText("Message");
    fireEvent.change(box, { target: { value: "Hello back" } });
    fireEvent.keyDown(box, { key: "Enter" });
    const plain = await screen.findByRole("button", { name: "Send as a plain message" });
    // Nothing was written; the member is told why, never shown a raw error.
    expect(screen.getAllByText(/doesn't take replies/).length).toBeGreaterThan(0);
    expect(screen.queryByRole("button", { name: "Reply" })).toBeNull();
    fireEvent.click(plain);
    await screen.findByText("Message sent.");
    expect(putMessage).toHaveBeenLastCalledWith({ hostDid: HOST, roomId: ROOM, body: "Hello back" });
  });

  it("a reaction goes through the wallet; the member's own is taken back by selecting it", async () => {
    const wallet = answeringWallet();
    (window as { vtaWallet?: unknown }).vtaWallet = { rooms: wallet };
    renderWith(<RoomPage hostDid={HOST} roomId={ROOM} />);
    await screen.findByRole("list", { name: "Messages" });
    fireEvent.click(screen.getAllByRole("button", { name: "React" })[0]!);
    fireEvent.click(screen.getByRole("button", { name: "React 😂" }));
    await waitFor(() =>
      expect(wallet.react).toHaveBeenCalledWith({ hostDid: HOST, roomId: ROOM, key: "m1", version: 1, value: "😂" }),
    );
    // The member's own 👍 on "Hi" is theirs to take back.
    const mine = screen.getByRole("button", { name: "👍 1, including yours" });
    expect(mine.getAttribute("aria-pressed")).toBe("true");
    fireEvent.click(mine);
    await waitFor(() =>
      expect(wallet.unreact).toHaveBeenCalledWith({ hostDid: HOST, roomId: ROOM, key: "m1", value: "👍" }),
    );
    // A room that takes no reactions says so, and offers none.
    (wallet.react as ReturnType<typeof vi.fn>).mockRejectedValueOnce(notListedError());
    fireEvent.click(screen.getAllByRole("button", { name: "React" })[0]!);
    fireEvent.click(screen.getByRole("button", { name: "React 🎉" }));
    await screen.findByText(/doesn't take replies and reactions yet/);
    expect(screen.queryByRole("button", { name: "React" })).toBeNull();
  });

  it("a wallet older than replies and reactions is offered neither, and the room is refreshed by hand", async () => {
    const wallet = fakeWallet({
      conversation: vi.fn(async () => CHAT),
      putMessage: vi.fn(async () => ({ key: "m9", version: 9 })),
    });
    (window as { vtaWallet?: unknown }).vtaWallet = { rooms: wallet };
    renderWith(<RoomPage hostDid={HOST} roomId={ROOM} />);
    await screen.findByRole("list", { name: "Messages" });
    expect(screen.queryByRole("button", { name: "Reply" })).toBeNull();
    expect(screen.queryByRole("button", { name: "React" })).toBeNull();
    expect(screen.queryByRole("button", { name: /including yours/ })).toBeNull();
    expect(screen.getByText("👍 1")).toBeTruthy();
    expect(screen.getByRole("button", { name: "Refresh" })).toBeTruthy();
    expect(screen.queryByText("Live")).toBeNull();
  });

  it("a room whose newest record is folded away (a reaction) is acknowledged at the room's version, so the watch does not fire forever", async () => {
    let onEvent: ((e: RoomWatchEvent) => void) | undefined;
    const handle = { read: vi.fn(), stop: vi.fn() };
    // Version 9 is a reaction: folded into message m1, it is no record the page shows,
    // so the highest version shown stays 4.
    const conversation = vi.fn(async () => CHAT);
    const watch = vi.fn((_p: unknown, on: (e: RoomWatchEvent) => void) => {
      onEvent = on;
      return handle;
    });
    const wallet = answeringWallet({ conversation, watch });
    (window as { vtaWallet?: unknown }).vtaWallet = { rooms: wallet };
    renderWith(<RoomPage hostDid={HOST} roomId={ROOM} />);
    await screen.findByRole("list", { name: "Messages" });
    await waitFor(() => expect(watch).toHaveBeenCalled());
    act(() => onEvent!({ type: "changed", latestVersion: 9 }));
    // Told the room's version, never the page's lower one — which the host would
    // answer by firing again at once.
    await waitFor(() => expect(handle.read).toHaveBeenCalledWith(9));
    expect(handle.read).not.toHaveBeenCalledWith(4);
  });

  it("a watched room is read again when the wallet says it moved, and the watch is told what was read", async () => {
    let onEvent: ((e: RoomWatchEvent) => void) | undefined;
    const handle = { read: vi.fn(), stop: vi.fn() };
    const moved = { ...CHAT, records: [...CHAT.records, { ...CHAT.records[0]!, key: "m5", version: 5, body: "New" }] };
    const conversation = vi.fn().mockResolvedValueOnce(CHAT).mockResolvedValue(moved);
    const watch = vi.fn((_p: unknown, on: (e: RoomWatchEvent) => void) => {
      onEvent = on;
      return handle;
    });
    const wallet = answeringWallet({ conversation, watch });
    (window as { vtaWallet?: unknown }).vtaWallet = { rooms: wallet };
    const view = renderWith(<RoomPage hostDid={HOST} roomId={ROOM} />);
    await screen.findByRole("list", { name: "Messages" });
    await waitFor(() => expect(watch).toHaveBeenCalled());
    // Watched from the highest version the page holds.
    expect(watch.mock.calls[0]![0]).toEqual({ hostDid: HOST, roomId: ROOM, sinceVersion: 4 });
    // Armed: live, and no refresh button in the header.
    act(() => onEvent!({ type: "state", state: "armed" }));
    expect(screen.getByText("Live")).toBeTruthy();
    expect(screen.queryByRole("button", { name: "Refresh" })).toBeNull();
    // It moved: read again, then the watch is told the room was read to 5.
    act(() => onEvent!({ type: "changed", latestVersion: 5 }));
    await screen.findByText("New");
    await waitFor(() => expect(handle.read).toHaveBeenCalledWith(5));
    // Anything else and it is not live any more: never latched.
    act(() => onEvent!({ type: "state", state: "refused" }));
    expect(screen.queryByText("Live")).toBeNull();
    expect(screen.getByRole("button", { name: "Refresh" })).toBeTruthy();
    view.unmount();
    expect(handle.stop).toHaveBeenCalled();
  });

  it("a watch the wallet cannot keep falls back to reading the room on a timer", async () => {
    let onEvent: ((e: RoomWatchEvent) => void) | undefined;
    const conversation = vi.fn(async () => CHAT);
    const watch = vi.fn((_p: unknown, on: (e: RoomWatchEvent) => void) => {
      onEvent = on;
      return { read: vi.fn(), stop: vi.fn() };
    });
    const wallet = answeringWallet({ conversation, watch });
    (window as { vtaWallet?: unknown }).vtaWallet = { rooms: wallet };
    renderWith(<RoomPage hostDid={HOST} roomId={ROOM} />);
    await screen.findByRole("list", { name: "Messages" });
    await waitFor(() => expect(watch).toHaveBeenCalled());
    const before = conversation.mock.calls.length;
    vi.useFakeTimers();
    try {
      act(() => onEvent!({ type: "state", state: "unavailable" }));
      await act(async () => {
        await vi.advanceTimersByTimeAsync(20_000);
      });
    } finally {
      vi.useRealTimers();
    }
    await waitFor(() => expect(conversation.mock.calls.length).toBeGreaterThan(before));
  });

  it("a watch that says it is armed is still backed by a slow read, and the room is read when the tab is seen again", async () => {
    let onEvent: ((e: RoomWatchEvent) => void) | undefined;
    const handle = { read: vi.fn(), stop: vi.fn() };
    const conversation = vi.fn(async () => CHAT);
    const watch = vi.fn((_p: unknown, on: (e: RoomWatchEvent) => void) => {
      onEvent = on;
      return handle;
    });
    const wallet = answeringWallet({ conversation, watch });
    (window as { vtaWallet?: unknown }).vtaWallet = { rooms: wallet };
    // The backstop's timer starts with the page, so the clock is faked from the start.
    vi.useFakeTimers({ shouldAdvanceTime: true });
    try {
      renderWith(<RoomPage hostDid={HOST} roomId={ROOM} />);
      await screen.findByRole("list", { name: "Messages" });
      await waitFor(() => expect(watch).toHaveBeenCalled());
      act(() => onEvent!({ type: "state", state: "armed" }));
      expect(screen.getByText("Live")).toBeTruthy();
      // A delivery that broke without a word: nothing arrives, yet the room is read
      // again within the backstop, and the watch is told what was read.
      const before = conversation.mock.calls.length;
      await act(async () => {
        await vi.advanceTimersByTimeAsync(5 * 60_000);
      });
      await waitFor(() => expect(conversation.mock.calls.length).toBeGreaterThan(before));
      await waitFor(() => expect(handle.read).toHaveBeenCalled());
      // Coming back to the tab reads at once.
      const seen = conversation.mock.calls.length;
      act(() => {
        document.dispatchEvent(new Event("visibilitychange"));
      });
      await waitFor(() => expect(conversation.mock.calls.length).toBeGreaterThan(seen));
    } finally {
      vi.useRealTimers();
    }
  });

  it("a wallet older than messages is offered only a note, even in a chat", async () => {
    const wallet = fakeWallet({ conversation: vi.fn(async () => CHAT) });
    (window as { vtaWallet?: unknown }).vtaWallet = { rooms: wallet };
    renderWith(<RoomPage hostDid={HOST} roomId={ROOM} />);
    await screen.findByLabelText("Title");
    expect(screen.queryByLabelText("Message")).toBeNull();
    expect(screen.queryByRole("button", { name: /Back to the message/ })).toBeNull();
  });

  it("an opened record names its author as the chat does, and Escape closes it", async () => {
    const wallet = fakeWallet({ conversation: vi.fn(async () => CHAT) });
    const read = wallet.read;
    wallet.read = vi.fn(async (args: Parameters<WalletRooms["read"]>[0]) => ({ ...(await read(args)), author: ALBERTO }));
    (window as { vtaWallet?: unknown }).vtaWallet = { rooms: wallet };
    renderWith(<RoomPage hostDid={HOST} roomId={ROOM} />);
    fireEvent.click(await screen.findByRole("button", { name: "Open" }));
    const drawer = await screen.findByRole("complementary", { name: "Opened record" });
    // By the name the room gives them, as in the conversation — not the DID's last segment.
    await within(drawer).findByRole("button", { name: "Alberto Leon" });
    fireEvent.keyDown(window, { key: "Escape" });
    await waitFor(() => expect(screen.queryByRole("complementary", { name: "Opened record" })).toBeNull());
  });

  it("the conversation scrolls in its own window, opened at the newest, in the wallet's order", async () => {
    const tall = vi.spyOn(HTMLElement.prototype, "scrollHeight", "get").mockReturnValue(2000);
    try {
      const wallet = fakeWallet({ conversation: vi.fn(async () => CHAT) });
      (window as { vtaWallet?: unknown }).vtaWallet = { rooms: wallet };
      renderWith(<RoomPage hostDid={HOST} roomId={ROOM} />);
      const list = await screen.findByRole("list", { name: "Messages" });
      const window_ = list.parentElement!;
      expect(window_.className).toBe("chat-scroll");
      expect(window_.scrollTop).toBe(2000);
    } finally {
      tall.mockRestore();
    }
  });

  it("a room of notes and files stays a list of records, even from a wallet that assembles conversations", async () => {
    const notesOnly = { ...CHAT, records: [CHAT.records[2]!] };
    const wallet = fakeWallet({ conversation: vi.fn(async () => notesOnly) });
    (window as { vtaWallet?: unknown }).vtaWallet = { rooms: wallet };
    renderWith(<RoomPage hostDid={HOST} roomId={ROOM} />);
    await screen.findByRole("heading", { name: "Records" });
    expect(screen.queryByRole("heading", { name: "Conversation" })).toBeNull();
  });

  it("a conversation that does not assemble leaves the room's records", async () => {
    const wallet = fakeWallet({ conversation: vi.fn(async () => { throw new Error("no"); }) });
    (window as { vtaWallet?: unknown }).vtaWallet = { rooms: wallet };
    renderWith(<RoomPage hostDid={HOST} roomId={ROOM} />);
    await screen.findByText("Term sheet");
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

  describe("a chat message", () => {
    afterEach(() => window.localStorage.clear());

    it("the switch starts on Note; Message sends text with no title, and Enter sends it", async () => {
      const putMessage = vi.fn(async (_: { hostDid: string; roomId: string; body: string }) => ({ key: "m1", version: 5 }));
      const wallet = fakeWallet({ putMessage });
      (window as { vtaWallet?: unknown }).vtaWallet = { rooms: wallet };
      renderWith(<RoomPage hostDid={HOST} roomId={ROOM} />);
      await screen.findByText("Add to this room");
      const asNote = screen.getByRole("button", { name: "Note" });
      expect(asNote.getAttribute("aria-pressed")).toBe("true");
      expect(screen.getByLabelText("Title")).toBeTruthy();

      fireEvent.click(screen.getByRole("button", { name: "Message" }));
      expect(screen.queryByLabelText("Title")).toBeNull();
      const box = screen.getByLabelText("Message");
      fireEvent.change(box, { target: { value: "Lunch at one?" } });
      // Shift+Enter is a new line, not a send.
      fireEvent.keyDown(box, { key: "Enter", shiftKey: true });
      expect(putMessage).not.toHaveBeenCalled();
      fireEvent.keyDown(box, { key: "Enter" });
      await screen.findByText("Message sent.");
      expect(putMessage.mock.calls.map((c) => c[0])).toEqual([{ hostDid: HOST, roomId: ROOM, body: "Lunch at one?" }]);
      expect(wallet.calls.some((c) => c.method === "putNote")).toBe(false);
      expect((screen.getByLabelText("Message") as HTMLTextAreaElement).value).toBe("");
      expect(fetchSpy).not.toHaveBeenCalled();
    });

    it("an empty message is never sent", async () => {
      const putMessage = vi.fn(async () => ({ key: "m1", version: 5 }));
      const wallet = fakeWallet({ putMessage });
      (window as { vtaWallet?: unknown }).vtaWallet = { rooms: wallet };
      renderWith(<RoomPage hostDid={HOST} roomId={ROOM} />);
      await screen.findByText("Add to this room");
      fireEvent.click(screen.getByRole("button", { name: "Message" }));
      fireEvent.change(screen.getByLabelText("Message"), { target: { value: "  \n " } });
      fireEvent.keyDown(screen.getByLabelText("Message"), { key: "Enter" });
      expect((screen.getByRole("button", { name: /Send/ }) as HTMLButtonElement).disabled).toBe(true);
      expect(putMessage).not.toHaveBeenCalled();
    });

    it("the member's last choice is kept on this browser", async () => {
      window.localStorage.setItem("vtc-member-room-compose", "message");
      const wallet = fakeWallet({ putMessage: vi.fn(async () => ({ key: "m1", version: 5 })) });
      (window as { vtaWallet?: unknown }).vtaWallet = { rooms: wallet };
      renderWith(<RoomPage hostDid={HOST} roomId={ROOM} />);
      await screen.findByText("Add to this room");
      expect(screen.getByRole("button", { name: "Message" }).getAttribute("aria-pressed")).toBe("true");
      fireEvent.click(screen.getByRole("button", { name: "Note" }));
      expect(window.localStorage.getItem("vtc-member-room-compose")).toBe("note");
    });

    it("a wallet older than messages is offered notes only", async () => {
      window.localStorage.setItem("vtc-member-room-compose", "message");
      const wallet = fakeWallet();
      (window as { vtaWallet?: unknown }).vtaWallet = { rooms: wallet };
      renderWith(<RoomPage hostDid={HOST} roomId={ROOM} />);
      await screen.findByText("Add to this room");
      expect(screen.queryByRole("button", { name: "Message" })).toBeNull();
      expect(screen.getByLabelText("Title")).toBeTruthy();
    });
  });

  // rooms/records/put/0.4: an open room takes files too, encrypted under a key
  // its record carries in the clear — which the card says.
  it("an open room takes a note and a file, both said to be readable by its host", async () => {
    const wallet = fakeWallet({ info: vi.fn(async () => ({ ...INFO, visibility: "open" })) });
    (window as { vtaWallet?: unknown }).vtaWallet = { rooms: wallet };
    renderWith(<RoomPage hostDid={HOST} roomId={ROOM} />);
    await screen.findByText("Add to this room");
    expect(screen.getByText(/a file is stored encrypted under a key its record/)).toBeTruthy();
    expect(screen.getByText(/host can read both, as well as its members/)).toBeTruthy();
    expect(screen.getByLabelText("Or a file")).toBeTruthy();
    expect(screen.getByRole("button", { name: /Add file/ })).toBeTruthy();
    fireEvent.change(screen.getByLabelText("Title"), { target: { value: "Hello" } });
    fireEvent.click(screen.getByRole("button", { name: /Add note/ }));
    await screen.findByText("Note added.");
    await waitFor(() => expect(wallet.calls.find((c) => c.method === "putNote")?.args).toEqual({ hostDid: HOST, roomId: ROOM, title: "Hello" }));
  });

  it("an opened record takes the add form's place beside the list, and Add or Close brings the form back", async () => {
    const wallet = fakeWallet();
    (window as { vtaWallet?: unknown }).vtaWallet = { rooms: wallet };
    renderWith(<RoomPage hostDid={HOST} roomId={ROOM} />);
    await screen.findByText("Add to this room");
    fireEvent.click(await screen.findByRole("button", { name: /Term sheet/ }));
    await screen.findByRole("button", { name: /Download/ });
    expect(screen.queryByText("Add to this room")).toBeNull();
    // Both share one pane, next to the list rather than below it.
    const pane = document.querySelector(".room-pane")!;
    expect(within(pane as HTMLElement).getByRole("heading", { name: "Term sheet" })).toBeTruthy();

    fireEvent.click(screen.getByRole("button", { name: /^Add$/ }));
    await screen.findByText("Add to this room");
    fireEvent.click(screen.getByRole("button", { name: /Term sheet/ }));
    fireEvent.click(await screen.findByRole("button", { name: "Close" }));
    await screen.findByText("Add to this room");
  });

  // An open room's record is not signed by its author, so its file is checked
  // against the digest the record states — and the record view says so.
  it("an open room's file is said to match its record's digest, not its author's signature", async () => {
    const wallet = fakeWallet({
      info: vi.fn(async () => ({ ...INFO, visibility: "open" })),
      read: vi.fn(async () => ({
        key: "k1",
        version: 2,
        status: "active",
        updatedAt: "2026-10-16T00:00:00Z",
        author: MEMBER,
        title: "Term sheet",
        file: { name: "terms.pdf", size: 1234, mediaType: "application/pdf" },
        sealed: false,
        verification: {},
      })),
    });
    (window as { vtaWallet?: unknown }).vtaWallet = { rooms: wallet };
    renderWith(<RoomPage hostDid={HOST} roomId={ROOM} />);
    fireEvent.click(await screen.findByRole("button", { name: /Term sheet/ }));
    await screen.findByRole("button", { name: /Download/ });
    expect(screen.getByText(/checked against the digest its record states/)).toBeTruthy();
    expect(screen.queryByText(/what its author signed/)).toBeNull();
  });

  it("names authors briefly — the member's own as you — and folds retracted records away", async () => {
    const wallet = fakeWallet({
      browse: vi.fn(async () => ({
        records: [
          { key: "k1", version: 4, updatedAt: "2026-10-16T00:00:00Z", author: MEMBER },
          { key: "k2", version: 3, updatedAt: "2026-10-16T00:00:00Z", author: "did:webvh:QmBob:people.example:bob-vta" },
          { key: "k3", version: 2, updatedAt: "2026-10-16T00:00:00Z", author: MEMBER, status: "retracted" },
          { key: "k4", version: 1, updatedAt: "2026-10-16T00:00:00Z", author: MEMBER, status: "retracted" },
        ],
        complete: true,
        verification: {},
      })),
    });
    (window as { vtaWallet?: unknown }).vtaWallet = { rooms: wallet };
    renderWith(<RoomPage hostDid={HOST} roomId={ROOM} />);
    await screen.findByText(/v4 · .* · you$/);
    expect(screen.getByText(/v3 · .* · bob-vta$/)).toBeTruthy();
    const folded = screen.getByText("2 retracted records").closest("details")!;
    expect(folded.open).toBe(false);
    expect(within(folded).getAllByRole("listitem")).toHaveLength(2);
    // The facts are one line, naming who the member is here.
    expect(screen.getByLabelText("This room").textContent).toContain("Epoch 3");
  });

  it("a room that does not open says why", async () => {
    const wallet = fakeWallet({ info: vi.fn(async () => { throw new Error("has not been given that room"); }) });
    (window as { vtaWallet?: unknown }).vtaWallet = { rooms: wallet };
    renderWith(<RoomPage hostDid={HOST} roomId={ROOM} />);
    await screen.findByText(/has not been given that room/);
  });
});

// ── File previews ──
//
// A preview is chosen from the verified bytes the wallet hands over, never from
// the record's claimed type; a small picture is fetched unasked, anything else
// waits for a click; and every byte comes through `wallet.getFile`.

const PNG = new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0, 0, 0, 0]);

function fileRecord(key: string, file: { name: string; size: number; mediaType?: string }) {
  return {
    key,
    version: 2,
    status: "active",
    updatedAt: "2026-10-16T00:00:00Z",
    author: MEMBER,
    file,
    sealed: true,
    verification: {},
  };
}

function walletServing(
  records: ReturnType<typeof fileRecord>[],
  bytes: (key: string) => BlobPart,
  getFile?: WalletRooms["getFile"],
) {
  return fakeWallet({
    browse: vi.fn(async () => ({
      records: records.map((r) => ({ key: r.key, version: r.version, updatedAt: r.updatedAt, author: MEMBER })),
      complete: true,
      verification: {},
    })),
    read: vi.fn(async ({ key }: { key: string }) => records.find((r) => r.key === key)!),
    getFile:
      getFile ??
      vi.fn(async ({ key }: { key: string }) => {
        const r = records.find((x) => x.key === key)!;
        return { file: r.file, author: MEMBER, version: r.version, blob: new Blob([bytes(key)]) };
      }),
  });
}

describe("room file previews", () => {
  let created: string[];
  beforeEach(() => {
    vi.stubGlobal("fetch", vi.fn(async () => new Response("{}", { status: 404 })));
    created = [];
    URL.createObjectURL = vi.fn(() => {
      created.push("blob:x");
      return "blob:x";
    });
    URL.revokeObjectURL = vi.fn();
  });
  afterEach(() => {
    delete (window as { vtaWallet?: unknown }).vtaWallet;
    vi.unstubAllGlobals();
  });

  it("a small picture gets a thumbnail from its verified bytes, and is read once for view and download", async () => {
    const wallet = walletServing([fileRecord("k1", { name: "design.png", size: PNG.length, mediaType: "image/png" })], () => PNG);
    (window as { vtaWallet?: unknown }).vtaWallet = { rooms: wallet };
    renderWith(<RoomPage hostDid={HOST} roomId={ROOM} />);
    const thumb = await screen.findByRole("button", { name: "Open design.png" });
    const img = thumb.querySelector("img")!;
    expect(img.getAttribute("src")).toMatch(/^data:image\/png;base64,/);
    // Drawing a preview made no object URL: `data:` is what the CSP allows.
    expect(created).toHaveLength(0);

    fireEvent.click(thumb);
    await waitFor(() => expect(document.querySelector("img.file-preview-img")).not.toBeNull());
    // jsdom does not navigate; the save is the anchor's click.
    const save = vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => {});
    fireEvent.click(screen.getByRole("button", { name: /Download/ }));
    await waitFor(() => expect(save).toHaveBeenCalledTimes(1));
    save.mockRestore();
    expect(created).toHaveLength(1);
    expect(wallet.getFile).toHaveBeenCalledTimes(1);
    expect(wallet.getFile).toHaveBeenCalledWith({ hostDid: HOST, roomId: ROOM, key: "k1" });
  });

  it("a record labelled image/png whose bytes are HTML is never drawn as a picture or as markup", async () => {
    const html = "<html><body><script>window.pwned = 1</script><iframe src=x></iframe></body></html>";
    const wallet = walletServing([fileRecord("k1", { name: "photo.png", size: html.length, mediaType: "image/png" })], () => html);
    (window as { vtaWallet?: unknown }).vtaWallet = { rooms: wallet };
    renderWith(<RoomPage hostDid={HOST} roomId={ROOM} />);
    await screen.findByText("photo.png");
    // Fetched as a thumbnail candidate on the record's word, then refused by its bytes.
    await waitFor(() => expect(wallet.getFile).toHaveBeenCalledTimes(1));
    await waitFor(() => expect(screen.queryByLabelText("Loading a preview")).toBeNull());
    expect(document.querySelector("img")).toBeNull();
    expect(screen.queryByRole("button", { name: /Open photo.png/ })).toBeNull();

    // In the record's own view it is at most its text, in a <pre>, as text.
    fireEvent.click(screen.getByRole("button", { name: /photo.png/ }));
    const pre = await screen.findByLabelText("File preview");
    expect(pre.tagName).toBe("PRE");
    expect(pre.textContent).toBe(html);
    expect(pre.children).toHaveLength(0);
    expect(document.querySelector("img, iframe, script")).toBeNull();
    expect((window as { pwned?: number }).pwned).toBeUndefined();
  });

  it("bytes that are neither a picture nor text are download only", async () => {
    const wallet = walletServing(
      [fileRecord("k1", { name: "photo.png", size: 8, mediaType: "image/png" })],
      () => new Uint8Array([0x25, 0x50, 0x44, 0x46, 0, 1, 2, 3]),
    );
    (window as { vtaWallet?: unknown }).vtaWallet = { rooms: wallet };
    renderWith(<RoomPage hostDid={HOST} roomId={ROOM} />);
    fireEvent.click(await screen.findByRole("button", { name: /photo.png/ }));
    await screen.findByText(/No preview for this kind of file/);
    expect(document.querySelector("img")).toBeNull();
    expect(screen.getByRole("button", { name: /Download/ })).toBeTruthy();
  });

  it("text is previewed on a click, as text", async () => {
    const words = "Agreed: <b>ship it</b>\n\tFriday";
    const wallet = walletServing([fileRecord("k1", { name: "notes.txt", size: words.length, mediaType: "text/plain" })], () => words);
    (window as { vtaWallet?: unknown }).vtaWallet = { rooms: wallet };
    renderWith(<RoomPage hostDid={HOST} roomId={ROOM} />);
    fireEvent.click(await screen.findByRole("button", { name: /notes.txt/ }));
    await screen.findByRole("button", { name: /Preview/ });
    expect(wallet.getFile).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole("button", { name: /Preview/ }));
    const pre = await screen.findByLabelText("File preview");
    expect(pre.textContent).toBe(words);
    expect(pre.querySelector("b")).toBeNull();
    expect(screen.getByRole("button", { name: /Download/ })).toBeTruthy();
  });

  it("a picture above the auto-preview limit is not fetched until asked", async () => {
    const wallet = walletServing([fileRecord("k1", { name: "big.png", size: 3 * 1024 * 1024, mediaType: "image/png" })], () => PNG);
    (window as { vtaWallet?: unknown }).vtaWallet = { rooms: wallet };
    renderWith(<RoomPage hostDid={HOST} roomId={ROOM} />);
    fireEvent.click(await screen.findByRole("button", { name: /big.png/ }));
    const preview = await screen.findByRole("button", { name: /Preview/ });
    await new Promise((r) => setTimeout(r, 20));
    expect(wallet.getFile).not.toHaveBeenCalled();
    expect(document.querySelector("img")).toBeNull();
    fireEvent.click(preview);
    await waitFor(() => expect(document.querySelector("img.file-preview-img")).not.toBeNull());
    expect(wallet.getFile).toHaveBeenCalledTimes(1);
  });

  it("thumbnails are fetched a few at a time, not all at once", async () => {
    const records = Array.from({ length: 6 }, (_, i) => fileRecord(`k${i}`, { name: `p${i}.png`, size: PNG.length, mediaType: "image/png" }));
    let inFlight = 0;
    let most = 0;
    const release: (() => void)[] = [];
    const getFile = vi.fn(async ({ key }: { key: string }) => {
      inFlight++;
      most = Math.max(most, inFlight);
      await new Promise<void>((r) => release.push(r));
      inFlight--;
      const r = records.find((x) => x.key === key)!;
      return { file: r.file, author: MEMBER, version: r.version, blob: new Blob([PNG]) };
    });
    const wallet = walletServing(records, () => PNG, getFile);
    (window as { vtaWallet?: unknown }).vtaWallet = { rooms: wallet };
    renderWith(<RoomPage hostDid={HOST} roomId={ROOM} />);
    await screen.findByText("p0.png");
    await waitFor(() => expect(getFile).toHaveBeenCalledTimes(2));
    await new Promise((r) => setTimeout(r, 20));
    expect(getFile).toHaveBeenCalledTimes(2);
    while (getFile.mock.calls.length < 6 || release.length > 0) {
      release.shift()?.();
      await new Promise((r) => setTimeout(r, 5));
    }
    await waitFor(() => expect(screen.getAllByRole("button", { name: /^Open p\d\.png$/ })).toHaveLength(6));
    expect(most).toBe(2);
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
