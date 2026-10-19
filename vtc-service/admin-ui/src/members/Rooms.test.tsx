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

    // Then it can be shared here, pre-ticked in the wallet's window.
    fireEvent.click(screen.getByRole("button", { name: /Share it here/ }));
    await waitFor(() => expect(wallet.choose).toHaveBeenCalledWith({ hostDid: HOST, suggest: ROOM, member: MEMBER }));
    expect(fetchSpy).not.toHaveBeenCalled();
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
