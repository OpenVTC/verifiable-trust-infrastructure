// The portal's Elections pages: everything is read through the member's wallet
// (`window.vtaWallet.elections`), and taking a ticket or voting hands off to the
// wallet's own window. The page never holds a ballot, and after a vote is not
// told whether one was cast.

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { ElectionPage, ElectionsPage } from "./Elections";
import { actionableFirst, stageOf, type PageElection, type PageElectionView } from "./wallet-elections";

const HOST = "did:webvh:QmHost:acme.example";
const ME = "did:key:z6MkMember";
const HOUR = 3600_000;

const iso = (ms: number) => new Date(ms).toISOString();

function listed(over: Partial<PageElection> = {}): PageElection {
  return {
    electionId: "agm-2027",
    title: "AGM 2027",
    state: "voting",
    votingOpensAt: iso(Date.now() - HOUR),
    votingClosesAt: iso(Date.now() + HOUR),
    binding: false,
    ticketHeld: true,
    ...over,
  };
}

function shown(over: Partial<PageElectionView> = {}): PageElectionView {
  return {
    electionId: "agm-2027",
    title: "AGM 2027",
    description: "Elect the chair.",
    state: "voting",
    secrecy: "open",
    registrationOpensAt: iso(Date.now() - 2 * HOUR),
    votingOpensAt: iso(Date.now() - HOUR),
    votingClosesAt: iso(Date.now() + HOUR),
    binding: false,
    questions: [{ key: "chair", type: "choice", text: "Who chairs?", options: [{ key: "ana", label: "Ana" }, { key: "bo" }], optional: false }],
    disclosure: {
      ballotBox: "did:webvh:QmBox:ballots.example",
      ballotBoxOperator: "Independent Ballots Ltd",
      sameOperator: false,
      boardVisibility: "public",
      revote: "replace",
      auditors: [],
    },
    ...over,
  };
}

function withWallet(over: Record<string, unknown> = {}) {
  const wallet = {
    list: vi.fn(async () => ({ elections: [listed()] })),
    show: vi.fn(async () => shown()),
    takeTicket: vi.fn(async () => ({ ticketHeld: true as const, taken: true })),
    vote: vi.fn(async () => ({ ticketTaken: false })),
    ...over,
  };
  (window as { vtaWallet?: unknown }).vtaWallet = { elections: wallet };
  return wallet;
}

function renderWith(node: React.ReactNode) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(<QueryClientProvider client={qc}>{node}</QueryClientProvider>);
}

afterEach(() => {
  delete (window as { vtaWallet?: unknown }).vtaWallet;
});

describe("stages", () => {
  it("reads where an election stands from its state and its schedule", () => {
    const now = Date.now();
    expect(stageOf(listed(), now)).toBe("voting");
    expect(stageOf(listed({ state: "registration", votingOpensAt: iso(now + HOUR), votingClosesAt: iso(now + 2 * HOUR) }), now)).toBe(
      "ticketsOpen",
    );
    expect(stageOf(listed({ state: "voting", votingClosesAt: iso(now - 1) }), now)).toBe("closed");
    expect(stageOf(listed({ state: "cancelled" }), now)).toBe("cancelled");
    expect(stageOf(listed({ state: "pendingRegistration" }), now)).toBe("upcoming");
  });

  it("puts what the member can act on first", () => {
    const done = listed({ electionId: "old", state: "tallied" });
    const open = listed({ electionId: "now" });
    expect(actionableFirst([done, open]).map((e) => e.electionId)).toEqual(["now", "old"]);
  });
});

describe("the list", () => {
  it("without a wallet says how to get one, and reads nothing", () => {
    renderWith(<ElectionsPage hostDid={HOST} member={ME} />);
    expect(screen.getByText("You vote with your wallet")).toBeTruthy();
  });

  it("lists the elections the wallet reads as the member", async () => {
    const wallet = withWallet();
    renderWith(<ElectionsPage hostDid={HOST} member={ME} />);
    await screen.findByText("AGM 2027");
    expect(wallet.list).toHaveBeenCalledWith({ hostDid: HOST, member: ME });
    expect(screen.getByText(/you have your ticket/)).toBeTruthy();
  });

  it("an election with an empty title is named by its id and opens from its card", async () => {
    withWallet({ list: vi.fn(async () => ({ elections: [listed({ title: "", ticketHeld: false, state: "registration", votingOpensAt: iso(Date.now() + HOUR), votingClosesAt: iso(Date.now() + 2 * HOUR) })] })) });
    renderWith(<ElectionsPage hostDid={HOST} member={ME} />);
    const named = await screen.findByRole("link", { name: "agm-2027" });
    const open = screen.getByRole("link", { name: "Open to take your ticket" });
    expect(open.getAttribute("href")).toBe(named.getAttribute("href"));
    expect(screen.getByText("Tickets open")).toBeTruthy();
  });

  it("shows the wallet's refusal", async () => {
    withWallet({ list: vi.fn(async () => Promise.reject(new Error("The wallet holds no identity you use at this community."))) });
    renderWith(<ElectionsPage hostDid={HOST} member={ME} />);
    await screen.findByText(/holds no identity/);
  });
});

describe("one election", () => {
  it("shows what it asks and how it is run, and hands the vote to the wallet", async () => {
    const wallet = withWallet();
    renderWith(<ElectionPage hostDid={HOST} member={ME} electionId="agm-2027" />);
    await screen.findByText("Who chairs?");
    expect(screen.getByText(/Independent Ballots Ltd/)).toBeTruthy();
    expect(screen.queryByText("Take my ticket")).toBeNull();
    fireEvent.click(await screen.findByRole("button", { name: "Vote, or see my vote, in my wallet" }));
    await waitFor(() => expect(wallet.vote).toHaveBeenCalledWith({ hostDid: HOST, electionId: "agm-2027", member: ME }));
    await screen.findByText(/This site isn.t told/);
    expect(screen.queryByRole("radio")).toBeNull();
  });

  it("offers the ticket when none is held, and says to come back to vote", async () => {
    const wallet = withWallet({ list: vi.fn(async () => ({ elections: [listed({ ticketHeld: false })] })) });
    renderWith(<ElectionPage hostDid={HOST} member={ME} electionId="agm-2027" />);
    fireEvent.click(await screen.findByRole("button", { name: "Take my ticket" }));
    await waitFor(() => expect(wallet.takeTicket).toHaveBeenCalled());
    await screen.findByText(/Come back to vote later/);
  });

  it("a ticket the member declined in the wallet is not an error", async () => {
    withWallet({
      list: vi.fn(async () => ({ elections: [listed({ ticketHeld: false })] })),
      takeTicket: vi.fn(async () => Promise.reject(new Error("You did not take a ticket."))),
    });
    renderWith(<ElectionPage hostDid={HOST} member={ME} electionId="agm-2027" />);
    fireEvent.click(await screen.findByRole("button", { name: "Take my ticket" }));
    await waitFor(() => expect(screen.queryByRole("alert")).toBeNull());
  });

  it("voting is off until it opens, and a shared operator is said out loud", async () => {
    withWallet({
      show: vi.fn(async () =>
        shown({
          state: "registration",
          votingOpensAt: iso(Date.now() + HOUR),
          votingClosesAt: iso(Date.now() + 2 * HOUR),
          disclosure: { ...shown().disclosure, sameOperator: true },
        }),
      ),
    });
    renderWith(<ElectionPage hostDid={HOST} member={ME} electionId="agm-2027" />);
    const vote = (await screen.findByRole("button", { name: "Vote, or see my vote, in my wallet" })) as HTMLButtonElement;
    expect(vote.disabled).toBe(true);
    expect(screen.getByText(/same operator runs this community/)).toBeTruthy();
  });

  it("tells the member, before a ticket, when written answers come out below 10 (VTI-VOT-090)", async () => {
    withWallet({ show: vi.fn(async () => shown({ textReleaseThreshold: 3 })) });
    renderWith(<ElectionPage hostDid={HOST} member={ME} electionId="agm-2027" />);
    expect(await screen.findByText(/a written answer may identify who wrote it/)).toBeTruthy();
    expect(screen.getByText(/released once 3 ballots are counted/)).toBeTruthy();
  });

  it("says nothing more at 10, or when the wallet does not pass the threshold on", async () => {
    for (const view of [shown({ textReleaseThreshold: 10 }), shown()]) {
      withWallet({ show: vi.fn(async () => view) });
      const { unmount } = renderWith(<ElectionPage hostDid={HOST} member={ME} electionId="agm-2027" />);
      await screen.findByRole("button", { name: "Vote, or see my vote, in my wallet" });
      expect(screen.queryByText(/may identify who wrote it/)).toBeNull();
      unmount();
    }
  });
});
