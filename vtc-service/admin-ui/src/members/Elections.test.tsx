// The portal's Elections pages: everything is read through the member's wallet
// (`window.vtaWallet.elections`), and taking a ticket or voting hands off to the
// wallet's own window. The page never holds a ballot, and after a vote is not
// told whether one was cast.

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { ConfirmDialogProvider } from "@/components/ConfirmDialog";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

// Board titles are read through the portal's own signed reads; nothing about elections is.
const send = vi.fn(async (..._a: unknown[]): Promise<unknown> => {
  throw new Error("no portal reads in this test");
});
vi.mock("./directory-api", async (orig) => ({
  ...(await orig<typeof import("./directory-api")>()),
  send: (...a: unknown[]) => send(...a),
}));

import { BOARDS_LIST_TASK } from "./boards-api";
import { ElectionPage, ElectionsPage } from "./Elections";
import {
  actionableFirst,
  declinedInWallet,
  electionListOf,
  memberOfFor,
  notifiedOnly,
  refusalKind,
  stageOf,
  walletErrorCode,
  type PageElection,
  type PageElectionView,
  type PageNotifiedElection,
} from "./wallet-elections";

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
  return render(<QueryClientProvider client={qc}><ConfirmDialogProvider look="portal">{node}</ConfirmDialogProvider></QueryClientProvider>);
}

afterEach(() => {
  delete (window as { vtaWallet?: unknown }).vtaWallet;
});

describe("grouped by the board they came from", () => {
  const BOARD = "brd_ff-8cTg0yX5EWSyHPcluzA";
  const fromBoard = listed({
    electionId: `board.${BOARD}.ida_zgA8cE7kD8Ty8Zt_Qk1-VQ`,
    title: "Hart should buy me lunch",
    ticketHeld: false,
  });

  it("lists stand-alone elections apart from each board's, named from the board list", async () => {
    send.mockImplementation(async (type: unknown) => {
      if (type === BOARDS_LIST_TASK) return { boards: [{ boardId: BOARD, title: "IIW Sessions" }] };
      throw new Error(`unexpected ${String(type)}`);
    });
    withWallet({ list: vi.fn(async () => ({ elections: [fromBoard, listed()] })) });
    renderWith(<ElectionsPage hostDid={HOST} member={ME} />);
    const standalone = await screen.findByRole("list", { name: "Stand-alone elections" });
    expect(standalone.textContent).toContain("AGM 2027");
    const iiw = (await screen.findByText("IIW Sessions", { selector: "summary strong" })).closest("details")!;
    expect(iiw.textContent).toContain("1 idea to vote on");
    expect(iiw.textContent).toContain("Hart should buy me lunch");
    expect(iiw.querySelector(`a[href="#/boards/${BOARD}"]`)).toBeTruthy();
    // VTI-VOT-001: grouping adds nothing about whether anyone voted.
    expect(screen.queryByText(/you have voted|vote (was )?(cast|recorded)/i)).toBeNull();
  });

  it("still groups when the boards cannot be read", async () => {
    send.mockReset();
    send.mockRejectedValue(new Error("offline"));
    withWallet({ list: vi.fn(async () => ({ elections: [fromBoard, listed()] })) });
    renderWith(<ElectionsPage hostDid={HOST} member={ME} />);
    expect(await screen.findByText("Board ff-8cTg0…", { selector: "summary strong" })).toBeTruthy();
    expect(screen.getByRole("link", { name: "AGM 2027" })).toBeTruthy();
  });
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

  it("vti_vot_053: after close the wallet checks the vote in its own window, offered to every member", async () => {
    const closed = shown({ state: "tallied", votingOpensAt: iso(Date.now() - 2 * HOUR), votingClosesAt: iso(Date.now() - HOUR) });
    const checkVote = vi.fn(async () => ({}));
    withWallet({ show: vi.fn(async () => closed), checkVote });
    renderWith(<ElectionPage hostDid={HOST} member={ME} electionId="agm-2027" />);
    fireEvent.click(await screen.findByRole("button", { name: "Check my vote in my wallet" }));
    await waitFor(() => expect(checkVote).toHaveBeenCalledWith({ hostDid: HOST, electionId: "agm-2027", member: ME }));
    // VTI-VOT-001: the page learns nothing of the answer.
    expect(screen.queryByText(/included|you have voted/i)).toBeNull();
    expect(screen.queryByText(/Voting opens/)).toBeNull();
  });

  it("offers no check while voting is open, or from a wallet without one", async () => {
    withWallet({ checkVote: vi.fn(async () => ({})) });
    renderWith(<ElectionPage hostDid={HOST} member={ME} electionId="agm-2027" />);
    await screen.findByText("Who chairs?");
    expect(screen.queryByRole("button", { name: "Check my vote in my wallet" })).toBeNull();
  });

  it("an older wallet is offered no check after close", async () => {
    withWallet({ show: vi.fn(async () => shown({ state: "closed" })) });
    renderWith(<ElectionPage hostDid={HOST} member={ME} electionId="agm-2027" />);
    await screen.findByText("Who chairs?");
    expect(screen.queryByRole("button", { name: "Check my vote in my wallet" })).toBeNull();
  });

  it("tells the member, before a ticket, when written answers come out below 10 (VTI-VOT-090)", async () => {
    withWallet({ show: vi.fn(async () => shown({ textReleaseThreshold: 3 })) });
    renderWith(<ElectionPage hostDid={HOST} member={ME} electionId="agm-2027" />);
    expect(await screen.findByText(/a written answer may identify who wrote it/)).toBeTruthy();
    expect(screen.getByText(/released once 3 ballots are counted/)).toBeTruthy();
  });

  it("tells the member, before a ticket, whose membership credential counts (VTI-VOT-090)", async () => {
    const view = shown();
    withWallet({
      show: vi.fn(async () => ({
        ...view,
        disclosure: {
          ...view.disclosure,
          rollCredential: { memberOf: "did:webvh:QmGroup:community.example:groups:g7", memberOfKind: "communityGroup", memberOfName: "Engineering" },
        },
      })),
    });
    renderWith(<ElectionPage hostDid={HOST} member={ME} electionId="agm-2027" />);
    expect(await screen.findByText(/membership credential issued by/)).toBeTruthy();
    expect(screen.getByText("Engineering", { exact: false })).toBeTruthy();
    expect(screen.getByText(/shows this community that you are a member of/)).toBeTruthy();
  });

  it("says nothing of a credential when the wallet passes none on", async () => {
    withWallet({ show: vi.fn(async () => shown()) });
    renderWith(<ElectionPage hostDid={HOST} member={ME} electionId="agm-2027" />);
    await screen.findByRole("button", { name: "Vote, or see my vote, in my wallet" });
    expect(screen.queryByText(/membership credential issued by/)).toBeNull();
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

// VTI-NTF-063: a wallet with notifications answers `list` with `{ elections, notified }`; one
// before them with `{ elections }`. Wallets update apart from the portal, so both must work.
const PARTY = "did:webvh:QmParty:partner.example";

// One clock reading for every notice, so two built in one test compare equal.
const NOW = Date.now();

function notice(over: Partial<PageNotifiedElection> = {}): PageNotifiedElection {
  return {
    electionId: "partner-poll",
    audience: PARTY,
    status: "available",
    votingOpensAt: iso(NOW - HOUR),
    votingClosesAt: iso(NOW + 6 * HOUR),
    ...over,
  };
}

describe("both wallet shapes", () => {
  it("reads notifications from a newer wallet, none from an older one, and a bare list too", () => {
    expect(electionListOf({ elections: [listed()], notified: [notice()] }).notified).toEqual([notice()]);
    const one = listed();
    expect(electionListOf({ elections: [one] })).toEqual({ elections: [one], notified: [] });
    expect(electionListOf([one])).toEqual({ elections: [one], notified: [] });
    expect(electionListOf(undefined)).toEqual({ elections: [], notified: [] });
  });

  it("keeps only what VTI-NTF-063 lets the page see, and drops what is not a notification", () => {
    const got = electionListOf({
      elections: [],
      notified: [{ ...notice(), title: "Secret", manifest: { questions: [] } }, { electionId: "x" }, null, { ...notice(), status: "odd" }],
    });
    expect(got.notified).toEqual([notice()]);
  });

  it("de-duplicates: a listed election stays in the list, and one notice per election", () => {
    const list = electionListOf({
      elections: [listed()],
      notified: [notice({ electionId: "agm-2027", audience: HOST }), notice({ status: "withdrawn" }), notice()],
    });
    expect(notifiedOnly(list)).toEqual([notice()]);
  });

  it("takes memberOf only from a notice still standing", () => {
    const list = electionListOf({ elections: [], notified: [notice({ status: "withdrawn" })] });
    expect(memberOfFor(list, "partner-poll")).toBeUndefined();
    expect(memberOfFor(electionListOf({ elections: [], notified: [notice()] }), "partner-poll")).toBe(PARTY);
    expect(memberOfFor(undefined, "partner-poll")).toBeUndefined();
  });

  it("an older wallet lists as before, with nothing told", async () => {
    withWallet({ list: vi.fn(async () => ({ elections: [listed()] })) });
    renderWith(<ElectionsPage hostDid={HOST} member={ME} />);
    await screen.findByText("AGM 2027");
    expect(screen.queryByText(/told about/i)).toBeNull();
  });

  it("an older wallet opens an election with no memberOf sent", async () => {
    const wallet = withWallet({ list: vi.fn(async () => ({ elections: [listed()] })) });
    renderWith(<ElectionPage hostDid={HOST} member={ME} electionId="agm-2027" />);
    fireEvent.click(await screen.findByRole("button", { name: "Vote, or see my vote, in my wallet" }));
    await waitFor(() => expect(wallet.vote).toHaveBeenCalled());
    expect(wallet.show).toHaveBeenCalledWith({ hostDid: HOST, electionId: "agm-2027", member: ME });
    expect(wallet.vote).toHaveBeenCalledWith({ hostDid: HOST, electionId: "agm-2027", member: ME });
  });
});

describe("elections the member was told about", () => {
  it("lists one the community does not, with only what the notice says", async () => {
    withWallet({ list: vi.fn(async () => ({ elections: [listed()], notified: [notice()] })) });
    renderWith(<ElectionsPage hostDid={HOST} member={ME} />);
    const told = await screen.findByRole("list", { name: "Elections you were told about" });
    expect(told.textContent).toContain("partner-poll");
    expect(told.textContent).toContain(PARTY);
    expect(told.textContent).toContain("You were told about this");
    expect(told.querySelector('a[href="#/elections/partner-poll"]')).toBeTruthy();
    // The community's own list is unchanged.
    expect(screen.getByRole("link", { name: "AGM 2027" })).toBeTruthy();
  });

  it("marks a listed election the member was told about once, in the list", async () => {
    withWallet({ list: vi.fn(async () => ({ elections: [listed()], notified: [notice({ electionId: "agm-2027", audience: HOST })] })) });
    renderWith(<ElectionsPage hostDid={HOST} member={ME} />);
    await screen.findByText(/you were told about this/);
    expect(screen.queryByRole("list", { name: "Elections you were told about" })).toBeNull();
    expect(screen.getAllByRole("link", { name: "AGM 2027" })).toHaveLength(1);
  });

  it("shows a withdrawn notice without a way to open it", async () => {
    withWallet({ list: vi.fn(async () => ({ elections: [], notified: [notice({ status: "withdrawn" })] })) });
    renderWith(<ElectionsPage hostDid={HOST} member={ME} />);
    await screen.findByText("Notice withdrawn");
    expect(screen.queryByRole("link", { name: "Open in my wallet" })).toBeNull();
    expect(screen.queryByText(/no elections you can vote in/)).toBeNull();
  });

  it("passes the notice's party on as memberOf to show, take ticket and vote", async () => {
    const wallet = withWallet({
      list: vi.fn(async () => ({ elections: [], notified: [notice()] })),
      show: vi.fn(async () => shown({ electionId: "partner-poll", title: "Partner poll", state: "registration" })),
      vote: vi.fn(async () => ({ ticketTaken: true })),
    });
    renderWith(<ElectionPage hostDid={HOST} member={ME} electionId="partner-poll" />);
    await screen.findByText("Partner poll");
    const expected = { hostDid: HOST, electionId: "partner-poll", member: ME, memberOf: PARTY };
    expect(wallet.show).toHaveBeenCalledWith(expected);
    // Read with the party named from the first read, never without and then again.
    expect(wallet.show).toHaveBeenCalledTimes(1);
    fireEvent.click(screen.getByRole("button", { name: "Take my ticket" }));
    await waitFor(() => expect(wallet.takeTicket).toHaveBeenCalledWith(expected));
    fireEvent.click(screen.getByRole("button", { name: "Vote, or see my vote, in my wallet" }));
    await waitFor(() => expect(wallet.vote).toHaveBeenCalledWith(expected));
    // The page passes a DID, never a presentation or a credential.
    for (const call of [...wallet.show.mock.calls, ...wallet.takeTicket.mock.calls, ...wallet.vote.mock.calls]) {
      expect(Object.keys((call as unknown[])[0] as object).sort()).toEqual(["electionId", "hostDid", "member", "memberOf"]);
    }
  });

  it("sends no memberOf for a withdrawn notice", async () => {
    const wallet = withWallet({ list: vi.fn(async () => ({ elections: [listed()], notified: [notice({ electionId: "agm-2027", status: "withdrawn" })] })) });
    renderWith(<ElectionPage hostDid={HOST} member={ME} electionId="agm-2027" />);
    await screen.findByText("Who chairs?");
    expect(wallet.show).toHaveBeenCalledWith({ hostDid: HOST, electionId: "agm-2027", member: ME });
  });
});

describe("the community's refusals, in words", () => {
  it("classifies the wallet's wording and bare codes", () => {
    expect(refusalKind(new Error("Acme shows you no such election — it may not be open to you."))).toBe("electionUnknown");
    expect(refusalKind(new Error("Acme refused (https://openvtc.org/errors#electionUnknown)."))).toBe("electionUnknown");
    expect(refusalKind(new Error("No such election is open to you at this community."))).toBe("electionUnknown");
    expect(refusalKind(new Error("Acme could not check your membership credential just now: ..."))).toBe("indeterminate");
    expect(refusalKind(new Error("Acme refused (indeterminate)."))).toBe("indeterminate");
    expect(refusalKind(new Error("The wallet holds no identity you use at this community."))).toBe("other");
  });

  it("electionUnknown says it cannot tell which, and names the party it was told about", async () => {
    withWallet({
      list: vi.fn(async () => ({ elections: [], notified: [notice()] })),
      show: vi.fn(async () => Promise.reject(new Error("Acme shows you no such election — it may not be open to you."))),
    });
    renderWith(<ElectionPage hostDid={HOST} member={ME} electionId="partner-poll" />);
    expect(await screen.findByText("This community shows you no such election.")).toBeTruthy();
    expect(screen.getByText(/gives the same answer in each case/)).toBeTruthy();
    expect(screen.getByRole("alert").textContent).toContain(PARTY);
  });

  it("indeterminate says nothing was recorded and to try again", async () => {
    withWallet({
      show: vi.fn(async () =>
        Promise.reject(new Error("Acme could not check your membership credential just now: its issuer's DID document or status list could not be read.")),
      ),
    });
    renderWith(<ElectionPage hostDid={HOST} member={ME} electionId="agm-2027" />);
    expect(await screen.findByText("The community couldn’t check your membership just now.")).toBeTruthy();
    expect(screen.getByText(/nothing was recorded\. Try again/)).toBeTruthy();
  });

  it("a ticket refused as indeterminate is said in words too", async () => {
    withWallet({
      list: vi.fn(async () => ({ elections: [listed({ ticketHeld: false })] })),
      takeTicket: vi.fn(async () => Promise.reject(new Error("Acme refused (indeterminate)."))),
    });
    renderWith(<ElectionPage hostDid={HOST} member={ME} electionId="agm-2027" />);
    fireEvent.click(await screen.findByRole("button", { name: "Take my ticket" }));
    expect(await screen.findByText("The community couldn’t check your membership just now.")).toBeTruthy();
  });

  it("choosing in the wallet not to show a membership is not an error, and can be asked again", async () => {
    const wallet = withWallet({
      list: vi.fn(async () => ({ elections: [], notified: [notice()] })),
      show: vi.fn(async () => Promise.reject(new Error("You chose not to show your membership, so the election was not read."))),
    });
    renderWith(<ElectionPage hostDid={HOST} member={ME} electionId="partner-poll" />);
    fireEvent.click(await screen.findByRole("button", { name: "Ask my wallet again" }));
    expect(screen.queryByRole("alert")).toBeNull();
    await waitFor(() => expect(wallet.show).toHaveBeenCalledTimes(2));
  });
});

/** A wallet error as a wallet with page-facing codes rejects it: the message, and `code`. */
const coded = (message: string, code: string) => Object.assign(new Error(message), { code });

describe("the wallet's error codes, before its words", () => {
  it("reads a code only when the wallet put a non-empty string there", () => {
    expect(walletErrorCode(coded("x", "electionUnknown"))).toBe("electionUnknown");
    expect(walletErrorCode(new Error("x"))).toBeUndefined();
    expect(walletErrorCode(coded("x", ""))).toBeUndefined();
    expect(walletErrorCode(Object.assign(new Error("x"), { code: 7 }))).toBeUndefined();
    expect(walletErrorCode("electionUnknown")).toBeUndefined();
  });

  it("decides the community's refusals by their Trust Task code, whatever the words say", () => {
    expect(refusalKind(coded("Something went wrong.", "electionUnknown"))).toBe("electionUnknown");
    expect(refusalKind(coded("Something went wrong.", "indeterminate"))).toBe("indeterminate");
    // The code wins over words that would read as the other answer.
    expect(refusalKind(coded("Acme could not check your membership just now.", "electionUnknown"))).toBe("electionUnknown");
    expect(refusalKind(coded("Acme shows you no such election.", "indeterminate"))).toBe("indeterminate");
  });

  it("a wallet-local code is never a community refusal, nor a refusal a decline", () => {
    expect(refusalKind(coded("Acme shows you no such election.", "declined"))).toBe("other");
    expect(declinedInWallet(coded("You declined.", "declined"))).toBe(true);
    expect(declinedInWallet(coded("You declined to be told.", "electionUnknown"))).toBe(false);
    expect(declinedInWallet(coded("The wallet window closed.", "declined"))).toBe(true);
  });

  it("falls back to the words for an older wallet, or a code this page does not know", () => {
    expect(refusalKind(coded("Acme refused (indeterminate).", "someFutureCode"))).toBe("indeterminate");
    expect(declinedInWallet(coded("You did not take a ticket.", "someFutureCode"))).toBe(true);
    expect(declinedInWallet(new Error("You did not take a ticket."))).toBe(true);
    expect(refusalKind(coded("Something else.", "toString"))).toBe("other");
  });

  it("words a coded refusal on the page", async () => {
    withWallet({ show: vi.fn(async () => Promise.reject(coded("Acme refused.", "indeterminate"))) });
    renderWith(<ElectionPage hostDid={HOST} member={ME} electionId="agm-2027" />);
    expect(await screen.findByText("The community couldn’t check your membership just now.")).toBeTruthy();
  });

  it("a coded decline in the wallet is not an error, and can be asked again", async () => {
    const wallet = withWallet({
      list: vi.fn(async () => ({ elections: [], notified: [notice()] })),
      show: vi.fn(async () => Promise.reject(coded("Not shown.", "declined"))),
    });
    renderWith(<ElectionPage hostDid={HOST} member={ME} electionId="partner-poll" />);
    fireEvent.click(await screen.findByRole("button", { name: "Ask my wallet again" }));
    expect(screen.queryByRole("alert")).toBeNull();
    await waitFor(() => expect(wallet.show).toHaveBeenCalledTimes(2));
  });
});
