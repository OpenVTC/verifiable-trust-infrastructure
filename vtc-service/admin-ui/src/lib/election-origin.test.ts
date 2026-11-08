import { describe, expect, it } from "vitest";

import { boardOfElection, boardStandIn, groupByBoard, stageSummary } from "./election-origin";

const B1 = "brd_ff-8cTg0yX5EWSyHPcluzA";
const B2 = "brd_Uc7N2qLm4Rt8Vx1ZAAAAAA";
const I1 = "ida_zgA8cE7kD8Ty8Zt_Qk1-VQ";
const I2 = "ida_Pk3Wq9Ls2Dn6Hy4BAAAAAA";
const e = (electionId: string, state = "voting") => ({ electionId, state });

describe("boardOfElection", () => {
  it("reads the board and idea of a board's election", () => {
    expect(boardOfElection(`board.${B1}.${I1}`)).toEqual({ boardId: B1, ideaId: I1 });
  });

  it("treats anything only resembling the convention as stand-alone", () => {
    for (const id of [
      "favourite-city",
      `board.${B1}`,
      `board.${B1}.${I1}.extra`,
      `board.brd_short.${I1}`,
      `board.${B1}.not-an-idea`,
      `boards.${B1}.${I1}`,
      `board.${I1}.${B1}`,
    ]) {
      expect(boardOfElection(id)).toBeNull();
    }
  });
});

describe("groupByBoard", () => {
  it("keeps stand-alone elections apart, in order", () => {
    const g = groupByBoard([e("a"), e("b")], new Map(), "Deleted board");
    expect(g.standalone.map((x) => x.electionId)).toEqual(["a", "b"]);
    expect(g.boards).toEqual([]);
  });

  it("puts each board's elections in one group, named from the list, in first-seen order", () => {
    const items = [e(`board.${B2}.${I1}`), e("solo"), e(`board.${B1}.${I1}`), e(`board.${B2}.${I2}`)];
    const g = groupByBoard(items, new Map([[B1, "IIW Sessions"], [B2, "Roadmap"]]), "Deleted board");
    expect(g.standalone.map((x) => x.electionId)).toEqual(["solo"]);
    expect(g.boards.map((b) => [b.title, b.known, b.items.length])).toEqual([
      ["Roadmap", true, 2],
      ["IIW Sessions", true, 1],
    ]);
  });

  it("names a board the list does not have as missing", () => {
    const g = groupByBoard([e(`board.${B1}.${I1}`)], new Map(), "Deleted board");
    expect(g.boards[0]).toMatchObject({ boardId: B1, title: "Deleted board", known: false });
  });

  it("names every board by its identifier when there is no list", () => {
    const g = groupByBoard([e(`board.${B1}.${I1}`)], null, "Deleted board");
    expect(g.boards[0]).toMatchObject({ title: boardStandIn(B1), known: false });
    expect(boardStandIn(B1)).toBe("Board ff-8cTg0…");
  });
});

describe("stageSummary", () => {
  it("counts each stage in first-seen order", () => {
    expect(stageSummary([e("a", "Voting"), e("b", "Taking tickets"), e("c", "Voting")], (x) => x.state)).toBe(
      "2 voting · 1 taking tickets",
    );
  });
});
