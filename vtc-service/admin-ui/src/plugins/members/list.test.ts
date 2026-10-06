import { describe, expect, it } from "vitest";

import { compareValues, didHandle, matchScore, nextSort, searchTerms } from "./list";

const DID = "did:webvh:QmNvpxDbHuAbCdEf:webvh.storm.ws:glance-arrow";
const fields = (name: string, did = DID) => ({
  short: [name, "member", didHandle(did), "stormer78-2"],
  long: [did],
});

describe("members search", () => {
  it("matches every row on a blank query", () => {
    expect(matchScore(searchTerms("   "), fields("Alice"))).toBe(0);
  });

  it("matches a substring of any field, case-insensitively", () => {
    expect(matchScore(searchTerms("ALI"), fields("Alice Wong"))).not.toBeNull();
    expect(matchScore(searchTerms("storm.ws"), fields("Alice"))).not.toBeNull();
    expect(matchScore(searchTerms("stormer"), fields("Alice"))).not.toBeNull();
  });

  it("needs every term to match something", () => {
    expect(matchScore(searchTerms("alice glance"), fields("Alice"))).not.toBeNull();
    expect(matchScore(searchTerms("alice zebra"), fields("Alice"))).toBeNull();
  });

  it("matches letters in order on the short fields only", () => {
    expect(matchScore(searchTerms("glarr"), fields("Alice"))).not.toBeNull();
    // Letters scattered through the full DID alone are not a match.
    expect(matchScore(searchTerms("qnvx"), fields("Alice"))).toBeNull();
  });

  it("ranks a word-start match over an inner one over letters in order", () => {
    const start = matchScore(searchTerms("won"), fields("Alice Wong"))!;
    const inner = matchScore(searchTerms("ong"), fields("Alice Wong"))!;
    const loose = matchScore(searchTerms("aw"), fields("Alice Wong"))!;
    expect(start).toBeGreaterThan(inner);
    expect(inner).toBeGreaterThan(loose);
  });

  it("takes a DID's handle from its last segment", () => {
    expect(didHandle(DID)).toBe("glance-arrow");
    expect(didHandle("not-a-did")).toBe("");
  });
});

describe("members sort", () => {
  it("starts a column at its natural direction and flips it on a second click", () => {
    const first = nextSort(null, "joined", "desc");
    expect(first).toEqual({ key: "joined", dir: "desc" });
    expect(nextSort(first, "joined")).toEqual({ key: "joined", dir: "asc" });
    expect(nextSort(first, "name")).toEqual({ key: "name", dir: "asc" });
  });

  it("puts empty values last in either direction", () => {
    const values = ["b", null, "a", ""];
    expect([...values].sort((x, y) => compareValues(x, y, "asc"))).toEqual(["a", "b", null, ""]);
    expect([...values].sort((x, y) => compareValues(x, y, "desc"))).toEqual(["b", "a", null, ""]);
  });

  it("compares numbers numerically and text naturally", () => {
    expect(compareValues(2, 10, "asc")).toBeLessThan(0);
    expect(compareValues("member 2", "member 10", "asc")).toBeLessThan(0);
  });
});
