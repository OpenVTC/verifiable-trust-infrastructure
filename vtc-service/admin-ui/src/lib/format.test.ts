import { describe, expect, it } from "vitest";

import { formatRelative, shortenDid } from "./format";

describe("formatRelative", () => {
  const now = Date.parse("2026-10-11T12:00:00Z");
  const ago = (s: number) => new Date(now - s * 1000).toISOString();

  it("says how long ago, coarsening with age", () => {
    expect(formatRelative(ago(20), now)).toBe("just now");
    expect(formatRelative(ago(5 * 60), now)).toBe("5 min ago");
    expect(formatRelative(ago(2 * 3600 + 59), now)).toBe("2 h ago");
    expect(formatRelative(ago(30 * 3600), now)).toBe("yesterday");
    expect(formatRelative(ago(3 * 86400), now)).toBe("3 days ago");
  });

  it("gives the date past a week, and survives skew and garbage", () => {
    expect(formatRelative(ago(30 * 86400), now)).toBe(
      new Date(now - 30 * 86400 * 1000).toLocaleDateString(),
    );
    expect(formatRelative(new Date(now + 60_000).toISOString(), now)).toBe("just now");
    expect(formatRelative("not a date", now)).toBe("not a date");
  });
});

// The shared vectors of `vta_sdk::display_name::shorten_did`
// (`shorten_did_matches_shared_vectors`): the console and the CLIs must
// abbreviate a DID the same way. Change one table, change both.
const VECTORS: [string, string][] = [
  ["alice", "alice"],
  ["https://example.com/@alice", "https://example.com/@alice"],
  [
    "did:webvh:QmXkAbCdEfGhIjKlMnOp:webvh.storm.ws:glenn-vta",
    "did:webvh:QmXkAbCdEf…:…storm.ws:glenn-vta",
  ],
  [
    "did:webvh:QmXkAbCdEfGhIjKlMnOp:dids.firstperson.dev:stem-wall",
    "did:webvh:QmXkAbCdEf…:…firstperson.dev:stem-wall",
  ],
  [
    "did:webvh:QmXkAbCdEfGhIjKlMnOp:dids.ic3.dev:fruit-feel",
    "did:webvh:QmXkAbCdEf…:dids.ic3.dev:fruit-feel",
  ],
  [
    "did:webvh:QmXkAbCdEfGhIjKlMnOp:firstperson.network:a:b",
    "did:webvh:QmXkAbCdEf…:firstperson.network:a:b",
  ],
  ["did:web:QmXkAbCdEfGhIjKlMnOp:example.com", "did:web:QmXkAbCdEf…:example.com"],
  ["did:webvh:Qm123:example.com", "did:webvh:Qm123:example.com"],
  ["did:key:z6MkfrQjWzPQrTuVwXyZaBcDeFgHiJkLmNoPqRsTuVwXyZ4rT", "did:key:z6MkfrQjWz…XyZ4rT"],
  ["did:key:z6MkfrQjWz", "did:key:z6MkfrQjWz"],
  ["did:webvh:QmXkAbCdEfGhIjKlMnOpQrSt", "did:webvh:QmXkAbCdEf…OpQrSt"],
];

describe("shortenDid", () => {
  it.each(VECTORS)("%s → %s", (input, expected) => {
    expect(shortenDid(input)).toBe(expected);
  });
});
