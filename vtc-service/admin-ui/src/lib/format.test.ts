import { describe, expect, it } from "vitest";

import { shortenDid } from "./format";

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
