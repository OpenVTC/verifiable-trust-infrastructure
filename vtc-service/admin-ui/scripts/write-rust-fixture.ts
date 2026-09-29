// Produce the signed Trust Task document that `vtc-service/tests/
// console_signed_document.rs` verifies with the daemon's own verifier.
//
//     cd vtc-service/admin-ui && npx vite-node scripts/write-rust-fixture.ts
//
// Run it when the signing code changes, and commit the result. The point is
// that the two stacks are checked against each other rather than each against
// itself: `console-key.test.ts` proves the signer agrees with a reader of its
// own output, which would stay true if both halves shared a mistake. Only the
// Rust side — `affinidi-data-integrity`'s `eddsa-jcs-2022`, reached exactly as
// `POST /v1/trust-tasks` reaches it — can say the bytes are right.
//
// A fresh key each run, deliberately: the private half is non-extractable and
// cannot be committed, and nothing needs it. The `did:key` in the document
// carries the public half, which is all a verifier resolves.
//
// Lives outside `src/` so `tsc -b` (which compiles `include: ["src"]`) never
// sees it and the console keeps no build-time dependency on Node's types.

import { mkdirSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import { fileURLToPath } from "node:url";

import {
  buildTrustTaskDocument,
  generateConsoleKey,
  signTrustTaskDocument,
} from "../src/lib/console-key";

const OUT = fileURLToPath(
  new URL(
    "../../tests/fixtures/console-signed-document.json",
    import.meta.url,
  ),
);

const key = await generateConsoleKey();

// `vtc/members/purge/0.1` — the smallest of the four #1681 tasks, and the one
// whose payload is a single member, so the fixture is about the envelope and
// the proof rather than about a payload shape.
const signed = await signTrustTaskDocument(
  buildTrustTaskDocument({
    typeUri: "https://trusttasks.org/spec/vtc/members/purge/0.1",
    payload: { did: "did:key:z6MkjchhfUsD6mmvni8mCdXHw216Xrm9bQe2mBH1P5RDjVJG" },
    issuer: key.consoleDid,
    recipient: "did:webvh:QmFixtureScid:community.example:vtc",
    // Fixed, so the fixture's only churn between runs is the key and the
    // signature. The Rust test does not check freshness — it verifies the
    // proof, which is the part that must not drift.
    issuedAt: new Date("2026-09-23T10:15:00.000Z"),
  }),
  key,
  { now: new Date("2026-09-23T10:15:00.000Z") },
);

mkdirSync(dirname(OUT), { recursive: true });
writeFileSync(OUT, JSON.stringify(signed, null, 2) + "\n");
console.log(`wrote ${OUT}\nsigner: ${key.consoleDid}`);
