// The endorsement-type writes are signed documents, with no bearer route.
// These hold what goes on the wire, signed by a real console key;
// `StatementTypesCard.test.tsx` drives the card through the unsigned stand-in.

import { afterEach, describe, expect, it } from "vitest";

import type { SignedTrustTaskDocument } from "@/lib/console-key";
import {
  forgetConsoleKey,
  generateConsoleKey,
  resetConsoleKeyCacheForTests,
} from "@/lib/console-key";
import { mockFetch } from "@/test/render";

import {
  ACCEPTS_PAGE_SIZE,
  deleteEndorsementType,
  fetchCriteria,
  registerEndorsementType,
} from "./api";

const VTC_DID = "did:webvh:QmScid:community.example:vtc";
const REGISTER = "https://trusttasks.org/spec/vtc/endorsement-types/register/0.1";
const DELETE = "https://trusttasks.org/spec/vtc/endorsement-types/delete/0.1";
const TYPE = "https://example.org/predicates/vetted/1";

afterEach(async () => {
  await forgetConsoleKey();
  resetConsoleKeyCacheForTests();
});

function health() {
  return {
    method: "GET",
    path: "/health",
    body: { status: "ok", version: "t", vtc_did: VTC_DID },
  };
}

function response(type: string, payload: unknown) {
  return {
    id: "urn:uuid:response",
    type: `${type}#response`,
    issuer: VTC_DID,
    recipient: "did:key:zConsole",
    issuedAt: "2026-09-24T10:15:01Z",
    threadId: "urn:uuid:request",
    payload,
  };
}

describe("admission criteria listing", () => {
  const ACCEPTS_LIST = "https://trusttasks.org/spec/vtc/schemas/accepts/list/0.2";

  // `vtc/schemas/accepts/list` caps `limit` at 50; asking for more is refused
  // as malformed and the Requirements tab showed "could not load the
  // admission criteria". Pin the bound, and that paging follows the cursor.
  it("asks within the specification's limit and follows the cursor", async () => {
    expect(ACCEPTS_PAGE_SIZE).toBeLessThanOrEqual(50);
    await generateConsoleKey();
    const requests = mockFetch([
      health(),
      {
        method: "POST",
        path: "/v1/trust-tasks",
        body: ({ body }: { url: string; body: unknown }) =>
          (body as SignedTrustTaskDocument).payload &&
          ((body as SignedTrustTaskDocument).payload as { cursor?: string }).cursor === "page-2"
            ? response(ACCEPTS_LIST, { items: [{ id: "b" }] })
            : response(ACCEPTS_LIST, { items: [{ id: "a" }], nextCursor: "page-2" }),
      },
    ]);

    const criteria = await fetchCriteria();
    expect(criteria.map((c) => (c as unknown as { id: string }).id)).toEqual(["a", "b"]);

    const docs = requests
      .filter((r) => r.url === "/v1/trust-tasks")
      .map((r) => r.body as SignedTrustTaskDocument);
    const [first, second] = docs;
    expect(docs).toHaveLength(2);
    expect(first?.type).toBe(ACCEPTS_LIST);
    expect(first?.payload).toEqual({ limit: ACCEPTS_PAGE_SIZE });
    expect(second?.payload).toEqual({ limit: ACCEPTS_PAGE_SIZE, cursor: "page-2" });
  });
});

describe("endorsement-type writes with a console key", () => {
  it("registers through the signed door, with the body as the payload", async () => {
    await generateConsoleKey();
    const requests = mockFetch([
      health(),
      {
        method: "POST",
        path: "/v1/trust-tasks",
        body: response(REGISTER, { endorsementType: { typeUri: TYPE } }),
      },
    ]);

    const result = await registerEndorsementType({ typeUri: TYPE });
    expect(result.endorsementType.typeUri).toBe(TYPE);

    expect(requests.some((r) => r.url === "/v1/endorsement-types")).toBe(false);
    const doc = requests.find((r) => r.url === "/v1/trust-tasks")!
      .body as SignedTrustTaskDocument;
    expect(doc.type).toBe(REGISTER);
    expect(doc.payload).toEqual({ typeUri: TYPE });
    expect(doc.proof.cryptosuite).toBe("eddsa-jcs-2022");
  });

  it("deletes through the signed door, naming the type in the payload", async () => {
    await generateConsoleKey();
    const requests = mockFetch([
      health(),
      {
        method: "POST",
        path: "/v1/trust-tasks",
        body: response(DELETE, { typeUri: TYPE }),
      },
    ]);

    const result = await deleteEndorsementType(TYPE);
    expect(result.typeUri).toBe(TYPE);

    const doc = requests.find((r) => r.url === "/v1/trust-tasks")!
      .body as SignedTrustTaskDocument;
    expect(doc.type).toBe(DELETE);
    // The bearer route carries the URI as a path segment; the document
    // carries it as `typeUri`, which is what the task's payload names.
    expect(doc.payload).toEqual({ typeUri: TYPE });
  });

  it("does not fall back to the bearer route when the signed call is refused", async () => {
    await generateConsoleKey();
    const requests = mockFetch([
      health(),
      {
        method: "POST",
        path: "/v1/trust-tasks",
        status: 409,
        body: {
          id: "urn:uuid:err",
          type: "https://trusttasks.org/spec/trust-task-error/0.5",
          payload: {
            code: "vtc/endorsement-types/delete:inUse",
            message: "endorsement-type-in-use: still referenced",
            retryable: false,
          },
        },
      },
    ]);

    await expect(deleteEndorsementType(TYPE)).rejects.toMatchObject({
      status: 409,
      message: "endorsement-type-in-use: still referenced",
    });
    expect(
      requests.some((r) => r.url.startsWith("/v1/endorsement-types")),
    ).toBe(false);
  });
});
