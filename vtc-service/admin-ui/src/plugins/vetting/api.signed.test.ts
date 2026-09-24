// The endorsement-type writes go through the signed door when this browser
// holds a console key, and over the bearer route when it does not (#1641
// batch 4). `StatementTypesCard.test.tsx` covers the bearer fallback, which is
// what a test browser with no key takes; these hold the other branch.

import { afterEach, describe, expect, it } from "vitest";

import type { SignedTrustTaskDocument } from "@/lib/console-key";
import {
  forgetConsoleKey,
  generateConsoleKey,
  resetConsoleKeyCacheForTests,
} from "@/lib/console-key";
import { mockFetch } from "@/test/render";

import { deleteEndorsementType, registerEndorsementType } from "./api";

const VTC_DID = "did:webvh:QmScid:community.example:vtc";
const REGISTER = "https://trusttasks.org/spec/vtc/endorsement-types/register/0.1";
const DELETE = "https://trusttasks.org/spec/vtc/endorsement-types/delete/0.1";
const TYPE = "https://example.org/endorsements/identity-vetting/0.1";

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
