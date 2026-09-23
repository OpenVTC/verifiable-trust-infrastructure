// What the console actually puts on the wire at `POST /v1/trust-tasks`, and
// when it declines to.
//
// These assert on the *document*, not on "we called fetch": a test that only
// counts requests would pass for a document the daemon refuses, which is the
// failure mode this whole feature has.

import { afterEach, describe, expect, it } from "vitest";

import { postSignedTrustTask, signedOrBearer, SigningUnavailableError } from "./api";
import type { SignedTrustTaskDocument } from "./console-key";
import {
  forgetConsoleKey,
  generateConsoleKey,
  resetConsoleKeyCacheForTests,
} from "./console-key";
import { base58btcDecode, jcsCanonicalize, sha256 } from "./jcs";
import { mockFetch, type RecordedRequest } from "@/test/render";

const VTC_DID = "did:webvh:QmScid:community.example:vtc";
const PURGE = "https://trusttasks.org/spec/vtc/members/purge/0.1";

afterEach(async () => {
  await forgetConsoleKey();
  resetConsoleKeyCacheForTests();
});

/** The `#response` document the daemon answers a dispatched task with. */
function responseDocument(payload: unknown) {
  return {
    id: "urn:uuid:response",
    type: `${PURGE}#response`,
    issuer: VTC_DID,
    recipient: "did:key:zConsole",
    issuedAt: "2026-09-23T10:15:01Z",
    threadId: "urn:uuid:request",
    payload,
  };
}

function health() {
  return { method: "GET", path: "/health", body: { status: "ok", version: "t", vtc_did: VTC_DID } };
}

describe("postSignedTrustTask", () => {
  it("sends a document the daemon's own rules accept, and returns its payload", async () => {
    const key = await generateConsoleKey();
    const requests: RecordedRequest[] = mockFetch([
      health(),
      {
        method: "POST",
        path: "/v1/trust-tasks",
        body: responseDocument({ did: "did:key:z6MkTarget", removed: true }),
      },
    ]);

    const result = await postSignedTrustTask<{ removed: boolean }>(PURGE, {
      did: "did:key:z6MkTarget",
    });
    expect(result.removed).toBe(true);

    const sent = requests.find((r) => r.url === "/v1/trust-tasks");
    expect(sent).toBeDefined();
    // Typed as the wire shape rather than `Record<string, unknown>`: the
    // assertions below are about named members, and an index signature would
    // make each one `| undefined` and each check weaker than it reads.
    const doc = sent!.body as SignedTrustTaskDocument;

    // The envelope, member by member, because each one is a separate refusal.
    expect(doc.id).toMatch(/^urn:uuid:[0-9a-f-]{36}$/); // §7.2 replay record
    expect(doc.type).toBe(PURGE); // the routing key — no Trust-Task header
    expect(doc.issuer).toBe(key.consoleDid); // §4.7, bound to the proof below
    expect(doc.recipient).toBe(VTC_DID); // §4.8.2 audience binding
    expect(doc.issuedAt).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/);
    expect(doc.payload).toEqual({ did: "did:key:z6MkTarget" });

    // The proof, and the binding the spine makes right after verifying it.
    expect(doc.proof.cryptosuite).toBe("eddsa-jcs-2022");
    expect(doc.proof.verificationMethod.split("#")[0]).toBe(doc.issuer);

    // And the signature really covers those bytes.
    const { proof, ...unsigned } = doc;
    const { proofValue, ...proofConfig } = proof;
    const hashData = new Uint8Array(64);
    hashData.set(await sha256(jcsCanonicalize(proofConfig)), 0);
    hashData.set(await sha256(jcsCanonicalize(unsigned)), 32);
    expect(
      await crypto.subtle.verify(
        { name: "Ed25519" },
        key.keypair.publicKey,
        base58btcDecode(proofValue.slice(1)),
        hashData,
      ),
    ).toBe(true);
  });

  it("does not send a Trust-Task header — the document's type is the routing key", async () => {
    await generateConsoleKey();
    const requests = mockFetch([
      health(),
      { method: "POST", path: "/v1/trust-tasks", body: responseDocument({}) },
    ]);
    await postSignedTrustTask(PURGE, { did: "did:key:z6MkTarget" });
    const sent = requests.find((r) => r.url === "/v1/trust-tasks");
    expect(sent!.headers.has("Trust-Task")).toBe(false);
  });

  it("surfaces a trust-task-error document's own message", async () => {
    await generateConsoleKey();
    mockFetch([
      health(),
      {
        method: "POST",
        path: "/v1/trust-tasks",
        status: 403,
        body: {
          id: "urn:uuid:err",
          type: "https://trusttasks.org/spec/trust-task-error/0.5",
          payload: {
            code: "permissionDenied",
            message: "Trust Task proof verification failed",
            retryable: false,
          },
        },
      },
    ]);

    // Not the bare status line: the daemon's message is the only thing that
    // distinguishes a revoked delegation from a demoted ACL row.
    await expect(
      postSignedTrustTask(PURGE, { did: "did:key:z6MkTarget" }),
    ).rejects.toMatchObject({
      status: 403,
      message: "Trust Task proof verification failed",
    });
  });

  it("refuses to sign when this browser holds no key", async () => {
    mockFetch([health()]);
    await expect(postSignedTrustTask(PURGE, {})).rejects.toBeInstanceOf(
      SigningUnavailableError,
    );
  });
});

describe("signedOrBearer", () => {
  it("takes the bearer route when this browser has never enrolled", async () => {
    mockFetch([health()]);
    let bearerCalls = 0;
    const result = await signedOrBearer(PURGE, { did: "x" }, async () => {
      bearerCalls += 1;
      return "from-bearer";
    });
    expect(result).toBe("from-bearer");
    expect(bearerCalls).toBe(1);
  });

  it("takes the bearer route on a browser with no WebCrypto Ed25519", async () => {
    // Chrome <137 / Firefox <130 / Safari <17. The console must keep working.
    await generateConsoleKey();
    resetConsoleKeyCacheForTests();
    const real = crypto.subtle.generateKey;
    Object.defineProperty(crypto.subtle, "generateKey", {
      configurable: true,
      value: () => Promise.reject(new DOMException("nope", "NotSupportedError")),
    });
    try {
      mockFetch([health()]);
      const result = await signedOrBearer(PURGE, {}, async () => "from-bearer");
      expect(result).toBe("from-bearer");
    } finally {
      Object.defineProperty(crypto.subtle, "generateKey", {
        configurable: true,
        value: real,
      });
    }
  });

  it("does NOT fall back when the signed call is refused", async () => {
    // The property that makes the fallback safe. Retrying a refused document
    // over a bearer token would use the session as the authority the signed
    // door exists to stop relying on — and would hide a revocation from the
    // operator who just performed it.
    await generateConsoleKey();
    mockFetch([
      health(),
      {
        method: "POST",
        path: "/v1/trust-tasks",
        status: 403,
        body: { payload: { code: "permissionDenied", message: "no" } },
      },
    ]);

    let bearerCalls = 0;
    await expect(
      signedOrBearer(PURGE, {}, async () => {
        bearerCalls += 1;
        return "from-bearer";
      }),
    ).rejects.toMatchObject({ status: 403 });
    expect(bearerCalls).toBe(0);
  });
});
