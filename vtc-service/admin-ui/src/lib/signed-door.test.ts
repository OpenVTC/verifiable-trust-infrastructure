// What the console actually puts on the wire at `POST /v1/trust-tasks`, and
// when it declines to.
//
// These assert on the *document*, not on "we called fetch": a test that only
// counts requests would pass for a document the daemon refuses, which is the
// failure mode this whole feature has.

import { afterEach, describe, expect, it } from "vitest";

import { postSignedTrustTask, SIGNING_KEY_REFUSED_EVENT, SigningUnavailableError } from "./api";
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

  // The VTC's rate-limit refusal is not a Trust Task document, and its body
  // says how long to wait. A short wait is waited out once, with the identical
  // document; the operator never sees "429 from the signed Trust Task endpoint".
  it("waits out a short rate limit and resends the same document", async () => {
    await generateConsoleKey();
    let calls = 0;
    const requests = mockFetch([
      health(),
      {
        method: "POST",
        path: "/v1/trust-tasks",
        // `mockFetch` reads the body before the status.
        body: () =>
          ++calls === 1
            ? { error: "rate_limited", limiter: "unauth", retryAfterSecs: 0 }
            : responseDocument({ removed: true }),
        status: () => (calls === 1 ? 429 : 200),
      },
    ]);
    await expect(postSignedTrustTask(PURGE, { did: "did:key:z6MkTarget" })).resolves.toEqual({
      removed: true,
    });
    const sent = requests.filter((r) => r.url === "/v1/trust-tasks");
    expect(sent).toHaveLength(2);
    expect(sent[1]!.body).toEqual(sent[0]!.body);
  });

  it("says how long to wait when a rate limit is too long to wait out", async () => {
    await generateConsoleKey();
    const requests = mockFetch([
      health(),
      {
        method: "POST",
        path: "/v1/trust-tasks",
        status: 429,
        body: { error: "rate_limited", limiter: "unauth", retryAfterSecs: 40 },
      },
    ]);
    await expect(postSignedTrustTask(PURGE, {})).rejects.toMatchObject({
      status: 429,
      code: "rateLimited",
      message: expect.stringMatching(/try again in 40 seconds/i),
    });
    expect(requests.filter((r) => r.url === "/v1/trust-tasks")).toHaveLength(1);
  });

  it("tells the shell when a signed document is refused outright", async () => {
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
    let heard = 0;
    const listener = () => heard++;
    window.addEventListener(SIGNING_KEY_REFUSED_EVENT, listener);
    try {
      await expect(postSignedTrustTask(PURGE, {})).rejects.toMatchObject({ status: 403 });
    } finally {
      window.removeEventListener(SIGNING_KEY_REFUSED_EVENT, listener);
    }
    expect(heard).toBe(1);
  });

  it("refuses to sign when this browser holds no key", async () => {
    mockFetch([health()]);
    await expect(postSignedTrustTask(PURGE, {})).rejects.toBeInstanceOf(
      SigningUnavailableError,
    );
  });
});

describe("no bearer door", () => {
  it("tells a browser with no WebCrypto Ed25519 that it cannot sign", async () => {
    // Chrome <137 / Firefox <130 / Safari <17. There is no REST route to fall
    // back to: the operator is told why, and nothing is sent.
    await generateConsoleKey();
    resetConsoleKeyCacheForTests();
    const real = crypto.subtle.generateKey;
    Object.defineProperty(crypto.subtle, "generateKey", {
      configurable: true,
      value: () => Promise.reject(new DOMException("nope", "NotSupportedError")),
    });
    try {
      const requests = mockFetch([health()]);
      await expect(postSignedTrustTask(PURGE, {})).rejects.toBeInstanceOf(
        SigningUnavailableError,
      );
      expect(requests.filter((r) => r.url.endsWith("/v1/trust-tasks"))).toHaveLength(0);
    } finally {
      Object.defineProperty(crypto.subtle, "generateKey", {
        configurable: true,
        value: real,
      });
    }
  });

  it("surfaces a refused signed call as the refusal", async () => {
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
    await expect(postSignedTrustTask(PURGE, {})).rejects.toMatchObject({
      status: 403,
      code: "permissionDenied",
    });
  });
});
