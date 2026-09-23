import { afterEach, describe, expect, it } from "vitest";

import {
  buildTrustTaskDocument,
  ed25519Available,
  forgetConsoleKey,
  generateConsoleKey,
  loadConsoleKey,
  resetConsoleKeyCacheForTests,
  signTrustTaskDocument,
  type SignedTrustTaskDocument,
} from "./console-key";
import {
  base58btcDecode,
  ed25519FromMultikey,
  jcsCanonicalize,
  sha256,
} from "./jcs";

afterEach(async () => {
  await forgetConsoleKey();
  resetConsoleKeyCacheForTests();
});

describe("key custody", () => {
  // The whole point of the module, and the defect fixed in
  // affinidi-webvh-service#210 (`extractable: true` on the file this was
  // lifted from). A flip back would be invisible in every functional test —
  // the key signs identically either way — so it is asserted directly.
  it("generates a private key that does not export, and a public key that does", async () => {
    const key = await generateConsoleKey();

    expect(key.keypair.privateKey.extractable).toBe(false);
    await expect(
      crypto.subtle.exportKey("pkcs8", key.keypair.privateKey),
    ).rejects.toThrow();
    await expect(
      crypto.subtle.exportKey("jwk", key.keypair.privateKey),
    ).rejects.toThrow();

    // `extractable: false` costs nothing: the public half still exports, which
    // is the claim the `true` in the lifted file was wrongly justified by.
    const raw = new Uint8Array(
      await crypto.subtle.exportKey("raw", key.keypair.publicKey),
    );
    expect(raw.length).toBe(32);
  });

  it("derives a did:key that is the public key", async () => {
    const key = await generateConsoleKey();
    const raw = new Uint8Array(
      await crypto.subtle.exportKey("raw", key.keypair.publicKey),
    );

    expect(key.consoleDid.startsWith("did:key:z6Mk")).toBe(true);
    expect(ed25519FromMultikey(key.consoleDid.slice("did:key:".length))).toEqual(
      raw,
    );
    // `did_key_to_vm`: a `did:key` carries its own verification method.
    expect(key.verificationMethod).toBe(
      `${key.consoleDid}#${key.consoleDid.slice("did:key:".length)}`,
    );
  });

  it("restores the same key after a reload, still non-extractable", async () => {
    const first = await generateConsoleKey();
    // What a page reload does: the module cache is gone, storage is not.
    resetConsoleKeyCacheForTests();

    const restored = await loadConsoleKey();
    expect(restored?.consoleDid).toBe(first.consoleDid);
    expect(restored?.keypair.privateKey.extractable).toBe(false);
  });

  it("reports no key when the profile has never generated one", async () => {
    expect(await loadConsoleKey()).toBeNull();
  });

  it("forgets the key when asked", async () => {
    await generateConsoleKey();
    await forgetConsoleKey();
    resetConsoleKeyCacheForTests();
    expect(await loadConsoleKey()).toBeNull();
  });
});

describe("availability", () => {
  it("reports Ed25519 as available where it is", async () => {
    expect(await ed25519Available()).toBe(true);
  });

  it("reports it unavailable rather than throwing when generateKey refuses", async () => {
    // A browser below the floor — Chrome <137, Firefox <130, Safari <17 —
    // throws `NotSupportedError` from `generateKey`. The console must answer
    // "no" and stay on the bearer routes, not take a screen down.
    resetConsoleKeyCacheForTests();
    const real = crypto.subtle.generateKey;
    Object.defineProperty(crypto.subtle, "generateKey", {
      configurable: true,
      value: () => Promise.reject(new DOMException("nope", "NotSupportedError")),
    });
    try {
      expect(await ed25519Available()).toBe(false);
    } finally {
      Object.defineProperty(crypto.subtle, "generateKey", {
        configurable: true,
        value: real,
      });
      resetConsoleKeyCacheForTests();
    }
  });
});

/** Recompute the bytes the verifier will hash, from the document as sent. */
async function hashDataFor(doc: SignedTrustTaskDocument) {
  const { proof, ...unsigned } = doc;
  const { proofValue: _dropped, ...proofConfig } = proof;
  const configHash = await sha256(jcsCanonicalize(proofConfig));
  const docHash = await sha256(jcsCanonicalize(unsigned));
  const out = new Uint8Array(64);
  out.set(configHash, 0);
  out.set(docHash, 32);
  return out;
}

describe("eddsa-jcs-2022 proof", () => {
  it("signs the bytes an independent reader of the document computes", async () => {
    // Deliberately not "the signer agrees with itself": the hashing is redone
    // here from the document *as it would go on the wire*, the way the daemon
    // does, and the signature is checked against the public key.
    const key = await generateConsoleKey();
    const doc = buildTrustTaskDocument({
      typeUri: "https://trusttasks.org/spec/vtc/members/purge/0.1",
      payload: { did: "did:key:z6MkTarget" },
      issuer: key.consoleDid,
      recipient: "did:webvh:scid:example.com:vtc",
    });
    const signed = await signTrustTaskDocument(doc, key);

    const signature = signatureBytes(signed);
    expect(signature.length).toBe(64);

    const ok = await crypto.subtle.verify(
      { name: "Ed25519" },
      key.keypair.publicKey,
      signature,
      await hashDataFor(signed),
    );
    expect(ok).toBe(true);
  });

  it("carries exactly the six members the verifier re-parses", async () => {
    // The daemon round-trips `proof` through a fixed `DataIntegrityProof`
    // struct before re-hashing, so an extra member would be dropped there and
    // the signature would not verify.
    const key = await generateConsoleKey();
    const signed = await signTrustTaskDocument(
      buildTrustTaskDocument({
        typeUri: "https://trusttasks.org/spec/vtc/members/purge/0.1",
        payload: { did: "did:key:z6MkTarget" },
        issuer: key.consoleDid,
        recipient: "did:webvh:scid:example.com:vtc",
      }),
      key,
    );

    expect(Object.keys(signed.proof).sort()).toEqual([
      "created",
      "cryptosuite",
      "proofPurpose",
      "proofValue",
      "type",
      "verificationMethod",
    ]);
    expect(signed.proof.type).toBe("DataIntegrityProof");
    expect(signed.proof.cryptosuite).toBe("eddsa-jcs-2022");
    expect(signed.proof.proofPurpose).toBe("assertionMethod");
    expect(signed.proof.verificationMethod).toBe(key.verificationMethod);
    expect(signed.proof.proofValue.startsWith("z")).toBe(true);
  });

  it("back-dates `created` by a minute", async () => {
    // A Data-Integrity verifier refuses a `created` in *its* future with a
    // 60s allowance, and nothing bounds how old it may be. The console's clock
    // is the operator's laptop, so the margin is free and the absence of it is
    // a race between skew and latency.
    const key = await generateConsoleKey();
    const now = new Date("2026-09-23T10:15:00.000Z");
    const signed = await signTrustTaskDocument(
      buildTrustTaskDocument({
        typeUri: "https://trusttasks.org/spec/vtc/members/purge/0.1",
        payload: { did: "did:key:z6MkTarget" },
        issuer: key.consoleDid,
        recipient: "did:webvh:scid:example.com:vtc",
      }),
      key,
      { now },
    );
    expect(signed.proof.created).toBe("2026-09-23T10:14:00Z");
  });

  it("stamps both timestamps at whole seconds, with no fractional part", async () => {
    // The verifier re-serialises the *parsed* document before canonicalising,
    // and chrono writes a `DateTime<Utc>` with no fractional digits when the
    // sub-second part is zero. `toISOString()` always writes three, so a
    // document stamped on a whole second would verify nowhere — once in a
    // thousand, and never twice. `console_signed_document.rs` is what proves
    // the round trip; this is what fails fast if someone reverts it.
    const key = await generateConsoleKey();
    const doc = buildTrustTaskDocument({
      typeUri: "https://trusttasks.org/spec/vtc/members/purge/0.1",
      payload: {},
      issuer: key.consoleDid,
      recipient: "did:webvh:x",
      issuedAt: new Date("2026-09-23T10:15:00.123Z"),
    });
    expect(doc.issuedAt).toBe("2026-09-23T10:15:00Z");

    const signed = await signTrustTaskDocument(doc, key, {
      now: new Date("2026-09-23T10:15:00.789Z"),
    });
    expect(signed.proof.created).toBe("2026-09-23T10:14:00Z");
  });

  it("signs the document without its proof, so a re-sign is not self-referential", async () => {
    // Hand the signer a document that already carries a proof. If `proof` were
    // included in the hashed document the second signature would cover the
    // first, and the daemon — which strips `proof` before hashing — would
    // refuse it.
    const key = await generateConsoleKey();
    const doc = buildTrustTaskDocument({
      typeUri: "https://trusttasks.org/spec/vtc/members/purge/0.1",
      payload: { did: "did:key:z6MkTarget" },
      issuer: key.consoleDid,
      recipient: "did:webvh:scid:example.com:vtc",
    });
    const once = await signTrustTaskDocument(doc, key);
    const twice = await signTrustTaskDocument(once, key, {
      now: new Date(Date.parse(once.proof.created) + 60_000),
    });

    const ok = await crypto.subtle.verify(
      { name: "Ed25519" },
      key.keypair.publicKey,
      signatureBytes(twice),
      await hashDataFor(twice),
    );
    expect(ok).toBe(true);
  });

  it("builds an addressed document with the members the spine requires", async () => {
    const key = await generateConsoleKey();
    const doc = buildTrustTaskDocument({
      typeUri: "https://trusttasks.org/spec/vtc/members/purge/0.1",
      payload: { did: "did:key:z6MkTarget" },
      issuer: key.consoleDid,
      recipient: "did:webvh:scid:example.com:vtc",
    });

    // `id` fresh per document (SPEC §7.2 replay record), `issuedAt` present
    // (the VTC's freshness policy requires it), `recipient` present (§4.8.2
    // audience binding refuses a signed document without one).
    expect(doc.id).toMatch(/^urn:uuid:[0-9a-f-]{36}$/);
    expect(Date.parse(doc.issuedAt)).toBeGreaterThan(0);
    expect(doc.recipient).toBe("did:webvh:scid:example.com:vtc");
    // SPEC §4.7: the proof's verificationMethod DID must be the issuer.
    expect(doc.issuer).toBe(key.consoleDid);
    expect(
      (await signTrustTaskDocument(doc, key)).proof.verificationMethod.split(
        "#",
      )[0],
    ).toBe(doc.issuer);
  });

  it("refuses a proofValue whose signature is the wrong length", async () => {
    const key = await generateConsoleKey();
    const real = crypto.subtle.sign.bind(crypto.subtle);
    Object.defineProperty(crypto.subtle, "sign", {
      configurable: true,
      value: () => Promise.resolve(new ArrayBuffer(63)),
    });
    try {
      await expect(
        signTrustTaskDocument(
          buildTrustTaskDocument({
            typeUri: "https://trusttasks.org/spec/vtc/members/purge/0.1",
            payload: {},
            issuer: key.consoleDid,
            recipient: "did:webvh:x",
          }),
          key,
        ),
      ).rejects.toThrow(/signature length/);
    } finally {
      Object.defineProperty(crypto.subtle, "sign", {
        configurable: true,
        value: real,
      });
    }
  });
});

describe("the 64 KiB signed door, against `members/update`'s extensions bag", () => {
  // The signed endpoint rides the governed unauth chain: `UNAUTH_BODY_SIZE =
  // 64 * 1024`, enforced as a refusal (413) rather than a truncation. A
  // member's `extensions` bag is capped separately at
  // `MEMBER_EXTENSIONS_MAX_BYTES = 16 * 1024`. The arithmetic is the question
  // #1684 asks be checked before moving `members/update`, so check it rather
  // than assume it.
  it("fits a maximal extensions bag with room to spare", async () => {
    const key = await generateConsoleKey();

    // 16 KiB of `extensions` as serialised — the largest the daemon stores.
    let extensions: Record<string, string> = {};
    let filler = "";
    while (JSON.stringify({ ...extensions, note: filler }).length <= 16 * 1024) {
      filler += "x".repeat(256);
    }
    extensions = { note: filler.slice(0, filler.length - 256) };
    expect(JSON.stringify(extensions).length).toBeLessThanOrEqual(16 * 1024);

    const signed = await signTrustTaskDocument(
      buildTrustTaskDocument({
        typeUri: "https://trusttasks.org/spec/vtc/members/update/0.1",
        payload: {
          did: "did:webvh:QmScidScidScid:community.example:member-with-a-long-name",
          label: "x".repeat(256),
          role: "moderator",
          publishConsent: true,
          departurePreference: "tombstone",
          extensions,
        },
        issuer: key.consoleDid,
        recipient: "did:webvh:QmScidScidScid:community.example:vtc",
      }),
      key,
    );

    const bytes = new TextEncoder().encode(JSON.stringify(signed)).length;
    expect(bytes).toBeLessThan(64 * 1024);
    // Recorded rather than merely asserted: the margin is what says whether a
    // later field can be added without re-doing this sum. Measured at ~17 KiB,
    // so roughly 47 KiB of headroom.
    expect(bytes).toBeLessThan(18 * 1024);
  });
});

/** The raw 64 signature bytes behind a multibase `proofValue`. */
function signatureBytes(doc: SignedTrustTaskDocument) {
  const value = doc.proof.proofValue;
  if (!value.startsWith("z")) throw new Error("proofValue is not base58btc multibase");
  return base58btcDecode(value.slice(1));
}
