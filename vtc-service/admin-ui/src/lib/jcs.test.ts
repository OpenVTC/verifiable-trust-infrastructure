import { describe, expect, it } from "vitest";

import {
  base58btcDecode,
  base58btcEncode,
  ed25519FromMultikey,
  ed25519Multikey,
  jcsCanonicalize,
  sha256,
} from "./jcs";

describe("JCS canonicalisation", () => {
  it("sorts object keys by UTF-16 code unit and minifies", () => {
    expect(jcsCanonicalize({ b: 1, a: 2, A: 3 })).toBe('{"A":3,"a":2,"b":1}');
  });

  it("sorts nested objects too, and leaves array order alone", () => {
    expect(jcsCanonicalize({ z: [{ b: 1, a: 2 }, 3], a: null })).toBe(
      '{"a":null,"z":[{"a":2,"b":1},3]}',
    );
  });

  // Presence, not value. This is the property the whole signature rests on:
  // the verifier hashes the document with `proof` *removed*, so a document
  // carrying `proof: null` canonicalises differently and verifies nowhere.
  it("distinguishes an absent member from a null one", () => {
    expect(jcsCanonicalize({ a: 1 })).not.toBe(jcsCanonicalize({ a: 1, proof: null }));
    expect(jcsCanonicalize({ a: 1, proof: null })).toBe('{"a":1,"proof":null}');
  });

  it("escapes only what JSON requires", () => {
    expect(jcsCanonicalize('a"b\\c\nd\te\u0001f')).toBe(
      '"a\\"b\\\\c\\nd\\te\\u0001f"',
    );
  });

  it("keeps non-ASCII as itself rather than escaping it", () => {
    // RFC 8785 emits the UTF-8 character, not a \u escape. The daemon's
    // `serde_jcs` does the same, and an operator label is the likely carrier.
    expect(jcsCanonicalize({ label: "Work laptop — Chrome" })).toBe(
      '{"label":"Work laptop — Chrome"}',
    );
  });

  it("collapses negative zero and refuses what JCS cannot model", () => {
    expect(jcsCanonicalize(-0)).toBe("0");
    expect(() => jcsCanonicalize(NaN)).toThrow(/non-finite/);
    expect(() => jcsCanonicalize(undefined)).toThrow(/cannot encode/);
    const circular: Record<string, unknown> = {};
    circular.self = circular;
    expect(() => jcsCanonicalize(circular)).toThrow(/circular/);
  });

  it("canonicalises a Trust Task document the way the daemon parses one", () => {
    // Field order as a browser would naturally write it; JCS output is sorted.
    expect(
      jcsCanonicalize({
        id: "urn:uuid:0d4b",
        type: "https://trusttasks.org/spec/vtc/members/purge/0.1",
        issuer: "did:key:z6Mk",
        recipient: "did:webvh:scid:example.com:vtc",
        issuedAt: "2026-09-23T10:15:00.000Z",
        payload: { did: "did:key:z6MkTarget" },
      }),
    ).toBe(
      '{"id":"urn:uuid:0d4b",' +
        '"issuedAt":"2026-09-23T10:15:00.000Z",' +
        '"issuer":"did:key:z6Mk",' +
        '"payload":{"did":"did:key:z6MkTarget"},' +
        '"recipient":"did:webvh:scid:example.com:vtc",' +
        '"type":"https://trusttasks.org/spec/vtc/members/purge/0.1"}',
    );
  });
});

describe("base58btc", () => {
  it("round-trips", () => {
    const bytes = new Uint8Array([0, 0, 1, 2, 3, 250, 255]);
    expect(base58btcDecode(base58btcEncode(bytes))).toEqual(bytes);
  });

  it("preserves leading zero bytes as leading ones", () => {
    expect(base58btcEncode(new Uint8Array([0, 0, 1]))).toBe("112");
  });

  it("refuses a character outside the alphabet", () => {
    expect(() => base58btcDecode("0OIl")).toThrow(/invalid base58btc/);
  });
});

describe("Ed25519 multikey", () => {
  // The multicodec prefix is what makes a 32-byte key render as `z6Mk…`;
  // getting it wrong yields a `did:key` that resolves to nothing.
  it("prefixes 0xed 0x01 and renders as z6Mk…", () => {
    const key = new Uint8Array(32).fill(7);
    const multikey = ed25519Multikey(key);
    expect(multikey.startsWith("z6Mk")).toBe(true);
    expect(base58btcDecode(multikey.slice(1)).slice(0, 2)).toEqual(
      new Uint8Array([0xed, 0x01]),
    );
    expect(ed25519FromMultikey(multikey)).toEqual(key);
  });

  it("refuses a key that is not 32 bytes", () => {
    expect(() => ed25519Multikey(new Uint8Array(31))).toThrow(/32-byte/);
  });

  it("refuses a multikey that is not Ed25519", () => {
    const notEd = new Uint8Array(34);
    notEd[0] = 0xec; // X25519
    notEd[1] = 0x01;
    expect(() => ed25519FromMultikey("z" + base58btcEncode(notEd))).toThrow(
      /not an Ed25519/,
    );
  });
});

describe("sha256", () => {
  it("matches the published digest of the empty string", () => {
    return sha256("").then((d) => {
      expect(
        [...d].map((b) => b.toString(16).padStart(2, "0")).join(""),
      ).toBe("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    });
  });
});
