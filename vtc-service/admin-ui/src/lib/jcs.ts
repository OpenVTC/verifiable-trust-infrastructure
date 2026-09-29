// Canonicalisation and multibase primitives for `eddsa-jcs-2022` Data
// Integrity proofs.
//
// Kept apart from `console-key.ts` because the signer and any future verifier
// MUST hash byte-identical input, and because these are the parts worth
// testing against the Rust `serde_jcs` output on their own. Zero dependencies:
// the console's CSP is `script-src 'self'` with no `wasm-unsafe-eval`, so a
// WASM or CDN-hosted canonicaliser would need the policy widened, which is a
// reason not to reach for one.
//
// Lifted, near-verbatim, from the two implementations that already speak this
// wire format — `pnm-browser-plugin`'s `packages/core/src/trust-tasks/
// canonical.ts` and `affinidi-webvh-service`'s `did-hosting-ui/lib/
// session-key.ts`, which are the same code. The caveat their authors record
// applies here too: this is a "good enough for Trust Task documents" JCS
// rather than a conformance-tested one — number serialisation leans on
// `String(v)` rather than RFC 8785's ES6 `Number::toString`, and there is no
// Unicode normalisation. Trust Task documents are strings, integers and
// nested objects. `jcs.test.ts` pins the cases that matter against the bytes
// the Rust verifier canonicalises.

/**
 * Canonicalise a JSON value per RFC 8785 (JSON Canonicalization Scheme): the
 * input `eddsa-jcs-2022` feeds to SHA-256.
 *
 * Minified JSON, object keys sorted lexicographically by UTF-16 code unit,
 * strict JSON-only string escaping per ECMA-404, no trailing commas.
 *
 * Throws on non-finite numbers, `undefined`, functions, symbols and circular
 * references — JCS models none of them, and a signature over silently-dropped
 * data verifies nowhere.
 */
export function jcsCanonicalize(value: unknown): string {
  const seen = new WeakSet<object>();
  return enc(value);

  function enc(v: unknown): string {
    if (v === null) return "null";
    if (v === true) return "true";
    if (v === false) return "false";
    if (typeof v === "number") {
      if (!Number.isFinite(v)) throw new Error("JCS rejects non-finite numbers");
      // ECMA-404 minimal numeric form; `-0` collapses to `0`.
      if (Object.is(v, -0)) return "0";
      return String(v);
    }
    if (typeof v === "string") return encString(v);
    if (Array.isArray(v)) {
      if (seen.has(v)) throw new Error("circular reference in JCS input");
      seen.add(v);
      const out = "[" + v.map(enc).join(",") + "]";
      seen.delete(v);
      return out;
    }
    if (typeof v === "object") {
      const obj = v as Record<string, unknown>;
      if (seen.has(obj)) throw new Error("circular reference in JCS input");
      seen.add(obj);
      // `Array.prototype.sort` with no comparator orders by UTF-16 code
      // unit, which is exactly what JCS asks for.
      const keys = Object.keys(obj).sort();
      const parts = keys.map((k) => encString(k) + ":" + enc(obj[k]));
      seen.delete(obj);
      return "{" + parts.join(",") + "}";
    }
    throw new Error(`JCS cannot encode value of type ${typeof v}`);
  }

  function encString(s: string): string {
    let out = '"';
    for (let i = 0; i < s.length; i++) {
      const ch = s.charCodeAt(i);
      if (ch === 0x22) out += '\\"';
      else if (ch === 0x5c) out += "\\\\";
      else if (ch === 0x08) out += "\\b";
      else if (ch === 0x0c) out += "\\f";
      else if (ch === 0x0a) out += "\\n";
      else if (ch === 0x0d) out += "\\r";
      else if (ch === 0x09) out += "\\t";
      else if (ch < 0x20) out += "\\u" + ch.toString(16).padStart(4, "0");
      else out += s[i];
    }
    return out + '"';
  }
}

// ── base58btc (Bitcoin alphabet) ────────────────────────────────────────
//
// The `z`-prefixed multibase encoding, used for both the `did:key` multikey
// and the Ed25519 `proofValue`.

const B58_ALPHABET =
  "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/** Encode bytes as base58btc. Leading zero bytes become leading `1`s. */
export function base58btcEncode(bytes: Uint8Array): string {
  let zeros = 0;
  while (zeros < bytes.length && bytes[zeros] === 0) zeros++;

  // base-256 → base-58 by repeated division.
  const digits: number[] = [];
  for (let i = 0; i < bytes.length; i++) {
    let carry = bytes[i] as number;
    for (let j = 0; j < digits.length; j++) {
      carry += (digits[j] as number) << 8;
      digits[j] = carry % 58;
      carry = (carry / 58) | 0;
    }
    while (carry > 0) {
      digits.push(carry % 58);
      carry = (carry / 58) | 0;
    }
  }

  let out = "";
  for (let z = 0; z < zeros; z++) out += B58_ALPHABET[0];
  for (let i = digits.length - 1; i >= 0; i--) {
    out += B58_ALPHABET[digits[i] as number];
  }
  return out;
}

/** Decode a base58btc string. Throws on a character outside the alphabet. */
export function base58btcDecode(s: string): Uint8Array<ArrayBuffer> {
  let zeros = 0;
  while (zeros < s.length && s[zeros] === "1") zeros++;

  const bytes: number[] = [];
  for (let i = 0; i < s.length; i++) {
    const ch = s[i] as string;
    const value = B58_ALPHABET.indexOf(ch);
    if (value === -1) throw new Error(`invalid base58btc character: ${ch}`);
    let carry = value;
    for (let j = 0; j < bytes.length; j++) {
      carry += (bytes[j] as number) * 58;
      bytes[j] = carry & 0xff;
      carry >>= 8;
    }
    while (carry > 0) {
      bytes.push(carry & 0xff);
      carry >>= 8;
    }
  }

  const out = new Uint8Array(zeros + bytes.length);
  for (let i = 0; i < bytes.length; i++) {
    out[zeros + bytes.length - 1 - i] = bytes[i] as number;
  }
  return out;
}

/**
 * Encode a raw 32-byte Ed25519 public key as the W3C Data Integrity multikey:
 * multicodec `0xed 0x01` followed by the key, base58btc with the `z`
 * multibase prefix. Produces the canonical `z6Mk…` form.
 */
export function ed25519Multikey(rawPublicKey: Uint8Array): string {
  if (rawPublicKey.length !== 32) {
    throw new Error(
      `Ed25519 multikey expects a 32-byte public key, got ${rawPublicKey.length}`,
    );
  }
  const prefixed = new Uint8Array(34);
  prefixed[0] = 0xed;
  prefixed[1] = 0x01;
  prefixed.set(rawPublicKey, 2);
  return "z" + base58btcEncode(prefixed);
}

/** The raw 32 bytes behind a `z6Mk…` Ed25519 multikey. Throws if it is not one. */
export function ed25519FromMultikey(multikey: string): Uint8Array<ArrayBuffer> {
  if (!multikey.startsWith("z")) {
    throw new Error("multikey is not base58btc multibase (`z`-prefixed)");
  }
  const bytes = base58btcDecode(multikey.slice(1));
  if (bytes.length !== 34 || bytes[0] !== 0xed || bytes[1] !== 0x01) {
    throw new Error("multikey is not an Ed25519 (0xed01) multikey");
  }
  // A copy rather than a view, so the result owns an `ArrayBuffer` and can be
  // handed to WebCrypto as a `BufferSource`.
  const key = new Uint8Array(32);
  key.set(bytes.subarray(2));
  return key;
}

/** SHA-256 over the UTF-8 encoding of `input`. */
export async function sha256(input: string): Promise<Uint8Array<ArrayBuffer>> {
  const buf = new TextEncoder().encode(input);
  return new Uint8Array(await crypto.subtle.digest("SHA-256", buf));
}
