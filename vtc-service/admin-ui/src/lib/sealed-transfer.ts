// Sealing to the community in this browser: the workspace's one secret-bearing
// wire format (`vta_sdk::sealed_transfer`), sealing side only.
//
// `vtc/storage/credentials/set/0.2` requires the administrator's own client to seal
// a `sealed` config's credential to the community before it leaves the page, so
// no transport, relay or log between here and the community can read it. This is
// that client. It produces byte-for-byte the framing the Rust producer does, and
// the community opens it with the same `open_bundle`:
//
// - The payload is `SealedPayloadV1::StorageCredential`, CBOR-encoded as serde
//   and ciborium encode it: an externally tagged map, `{"storage_credential": …}`.
// - It is cut into fragments of at most 32 KiB, each wrapped in a CBOR
//   `ChunkPlaintext` (byte fields as arrays of integers, as serde writes
//   `[u8; N]` and `Vec<u8>`), the first carrying the producer's DID and a
//   `PinnedOnly` assertion: the request's own proof covers the block and its digest.
// - Each chunk is sealed with HPKE base mode (X25519-HKDF-SHA256, HKDF-SHA256,
//   ChaCha20-Poly1305, info `vta-sealed-transfer/v1`; the suite is fixed, never
//   negotiated) under an AAD binding version, bundle id, chunk position and the
//   digest algorithm, and the `{kem_encap, aead_ciphertext}` pair CBOR-encoded.
// - The chunks are ASCII-armored (`-----BEGIN VTA SEALED BUNDLE-----`, CRC-24),
//   and the digest is SHA-256 over the sealed chunks in order, as a multibase
//   sha2-256 multihash.
//
// The recipient is the X25519 form of the community DID's Ed25519 key — `#key-0`,
// as `cnm storage credentials set` picks it — read from the DID document this
// community serves (`/.well-known/did.jsonl`). This page trusts that origin for
// the key no more than it already trusts it for the code doing the sealing.
//
// `sealed-transfer.vectors.json` is a block this module sealed to a fixed
// community key; `vtc-service`'s `storage_credentials` tests open it with the
// Rust opener, so a drift on either side fails a test.

import { CipherSuite, HkdfSha256 } from "@hpke/core";
import { Chacha20Poly1305 } from "@hpke/chacha20poly1305";
import { DhkemX25519HkdfSha256 } from "@hpke/dhkem-x25519";
import { ed25519 } from "@noble/curves/ed25519.js";
import { encode as cborEncode } from "cborg";

import { base58btcDecode, base58btcEncode } from "./jcs";
import type { SealedStorageCredential } from "./wire-types";

/** HPKE `info`, domain-bound to this format. */
const HPKE_INFO = new TextEncoder().encode("vta-sealed-transfer/v1");
/** `chunk::VERSION`. */
const VERSION = 1;
/** `chunk::MAX_PAYLOAD_FRAGMENT`. */
const MAX_PAYLOAD_FRAGMENT = 32 * 1024;
/** `DEFAULT_DIGEST_ALGO`. */
const DIGEST_ALGO = "sha256";
/** The multicodec prefix of an Ed25519 public key (`0xed01`). */
const ED25519_PUB_CODEC = [0xed, 0x01] as const;

/** A sealed block and the digest the request pins it with. */
export interface SealedBlock {
  /** The ASCII-armored bundle: the request's `sealed`. */
  readonly armor: string;
  /** SHA-256 over the sealed chunks, multibase: the request's `digestMultibase`. */
  readonly digestMultibase: string;
}

/** Why this browser cannot seal to the community; the terminal still can. */
export class SealingUnavailableError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "SealingUnavailableError";
  }
}

function suite(): CipherSuite {
  return new CipherSuite({
    kem: new DhkemX25519HkdfSha256(),
    kdf: new HkdfSha256(),
    aead: new Chacha20Poly1305(),
  });
}

// ── The recipient ───────────────────────────────────────────────────────

/**
 * The X25519 public key of an Ed25519 `publicKeyMultibase` (base58btc, with or
 * without the `0xed01` multicodec prefix, as `decode_ed25519_public_key_multibase`
 * reads it).
 */
export function x25519FromEd25519Multibase(multibase: string): Uint8Array {
  if (!multibase.startsWith("z")) {
    throw new SealingUnavailableError("the community's key is not base58btc multibase");
  }
  const raw = base58btcDecode(multibase.slice(1));
  let key: Uint8Array;
  if (raw.length === 34 && raw[0] === ED25519_PUB_CODEC[0] && raw[1] === ED25519_PUB_CODEC[1]) {
    key = raw.slice(2);
  } else if (raw.length === 32) {
    key = raw;
  } else {
    throw new SealingUnavailableError("the community's key is not an Ed25519 public key");
  }
  return ed25519.utils.toMontgomery(key);
}

interface VerificationMethodLike {
  id?: unknown;
  publicKeyMultibase?: unknown;
}

/** The Ed25519 key a DID document lists to seal to: `#key-0`, else the first. */
function sealingMultibase(doc: unknown): string | null {
  const methods = (doc as { verificationMethod?: unknown } | null)?.verificationMethod;
  if (!Array.isArray(methods)) return null;
  const usable = (m: VerificationMethodLike) =>
    typeof m.publicKeyMultibase === "string" ? m.publicKeyMultibase : null;
  const keyZero = (methods as VerificationMethodLike[]).find(
    (m) => typeof m.id === "string" && m.id.endsWith("#key-0") && usable(m) !== null,
  );
  if (keyZero) return usable(keyZero);
  for (const m of methods as VerificationMethodLike[]) {
    const mb = usable(m);
    if (mb === null) continue;
    try {
      x25519FromEd25519Multibase(mb);
      return mb;
    } catch {
      // Not an Ed25519 key; try the next.
    }
  }
  return null;
}

/** The DID document in the last entry of a `did:webvh` log. */
export function lastLogState(log: string): unknown {
  const lines = log.split("\n").filter((l) => l.trim() !== "");
  const last = lines.at(-1);
  if (!last) return null;
  try {
    return (JSON.parse(last) as { state?: unknown }).state ?? null;
  } catch {
    return null;
  }
}

/**
 * The X25519 key to seal to for `communityDid`: from the DID itself for a
 * `did:key`, else from the `did.jsonl` this community serves, whose document must
 * be that DID's.
 */
export async function communitySealingKey(
  communityDid: string,
  fetchLog: () => Promise<Response> = () =>
    fetch("/.well-known/did.jsonl", { headers: { Accept: "text/jsonl" } }),
): Promise<Uint8Array> {
  if (communityDid.startsWith("did:key:")) {
    return x25519FromEd25519Multibase(communityDid.slice("did:key:".length).split("#")[0] ?? "");
  }
  let res: Response;
  try {
    res = await fetchLog();
  } catch {
    throw new SealingUnavailableError("this community's DID document could not be read");
  }
  if (!res.ok) {
    throw new SealingUnavailableError(
      `this community does not serve its own DID document here (HTTP ${res.status})`,
    );
  }
  const doc = lastLogState(await res.text());
  if ((doc as { id?: unknown } | null)?.id !== communityDid) {
    throw new SealingUnavailableError("the DID document served here is not this community's");
  }
  const mb = sealingMultibase(doc);
  if (!mb) {
    throw new SealingUnavailableError("this community's DID document lists no Ed25519 key to seal to");
  }
  return x25519FromEd25519Multibase(mb);
}

// ── Sealing ─────────────────────────────────────────────────────────────

/** `ChunkPlaintext::aad`. */
function chunkAad(bundleId: Uint8Array, index: number, total: number): Uint8Array {
  const algo = new TextEncoder().encode(DIGEST_ALGO);
  const out = new Uint8Array(1 + 16 + 2 + 2 + 1 + algo.length);
  const view = new DataView(out.buffer);
  out[0] = VERSION;
  out.set(bundleId, 1);
  view.setUint16(17, index);
  view.setUint16(19, total);
  out[21] = algo.length;
  out.set(algo, 22);
  return out;
}

/** serde's encoding of `[u8; N]` and `Vec<u8>`: an array of integers. */
const byteArray = (b: Uint8Array): number[] => Array.from(b);

/** Test seams: a fixed bundle id and HPKE ephemeral key, for the shared vectors. */
export interface SealOptions {
  readonly bundleId?: Uint8Array;
  /** Keying material each chunk's ephemeral X25519 key is derived from (HPKE
   *  `DeriveKeyPair`), so a seal is reproducible. Never set outside tests. */
  readonly ephemeralIkm?: readonly Uint8Array[];
}

/**
 * Seal an externally tagged `SealedPayloadV1` value (`{"storage_credential": …}`)
 * to `recipient`, produced by `producerDid` with a `PinnedOnly` assertion.
 */
export async function sealPayload(
  recipient: Uint8Array,
  producerDid: string,
  payload: Record<string, unknown>,
  options: SealOptions = {},
): Promise<SealedBlock> {
  const bundleId = options.bundleId ?? crypto.getRandomValues(new Uint8Array(16));
  if (bundleId.length !== 16) throw new Error("a bundle id is 16 bytes");

  const payloadBytes = cborEncode(payload);
  const total = Math.max(1, Math.ceil(payloadBytes.length / MAX_PAYLOAD_FRAGMENT));
  if (total > 0xffff) throw new Error("payload too large for u16 chunk count");

  const hpke = suite();
  const recipientKey = await hpke.kem.deserializePublicKey(recipient);
  const chunks: Uint8Array[] = [];
  for (let i = 0; i < total; i++) {
    const plaintext = cborEncode({
      version: VERSION,
      bundle_id: byteArray(bundleId),
      chunk_index: i,
      total_chunks: total,
      ...(i === 0
        ? {
            producer_did: producerDid,
            producer_assertion: { producer_did: producerDid, proof: { type: "pinned_only" } },
          }
        : {}),
      payload_fragment: byteArray(
        payloadBytes.subarray(i * MAX_PAYLOAD_FRAGMENT, (i + 1) * MAX_PAYLOAD_FRAGMENT),
      ),
    });
    const ekm = options.ephemeralIkm?.[i];
    const { ct, enc } = await hpke.seal(
      { recipientPublicKey: recipientKey, info: HPKE_INFO, ...(ekm ? { ekm } : {}) },
      plaintext,
      chunkAad(bundleId, i, total),
    );
    chunks.push(
      cborEncode({
        kem_encap: byteArray(new Uint8Array(enc)),
        aead_ciphertext: byteArray(new Uint8Array(ct)),
      }),
    );
  }

  return {
    armor: armor(bundleId, chunks),
    digestMultibase: await digestMultibase(chunks),
  };
}

/** Seal a storage config's credential to the community. */
export function sealStorageCredential(
  recipient: Uint8Array,
  producerDid: string,
  credential: SealedStorageCredential,
  options?: SealOptions,
): Promise<SealedBlock> {
  // As JSON, which is what the community validates: an absent optional member
  // (`sessionToken`) must be absent, never an `undefined` CBOR cannot carry.
  const asJson = JSON.parse(JSON.stringify(credential)) as SealedStorageCredential;
  return sealPayload(recipient, producerDid, { storage_credential: asJson }, options);
}

// ── Armor and digest ────────────────────────────────────────────────────

/** OpenPGP's CRC-24 (`armor::crc24`). */
export function crc24(data: Uint8Array): number {
  let crc = 0xb704ce;
  for (const b of data) {
    crc ^= b << 16;
    for (let i = 0; i < 8; i++) {
      crc <<= 1;
      if (crc & 0x1000000) crc ^= 0x1864cfb;
    }
  }
  return crc & 0xffffff;
}

function base64(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}

function hex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

/** `armor::encode`. */
function armor(bundleId: Uint8Array, chunks: readonly Uint8Array[]): string {
  return chunks
    .map((sealed, i) => {
      const lines = [
        "-----BEGIN VTA SEALED BUNDLE-----",
        "Version: 1",
        `Bundle-Id: ${hex(bundleId)}`,
        `Chunk: ${i + 1}/${chunks.length}`,
        `Digest-Algo: ${DIGEST_ALGO}`,
        "",
      ];
      const b64 = base64(sealed);
      for (let at = 0; at < b64.length; at += 64) lines.push(b64.slice(at, at + 64));
      const crc = crc24(sealed);
      lines.push(`=${base64(new Uint8Array([(crc >> 16) & 0xff, (crc >> 8) & 0xff, crc & 0xff]))}`);
      lines.push("-----END VTA SEALED BUNDLE-----");
      return `${lines.join("\n")}\n`;
    })
    .join("\n");
}

/** `bundle_digest_multibase`: a sha2-256 multihash, base58btc. */
async function digestMultibase(chunks: readonly Uint8Array[]): Promise<string> {
  const all = new Uint8Array(chunks.reduce((n, c) => n + c.length, 0));
  let at = 0;
  for (const c of chunks) {
    all.set(c, at);
    at += c.length;
  }
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", all as BufferSource));
  const multihash = new Uint8Array(2 + digest.length);
  multihash.set([0x12, 0x20]);
  multihash.set(digest, 2);
  return `z${base58btcEncode(multihash)}`;
}
