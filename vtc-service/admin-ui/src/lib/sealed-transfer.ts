// Sealing to the community in this browser: the workspace's one secret-bearing
// wire format (`vta_sdk::sealed_transfer`), sealing side only.
//
// `vtc/storage/credentials/set/0.3` requires the administrator's own client to seal
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
// The recipient is the X25519 form of the community DID's Ed25519 signing key. A
// browser cannot resolve and verify every DID method — a `did:webs` means a KERI
// key event stream, a hosted `did:webvh` a log from another origin — so the key is
// asked of the community itself (`vtc/storage/credentials/recipient/0.1`), on the
// same origin the credential then goes to. This page trusts that origin for the key
// no more than it already trusts it for the code doing the sealing.
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

/** `vtc/storage/credentials/recipient/0.1`'s answer. */
export interface RecipientAnswer {
  readonly communityDid: string;
  readonly verificationMethod: string;
  readonly recipientKey: string;
}

/** The refusal a community gives when its key is not the one its document publishes. */
const NOT_PUBLISHED = "vtc/storage/credentials/recipient:notPublished";

/**
 * The X25519 key to seal to for `communityDid`: from the DID itself for a
 * `did:key`, else the community's own answer to `credentials/recipient`, held to
 * name that DID (item 4) and sealed to as given (item 5).
 */
export async function communitySealingKey(
  communityDid: string,
  ask: () => Promise<RecipientAnswer>,
): Promise<Uint8Array> {
  if (communityDid.startsWith("did:key:")) {
    return x25519FromEd25519Multibase(communityDid.slice("did:key:".length).split("#")[0] ?? "");
  }
  let answer: RecipientAnswer;
  try {
    answer = await ask();
  } catch (e) {
    if ((e as { code?: unknown } | null)?.code === NOT_PUBLISHED) {
      throw new SealingUnavailableError(
        "this community's key is not the one its DID document publishes yet — a rotation " +
          "still to be published at its VTA; try again once it is",
      );
    }
    throw e;
  }
  if (answer.communityDid !== communityDid || !answer.verificationMethod.startsWith(`${communityDid}#`)) {
    throw new SealingUnavailableError("the community answered with a key that is not its own");
  }
  if (!answer.recipientKey.startsWith("did:key:")) {
    throw new SealingUnavailableError("the community's key is not a did:key");
  }
  return x25519FromEd25519Multibase(answer.recipientKey.slice("did:key:".length));
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
