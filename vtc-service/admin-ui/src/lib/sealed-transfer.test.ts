// Sealing a storage credential in the browser (`sealed-transfer.ts`).
//
// The shared vectors (`sealed-transfer.vectors.json`) are blocks this module
// sealed, with a fixed bundle id and ephemeral key, to the community key the
// Rust tests use (seed `[7; 32]`). Here they must reproduce byte for byte; in
// `vtc-service/src/rooms/storage_credentials.rs` the Rust opener must open
// them. Regenerate after a deliberate change with
// `UPDATE_SEALED_VECTORS=1 npx vitest run src/lib/sealed-transfer.test.ts`.

import { writeFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { CipherSuite, HkdfSha256 } from "@hpke/core";
import { Chacha20Poly1305 } from "@hpke/chacha20poly1305";
import { DhkemX25519HkdfSha256 } from "@hpke/dhkem-x25519";
import { ed25519, x25519 } from "@noble/curves/ed25519.js";
import { decode as cborDecode } from "cborg";

import { base58btcEncode } from "./jcs";
import {
  SealingUnavailableError,
  communitySealingKey,
  crc24,
  sealStorageCredential,
  x25519FromEd25519Multibase,
} from "./sealed-transfer";
import vectors from "./sealed-transfer.vectors.json";
import type { SealedStorageCredential } from "./wire-types";

const fromHex = (h: string) => new Uint8Array(h.match(/../g)!.map((b) => parseInt(b, 16)));
const toHex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");

const SEED = new Uint8Array(32).fill(7);
const COMMUNITY_PUBLIC = ed25519.getPublicKey(SEED);
const COMMUNITY_MULTIBASE = `z${base58btcEncode(new Uint8Array([0xed, 0x01, ...COMMUNITY_PUBLIC]))}`;
const COMMUNITY_X25519_SECRET = ed25519.utils.toMontgomerySecret(SEED);
const COMMUNITY_X25519 = x25519.getPublicKey(COMMUNITY_X25519_SECRET);
const PRODUCER = "did:key:z6MkConsoleKeyOfTheAdministrator";
const BUNDLE_ID = fromHex("0f1e2d3c4b5a69788796a5b4c3d2e1f0");
const IKM = [fromHex("11".repeat(32)), fromHex("22".repeat(32))];

const PEM = `-----BEGIN PRIVATE KEY-----\n${"MIIEvQIBADANBgkqhkiG9w0BAQEFAASC".repeat(4)}\n-----END PRIVATE KEY-----\n`;

const CASES: { name: string; credential: SealedStorageCredential }[] = [
  {
    name: "s3 with a session token",
    credential: {
      kind: "s3",
      configId: "r2-archive",
      accessKeyId: "EXAMPLEKEYID0001",
      secretAccessKey: "example-secret-not-a-real-one",
      sessionToken: "example-session-token",
    },
  },
  {
    name: "gcs service-account key",
    credential: {
      kind: "gcs",
      configId: "rooms-eu",
      serviceAccountKey: {
        type: "service_account",
        project_id: "example-project",
        client_email: "rooms@example-project.iam.gserviceaccount.com",
        private_key_id: "0123456789abcdef",
        private_key: PEM,
      },
    },
  },
  {
    // Over 32 KiB of payload: two chunks, so the Rust side reassembles.
    name: "gcs key large enough to need two chunks",
    credential: {
      kind: "gcs",
      configId: "rooms-big",
      serviceAccountKey: {
        type: "service_account",
        client_email: "rooms@example-project.iam.gserviceaccount.com",
        private_key_id: "0123456789abcdef",
        private_key: PEM,
        padding: "x".repeat(33 * 1024),
      },
    },
  },
];

async function seal(credential: SealedStorageCredential) {
  return sealStorageCredential(COMMUNITY_X25519, PRODUCER, credential, {
    bundleId: BUNDLE_ID,
    ephemeralIkm: IKM,
  });
}

/** Open a block the way `open_bundle` does, to check what is inside. */
async function open(armor: string) {
  const blocks = armor.split("-----BEGIN VTA SEALED BUNDLE-----").slice(1);
  const hpke = new CipherSuite({
    kem: new DhkemX25519HkdfSha256(),
    kdf: new HkdfSha256(),
    aead: new Chacha20Poly1305(),
  });
  const recipientKey = await hpke.kem.deserializePrivateKey(COMMUNITY_X25519_SECRET);
  const chunks: { header: Record<string, unknown>; fragment: number[] }[] = [];
  for (const block of blocks) {
    const [head, body] = block.split("\n\n") as [string, string];
    const total = Number(/Chunk: \d+\/(\d+)/.exec(head)![1]);
    const index = Number(/Chunk: (\d+)\//.exec(head)![1]) - 1;
    const b64 = body
      .split("\n")
      .filter((l) => l && !l.startsWith("=") && !l.startsWith("-----"))
      .join("");
    const sealed = Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
    const crcLine = body.split("\n").find((l) => l.startsWith("="))!;
    const crc = Uint8Array.from(atob(crcLine.slice(1)), (c) => c.charCodeAt(0));
    expect((crc[0]! << 16) | (crc[1]! << 8) | crc[2]!).toBe(crc24(sealed));
    const { kem_encap, aead_ciphertext } = cborDecode(sealed) as {
      kem_encap: number[];
      aead_ciphertext: number[];
    };
    const aad = new Uint8Array([1, ...BUNDLE_ID, 0, index, 0, total, 6, ...new TextEncoder().encode("sha256")]);
    const pt = await hpke.open(
      {
        recipientKey,
        enc: new Uint8Array(kem_encap),
        info: new TextEncoder().encode("vta-sealed-transfer/v1"),
      },
      new Uint8Array(aead_ciphertext),
      aad,
    );
    const header = cborDecode(new Uint8Array(pt)) as Record<string, unknown>;
    chunks.push({ header, fragment: header.payload_fragment as number[] });
  }
  const payload = cborDecode(new Uint8Array(chunks.flatMap((c) => c.fragment)));
  return { chunks, payload };
}

describe("sealing a storage credential to the community", () => {
  it("reproduces the shared vectors the Rust opener opens", async () => {
    const rendered = {
      comment:
        "Blocks admin-ui's sealed-transfer.ts sealed (fixed bundle id and HPKE ikm) to the community key of seed [7; 32]. vtc-service's storage_credentials tests open them; sealed-transfer.test.ts reproduces them.",
      communityPublicKeyMultibase: COMMUNITY_MULTIBASE,
      communityX25519Hex: toHex(COMMUNITY_X25519),
      producerDid: PRODUCER,
      cases: [] as unknown[],
    };
    for (const c of CASES) {
      const block = await seal(c.credential);
      rendered.cases.push({
        name: c.name,
        configId: c.credential.configId,
        kind: c.credential.kind,
        cleartext: c.credential,
        sealed: block.armor,
        digestMultibase: block.digestMultibase,
      });
    }
    if (process.env.UPDATE_SEALED_VECTORS) {
      writeFileSync("src/lib/sealed-transfer.vectors.json", `${JSON.stringify(rendered, null, 2)}\n`);
    }
    expect(rendered).toEqual(vectors);
  });

  it("derives the community's X25519 key from its Ed25519 key, prefixed or bare", () => {
    expect(toHex(x25519FromEd25519Multibase(COMMUNITY_MULTIBASE))).toBe(vectors.communityX25519Hex);
    expect(toHex(x25519FromEd25519Multibase(`z${base58btcEncode(COMMUNITY_PUBLIC)}`))).toBe(
      vectors.communityX25519Hex,
    );
    expect(() => x25519FromEd25519Multibase("uAAAA")).toThrow(SealingUnavailableError);
  });

  it("frames what the Rust opener expects: one producer assertion, the tagged payload", async () => {
    for (const c of CASES) {
      const block = await seal(c.credential);
      const { chunks, payload } = await open(block.armor);
      expect(payload).toEqual({ storage_credential: c.credential });
      chunks.forEach(({ header }, i) => {
        expect(header.version).toBe(1);
        expect(header.bundle_id).toEqual(Array.from(BUNDLE_ID));
        expect(header.chunk_index).toBe(i);
        expect(header.total_chunks).toBe(chunks.length);
        if (i === 0) {
          expect(header.producer_did).toBe(PRODUCER);
          expect(header.producer_assertion).toEqual({
            producer_did: PRODUCER,
            proof: { type: "pinned_only" },
          });
        } else {
          expect(header.producer_did).toBeUndefined();
          expect(header.producer_assertion).toBeUndefined();
        }
      });
    }
    expect((await open((await seal(CASES[2]!.credential)).armor)).chunks).toHaveLength(2);
  });

  it("never leaves an absent optional member as undefined", async () => {
    const block = await seal({
      kind: "s3",
      configId: "r2",
      accessKeyId: "AKID",
      secretAccessKey: "s",
      sessionToken: undefined,
    } as SealedStorageCredential);
    const { payload } = await open(block.armor);
    expect(payload).toEqual({
      storage_credential: { kind: "s3", configId: "r2", accessKeyId: "AKID", secretAccessKey: "s" },
    });
  });

  it("seals each time under a fresh bundle id and ephemeral key", async () => {
    const credential = CASES[0]!.credential;
    const a = await sealStorageCredential(COMMUNITY_X25519, PRODUCER, credential);
    const b = await sealStorageCredential(COMMUNITY_X25519, PRODUCER, credential);
    expect(a.armor).not.toBe(b.armor);
    expect(a.digestMultibase).not.toBe(b.digestMultibase);
    expect(a.armor).not.toContain("example-secret");
  });
});

describe("the community's key to seal to", () => {
  const DID = "did:webvh:QmScid:community.example";
  const entry = (state: unknown) => JSON.stringify({ versionId: "1-Qm", state });
  const log = (...states: unknown[]) => async () =>
    new Response(states.map(entry).join("\n") + "\n", { status: 200 });
  const other = `z${base58btcEncode(new Uint8Array([0xed, 0x01, ...ed25519.getPublicKey(new Uint8Array(32).fill(9))]))}`;

  it("reads #key-0 from the latest entry of the log this community serves", async () => {
    const key = await communitySealingKey(
      DID,
      log(
        { id: DID, verificationMethod: [{ id: `${DID}#key-0`, publicKeyMultibase: other }] },
        {
          id: DID,
          verificationMethod: [
            { id: `${DID}#key-1`, publicKeyMultibase: other },
            { id: `${DID}#key-0`, publicKeyMultibase: COMMUNITY_MULTIBASE },
          ],
        },
      ),
    );
    expect(toHex(key)).toBe(vectors.communityX25519Hex);
  });

  it("falls back to the first Ed25519 key when there is no #key-0", async () => {
    const key = await communitySealingKey(
      DID,
      log({
        id: DID,
        verificationMethod: [
          { id: "#mldsa", publicKeyMultibase: "zNotAnEd25519Key" },
          { id: "#signing", publicKeyMultibase: COMMUNITY_MULTIBASE },
        ],
      }),
    );
    expect(toHex(key)).toBe(vectors.communityX25519Hex);
  });

  it("takes a did:key's key from the DID itself", async () => {
    const key = await communitySealingKey(`did:key:${COMMUNITY_MULTIBASE}`, async () => {
      throw new Error("never fetched");
    });
    expect(toHex(key)).toBe(vectors.communityX25519Hex);
  });

  it("refuses another DID's document, a missing log, and a document with no key", async () => {
    await expect(
      communitySealingKey(DID, log({ id: "did:webvh:QmOther:elsewhere.example", verificationMethod: [] })),
    ).rejects.toThrow(/not this community's/);
    await expect(
      communitySealingKey(DID, async () => new Response("did log not found", { status: 404 })),
    ).rejects.toThrow(SealingUnavailableError);
    await expect(communitySealingKey(DID, log({ id: DID, verificationMethod: [] }))).rejects.toThrow(
      /no Ed25519 key/,
    );
  });
});
