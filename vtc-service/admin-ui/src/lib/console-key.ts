// The console's signing key: generation, custody, and the `eddsa-jcs-2022`
// Data-Integrity proof it puts on a Trust Task document.
//
// Design note: `docs/05-design-notes/vtc-console-signing.md` (Option A).
// Server half: #1692 — `POST /v1/admin/console-keys` enrols the `did:key`
// derived here as a **delegation** of the operator's admin DID. The key is a
// credential of that identity the way a passkey is: it confers no role, it
// holds no ACL row, and authority stays the delegating admin's row, read at
// execution time on every document.
//
// ## Why the private key is never bytes
//
// `crypto.subtle.generateKey({name:"Ed25519"}, false, …)` — **the `false` is
// load-bearing and is not a typo to tidy up.** The flag governs the *private*
// key only; WebCrypto sets `publicKey.[[extractable]]` to `true`
// unconditionally for a generated pair, so `exportKey("raw", publicKey)` still
// returns the 32 bytes this module needs to derive `did:key:z6Mk…`, while
// `exportKey("pkcs8"|"jwk", privateKey)` throws `InvalidAccessError`.
//
// Passing `true` costs nothing visible and hands the private key to any script
// that runs in this origin. That is not hypothetical: the file this module was
// lifted from — `did-hosting-ui/lib/session-key.ts` — passed `true` with a
// comment claiming it was needed to export the public key. It was not.
// affinidi-webvh-service#210 is the fix; `console-key.test.ts` asserts the
// private key does not export so this cannot quietly flip back.
//
// The `CryptoKey` objects are structured-cloneable, so IndexedDB stores the
// opaque wrappers rather than key material, and the browser's serialiser
// preserves `extractable: false` across the round trip. There is no code path
// in this console that turns the key into bytes.
//
// ## What it costs an attacker, honestly
//
// A non-extractable key prevents exfiltration, not use: script running in this
// origin can sign whatever the operator could, for as long as it runs. That is
// roughly the bound that already applies, since such script can ride the
// HttpOnly session cookie. What it cannot do is leave anything behind —
// enrolling a *new* key needs a live passkey gesture (`stepUpSession()`), and
// a signed document it captured stops being accepted when the 10-minute
// acceptance window closes or its `id` is spent.

import { jcsCanonicalize, base58btcEncode, ed25519Multikey, sha256 } from "./jcs";

/** A console signing key, as everything downstream sees it. */
export interface ConsoleSigningKey {
  /** `did:key:z6Mk…`, derived from the public half. */
  readonly consoleDid: string;
  /** `${consoleDid}#${multikey}` — what the proof names. */
  readonly verificationMethod: string;
  /** The non-extractable pair. Only `crypto.subtle.sign` ever reads it. */
  readonly keypair: CryptoKeyPair;
}

/**
 * How far into the past a proof's `created` is stamped, in milliseconds.
 *
 * A W3C Data-Integrity verifier rejects any `created` in **its** future with
 * no skew tolerance at all, and this timestamp comes from the operator's
 * laptop while the check runs on the daemon's clock. Without the back-date,
 * acceptance is a race between clock skew and network latency — the same click
 * failing or succeeding depending on how fast the request lands. Both prior
 * implementations back-date; the plugin's comment records that it was found
 * the hard way.
 *
 * 60 s, matching `pnm-browser-plugin` rather than did-hosting-ui's 5 s: the
 * document's own `issuedAt` carries the freshness bound the VTC enforces (10
 * minutes, VTI-OPS-024), and nothing bounds how old `created` may be, so a
 * wider margin is free.
 */
const CREATED_BACKDATE_MS = 60_000;

/**
 * An RFC-3339 UTC timestamp at **whole-second** precision, with no fractional
 * part: `2026-09-23T10:15:00Z`.
 *
 * Not cosmetic, and the reason is the sharpest edge in this file. The VTC does
 * **not** verify the proof over the bytes it received: it parses them into a
 * `trust_tasks_rs::TrustTask`, strips `proof`, and re-serialises *that* before
 * canonicalising. `issuedAt` is a `chrono::DateTime<Utc>` in the struct, and
 * chrono's serde writes it with `SecondsFormat::AutoSi` — which emits **no**
 * fractional digits when the sub-second part is zero, three when it is
 * whole milliseconds, and so on.
 *
 * `Date.prototype.toISOString` always writes exactly three. So a document
 * stamped at a whole second goes out as `…:00.000Z`, comes back from the
 * parser as `…:00Z`, canonicalises to different bytes, and the proof fails —
 * while every other document that second verifies. One request in a thousand,
 * never reproducible, and indistinguishable at the client from a revoked
 * delegation. `console_signed_document.rs` caught exactly this against the
 * real verifier; nothing on this side could have.
 *
 * Truncating to seconds makes the round trip an identity for every value: the
 * VTC's freshness window is ten minutes, so the lost precision is free.
 */
function isoSeconds(at: Date): string {
  return `${at.toISOString().slice(0, 19)}Z`;
}

/** A Trust Task document as this console builds it, before the proof. */
export interface UnsignedTrustTaskDocument {
  id: string;
  type: string;
  issuer: string;
  recipient: string;
  issuedAt: string;
  payload: unknown;
}

/** The same document with its `eddsa-jcs-2022` proof attached. */
export interface SignedTrustTaskDocument extends UnsignedTrustTaskDocument {
  proof: {
    type: "DataIntegrityProof";
    cryptosuite: "eddsa-jcs-2022";
    verificationMethod: string;
    created: string;
    proofPurpose: "assertionMethod" | "authentication";
    proofValue: string;
  };
}

/**
 * Build the unsigned document.
 *
 * `recipient` is **not** optional in practice: SPEC §4.8.2 audience binding
 * refuses a *signed* document with no in-band recipient unless its
 * specification is a bearer spec, and the VTC additionally requires the
 * recipient to be its own DID (`validate_basic`) — that binding is the replay
 * defence. `issuedAt` is required by the VTC's freshness policy
 * (`requiring_issued_at`, 10-minute window).
 *
 * Mirrors `vta_sdk::trust_task_sign::build_unsigned`, including the
 * `urn:uuid:` id, so a document from this console and one from the Rust SDK
 * are the same shape.
 */
export function buildTrustTaskDocument(args: {
  typeUri: string;
  payload: unknown;
  issuer: string;
  recipient: string;
  /** Test seam only — production always stamps `now`. */
  issuedAt?: Date;
}): UnsignedTrustTaskDocument {
  return {
    id: `urn:uuid:${crypto.randomUUID()}`,
    type: args.typeUri,
    issuer: args.issuer,
    recipient: args.recipient,
    issuedAt: isoSeconds(args.issuedAt ?? new Date()),
    payload: args.payload,
  };
}

/**
 * Attach an `eddsa-jcs-2022` Data-Integrity proof.
 *
 * `hashData = SHA-256(JCS(proofConfig)) || SHA-256(JCS(document minus proof))`,
 * signed with Ed25519, `proofValue = "z" + base58btc(signature)`.
 *
 * Three details, each of which yields a signature that verifies nowhere if
 * missed, and none of which any test of "we called fetch" would catch:
 *
 * 1. **The proof-config hash comes first.** Concatenation is not symmetric.
 * 2. **`proof` is *removed*** before canonicalising the document — not set to
 *    `null`, not left as an empty object. JCS is presence-sensitive, so a
 *    document that already carries a `proof` key hashes differently.
 * 3. **`proofValue` is absent from the proof config that is hashed.** It is
 *    added afterwards.
 *
 * Signing goes through WebCrypto rather than a JS Ed25519 library because the
 * key is a non-extractable `CryptoKey` — a library would need the bytes, which
 * is the property this module exists to keep.
 */
export async function signTrustTaskDocument(
  doc: UnsignedTrustTaskDocument,
  key: ConsoleSigningKey,
  options: {
    now?: Date;
    /** Defaults to `assertionMethod`, what the console's documents carry. A
     *  `did:key` is authorised for every purpose; an operational document
     *  from another caller (the member portal's sign-in key) may say
     *  `authentication` (VTI-KEY-106). */
    proofPurpose?: "assertionMethod" | "authentication";
  } = {},
): Promise<SignedTrustTaskDocument> {
  // `created` is an `Option<String>` on the Rust side, so it survives the
  // round trip verbatim — but it is written the same way as `issuedAt` so
  // there is one timestamp format in this module rather than two, and so a
  // later change of that field's type cannot reintroduce the bug above.
  const created = isoSeconds(
    new Date((options.now?.getTime() ?? Date.now()) - CREATED_BACKDATE_MS),
  );

  // The proof config as hashed: everything the proof will carry *except*
  // `proofValue`.
  const proofConfig = {
    type: "DataIntegrityProof" as const,
    cryptosuite: "eddsa-jcs-2022" as const,
    verificationMethod: key.verificationMethod,
    created,
    proofPurpose: options.proofPurpose ?? ("assertionMethod" as const),
  };

  // The document as hashed: no `proof` member at all. `doc` is built without
  // one, and the spread below is what guarantees it stays that way even if a
  // caller hands us a document that has been signed once already.
  const unsigned: Record<string, unknown> = { ...doc };
  delete unsigned.proof;

  const proofConfigHash = await sha256(jcsCanonicalize(proofConfig));
  const documentHash = await sha256(jcsCanonicalize(unsigned));

  const toSign = new Uint8Array(proofConfigHash.length + documentHash.length);
  toSign.set(proofConfigHash, 0);
  toSign.set(documentHash, proofConfigHash.length);

  const signature = new Uint8Array(
    await crypto.subtle.sign({ name: "Ed25519" }, key.keypair.privateKey, toSign),
  );
  if (signature.length !== 64) {
    throw new Error(
      `unexpected Ed25519 signature length: ${signature.length} bytes (expected 64)`,
    );
  }

  return {
    ...doc,
    proof: { ...proofConfig, proofValue: "z" + base58btcEncode(signature) },
  };
}

// ---------------------------------------------------------------------------
// Availability
// ---------------------------------------------------------------------------

let ed25519Supported: Promise<boolean> | null = null;

/**
 * Can this browser generate an Ed25519 key at all?
 *
 * WebCrypto Ed25519 needs Chrome 137+, Firefox 130+ or Safari 17+. Feature
 * detection has to be a real `generateKey` — the algorithm's presence is not
 * advertised anywhere synchronously, and a browser that has `crypto.subtle`
 * may still throw `NotSupportedError` for this curve.
 *
 * Cached, because the console asks on every render that decides whether to
 * offer the signed door.
 */
export function ed25519Available(): Promise<boolean> {
  if (ed25519Supported) return ed25519Supported;
  ed25519Supported = (async () => {
    if (typeof crypto === "undefined" || !crypto.subtle) return false;
    try {
      await crypto.subtle.generateKey({ name: "Ed25519" }, false, [
        "sign",
        "verify",
      ]);
      return true;
    } catch {
      return false;
    }
  })();
  return ed25519Supported;
}

// ---------------------------------------------------------------------------
// Generation + custody
// ---------------------------------------------------------------------------

/** Turn a generated pair into the identity the rest of the console uses. */
async function identityFor(keypair: CryptoKeyPair): Promise<ConsoleSigningKey> {
  // The assertion the design note asks for, and the reason it is here rather
  // than only in a test: a future edit that flips the flag back would produce
  // a key that works perfectly and is readable by any script in the origin.
  // Failing loudly at generation is the only moment that is cheap to notice.
  if (keypair.privateKey.extractable) {
    throw new Error(
      "refusing an extractable console signing key — the private half must not be readable by script in this origin",
    );
  }

  const raw = new Uint8Array(
    await crypto.subtle.exportKey("raw", keypair.publicKey),
  );
  if (raw.length !== 32) {
    throw new Error(
      `unexpected Ed25519 public key length: ${raw.length} bytes (expected 32)`,
    );
  }

  const multikey = ed25519Multikey(raw);
  const consoleDid = `did:key:${multikey}`;
  return {
    consoleDid,
    // Matches `vta_sdk::trust_task_sign::did_key_to_vm`: a `did:key` carries
    // its own verification method, so the fragment repeats the multikey.
    verificationMethod: `${consoleDid}#${multikey}`,
    keypair,
  };
}

/**
 * Generate a fresh console signing key, **without** storing it.
 *
 * Every enrolment uses a fresh key: `auth/signing-key/enroll/0.1` is "a
 * freshly generated key asks to be enrolled", and the VTC refuses any key it
 * has a delegation for — `keyRevoked`, and `alreadyEnrolled`, which an
 * *expired* delegation still is. So a browser whose delegation lapsed cannot
 * revive its old key; it makes a new one. [`adoptConsoleKey`] stores it once
 * the VTC has enrolled it, so a ceremony that fails or is cancelled leaves the
 * key this browser already held where it was.
 */
export async function mintConsoleKey(): Promise<ConsoleSigningKey> {
  if (typeof crypto === "undefined" || !crypto.subtle) {
    throw new Error(
      "WebCrypto is not available here — the console cannot sign documents in this browser",
    );
  }
  const keypair = (await crypto.subtle.generateKey({ name: "Ed25519" }, false, [
    "sign",
    "verify",
  ])) as CryptoKeyPair;
  return identityFor(keypair);
}

/** [`mintConsoleKey`] and [`adoptConsoleKey`] in one step. */
export async function generateConsoleKey(): Promise<ConsoleSigningKey> {
  const identity = await mintConsoleKey();
  await adoptConsoleKey(identity);
  return identity;
}

/**
 * Make `identity` this browser's key: store it, read it back, and ask the
 * browser to keep this origin's storage.
 *
 * Throws [`KeyStorageError`] if it could not be stored. Before this, a failed
 * write fell back to memory without a word: the key signed until the next
 * reload and then vanished, leaving an enrolled delegation nobody held.
 */
export async function adoptConsoleKey(
  identity: ConsoleSigningKey,
): Promise<StorageDurability> {
  const durability = await persist(identity);
  cached = identity;
  return durability;
}

let cached: ConsoleSigningKey | null = null;
/** Coalesces concurrent restores so two signings share one store round-trip. */
let restoreInFlight: Promise<ConsoleSigningKey | null> | null = null;

/**
 * The key this browser holds, restoring it from storage on first use after a
 * reload. `null` only when this profile holds none.
 *
 * Throws [`KeyStorageError`] when the store could not be read. That is not
 * "no key": reading it as one sends the operator to enrol again, and it once
 * also overwrote the key they had.
 */
export async function loadConsoleKey(): Promise<ConsoleSigningKey | null> {
  if (cached) return cached;
  if (restoreInFlight) return restoreInFlight;
  restoreInFlight = (async () => {
    try {
      const stored = await read();
      if (!stored) return null;
      cached = await identityFor(stored.keypair);
      return cached;
    } catch (e) {
      throw new KeyStorageError(
        `this browser's signing key could not be read from its storage: ${messageOf(e)}`,
      );
    } finally {
      restoreInFlight = null;
    }
  })();
  return restoreInFlight;
}

/** The browser's key store could not be read or written. */
export class KeyStorageError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "KeyStorageError";
  }
}

function messageOf(e: unknown): string {
  return (e as Error | null)?.message ?? String(e);
}

/** Forget this browser's key. The delegation is revoked separately. */
export async function forgetConsoleKey(): Promise<void> {
  cached = null;
  await remove();
}

/**
 * Drop the module-scope cache without touching storage.
 *
 * For tests, which simulate a page reload, and for nothing else — production
 * has no reason to forget a key it can still use.
 */
export function resetConsoleKeyCacheForTests(): void {
  cached = null;
  restoreInFlight = null;
  ed25519Supported = null;
}

// ---------------------------------------------------------------------------
// Persistence
// ---------------------------------------------------------------------------
//
// IndexedDB, holding the `CryptoKey` objects themselves. The record survives
// a VTC restart (nothing about it lives on the daemon), a browser restart and
// an OS reboot. What ends it is the browser deleting this origin's storage:
//
// - the operator clearing site data, or a private window closing;
// - eviction. Storage is best-effort unless the origin has been granted
//   persistence, and best-effort storage is what a browser deletes first
//   under disk pressure. So adopting a key asks for
//   `navigator.storage.persist()`: Chromium grants it silently to a site the
//   operator uses, Firefox asks, Safari decides by engagement. Safari also
//   deletes an origin's script-writable storage after seven days of browser
//   use without a visit, persisted or not.
//
// The key is per **origin**: `https://vtc.example` and
// `https://vtc.example:8443` — or `localhost` and `127.0.0.1` — are two
// browsers as far as the key is concerned.
//
// Where the browser offers no IndexedDB at all (some embedded webviews, and
// jsdom under the console's own tests) the key is held in memory and
// [`StorageDurability`] says so. Nothing else falls back to memory: a write
// IndexedDB refuses is an error, not a quieter kind of success.

/** How a stored key is held. */
export type StorageDurability =
  /** IndexedDB, and the browser agreed not to evict this origin's storage. */
  | "persistent"
  /** IndexedDB, best-effort: kept unless the browser needs the space. */
  | "best-effort"
  /** No IndexedDB here: the key lasts as long as this tab. */
  | "memory";

/** Ask the browser not to evict this origin's storage. Never throws. */
async function requestPersistence(): Promise<boolean> {
  try {
    const storage = typeof navigator === "undefined" ? undefined : navigator.storage;
    if (!storage?.persist) return false;
    if (storage.persisted && (await storage.persisted())) return true;
    return await storage.persist();
  } catch {
    return false;
  }
}

/**
 * How this browser holds its key right now, for the console to say. Asks the
 * browser for nothing and never throws.
 */
export async function keyStorageDurability(): Promise<StorageDurability> {
  if (typeof indexedDB === "undefined") return "memory";
  try {
    const storage = typeof navigator === "undefined" ? undefined : navigator.storage;
    return storage?.persisted && (await storage.persisted()) ? "persistent" : "best-effort";
  } catch {
    return "best-effort";
  }
}

interface StoredKey {
  keypair: CryptoKeyPair;
}

const IDB_NAME = "vtc-admin-console";
const IDB_STORE = "signing-keys";
const IDB_VERSION = 1;
/** One key per origin; a second VTC is a second origin. */
const RECORD_KEY = "console-signing-key";

let memoryFallback: StoredKey | null = null;

function openDb(): Promise<IDBDatabase | null> {
  return new Promise((resolve, reject) => {
    if (typeof indexedDB === "undefined") {
      resolve(null);
      return;
    }
    const req = indexedDB.open(IDB_NAME, IDB_VERSION);
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains(IDB_STORE)) {
        db.createObjectStore(IDB_STORE);
      }
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error ?? new Error("indexedDB.open failed"));
    req.onblocked = () =>
      reject(new Error("indexedDB.open blocked by an older connection"));
  });
}

async function persist(identity: ConsoleSigningKey): Promise<StorageDurability> {
  const record: StoredKey = { keypair: identity.keypair };
  let db: IDBDatabase | null;
  try {
    db = await openDb();
  } catch (e) {
    throw new KeyStorageError(
      `this browser's storage could not be opened to keep the signing key: ${messageOf(e)}`,
    );
  }
  if (!db) {
    memoryFallback = record;
    return "memory";
  }
  try {
    await new Promise<void>((resolve, reject) => {
      const tx = db.transaction(IDB_STORE, "readwrite");
      tx.objectStore(IDB_STORE).put(record, RECORD_KEY);
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error ?? new Error("IDB put failed"));
      tx.onabort = () => reject(tx.error ?? new Error("IDB put aborted"));
    });
  } catch (e) {
    throw new KeyStorageError(`this browser refused to store the signing key: ${messageOf(e)}`);
  } finally {
    db.close();
  }
  // Read it back. A store that took the write but cannot hand back a usable
  // key is a store that loses it on the next reload — find out now, while the
  // operator is still here, not then.
  let back: StoredKey | null;
  try {
    back = await read();
  } catch (e) {
    throw new KeyStorageError(`the signing key was stored but could not be read back: ${messageOf(e)}`);
  }
  const restored = back ? await identityFor(back.keypair) : null;
  if (restored?.consoleDid !== identity.consoleDid) {
    throw new KeyStorageError("the signing key read back is not the one just stored");
  }
  return (await requestPersistence()) ? "persistent" : "best-effort";
}

/** The stored record, or `null` when there is none. Throws if the store fails. */
async function read(): Promise<StoredKey | null> {
  const db = await openDb();
  if (!db) return memoryFallback;
  try {
    const record = await new Promise<StoredKey | undefined>((resolve, reject) => {
      const tx = db.transaction(IDB_STORE, "readonly");
      const req = tx.objectStore(IDB_STORE).get(RECORD_KEY);
      req.onsuccess = () => resolve(req.result as StoredKey | undefined);
      req.onerror = () => reject(req.error ?? new Error("IDB get failed"));
    });
    return record ?? null;
  } finally {
    db.close();
  }
}

async function remove(): Promise<void> {
  memoryFallback = null;
  let db: IDBDatabase | null = null;
  try {
    db = await openDb();
  } catch {
    db = null;
  }
  if (!db) return;
  try {
    await new Promise<void>((resolve, reject) => {
      const tx = db.transaction(IDB_STORE, "readwrite");
      tx.objectStore(IDB_STORE).delete(RECORD_KEY);
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error ?? new Error("IDB delete failed"));
      tx.onabort = () => reject(tx.error ?? new Error("IDB delete aborted"));
    });
  } finally {
    db.close();
  }
}
