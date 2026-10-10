// Wallet sign-in started by a trigger link — the starter (browser) side of
// `auth/oob/*` (design-docs/vtc-qr-login-design.md §13, contract C1, C2, C9).
//
// The browser holds a non-extractable WebCrypto Ed25519 key `K_b`, signs
// `auth/oob/request`, shows the trigger link as a QR code that is also a link,
// and long-polls `auth/oob/redeem` signed with `K_b`. Only `K_b`'s holder can
// redeem the member's grant, so nothing here is a bearer secret: the request
// id is public, and the session arrives as HttpOnly cookies.
//
// TODO: switch to `@openvtc/rp-sdk/browser` (`createSignIn`) once it is
// published (contract C9). Until then this is the portal's own starter, kept
// to the same wire.

import {
  buildTrustTaskDocument,
  signTrustTaskDocument,
  type ConsoleSigningKey,
} from "@/lib/console-key";
import { ed25519Multikey } from "@/lib/jcs";

// TODO: replace with generated trust-tasks types
export const OOB_TYPES = {
  request: "https://trusttasks.org/spec/auth/oob/request/0.1",
  redeem: "https://trusttasks.org/spec/auth/oob/redeem/0.1",
  cancel: "https://trusttasks.org/spec/auth/oob/cancel/0.1",
} as const;

/** Which session a sign-in asks for. `member` is the portal's; `admin` is
 *  the operator console's, for an identity the community's ACL holds as an
 *  administrator. */
export type SessionAudience = "member" | "admin";

/** The `ext` namespace that carries the audience on `auth/oob/request`, and
 *  in the VTC's signed step 1 and step 2 (so the member's grant covers it).
 *  `auth/oob/0.1`'s `purpose` is a closed enum, so it is not a purpose. */
export const SESSION_EXT = "org.openvtc.session";

/** The decline reason for an identity that is not an administrator. */
export const NOT_AN_ADMIN = "notAnAdmin";

/** What `GET /v1/member/sign-in/config` answers. */
export interface SignInConfig {
  vtcDid: string;
  linkHost: string;
  flow: string;
}

/** A successful `redeem` (contract C9). No tokens. */
export interface RedeemResult {
  subject: string;
  displayName?: string | null;
  notAfter: number;
  amr: string[];
  /** The session the VTC issued, from the response's `ext`; `member` when
   *  it says nothing. */
  audience: SessionAudience;
}

/** The audience an `ext` names, or `member` when it names none. */
export function audienceOf(ext: unknown): SessionAudience {
  const ns = (ext as Record<string, unknown> | null | undefined)?.[SESSION_EXT] as
    | { audience?: unknown }
    | undefined;
  return ns?.audience === "admin" ? "admin" : "member";
}

/** A refusal from the sign-in service: the local part of its code. */
export class OobError extends Error {
  constructor(
    readonly code: string,
    message: string,
    readonly details: Record<string, unknown> = {},
  ) {
    super(message);
    this.name = "OobError";
  }
}

/** The session key `K_b`: non-extractable, held in memory for this page
 *  only, and dropped at sign-out. */
let sessionKey: ConsoleSigningKey | null = null;

/** Generate a fresh `K_b`. The `false` is load-bearing: the private half can
 *  sign but never be read by script (see `@/lib/console-key`). */
export async function generateSessionKey(): Promise<ConsoleSigningKey> {
  const keypair = (await crypto.subtle.generateKey({ name: "Ed25519" }, false, [
    "sign",
    "verify",
  ])) as CryptoKeyPair;
  if (keypair.privateKey.extractable) {
    throw new Error("refusing an extractable sign-in key");
  }
  const raw = new Uint8Array(await crypto.subtle.exportKey("raw", keypair.publicKey));
  const multikey = ed25519Multikey(raw);
  const did = `did:key:${multikey}`;
  sessionKey = { consoleDid: did, verificationMethod: `${did}#${multikey}`, keypair };
  return sessionKey;
}

/** Forget `K_b` — at sign-out, or when a sign-in ends without a session. */
export function forgetSessionKey(): void {
  sessionKey = null;
}

export async function fetchSignInConfig(): Promise<SignInConfig> {
  const res = await fetch("/v1/member/sign-in/config", { credentials: "same-origin" });
  const body = (await res.json().catch(() => ({}))) as Partial<SignInConfig> & {
    message?: string;
  };
  if (!res.ok || !body.vtcDid || !body.linkHost || !body.flow) {
    throw new Error(body.message || "Wallet sign-in isn't available on this community yet.");
  }
  return body as SignInConfig;
}

/** Percent-encode `&`, `=`, `#` and `%`, and nothing else (contract C1). */
export function encodeFrom(did: string): string {
  return did.replace(/[&=#%]/g, (c) => "%" + c.charCodeAt(0).toString(16).toUpperCase());
}

/** The trigger link (contract C1). ASCII only, and at QR level M at most 251
 *  bytes (VTI-LNK-080, 081). */
export function triggerLink(
  cfg: SignInConfig,
  requestId: string,
  claimDeadline: number,
): string {
  const link =
    `https://${cfg.linkHost}/t#_from=${encodeFrom(cfg.vtcDid)}` +
    `&_id=${requestId}&_exp=${claimDeadline}&_type=${cfg.flow}`;
  // eslint-disable-next-line no-control-regex
  if (!/^[\x00-\x7f]*$/.test(link) || link.length > 251) {
    throw new Error("This community's sign-in link is too long to show as a code.");
  }
  // VTI-LNK-084: a universal link on the page's own domain opens the browser.
  const here = window.location.hostname;
  if (here === cfg.linkHost || here.endsWith(`.${cfg.linkHost}`)) {
    throw new Error("The sign-in link host is this site's own domain; ask the operator to change it.");
  }
  return link;
}

/** An instant on the wire: integer epoch seconds only (contract C9). */
export function epochOf(v: unknown): number | null {
  return typeof v === "number" && Number.isInteger(v) && v >= 0 ? v : null;
}

interface WireReply {
  ok: boolean;
  payload: Record<string, unknown>;
}

/** Sign `payload` as `K_b` and post it to the trust-task door. A refusal
 *  becomes an [`OobError`] carrying the local part of its code (the VTC
 *  emits `auth/oob/<task>:<local>`). */
async function send(
  type: string,
  payload: unknown,
  cfg: SignInConfig,
  signal?: AbortSignal,
): Promise<Record<string, unknown>> {
  if (!sessionKey) throw new Error("No sign-in key; start again.");
  const doc = await signTrustTaskDocument(
    buildTrustTaskDocument({
      typeUri: type,
      payload,
      issuer: sessionKey.consoleDid,
      recipient: cfg.vtcDid,
    }),
    sessionKey,
    { proofPurpose: "authentication" },
  );
  const res = await fetch("/v1/trust-tasks", {
    method: "POST",
    headers: { "content-type": "application/json" },
    credentials: "same-origin",
    body: JSON.stringify(doc),
    signal,
  });
  const body = (await res.json().catch(() => null)) as {
    type?: string;
    payload?: Record<string, unknown>;
  } | null;
  const reply: WireReply = {
    ok: res.ok && !(body?.type ?? "").includes("/trust-task-error/"),
    payload: body?.payload ?? {},
  };
  if (reply.ok) return reply.payload;
  const raw = typeof reply.payload.code === "string" ? reply.payload.code : `http${res.status}`;
  const local = raw.includes(":") ? raw.slice(raw.lastIndexOf(":") + 1) : raw;
  throw new OobError(
    local,
    typeof reply.payload.message === "string" ? reply.payload.message : `${res.status}`,
    (reply.payload.details as Record<string, unknown>) ?? {},
  );
}

/** `auth/oob/request`: open a request. Returns its id and claim deadline.
 *  A member request is sent exactly as before; an operator-console one adds
 *  `ext["org.openvtc.session"]`, and is refused here unless the VTC echoed
 *  it — a VTC that predates the extension carries `ext` through unread and
 *  would open a member sign-in instead. */
export async function openRequest(
  cfg: SignInConfig,
  audience: SessionAudience = "member",
): Promise<{ requestId: string; claimDeadline: number }> {
  const payload =
    audience === "member"
      ? { purpose: "login", mode: "scan" }
      : { purpose: "login", mode: "scan", ext: { [SESSION_EXT]: { audience } } };
  const p = await send(OOB_TYPES.request, payload, cfg);
  if (audienceOf(p.ext) !== audience) {
    throw new Error(
      "This community's service doesn't offer wallet sign-in to the operator console yet. " +
        "Use your passkey, or an older wallet below.",
    );
  }
  const requestId = typeof p.requestId === "string" ? p.requestId : "";
  const claimDeadline = epochOf(p.claimDeadline);
  if (!/^[A-Za-z0-9_-]{22}$/.test(requestId) || claimDeadline === null) {
    throw new Error("The community answered the sign-in request in a shape this page can't read.");
  }
  return { requestId, claimDeadline };
}

/** One `redeem` long poll: the result on success, or an [`OobError`] —
 *  `pending` (with `details.state` and, once claimed, `details.matchNumber`),
 *  `declined` (`details.state` is `cancelled` for a cancellation),
 *  `requestExpired`, … */
export async function redeemOnce(
  cfg: SignInConfig,
  requestId: string,
  signal?: AbortSignal,
): Promise<RedeemResult> {
  const p = await send(OOB_TYPES.redeem, { requestId }, cfg, signal);
  return {
    subject: String(p.subject ?? ""),
    displayName: typeof p.displayName === "string" ? p.displayName : null,
    notAfter: epochOf(p.notAfter) ?? 0,
    amr: Array.isArray(p.amr) ? (p.amr as string[]) : [],
    audience: audienceOf(p.ext),
  };
}

/** `auth/oob/cancel`, by the starter. Best effort: the request ends on its
 *  own clock either way. */
export async function cancelRequest(cfg: SignInConfig, requestId: string): Promise<void> {
  try {
    await send(OOB_TYPES.cancel, { requestId }, cfg);
  } catch {
    /* already ended */
  }
}
