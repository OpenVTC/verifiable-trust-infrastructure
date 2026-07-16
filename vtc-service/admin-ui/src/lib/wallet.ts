// VTA browser-extension wallet bridge for the VTC admin UI.
//
// On web, the VTA wallet extension injects `window.vtaWallet` into pages it
// has host-permission for. This module is a thin feature-detect + wrapper
// that asks the wallet to log into THIS VTC, mirroring did-hosting-ui's
// `lib/wallet.ts`.
//
// Two flows, both ending in a server-issued bearer token that the caller
// exchanges for the admin cookie session via `/v1/auth/admin-session`:
//
//  - `loginWithWallet()` — the holder self-issues a SIOPv2 id_token; the
//    extension runs the `/auth/challenge` → `/auth/` round-trip internally.
//  - `loginWithWalletProxy()` — the VTA mints a SIOP id_token on behalf of a
//    `did-self-issued` vault entry pinned to this VTC; the long-term key
//    never leaves the VTA.
//
// The wallet posts to `${baseUrl}/auth/challenge` and `${baseUrl}/auth/`
// with no Trust-Task header, so we point `baseUrl` at the VTC's header-exempt
// `/v1/wallet` surface.

import { fetchHealth } from "@/lib/api";

interface VtaWalletLoginParams {
  rpDid: string;
  baseUrl: string;
}

export interface VtaWalletLoginResult {
  accessToken: string;
  refreshToken: string;
  sessionId: string;
  holderDid: string;
}

/** Canonical `secretKind` wire values — camelCase, mirroring
 *  `vault/_shared/0.2/vault-entry.schema.json#/$defs/SecretKind`. The
 *  maintainer schema-validates this enum before dispatch, so a
 *  kebab-case value is a payload rejection, not a no-op filter. Keep
 *  this the single source of truth for outbound `secretKind` filters. */
export type SecretKind =
  | "password"
  | "passkey"
  | "oauthTokens"
  | "didSelfIssued"
  | "didcommPeer"
  | "bearerToken"
  | "sshKey"
  | "custom";

/** A `did-self-issued` vault entry pinned to this RP, eligible for
 *  VTA-proxied SIOP login. */
export interface ProxyVaultEntry {
  id: string;
  label: string;
  contextId: string;
  secretKind: string;
  principalDid?: string;
  targets: Array<{ kind: string; [k: string]: unknown }>;
  lastUsedAt?: string;
}

interface VaultListWireResult {
  entries: ProxyVaultEntry[];
  truncated: boolean;
}

interface ProxyLoginWireResult {
  sessionBlob: {
    sessionId: string;
    expiresAt: string;
    headers?: Array<{ name: string; value: string }>;
    cookies?: unknown[];
    bindOrigin?: string;
  };
  sessionId: string;
  expiresAt: string;
}

interface VtaWalletProvider {
  login(params: VtaWalletLoginParams): Promise<VtaWalletLoginResult>;
  vaultList?(params: {
    targetDid?: string;
    targetOriginPrefix?: string;
    secretKind?: SecretKind;
  }): Promise<VaultListWireResult>;
  proxyLogin?(params: {
    entryId: string;
    nonce?: string;
    target?: { kind: string; [k: string]: unknown };
    ttlSecondsHint?: number;
  }): Promise<ProxyLoginWireResult>;
}

declare global {
  interface Window {
    vtaWallet?: VtaWalletProvider;
  }
}

/** True iff the wallet extension has injected its provider into the page. */
export function isWalletAvailable(): boolean {
  return (
    typeof window !== "undefined" &&
    typeof window.vtaWallet?.login === "function"
  );
}

/** True iff the wallet additionally exposes the proxy-login + vault-list
 *  APIs (newer extension builds). */
export function isWalletProxyAvailable(): boolean {
  return (
    isWalletAvailable() &&
    typeof window.vtaWallet?.proxyLogin === "function" &&
    typeof window.vtaWallet?.vaultList === "function"
  );
}

/** API base for the wallet's auth round-trip. Points at the VTC's
 *  header-exempt wallet surface, served same-origin with the admin UI. */
function walletApiBase(): string {
  const origin = typeof window !== "undefined" ? window.location.origin : "";
  return `${origin}/v1/wallet`;
}

/** The RP DID the wallet signs the SIOP `id_token` for — this VTC's own
 *  `did:webvh`, read from `/health`. */
async function rpDid(): Promise<string> {
  const health = await fetchHealth();
  const did = health.vtc_did;
  if (!did) {
    throw new Error(
      "This VTC has no DID configured yet, so wallet login can't be used.",
    );
  }
  return did;
}

/** Trigger the wallet's SIOPv2 login. Resolves to the server-issued bearer
 *  token; rejects if the wallet is unavailable, the user denies consent, or
 *  the server rejects the `id_token`. */
export async function loginWithWallet(): Promise<VtaWalletLoginResult> {
  if (!isWalletAvailable()) {
    throw new Error("VTA wallet extension is not installed.");
  }
  return window.vtaWallet!.login({
    rpDid: await rpDid(),
    baseUrl: walletApiBase(),
  });
}

const AUTH_AUTHENTICATE_TYPE =
  "https://trusttasks.org/spec/auth/authenticate/0.1";

/** Extract the compact JWS id_token from a SessionBlob's Authorization
 *  header. */
function bearerFromBlob(
  blob: ProxyLoginWireResult["sessionBlob"],
): string | null {
  const auth = blob.headers?.find(
    (h) => h.name.toLowerCase() === "authorization",
  );
  if (!auth) return null;
  const m = /^\s*Bearer\s+(.+)\s*$/i.exec(auth.value);
  return m && m[1] ? m[1] : null;
}

/** Enumerate `did-self-issued` vault entries pinned to this VTC. */
export async function listProxyCandidates(): Promise<ProxyVaultEntry[]> {
  if (!isWalletProxyAvailable()) {
    throw new Error("VTA wallet doesn't expose proxy-login APIs.");
  }
  const wire = await window.vtaWallet!.vaultList!({
    targetDid: await rpDid(),
    secretKind: "didSelfIssued",
  });
  return wire.entries.filter((e) => Boolean(e.principalDid));
}

/** Run the full VTA-proxied SIOP login against a chosen entry. The page
 *  drives the round-trip: fetch a challenge bound to the entry's principal
 *  DID, ask the VTA to mint an `id_token` with that challenge as nonce, then
 *  post it to `/auth/`. Resolves to the server-issued bearer. */
export async function loginWithWalletProxy(
  entry: ProxyVaultEntry,
): Promise<VtaWalletLoginResult> {
  if (!isWalletProxyAvailable()) {
    throw new Error("VTA wallet doesn't expose proxy-login APIs.");
  }
  if (!entry.principalDid) {
    throw new Error(
      "Chosen entry has no principal DID — only did-self-issued entries can proxy-login.",
    );
  }
  const rp = await rpDid();
  const base = walletApiBase().replace(/\/+$/, "");

  // 1. Challenge bound to the entry's principal DID.
  const chRes = await fetch(`${base}/auth/challenge`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    credentials: "include",
    body: JSON.stringify({ did: entry.principalDid }),
  });
  if (!chRes.ok) {
    throw new Error(`/auth/challenge failed (${chRes.status})`);
  }
  // Challenge response is camelCase; the authenticate payload is snake_case.
  const ch = (await chRes.json()) as { challenge: string; sessionId: string };
  if (!ch.sessionId || !ch.challenge) {
    throw new Error("/auth/challenge: malformed response");
  }

  // 2. VTA mints the SIOP id_token (long-term key stays in the VTA).
  const pl = await window.vtaWallet!.proxyLogin!({
    entryId: entry.id,
    nonce: ch.challenge,
    target: { kind: "did", did: rp },
  });
  const idToken = bearerFromBlob(pl.sessionBlob);
  if (!idToken) {
    throw new Error("vault/proxy-login: SessionBlob carried no id_token.");
  }

  // 3. Post the id_token; the server verifies + issues a bearer.
  const authRes = await fetch(`${base}/auth/`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    credentials: "include",
    body: JSON.stringify({
      type: AUTH_AUTHENTICATE_TYPE,
      payload: { id_token: idToken, session_id: ch.sessionId },
    }),
  });
  if (!authRes.ok) {
    throw new Error(`/auth/ failed (${authRes.status})`);
  }
  const tokenResp = (await authRes.json()) as {
    session: { id: string };
    tokens: { accessToken: string; refreshToken?: string };
  };
  if (!tokenResp.tokens?.accessToken) {
    throw new Error("/auth/: missing tokens.accessToken");
  }
  return {
    accessToken: tokenResp.tokens.accessToken,
    refreshToken: tokenResp.tokens.refreshToken ?? "",
    sessionId: tokenResp.session.id,
    holderDid: entry.principalDid,
  };
}
