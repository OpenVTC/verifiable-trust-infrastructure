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

import { daemonErrorMessage, fetchHealth } from "@/lib/api";

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
    entryId?: string;
    nonce?: string;
    target?: { kind: string; [k: string]: unknown };
    ttlSecondsHint?: number;
  }): Promise<ProxyLoginWireResult>;
  /** Which persona this site knows the user as, resolving or binding one.
   *  Mints nothing. Present from the wallet build that added first-use
   *  persona binding (OpenVTC/vta-browser-plugin#145). */
  walletProfile?(params: {
    target?: { kind: string; [k: string]: unknown };
  }): Promise<WalletProfileWireResult>;
  /** Sign a Trust Task document this page built. With `asDid`, the VTA signs
   *  as that persona (`vault/sign-trust-task`), so the key never leaves it.
   *  The wallet prompts every time, and only for the RP this origin signed in
   *  to (`recipient` must be that RP's DID). */
  signTrustTask?(params: {
    envelope: Record<string, unknown>;
    asDid?: string;
  }): Promise<{ signedEnvelope: Record<string, unknown>; holderDid: string }>;
  /** Answer an operation-bound step-up with this browser's **step-up
   *  approver** — the plugin's approver `did:key` for `audience`, whose seed is
   *  unlocked only by a user gesture (VTI-APV-015 as amended).
   *
   *  The plugin recomputes the request's `boundTo` from `operation` (the VTC
   *  step-up digest, salted with `request.challenge`) and refuses when it
   *  differs, renders the operation, takes the gesture, and returns a complete
   *  signed `auth/step-up/approver/attest/0.1` statement with `purpose:
   *  stepUp`. It signs nothing else: the console has the wallet sign the
   *  approve-response around it as the subject's own DID.
   *
   *  Absent from wallet builds without approver support. */
  approveStepUp?(params: {
    request: ApproverStepUpRequest;
    operation: { type: string; payload: unknown };
    audience: string;
  }): Promise<ApproverStatementResult>;
  /** The approver `did:key` the plugin holds for `audience` — one per relying
   *  party, so communities cannot correlate the user by it. Mints nothing the
   *  VTC can use: binding it still needs an enrolment statement. */
  approverIdentity?(params: { audience: string }): Promise<{ approverDid: string }>;
  /** Have the approver for `audience` sign an enrolment statement
   *  (`auth/step-up/approver/attest/0.1`, `purpose: enrol`) — proof of
   *  possession over the VTC's enrolment `challenge`, bound to `boundTo`
   *  (an `enrollmentId`, a `claimId`, or a self-service terms digest). */
  attestApprover?(params: {
    purpose: "enrol";
    subject: string;
    audience: string;
    challenge: string;
    boundTo: string;
  }): Promise<ApproverStatementResult>;
  /** Have the approver for `audience` sign a **decision** statement
   *  (`auth/step-up/approver/attest/0.1`, `purpose: decision`) over an
   *  administrator action (vta-browser-plugin #293).
   *
   *  `decision.payloadDigest` is the decision's per-approver **wire** digest —
   *  `wireDigest(action.type, action.payload, decision.challenge)`, domain
   *  `vta/task-consent/v1\0` — never the action's unsalted `payloadDigest`.
   *  The plugin recomputes it from `action` and refuses when it differs,
   *  renders the action (and its `summary`) to the user, takes the gesture,
   *  and returns the signed statement. It then signs, without a second
   *  prompt, a `task-consent/decision/0.2` from `subject` whose payload
   *  carries exactly these `challenge`, `payloadDigest`, `decision`, `reason`
   *  and `actionId` with the statement as `approverSigned` evidence — any
   *  other payload prompts as an ordinary `signTrustTask`.
   *
   *  Absent from wallet builds without decision support. */
  approveDecision?(params: ApproveDecisionParams): Promise<ApproverStatementResult>;
}

/** What [`VtaWalletProvider.approveDecision`] takes. */
export interface ApproveDecisionParams {
  /** The VTC's DID — whose approver answers. */
  audience: string;
  /** The signed-in administrator — the decision's signer. */
  subject: string;
  action: {
    /** The action's `typeUri`. */
    type: string;
    payload: unknown;
    actionId: string;
    /** The action's summary, as received. */
    summary: unknown;
  };
  decision: {
    challenge: string;
    /** The salted wire digest, as the decision carries it. */
    payloadDigest: string;
    decision: "approve" | "deny";
    reason?: string;
  };
}

/** `task-consent/decision/0.2`'s `approverSigned` evidence: the approver's
 *  signed `attest/0.1` statement (`purpose: decision`), carried unchanged. */
export interface ApproverSignedEvidence {
  kind: "approverSigned";
  statement: Record<string, unknown>;
}

/** The step-up request handed to the plugin's `approveStepUp` — the VTC's
 *  inline `auth/step-up/approve-request/0.4` payload, as received. */
export interface ApproverStepUpRequest {
  subject: string;
  challenge: string;
  boundTo?: string;
  reason: string;
  accepts?: string[];
  approvers?: string[];
  [k: string]: unknown;
}

/** What the plugin's approver methods return: the complete signed
 *  `auth/step-up/approver/attest/0.1` document, carried unchanged. */
export interface ApproverStatementResult {
  statement: Record<string, unknown>;
  approverDid: string;
}

interface WalletProfileWireResult {
  /** The persona DID this VTC knows the operator as. `/auth/challenge` is
   *  bound to it, so it has to be known before a nonce can be asked for. */
  did: string;
  /** The vault entry backing it — passed straight to `proxyLogin` so the
   *  wallet does not repeat the lookup it just did. */
  entryId: string;
  /** True when the wallet bound this persona just now, i.e. the operator was
   *  prompted. The VTC has never seen it, so the sign-in that follows will be
   *  refused until the DID is on the ACL — which is worth saying plainly
   *  rather than surfacing as an opaque 403. */
  bound: boolean;
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

/** True iff the wallet exposes the whole proxy-login surface this page drives:
 *  `walletProfile` to resolve the identity, `proxyLogin` to mint as it, and
 *  `vaultList` for the pick-a-different-identity path.
 *
 *  Presence detection, not version negotiation — the extension may simply not
 *  be installed. There is deliberately no separate probe per method: every
 *  build that has one has all three, so a second probe would only describe a
 *  wallet that does not exist. */
export function isWalletProxyAvailable(): boolean {
  return (
    isWalletAvailable() &&
    typeof window.vtaWallet?.walletProfile === "function" &&
    typeof window.vtaWallet?.proxyLogin === "function" &&
    typeof window.vtaWallet?.vaultList === "function"
  );
}

/** True iff the wallet can sign a Trust Task document as a persona. */
export function isWalletSigningAvailable(): boolean {
  return isWalletAvailable() && typeof window.vtaWallet?.signTrustTask === "function";
}

/** True iff the wallet can answer a step-up with its approver **and** sign the
 *  approve-response as the subject — both halves of an `approverSigned`
 *  answer (`auth/step-up/approve-response/0.6`). */
export function isWalletApproverAvailable(): boolean {
  return isWalletSigningAvailable() && typeof window.vtaWallet?.approveStepUp === "function";
}

/** True iff the wallet can enrol its approver here: name it, prove possession
 *  of it, and sign the enrolment as the subject. */
export function isWalletApproverEnrolmentAvailable(): boolean {
  return (
    isWalletSigningAvailable() &&
    typeof window.vtaWallet?.approverIdentity === "function" &&
    typeof window.vtaWallet?.attestApprover === "function"
  );
}

/** True iff the wallet can answer an administrator action's decision with its
 *  approver **and** sign the decision as the administrator — both halves of an
 *  `approverSigned` decision (`task-consent/decision/0.2`). */
export function isWalletDecisionApproverAvailable(): boolean {
  return isWalletSigningAvailable() && typeof window.vtaWallet?.approveDecision === "function";
}

/** The approver `did:key` this browser's plugin holds for `audience`, or
 *  `null` when the plugin does not say (no `approverIdentity`). */
export async function walletApproverIdentity(audience: string): Promise<string | null> {
  if (typeof window === "undefined" || typeof window.vtaWallet?.approverIdentity !== "function") {
    return null;
  }
  const { approverDid } = await window.vtaWallet.approverIdentity({ audience });
  return typeof approverDid === "string" && approverDid ? approverDid : null;
}

/** [`VtaWalletProvider.approveDecision`], feature-detected. */
export async function approveDecisionWithWallet(
  params: ApproveDecisionParams,
): Promise<ApproverStatementResult> {
  if (!isWalletDecisionApproverAvailable()) {
    throw new Error("The VTA wallet extension cannot answer a decision with an approver.");
  }
  return checkStatement(await window.vtaWallet!.approveDecision!(params));
}

/** The statement must be an `attest/0.1` document issued by a `did:key` —
 *  checked so a wallet that answered with something else is named here rather
 *  than refused as `statementInvalid` by the VTC. */
function checkStatement(result: ApproverStatementResult): ApproverStatementResult {
  const s = result?.statement;
  if (
    !s ||
    typeof s !== "object" ||
    s.type !== ATTEST_TYPE ||
    typeof s.issuer !== "string" ||
    !s.issuer.startsWith("did:key:") ||
    !s.proof
  ) {
    throw new Error("The wallet returned no signed approver statement.");
  }
  return { statement: s, approverDid: s.issuer };
}

const ATTEST_TYPE = "https://trusttasks.org/spec/auth/step-up/approver/attest/0.1";

/** [`VtaWalletProvider.approveStepUp`], feature-detected. */
export async function approveStepUpWithWallet(params: {
  request: ApproverStepUpRequest;
  operation: { type: string; payload: unknown };
  audience: string;
}): Promise<ApproverStatementResult> {
  if (!isWalletApproverAvailable()) {
    throw new Error("The VTA wallet extension cannot answer a step-up with an approver.");
  }
  return checkStatement(await window.vtaWallet!.approveStepUp!(params));
}

/** [`VtaWalletProvider.approverIdentity`], feature-detected. */
export async function walletApproverDid(audience: string): Promise<string> {
  if (!isWalletApproverEnrolmentAvailable()) {
    throw new Error("The VTA wallet extension has no approver to enrol.");
  }
  const { approverDid } = await window.vtaWallet!.approverIdentity!({ audience });
  if (typeof approverDid !== "string" || !approverDid.startsWith("did:key:z6Mk")) {
    throw new Error("The wallet's approver is not an Ed25519 did:key.");
  }
  return approverDid;
}

/** [`VtaWalletProvider.attestApprover`], feature-detected. */
export async function attestApproverWithWallet(params: {
  purpose: "enrol";
  subject: string;
  audience: string;
  challenge: string;
  boundTo: string;
}): Promise<ApproverStatementResult> {
  if (!isWalletApproverEnrolmentAvailable()) {
    throw new Error("The VTA wallet extension has no approver to enrol.");
  }
  return checkStatement(await window.vtaWallet!.attestApprover!(params));
}

/** The persona DID this VTC knows the user as, from the wallet — or `null`
 *  when the wallet cannot say (no `walletProfile`). */
export async function walletPersonaDid(): Promise<string | null> {
  if (typeof window === "undefined" || typeof window.vtaWallet?.walletProfile !== "function") {
    return null;
  }
  const profile = await window.vtaWallet.walletProfile({
    target: { kind: "did", did: await rpDid() },
  });
  return profile?.did || null;
}

/**
 * Have the wallet sign `envelope` as `asDid` — the persona this VTC knows the
 * operator as, whose key the VTA holds.
 *
 * Checks the proof names `asDid` before returning it. A wallet that finds no
 * persona for `asDid` has been seen to sign with its own extension key
 * instead, which the VTC would refuse as signed by somebody else; saying so
 * here names the actual problem.
 */
export async function signWithWallet(
  envelope: Record<string, unknown>,
  asDid: string,
): Promise<Record<string, unknown>> {
  if (!isWalletSigningAvailable()) {
    throw new Error("The VTA wallet extension is not available to sign with.");
  }
  const { signedEnvelope } = await window.vtaWallet!.signTrustTask!({ envelope, asDid });
  const vm = (signedEnvelope.proof as { verificationMethod?: unknown } | undefined)
    ?.verificationMethod;
  if (typeof vm !== "string" || vm.split("#")[0] !== asDid) {
    throw new Error(
      `The wallet signed as a different identity than ${asDid}. Sign in with the ` +
        "wallet identity this community knows you as, then try again.",
    );
  }
  return signedEnvelope;
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
  return runProxySiop(entry.principalDid, entry.id);
}

/** A VTA-identity sign-in that failed, carrying the DID it presented — the
 *  DID a refusal is about, and the one the VTC's ACL would have to name. */
export class SignInAsError extends Error {
  readonly presentedDid: string;
  constructor(message: string, presentedDid: string) {
    super(message);
    this.name = "SignInAsError";
    this.presentedDid = presentedDid;
  }
}

/**
 * The preferred VTA-proxied sign-in: let the wallet say which persona this
 * VTC knows the operator as, then run the round-trip as that persona.
 *
 * Why this and not `listProxyCandidates()` first — the flow it replaces asked
 * the wallet to enumerate *every* vault entry pinned to this VTC in order to
 * find one, which is a disclosure of the operator's vault to answer a question
 * about a single entry, and on a fresh wallet it returned nothing and dead-ended
 * with "add an entry, then retry". The wallet now owns that question: it
 * resolves the entry for this origin, or asks the operator to choose a persona
 * and remembers the answer.
 *
 * The persona DID has to be known *before* the challenge, because
 * `/auth/challenge` is bound to it — which is why this cannot be folded into
 * `proxyLogin` as a single call.
 */
export async function loginWithWalletProfile(): Promise<VtaWalletLoginResult> {
  if (!isWalletProxyAvailable()) {
    throw new Error("VTA wallet doesn't expose proxy-login APIs.");
  }
  const rp = await rpDid();
  const profile = await window.vtaWallet!.walletProfile!({
    target: { kind: "did", did: rp },
  });
  if (!profile.did || !profile.entryId) {
    throw new Error("wallet returned no identity for this site");
  }
  try {
    return await runProxySiop(profile.did, profile.entryId);
  } catch (err) {
    if (!profile.bound) {
      // Not a first sign-in, but the DID is still the one thing a refusal
      // needs and the page cannot otherwise see — carry it to the caller.
      throw new SignInAsError(
        err instanceof Error ? err.message : String(err),
        profile.did,
      );
    }
    // The persona was created a moment ago, so this VTC has never seen it and
    // the ACL gate in `handle_challenge` is by far the likeliest cause. Say
    // which DID needs admitting: the operator cannot act on a 403 alone, and
    // the DID is not otherwise on screen anywhere.
    const message = err instanceof Error ? err.message : String(err);
    throw new Error(
      `${message}\n\nThis was the first sign-in as ${profile.did}. ` +
        "If the VTC refused it, that DID needs an Admin entry in this VTC's ACL — " +
        `ask another admin to run \`vtc admin invite --did ${profile.did}\`.`,
    );
  }
}

/** Challenge → mint → authenticate, as a known persona. Shared by the
 *  wallet-resolved path and the hand-picked-entry path, so both apply the same
 *  rule and the same error handling. */
async function runProxySiop(
  principalDid: string,
  entryId: string,
): Promise<VtaWalletLoginResult> {
  const rp = await rpDid();
  const base = walletApiBase().replace(/\/+$/, "");

  // 1. Challenge bound to the entry's principal DID.
  const chRes = await fetch(`${base}/auth/challenge`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    credentials: "include",
    body: JSON.stringify({ did: principalDid }),
  });
  if (!chRes.ok) {
    // Carry the daemon's message, not just the code. A 403 here is the ACL
    // gate in `handle_challenge` and it has three distinct causes — the
    // principal DID is absent from the VTC ACL, its entry has expired, or its
    // role is not `Admin` — which the status code alone cannot tell apart.
    throw new Error(
      `/auth/challenge failed (${chRes.status}): ${await daemonErrorMessage(
        chRes,
        chRes.statusText,
      )}`,
    );
  }
  // Challenge response is camelCase; the authenticate payload is snake_case.
  const ch = (await chRes.json()) as { challenge: string; sessionId: string };
  if (!ch.sessionId || !ch.challenge) {
    throw new Error("/auth/challenge: malformed response");
  }

  // 2. VTA mints the SIOP id_token (long-term key stays in the VTA).
  const pl = await window.vtaWallet!.proxyLogin!({
    entryId,
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
    throw new Error(
      `/auth/ failed (${authRes.status}): ${await daemonErrorMessage(
        authRes,
        authRes.statusText,
      )}`,
    );
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
    holderDid: principalDid,
  };
}
