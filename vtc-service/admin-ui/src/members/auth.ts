// The two ways a member signs in: SIOPv2 issued by the member's own VTA, and a
// portal passkey. Each ends with the portal's cookies set by the daemon.
//
// SIOPv2 here is the VTA-issued kind, not the wallet extension's own `login()`.
// `login()` self-issues with whatever the extension holds for this site — by
// default its own holder `did:key` — and that is not the identity a community
// admitted. A member joined as their VTA identity, so the portal asks the
// wallet which VTA persona this community knows them as (`walletProfile`) and
// has the VTA mint the `id_token` for that DID (`proxyLogin`). The long-term
// key never leaves the VTA, and the DID presented is the member's.

import {
  decodePublicKeyOptions,
  serializeAssertion,
  serializeRegistration,
  type JsonPublicKeyOptions,
} from "@/lib/webauthn";

import {
  errorMessage,
  MemberApiError,
  postMember,
  vtcDid,
  type MemberPasskey,
} from "./api";

const AUTHENTICATE_TYPE = "https://trusttasks.org/spec/auth/authenticate/0.1";

/** The member SIOP surface. Same shapes as the console's `/v1/wallet`; only
 *  the base differs, and with it who is admitted and the audience minted. */
export function memberWalletBase(): string {
  return `${window.location.origin}/v1/member/wallet`;
}

/** True when the wallet extension can sign in as a VTA identity: resolve the
 *  persona for this site and have the VTA mint as it. */
export function isVtaSignInAvailable(): boolean {
  return (
    typeof window !== "undefined" &&
    typeof window.vtaWallet?.walletProfile === "function" &&
    typeof window.vtaWallet?.proxyLogin === "function"
  );
}

/** A refused VTA sign-in, carrying the DID it presented — the one thing a
 *  member needs to tell an administrator, and not otherwise on screen. */
export class PresentedDidError extends MemberApiError {
  constructor(
    message: string,
    status: number,
    readonly presentedDid: string,
  ) {
    super(message, status);
    this.name = "PresentedDidError";
  }
}

function bearerFromSessionBlob(
  headers: Array<{ name: string; value: string }> | undefined,
): string | null {
  const auth = headers?.find((h) => h.name.toLowerCase() === "authorization");
  const m = auth && /^\s*Bearer\s+(.+?)\s*$/i.exec(auth.value);
  return m && m[1] ? m[1] : null;
}

/** @deprecated Legacy SIOPv2 sign-in (contract C7), behind "Using an older
 *  wallet?". New wallets use the trigger-link sign-in (`./oob`).
 *
 *  SIOPv2 from the member's VTA, as the persona the wallet has bound to this
 *  community (binding one on first use), then mirror the bearer into cookies.
 *
 *  The persona has to be known before the challenge — `/auth/challenge` is
 *  bound to its DID — which is why this is two wallet calls and not one. */
export async function signInWithVta(): Promise<void> {
  requireVtaSignIn();
  const rp = await vtcDid();
  const profile = await window.vtaWallet!.walletProfile!({
    target: { kind: "did", did: rp },
  });
  if (!profile?.did || !profile.entryId) {
    throw new Error("Your wallet returned no identity for this community.");
  }
  await runSiop(rp, profile.did, profile.entryId);
}

/** One of the wallet's VTA identities pinned to this community. */
export interface VtaIdentity {
  entryId: string;
  label: string;
  did: string;
}

/** True when the wallet can also list its identities for this community, so
 *  a member holding more than one can choose. */
export function isIdentityChoiceAvailable(): boolean {
  return isVtaSignInAvailable() && typeof window.vtaWallet?.vaultList === "function";
}

/** The wallet's `did-self-issued` identities pinned to this community. Costs a
 *  wallet consent prompt (it discloses those vault entries to this page), so
 *  it runs only when the member asks to choose. */
export async function listVtaIdentities(): Promise<VtaIdentity[]> {
  if (!isIdentityChoiceAvailable()) {
    throw new Error("Your VTA Wallet extension can't list identities. Update it, then reload.");
  }
  const wire = await window.vtaWallet!.vaultList!({
    targetDid: await vtcDid(),
    secretKind: "didSelfIssued",
  });
  return (wire?.entries ?? [])
    .filter((e) => Boolean(e.principalDid))
    .map((e) => ({ entryId: e.id, label: e.label, did: e.principalDid! }));
}

/** @deprecated Legacy SIOPv2 sign-in (contract C7).
 *  SIOPv2 from the member's VTA as an identity they chose. */
export async function signInWithVtaAs(identity: VtaIdentity): Promise<void> {
  requireVtaSignIn();
  await runSiop(await vtcDid(), identity.did, identity.entryId);
}

function requireVtaSignIn(): void {
  if (!isVtaSignInAvailable()) {
    throw new Error(
      "The VTA Wallet extension isn't installed, or is too old to sign in as your VTA identity.",
    );
  }
}

/** challenge (bound to `did`) → the VTA mints an `id_token` with the
 *  challenge as nonce, addressed to this VTC → `/auth/` verifies it and admits
 *  only an active member → the bearer becomes the portal's cookies. */
async function runSiop(rp: string, did: string, entryId: string): Promise<void> {
  const base = memberWalletBase();

  const ch = await fetch(`${base}/auth/challenge`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    credentials: "same-origin",
    body: JSON.stringify({ did }),
  });
  if (!ch.ok) {
    throw new PresentedDidError(await errorMessage(ch), ch.status, did);
  }
  const challenge = (await ch.json()) as { challenge?: string; sessionId?: string };
  if (!challenge.challenge || !challenge.sessionId) {
    throw new Error("The community sent a malformed sign-in challenge.");
  }

  const minted = await window.vtaWallet!.proxyLogin!({
    entryId,
    nonce: challenge.challenge,
    target: { kind: "did", did: rp },
  });
  const idToken = bearerFromSessionBlob(minted?.sessionBlob?.headers);
  if (!idToken) throw new Error("Your VTA returned no sign-in token.");

  // `id_token` / `session_id` are snake_case on this wire, as the wallet and
  // did-hosting-control send them.
  const auth = await fetch(`${base}/auth/`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    credentials: "same-origin",
    body: JSON.stringify({
      type: AUTHENTICATE_TYPE,
      payload: { id_token: idToken, session_id: challenge.sessionId },
    }),
  });
  if (!auth.ok) {
    throw new PresentedDidError(await errorMessage(auth), auth.status, did);
  }
  const tokens = (await auth.json()) as {
    tokens?: { accessToken?: string; refreshToken?: string };
  };
  if (!tokens.tokens?.accessToken) {
    throw new Error("The community answered the sign-in without a token.");
  }
  await postMember("/v1/member/session", {
    accessToken: tokens.tokens.accessToken,
    refreshToken: tokens.tokens.refreshToken || undefined,
  });
}

export function passkeysSupported(): boolean {
  return (
    typeof window !== "undefined" &&
    typeof window.PublicKeyCredential === "function" &&
    typeof navigator.credentials?.get === "function"
  );
}

/** Discoverable passkey sign-in against portal passkeys only. */
export async function signInWithPasskey(): Promise<void> {
  const start = await postMember<{
    authId: string;
    options: JsonPublicKeyOptions;
  }>("/v1/member/passkey-login/start");
  const publicKey = decodePublicKeyOptions(
    start.options,
  ) as PublicKeyCredentialRequestOptions;
  const credential = (await navigator.credentials.get({
    publicKey,
  })) as PublicKeyCredential | null;
  if (!credential) throw new Error("No passkey was chosen.");
  await postMember("/v1/member/passkey-login/finish", {
    authId: start.authId,
    credential: serializeAssertion(credential),
  });
}

/** Add a portal passkey. The daemon allows it only from a VTA sign-in. */
export async function addPasskey(label: string): Promise<MemberPasskey> {
  const start = await postMember<{
    registrationId: string;
    options: JsonPublicKeyOptions;
  }>("/v1/member/passkeys/register/start");
  const publicKey = decodePublicKeyOptions(
    start.options,
  ) as PublicKeyCredentialCreationOptions;
  const credential = (await navigator.credentials.create({
    publicKey,
  })) as PublicKeyCredential | null;
  if (!credential) throw new Error("Passkey creation was cancelled.");
  return postMember<MemberPasskey>("/v1/member/passkeys/register/finish", {
    registrationId: start.registrationId,
    credential: serializeRegistration(credential),
    label: label.trim() || undefined,
  });
}
