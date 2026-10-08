// The two ways a member signs in: the browser wallet (SIOPv2) and a portal
// passkey. Each ends with the portal's cookies set by the daemon.

import {
  decodePublicKeyOptions,
  serializeAssertion,
  serializeRegistration,
  type JsonPublicKeyOptions,
} from "@/lib/webauthn";

import { postMember, vtcDid, type MemberPasskey } from "./api";

/** The wallet surface the portal points the extension at. The wallet appends
 *  `/auth/challenge`, `/auth/` and `/auth/refresh`, exactly as it does for the
 *  console's `/v1/wallet` — only the base differs, and with it the audience of
 *  the token the VTC mints. */
export function memberWalletBase(): string {
  return `${window.location.origin}/v1/member/wallet`;
}

export function isWalletInstalled(): boolean {
  return (
    typeof window !== "undefined" &&
    typeof window.vtaWallet?.login === "function"
  );
}

/** SIOPv2 through the browser wallet, then mirror the bearer into cookies. */
export async function signInWithWallet(): Promise<void> {
  if (!isWalletInstalled()) {
    throw new Error("The VTA Wallet browser extension isn't installed.");
  }
  const result = await window.vtaWallet!.login({
    rpDid: await vtcDid(),
    baseUrl: memberWalletBase(),
  });
  await postMember("/v1/member/session", {
    accessToken: result.accessToken,
    refreshToken: result.refreshToken || undefined,
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

/** Add a portal passkey. The daemon allows it only from a wallet sign-in. */
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
