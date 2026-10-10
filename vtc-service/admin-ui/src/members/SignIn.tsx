// Member sign-in. In order:
//
// 1. **Sign in with your wallet** — the trigger-link key grant (`auth/oob/*`,
//    `WalletSignIn`), the default (contract C7).
// 2. A portal passkey.
// 3. **Using an older wallet?** — SIOPv2 issued by the member's VTA through
//    the browser extension. Deprecated (contract C7): kept, not deleted, until
//    a removal date is set.
//
// Only an active member of this community is admitted; the daemon says so in
// one message whatever the reason, and so does this page. There is
// deliberately no "sign in with this browser's wallet" button: the
// extension's own `login()` presents its holder `did:key`, which no community
// admitted as a member.

import { useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { Fingerprint, Wallet } from "lucide-react";

import { shortenDid } from "@/lib/format";

import { HomeLink, OlderWalletOptions, SignInPage } from "../signin/SignInLayout";

import { MemberApiError } from "./api";
import { InstallWallet } from "./InstallWallet";
import { WalletSignIn } from "./WalletSignIn";
import {
  isIdentityChoiceAvailable,
  isVtaSignInAvailable,
  listVtaIdentities,
  passkeysSupported,
  PresentedDidError,
  signInWithPasskey,
  signInWithVta,
  signInWithVtaAs,
  type VtaIdentity,
} from "./auth";

type Method = "vta" | "passkey" | "choose";

type Phase =
  | { kind: "idle" }
  | { kind: "running"; method: Method }
  | {
      kind: "error";
      message: string;
      hint?: string;
      /** The DID a refused VTA sign-in presented. */
      presentedDid?: string;
    };

const NOT_A_MEMBER_HINT =
  "Sign-in is for active members of this community. If you have joined, make " +
  "sure you are signing in with the identity the community admitted — your " +
  "VTA can hold more than one.";

function describe(err: unknown, method: Method): Phase {
  if (err instanceof DOMException && err.name === "NotAllowedError") {
    return { kind: "error", message: "The passkey prompt was cancelled." };
  }
  const message = err instanceof Error ? err.message : String(err);
  if (err instanceof MemberApiError && (err.status === 401 || err.status === 403)) {
    return {
      kind: "error",
      message: "This community didn't accept that sign-in.",
      hint:
        method === "passkey"
          ? "Passkeys work once you have added one after signing in with your VTA. " +
            NOT_A_MEMBER_HINT
          : NOT_A_MEMBER_HINT,
      ...(err instanceof PresentedDidError ? { presentedDid: err.presentedDid } : {}),
    };
  }
  return { kind: "error", message };
}

export function SignIn({ communityName }: { communityName?: string | null }) {
  const [phase, setPhase] = useState<Phase>({ kind: "idle" });
  const qc = useQueryClient();
  const [choices, setChoices] = useState<VtaIdentity[] | null>(null);
  const vtaAvailable = isVtaSignInAvailable();
  const canChoose = isIdentityChoiceAvailable();
  const busy = phase.kind === "running";

  const attempt = async (method: Method, signIn: () => Promise<void>) => {
    setPhase({ kind: "running", method });
    try {
      await signIn();
      setPhase({ kind: "idle" });
      setChoices(null);
      await qc.invalidateQueries({ queryKey: ["member-me"] });
    } catch (err) {
      setPhase(describe(err, method));
    }
  };

  const run = (method: "vta" | "passkey") =>
    attempt(method, method === "vta" ? signInWithVta : signInWithPasskey);

  // Lists the wallet's identities pinned to this community. Behind an explicit
  // click because the wallet asks consent before disclosing its vault entries.
  const chooseIdentity = async () => {
    setPhase({ kind: "running", method: "choose" });
    setChoices(null);
    try {
      const found = await listVtaIdentities();
      if (found.length === 0) {
        setPhase({
          kind: "error",
          message: "Your wallet has no other identities set up for this community.",
          hint:
            "Use “Sign in with your VTA” — the wallet asks which of your VTA's " +
            "identities to use and remembers it for this community.",
        });
        return;
      }
      setPhase({ kind: "idle" });
      setChoices(found);
    } catch (err) {
      setPhase(describe(err, "choose"));
    }
  };

  return (
    <SignInPage
      eyebrow="Member portal"
      title={<>Sign in to {communityName || "your community"}</>}
      lead={
        <>
          Sign in with the wallet that holds your membership, or with a passkey
          you've added here. There are no passwords.
        </>
      }
      after={
        phase.kind === "error" && (
          <div className="alert" role="alert">
            <p className="alert-title">{phase.message}</p>
            {phase.presentedDid && (
              <p>
                Your VTA signed in as{" "}
                <code className="did-inline" title={phase.presentedDid}>
                  {shortenDid(phase.presentedDid)}
                </code>
                .
              </p>
            )}
            {phase.hint && <p>{phase.hint}</p>}
            {phase.presentedDid && canChoose && (
              <button
                type="button"
                className="btn btn-secondary btn-sm"
                onClick={chooseIdentity}
                disabled={busy}
              >
                Sign in as a different identity…
              </button>
            )}
          </div>
        )
      }
      foot={[
        <>
          Not a member yet? Start at{" "}
          <a href="https://openvtc.net" target="_blank" rel="noopener noreferrer">
            openvtc.net
          </a>
          . Running this community? The <a href="/admin/">operator console</a> is
          separate.
        </>,
        <HomeLink communityName={communityName} />,
      ]}
    >
      <WalletSignIn
        communityName={communityName}
        onSignedIn={() => qc.invalidateQueries({ queryKey: ["member-me"] })}
      />

      <button
        type="button"
        className="btn btn-secondary btn-lg"
        onClick={() => run("passkey")}
        disabled={busy || !passkeysSupported()}
      >
        <Fingerprint size={18} aria-hidden="true" />
        {phase.kind === "running" && phase.method === "passkey"
          ? "Waiting for your passkey…"
          : "Sign in with a passkey"}
      </button>
      <p className="option-note">
        First time? Sign in with your wallet, then add a passkey for this
        device.
      </p>

      <OlderWalletOptions>
        <p className="option-note">
          The VTA Wallet browser extension's older sign-in (SIOPv2). It is
          deprecated and will be removed; use “Sign in with your wallet”
          when your wallet supports it.
        </p>
        <button
          type="button"
          className="btn btn-secondary"
          onClick={() => run("vta")}
          disabled={busy || !vtaAvailable}
        >
          <Wallet size={18} aria-hidden="true" />
          {phase.kind === "running" && phase.method === "vta"
            ? "Waiting for your VTA…"
            : "Sign in with your VTA"}
        </button>
        <p className="option-note">
          {vtaAvailable
            ? "SIOPv2: your VTA signs as your member identity. Its key never leaves your VTA."
            : "Needs the VTA Wallet browser extension, which connects this page to your VTA — install it below, then reload."}
        </p>
        {canChoose && (
          <button
            type="button"
            className="btn btn-link"
            onClick={chooseIdentity}
            disabled={busy}
          >
            {phase.kind === "running" && phase.method === "choose"
              ? "Asking your wallet…"
              : "Sign in as a different identity…"}
          </button>
        )}

        {choices && (
          <section className="identity-picker" aria-labelledby="identity-picker-heading">
            <h2 id="identity-picker-heading">Choose an identity</h2>
            <p className="option-note">
              Your wallet holds these identities for this community. Pick the
              one the community admitted you as.
            </p>
            <ul className="identity-choices">
              {choices.map((c) => (
                <li key={c.entryId}>
                  <button
                    type="button"
                    className="identity-choice"
                    onClick={() => attempt("vta", () => signInWithVtaAs(c))}
                    disabled={busy}
                    title={c.did}
                  >
                    <span className="identity-choice-label">{c.label || "Identity"}</span>
                    <code className="identity-choice-did">{shortenDid(c.did)}</code>
                  </button>
                </li>
              ))}
            </ul>
            <button
              type="button"
              className="btn btn-ghost btn-sm"
              onClick={() => setChoices(null)}
            >
              Cancel
            </button>
          </section>
        )}

        <InstallWallet open={false} />
      </OlderWalletOptions>
    </SignInPage>
  );
}
