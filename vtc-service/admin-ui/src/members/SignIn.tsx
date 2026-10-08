// Member sign-in: the browser wallet (SIOPv2) or a portal passkey — nothing
// else. Only an active member of this community is admitted; the daemon says
// so in one message whatever the reason, and so does this page.

import { useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { Fingerprint, Wallet } from "lucide-react";

import { MemberApiError } from "./api";
import { InstallWallet } from "./InstallWallet";
import {
  isWalletInstalled,
  passkeysSupported,
  signInWithPasskey,
  signInWithWallet,
} from "./auth";

type Phase =
  | { kind: "idle" }
  | { kind: "running"; method: "wallet" | "passkey" }
  | { kind: "error"; message: string; hint?: string };

const NOT_A_MEMBER_HINT =
  "Sign-in is for active members of this community. If you have joined, make " +
  "sure you are signing in with the identity the community admitted — your " +
  "wallet can hold more than one.";

function describe(err: unknown, method: "wallet" | "passkey"): Phase {
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
          ? "Passkeys work once you have added one from a wallet sign-in. " +
            NOT_A_MEMBER_HINT
          : NOT_A_MEMBER_HINT,
    };
  }
  return { kind: "error", message };
}

export function SignIn({ communityName }: { communityName?: string | null }) {
  const [phase, setPhase] = useState<Phase>({ kind: "idle" });
  const qc = useQueryClient();
  const walletInstalled = isWalletInstalled();
  const busy = phase.kind === "running";

  const run = async (method: "wallet" | "passkey") => {
    setPhase({ kind: "running", method });
    try {
      await (method === "wallet" ? signInWithWallet() : signInWithPasskey());
      setPhase({ kind: "idle" });
      await qc.invalidateQueries({ queryKey: ["member-me"] });
    } catch (err) {
      setPhase(describe(err, method));
    }
  };

  return (
    <main className="signin" id="main">
      <section className="signin-card" aria-labelledby="signin-heading">
        <p className="eyebrow">Member portal</p>
        <h1 id="signin-heading">
          Sign in to {communityName || "your community"}
        </h1>
        <p className="lead">
          Use your VTA Wallet or a passkey you've added here. There are no
          passwords.
        </p>

        <div className="signin-options">
          <button
            type="button"
            className="btn btn-primary btn-lg"
            onClick={() => run("wallet")}
            disabled={busy || !walletInstalled}
          >
            <Wallet size={18} aria-hidden="true" />
            {phase.kind === "running" && phase.method === "wallet"
              ? "Waiting for your wallet…"
              : "Sign in with VTA Wallet"}
          </button>
          {!walletInstalled && (
            <p className="option-note">
              No wallet detected in this browser — install it below, then reload.
            </p>
          )}

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
        </div>

        {phase.kind === "error" && (
          <div className="alert" role="alert">
            <p className="alert-title">{phase.message}</p>
            {phase.hint && <p>{phase.hint}</p>}
          </div>
        )}
      </section>

      <InstallWallet open={!walletInstalled} />

      <p className="signin-foot">
        Not a member yet? Start at{" "}
        <a href="https://openvtc.net" target="_blank" rel="noopener noreferrer">
          openvtc.net
        </a>
        . Running this community? The <a href="/admin/">operator console</a> is
        separate.
      </p>
    </main>
  );
}
