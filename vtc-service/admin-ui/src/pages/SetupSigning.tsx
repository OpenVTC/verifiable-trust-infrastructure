// The step between signing in and the console: give this browser a signing
// key the community accepts.
//
// Every administrator verb the console sends is a signed Trust Task document
// (the bearer twins are gone, #1808), so an administrator whose browser holds
// no enrolled key can sign in and then do nothing — and, before this page,
// every screen they opened sent a document signed by a key the VTC did not
// know. The VTC charges those to the anonymous per-address budget
// (`routing::trust_task_admission`), so a few clicks around the console used
// it up and the enrolment that would have fixed it came back 429.
//
// So the shell asks `signingStatus` once a session exists and, for an
// administrator without an accepted key, shows this instead of the console.
// Nothing here signs anything until the operator asks; the enrolment it runs
// is three requests (enrol, the passkey answer, enrol again).

import { type ReactNode, useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";

import { useConfirm } from "@/components/ConfirmDialog";
import { signOut, type WhoamiResponse } from "@/lib/api";
import {
  type EnrolEvidence,
  enrolThisBrowser,
  explainEnrolError,
  preferredEvidence,
  type SigningStatus,
  TooManyKeysError,
} from "@/lib/console-keys-api";
import { formatIso, shortenDid } from "@/lib/format";
import { gestureFromConfirm } from "@/lib/signed-act";
import { isWalletSigningAvailable } from "@/lib/wallet";
import { Field } from "@/components/Field";

/** The query key the shell keeps this browser's signing status under. */
export const SIGNING_STATUS_KEY = "signing-status";

/** A label to start from: the browser and OS this is, so a list of keys reads. */
export function suggestedLabel(userAgent: string = navigator.userAgent): string {
  const browser = /Edg\//.test(userAgent)
    ? "Edge"
    : /Firefox\//.test(userAgent)
      ? "Firefox"
      : /Chrome\//.test(userAgent)
        ? "Chrome"
        : /Safari\//.test(userAgent)
          ? "Safari"
          : "Browser";
  const os = /iPhone|iPad/.test(userAgent)
    ? "iOS"
    : /Android/.test(userAgent)
      ? "Android"
      : /Mac OS X/.test(userAgent)
        ? "macOS"
        : /Windows/.test(userAgent)
          ? "Windows"
          : /Linux/.test(userAgent)
            ? "Linux"
            : null;
  return os ? `${browser} on ${os}` : browser;
}

function whyLine(status: SigningStatus): string {
  switch (status.state) {
    case "not-enrolled":
      return (
        "This browser's signing key is no longer accepted here — it expired, was " +
        "revoked, or the community was restored from a backup. Setting up makes a " +
        "new one."
      );
    case "other-identity":
      return (
        `This browser's signing key belongs to another administrator ` +
        `(${shortenDid(status.identityDid)}). Setting up here replaces it in this ` +
        "browser; they set up again the next time they use it."
      );
    default:
      return "This browser has no signing key for this community yet.";
  }
}

export function SetupSigning({
  whoami,
  status,
}: {
  whoami: WhoamiResponse;
  status: SigningStatus;
}) {
  const queryClient = useQueryClient();
  const confirm = useConfirm();
  const [label, setLabel] = useState(() => suggestedLabel());
  const [evidence, setEvidence] = useState<EnrolEvidence>(() =>
    preferredEvidence(whoami.session.amr),
  );
  const [replaces, setReplaces] = useState<string | null>(null);
  const canUseWallet = isWalletSigningAvailable();

  const enrol = useMutation({
    mutationFn: (opts: { replaces?: string }) =>
      enrolThisBrowser(label, gestureFromConfirm(confirm), {
        evidence,
        replaces: opts.replaces,
      }),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: [SIGNING_STATUS_KEY] });
      void queryClient.invalidateQueries({ queryKey: ["console-keys"] });
    },
  });
  // At the cap the VTC lists the active keys; the least recently used comes
  // first and is the one offered by default.
  const atCap = enrol.error instanceof TooManyKeysError ? enrol.error : null;
  const chosen = replaces ?? atCap?.activeKeys[0]?.signingKeyDid ?? null;
  const waiting = evidence === "wallet" ? "Waiting for your wallet…" : "Waiting for your passkey…";

  const signOutMut = useMutation({
    mutationFn: signOut,
    onSettled: () => queryClient.invalidateQueries({ queryKey: ["whoami"] }),
  });

  if (status.state === "unsupported") {
    return (
      <section className="page login-page">
        <div className="login-card">
          <h2>This browser cannot sign</h2>
          <p className="lead">
            The console signs everything you do with a key kept in your browser,
            and this one has no WebCrypto Ed25519. Use Chrome 137 or later,
            Firefox 130 or later, or Safari 17 or later.
          </p>
          <SignOutFooter onSignOut={() => signOutMut.mutate()} />
        </div>
      </section>
    );
  }

  return (
    <section className="page login-page">
      <div className="login-card">
        <h2>Set up signing</h2>
        <p className="lead">
          Everything you do in this console is signed by a key that never leaves
          this browser.{" "}
          {evidence === "wallet"
            ? "Setting it up takes one approval in your VTA wallet"
            : "Setting it up takes one passkey confirmation"}
          , and lasts up to 30 days — the console reminds you to renew before then.
        </p>
        <p className="lead">{whyLine(status)}</p>
        <p className="login-did">
          <span className="muted">Signed in as</span>
          <code title={whoami.session.subject}>{whoami.session.subject}</code>
        </p>
        {atCap ? (
          <form
            className="form-stack"
            onSubmit={(e) => {
              e.preventDefault();
              if (chosen) enrol.mutate({ replaces: chosen });
            }}
          >
            <p className="lead">
              You already have {atCap.maxActiveKeys ?? "the maximum number of"} active
              signing keys, from other browsers. Choose one you no longer use to
              replace — it stops working immediately. This asks for your{" "}
              {evidence === "wallet" ? "wallet" : "passkey"} once more.
            </p>
            {atCap.activeKeys.map((k) => (
              <label key={k.signingKeyDid} className="login-option">
                <span>
                  <input
                    type="radio"
                    name="replaces"
                    value={k.signingKeyDid}
                    checked={chosen === k.signingKeyDid}
                    onChange={() => setReplaces(k.signingKeyDid)}
                  />{" "}
                  {k.deviceLabel ?? shortenDid(k.signingKeyDid)}
                </span>
                <span className="login-option-note">
                  Last used {k.lastUsedAt ? formatIso(k.lastUsedAt) : "never"} · set up{" "}
                  {formatIso(k.createdAt)}
                </span>
              </label>
            ))}
            <button type="submit" className="primary" disabled={enrol.isPending || !chosen}>
              {enrol.isPending ? waiting : "Replace it and set up signing"}
            </button>
          </form>
        ) : (
          <form
            className="form-stack"
            onSubmit={(e) => {
              e.preventDefault();
              enrol.mutate({});
            }}
          >
            <Field label="Name this browser">
              <input
                type="text"
                value={label}
                maxLength={128}
                onChange={(e) => setLabel(e.target.value)}
              />
            </Field>
            <button type="submit" className="primary" disabled={enrol.isPending}>
              {enrol.isPending
                ? waiting
                : evidence === "wallet"
                  ? "Set up signing with your wallet"
                  : "Set up signing with your passkey"}
            </button>
            {canUseWallet && (
              <button
                type="button"
                className="link"
                disabled={enrol.isPending}
                onClick={() => setEvidence(evidence === "wallet" ? "passkey" : "wallet")}
              >
                {evidence === "wallet" ? "Use a passkey instead" : "Use your VTA wallet instead"}
              </button>
            )}
          </form>
        )}
        {enrol.error && !atCap && (
          <section className="card error" role="alert">
            <h3>Signing was not set up</h3>
            <p>{explainEnrolError(enrol.error)}</p>
          </section>
        )}
        <SignOutFooter onSignOut={() => signOutMut.mutate()}>
          The key is kept for this address only ({window.location.origin}).
          Another browser, profile or private window sets up its own.
        </SignOutFooter>
      </div>
    </section>
  );
}

/**
 * The status check itself failed — the network, the VTC, a rate limit or the
 * browser's key store. Not evidence the key stopped working, so this offers a
 * retry and never enrolment.
 */
export function SigningCheckFailed({ error, onRetry }: { error: unknown; onRetry: () => void }) {
  const queryClient = useQueryClient();
  const signOutMut = useMutation({
    mutationFn: signOut,
    onSettled: () => queryClient.invalidateQueries({ queryKey: ["whoami"] }),
  });
  return (
    <section className="page login-page">
      <div className="login-card">
        <h2>Could not check this browser's signing key</h2>
        <p className="lead">{(error as Error | null)?.message ?? String(error)}</p>
        <button type="button" className="primary" onClick={onRetry}>
          Try again
        </button>
        <SignOutFooter onSignOut={() => signOutMut.mutate()} />
      </div>
    </section>
  );
}

function SignOutFooter({
  onSignOut,
  children,
}: {
  onSignOut: () => void;
  children?: ReactNode;
}) {
  return (
    <footer>
      {children && <p>{children}</p>}
      <p>
        <button type="button" className="link" onClick={onSignOut}>
          Sign out
        </button>
      </p>
    </footer>
  );
}
