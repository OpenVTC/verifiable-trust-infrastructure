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
  enrolThisBrowser,
  explainEnrolError,
  type SigningStatus,
} from "@/lib/console-keys-api";
import { shortenDid } from "@/lib/format";
import { gestureFromConfirm } from "@/lib/signed-act";

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

  const enrol = useMutation({
    mutationFn: () => enrolThisBrowser(label, gestureFromConfirm(confirm)),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: [SIGNING_STATUS_KEY] });
      void queryClient.invalidateQueries({ queryKey: ["console-keys"] });
    },
  });

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
          this browser. Setting it up takes one passkey confirmation, and lasts
          up to 30 days — the console reminds you to renew before then.
        </p>
        <p className="lead">{whyLine(status)}</p>
        <p className="login-did">
          <span className="muted">Signed in as</span>
          <code title={whoami.session.subject}>{whoami.session.subject}</code>
        </p>
        <form
          className="form-stack"
          onSubmit={(e) => {
            e.preventDefault();
            enrol.mutate();
          }}
        >
          <label className="field">
            <span className="field-label">Name this browser</span>
            <input
              type="text"
              value={label}
              maxLength={128}
              onChange={(e) => setLabel(e.target.value)}
            />
          </label>
          <button type="submit" className="primary" disabled={enrol.isPending}>
            {enrol.isPending ? "Waiting for your passkey…" : "Set up signing"}
          </button>
        </form>
        {enrol.error && (
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
