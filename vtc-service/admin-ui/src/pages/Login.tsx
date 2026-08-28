// Login page: passkey + VTA-wallet sign-in.
//
// Passkey: POST `/v1/auth/passkey-login/start` → `navigator.credentials.get`
// → POST `/finish` → daemon sets the `vtc_admin_session` + `csrf` cookies.
//
// VTA wallet (additive — passkey is unchanged): the browser wallet extension
// runs a SIOPv2 login against the VTC's header-exempt `/v1/wallet` surface
// and returns a bearer token; we exchange it for the same cookie session via
// `/v1/auth/admin-session`. A second option proxies the SIOP through the VTA
// for a `did-self-issued` vault entry. Both end by invalidating the `whoami`
// probe so the shell re-renders into the authenticated tree.

import { useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { Fingerprint, Wallet } from "lucide-react";

import { postJson } from "@/lib/api";
import {
  decodePublicKeyOptions,
  serializeAssertion,
  type JsonPublicKeyOptions,
} from "@/lib/webauthn";
import {
  isWalletAvailable,
  isWalletProxyAvailable,
  listProxyCandidates,
  loginWithWallet,
  loginWithWalletProxy,
  type ProxyVaultEntry,
} from "@/lib/wallet";

// 0.2, not 0.1: the daemon binds the successor wire form, whose `purpose`
// enum uses the camelCase `stepUp` value. The Trust-Task header is matched
// exactly, so this must track the route binding in `routes/mod.rs`.
const TRUST_TASK_START =
  "https://trusttasks.org/spec/auth/passkey/login/start/0.2";
const TRUST_TASK_FINISH =
  "https://trusttasks.org/spec/auth/passkey/login/finish/0.2";
const TRUST_TASK_ADMIN_SESSION =
  "https://trusttasks.org/spec/vtc/auth/admin-session/0.1";

type Phase =
  | { kind: "idle" }
  | { kind: "running" }
  | { kind: "error"; message: string; hint?: string };

export function Login() {
  const [phase, setPhase] = useState<Phase>({ kind: "idle" });
  const [walletPhase, setWalletPhase] = useState<Phase>({ kind: "idle" });
  const [candidates, setCandidates] = useState<ProxyVaultEntry[] | null>(null);
  const queryClient = useQueryClient();

  const walletAvailable = isWalletAvailable();
  const proxyAvailable = isWalletProxyAvailable();
  const busy = phase.kind === "running" || walletPhase.kind === "running";

  // Shared success tail: the wallet returned a bearer; mirror it into the
  // SPA cookie session, then flip the shell to authenticated.
  const finishWithBearer = async (accessToken: string) => {
    await postJson<void>(
      "/v1/auth/admin-session",
      { accessToken },
      { trustTask: TRUST_TASK_ADMIN_SESSION },
    );
    await queryClient.invalidateQueries({ queryKey: ["whoami"] });
  };

  const signIn = async () => {
    setPhase({ kind: "running" });
    // Did we get as far as handing the challenge to the browser? Everything
    // before that point is the daemon's response and our handling of it;
    // everything after is the authenticator and the operator. The two have
    // completely different remedies, and an operator can see which side they
    // are on — "it never asked me for my passkey" — so the console should be
    // able to say it too.
    let reachedPrompt = false;
    try {
      // `login/start/0.2` sends the *inner* WebAuthn options — the value that
      // goes in `navigator.credentials.get({ publicKey: … })` — not
      // webauthn-rs's `{publicKey: …}` wrapper. #1112 dropped the wrapper.
      const start = await postJson<{
        authId: string;
        options: JsonPublicKeyOptions;
      }>("/v1/auth/passkey-login/start", undefined, {
        trustTask: TRUST_TASK_START,
        // The sign-in screen is where an unhelpful error costs the most: it
        // is the one page an operator cannot navigate away from. Without
        // this, a daemon newer than the bundle fails inside
        // `decodePublicKeyOptions` as "Cannot read properties of undefined
        // (reading 'challenge')" — with no passkey prompt, because the throw
        // happens on the line before `navigator.credentials.get`.
        requires: ["authId", "options.challenge"],
      });

      const publicKey = decodePublicKeyOptions(
        start.options,
      ) as PublicKeyCredentialRequestOptions;

      reachedPrompt = true;
      const credential = (await navigator.credentials.get({
        publicKey,
      })) as PublicKeyCredential | null;
      if (!credential) {
        setPhase({
          kind: "error",
          message: "Passkey ceremony returned no credential.",
          hint: "Retry, or use a different authenticator.",
        });
        return;
      }

      await postJson<unknown>(
        "/v1/auth/passkey-login/finish",
        {
          auth_id: start.authId,
          credential: serializeAssertion(credential),
        },
        { trustTask: TRUST_TASK_FINISH },
      );

      await queryClient.invalidateQueries({ queryKey: ["whoami"] });
    } catch (err) {
      const e = err as { status?: number; message?: string };
      let hint: string | undefined;
      if (e.status === 401) {
        hint =
          "Your passkey isn't recognised, or the ACL revoked your admin role. " +
          "Ask another admin to issue a fresh `vtc admin invite --did <your-did>`.";
      } else if (e.status === 404) {
        hint = "No passkeys are registered yet — claim the install URL first.";
      } else if (
        err instanceof DOMException &&
        err.name === "NotAllowedError"
      ) {
        hint = "Passkey prompt cancelled or denied by the browser.";
      } else if (!reachedPrompt) {
        // No prompt was ever shown, so nothing about the operator's passkey,
        // authenticator, or browser can be at fault — the challenge the
        // daemon sent could not be used. Saying so rules out the whole half
        // of the problem space an operator would otherwise search first.
        hint =
          "This failed before the browser could ask for your passkey, so it " +
          "is not your passkey, your authenticator, or your browser — the " +
          "daemon's sign-in challenge could not be used. Hard-reload the page " +
          "(Cmd/Ctrl-Shift-R). If that doesn't help, this console and the " +
          "daemon serving it were built from different sources; the daemon " +
          "needs rebuilding from its own tree.";
      }
      setPhase({ kind: "error", message: e.message ?? String(err), hint });
    }
  };

  const handleWalletLogin = async () => {
    setWalletPhase({ kind: "running" });
    setCandidates(null);
    try {
      const result = await loginWithWallet();
      await finishWithBearer(result.accessToken);
    } catch (err) {
      const e = err as { message?: string };
      setWalletPhase({
        kind: "error",
        message: e.message ?? String(err),
        hint: "Make sure the VTA wallet extension is unlocked and you approved the request.",
      });
    }
  };

  const runProxyLogin = async (entry: ProxyVaultEntry) => {
    setWalletPhase({ kind: "running" });
    setCandidates(null);
    try {
      const result = await loginWithWalletProxy(entry);
      await finishWithBearer(result.accessToken);
    } catch (err) {
      const e = err as { message?: string };
      setWalletPhase({ kind: "error", message: e.message ?? String(err) });
    }
  };

  const handleProxyStart = async () => {
    setWalletPhase({ kind: "running" });
    setCandidates(null);
    try {
      const found = await listProxyCandidates();
      if (found.length === 0) {
        setWalletPhase({
          kind: "error",
          message: "No did-self-issued vault entry is pinned to this VTC.",
          hint: "Open the wallet, add an entry targeting this VTC's DID, then retry.",
        });
        return;
      }
      if (found.length === 1) {
        await runProxyLogin(found[0]!);
      } else {
        setWalletPhase({ kind: "idle" });
        setCandidates(found);
      }
    } catch (err) {
      const e = err as { message?: string };
      setWalletPhase({ kind: "error", message: e.message ?? String(err) });
    }
  };

  return (
    <section className="page login-page">
      <div className="login-card">
        <h2>VTC Admin</h2>
        <p className="lead">
          Sign in with your registered passkey or your VTA wallet.
        </p>

        <button
          type="button"
          className="primary"
          onClick={signIn}
          disabled={busy}
        >
          <Fingerprint size={16} aria-hidden="true" />
          {phase.kind === "running"
            ? "Waiting for passkey…"
            : "Sign in with passkey"}
        </button>

        {walletAvailable ? (
          <button
            type="button"
            className="secondary"
            onClick={handleWalletLogin}
            disabled={busy}
          >
            <Wallet size={16} aria-hidden="true" />
            {walletPhase.kind === "running"
              ? "Waiting for wallet…"
              : "Sign in with VTA wallet"}
          </button>
        ) : (
          <p className="lead">
            Install the VTA wallet browser extension to sign in with your
            DID — no passkey required.
          </p>
        )}

        {proxyAvailable && (
          <button
            type="button"
            className="secondary"
            onClick={handleProxyStart}
            disabled={busy}
          >
            Sign in via VTA-proxied SIOP
          </button>
        )}

        {candidates && (
          <section className="card">
            <h3>Pick a proxy identity</h3>
            <p className="lead">
              Multiple vault entries are pinned to this VTC. Choose which one
              to sign in as.
            </p>
            {candidates.map((c) => (
              <button
                key={c.id}
                type="button"
                className="secondary"
                onClick={() => runProxyLogin(c)}
                disabled={busy}
              >
                {c.label} — <code>{c.principalDid}</code>
              </button>
            ))}
          </section>
        )}

        {(phase.kind === "error" || walletPhase.kind === "error") && (
          <section className="card error">
            <h3>Sign-in failed</h3>
            <p>
              {phase.kind === "error"
                ? phase.message
                : walletPhase.kind === "error"
                  ? walletPhase.message
                  : null}
            </p>
            {phase.kind === "error" && phase.hint && (
              <p className="lead">{phase.hint}</p>
            )}
            {walletPhase.kind === "error" && walletPhase.hint && (
              <p className="lead">{walletPhase.hint}</p>
            )}
          </section>
        )}

        <footer>
          <p>
            No passkey yet? Open the install URL the daemon operator shared, or
            ask them to mint a fresh one via <code>vtc admin invite</code>.
          </p>
        </footer>
      </div>
    </section>
  );
}
