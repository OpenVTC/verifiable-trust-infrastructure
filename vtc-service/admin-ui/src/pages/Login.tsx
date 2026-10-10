// Login page for the operator console. It wears the community's sign-in look
// (`@/signin`, shared with the member portal's `members/SignIn.tsx`) rather
// than the console's, because an operator arrives here from the community's
// site: the same top bar, centred card, option buttons and footer, with a
// "Back to <community>" link home. It stays a standalone page at `/admin/`.
// The rest of the console keeps its own look.
//
// The options, in order (contract C7):
//
// 1. **Sign in with your wallet** — the trigger-link key grant
//    (`auth/oob/*`), the shared `WalletSignIn` asking for the console's
//    session with `ext["org.openvtc.session"].audience = "admin"`. The VTC
//    issues the same cookie session the other console sign-ins do, and only
//    to an identity its ACL holds as an administrator; anyone else is told
//    "This identity isn't an administrator of this community."
// 2. **Passkey.**
// 3. **Using an older wallet?** — the two SIOPv2 wallet buttons below,
//    deprecated, unchanged, behind a disclosure.
//
// Passkey: POST `/v1/auth/passkey-login/start` → `navigator.credentials.get`
// → POST `/finish` → daemon sets the `vtc_admin_session` + `csrf` cookies.
//
// The community's DID is shown before sign-in, from the unauthenticated
// `/health`. Two reasons it belongs here rather than only on the dashboard:
// it tells an operator which community this console is for before they
// authenticate to it — several VTCs look identical at the login screen — and it
// is the string a prospective member needs in order to join, which until now
// could only be read from behind a login they did not have.
//
// VTA wallet (additive — passkey is unchanged): the browser wallet extension
// runs a SIOPv2 login against the VTC's header-exempt `/v1/wallet` surface
// and returns a bearer token; we exchange it for the same cookie session via
// `/v1/auth/admin-session`. A second option proxies the SIOP through the VTA
// for a `did-self-issued` vault entry. Both end by invalidating the `whoami`
// probe so the shell re-renders into the authenticated tree.
//
// The two wallet buttons can present DIFFERENT DIDs, and the VTC's ACL admits
// a DID, not a person — so each button says which identity it presents
// (Keyring Q13). `login()` lets the wallet choose: the persona it has bound to
// this site if there is one, otherwise it asks, and one answer it offers is
// the wallet's own holder key (a `did:key`). A wallet that predates per-site
// personas always presents the holder key. The proxied path never does: it
// always presents a VTA-held `did-self-issued` persona, which the VTA signs
// for. An admin whose ACL entry names their VTA identity therefore has one
// button that is certain to present it, and it is the second.

import { useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Fingerprint, Wallet } from "lucide-react";

import { fetchHealth, postJson, signOut, type HealthResponse } from "@/lib/api";
import { shortenDid } from "@/lib/format";
import { WalletSignIn } from "@/members/WalletSignIn";
import {
  CommunityTopbar,
  fetchCommunityProfile,
  HomeLink,
  OlderWalletOptions,
  SignInPage,
} from "@/signin/SignInLayout";
import "@/signin/signin.css";
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
  loginWithWalletProfile,
  loginWithWalletProxy,
  SignInAsError,
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

/** The refusal hint for a VTA-identity sign-in, which — unlike the wallet's own
 *  `login()` — knows the DID it presented before the VTC answers. A refusal is
 *  only actionable with that DID in hand: it is what the ACL has to name. */
function presentedHint(did: string): string {
  return (
    `This sign-in presented ${did}. If the VTC refused it, that DID needs an ` +
    `Admin entry in this VTC's ACL — ask another admin to run ` +
    `\`vtc admin invite --did ${did}\`.`
  );
}

export function Login() {
  // `/health` is header-exempt and unauthenticated, so this resolves on the
  // login screen. It carries only `{status, version, vtc_did}` — the
  // infrastructure detail moved to the admin-gated diagnostics route, so
  // reading it here discloses nothing that resolving the DID would not.
  const health = useQuery<HealthResponse>({
    queryKey: ["health"],
    queryFn: fetchHealth,
  });
  const vtcDid = health.data?.vtc_did;
  // The community's public name and logo, for the top bar and heading.
  const profile = useQuery({
    queryKey: ["community-profile"],
    queryFn: fetchCommunityProfile,
    staleTime: Infinity,
  });
  const communityName = profile.data?.name ?? null;

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
      // The wallet does not say which DID it presented when the sign-in is
      // refused, so this cannot name it — but it can name the likeliest
      // mismatch, which is the one Keyring hit: an ACL entry for a VTA
      // identity, and a wallet that signed in with its own key.
      setWalletPhase({
        kind: "error",
        message: e.message ?? String(err),
        hint:
          "Make sure the VTA wallet extension is unlocked and you approved the " +
          "request. If the VTC refused the sign-in, the identity the wallet " +
          "presented has no Admin entry in this VTC's ACL." +
          (proxyAvailable
            ? " If your entry names your VTA identity, use “Sign in as a VTA " +
              "identity” instead — it always presents that identity."
            : ""),
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
      setWalletPhase({
        kind: "error",
        message: e.message ?? String(err),
        ...(entry.principalDid
          ? { hint: presentedHint(entry.principalDid) }
          : {}),
      });
    }
  };

  // The wallet owns "which identity does this VTC know me as". It resolves the
  // entry for this origin, or — on a first sign-in — asks the operator to pick
  // a persona and remembers it. The flow this replaces asked the wallet to
  // enumerate every entry pinned to this VTC just to find one, and on a fresh
  // wallet returned nothing and dead-ended with "add an entry, then retry".
  const handleProxyStart = async () => {
    setWalletPhase({ kind: "running" });
    setCandidates(null);
    try {
      const result = await loginWithWalletProfile();
      await finishWithBearer(result.accessToken);
    } catch (err) {
      const e = err as { message?: string };
      setWalletPhase({
        kind: "error",
        message: e.message ?? String(err),
        ...(err instanceof SignInAsError
          ? { hint: presentedHint(err.presentedDid) }
          : {}),
      });
    }
  };

  // Escape hatch, not the default: pick from the entries pinned to this VTC.
  // Kept because an operator may hold more than one persona here — an Admin and
  // a member identity, say — and the wallet's own answer is the one bound to
  // this origin. It stays behind an explicit click because reaching it costs a
  // consent prompt that enumerates the vault to this page.
  const handleChooseIdentity = async () => {
    setWalletPhase({ kind: "running" });
    setCandidates(null);
    try {
      const found = await listProxyCandidates();
      if (found.length === 0) {
        setWalletPhase({
          kind: "error",
          message: "No did-self-issued vault entry is pinned to this VTC.",
          hint: "Use “Sign in as a VTA identity” instead — the wallet will ask which identity to use and remember it.",
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

  const errorPhase =
    phase.kind === "error" ? phase : walletPhase.kind === "error" ? walletPhase : null;

  return (
    <div className="vtc-signin vtc-signin-page">
      <a className="skip" href="#main">
        Skip to content
      </a>
      <CommunityTopbar
        communityName={communityName}
        logoUrl={profile.data?.logoUrl}
        tag="Operator console"
      />
      <SignInPage
        eyebrow="Operator console"
        title={
          communityName ? (
            <>Sign in to {communityName} — operator console</>
          ) : (
            <>Sign in to the operator console</>
          )
        }
        lead={
          <>
            For this community's administrators. Sign in with the wallet that
            holds your administrator identity, or with your passkey. There are
            no passwords.
          </>
        }
        after={
          <>
            {/* Absent while `/health` is in flight, and on a daemon that has
                not been set up yet — which is a real state, not an error, so
                it says so rather than rendering an empty box or a spinner. */}
            {vtcDid ? (
              <p className="option-note login-did">
                Community DID{" "}
                <code className="did-inline" title={vtcDid}>
                  {vtcDid}
                </code>
              </p>
            ) : (
              health.isSuccess && (
                <p className="option-note">
                  This VTC has no DID yet — it has not been set up.
                </p>
              )
            )}

            {errorPhase && (
              <div className="alert" role="alert">
                <p className="alert-title">Sign-in failed</p>
                <p>{errorPhase.message}</p>
                {errorPhase.hint && <p>{errorPhase.hint}</p>}
              </div>
            )}
          </>
        }
        foot={[
          <>
            Not an operator? Go to the <a href="/members/">member portal</a>.
          </>,
          <HomeLink communityName={communityName} />,
        ]}
      >
        <WalletSignIn
          audience="admin"
          communityName={communityName}
          onSignedIn={() => queryClient.invalidateQueries({ queryKey: ["whoami"] })}
          onNotMe={signOut}
        />

        <button
          type="button"
          className="btn btn-secondary btn-lg"
          onClick={signIn}
          disabled={busy}
        >
          <Fingerprint size={18} aria-hidden="true" />
          {phase.kind === "running"
            ? "Waiting for your passkey…"
            : "Sign in with a passkey"}
        </button>
        <p className="option-note">
          No passkey yet? Open the install URL the daemon operator shared, or
          ask them to mint a fresh one via <code>vtc admin invite</code>.
        </p>

        <OlderWalletOptions>
          <p className="option-note">
            The VTA Wallet browser extension's older sign-in (SIOPv2). It is
            deprecated and will be removed; use “Sign in with your wallet” when
            your wallet supports it.
          </p>
          {walletAvailable ? (
            <>
              <button
                type="button"
                className="btn btn-secondary"
                onClick={handleWalletLogin}
                disabled={busy}
              >
                <Wallet size={18} aria-hidden="true" />
                {walletPhase.kind === "running"
                  ? "Waiting for wallet…"
                  : "Sign in with this browser's wallet"}
              </button>
              <p className="option-note">
                The wallet presents the identity it uses for this site — its
                own key (a <code>did:key</code>) unless you have chosen a VTA
                identity here.
              </p>
            </>
          ) : (
            <p className="option-note">
              Install the VTA wallet browser extension to sign in with your
              DID — no passkey required.
            </p>
          )}

          {proxyAvailable && (
            <>
              <button
                type="button"
                className="btn btn-secondary"
                onClick={handleProxyStart}
                disabled={busy}
              >
                Sign in as a VTA identity
              </button>
              <p className="option-note">
                Your VTA signs as the identity bound to this community. Use
                this when your ACL entry names your VTA identity.
              </p>

              {/* Secondary, and worded as the exception it is. The button
                  above uses whichever identity the wallet has bound to this
                  site; this is for an operator holding more than one here,
                  and it costs a consent prompt that enumerates the vault to
                  this page. */}
              <button
                type="button"
                className="btn btn-link"
                onClick={handleChooseIdentity}
                disabled={busy}
              >
                Sign in as a different VTA identity…
              </button>
            </>
          )}

          {candidates && (
            <section className="identity-picker" aria-labelledby="proxy-picker-heading">
              <h2 id="proxy-picker-heading">Pick a proxy identity</h2>
              <p className="option-note">
                Multiple vault entries are pinned to this VTC. Choose which one
                to sign in as.
              </p>
              <div className="identity-choices">
                {candidates.map((c) => (
                  <button
                    key={c.id}
                    type="button"
                    className="identity-choice"
                    onClick={() => runProxyLogin(c)}
                    disabled={busy}
                    title={c.principalDid}
                  >
                    <span className="identity-choice-label">{c.label}</span>
                    {c.principalDid && (
                      <code className="identity-choice-did">
                        {shortenDid(c.principalDid)}
                      </code>
                    )}
                  </button>
                ))}
              </div>
            </section>
          )}
        </OlderWalletOptions>
      </SignInPage>
    </div>
  );
}
