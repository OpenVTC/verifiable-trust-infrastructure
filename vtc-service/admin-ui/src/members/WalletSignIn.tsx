// "Sign in with your wallet": the trigger-link sign-in (contract C1, C2, C9;
// base design §13). The first option on the sign-in page — the member
// portal's, and the operator console's (`audience="admin"`), which asks the
// VTC for a console session through `ext["org.openvtc.session"]`.
//
// States: idle → waiting (the code) → claimed (the number) → confirm
// ("Continue as …?") → signed in; or declined, cancelled, expired. The
// confirm is skipped when this browser last continued as the same identity
// for the same audience: "Continue as …?" guards against someone else's
// identity being signed in here (T4), and a known identity is not that.
//
// The code needs no click: it is made as soon as the page knows wallet
// sign-in can work and the tab is in view. Reading the config is retried a
// few times; when it still fails, the page says why, with "Try again". Nobody can use a code without
// being a member and seeing the number, and the first scanner locks it, so
// showing it unasked costs one request and gives nothing away. An unclaimed
// code is renewed when its claim window closes — while the tab is in view
// only, so a page left in a background tab makes no requests; one that
// lapsed there is renewed when the tab comes back (`lapsed`). A claimed code
// that expires still ends as expired: someone scanned it.
//
// The claimed number carries `data-oob-request-id` and
// `data-oob-match-number` (contract C11). The browser plugin's content
// script reads them, only for a code the person clicked on this page, and
// fills the number in for them. The page posts nothing and learns nothing
// back; a phone wallet still asks the person to type the number.
//
// A rate-limit refusal (`429`, or the VTC's own `rateLimited`) is waited out
// for its `Retry-After` and retried — a poll always, the code request a few
// times — and only one that persists is shown, in words, never as "429".

import { useCallback, useEffect, useRef, useState } from "react";
import QRCode from "qrcode";
import { QrCode, Smartphone } from "lucide-react";

import { postMember } from "./api";
import {
  cancelRequest,
  fetchSignInConfig,
  forgetSessionKey,
  generateSessionKey,
  keepSessionKeyForPortal,
  missingDidServices,
  NOT_AN_ADMIN,
  retryAfterMs,
  OobError,
  openRequest,
  redeemOnce,
  triggerLink,
  type RedeemResult,
  type SessionAudience,
  type SignInConfig,
} from "./oob";

type Phase =
  | { kind: "idle" }
  | { kind: "starting" }
  | { kind: "waiting"; link: string; requestId: string; claimDeadline: number }
  /** An unclaimed code's window closed while the tab was hidden; a new one
   *  is made when the tab is in view again. */
  | { kind: "lapsed" }
  | { kind: "claimed"; requestId: string; matchNumber: string }
  | { kind: "confirm"; result: RedeemResult }
  | { kind: "ended"; reason: "declined" | "cancelled" | "expired" | "notAnAdmin" }
  | { kind: "error"; message: string };

/** Tries for the config on page load, and for a code request a rate limit
 *  refused, before the page says what went wrong. */
const CONFIG_ATTEMPTS = 3;
const REQUEST_ATTEMPTS = 3;

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

/** The wait before try `attempt + 1`: a rate limit's own `Retry-After`, else
 *  a short backoff. */
function backoffMs(e: unknown, attempt: number): number {
  return e instanceof OobError && e.code === "rateLimited"
    ? retryAfterMs(e)
    : 500 * 2 ** attempt;
}

/** The code as SVG rects: level M, no logo, a 4-module quiet zone, at least
 *  4 CSS px a module, dark on light in every theme (contract C1). */
export function QrSvg({ text, label }: { text: string; label: string }) {
  const qr = QRCode.create(text, { errorCorrectionLevel: "M" });
  const n = qr.modules.size;
  const quiet = 4;
  const size = n + quiet * 2;
  const cells: string[] = [];
  for (let r = 0; r < n; r++) {
    for (let c = 0; c < n; c++) {
      if (qr.modules.get(r, c)) cells.push(`M${c + quiet} ${r + quiet}h1v1h-1z`);
    }
  }
  const px = Math.max(4, Math.floor(240 / size)) * size;
  return (
    <svg
      role="img"
      aria-label={label}
      viewBox={`0 0 ${size} ${size}`}
      width={px}
      height={px}
      shapeRendering="crispEdges"
      className="qr"
    >
      <rect width={size} height={size} fill="#ffffff" />
      <path d={cells.join("")} fill="#000000" />
    </svg>
  );
}

/** The identity this browser last chose "Continue" for, per audience. A
 *  convenience only: when it is missing (cleared, private window, storage
 *  blocked) the page asks again. */
const knownKey = (audience: SessionAudience) => `vtc-wallet-signin-known-${audience}`;

function knownSubject(audience: SessionAudience): string | null {
  try {
    return window.localStorage.getItem(knownKey(audience));
  } catch {
    return null;
  }
}

function rememberSubject(audience: SessionAudience, subject: string): void {
  try {
    window.localStorage.setItem(knownKey(audience), subject);
  } catch {
    /* the next sign-in asks again */
  }
}

/** How long a code must have lived to be renewed when it ends unclaimed. */
const MIN_CODE_LIFE_MS = 10_000;

/** What an ended sign-in says. */
function endedMessage(reason: Extract<Phase, { kind: "ended" }>["reason"]): string {
  switch (reason) {
    case "notAnAdmin":
      return "This identity isn't an administrator of this community.";
    case "declined":
      return "The sign-in was declined.";
    case "cancelled":
      return "The sign-in was cancelled.";
    case "expired":
      return "The code expired.";
  }
}

export function WalletSignIn({
  onSignedIn,
  communityName,
  audience = "member",
  onNotMe,
}: {
  onSignedIn: () => Promise<void> | void;
  communityName?: string | null;
  /** Which session to ask for: the member portal's (default) or the
   *  operator console's. */
  audience?: SessionAudience;
  /** End the session just issued, for "Not me". Defaults to the member
   *  portal's sign-out. */
  onNotMe?: () => Promise<unknown>;
}) {
  const [phase, setPhase] = useState<Phase>({ kind: "idle" });
  // The code is hidden when the tab is hidden, and stays hidden until the
  // member asks for it again. The request is not cancelled and the poll
  // keeps running (contract C9) — on a phone, tapping the code hides the tab.
  const [codeHidden, setCodeHidden] = useState(false);
  const cfgRef = useRef<SignInConfig | null>(null);
  // Services the community's DID document lacks, so no wallet would accept
  // its codes: the option is replaced by a note and the page's other options
  // carry on. `null` until known, and whenever wallet sign-in can be offered.
  const [missing, setMissing] = useState<string[] | null>(null);
  // Whether the config is known and wallet sign-in can be offered: the code
  // is made unasked only then.
  const [ready, setReady] = useState(false);
  // Why the config could not be read, after its retries; `null` while it
  // could be, or is still being tried.
  const [configFailed, setConfigFailed] = useState<string | null>(null);
  const [visible, setVisible] = useState(() => document.visibilityState !== "hidden");
  const abortRef = useRef<AbortController | null>(null);
  const runRef = useRef(0);

  const stopPolling = useCallback(() => {
    runRef.current += 1;
    abortRef.current?.abort();
    abortRef.current = null;
  }, []);

  useEffect(() => stopPolling, [stopPolling]);

  // Learn up front whether wallet sign-in can work, trying a few times — a
  // rate limit or a blip on load is not worth showing. One that persists is
  // shown with its reason and "Try again".
  useEffect(() => {
    let live = true;
    void (async () => {
      for (let attempt = 0; ; attempt++) {
        try {
          const cfg = await fetchSignInConfig();
          if (!live) return;
          cfgRef.current = cfg;
          const lacking = missingDidServices(cfg);
          setMissing(lacking);
          setReady(lacking === null);
          return;
        } catch (e) {
          if (!live) return;
          if (attempt + 1 >= CONFIG_ATTEMPTS) {
            setConfigFailed(e instanceof Error ? e.message : String(e));
            return;
          }
          await sleep(backoffMs(e, attempt));
          if (!live) return;
        }
      }
    })();
    return () => {
      live = false;
    };
  }, []);

  useEffect(() => {
    const onVisibility = () => {
      const shown = document.visibilityState !== "hidden";
      setVisible(shown);
      if (!shown) setCodeHidden(true);
    };
    document.addEventListener("visibilitychange", onVisibility);
    return () => document.removeEventListener("visibilitychange", onVisibility);
  }, []);

  // An unclaimed code whose claim window closed: a new one while the tab is
  // in view, otherwise `lapsed` until it is. Read through a ref so the poll
  // loop calls the current `showCode`.
  // A code that ends within `MIN_CODE_LIFE_MS` of being made (a clock off by
  // minutes, a VTC that drops requests) ends as expired instead, so a page
  // never makes code after code in a loop.
  const renewRef = useRef<() => void>(() => {});
  const openedAtRef = useRef(0);
  renewRef.current = () => {
    stopPolling();
    forgetSessionKey();
    if (Date.now() - openedAtRef.current < MIN_CODE_LIFE_MS) {
      setPhase({ kind: "ended", reason: "expired" });
    } else if (document.visibilityState === "hidden") setPhase({ kind: "lapsed" });
    else void showCode();
  };

  useEffect(() => {
    if (phase.kind !== "waiting") return;
    const ms = phase.claimDeadline * 1000 - Date.now();
    const t = window.setTimeout(() => renewRef.current(), Math.max(0, ms));
    return () => window.clearTimeout(t);
  }, [phase]);

  // A member sign-in keeps its browser key for the directory pages, which
  // sign with it under the delegation the member approved.
  // Kept before anything else runs (the key is cached synchronously); its
  // write to storage finishes in the background and never holds sign-in up.
  const signedIn = useCallback(async () => {
    if (audience === "member") void keepSessionKeyForPortal();
    await onSignedIn();
  }, [audience, onSignedIn]);

  const poll = useCallback(
    async (requestId: string, run: number) => {
      const cfg = cfgRef.current!;
      let claimed = false;
      while (runRef.current === run) {
        const ctl = new AbortController();
        abortRef.current = ctl;
        try {
          const result = await redeemOnce(cfg, requestId, ctl.signal);
          if (runRef.current !== run) return;
          if (result.audience !== audience) {
            // Never carry on with a session this page did not ask for.
            forgetSessionKey();
            setPhase({
              kind: "error",
              message: "The community answered with a different kind of session; sign in again.",
            });
            return;
          }
          if (result.subject && result.subject === knownSubject(audience)) {
            void signedIn();
            return;
          }
          setPhase({ kind: "confirm", result });
          return;
        } catch (e) {
          if (runRef.current !== run) return;
          if (!(e instanceof OobError)) {
            // Network blip: back off and poll again on the same request.
            await new Promise((r) => setTimeout(r, 2000));
            continue;
          }
          switch (e.code) {
            case "pending": {
              const n = e.details.matchNumber;
              if (typeof n === "string") {
                claimed = true;
                setPhase({ kind: "claimed", requestId, matchNumber: n });
              }
              continue;
            }
            case "rateLimited":
              // Wait out the limit, then poll the same request again.
              await sleep(retryAfterMs(e));
              continue;
            case "declined":
              forgetSessionKey();
              setPhase({
                kind: "ended",
                reason:
                  e.details.reason === NOT_AN_ADMIN
                    ? "notAnAdmin"
                    : e.details.state === "cancelled"
                      ? "cancelled"
                      : "declined",
              });
              return;
            case "requestExpired":
            case "requestNotFound":
              if (!claimed) {
                // Nobody scanned it: a fresh code, not an error.
                renewRef.current();
                return;
              }
              forgetSessionKey();
              setPhase({ kind: "ended", reason: "expired" });
              return;
            default:
              forgetSessionKey();
              setPhase({ kind: "error", message: e.message });
              return;
          }
        }
      }
    },
    [audience, signedIn],
  );

  const showCode = async () => {
    stopPolling();
    const run = runRef.current;
    setCodeHidden(false);
    setPhase({ kind: "starting" });
    try {
      cfgRef.current ??= await fetchSignInConfig();
      await generateSessionKey();
      // Unmounted or superseded while the key was made: open no request.
      if (runRef.current !== run) return;
      let opened: Awaited<ReturnType<typeof openRequest>> | undefined;
      for (let attempt = 0; !opened; attempt++) {
        try {
          opened = await openRequest(cfgRef.current, audience);
        } catch (e) {
          const limited = e instanceof OobError && e.code === "rateLimited";
          if (!limited || attempt + 1 >= REQUEST_ATTEMPTS) throw e;
          await sleep(retryAfterMs(e));
          if (runRef.current !== run) return;
        }
      }
      const { requestId, claimDeadline } = opened;
      if (runRef.current !== run) return;
      openedAtRef.current = Date.now();
      setPhase({
        kind: "waiting",
        link: triggerLink(cfgRef.current, requestId, claimDeadline),
        requestId,
        claimDeadline,
      });
      void poll(requestId, run);
    } catch (e) {
      forgetSessionKey();
      setPhase({
        kind: "error",
        message:
          e instanceof Error && e.name === "NotSupportedError"
            ? "This browser can't make the key wallet sign-in needs. Update it, or use a passkey."
            : e instanceof Error
              ? e.message
              : String(e),
      });
    }
  };

  // Make the code unasked once wallet sign-in can work and the tab is in
  // view, and renew one that lapsed while the tab was hidden.
  const showCodeRef = useRef(showCode);
  showCodeRef.current = showCode;
  useEffect(() => {
    if (!ready || !visible) return;
    if (phase.kind === "idle" || phase.kind === "lapsed") void showCodeRef.current();
  }, [ready, visible, phase.kind]);

  const cancel = async (requestId: string) => {
    stopPolling();
    if (cfgRef.current) await cancelRequest(cfgRef.current, requestId);
    forgetSessionKey();
    setPhase({ kind: "ended", reason: "cancelled" });
  };

  const continueAs = (subject: string) => {
    rememberSubject(audience, subject);
    void signedIn();
  };

  const notMe = async () => {
    try {
      await (onNotMe ? onNotMe() : postMember("/v1/member/sign-out"));
    } finally {
      forgetSessionKey();
      setPhase({ kind: "idle" });
    }
  };

  return (
    <section className="wallet-signin" aria-labelledby="wallet-signin-heading">
      <h2 id="wallet-signin-heading" className="option-heading">
        <Smartphone size={18} aria-hidden="true" /> Sign in with your wallet
      </h2>

      {missing && phase.kind === "idle" && (
        <div className="alert" role="status">
          <p className="alert-title">Wallet sign-in isn't available here yet.</p>
          <p>
            This community's DID document doesn't list {missing.join(" or ")}, so wallets
            can't accept its sign-in codes. Use another option below; the operator's logs
            say how to fix it.
          </p>
        </div>
      )}

      {!missing &&
        (phase.kind === "idle" || phase.kind === "starting" || phase.kind === "lapsed") && (
        <>
          {configFailed && phase.kind === "idle" ? (
            <div className="alert" role="status">
              <p className="alert-title">{configFailed}</p>
              <button type="button" className="btn btn-secondary btn-sm" onClick={showCode}>
                Try again
              </button>
            </div>
          ) : (
            <p className="option-note" role="status">
              <QrCode size={18} aria-hidden="true" /> Getting a code…
            </p>
          )}
          <p className="option-note">
            Scan it with your wallet app (Keyring is the first), or click it if your wallet
            is on this device. Your keys stay with your wallet.
            {audience === "admin" &&
              " Approve as the identity that administers this community."}
          </p>
        </>
      )}

      {phase.kind === "waiting" &&
        (codeHidden ? (
          <button
            type="button"
            className="btn btn-secondary"
            onClick={() => setCodeHidden(false)}
          >
            Show the code again
          </button>
        ) : (
          <div className="qr-wrap">
            {/* C2: the code is also a link to the same text (VTI-LNK-086). */}
            <a href={phase.link} className="qr-link" rel="noreferrer">
              <QrSvg
                text={phase.link}
                label={`Sign-in code for ${communityName || "this community"}${
                  audience === "admin" ? " operator console" : ""
                }. Scan it with your wallet, or click it to open your wallet.`}
              />
            </a>
            <p className="option-note">
              Scan it with your wallet app, or click it if your wallet is on this device.
              {audience === "admin" &&
                " Approve as the identity that administers this community."}
            </p>
            <button
              type="button"
              className="btn btn-ghost btn-sm"
              onClick={() => cancel(phase.requestId)}
            >
              Cancel
            </button>
          </div>
        ))}

      {phase.kind === "claimed" && (
        <div className="claimed" role="status">
          <p className="lead">
            Approve on your phone. Your number is{" "}
            {/* C11: the browser plugin reads these, for a code clicked here. */}
            <strong
              className="match-number"
              data-oob-request-id={phase.requestId}
              data-oob-match-number={phase.matchNumber}
            >
              {phase.matchNumber}
            </strong>
          </p>
          <p className="option-note">
            If you didn't just scan this code, someone else did: cancel and get a new one.
          </p>
          <button
            type="button"
            className="btn btn-ghost btn-sm"
            onClick={() => cancel(phase.requestId)}
          >
            Cancel
          </button>
        </div>
      )}

      {phase.kind === "confirm" && (
        <div className="confirm" role="alertdialog" aria-labelledby="confirm-heading">
          <p id="confirm-heading" className="lead">
            Continue as{" "}
            <strong title={phase.result.subject}>
              {phase.result.displayName || phase.result.subject}
            </strong>
            ?
          </p>
          <div className="confirm-actions">
            <button
              type="button"
              className="btn btn-primary"
              onClick={() => continueAs(phase.result.subject)}
            >
              Continue
            </button>
            <button type="button" className="btn btn-secondary" onClick={notMe}>
              Not me
            </button>
          </div>
        </div>
      )}

      {phase.kind === "ended" && (
        <div className="alert" role="alert">
          <p className="alert-title">{endedMessage(phase.reason)}</p>
          {phase.reason === "notAnAdmin" && (
            <p>
              The console admits identities this community's ACL holds as administrators. If
              you hold more than one identity, approve with the one that administers it.
            </p>
          )}
          <button type="button" className="btn btn-secondary btn-sm" onClick={showCode}>
            Get a new code
          </button>
        </div>
      )}

      {phase.kind === "error" && (
        <div className="alert" role="alert">
          <p className="alert-title">{phase.message}</p>
          <button type="button" className="btn btn-secondary btn-sm" onClick={showCode}>
            Try again
          </button>
        </div>
      )}
    </section>
  );
}
