// "Sign in with your wallet": the trigger-link sign-in (contract C1, C2, C9;
// base design §13). The first option on the sign-in page.
//
// States: idle → waiting (the code) → claimed (the number) → confirm
// ("Continue as …?") → signed in; or declined, cancelled, expired.

import { useCallback, useEffect, useRef, useState } from "react";
import QRCode from "qrcode";
import { QrCode, Smartphone } from "lucide-react";

import { postMember } from "./api";
import {
  cancelRequest,
  fetchSignInConfig,
  forgetSessionKey,
  generateSessionKey,
  OobError,
  openRequest,
  redeemOnce,
  triggerLink,
  type RedeemResult,
  type SignInConfig,
} from "./oob";

type Phase =
  | { kind: "idle" }
  | { kind: "starting" }
  | { kind: "waiting"; link: string; requestId: string; claimDeadline: number }
  | { kind: "claimed"; requestId: string; matchNumber: string }
  | { kind: "confirm"; result: RedeemResult }
  | { kind: "ended"; reason: "declined" | "cancelled" | "expired" }
  | { kind: "error"; message: string };

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

export function WalletSignIn({
  onSignedIn,
  communityName,
}: {
  onSignedIn: () => Promise<void> | void;
  communityName?: string | null;
}) {
  const [phase, setPhase] = useState<Phase>({ kind: "idle" });
  // The code is hidden when the tab is hidden, and stays hidden until the
  // member asks for it again. The request is not cancelled and the poll
  // keeps running (contract C9) — on a phone, tapping the code hides the tab.
  const [codeHidden, setCodeHidden] = useState(false);
  const cfgRef = useRef<SignInConfig | null>(null);
  const abortRef = useRef<AbortController | null>(null);
  const runRef = useRef(0);

  const stopPolling = useCallback(() => {
    runRef.current += 1;
    abortRef.current?.abort();
    abortRef.current = null;
  }, []);

  useEffect(() => stopPolling, [stopPolling]);

  useEffect(() => {
    const onVisibility = () => {
      if (document.visibilityState === "hidden") setCodeHidden(true);
    };
    document.addEventListener("visibilitychange", onVisibility);
    return () => document.removeEventListener("visibilitychange", onVisibility);
  }, []);

  // Hide an unclaimed code once its claim window closes.
  useEffect(() => {
    if (phase.kind !== "waiting") return;
    const ms = phase.claimDeadline * 1000 - Date.now();
    const t = window.setTimeout(() => {
      stopPolling();
      forgetSessionKey();
      setPhase({ kind: "ended", reason: "expired" });
    }, Math.max(0, ms));
    return () => window.clearTimeout(t);
  }, [phase, stopPolling]);

  const poll = useCallback(
    async (requestId: string, run: number) => {
      const cfg = cfgRef.current!;
      while (runRef.current === run) {
        const ctl = new AbortController();
        abortRef.current = ctl;
        try {
          const result = await redeemOnce(cfg, requestId, ctl.signal);
          if (runRef.current !== run) return;
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
                setPhase({ kind: "claimed", requestId, matchNumber: n });
              }
              continue;
            }
            case "rateLimited":
              await new Promise((r) => setTimeout(r, 1000));
              continue;
            case "declined":
              forgetSessionKey();
              setPhase({
                kind: "ended",
                reason: e.details.state === "cancelled" ? "cancelled" : "declined",
              });
              return;
            case "requestExpired":
            case "requestNotFound":
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
    [],
  );

  const showCode = async () => {
    stopPolling();
    const run = runRef.current;
    setCodeHidden(false);
    setPhase({ kind: "starting" });
    try {
      cfgRef.current ??= await fetchSignInConfig();
      await generateSessionKey();
      const { requestId, claimDeadline } = await openRequest(cfgRef.current);
      if (runRef.current !== run) return;
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

  const cancel = async (requestId: string) => {
    stopPolling();
    if (cfgRef.current) await cancelRequest(cfgRef.current, requestId);
    forgetSessionKey();
    setPhase({ kind: "ended", reason: "cancelled" });
  };

  const notMe = async () => {
    try {
      await postMember("/v1/member/sign-out");
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

      {(phase.kind === "idle" || phase.kind === "starting") && (
        <>
          <button
            type="button"
            className="btn btn-primary btn-lg"
            onClick={showCode}
            disabled={phase.kind === "starting"}
          >
            <QrCode size={18} aria-hidden="true" />
            {phase.kind === "starting" ? "Getting a code…" : "Show sign-in code"}
          </button>
          <p className="option-note">
            Scan it with your wallet app (Keyring is the first), or click it if your wallet
            is on this device. Your keys stay with your wallet.
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
                label={`Sign-in code for ${communityName || "this community"}. Scan it with your wallet, or click it to open your wallet.`}
              />
            </a>
            <p className="option-note">Waiting for your wallet…</p>
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
            <strong className="match-number">{phase.matchNumber}</strong>
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
            <button type="button" className="btn btn-primary" onClick={() => onSignedIn()}>
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
          <p className="alert-title">
            {phase.reason === "declined"
              ? "The sign-in was declined."
              : phase.reason === "cancelled"
                ? "The sign-in was cancelled."
                : "The code expired."}
          </p>
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
