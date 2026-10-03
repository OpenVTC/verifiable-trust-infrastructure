import { useEffect, useRef, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { NavLink, Route, Routes, useLocation } from "react-router-dom";
import { ChevronsLeft, ChevronsRight, Menu, RefreshCw, X } from "lucide-react";

import { getPlugins, subscribePlugins, type PluginManifest } from "@/plugin-api";
import { BreakGlassBanner } from "@/components/BreakGlassBanner";
import { LiveIndicator } from "@/components/LiveIndicator";
import { PluginHost } from "@/components/PluginHost";
import { ThemeSwitcher } from "@/components/ThemeSwitcher";
import {
  probeSession,
  signOut,
  watchSession,
  SIGNING_KEY_REFUSED_EVENT,
  WhoamiResponse,
} from "@/lib/api";
import { signingStatus, type SigningStatus } from "@/lib/console-keys-api";
import {
  ACTIONS_PLUGIN_ID,
  bannerDismissed,
  dismissBanner,
  useActionsAttention,
  waitingSentence,
} from "@/lib/action-badge";
import {
  CoolingOffBanner,
  OperatorWriteBanner,
  SingleAdminModeBanner,
} from "@/components/ActionsAlertBanners";
import {
  formatTally,
  JOIN_DECIDE_CAP,
  JOIN_REQUESTS_PLUGIN_ID,
  mayCount,
  usePendingJoinRequests,
} from "@/lib/community-counts";
import { pluginVisible } from "@/lib/viewer";
import { useLiveEvents } from "@/lib/use-live-events";
import { shortenDid } from "@/lib/format";
import { reloadThirdPartyPlugins } from "@/lib/plugin-loader";
import { useToast } from "@/lib/toast";
import { Install } from "@/pages/Install";
import { EnrolApproverPage } from "@/pages/EnrolApprover";
import { EnrolStepUpPage } from "@/pages/EnrolStepUp";
import { Login } from "@/pages/Login";
import {
  SetupSigning,
  SIGNING_STATUS_KEY,
  SigningCheckFailed,
} from "@/pages/SetupSigning";
import { StepUpPage } from "@/pages/StepUp";

/**
 * Hook that subscribes to plugin-registry changes and returns the
 * current snapshot. The registry is mutated by `registerPlugin`; this
 * hook forces a rerender whenever that fires so the shell's nav
 * picks up third-party plugins added after boot.
 */
function usePlugins() {
  const [, force] = useState(0);
  useEffect(() => subscribePlugins(() => force((n) => n + 1)), []);
  return getPlugins();
}

export default function App() {
  const allPlugins = usePlugins();
  const { pathname } = useLocation();
  const [navOpen, setNavOpen] = useState(false);
  // Desktop nav collapse — an icons-only rail to reclaim horizontal
  // space. Persisted so the operator's choice survives reloads.
  const [navCollapsed, setNavCollapsed] = useState(() => {
    try {
      return localStorage.getItem("vtc-admin-nav-collapsed") === "1";
    } catch {
      return false;
    }
  });
  useEffect(() => {
    try {
      localStorage.setItem("vtc-admin-nav-collapsed", navCollapsed ? "1" : "0");
    } catch {
      // Private-mode / blocked storage: collapse just won't persist.
    }
  }, [navCollapsed]);
  const qc = useQueryClient();
  const toast = useToast();
  // De-dupe back-to-back expiry events: one expired session can fire
  // 401s on every in-flight query in parallel. The ref clears once
  // the whoami probe has flipped to null so a fresh sign-in can be
  // detected again on its next expiry.
  const expiryNotifiedRef = useRef(false);

  // Auto-close the mobile nav on route change — operators expect the
  // sheet to dismiss after they pick a destination.
  useEffect(() => {
    setNavOpen(false);
  }, [pathname]);

  // Global session-expiry handler. `lib/api` dispatches
  // `vtc-session-expired` whenever any authenticated request returns
  // 401/403; when there's actually a cached whoami payload (i.e. the
  // operator *was* signed in), we invalidate it so App re-renders
  // into <Login> and show a friendly toast. The check on
  // `getQueryData(["whoami"])` filters out 401s emitted during the
  // login ceremony itself (no session present yet).
  useEffect(() => {
    const onExpired = () => {
      const current = qc.getQueryData(["whoami"]);
      if (!current) return;
      if (expiryNotifiedRef.current) return;
      expiryNotifiedRef.current = true;
      // Re-probe before declaring the session dead. Renewal rotates the
      // refresh token and the daemon claims the old one atomically, so
      // two tabs renewing at once means one of them is refused — even
      // though the session is perfectly alive, because the *other* tab
      // just renewed it and both share the cookie jar. Without this
      // check the losing tab would bounce a working session to Login.
      void probeSession().then((session) => {
        if (session) {
          // Someone else renewed it. Re-arm and carry on.
          expiryNotifiedRef.current = false;
          qc.setQueryData(["whoami"], session);
          return;
        }
        toast.push("info", "Your session expired. Sign in again to continue.");
        qc.setQueryData(["whoami"], null);
        void qc.invalidateQueries({ queryKey: ["whoami"] });
      });
    };
    window.addEventListener("vtc-session-expired", onExpired);
    return () => {
      window.removeEventListener("vtc-session-expired", onExpired);
    };
  }, [qc, toast]);

  // Probe the session cookie via `/v1/auth/whoami`. Returning the
  // claim payload (not just a bool) lets the navbar show "Signed
  // in as …" without a second round trip. 401/403 → show Login.
  //
  // Rules-of-Hooks discipline: every `use*` hook in this function
  // body lives *above* every conditional early return. A previous
  // version short-circuited `/install` before reaching this
  // `useQuery`, which flipped the hook count between routes and
  // would trip React's mount-time hook-order check on the first
  // navigation away from `/install`. Conditional rendering moves
  // strictly after the hook block.
  const probe = useQuery({
    queryKey: ["whoami"],
    queryFn: probeSession,
    staleTime: 30_000,
    retry: false,
    // Skip the network call when we're on the install ceremony —
    // there's no session yet and the 401 would just trigger the
    // expired-session toast we already filter out. The hook is
    // still invoked unconditionally; `enabled` is a runtime
    // property, not a hook-shape change.
    enabled: !pathname.startsWith("/install"),
  });

  // Whether this browser can sign for the signed-in administrator. Every
  // administrator verb is a signed document, so without an accepted key the
  // console can show nothing that works; the shell puts the operator through
  // setup first (`pages/SetupSigning.tsx`). Asked once per identity, and again
  // only when something says the answer changed — enrolment, revocation, or a
  // signed document the VTC refused outright.
  const subject = probe.data?.session.subject ?? null;
  const needsSigning = !!probe.data && probe.data.roles.includes("admin");
  const signing = useQuery<SigningStatus>({
    queryKey: [SIGNING_STATUS_KEY, subject],
    queryFn: () => signingStatus(subject!),
    enabled: needsSigning && !pathname.startsWith("/install"),
    staleTime: Infinity,
    retry: false,
  });
  useEffect(() => {
    const onRefused = () => {
      // Only a key believed good is worth re-checking; anything else is
      // already on the setup page, and re-checking it would loop.
      const current = qc.getQueryData<SigningStatus>([SIGNING_STATUS_KEY, subject]);
      if (current?.state === "ready") {
        void qc.invalidateQueries({ queryKey: [SIGNING_STATUS_KEY] });
      }
    };
    window.addEventListener(SIGNING_KEY_REFUSED_EVENT, onRefused);
    return () => window.removeEventListener(SIGNING_KEY_REFUSED_EVENT, onRefused);
  }, [qc, subject]);

  // How many administrator actions wait for this admin (lib/action-badge.ts):
  // the Actions nav badge, the banner below and the tab title. Only once the
  // browser can sign — the count is a signed read.
  // The same read carries the operator writes awaiting this admin's
  // acknowledgement and the cooling-offs against them — the Critical banners.
  const attention = useActionsAttention(
    needsSigning && signing.data?.state === "ready" && !pathname.startsWith("/install"),
  );
  const waiting = attention.waiting;
  // Join requests awaiting a decision (lib/community-counts.ts): the Join
  // requests nav badge, refreshed the same way, and only for a viewer who may
  // decide them — the entry it sits on is gated on the same capability.
  const pendingJoins = usePendingJoinRequests(
    needsSigning &&
      signing.data?.state === "ready" &&
      !pathname.startsWith("/install") &&
      mayCount(probe.data?.capabilities, JOIN_DECIDE_CAP),
  );
  // The live channel (lib/use-live-events.ts): one subscription for the
  // session, whose hints re-read the badge, banner, tile and page queries
  // above and below; the polls stay as the fallback.
  useLiveEvents(
    needsSigning && signing.data?.state === "ready" && !pathname.startsWith("/install"),
  );
  const [bannerHidden, setBannerHidden] = useState(bannerDismissed);

  // Re-arm the session-expiry guard whenever a fresh session lands.
  // Without this, a second expiry inside the same browser tab would
  // be silently ignored.
  useEffect(() => {
    if (probe.data) {
      expiryNotifiedRef.current = false;
    }
  }, [probe.data]);

  // Keep the session's deadline in view while signed in: renew ahead of it,
  // and once it passes with renewal refused, raise the expiry event above so
  // the shell flips to Login on its own. Without this an idle dashboard kept
  // looking signed in after its cookie lapsed, and the operator learned of it
  // from the next click — "Sign-out failed", in the report that prompted it.
  //
  // Keyed on the payload, not on "signed in": the watcher stops once it has
  // raised the event, and when the re-probe finds the session alive after
  // all (another tab renewed it) it lands a fresh payload, which re-arms it.
  useEffect(() => {
    if (!probe.data) return;
    return watchSession();
  }, [probe.data]);

  // Once the operator is signed in, watch for new plugins:
  // - On window focus (operator alt-tabs back after dropping a
  //   plugin into the daemon's plugin_dir).
  // - On a short interval as a fallback for browsers that don't
  //   reliably fire `focus`.
  // Already-loaded plugins are skipped by `reloadThirdPartyPlugins`,
  // so the cost on the steady-state path is one HEAD-like JSON fetch.
  useEffect(() => {
    if (!probe.data) return;
    let cancelled = false;
    const tick = () => {
      if (cancelled) return;
      void reloadThirdPartyPlugins();
    };
    window.addEventListener("focus", tick);
    return () => {
      cancelled = true;
      window.removeEventListener("focus", tick);
    };
  }, [probe.data]);

  // ── Conditional rendering only happens after every hook above. ──

  // `/install` is the unauthenticated install-claim ceremony. It
  // renders standalone (no nav, no plugins) because the operator
  // who hits it doesn't have a session yet.
  if (pathname.startsWith("/install")) {
    return <Install />;
  }

  // Redeeming a step-up passkey invite needs no session: the invitee may be
  // a member who is no console user at all.
  if (pathname.startsWith("/enrol-step-up")) {
    return <EnrolStepUpPage />;
  }
  // Nor does redeeming a step-up approver invite: the invitee may be a wallet
  // administrator with no step-up factor here at all.
  if (pathname.startsWith("/enrol-approver")) {
    return <EnrolApproverPage />;
  }
  if (probe.isPending) {
    return <SignInLoading />;
  }
  if (!probe.data) {
    // Nor does answering a bound step-up with a step-up passkey.
    if (pathname.startsWith("/step-up")) {
      return (
        <main className="content">
          <StepUpPage />
        </main>
      );
    }
    return <Login />;
  }

  // An administrator's browser needs an accepted signing key before the
  // console is any use. `/step-up` stays reachable: answering a passkey
  // step-up handed over from `cnm` signs nothing.
  if (needsSigning && !pathname.startsWith("/step-up")) {
    if (signing.isPending) {
      return <SignInLoading message="Checking this browser's signing key…" />;
    }
    if (signing.isError) {
      return (
        <SigningCheckFailed error={signing.error} onRetry={() => void signing.refetch()} />
      );
    }
    if (signing.data.state !== "ready") {
      return <SetupSigning whoami={probe.data} status={signing.data} />;
    }
  }
  const renewSoon = signing.data?.state === "ready" && signing.data.renewSoon;

  // Navigation follows the viewer's capabilities, read live behind `whoami`
  // (`vtc-admin-roles.md` §4) — not the session's role hint, which every
  // administrative role shares. The VTC still refuses what the entry does not
  // hold; hiding it keeps the UX coherent.
  const plugins = allPlugins.filter((p) => pluginVisible(probe.data, p));

  return (
    <div
      className={`layout${navOpen ? " nav-open" : ""}${
        navCollapsed ? " nav-collapsed" : ""
      }`}
    >
      <button
        type="button"
        className="nav-toggle"
        aria-label={navOpen ? "Close navigation" : "Open navigation"}
        aria-expanded={navOpen}
        aria-controls="admin-nav"
        onClick={() => setNavOpen((v) => !v)}
      >
        <span className="button-icon" aria-hidden="true">
          {navOpen ? <X /> : <Menu />}
        </span>
        Menu
      </button>
      <aside
        className={`nav${navCollapsed ? " collapsed" : ""}`}
        id="admin-nav"
      >
        <header>
          <div className="nav-brand">
            <h1>VTC Admin</h1>
            <button
              type="button"
              className="nav-collapse-btn"
              aria-label={
                navCollapsed ? "Expand navigation" : "Collapse navigation"
              }
              aria-expanded={!navCollapsed}
              title={navCollapsed ? "Expand" : "Collapse"}
              onClick={() => setNavCollapsed((v) => !v)}
            >
              <span className="button-icon" aria-hidden="true">
                {navCollapsed ? <ChevronsRight /> : <ChevronsLeft />}
              </span>
            </button>
          </div>
          <SessionBadge whoami={probe.data} />
          {needsSigning && <LiveIndicator />}
          <ThemeSwitcher />
        </header>
        <ul>
          {plugins.map((p) => (
            <li key={p.id}>
              <NavLink to={p.path} title={p.label}>
                <span className="nav-icon" aria-hidden="true">
                  <PluginIcon plugin={p} />
                </span>
                <span className="nav-label">{p.label}</span>
                {p.id === ACTIONS_PLUGIN_ID && waiting > 0 && (
                  <span
                    className="nav-badge"
                    aria-label={`${waiting} waiting for you`}
                  >
                    {waiting}
                  </span>
                )}
                {p.id === JOIN_REQUESTS_PLUGIN_ID &&
                  pendingJoins &&
                  pendingJoins.count > 0 && (
                    <span
                      className="nav-badge"
                      aria-label={`${formatTally(pendingJoins)} pending`}
                    >
                      {formatTally(pendingJoins)}
                    </span>
                  )}
              </NavLink>
            </li>
          ))}
        </ul>
        <ReloadPluginsButton />
      </aside>
      <main className="content">
        {/* Permanent while in effect: single-administrator mode is reported to
            every administrator on every page (VTI-APV-022). */}
        <SingleAdminModeBanner on={attention.singleAdminMode} />
        {/* Not dismissible: it clears when every self-granted elevated right
            has been ratified or revoked (git-ns/right/break-glass). */}
        <BreakGlassBanner />
        {/* Not dismissible either: an operator's offline write clears when
            acknowledged (VTI-VTC-023), a cooling-off against you when it is
            cancelled or lands (VTI-APV-019). */}
        <OperatorWriteBanner actionIds={attention.operatorWritesUnacknowledged} />
        <CoolingOffBanner items={attention.coolingOffAgainstMe} />
        {renewSoon && !pathname.startsWith("/console-keys") && (
          <div className="signing-renew-banner" role="status">
            <strong>This browser's signing key expires soon.</strong>
            <span>
              Renew it now — one passkey confirmation — so the console keeps
              working.
            </span>
            <NavLink to="/console-keys">Renew</NavLink>
          </div>
        )}
        {waiting > 0 && !bannerHidden && !pathname.startsWith("/actions") && (
          <div className="actions-banner" role="status">
            <strong>{waitingSentence(waiting)}.</strong>
            <NavLink to="/actions">Review them</NavLink>
            <button
              type="button"
              className="link"
              aria-label="Dismiss for this session"
              onClick={() => {
                dismissBanner();
                setBannerHidden(true);
              }}
            >
              Dismiss
            </button>
          </div>
        )}
        <Routes>
          {plugins.map((p) => (
            <Route
              key={p.id}
              path={`${p.path}/*`}
              element={<PluginHost plugin={p} />}
            />
          ))}
          {/* Default route: first plugin (Dashboard). */}
          {plugins[0] && (
            <Route path="/" element={<PluginHost plugin={plugins[0]} />} />
          )}
          {/* A passkey step-up handed over from `cnm` (lib/bound-step-up.ts). */}
          <Route path="/step-up" element={<StepUpPage />} />
          {/* Fallback for unknown URLs under /admin/ */}
          <Route path="*" element={<NotFound />} />
        </Routes>
      </main>
    </div>
  );
}

/**
 * The nav's icon slot for one plugin.
 *
 * Exported for its own test: the `<img>` below is a security property, not a
 * styling choice, and a later refactor back to injected markup would look like
 * a simplification.
 */
export function PluginIcon({ plugin }: { plugin: PluginManifest }) {
  // Built-in plugins ship a lucide-react component; third-party
  // plugins fall back to the `icon` string (inline SVG or single
  // glyph). If neither is set, fall back to the label's first
  // letter so the nav row stays balanced.
  if (plugin.iconComponent) {
    const Icon = plugin.iconComponent;
    return <Icon aria-hidden="true" />;
  }
  if (plugin.icon) {
    // An SVG icon is rendered as an image, never injected as markup.
    //
    // This used to be `dangerouslySetInnerHTML`, which put the plugin's
    // string into the document as live DOM. `script-src 'self'`
    // (`vtc-service/src/routing/security_headers.rs`) stops a `<script>` in
    // it from executing — but an `onload=` / `onerror=` attribute is not
    // script-src's business, and `icon` reaches the shell from plugin
    // JavaScript that a third party may have written.
    //
    // Inside an `<img>` an SVG is a picture: the browser renders it in a
    // non-scripted context, so neither scripts nor event handlers in it ever
    // run, and `img-src 'self' data:` already admits the data URL. No
    // sanitiser, and so no dependency on one being configured correctly.
    if (/^<svg[\s>]/i.test(plugin.icon.trim())) {
      const src = `data:image/svg+xml;charset=utf-8,${encodeURIComponent(
        plugin.icon,
      )}`;
      return (
        <img className="plugin-icon-raw" src={src} alt="" aria-hidden="true" />
      );
    }
    // Anything else is text — a glyph or emoji as before, and markup that is
    // not an SVG as its own characters, because React escapes it.
    return <span aria-hidden="true">{plugin.icon}</span>;
  }
  return <span aria-hidden="true">{plugin.label.charAt(0).toUpperCase()}</span>;
}

function SessionBadge({ whoami }: { whoami: WhoamiResponse }) {
  const qc = useQueryClient();
  const toast = useToast();
  const signOutMut = useMutation({
    mutationFn: signOut,
    onError: (err) => toast.pushFromError(err, "Sign-out failed"),
    onSettled: () => {
      // Whether the server-side revoke succeeded or not, the
      // cookies are gone now — force the query cache to refetch
      // so the shell flips back to the Login screen.
      qc.invalidateQueries({ queryKey: ["whoami"] });
    },
  });

  return (
    <div className="session-badge">
      <div className="session-did" title={whoami.session.subject}>
        <span className="session-label">Signed in as</span>
        <code>{shortenDid(whoami.session.subject)}</code>
      </div>
      <button
        type="button"
        className="link"
        onClick={() => signOutMut.mutate()}
        disabled={signOutMut.isPending}
        aria-busy={signOutMut.isPending}
      >
        {signOutMut.isPending ? "Signing out…" : "Sign out"}
      </button>
    </div>
  );
}

function ReloadPluginsButton() {
  const toast = useToast();
  const [pending, setPending] = useState(false);
  return (
    <div className="nav-footer">
      <button
        type="button"
        className="link"
        disabled={pending}
        aria-busy={pending}
        title="Refetch /admin/plugins.json and import any new plugins"
        onClick={async () => {
          setPending(true);
          try {
            const added = await reloadThirdPartyPlugins();
            if (added.length === 0) {
              toast.push("info", "No new plugins.");
            } else {
              toast.push(
                "success",
                `Loaded ${added.length} new plugin${added.length === 1 ? "" : "s"}: ${added.join(", ")}`,
              );
            }
          } catch (err) {
            toast.pushFromError(err, "Plugin reload failed");
          } finally {
            setPending(false);
          }
        }}
      >
        <span className="button-icon" aria-hidden="true">
          <RefreshCw />
        </span>
        <span className="nav-footer-label">
          {pending ? "Reloading plugins…" : "Reload plugins"}
        </span>
      </button>
    </div>
  );
}

function SignInLoading({ message = "Checking session…" }: { message?: string }) {
  return (
    <section className="page login-page">
      <div className="login-card">
        <h2>VTC Admin</h2>
        <p className="lead">{message}</p>
      </div>
    </section>
  );
}

function NotFound() {
  return (
    <section className="page">
      <h2>Not found</h2>
      <p className="lead">
        The URL didn't match a registered plugin. The nav on the left
        shows what's available.
      </p>
    </section>
  );
}
