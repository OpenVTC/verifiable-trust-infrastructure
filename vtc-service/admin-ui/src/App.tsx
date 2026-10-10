import { useEffect, useRef, useState, type ReactNode } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { NavLink, Route, Routes, useLocation } from "react-router-dom";
import { ChevronsLeft, ChevronsRight, Menu, RefreshCw, X } from "lucide-react";

import { getPlugins, subscribePlugins } from "@/plugin-api";
import { AccountMenu } from "@/components/AccountMenu";
import { AttentionStrip, type AttentionItem } from "@/components/AttentionStrip";
import { BreakGlassNotice, useBreakGlassState } from "@/components/BreakGlassBanner";
import { LiveIndicator } from "@/components/LiveIndicator";
import { PluginHost } from "@/components/PluginHost";
import { PluginIcon } from "@/components/PluginIcon";
import { probeSession, watchSession, SIGNING_KEY_REFUSED_EVENT } from "@/lib/api";
import { signingStatus, type SigningStatus } from "@/lib/console-keys-api";
import {
  ACTIONS_PLUGIN_ID,
  bannerDismissed,
  dismissBanner,
  useActionsAttention,
  waitingSentence,
} from "@/lib/action-badge";
import {
  CoolingOffNotice,
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
import { useCommunityIdentity } from "@/lib/community-identity";
import { arrangeNav } from "@/lib/nav-groups";
import { useLiveEvents } from "@/lib/use-live-events";
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
  const canSign = needsSigning && signing.data?.state === "ready";

  // Navigation follows the viewer's capabilities, read live behind `whoami`
  // (`vtc-admin-roles.md` §4) — not the session's role hint, which every
  // administrative role shares. The VTC still refuses what the entry does not
  // hold; hiding it keeps the UX coherent.
  const plugins = allPlugins.filter((p) => pluginVisible(probe.data, p));
  // Grouped for the sidebar, and the operator's own entries for the account
  // menu (`lib/nav-groups.ts`). A group the viewer can see nothing in is left
  // out; plugins naming no group are listed under "More".
  const nav = arrangeNav(plugins);

  return (
    <div
      className={`layout${navOpen ? " nav-open" : ""}${
        navCollapsed ? " nav-collapsed" : ""
      }`}
    >
      <TopBar
        canSign={canSign}
        toggle={
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
            <span className="nav-toggle-label">Menu</span>
          </button>
        }
        end={
          <>
            {needsSigning && <LiveIndicator />}
            <AccountMenu
              whoami={probe.data}
              plugins={nav.account}
              renewSoon={!!renewSoon}
            />
          </>
        }
      />
      <aside
        className={`nav${navCollapsed ? " collapsed" : ""}`}
        id="admin-nav"
        aria-label="Console navigation"
      >
        {nav.sections.map((section) => (
          <div className="nav-group" key={section.id} data-nav-group={section.id}>
            <div className="nav-group-label" id={`nav-group-${section.id}`}>
              {section.label}
            </div>
            <ul aria-labelledby={`nav-group-${section.id}`}>
              {section.plugins.map((p) => (
                <li key={p.id}>
                  <NavLink to={p.path} title={p.label} end={p.path === "/"}>
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
          </div>
        ))}
        <div className="nav-footer">
          <ReloadPluginsButton />
          <button
            type="button"
            className="nav-collapse-btn"
            aria-label={navCollapsed ? "Expand navigation" : "Collapse navigation"}
            aria-expanded={!navCollapsed}
            title={navCollapsed ? "Expand" : "Collapse"}
            onClick={() => setNavCollapsed((v) => !v)}
          >
            <span className="button-icon" aria-hidden="true">
              {navCollapsed ? <ChevronsRight /> : <ChevronsLeft />}
            </span>
          </button>
        </div>
      </aside>
      <main className="content">
        <ConsoleAttention
          attention={attention}
          renewSoon={!!renewSoon}
          bannerHidden={bannerHidden}
          onDismissBanner={() => {
            dismissBanner();
            setBannerHidden(true);
          }}
        />
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

// Re-exported: `App.test.tsx` and any out-of-tree code that imported it from
// here keep working now that it lives in its own file.
export { PluginIcon };

/**
 * The top bar: the mobile nav toggle, the community's mark and name
 * (`lib/community-identity.ts`), the "Operator console" pill, and at the end
 * the live indicator and the account menu.
 */
function TopBar({
  canSign,
  toggle,
  end,
}: {
  canSign: boolean;
  toggle: ReactNode;
  end: ReactNode;
}) {
  const identity = useCommunityIdentity(canSign);
  const [logoFailed, setLogoFailed] = useState(false);
  const logo = identity.logoUrl && !logoFailed ? identity.logoUrl : null;
  return (
    <header className="topbar">
      {toggle}
      <NavLink to="/" end className="topbar-brand" aria-label={`${identity.name}: dashboard`}>
        {logo ? (
          <img
            className="community-mark community-logo"
            src={logo}
            alt=""
            onError={() => setLogoFailed(true)}
          />
        ) : (
          <span className="community-mark" aria-hidden="true" />
        )}
        <span className="community-name">{identity.name}</span>
      </NavLink>
      <span className="console-pill">Operator console</span>
      <span className="topbar-spacer" />
      <div className="topbar-end">{end}</div>
    </header>
  );
}

/**
 * Everything the operator must know, in one strip above the page
 * (`components/AttentionStrip.tsx`). Each item keeps the wording, links and
 * role it had as its own banner.
 */
function ConsoleAttention({
  attention,
  renewSoon,
  bannerHidden,
  onDismissBanner,
}: {
  attention: ReturnType<typeof useActionsAttention>;
  renewSoon: boolean;
  bannerHidden: boolean;
  onDismissBanner: () => void;
}) {
  const { pathname } = useLocation();
  const breakGlass = useBreakGlassState();
  const waiting = attention.waiting;
  const items: AttentionItem[] = [];

  // Not dismissible: an operator's offline write clears when acknowledged
  // (VTI-VTC-023), a cooling-off against you when it is cancelled or lands
  // (VTI-APV-019).
  if (attention.operatorWritesUnacknowledged.length > 0) {
    items.push({
      key: "operator-writes",
      severity: "critical",
      node: <OperatorWriteBanner actionIds={attention.operatorWritesUnacknowledged} />,
    });
  }
  for (const c of attention.coolingOffAgainstMe) {
    items.push({
      key: `cooling-off-${c.actionId}`,
      severity: "critical",
      node: <CoolingOffNotice item={c} />,
    });
  }
  // Not dismissible either: it clears when every self-granted elevated right
  // has been ratified or revoked (git-ns/right/break-glass). The "cannot be
  // checked from this browser" variant is pinned beside it.
  if (breakGlass.kind !== "none") {
    items.push({
      key: "break-glass",
      severity: "critical",
      node: <BreakGlassNotice state={breakGlass} />,
    });
  }
  // Permanent while in effect: single-administrator mode is reported to every
  // administrator on every page (VTI-APV-022).
  if (attention.singleAdminMode) {
    items.push({
      key: "single-admin",
      severity: "standing",
      node: <SingleAdminModeBanner on />,
    });
  }
  if (renewSoon && !pathname.startsWith("/console-keys")) {
    items.push({
      key: "signing-renew",
      severity: "warning",
      node: (
        <div
          className="signing-renew-banner attention-item attention-item--warning"
          role="status"
        >
          <strong>This browser's signing key expires soon.</strong>
          <span>
            Renew it now — one passkey confirmation — so the console keeps
            working.
          </span>
          <NavLink to="/console-keys">Renew</NavLink>
        </div>
      ),
    });
  }
  if (waiting > 0 && !bannerHidden && !pathname.startsWith("/actions")) {
    items.push({
      key: "actions-waiting",
      severity: "info",
      node: (
        <div className="actions-banner attention-item attention-item--info" role="status">
          <strong>{waitingSentence(waiting)}.</strong>
          <NavLink to="/actions">Review them</NavLink>
          <button
            type="button"
            className="link"
            aria-label="Dismiss for this session"
            onClick={onDismissBanner}
          >
            Dismiss
          </button>
        </div>
      ),
    });
  }
  return <AttentionStrip items={items} />;
}

function ReloadPluginsButton() {
  const toast = useToast();
  const [pending, setPending] = useState(false);
  return (
    <button
      type="button"
      className="link nav-reload"
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
