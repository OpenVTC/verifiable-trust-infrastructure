import { useEffect, useRef, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { NavLink, Route, Routes, useLocation } from "react-router-dom";
import { ChevronsLeft, ChevronsRight, Menu, RefreshCw, X } from "lucide-react";

import { getPlugins, subscribePlugins, type PluginManifest } from "@/plugin-api";
import { PluginHost } from "@/components/PluginHost";
import { ThemeSwitcher } from "@/components/ThemeSwitcher";
import { probeSession, signOut, WhoamiResponse } from "@/lib/api";
import { reloadThirdPartyPlugins } from "@/lib/plugin-loader";
import { useToast } from "@/lib/toast";
import { Install } from "@/pages/Install";
import { Login } from "@/pages/Login";

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
      toast.push("info", "Your session expired. Sign in again to continue.");
      qc.setQueryData(["whoami"], null);
      void qc.invalidateQueries({ queryKey: ["whoami"] });
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

  // Re-arm the session-expiry guard whenever a fresh session lands.
  // Without this, a second expiry inside the same browser tab would
  // be silently ignored.
  useEffect(() => {
    if (probe.data) {
      expiryNotifiedRef.current = false;
    }
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

  if (probe.isPending) {
    return <SignInLoading />;
  }
  if (!probe.data) {
    return <Login />;
  }

  // A "super admin" is Admin role with no context restrictions.
  // Scope-filtered plugins surface server errors as 403s anyway, but
  // hiding them from the nav keeps the UX coherent.
  const isSuperAdmin =
    probe.data.role === "admin" && probe.data.allowedContexts.length === 0;
  const plugins = allPlugins.filter((p) => {
    if (!p.scopes || p.scopes.length === 0) return true;
    if (p.scopes.includes("super-admin")) return isSuperAdmin;
    return true;
  });

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
              </NavLink>
            </li>
          ))}
        </ul>
        <ReloadPluginsButton />
      </aside>
      <main className="content">
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
          {/* Fallback for unknown URLs under /admin/ */}
          <Route path="*" element={<NotFound />} />
        </Routes>
      </main>
    </div>
  );
}

function PluginIcon({ plugin }: { plugin: PluginManifest }) {
  // Built-in plugins ship a lucide-react component; third-party
  // plugins fall back to the `icon` string (inline SVG or single
  // glyph). If neither is set, fall back to the label's first
  // letter so the nav row stays balanced.
  if (plugin.iconComponent) {
    const Icon = plugin.iconComponent;
    return <Icon aria-hidden="true" />;
  }
  if (plugin.icon) {
    if (plugin.icon.trim().startsWith("<")) {
      return (
        <span
          className="plugin-icon-raw"
          dangerouslySetInnerHTML={{ __html: plugin.icon }}
        />
      );
    }
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
      <div className="session-did" title={whoami.did}>
        <span className="session-label">Signed in as</span>
        <code>{shortDid(whoami.did)}</code>
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

function shortDid(did: string): string {
  // `did:key:z6Mk…XYZ` — keep the method prefix readable + the
  // last 6 chars so two distinct admins are still visually
  // distinguishable in the navbar.
  if (did.length <= 20) return did;
  return `${did.slice(0, 12)}…${did.slice(-6)}`;
}

function SignInLoading() {
  return (
    <section className="page login-page">
      <div className="login-card">
        <h2>VTC Admin</h2>
        <p className="lead">Checking session…</p>
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
