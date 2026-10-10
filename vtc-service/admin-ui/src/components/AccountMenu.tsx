// The account menu in the top bar: who is signed in, the operator's own
// settings (the plugins registered with `group: "account"` — My passkeys and
// Signing keys among the built-ins), the colour theme, and Sign out.
//
// A disclosure (button + panel) rather than an ARIA menu: its content is
// links, a segmented theme control and a button, which a menu role would hide
// from the usual Tab order. It closes on Escape (focus back to the button), on
// a click outside it, and when the route changes.

import { useEffect, useId, useRef, useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { NavLink, useLocation } from "react-router-dom";
import { ChevronDown, LogOut } from "lucide-react";

import { PluginIcon } from "@/components/PluginIcon";
import { ThemeSwitcher } from "@/components/ThemeSwitcher";
import { signOut, type WhoamiResponse } from "@/lib/api";
import { shortenDid } from "@/lib/format";
import { useNameBook } from "@/lib/names";
import { useToast } from "@/lib/toast";
import type { PluginManifest } from "@/plugin-api";

/** Up to two initials from a display name; `null` when there is none worth
 *  abbreviating (the avatar then shows a generic glyph). */
export function initialsOf(name: string | null | undefined): string | null {
  if (!name) return null;
  const words = name
    .replace(/\[unverified\]/i, "")
    .trim()
    .split(/[\s._@-]+/)
    .filter((w) => /^[\p{L}\p{N}]/u.test(w));
  if (words.length === 0) return null;
  const letters = words.length === 1 ? [words[0]!] : [words[0]!, words[words.length - 1]!];
  return letters.map((w) => [...w][0]!.toUpperCase()).join("");
}

export function AccountMenu({
  whoami,
  plugins,
  renewSoon,
}: {
  whoami: WhoamiResponse;
  /** Visible plugins with `group: "account"`, in registration order. */
  plugins: readonly PluginManifest[];
  /** This browser's signing key expires soon: flag the Signing keys entry. */
  renewSoon: boolean;
}) {
  const [open, setOpen] = useState(false);
  const panelId = useId();
  const rootRef = useRef<HTMLDivElement>(null);
  const triggerRef = useRef<HTMLButtonElement>(null);
  const { pathname } = useLocation();
  const book = useNameBook();
  const qc = useQueryClient();
  const toast = useToast();

  const did = whoami.session.subject;
  const name = book.nameOf(did);
  const label = name ?? shortenDid(did);
  const initials = initialsOf(name);

  const signOutMut = useMutation({
    mutationFn: signOut,
    onError: (err) => toast.pushFromError(err, "Sign-out failed"),
    onSettled: () => {
      // Whether the server-side revoke succeeded or not, the cookies are gone
      // now — force the query cache to refetch so the shell flips back to the
      // Login screen.
      qc.invalidateQueries({ queryKey: ["whoami"] });
    },
  });

  // Close on navigation.
  useEffect(() => {
    setOpen(false);
  }, [pathname]);

  // Close on a click outside, or Escape.
  useEffect(() => {
    if (!open) return;
    const onPointer = (e: MouseEvent) => {
      if (rootRef.current && !rootRef.current.contains(e.target as Node)) setOpen(false);
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        setOpen(false);
        triggerRef.current?.focus();
      }
    };
    document.addEventListener("mousedown", onPointer);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", onPointer);
      document.removeEventListener("keydown", onKey);
    };
  }, [open]);

  return (
    <div className="account-menu" ref={rootRef}>
      <button
        ref={triggerRef}
        type="button"
        className="account-trigger"
        aria-expanded={open}
        aria-controls={panelId}
        aria-label={`Account: ${label}`}
        title={did}
        onClick={() => setOpen((v) => !v)}
      >
        <span className="account-avatar" aria-hidden="true">
          {initials ?? label.charAt(0).toUpperCase()}
        </span>
        <span className="account-name">{label}</span>
        {renewSoon && <span className="account-flag" aria-hidden="true" />}
        <span className="button-icon account-chevron" aria-hidden="true">
          <ChevronDown />
        </span>
      </button>
      {open && (
        <div className="account-panel" id={panelId}>
          <div className="account-who session-badge">
            <span className="session-label">Signed in as</span>
            {name && <strong className="account-who-name">{name}</strong>}
            <code title={did}>{shortenDid(did)}</code>
          </div>
          {plugins.length > 0 && (
            <ul className="account-links">
              {plugins.map((p) => (
                <li key={p.id}>
                  <NavLink to={p.path}>
                    <span className="nav-icon" aria-hidden="true">
                      <PluginIcon plugin={p} />
                    </span>
                    <span className="nav-label">{p.label}</span>
                    {p.id === "console-keys" && renewSoon && (
                      <span className="chip warning account-renew">Renew soon</span>
                    )}
                  </NavLink>
                </li>
              ))}
            </ul>
          )}
          <div className="account-theme">
            <span>Theme</span>
            <ThemeSwitcher />
          </div>
          <button
            type="button"
            className="account-signout"
            onClick={() => signOutMut.mutate()}
            disabled={signOutMut.isPending}
            aria-busy={signOutMut.isPending}
          >
            <span className="button-icon" aria-hidden="true">
              <LogOut />
            </span>
            {signOutMut.isPending ? "Signing out…" : "Sign out"}
          </button>
        </div>
      )}
    </div>
  );
}
