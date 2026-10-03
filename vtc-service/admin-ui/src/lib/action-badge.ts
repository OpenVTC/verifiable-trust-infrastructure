// Seeing that something is waiting (docs/05-design-notes/vtc-action-list.md
// §7.1): the nav badge, the post-sign-in banner and the tab title, all driven
// by one count — `counts.waitingForMe` from a signed `vtc/admin/actions/list`
// read (a console key may sign reads).
//
// The count is fetched at sign-in, whenever the tab regains focus or becomes
// visible, and every 60 s while the console is open. It is a hint, not the
// source of truth: the Actions page reads the list itself.
//
// The same read carries the list's `ext["org.openvtc"]` — the operator writes
// waiting for this administrator's acknowledgement and the cooling-offs
// against them — which drive the shell's two Critical banners
// (`components/ActionsAlertBanners.tsx`).

import { useEffect } from "react";
import { useQuery } from "@tanstack/react-query";

import { fetchActionsAttention, type ActionsAttention } from "./actions-api";

/** The Actions plugin's id — the shell draws its nav badge. */
export const ACTIONS_PLUGIN_ID = "actions";

/** The react-query key the badge count lives under. */
export const WAITING_COUNT_KEY = ["actions-waiting"] as const;

/** How often the count is polled while signed in. */
export const WAITING_POLL_MS = 60_000;

/** The `(N) ` prefix the tab title carries. */
const TITLE_PREFIX = /^\(\d+\)\s/;

/** `title` with the waiting count in front when there is one. */
export function titleWithCount(title: string, count: number): string {
  const base = title.replace(TITLE_PREFIX, "");
  return count > 0 ? `(${count}) ${base}` : base;
}

/** The banner's sentence. */
export function waitingSentence(count: number): string {
  return `${count} action${count === 1 ? "" : "s"} waiting for your approval`;
}

/** Where the banner's dismissal is kept — for the session only. */
export const BANNER_DISMISSED_KEY = "vtc-actions-banner-dismissed";

export function bannerDismissed(): boolean {
  try {
    return sessionStorage.getItem(BANNER_DISMISSED_KEY) === "1";
  } catch {
    return false;
  }
}

export function dismissBanner(): void {
  try {
    sessionStorage.setItem(BANNER_DISMISSED_KEY, "1");
  } catch {
    // Storage blocked: the banner just comes back on the next render pass.
  }
}

const NOTHING: ActionsAttention = Object.freeze({
  waiting: 0,
  operatorWritesUnacknowledged: [],
  coolingOffAgainstMe: [],
  singleAdminMode: false,
}) as ActionsAttention;

/**
 * The number of actions waiting for the signed-in administrator, kept fresh
 * while `enabled`, with the tab title following it. `0` while unknown or on
 * any failure — the badge is decoration and must never take the shell down.
 */
export function useWaitingCount(enabled: boolean): number {
  return useActionsAttention(enabled).waiting;
}

/**
 * [`useWaitingCount`]'s read, whole: the count, plus the operator writes
 * waiting for this administrator's acknowledgement (VTI-VTC-023) and the
 * cooling-offs reducing their own authority (VTI-APV-019) — what the shell's
 * Critical banners show. Empty while unknown or on any failure.
 */
export function useActionsAttention(enabled: boolean): ActionsAttention {
  const query = useQuery({
    queryKey: WAITING_COUNT_KEY,
    queryFn: fetchActionsAttention,
    enabled,
    refetchInterval: enabled ? WAITING_POLL_MS : false,
    refetchIntervalInBackground: true,
    refetchOnWindowFocus: false,
    staleTime: 0,
    retry: false,
  });
  const { refetch } = query;

  useEffect(() => {
    if (!enabled) return;
    const onFocus = () => void refetch();
    const onVisible = () => {
      if (document.visibilityState === "visible") void refetch();
    };
    window.addEventListener("focus", onFocus);
    document.addEventListener("visibilitychange", onVisible);
    return () => {
      window.removeEventListener("focus", onFocus);
      document.removeEventListener("visibilitychange", onVisible);
    };
  }, [enabled, refetch]);

  const attention = enabled && query.data ? query.data : NOTHING;
  const count = attention.waiting;

  useEffect(() => {
    document.title = titleWithCount(document.title, count);
  }, [count]);
  useEffect(
    () => () => {
      document.title = titleWithCount(document.title, 0);
    },
    [],
  );

  return attention;
}
