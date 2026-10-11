// The banner every administrator sees, on every page, while any break-glass
// grant is waiting for another administrator (`git-ns/right/break-glass`).
//
// It is the console's half of the specification's *Visibility* requirement: a
// self-granted elevated right is safe only because nobody can miss it. So the
// banner has no dismiss button and no "don't show again" — it goes away when
// the records do, once each has been ratified or revoked. A viewer the list
// is not for (`git-ns/view:notAdministrator`: they administer no namespace)
// sees nothing, and the query stops asking.
//
// The list is a signed read (`git-ns/view/0.5`, `scope: administrator`,
// `breakGlass: true`), answered to the signer and never to a session. So a
// browser that cannot sign cannot see it — and says so, rather than showing
// the silence an empty list would, because "nothing awaits you" is exactly
// what a break-glass nobody noticed looks like.

import { Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { Siren } from "lucide-react";

import { fetchBreakGlass, gitNsKeys } from "@/plugins/repos/api";
import { awaitingItems } from "@/plugins/repos/model";
import { SigningUnavailableError } from "@/lib/api";
import { BREAK_GLASS_PATH, isNotAdministrator } from "@/plugins/repos/ui";
import { useNameBook } from "@/lib/names";
import { shortenDid } from "@/lib/format";

/** How often the banner re-reads, so a break-glass made elsewhere reaches a
 *  console that is merely open. The notice push reaches the administrator's
 *  devices; this reaches the tab. */
export const BREAK_GLASS_POLL_MS = 60_000;

/** What the break-glass check found: nothing to report, the list could not be
 *  read because this browser cannot sign, or grants awaiting ratification. */
export type BreakGlassState =
  | { readonly kind: "none" }
  | { readonly kind: "cannotCheck" }
  | {
      readonly kind: "waiting";
      readonly count: number;
      readonly who: string;
      readonly right: string;
      readonly resource: string;
    };

/**
 * The break-glass read behind the banner, for the shell's attention strip
 * (`components/AttentionStrip.tsx`), which needs to know whether there is
 * anything to show before it orders and counts its items.
 */
export function useBreakGlassState(): BreakGlassState {
  const book = useNameBook();
  const q = useQuery({
    queryKey: gitNsKeys.breakGlass,
    queryFn: fetchBreakGlass,
    retry: false,
    refetchInterval: (query) =>
      isNotAdministrator(query.state.error) ? false : BREAK_GLASS_POLL_MS,
    refetchOnWindowFocus: true,
  });
  if (q.error instanceof SigningUnavailableError) return { kind: "cannotCheck" };
  const waiting = awaitingItems(q.data?.items ?? []);
  if (waiting.length === 0) return { kind: "none" };
  const first = waiting[0]!;
  return {
    kind: "waiting",
    count: waiting.length,
    who: book.nameOf(first.subject) ?? shortenDid(first.subject),
    right: first.right,
    resource: first.resource,
  };
}

/** The banner for a state from {@link useBreakGlassState}. */
export function BreakGlassNotice({ state }: { state: BreakGlassState }) {
  if (state.kind === "cannotCheck") {
    return (
      <div className="breakglass-banner attention-item attention-item--critical" role="status">
        <strong>
          <Siren aria-hidden="true" size={18} />
          Break-glass grants cannot be checked from this browser
        </strong>
        <span>
          The list is a signed read, and this browser has no console signing key. Enable
          signing to see whether a break-glass grant awaits you.
        </span>
        <Link to="/console-keys">Enable console signing</Link>
      </div>
    );
  }
  if (state.kind === "none") return null;
  const { count, who, right, resource } = state;
  return (
    <div
      className="breakglass-banner attention-item attention-item--critical"
      role="alert"
      aria-live="assertive"
    >
      <strong>
        <Siren aria-hidden="true" size={18} />
        {count === 1
          ? "1 break-glass grant awaits another administrator"
          : `${count} break-glass grants await another administrator`}
      </strong>
      <span>
        {count === 1
          ? `${who} gave themselves ${right} on ${resource}.`
          : `Oldest: ${who} gave themselves ${right} on ${resource}.`}{" "}
        It is live now and does not expire. Ratify it or revoke it.
      </span>
      <Link to={BREAK_GLASS_PATH}>Review break-glass grants</Link>
    </div>
  );
}

export function BreakGlassBanner() {
  return <BreakGlassNotice state={useBreakGlassState()} />;
}
