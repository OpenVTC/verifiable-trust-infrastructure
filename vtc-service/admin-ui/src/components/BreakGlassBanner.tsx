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

export function BreakGlassBanner() {
  const book = useNameBook();
  const q = useQuery({
    queryKey: gitNsKeys.breakGlass,
    queryFn: fetchBreakGlass,
    retry: false,
    refetchInterval: (query) =>
      isNotAdministrator(query.state.error) ? false : BREAK_GLASS_POLL_MS,
    refetchOnWindowFocus: true,
  });
  if (q.error instanceof SigningUnavailableError) {
    return (
      <div className="breakglass-banner" role="status">
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
  const waiting = awaitingItems(q.data?.items ?? []);
  if (waiting.length === 0) return null;

  const first = waiting[0]!;
  const who = book.nameOf(first.subject) ?? shortenDid(first.subject);
  return (
    <div className="breakglass-banner" role="alert" aria-live="assertive">
      <strong>
        <Siren aria-hidden="true" size={18} />
        {waiting.length === 1
          ? "1 break-glass grant awaits another administrator"
          : `${waiting.length} break-glass grants await another administrator`}
      </strong>
      <span>
        {waiting.length === 1
          ? `${who} gave themselves ${first.right} on ${first.resource}.`
          : `Oldest: ${who} gave themselves ${first.right} on ${first.resource}.`}{" "}
        It is live now and does not expire. Ratify it or revoke it.
      </span>
      <Link to={BREAK_GLASS_PATH}>Review break-glass grants</Link>
    </div>
  );
}
