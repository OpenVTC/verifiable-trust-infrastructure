// The two Critical banners the action list raises outside the Actions page.
//
// - An operator changed the community's access control offline (VTI-VTC-023)
//   and this administrator has not acknowledged it yet. The change is already
//   in effect; the banner exists so nobody can miss that it happened.
// - Another administrator has asked to reduce this administrator's own
//   authority under the two-administrator rule (VTI-APV-019): it lands by
//   itself at the end of a cooling-off unless the requester cancels it, and
//   the subject cannot block it — but must be able to see it coming.
//
// Like the break-glass banner, neither has a dismiss button: each goes away
// only when what it reports does (acknowledged; cancelled or landed). Both
// read the list's `ext["org.openvtc"]` from the badge's own signed read
// (`lib/action-badge.ts`), so they cost no request of their own.

import { Link } from "react-router-dom";
import { ShieldAlert, Siren } from "lucide-react";

import { landsIn, type CoolingOffAgainstMe } from "@/lib/actions-api";
import { actionPath } from "@/lib/parked-action";
import { formatIso, shortenDid } from "@/lib/format";
import { useNameBook } from "@/lib/names";

export const OPERATOR_WRITE_SENTENCE =
  "The operator changed this community's access control offline. Acknowledge it in Actions.";

export function OperatorWriteBanner({ actionIds }: { actionIds: readonly string[] }) {
  if (actionIds.length === 0) return null;
  const target = actionIds.length === 1 ? actionPath(actionIds[0]!) : "/actions";
  return (
    <div className="breakglass-banner critical-banner" role="alert" aria-live="assertive">
      <strong>
        <Siren aria-hidden="true" size={18} />
        Critical: an offline change waits for your acknowledgement
      </strong>
      <span>
        {OPERATOR_WRITE_SENTENCE}
        {actionIds.length > 1 && ` (${actionIds.length} changes)`}
      </span>
      <Link to={target}>Open Actions</Link>
    </div>
  );
}

export function CoolingOffBanner({ items }: { items: readonly CoolingOffAgainstMe[] }) {
  const book = useNameBook();
  if (items.length === 0) return null;
  return (
    <>
      {items.map((c) => {
        const who = book.nameOf(c.requester) ?? shortenDid(c.requester);
        return (
          <div
            key={c.actionId}
            className="breakglass-banner critical-banner"
            role="alert"
            aria-live="assertive"
          >
            <strong>
              <ShieldAlert aria-hidden="true" size={18} />
              Critical: a reduction of your authority is cooling off
            </strong>
            <span>
              {who} has asked to reduce your authority. It takes effect at{" "}
              {formatIso(c.landsAt)} ({landsIn(c.landsAt)}) unless they cancel it.
            </span>
            <Link to={actionPath(c.actionId)}>View the action</Link>
          </div>
        );
      })}
    </>
  );
}
