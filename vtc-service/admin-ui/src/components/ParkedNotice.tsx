// The success notice for an act the VTC parked as an administrator action,
// and the inline error card that shows one in place of an error.
//
// A screen that renders a mutation's error inline (rather than as a toast)
// uses `<ErrorOrParked>`: a parked act arrives as the mutation's error
// (`lib/parked-action.ts` says why it is thrown), but it is a success, and
// reading it in a red "failed" card is the confusion §7.3 of the action-list
// design removes.

import { Link } from "react-router-dom";

import { formatIso } from "@/lib/format";
import { parkedOf, type ParkedAction } from "@/lib/parked-action";

export function ParkedNotice({ action }: { action: ParkedAction }) {
  // A cooling-off (VTI-APV-019) asks nobody for approval: it lands by itself
  // unless the requester cancels it, so "N must approve" would be false.
  if (action.coolingOffUntil) {
    return (
      <section className="card success parked-notice" role="status">
        <h3>Sent — lands after a cooling-off</h3>
        <p>{action.message}</p>
        <p>
          Lands by itself at <strong>{formatIso(action.coolingOffUntil)}</strong> unless you
          cancel it.
        </p>
        <p>
          <Link to={action.path}>View the action</Link>
        </p>
      </section>
    );
  }
  return (
    <section className="card success parked-notice" role="status">
      <h3>Sent for approval</h3>
      <p>{action.message}</p>
      <p>
        <Link to={action.path}>View the action</Link>
      </p>
    </section>
  );
}

/** `error` as an error card titled `title`, or as a [`ParkedNotice`]. */
export function ErrorOrParked({ title, error }: { title: string; error: unknown }) {
  if (!error) return null;
  const parked = parkedOf(error);
  if (parked) return <ParkedNotice action={parked} />;
  return (
    <section className="card error">
      <h3>{title}</h3>
      <p>{(error as Error).message}</p>
    </section>
  );
}
