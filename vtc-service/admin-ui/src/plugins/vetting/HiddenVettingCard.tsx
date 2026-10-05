// Hidden vetting (PCS) for one criterion: whether it is on, what this
// community publishes for it, and the controls an administrator runs it with.
//
// What is shown is the join manifest's `vetting.ext["org.openvtc.hidden-vetting"]`
// — what applicants and vetters receive — never a copy the console keeps.
//
// Every write is `vtc/vetting/hidden/publish/0.1`, which **replaces** the
// criterion's configuration, events included. The manifest omits each event's
// `approvedBy` and `graceDays`, so re-publishing from it would un-approve every
// event. A criterion with events is therefore shown but not edited here.

import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { useConfirm } from "@/components/ConfirmDialog";
import {
  fetchHiddenVettingSupport,
  hiddenVettingKeys,
  labelsBehind,
  periodOf,
  publishHiddenVetting,
  type PublishedHiddenVetting,
} from "@/lib/hidden-vetting";
import { useToast } from "@/lib/toast";

import { vettingKeys } from "./api";
import { errorMessage, FormField } from "./ui";

/** The drip rates the daemon accepts: a positive whole number. */
function parseDrip(value: string): number | null {
  const n = Number(value.trim());
  return Number.isInteger(n) && n > 0 ? n : null;
}

export function HiddenVettingCard({
  criterionId,
  asksForVetting,
  published,
}: {
  criterionId: string;
  /** The stored criterion asks for vetting; publish refuses one that does not. */
  asksForVetting: boolean;
  /** The criterion's published parameters, `null` when hidden vetting is off. */
  published: PublishedHiddenVetting | null;
}) {
  const support = useQuery({
    queryKey: hiddenVettingKeys.support,
    queryFn: fetchHiddenVettingSupport,
    retry: false,
    staleTime: Infinity,
  });
  const queryClient = useQueryClient();
  const toast = useToast();
  const confirm = useConfirm();
  const [drip, setDrip] = useState<string>(String(published?.dripPerTick ?? 3));

  const refresh = () => {
    void queryClient.invalidateQueries({ queryKey: vettingKeys.manifest });
    void queryClient.invalidateQueries({ queryKey: vettingKeys.criteria });
  };

  const publish = useMutation({
    mutationFn: publishHiddenVetting,
    onSuccess: (res, input) => {
      refresh();
      toast.push(
        "success",
        published
          ? `Updated hidden vetting on "${criterionId}". Vetters and applicants read ${res.published.vetterLabels.join(", ")} from now on.`
          : `Hidden vetting is on for "${criterionId}" under ${res.published.vetterLabels.join(", ")}. Vetters enrol from their own client next.`,
      );
      if (input.dripPerTick !== undefined) setDrip(String(res.published.dripPerTick));
    },
  });

  if (!support.data?.publish) return null;

  const busy = publish.isPending;
  const hasEvents = (published?.events.length ?? 0) > 0;
  // A re-publish replaces the events, and this card builds it from the
  // manifest, which carries no approvals: sent back, every event would lose
  // its approval. So a criterion with events is not edited here until the
  // console reads the stored configuration (`vtc/vetting/hidden/show`).
  const editable = !hasEvents;
  const behind = published ? labelsBehind(published) : false;
  const dripValue = parseDrip(drip);
  const thisMonth = periodOf();

  const onEnable = async () => {
    const ok = await confirm({
      title: `Turn on hidden vetting for "${criterionId}"?`,
      message: `Applicants may then prove that enough of this community's vetters vetted them without saying which. Statements from named vetters keep counting as before. The keys are derived from this community's signing key; vetters enrol for vetter/${thisMonth} from their own client.`,
      confirmLabel: "Turn on hidden vetting",
    });
    if (ok) publish.mutate({ criterionId, ...(dripValue ? { dripPerTick: dripValue } : {}) });
  };

  const onRoll = async () => {
    const ok = await confirm({
      title: `Move "${criterionId}" to ${thisMonth}?`,
      message: `Vetters enrol and draw tokens under vetter/${thisMonth} and token/${thisMonth} from now on. Earlier labels stop being live, so an application still holding tokens under them has to gather new ones.`,
      confirmLabel: `Roll to ${thisMonth}`,
    });
    if (ok && published) {
      publish.mutate({ criterionId, dripPerTick: published.dripPerTick });
    }
  };

  const onSaveDrip = () => {
    if (!published || dripValue === null) return;
    publish.mutate({
      criterionId,
      livePeriods: published.vetterLabels.map((l) => l.replace(/^vetter\//, "")),
      liveTokenLabels: published.tokenLabels,
      dripPerTick: dripValue,
    });
  };

  const error = publish.error;

  return (
    <div className="vet-fieldset" aria-label="Hidden vetting">
      <h4>Hidden vetting (PCS)</h4>
      {!published ? (
        <>
          <p className="muted">
            Off. Only statements from named vetters count toward this criterion.
            {asksForVetting
              ? " Turning it on also accepts a zero-knowledge proof that enough vetters vetted the applicant, without revealing which."
              : " It qualifies a criterion's vetting, so this criterion has to ask for vetting first."}
          </p>
          {asksForVetting && (
            <div className="form-actions">
              <button
                type="button"
                className="secondary"
                disabled={busy}
                onClick={() => void onEnable()}
              >
                {publish.isPending ? "Turning on…" : "Turn on hidden vetting"}
              </button>
            </div>
          )}
        </>
      ) : (
        <>
          <dl>
            <dt>Status</dt>
            <dd>
              <strong>On</strong>, alongside named vetters
            </dd>
            <dt>Vetter labels</dt>
            <dd>
              {published.vetterLabels.map((l) => (
                <code key={l}>{l} </code>
              ))}
            </dd>
            <dt>Token labels</dt>
            <dd>
              {published.tokenLabels.map((l) => (
                <code key={l}>{l} </code>
              ))}
            </dd>
            <dt>Tokens a vetter may draw per tick</dt>
            <dd>{published.dripPerTick}</dd>
            <dt>Suite</dt>
            <dd>
              <code>{published.suite}</code>
            </dd>
            <dt>Events</dt>
            <dd>
              {hasEvents
                ? published.events.map((e) => (
                    <span key={e.eventId}>
                      <code>{e.eventId}</code> {e.startDate} – {e.endDate}{" "}
                    </span>
                  ))
                : "none"}
            </dd>
          </dl>
          <details>
            <summary>Verification keys</summary>
            <dl>
              <dt>Helper key</dt>
              <dd>
                <code>{published.helperKey}</code>
              </dd>
              <dt>Token key</dt>
              <dd>
                <code>{published.tokenKey}</code>
              </dd>
            </dl>
          </details>

          {behind && (
            <div className="finding warn" role="status">
              <strong>The live labels are behind this month.</strong>{" "}
              <span className="muted">
                They never advance on their own: vetters keep enrolling and
                drawing under {published.vetterLabels.join(", ")} until you
                roll them.
              </span>
            </div>
          )}

          {!editable && (
            <div className="finding warn" role="status">
              <strong>This criterion runs events, so it is not edited here yet.</strong>{" "}
              <span className="muted">
                A change replaces the whole configuration, and this VTC does not
                yet let the console read each event&rsquo;s approval back, so
                saving from here would un-approve them.
              </span>
            </div>
          )}

          {editable && (
            <>
              <FormField
                id={`pcs-drip-${criterionId}`}
                label="Tokens a vetter may draw per tick"
                hint="The published drip rate. A vetter's client draws at most this many attestation tokens each tick, whether or not they vetted anyone, so the rate never reveals who is busy."
                error={dripValue === null ? "A whole number of at least 1." : undefined}
              >
                <input
                  id={`pcs-drip-${criterionId}`}
                  type="text"
                  inputMode="numeric"
                  value={drip}
                  onChange={(e) => setDrip(e.target.value)}
                />
              </FormField>
              <div className="form-actions">
                <button
                  type="button"
                  className="secondary"
                  disabled={busy || dripValue === null || dripValue === published.dripPerTick}
                  onClick={onSaveDrip}
                >
                  Save drip rate
                </button>
                <button
                  type="button"
                  className={behind ? "primary" : "secondary"}
                  disabled={busy || !behind}
                  onClick={() => void onRoll()}
                >
                  Roll labels to {thisMonth}
                </button>
              </div>
            </>
          )}
          <p className="muted">
            Hidden vetting cannot be turned off for a criterion yet. Removing the
            criterion&rsquo;s vetting, or the criterion, removes it.
          </p>
        </>
      )}
      {error && (
        <div className="finding error" role="alert">
          <strong>Could not change hidden vetting</strong>
          <p>{errorMessage(error)}</p>
        </div>
      )}
    </div>
  );
}
