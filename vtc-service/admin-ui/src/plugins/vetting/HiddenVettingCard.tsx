// Hidden vetting (PCS) for one criterion: whether it is on, what this
// community publishes for it, and every control an administrator runs it with —
// turning it on and off, the drip rate, rolling the labels, and events.
//
// Two reads, for two questions. The join manifest's
// `vetting.ext["org.openvtc.hidden-vetting"]` is what applicants and vetters
// receive. `vtc/vetting/hidden/show/0.1` is what is stored — each event's
// approval and grace included — with the counts an administrator runs it by:
// members enrolled under each label, and each event's demand against its floor.
//
// Every write is `vtc/vetting/hidden/publish/0.1`, which **replaces** the
// whole configuration, so every edit starts from the stored one (`republish`).
// On a build without `show`, a criterion with events is shown but not edited:
// the manifest carries no approvals, and sending it back would drop them.

import { type FormEvent, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { useConfirm } from "@/components/ConfirmDialog";
import {
  DEFAULT_TICK_LENGTH,
  describeTickLength,
  tickLengthHours,
  type EventInput,
  type EventStatus,
  eventLabel,
  fetchHiddenVettingSupport,
  hiddenVettingKeys,
  labelsBehind,
  periodOf,
  publishHiddenVetting,
  type PublishHiddenInput,
  type PublishedHiddenVetting,
  republish,
  showHiddenVetting,
  type StoredHiddenVetting,
  withdrawHiddenVetting,
} from "@/lib/hidden-vetting";
import { useToast } from "@/lib/toast";
import { useViewerDid } from "@/lib/viewer";

import { vettingKeys } from "./api";
import { errorMessage, FormField } from "./ui";

/** A positive whole number, or `null`. */
function parsePositive(value: string): number | null {
  const n = Number(value.trim());
  return Number.isInteger(n) && n > 0 ? n : null;
}

export function HiddenVettingCard({
  criterionId,
  asksForVetting,
  published,
  otherHiddenCriterion,
}: {
  criterionId: string;
  /** The stored criterion asks for vetting; publish refuses one that does not. */
  asksForVetting: boolean;
  /** The criterion's published parameters, `null` when hidden vetting is off. */
  published: PublishedHiddenVetting | null;
  /** Another criterion that already has hidden vetting on, if any. Vetters
   * enrol and draw under the first such criterion, so a second one is
   * accepted but never minted for. */
  otherHiddenCriterion?: string;
}) {
  const support = useQuery({
    queryKey: hiddenVettingKeys.support,
    queryFn: fetchHiddenVettingSupport,
    retry: false,
    staleTime: Infinity,
  });
  const show = useQuery({
    queryKey: hiddenVettingKeys.show(criterionId),
    queryFn: () => showHiddenVetting(criterionId),
    enabled: Boolean(support.data?.show && published),
    retry: false,
  });
  const viewerDid = useViewerDid();
  const queryClient = useQueryClient();
  const toast = useToast();
  const confirm = useConfirm();
  const [drip, setDrip] = useState<string | null>(null);
  const [tick, setTick] = useState<string | null>(null);

  const refresh = () => {
    void queryClient.invalidateQueries({ queryKey: vettingKeys.manifest });
    void queryClient.invalidateQueries({ queryKey: vettingKeys.criteria });
    void queryClient.invalidateQueries({ queryKey: hiddenVettingKeys.show(criterionId) });
  };

  const publish = useMutation({
    mutationFn: (input: { body: PublishHiddenInput; done: string }) =>
      publishHiddenVetting(input.body),
    onSuccess: (_res, input) => {
      refresh();
      setDrip(null);
      setTick(null);
      toast.push("success", input.done);
    },
  });
  const withdraw = useMutation({
    mutationFn: withdrawHiddenVetting,
    onSuccess: () => {
      refresh();
      toast.push(
        "success",
        `Hidden vetting is off for "${criterionId}". Only statements from named vetters count from now on.`,
      );
    },
  });

  if (!support.data?.publish) return null;

  const stored: StoredHiddenVetting | null = show.data?.stored ?? null;
  const busy = publish.isPending || withdraw.isPending;
  const hasEvents = (published?.events.length ?? 0) > 0;
  // Edits start from the stored configuration when the build can read it;
  // without it, only a criterion with no events (nothing to lose) is edited.
  const editable = Boolean(published) && (stored !== null || !hasEvents);
  const behind = published ? labelsBehind(published) : false;
  const dripText = drip ?? String(published?.dripPerTick ?? 3);
  const dripValue = parsePositive(dripText);
  const publishedTick = published?.tickLength ?? DEFAULT_TICK_LENGTH;
  const tickText = (tick ?? publishedTick).trim();
  const tickValid = tickLengthHours(tickText) !== null;
  const rateChanged =
    (dripValue !== null && dripValue !== published?.dripPerTick) || tickText !== publishedTick;
  const thisMonth = periodOf();

  /** The publish an edit sends: from the stored configuration when there is one. */
  const body = (patch: Partial<Omit<PublishHiddenInput, "criterionId">>): PublishHiddenInput =>
    stored
      ? republish(criterionId, stored, patch)
      : {
          criterionId,
          livePeriods: published!.vetterLabels.map((l) => l.replace(/^vetter\//, "")),
          liveTokenLabels: published!.tokenLabels,
          dripPerTick: published!.dripPerTick,
          ...(published!.tickLength ? { tickLength: published!.tickLength } : {}),
          ...patch,
        };

  const onEnable = async () => {
    const ok = await confirm({
      title: `Turn on hidden vetting for "${criterionId}"?`,
      message: `Applicants may then prove that enough of this community's vetters vetted them without saying which. Statements from named vetters keep counting as before. The keys are derived from this community's signing key; vetters enrol for vetter/${thisMonth} from their own client.`,
      confirmLabel: "Turn on hidden vetting",
    });
    if (ok) {
      publish.mutate({
        body: { criterionId, ...(dripValue ? { dripPerTick: dripValue } : {}) },
        done: `Hidden vetting is on for "${criterionId}" under vetter/${thisMonth}. Vetters enrol from their own client next.`,
      });
    }
  };

  const onRoll = async () => {
    const ok = await confirm({
      title: `Move "${criterionId}" to ${thisMonth}?`,
      message: `Vetters enrol and draw tokens under vetter/${thisMonth} and token/${thisMonth} from now on. Earlier labels stop being live, so an application still holding tokens under them has to gather new ones. Events keep their own labels.`,
      confirmLabel: `Roll to ${thisMonth}`,
    });
    if (!ok) return;
    const eventLabels = (stored?.events ?? []).map((e) => eventLabel(e.eventId));
    publish.mutate({
      body: body({
        livePeriods: [thisMonth],
        liveTokenLabels: [`token/${thisMonth}`, ...eventLabels],
      }),
      done: `"${criterionId}" now runs under vetter/${thisMonth}.`,
    });
  };

  const onSaveDrip = () => {
    if (dripValue === null || !tickValid) return;
    publish.mutate({
      body: body({ dripPerTick: dripValue, tickLength: tickText }),
      done: `Vetters may now draw ${dripValue} token${dripValue === 1 ? "" : "s"} every ${describeTickLength(tickText)}.`,
    });
  };

  const onWithdraw = async () => {
    const ok = await confirm({
      title: `Turn off hidden vetting for "${criterionId}"?`,
      message:
        "Applicants can no longer submit a hidden proof for this criterion, and one already gathering hidden attestations will have to be vetted by named vetters instead. Vetters' enrolments are kept, so turning it back on later works with the same keys.",
      confirmLabel: "Turn off hidden vetting",
      destructive: true,
    });
    if (ok) withdraw.mutate(criterionId);
  };

  const setEvents = (events: EventInput[], done: string) => {
    if (!stored) return;
    const periodLabels = stored.liveTokenLabels.filter((l) => !l.startsWith("token/event/"));
    publish.mutate({
      body: republish(criterionId, stored, {
        events,
        liveTokenLabels: [...periodLabels, ...events.map((e) => eventLabel(e.eventId))],
      }),
      done,
    });
  };

  const onApprove = async (event: EventInput) => {
    if (!stored || !viewerDid) return;
    const ok = await confirm({
      title: `Approve the event "${event.eventId}"?`,
      message: `Vetters who asked to vet at it may then draw its higher rate under ${eventLabel(event.eventId)}, from ${event.startDate} until its grace period ends — once at least ${event.groupFloor ?? 3} of them have asked. You are recorded as its approver. If you asked to vet at it yourself, another administrator has to approve it.`,
      confirmLabel: "Approve event",
    });
    if (!ok) return;
    setEvents(
      stored.events.map((e) => (e.eventId === event.eventId ? { ...e, approvedBy: viewerDid } : e)),
      `Approved "${event.eventId}".`,
    );
  };

  const onRemoveEvent = async (event: EventInput) => {
    if (!stored) return;
    const ok = await confirm({
      title: `Remove the event "${event.eventId}"?`,
      message: `Its label, ${eventLabel(event.eventId)}, stops being live: vetters can no longer draw under it, and tokens already drawn under it stop counting.`,
      confirmLabel: "Remove event",
      destructive: true,
    });
    if (!ok) return;
    setEvents(
      stored.events.filter((e) => e.eventId !== event.eventId),
      `Removed "${event.eventId}".`,
    );
  };

  const error = publish.error ?? withdraw.error ?? show.error;

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
          {otherHiddenCriterion && asksForVetting && (
            <div className="finding warn" role="status">
              <strong>
                Hidden vetting is on for <code>{otherHiddenCriterion}</code>.
              </strong>{" "}
              <span className="muted">
                A community runs it on one criterion: vetters enrol and draw
                under a single configuration. Turn it off there to move it here.
              </span>
            </div>
          )}
          {asksForVetting && (
            <div className="form-actions">
              <button
                type="button"
                className="secondary"
                disabled={busy || Boolean(otherHiddenCriterion)}
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
                <span key={l}>
                  <code>{l}</code>
                  {show.data?.enrolledVetters?.[l] !== undefined && (
                    <span className="muted">
                      {" "}
                      ({show.data.enrolledVetters[l]} enrolled)
                    </span>
                  )}{" "}
                </span>
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
            <dt>Tick length</dt>
            <dd>{describeTickLength(publishedTick)}</dd>
            <dt>Suite</dt>
            <dd>
              <code>{published.suite}</code>
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
              <strong>This criterion runs events, so it is not edited here.</strong>{" "}
              <span className="muted">
                A change replaces the whole configuration, and this VTC does not
                let the console read each event&rsquo;s approval back, so saving
                from here would un-approve them.
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
                  value={dripText}
                  onChange={(e) => setDrip(e.target.value)}
                />
              </FormField>
              <FormField
                id={`pcs-tick-${criterionId}`}
                label="Tick length"
                hint={
                  tickValid
                    ? `${describeTickLength(tickText)}. A vetter draws once per tick, never ahead; a tick it missed can still be drawn later. An ISO 8601 duration in days and/or hours, like P3D or PT12H.`
                    : "An ISO 8601 duration in days and/or hours, like P3D or PT12H."
                }
                error={tickValid ? undefined : "Days and/or hours, at least one hour."}
              >
                <input
                  id={`pcs-tick-${criterionId}`}
                  type="text"
                  spellCheck={false}
                  value={tickText}
                  onChange={(e) => setTick(e.target.value)}
                />
              </FormField>
              <div className="form-actions">
                <button
                  type="button"
                  className="secondary"
                  disabled={busy || dripValue === null || !tickValid || !rateChanged}
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
                {support.data.withdraw && (
                  <button
                    type="button"
                    className="secondary destructive"
                    disabled={busy}
                    onClick={() => void onWithdraw()}
                  >
                    Turn off hidden vetting
                  </button>
                )}
              </div>
            </>
          )}

          {stored && (
            <EventsSection
              criterionId={criterionId}
              events={stored.events}
              status={show.data?.eventStatus ?? []}
              viewerDid={viewerDid}
              busy={busy}
              onApprove={(e) => void onApprove(e)}
              onRemove={(e) => void onRemoveEvent(e)}
              onAdd={(e) =>
                setEvents([...stored.events, e], `Added the event "${e.eventId}". It needs an approval before vetters can draw under it.`)
              }
            />
          )}

          {!support.data.withdraw && (
            <p className="muted">
              This VTC cannot turn hidden vetting off for a criterion. Removing
              the criterion&rsquo;s vetting, or the criterion, removes it.
            </p>
          )}
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

// ── Events ──────────────────────────────────────────────────────────────

function EventsSection({
  criterionId,
  events,
  status,
  viewerDid,
  busy,
  onApprove,
  onRemove,
  onAdd,
}: {
  criterionId: string;
  events: StoredHiddenVetting["events"];
  status: EventStatus[];
  viewerDid: string | null;
  busy: boolean;
  onApprove: (event: EventInput) => void;
  onRemove: (event: EventInput) => void;
  onAdd: (event: EventInput) => void;
}) {
  const [adding, setAdding] = useState(false);
  const byId = new Map(status.map((s) => [s.eventId, s]));

  return (
    <div className="vet-fieldset" aria-label="Events">
      <h5>Events</h5>
      <p className="muted">
        An event gives vetters at a named gathering a higher drip rate under its
        own label, for its dates plus a grace period. It opens only when an
        administrator who is not vetting at it approves it, and enough vetters
        have asked to vet at it that a spend still hides who made it.
      </p>
      {events.length === 0 ? (
        <p className="muted">No events.</p>
      ) : (
        <table className="data-table">
          <thead>
            <tr>
              <th>Event</th>
              <th>Dates</th>
              <th>Vetters asked</th>
              <th>Approved by</th>
              <th>State</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {events.map((e) => {
              const s = byId.get(e.eventId);
              return (
                <tr key={e.eventId}>
                  <td>
                    <code>{e.eventId}</code>
                    <div className="muted">
                      {e.tiers.map((t) => `${t.name}: ${t.dripPerTick}/tick`).join(", ")}
                    </div>
                  </td>
                  <td>
                    {e.startDate} – {e.endDate}
                    <div className="muted">+{e.graceDays} days grace</div>
                  </td>
                  <td>
                    {s ? `${s.groupSize} of ${s.groupFloor} needed` : "—"}
                  </td>
                  <td>
                    {e.approvedBy ? (
                      <code>{e.approvedBy === viewerDid ? "you" : e.approvedBy}</code>
                    ) : (
                      <span className="muted">not yet</span>
                    )}
                  </td>
                  <td>
                    {s?.live
                      ? "Open"
                      : e.approvedBy && s && !s.approved
                        ? "Approver is vetting at it"
                        : !e.approvedBy
                          ? "Needs approval"
                          : s && s.groupSize < s.groupFloor
                            ? "Waiting for vetters"
                            : "Closed"}
                  </td>
                  <td>
                    <div className="form-actions">
                      {!e.approvedBy && (
                        <button
                          type="button"
                          className="secondary"
                          disabled={busy || !viewerDid}
                          onClick={() => onApprove(e)}
                        >
                          Approve
                        </button>
                      )}
                      <button
                        type="button"
                        className="secondary destructive"
                        disabled={busy}
                        onClick={() => onRemove(e)}
                      >
                        Remove
                      </button>
                    </div>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      )}
      {adding ? (
        <EventForm
          criterionId={criterionId}
          taken={events.map((e) => e.eventId)}
          busy={busy}
          onCancel={() => setAdding(false)}
          onSubmit={(e) => {
            onAdd(e);
            setAdding(false);
          }}
        />
      ) : (
        <div className="form-actions">
          <button
            type="button"
            className="secondary"
            disabled={busy}
            onClick={() => setAdding(true)}
          >
            Add an event
          </button>
        </div>
      )}
    </div>
  );
}

const EVENT_ID = /^[a-z0-9][a-z0-9-]*$/;
const ISO_DATE = /^\d{4}-\d{2}-\d{2}$/;

function EventForm({
  criterionId,
  taken,
  busy,
  onCancel,
  onSubmit,
}: {
  criterionId: string;
  taken: string[];
  busy: boolean;
  onCancel: () => void;
  onSubmit: (event: EventInput) => void;
}) {
  const [id, setId] = useState("");
  const [start, setStart] = useState("");
  const [end, setEnd] = useState("");
  const [grace, setGrace] = useState("14");
  const [floor, setFloor] = useState("3");
  const [tierName, setTierName] = useState("desk");
  const [tierDrip, setTierDrip] = useState("10");

  const problems = {
    id: !EVENT_ID.test(id)
      ? "Lower-case letters, digits and hyphens, like summit-2026."
      : taken.includes(id)
        ? "An event of that name is already configured."
        : undefined,
    dates:
      !ISO_DATE.test(start) || !ISO_DATE.test(end)
        ? "Both dates, as YYYY-MM-DD."
        : end < start
          ? "The event ends before it starts."
          : undefined,
    grace: Number.isInteger(Number(grace)) && Number(grace) >= 0 ? undefined : "Whole days, 0 or more.",
    floor: parsePositive(floor) && Number(floor) >= 2 ? undefined : "At least 2: a group of one is a name.",
    tier: tierName.trim() && parsePositive(tierDrip) ? undefined : "A tier name and a rate of at least 1.",
  };
  const ok = Object.values(problems).every((p) => p === undefined);

  const submit = (e: FormEvent) => {
    e.preventDefault();
    if (!ok) return;
    onSubmit({
      eventId: id,
      startDate: start,
      endDate: end,
      graceDays: Number(grace),
      groupFloor: Number(floor),
      tiers: [{ name: tierName.trim(), dripPerTick: Number(tierDrip) }],
    });
  };

  const fid = (name: string) => `pcs-event-${criterionId}-${name}`;
  return (
    <form className="form-stack" onSubmit={submit} aria-label="Add an event" noValidate>
      <FormField
        id={fid("id")}
        label="Event name"
        hint="It is the anonymity set for every token spent under it, so name something people attend — never one desk or one shift."
        error={id ? problems.id : undefined}
      >
        <input id={fid("id")} type="text" value={id} placeholder="summit-2026" onChange={(e) => setId(e.target.value)} />
      </FormField>
      <FormField id={fid("start")} label="First day" error={start && end ? problems.dates : undefined}>
        <input id={fid("start")} type="date" value={start} onChange={(e) => setStart(e.target.value)} />
      </FormField>
      <FormField id={fid("end")} label="Last day">
        <input id={fid("end")} type="date" value={end} onChange={(e) => setEnd(e.target.value)} />
      </FormField>
      <FormField
        id={fid("grace")}
        label="Grace days"
        hint="How long after the last day tokens drawn at the event still count."
        error={problems.grace}
      >
        <input id={fid("grace")} type="text" inputMode="numeric" value={grace} onChange={(e) => setGrace(e.target.value)} />
      </FormField>
      <FormField
        id={fid("floor")}
        label="Vetters needed before it opens"
        hint="The smallest group whose spends still hide which vetter made them."
        error={problems.floor}
      >
        <input id={fid("floor")} type="text" inputMode="numeric" value={floor} onChange={(e) => setFloor(e.target.value)} />
      </FormField>
      <FormField id={fid("tier")} label="Tier name" error={problems.tier}>
        <input id={fid("tier")} type="text" value={tierName} onChange={(e) => setTierName(e.target.value)} />
      </FormField>
      <FormField id={fid("tier-drip")} label="Tier rate (tokens per tick)">
        <input id={fid("tier-drip")} type="text" inputMode="numeric" value={tierDrip} onChange={(e) => setTierDrip(e.target.value)} />
      </FormField>
      <div className="form-actions">
        <button type="submit" className="primary" disabled={busy || !ok}>
          Add event
        </button>
        <button type="button" className="secondary" disabled={busy} onClick={onCancel}>
          Cancel
        </button>
      </div>
    </form>
  );
}
