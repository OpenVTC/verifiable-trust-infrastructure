// A community room's owner lifecycle on its page (`CommunityRoomDetail.tsx`):
// archive, unarchive, remove, cancel a removal — `vtc/rooms/community/
// {archive,unarchive,remove}/0.1` and `…/removal/cancel/0.1`
// (`lib/community-rooms-api.ts`, docs/03-vtc/community-rooms.md).
//
// **What each does is said before it is signed** (the archive and remove producer
// items): the access chosen, the open offers withdrawn, what a sealed tier keeps,
// that nothing already read is recalled, and — for a removal — when the content
// is deleted. An immediate removal cannot be undone, so it asks for the room's
// label typed exactly, then the passkey. Outcomes are reported from the answer's
// structured members only.
//
// Cancelling a scheduled removal takes no passkey on the VTC: stopping a mistaken
// removal is never harder than making it.

import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Archive, ArchiveRestore, Trash2, Undo2 } from "lucide-react";

import { useConfirm } from "@/components/ConfirmDialog";
import { Field } from "@/components/Field";
import { NamedDid } from "@/components/NamedDid";
import { TypedConfirmDialog } from "@/components/TypedConfirmDialog";
import {
  ARCHIVE_ACCESS,
  archiveCommunityRoom,
  archivePreview,
  cancelCommunityRoomRemoval,
  daysUntil,
  lifecycleOutcome,
  removalRoomPreview,
  removeCommunityRoom,
  roomStateOf,
  unarchiveCommunityRoom,
  type LifecycleExt,
} from "@/lib/community-rooms-api";
import { formatIso } from "@/lib/format";
import { useNameBook } from "@/lib/names";
import { gestureFromConfirm } from "@/lib/signed-act";
import type { CommunityRoom, CommunityRoomArchiveAccess } from "@/lib/wire-types";

import { RefusalCard } from "./CommunityRefusal";
import { ROOM_STATE_MEANS, RoomStateChip } from "./shared";

/** The query key every community-room read sits under. Duplicated from
 *  `CommunityRooms.tsx` to keep this module free of an import cycle. */
const COMMUNITY_ROOMS_KEY = ["rooms", "community"] as const;

type Mode = null | "archive" | "unarchive" | "remove" | "cancel";

/** The room's state in its owner's lifecycle, and what can be done from it. */
export function RoomLifecycle({
  room,
  lifecycle,
  openOffers,
}: {
  room: CommunityRoom;
  lifecycle: LifecycleExt | null;
  /** Open offers an archival would withdraw. */
  openOffers: number;
}) {
  const nameBook = useNameBook();
  const [mode, setMode] = useState<Mode>(null);
  const [outcome, setOutcome] = useState<string | null>(null);
  const status = room.status;
  const state = roomStateOf(room);
  const purgeIn = daysUntil(status?.purgeAt);

  return (
    <section className="card" aria-labelledby="community-room-lifecycle">
      <div className="rooms-toolbar">
        <h2 id="community-room-lifecycle">Lifecycle</h2>
        {mode === null && (
          <span className="form-actions">
            {state === "active" && (
              <button type="button" className="secondary" onClick={() => setMode("archive")}>
                <Archive size={14} aria-hidden="true" /> Archive…
              </button>
            )}
            {state === "archived" && (
              <>
                <button type="button" className="secondary" onClick={() => setMode("unarchive")}>
                  <ArchiveRestore size={14} aria-hidden="true" /> Unarchive
                </button>
                <button type="button" className="secondary" onClick={() => setMode("archive")}>
                  <Archive size={14} aria-hidden="true" /> Change access…
                </button>
                <button type="button" className="destructive" onClick={() => setMode("remove")}>
                  <Trash2 size={14} aria-hidden="true" /> Remove…
                </button>
              </>
            )}
            {state === "removalScheduled" && (
              <>
                <button type="button" className="secondary" onClick={() => setMode("cancel")}>
                  <Undo2 size={14} aria-hidden="true" /> Cancel removal
                </button>
                <button type="button" className="destructive" onClick={() => setMode("remove")}>
                  <Trash2 size={14} aria-hidden="true" /> Remove now…
                </button>
              </>
            )}
          </span>
        )}
      </div>
      <dl className="rooms-facts">
        <dt>State</dt>
        <dd>
          <RoomStateChip status={status} />
          <div className="muted rooms-sub">{ROOM_STATE_MEANS[state]}</div>
        </dd>
        {status?.changedAt && status.changedBy && (
          <>
            <dt>Since</dt>
            <dd>
              {formatIso(status.changedAt)}, by <NamedDid did={status.changedBy} book={nameBook} />
              <div className="muted rooms-sub">Why is in the audit trail.</div>
            </dd>
          </>
        )}
        {status?.purgeAt && (state === "removalScheduled" || state === "purging" || state === "removed") && (
          <>
            <dt>{state === "removalScheduled" ? "Content deleted" : "Purge was due"}</dt>
            <dd>
              {formatIso(status.purgeAt)}
              {state === "removalScheduled" && purgeIn !== null && purgeIn >= 0 && (
                <div className="rooms-sub">
                  <span className="chip warning">
                    in {purgeIn} day{purgeIn === 1 ? "" : "s"}
                  </span>
                </div>
              )}
            </dd>
          </>
        )}
        {state === "purging" && status?.purge && (
          <>
            <dt>Purge</dt>
            <dd>
              {status.purge.attempts === 0
                ? "Starting."
                : `${status.purge.attempts} pass${status.purge.attempts === 1 ? "" : "es"} so far`}
              {status.purge.nextAttemptAt && ` — next ${formatIso(status.purge.nextAttemptAt)}`}
              {status.purge.lastError && <div className="muted rooms-sub">Last pass: {status.purge.lastError}</div>}
            </dd>
          </>
        )}
        {state === "removed" && status?.removedAt && (
          <>
            <dt>Removed</dt>
            <dd>
              {formatIso(status.removedAt)}
              <div className="muted rooms-sub">
                Its content is gone; this record, and its members&rsquo; records, are kept as its history.
              </div>
            </dd>
          </>
        )}
        {lifecycle?.didRetirement && (
          <>
            <dt>Room DID</dt>
            <dd>{lifecycle.didRetirement}</dd>
          </>
        )}
        {status?.pendingChange && (
          <>
            <dt>Pending change</dt>
            <dd>
              <span className="chip warning">
                to {status.pendingChange.state}
                {status.pendingChange.access ? ` · ${status.pendingChange.access}` : ""}
              </span>{" "}
              since {formatIso(status.pendingChange.beganAt)}
              <div className="muted rooms-sub">
                The room&rsquo;s credentials may already be withdrawn; the community finishes this by
                itself{lifecycle?.pendingChange ? ` (${lifecycle.pendingChange.attempts} attempt(s) so far)` : ""}.
              </div>
              {(status.pendingChange.lastError ?? lifecycle?.pendingChange?.lastError) && (
                <div className="muted rooms-sub">
                  Last attempt: {status.pendingChange.lastError ?? lifecycle?.pendingChange?.lastError}
                </div>
              )}
            </dd>
          </>
        )}
        {(room.suspended ?? 0) > 0 && (
          <>
            <dt>Suspended</dt>
            <dd>
              {room.suspended} member{room.suspended === 1 ? "" : "s"}
              <div className="muted rooms-sub">
                Their credentials were withdrawn when the room was closed. They are restored if it reopens,
                never once it is removed.
              </div>
            </dd>
          </>
        )}
        {status?.restoring && (
          <>
            <dt>Restoring</dt>
            <dd>
              {status.restoring} member{status.restoring === 1 ? "" : "s"} — fresh credentials, kept for each to
              collect as a renewal.
              {lifecycle?.restore?.lastError && (
                <div className="muted rooms-sub">
                  Failing ({lifecycle.restore.attempts}×): {lifecycle.restore.lastError}
                </div>
              )}
            </dd>
          </>
        )}
      </dl>
      {outcome && (
        <p className="success" role="status">
          {outcome}
        </p>
      )}
      {mode === "archive" && (
        <ArchiveForm
          room={room}
          openOffers={openOffers}
          onDone={(o) => {
            setMode(null);
            if (o) setOutcome(o);
          }}
        />
      )}
      {mode === "unarchive" && (
        <ReasonForm
          title="Unarchive this room?"
          what={
            room.status?.access === "noAccess"
              ? "The room accepts writes again. Its suspended members are restored with fresh credentials, each kept for them to collect as a renewal; an admission that expired while it was closed is not. Offers withdrawn when it was archived are not restored — make them again."
              : "The room accepts writes again and can admit members. Offers withdrawn when it was archived are not restored — make them again."
          }
          button="Unarchive"
          run={(reason, gesture) => unarchiveCommunityRoom({ roomId: room.room.roomId, reason }, gesture)}
          onDone={(o) => {
            setMode(null);
            if (o) setOutcome(o);
          }}
        />
      )}
      {mode === "cancel" && (
        <ReasonForm
          title="Cancel this removal?"
          what="The purge is called off. The room stays archived with no access; its members stay suspended until it is unarchived."
          button="Cancel removal"
          run={(reason, gesture) => cancelCommunityRoomRemoval({ roomId: room.room.roomId, reason }, gesture)}
          onDone={(o) => {
            setMode(null);
            if (o) setOutcome(o);
          }}
        />
      )}
      {mode === "remove" && (
        <RemoveForm
          room={room}
          onDone={(o) => {
            setMode(null);
            if (o) setOutcome(o);
          }}
        />
      )}
    </section>
  );
}

function useChanged() {
  const queryClient = useQueryClient();
  return () => void queryClient.invalidateQueries({ queryKey: COMMUNITY_ROOMS_KEY });
}

function ArchiveForm({
  room,
  openOffers,
  onDone,
}: {
  room: CommunityRoom;
  openOffers: number;
  onDone: (outcome: string | null) => void;
}) {
  const confirm = useConfirm();
  const changed = useChanged();
  const current = room.status?.state === "archived" ? room.status.access : undefined;
  const [access, setAccess] = useState<CommunityRoomArchiveAccess>(
    current === "readOnly" ? "noAccess" : current === "noAccess" ? "readOnly" : "readOnly",
  );
  const [reason, setReason] = useState("");
  const ready = reason.trim() !== "" && access !== current;
  const run = useMutation({
    mutationFn: () =>
      archiveCommunityRoom({ roomId: room.room.roomId, access, reason: reason.trim() }, gestureFromConfirm(confirm)),
    onSuccess: (r) => {
      changed();
      onDone(lifecycleOutcome(r));
    },
  });
  return (
    <section className="card" aria-labelledby="archive-community-room">
      <h3 id="archive-community-room">{current ? "Change the archive's access" : "Archive this room"}</h3>
      <form
        className="form-stack"
        onSubmit={(e) => {
          e.preventDefault();
          if (ready) run.mutate();
        }}
      >
        <fieldset className="choice-group">
          <legend className="field-label">Members may still</legend>
          {ARCHIVE_ACCESS.map((a) => (
            <label key={a.id} className="checkbox">
              <input
                type="radio"
                name="archive-access"
                value={a.id}
                checked={access === a.id}
                disabled={a.id === current}
                onChange={() => setAccess(a.id)}
              />
              <span className="checkbox-text">
                <b>{a.label}</b>
                {a.id === current ? " (now)" : ""}
                <span className="choice-hint">{a.hint}</span>
              </span>
            </label>
          ))}
        </fieldset>
        <p className="list-note" role="note">
          {archivePreview(room.room.visibility, access, current ? 0 : openOffers)}
        </p>
        <Field label="Reason" hint="Recorded in the audit trail.">
          <input required maxLength={500} value={reason} onChange={(e) => setReason(e.target.value)} />
        </Field>
        <div className="form-actions">
          <button type="submit" className="primary" disabled={!ready || run.isPending}>
            {run.isPending ? "Archiving…" : current ? "Change access" : "Archive"}
          </button>
          <button type="button" className="secondary" onClick={() => onDone(null)}>
            Cancel
          </button>
        </div>
      </form>
      <RefusalCard title="Not archived" error={run.error} />
    </section>
  );
}

function ReasonForm({
  title,
  what,
  button,
  run,
  onDone,
}: {
  title: string;
  what: string;
  button: string;
  run: (
    reason: string,
    gesture: ReturnType<typeof gestureFromConfirm>,
  ) => Promise<Parameters<typeof lifecycleOutcome>[0]>;
  onDone: (outcome: string | null) => void;
}) {
  const confirm = useConfirm();
  const changed = useChanged();
  const [reason, setReason] = useState("");
  const m = useMutation({
    mutationFn: () => run(reason.trim(), gestureFromConfirm(confirm)),
    onSuccess: (r) => {
      changed();
      onDone(lifecycleOutcome(r));
    },
  });
  return (
    <section className="card">
      <h3>{title}</h3>
      <p className="list-note" role="note">
        {what}
      </p>
      <form
        className="form-stack"
        onSubmit={(e) => {
          e.preventDefault();
          if (reason.trim() !== "") m.mutate();
        }}
      >
        <Field label="Reason" hint="Recorded in the audit trail.">
          <input required maxLength={500} value={reason} onChange={(e) => setReason(e.target.value)} />
        </Field>
        <div className="form-actions">
          <button type="submit" className="primary" disabled={reason.trim() === "" || m.isPending}>
            {m.isPending ? "Working…" : button}
          </button>
          <button type="button" className="secondary" onClick={() => onDone(null)}>
            Back
          </button>
        </div>
      </form>
      <RefusalCard title="Not done" error={m.error} />
    </section>
  );
}

function RemoveForm({ room, onDone }: { room: CommunityRoom; onDone: (outcome: string | null) => void }) {
  const confirm = useConfirm();
  const changed = useChanged();
  const scheduled = room.status?.state === "removalScheduled";
  const [now, setNow] = useState(scheduled);
  const [days, setDays] = useState("");
  const [reason, setReason] = useState("");
  const [asking, setAsking] = useState(false);
  const n = days.trim() === "" ? null : Number(days);
  const daysValid = n === null || (Number.isInteger(n) && n >= 0 && n <= 365);
  const graceDays = now ? 0 : n;
  const ready = reason.trim() !== "" && daysValid;
  const run = useMutation({
    mutationFn: () =>
      removeCommunityRoom(
        {
          roomId: room.room.roomId,
          reason: reason.trim(),
          ...(graceDays !== null ? { graceDays } : {}),
        },
        gestureFromConfirm(confirm),
      ),
    onSuccess: (r) => {
      changed();
      onDone(lifecycleOutcome(r));
    },
  });
  return (
    <section className="card" aria-labelledby="remove-community-room">
      <h3 id="remove-community-room">{scheduled ? "Remove this room now" : "Remove this room"}</h3>
      <form
        className="form-stack"
        onSubmit={(e) => {
          e.preventDefault();
          if (ready) setAsking(true);
        }}
      >
        {!scheduled && (
          <>
            <Field
              label="Grace period (days)"
              hint="Empty: the community default (30 days unless configured). During it the removal can be cancelled."
              error={daysValid ? undefined : "A whole number of days, 0 to 365."}
            >
              <input
                inputMode="numeric"
                placeholder="community default"
                disabled={now}
                value={days}
                onChange={(e) => setDays(e.target.value)}
              />
            </Field>
            <label className="checkbox">
              <input type="checkbox" checked={now} onChange={(e) => setNow(e.target.checked)} />
              <span className="checkbox-text">
                Remove now — delete the content at once. <b>This cannot be undone.</b>
              </span>
            </label>
          </>
        )}
        <p className="list-note" role="note">
          {removalRoomPreview(graceDays === 0, graceDays)}
        </p>
        <Field label="Reason" hint="Recorded in the audit trail.">
          <input required maxLength={500} value={reason} onChange={(e) => setReason(e.target.value)} />
        </Field>
        <div className="form-actions">
          <button type="submit" className="destructive" disabled={!ready || run.isPending}>
            {run.isPending ? "Removing…" : graceDays === 0 ? "Remove now…" : "Remove…"}
          </button>
          <button type="button" className="secondary" onClick={() => onDone(null)}>
            Back
          </button>
        </div>
      </form>
      {asking && (
        <TypedConfirmDialog
          title={graceDays === 0 ? "Delete this room's content now?" : "Schedule this room's removal?"}
          message={removalRoomPreview(graceDays === 0, graceDays)}
          prompt={`Type the room's label — ${room.label} — to confirm`}
          matches={(typed) => typed === room.label}
          confirmLabel={graceDays === 0 ? "Remove now" : "Remove"}
          busy={run.isPending}
          onCancel={() => setAsking(false)}
          onConfirm={() => {
            setAsking(false);
            run.mutate();
          }}
        />
      )}
      <RefusalCard title="Not removed" error={run.error} />
    </section>
  );
}
