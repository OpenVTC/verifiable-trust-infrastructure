// One hosted room, as its host holds it (docs/05-design-notes/data-rooms-files.md
// §8.1 "Room detail") — `vtc/rooms/get/0.1`, per-member usage and daily
// activity from `vtc/rooms/usage/0.1`, and limit overrides through
// `vtc/rooms/limits/set/0.1`.
//
// Everything here is about hosting. The host holds sizes, counts and dates; on
// an `attributed` room, also which member added what, and that is said in words
// beside every figure that shows it, because it is the tier's actual privacy
// property. It holds no record title, file name or file contents, so there is
// no download button and nothing that implies one.

import { useMemo, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useLivePollMs } from "@/lib/use-live-events";

import { useConfirm } from "@/components/ConfirmDialog";
import { CopyButton } from "@/components/CopyButton";
import { DataTable } from "@/components/DataTable";
import { NamedDid } from "@/components/NamedDid";
import { ErrorOrParked } from "@/components/ParkedNotice";
import { PageHeader } from "@/components/PageHeader";
import { Tabs } from "@/components/Tabs";
import type { ApiError } from "@/lib/api";
import { formatEpoch, formatIso, shorten } from "@/lib/format";
import { useNameBook } from "@/lib/names";
import {
  MEMBER_USAGE_UNAVAILABLE,
  fetchRoom,
  fetchUsage,
  fillDays,
  formatBytes,
  fullness,
  rangeEnding,
  setRoomLimits,
  thresholdOf,
} from "@/lib/rooms-api";
import { parkedOf } from "@/lib/parked-action";
import { gestureFromConfirm } from "@/lib/signed-act";
import { assignRoomStorage, fetchStorageConfigs } from "@/lib/storage-api";
import { useToast } from "@/lib/toast";
import type {
  RoomGetResponse,
  RoomLimitSource,
  RoomLimitTarget,
  RoomScopeLimits,
  RoomUsageNow,
} from "@/lib/wire-types";

import { RefusalCard } from "./CommunityRefusal";
import { DayChart, type DayMetric } from "./DayChart";
import { LimitsForm } from "./LimitsForm";
import { LifecyclePill, TIER_BLURB, communityRoomPath, configPath, type Tier } from "./shared";
import { CommunityRoomBadge, MEMBER_NAMED_NOTE, useRoomNames, type RoomName } from "./useRoomNames";

export function RoomDetail() {
  // Already decoded by the router. Decoding again would turn a `did:web` port's
  // `%3A` into `:` and ask for a different room.
  const { roomId = "" } = useParams();
  const pollMs = useLivePollMs("rooms");
  const roomQuery = useQuery({
    queryKey: ["rooms", "get", roomId],
    queryFn: () => fetchRoom(roomId),
    enabled: roomId !== "",
    refetchInterval: pollMs,
  });
  // The label of a room the community owns, for a viewer who may read the
  // community's rooms; the DID otherwise. A refused or failed read of the
  // community's list leaves this page as it was (`useRoomNames`).
  const name = useRoomNames()(roomId);
  const title = name.kind === "community" ? name.label : "Room";
  const trail = [{ label: name.kind === "community" ? name.label : shorten(roomId) }];

  if (roomQuery.isPending) {
    return (
      <section className="page">
        <PageHeader title={title} trail={trail} />
        <section className="card">
          <p>Loading the room…</p>
        </section>
      </section>
    );
  }
  if (roomQuery.isError) {
    const notFound = (roomQuery.error as unknown as ApiError | null)?.code === "vtc/rooms/get:notFound";
    return (
      <section className="page">
        <PageHeader title={title} trail={trail} />
        <section className="card">
          <p className="muted">
            {notFound
              ? "This community hosts no room with that identifier."
              : "The room could not be read. This is a failure to ask, not a missing room."}
          </p>
        </section>
      </section>
    );
  }
  const data = roomQuery.data;
  return (
    <section className="page">
      <PageHeader
        title={title}
        actions={name.kind === "community" ? <CommunityRoomBadge roomId={roomId} /> : undefined}
        trail={trail}
        lead="What this community stores for one room: sizes, counts and dates. It cannot read the room's records or file names, so neither appears here."
      />
      <Identity data={data} name={name} />
      <Storage data={data} />
      <Limits data={data} />
      {data.room.visibility !== "private" && <MembersUsage data={data} />}
      <Activity data={data} />
    </section>
  );
}

function Identity({ data, name }: { data: RoomGetResponse; name: RoomName }) {
  const book = useNameBook();
  const r = data.room;
  return (
    <section className="card">
      <h2>Room</h2>
      <dl className="rooms-facts">
        {/* Unknown (a viewer who may not read the community's rooms): no row,
            as before — the identifier below is all there is to show. */}
        {name.kind !== "unknown" && (
          <>
            <dt>Name</dt>
            <dd>
              {name.kind === "community" ? (
                <>
                  {name.label}
                  <div className="muted rooms-sub">
                    This community owns the room;{" "}
                    <Link to={communityRoomPath(r.roomId)}>run it from Community rooms</Link>.
                  </div>
                </>
              ) : (
                <span className="muted">{MEMBER_NAMED_NOTE}</span>
              )}
            </dd>
          </>
        )}
        <dt>Identifier</dt>
        <dd>
          <code className="rooms-id">{r.roomId}</code> <CopyButton value={r.roomId} />
        </dd>
        <dt>Owner</dt>
        <dd>
          <NamedDid did={r.ownerDid} book={book} />
        </dd>
        <dt>Tier</dt>
        <dd>
          {r.visibility}
          <div className="muted rooms-sub">{TIER_BLURB[r.visibility as Tier]}</div>
        </dd>
        <dt>Lifecycle</dt>
        <dd>
          <LifecyclePill value={r.lifecycle} /> epoch {r.epoch}
          {r.epochExpiresAt ? `, expires ${formatEpoch(r.epochExpiresAt)}` : ""}
        </dd>
        <dt>Retention</dt>
        <dd>
          {r.retentionDays} days, {r.retentionPolicy === "chained" ? "history kept" : "from join"}
        </dd>
        <dt>Created</dt>
        <dd>{formatEpoch(r.createdAt)}</dd>
        {r.mirrorOf && (
          <>
            <dt>Copy of</dt>
            <dd>
              <code title={r.mirrorOf}>{shorten(r.mirrorOf)}</code> (read-only)
            </dd>
          </>
        )}
      </dl>
    </section>
  );
}

function Storage({ data }: { data: RoomGetResponse }) {
  const { storage, usage, largestBlobs } = data;
  const orphans = usage.orphans;
  return (
    <section className="card">
      <h2>Storage</h2>
      <dl className="rooms-facts">
        <dt>New uploads go to</dt>
        <dd>
          <Link to={configPath(storage.configId)}>
            <code>{storage.configId}</code>
          </Link>
        </dd>
        <dt>Held</dt>
        <dd>
          {usage.room.files} {usage.room.files === 1 ? "file" : "files"},{" "}
          {formatBytes(usage.room.bytes)}
          {usage.room.reservedBytes > 0 && (
            <span className="muted"> · {formatBytes(usage.room.reservedBytes)} being uploaded</span>
          )}
        </dd>
        <dt>Awaiting deletion</dt>
        <dd>
          {orphans.files === 0
            ? "nothing"
            : `${orphans.files} ${orphans.files === 1 ? "file" : "files"}, ${formatBytes(orphans.bytes)}`}
          {orphans.oldestOrphanedAt && (
            <span className="muted"> · oldest since {formatIso(orphans.oldestOrphanedAt)}</span>
          )}
          <div className="muted rooms-sub">
            Files no record names any more. They stopped counting against the room's
            limits when they were dropped, and are deleted after the grace window.
          </div>
        </dd>
      </dl>

      {storage.earlierConfigs.length > 0 && (
        <>
          <h3>Still on earlier storage</h3>
          <p className="muted">
            Files uploaded before the room was moved stay where they were and keep
            working; each one remembers its own storage.
          </p>
          <DataTable
            columns={[
              { key: "config", label: "Storage" },
              { key: "files", label: "Files" },
              { key: "bytes", label: "Size" },
            ]}
          >
            {storage.earlierConfigs.map((c) => (
              <tr key={c.configId}>
                <td>
                  <code>{c.configId}</code>
                </td>
                <td>{c.files}</td>
                <td>{formatBytes(c.bytes)}</td>
              </tr>
            ))}
          </DataTable>
        </>
      )}

      <MoveStorage roomId={data.room.roomId} current={storage.configId} />

      {storage.migration && (
        <p className="muted">
          Moving files: {storage.migration.state}, {storage.migration.doneFiles} of{" "}
          {storage.migration.totalFiles} files ({formatBytes(storage.migration.doneBytes)} of{" "}
          {formatBytes(storage.migration.totalBytes)}).
        </p>
      )}

      {largestBlobs && largestBlobs.length > 0 && (
        <>
          <h3>Largest files</h3>
          <p className="muted">By size only: this host does not know what they are called.</p>
          <DataTable
            columns={[
              { key: "size", label: "Size" },
              { key: "config", label: "Storage" },
              { key: "created", label: "Added" },
            ]}
          >
            {largestBlobs.map((b, i) => (
              <tr key={i}>
                <td>{formatBytes(b.size)}</td>
                <td>
                  <code>{b.configId}</code>
                </td>
                <td>{formatIso(b.createdAt)}</td>
              </tr>
            ))}
          </DataTable>
        </>
      )}
    </section>
  );
}

const SOURCE_SAYS: Record<RoomLimitSource, string> = {
  default: "community default",
  policy: "from the rooms policy",
  override: "override",
};

function describeLimits(l: RoomScopeLimits | undefined): string {
  const parts = [
    l?.maxFiles !== undefined ? `${l.maxFiles} files` : null,
    l?.maxBytes !== undefined ? formatBytes(l.maxBytes) : null,
    l?.maxFileBytes !== undefined ? `${formatBytes(l.maxFileBytes)} per file` : null,
  ].filter(Boolean);
  return parts.length ? parts.join(" · ") : "no limit";
}

function UsageAgainst({ usage, limits }: { usage: RoomUsageNow; limits?: RoomScopeLimits }) {
  const f = fullness(usage, limits);
  const band = thresholdOf(f);
  if (f === null) return null;
  return (
    <span className={`chip ${band === 100 ? "danger" : band ? "warning" : "success"}`}>
      {Math.round(f * 100)}% used
    </span>
  );
}

function Limits({ data }: { data: RoomGetResponse }) {
  const [editing, setEditing] = useState<"room" | "memberDefault" | null>(null);
  const { limits } = data.limits;
  const target = (kind: "room" | "memberDefault"): RoomLimitTarget => ({ kind });
  return (
    <section className="card">
      <h2>Limits</h2>
      <p className="muted">
        What the room is held to now. An override replaces the default for this room
        only. Lowering a limit deletes nothing: a room already over it keeps every
        file, and only new uploads are refused.
        {data.limits.hostCeilingBytes !== undefined &&
          ` No file anywhere on this host may exceed ${formatBytes(data.limits.hostCeilingBytes)}.`}
      </p>
      <FilesSwitch data={data} />
      <DataTable
        columns={[
          { key: "scope", label: "Scope" },
          { key: "limits", label: "Limits" },
          { key: "from", label: "From" },
          { key: "use", label: "Use" },
          { key: "act", label: "" },
        ]}
      >
        <tr>
          <td>The room</td>
          <td>{describeLimits(limits.room)}</td>
          <td>{SOURCE_SAYS[data.limits.roomSource]}</td>
          <td>
            <UsageAgainst usage={data.usage.room} limits={limits.room} />
          </td>
          <td>
            <button type="button" className="secondary" onClick={() => setEditing("room")}>
              Change
            </button>
          </td>
        </tr>
        <tr>
          <td>Each member</td>
          <td>{describeLimits(limits.member)}</td>
          <td>{SOURCE_SAYS[data.limits.memberSource]}</td>
          <td className="muted">per member, below</td>
          <td>
            <button
              type="button"
              className="secondary"
              onClick={() => setEditing("memberDefault")}
            >
              Change
            </button>
          </td>
        </tr>
      </DataTable>
      {editing && (
        <div className="rooms-edit">
          <h3>{editing === "room" ? "The room's limits" : "Each member's limits, by default"}</h3>
          <LimitsForm
            key={editing}
            roomId={data.room.roomId}
            target={target(editing)}
            current={editing === "room" ? limits.room : limits.member}
            hostCeilingBytes={data.limits.hostCeilingBytes}
            onDone={() => setEditing(null)}
          />
        </div>
      )}
    </section>
  );
}

/** Pause or resume new uploads to the room: `filesEnabled` alone, which leaves
 *  every limit as it is. Reads of files already stored continue either way. */
function FilesSwitch({ data }: { data: RoomGetResponse }) {
  const toast = useToast();
  const queryClient = useQueryClient();
  const [reason, setReason] = useState("");
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const enabled = data.limits.limits.filesEnabled;

  async function flip() {
    setBusy(true);
    try {
      await setRoomLimits({
        roomId: data.room.roomId,
        target: { kind: "room" },
        filesEnabled: !enabled,
        reason: reason.trim(),
      });
      toast.push("success", enabled ? "New uploads paused." : "Uploads allowed again.");
      await queryClient.invalidateQueries({ queryKey: ["rooms"] });
      setOpen(false);
      setReason("");
    } catch (err) {
      toast.pushFromError(err, "Could not change uploads");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="rooms-files-switch">
      <p>
        <span className={`chip ${enabled ? "success" : "warning"}`}>
          {enabled ? "uploads allowed" : "uploads paused"}
        </span>{" "}
        {!open && (
          <button type="button" className="link" onClick={() => setOpen(true)}>
            {enabled ? "Pause new uploads" : "Allow uploads"}
          </button>
        )}
      </p>
      {open && (
        <div className="rooms-edit">
          <p className="muted">
            {enabled
              ? "Members will not be able to add files to this room. Files already stored stay readable."
              : "Members will be able to add files again, within the limits below."}
          </p>
          <label className="field">
            <span className="field-label">Reason</span>
            <textarea rows={2} value={reason} onChange={(e) => setReason(e.target.value)} />
          </label>
          <div className="rooms-form-actions">
            <button
              type="button"
              onClick={flip}
              disabled={busy || reason.trim() === "" || reason.trim().length > 500}
            >
              {enabled ? "Pause uploads" : "Allow uploads"}
            </button>
            <button type="button" className="secondary" onClick={() => setOpen(false)}>
              Cancel
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

/** One row per member who has added files: not a roster — a member who has
 *  added nothing does not appear, because the host has never seen them. */
function MembersUsage({ data }: { data: RoomGetResponse }) {
  const book = useNameBook();
  const roomId = data.room.roomId;
  const [editing, setEditing] = useState<string | null>(null);
  const q = useQuery({
    queryKey: ["room-usage", "members", roomId],
    queryFn: () =>
      fetchUsage({
        groupBy: "member",
        filter: { roomId },
        sort: { by: "bytes", order: "desc" },
      }),
  });
  const unavailable = (q.error as unknown as ApiError | null)?.code === MEMBER_USAGE_UNAVAILABLE;
  const editingRow = q.data?.items.find((r) => r.member === editing);

  return (
    <section className="card">
      <h2>Members' usage</h2>
      <p className="muted">
        This host sees which member added each file to a{" "}
        {data.room.visibility} room, so it can show who uses how much. That is
        the tier's privacy property, not a leak. It never sees what the files are.
        Members who have added nothing are not listed: this is not a membership roster.
      </p>
      {q.isPending && <p>Reading members' usage…</p>}
      {q.isError &&
        (unavailable ? (
          <p className="muted">This host keeps no per-member figures for this room.</p>
        ) : (
          <RefusalCard title="Members' usage could not be read" error={q.error} />
        ))}
      {q.data && q.data.items.length === 0 && <p className="muted">No member has added a file.</p>}
      {q.data && q.data.items.length > 0 && (
        <DataTable
          columns={[
            { key: "member", label: "Member" },
            { key: "files", label: "Files" },
            { key: "bytes", label: "Size" },
            { key: "limits", label: "Their limits" },
            { key: "act", label: "" },
          ]}
        >
          {q.data.items.map((r) => (
            <tr key={r.member}>
              <td>{r.member && <NamedDid did={r.member} book={book} />}</td>
              <td>{r.files}</td>
              <td>{formatBytes(r.bytes)}</td>
              <td>
                {describeLimits(r.limits)} <UsageAgainst usage={r} limits={r.limits} />
              </td>
              <td>
                <button type="button" className="secondary" onClick={() => setEditing(r.member!)}>
                  Override
                </button>
              </td>
            </tr>
          ))}
        </DataTable>
      )}
      {q.data?.truncated && (
        <p className="muted">Only the largest {q.data.items.length} members are shown.</p>
      )}
      {editing && (
        <div className="rooms-edit">
          <h3>
            Limits for <NamedDid did={editing} book={book} />
          </h3>
          <LimitsForm
            key={editing}
            roomId={roomId}
            target={{ kind: "member", member: editing }}
            current={editingRow?.limits}
            hostCeilingBytes={data.limits.hostCeilingBytes}
            onDone={() => setEditing(null)}
          />
        </div>
      )}
    </section>
  );
}

const RANGES = [
  { id: "30", label: "30 days" },
  { id: "90", label: "90 days" },
  { id: "365", label: "365 days" },
] as const;
type RangeId = (typeof RANGES)[number]["id"];

const METRICS: { id: DayMetric; label: string; bytes: boolean; what: string }[] = [
  { id: "bytes", label: "Space", bytes: true, what: "Space held at the end of each day" },
  { id: "uploads", label: "Uploads", bytes: false, what: "Uploads per day" },
  { id: "downloads", label: "Downloads", bytes: false, what: "Downloads begun per day" },
  { id: "egressBytes", label: "Egress", bytes: true, what: "Bytes served per day" },
];

function Activity({ data }: { data: RoomGetResponse }) {
  const roomId = data.room.roomId;
  const [range, setRange] = useState<RangeId>("30");
  const [metric, setMetric] = useState<DayMetric>("bytes");
  const { from, to } = useMemo(() => rangeEnding(Number(range)), [range]);
  const q = useQuery({
    queryKey: ["room-usage", "days", roomId, from, to],
    queryFn: () => fetchUsage({ groupBy: "day", filter: { roomId, from, to } }),
  });
  const m = METRICS.find((x) => x.id === metric)!;
  const days = useMemo(
    () => (q.data ? fillDays(q.data.items, q.data.from, q.data.to) : []),
    [q.data],
  );
  const totals = useMemo(
    () =>
      (q.data?.items ?? []).reduce(
        (t, r) => ({
          uploads: t.uploads + r.uploads,
          downloads: t.downloads + r.downloads,
          egressBytes: t.egressBytes + r.egressBytes,
        }),
        { uploads: 0, downloads: 0, egressBytes: 0 },
      ),
    [q.data],
  );

  return (
    <section className="card">
      <h2>Activity</h2>
      <p className="muted">
        Counted by this host as files arrive and leave.
        {data.room.visibility === "attributed" &&
          " On an attributed room the host also knows which member did each, which is what the members' figures above are built from."}
      </p>
      <div className="rooms-toolbar">
        <Tabs
          variant="segmented"
          label="Range"
          items={RANGES}
          value={range}
          onChange={setRange}
        />
        <Tabs
          variant="segmented"
          label="Figure"
          items={METRICS.map((x) => ({ id: x.id, label: x.label }))}
          value={metric}
          onChange={setMetric}
        />
      </div>
      {q.isPending && <p>Reading activity…</p>}
      {q.isError && <RefusalCard title="Activity could not be read" error={q.error} />}
      {q.data && (
        <>
          <DayChart
            days={days}
            metric={metric}
            format={m.bytes ? formatBytes : String}
            label={m.what}
          />
          <p className="muted rooms-sub">
            Over the range: {totals.uploads} uploads, {totals.downloads} downloads,{" "}
            {formatBytes(totals.egressBytes)} served.
          </p>
        </>
      )}
    </section>
  );
}

/**
 * Point the room's new uploads at another storage location
 * (`vtc/rooms/storage/assign/0.1`). Its existing files stay where they are and
 * keep working, since each remembers its own location. Decides where members'
 * files go, so it takes the requester's passkey and is parked for another
 * holder of the room-hosting capability (§7.4).
 */
function MoveStorage({ roomId, current }: { roomId: string; current: string }) {
  const [open, setOpen] = useState(false);
  const [target, setTarget] = useState("");
  const [reason, setReason] = useState("");
  const confirm = useConfirm();
  const toast = useToast();
  const queryClient = useQueryClient();
  const configs = useQuery({
    queryKey: ["storage", "list"],
    queryFn: fetchStorageConfigs,
    enabled: open,
  });
  const choices = (configs.data ?? []).filter(
    (c) => c.config.state === "active" && c.config.id !== current,
  );
  const move = useMutation({
    mutationFn: () => assignRoomStorage(roomId, target, reason.trim(), gestureFromConfirm(confirm)),
    onSuccess: () => {
      toast.push("success", "New uploads now go to " + target + ".");
      void queryClient.invalidateQueries({ queryKey: ["rooms"] });
      void queryClient.invalidateQueries({ queryKey: ["storage"] });
      setOpen(false);
    },
  });
  if (parkedOf(move.error)) return <ErrorOrParked title="Not moved" error={move.error} />;
  if (!open) {
    return (
      <p>
        <button type="button" className="link" onClick={() => setOpen(true)}>
          Send new uploads to other storage
        </button>
      </p>
    );
  }
  return (
    <div className="rooms-edit">
      <h3>Send new uploads to other storage</h3>
      <p className="muted">
        Files already stored stay where they are and keep working. This needs your
        passkey, then another holder of the room-hosting capability to approve it
        (unless this community runs with a single administrator).
      </p>
      {configs.isPending && <p>Reading storage…</p>}
      {configs.data && choices.length === 0 && (
        <p className="muted">There is no other active storage location to move to.</p>
      )}
      {choices.length > 0 && (
        <>
          <label className="field">
            <span className="field-label">Storage</span>
            <select value={target} onChange={(e) => setTarget(e.target.value)}>
              <option value="">Choose…</option>
              {choices.map((c) => (
                <option key={c.config.id} value={c.config.id}>
                  {c.config.id} — {c.config.label}
                </option>
              ))}
            </select>
          </label>
          <label className="field">
            <span className="field-label">Reason</span>
            <textarea rows={2} value={reason} onChange={(e) => setReason(e.target.value)} />
          </label>
        </>
      )}
      <div className="rooms-form-actions">
        <button
          type="button"
          onClick={() => move.mutate()}
          disabled={
            move.isPending || target === "" || reason.trim() === "" || reason.trim().length > 500
          }
        >
          Send for approval
        </button>
        <button type="button" className="secondary" onClick={() => setOpen(false)}>
          Cancel
        </button>
      </div>
      <ErrorOrParked title="Not moved" error={move.error} />
    </div>
  );
}
