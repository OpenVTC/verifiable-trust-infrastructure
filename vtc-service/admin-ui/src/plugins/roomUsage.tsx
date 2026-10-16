// Room usage — the Usage tab of the Data rooms page (`dataRooms.tsx`): how much
// this community stores for its rooms, and how much is read back
// (docs/05-design-notes/data-rooms-files.md §6.3, §8.1 "Usage").
//
// One read, `vtc/rooms/usage/0.1`, grouped by room, member, storage config or
// day, over 30, 90 or 365 days; exported as CSV. Egress is shown beside space
// because on S3 reads are what cost money: a room downloaded a thousand times a
// day is a different conversation from one that is merely large.
//
// Per-member figures cover rooms whose host can tell members apart. A private
// room's uploads are not attributed to anyone, by design, so it never appears
// in a member grouping.

import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { useLivePollMs } from "@/lib/use-live-events";
import { Download } from "lucide-react";

import { DataTable } from "@/components/DataTable";
import { NamedDid } from "@/components/NamedDid";
import { Tabs } from "@/components/Tabs";
import { formatIso, shorten } from "@/lib/format";
import { useNameBook } from "@/lib/names";
import {
  fetchUsage,
  fillDays,
  formatBytes,
  fullness,
  rangeEnding,
  thresholdOf,
  usageCsv,
  type Threshold,
  type UsageGroup,
  type UsageSort,
} from "@/lib/rooms-api";
import type { RoomsUsageRow } from "@/lib/wire-types";

import { DayChart, type DayMetric } from "./rooms/DayChart";
import { roomPath } from "./rooms/shared";

const GROUPS: { id: UsageGroup; label: string }[] = [
  { id: "room", label: "Rooms" },
  { id: "member", label: "Members" },
  { id: "storageConfig", label: "Storage" },
  { id: "day", label: "Days" },
];

const RANGES = [
  { id: "30", label: "30 days" },
  { id: "90", label: "90 days" },
  { id: "365", label: "365 days" },
] as const;
type RangeId = (typeof RANGES)[number]["id"];

const SORTS: { id: UsageSort["by"]; label: string }[] = [
  { id: "bytes", label: "Space" },
  { id: "egressBytes", label: "Egress" },
  { id: "uploads", label: "Uploads" },
  { id: "downloads", label: "Downloads" },
  { id: "files", label: "Files" },
];

/** Save `text` as a file named `name`, from this page. */
function saveText(name: string, text: string, type: string) {
  const url = URL.createObjectURL(new Blob([text], { type }));
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  a.click();
  URL.revokeObjectURL(url);
}

/** The Usage tab of the Data rooms page. */
export function RoomUsage() {
  const [group, setGroup] = useState<UsageGroup>("room");
  const [range, setRange] = useState<RangeId>("30");
  const [sortBy, setSortBy] = useState<UsageSort["by"]>("bytes");
  const { from, to } = useMemo(() => rangeEnding(Number(range)), [range]);
  const sort: UsageSort =
    group === "day" ? { by: "date", order: "asc" } : { by: sortBy, order: "desc" };

  const q = useQuery({
    queryKey: ["room-usage", "report", group, from, to, sort.by],
    queryFn: () => fetchUsage({ groupBy: group, filter: { from, to }, sort }),
  });

  return (
    <>

      <NearLimits />

      <section className="card">
        <div className="rooms-toolbar">
          <Tabs label="Group by" items={GROUPS} value={group} onChange={setGroup} />
          <Tabs variant="segmented" label="Range" items={RANGES} value={range} onChange={setRange} />
          {group !== "day" && (
            <label className="field inline">
              <span className="field-label">Sort by</span>
              <select
                value={sortBy}
                onChange={(e) => setSortBy(e.target.value as UsageSort["by"])}
              >
                {SORTS.map((s) => (
                  <option key={s.id} value={s.id}>
                    {s.label}
                  </option>
                ))}
              </select>
            </label>
          )}
          <button
            type="button"
            className="secondary"
            disabled={!q.data || q.data.items.length === 0}
            onClick={() =>
              q.data &&
              saveText(
                `room-usage-${group}-${q.data.from}-${q.data.to}.csv`,
                usageCsv(group, q.data.items),
                "text/csv;charset=utf-8",
              )
            }
          >
            <Download aria-hidden="true" />
            Export CSV
          </button>
        </div>

        {group === "member" && (
          <p className="muted">
            Members' figures cover the rooms whose host can tell members apart. A
            private room's uploads are attributed to nobody, by design, so it is
            not counted here.
          </p>
        )}

        {q.isPending && <p>Reading usage…</p>}
        {q.isError && (
          <p className="muted">Usage could not be read. This is a failure to ask, not a community with none.</p>
        )}
        {q.data && q.data.items.length === 0 && (
          <p className="muted">Nothing stored and nothing read in this range.</p>
        )}
        {q.data && q.data.items.length > 0 && (
          <>
            {group === "day" ? (
              <Days rows={q.data.items} from={q.data.from} to={q.data.to} />
            ) : (
              <Rows group={group} rows={q.data.items} />
            )}
            <p className="muted rooms-sub">
              {q.data.from} to {q.data.to}. Space and files as of {formatIso(q.data.asOf)};
              uploads, downloads and egress over the range.
              {q.data.truncated && ` Only the first ${q.data.items.length} rows are shown and exported.`}
            </p>
          </>
        )}
      </section>
    </>
  );
}

function Rows({ group, rows }: { group: Exclude<UsageGroup, "day">; rows: RoomsUsageRow[] }) {
  const book = useNameBook();
  const keyLabel = group === "room" ? "Room" : group === "member" ? "Member" : "Storage";
  return (
    <DataTable
      columns={[
        { key: "key", label: keyLabel },
        ...(group === "room" ? [{ key: "config", label: "Storage" }] : []),
        { key: "files", label: "Files" },
        { key: "bytes", label: "Space" },
        { key: "full", label: "Of limit" },
        { key: "uploads", label: "Uploads" },
        { key: "downloads", label: "Downloads" },
        { key: "egress", label: "Egress" },
      ]}
    >
      {rows.map((r, i) => {
        const limit =
          group === "storageConfig"
            ? r.capacityBytes !== undefined
              ? { maxBytes: r.capacityBytes }
              : undefined
            : r.limits;
        const f = fullness(r, limit);
        return (
          <tr key={r.roomId ?? r.member ?? r.storageConfig ?? i}>
            <td>
              {group === "room" && r.roomId && (
                <Link to={roomPath(r.roomId)} title={r.roomId}>
                  <code>{shorten(r.roomId)}</code>
                </Link>
              )}
              {group === "member" && r.member && <NamedDid did={r.member} book={book} />}
              {group === "storageConfig" && <code>{r.storageConfig}</code>}
            </td>
            {group === "room" && (
              <td>
                <code>{r.storageConfig}</code>
              </td>
            )}
            <td>{r.files}</td>
            <td>{formatBytes(r.bytes)}</td>
            <td>{f === null ? "—" : <Band fraction={f} />}</td>
            <td>{r.uploads}</td>
            <td>{r.downloads}</td>
            <td>{formatBytes(r.egressBytes)}</td>
          </tr>
        );
      })}
    </DataTable>
  );
}

function Band({ fraction }: { fraction: number }) {
  const band = thresholdOf(fraction);
  return (
    <span className={`chip ${band === 100 ? "danger" : band ? "warning" : "success"}`}>
      {Math.round(fraction * 100)}%
    </span>
  );
}

const DAY_METRICS: { id: DayMetric; label: string; bytes: boolean; what: string }[] = [
  { id: "bytes", label: "Space", bytes: true, what: "Space held at the end of each day" },
  { id: "egressBytes", label: "Egress", bytes: true, what: "Bytes served per day" },
  { id: "uploads", label: "Uploads", bytes: false, what: "Uploads per day" },
  { id: "downloads", label: "Downloads", bytes: false, what: "Downloads begun per day" },
];

function Days({ rows, from, to }: { rows: RoomsUsageRow[]; from: string; to: string }) {
  const [metric, setMetric] = useState<DayMetric>("bytes");
  const days = useMemo(() => fillDays(rows, from, to), [rows, from, to]);
  const m = DAY_METRICS.find((x) => x.id === metric)!;
  return (
    <>
      <Tabs
        variant="segmented"
        label="Figure"
        items={DAY_METRICS.map((x) => ({ id: x.id, label: x.label }))}
        value={metric}
        onChange={setMetric}
      />
      <DayChart days={days} metric={metric} format={m.bytes ? formatBytes : String} label={m.what} />
    </>
  );
}

/**
 * Rooms and storage past 80 %, 95 % or 100 % of a limit, listed first because
 * they are the rows that ask someone to act — and invisible in a long table.
 */
function NearLimits() {
  const { from, to } = useMemo(() => rangeEnding(1), []);
  // A band crossing is what the live `rooms` topic hints about; polled as the
  // fallback.
  const pollMs = useLivePollMs("rooms");
  const rooms = useQuery({
    queryKey: ["room-usage", "near-limits", "room", to],
    queryFn: () =>
      fetchUsage({ groupBy: "room", filter: { from, to }, sort: { by: "bytes", order: "desc" } }),
    refetchInterval: pollMs,
  });
  const configs = useQuery({
    queryKey: ["room-usage", "near-limits", "storageConfig", to],
    queryFn: () => fetchUsage({ groupBy: "storageConfig", filter: { from, to } }),
    refetchInterval: pollMs,
  });
  const flagged = useMemo(() => {
    const out: { kind: "room" | "storage"; id: string; fraction: number; band: Threshold }[] = [];
    for (const r of rooms.data?.items ?? []) {
      const f = fullness(r, r.limits);
      const band = thresholdOf(f);
      if (band && r.roomId) out.push({ kind: "room", id: r.roomId, fraction: f!, band });
    }
    for (const c of configs.data?.items ?? []) {
      if (c.capacityBytes === undefined || !c.storageConfig) continue;
      const f = fullness(c, { maxBytes: c.capacityBytes });
      const band = thresholdOf(f);
      if (band) out.push({ kind: "storage", id: c.storageConfig, fraction: f!, band });
    }
    return out.sort((a, b) => b.fraction - a.fraction);
  }, [rooms.data, configs.data]);

  if (flagged.length === 0) return null;
  return (
    <section className="card">
      <h2>Near a limit</h2>
      <p className="muted">
        Past 80 % of a limit or of a storage location's capacity. At 100 % new uploads
        are refused; nothing already stored is touched.
      </p>
      <ul className="rooms-near-limits">
        {flagged.map((x) => (
          <li key={`${x.kind}:${x.id}`}>
            <Band fraction={x.fraction} />{" "}
            {x.kind === "room" ? (
              <>
                room{" "}
                <Link to={roomPath(x.id)} title={x.id}>
                  <code>{shorten(x.id)}</code>
                </Link>
              </>
            ) : (
              <>
                storage <code>{x.id}</code>
              </>
            )}
          </li>
        ))}
      </ul>
    </section>
  );
}
