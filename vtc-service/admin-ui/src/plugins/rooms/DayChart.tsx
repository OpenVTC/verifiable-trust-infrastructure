// One figure across a range of days, as bars — the console has no chart
// library, and a bar per day is all §8.1's activity and growth views need.
//
// The axis is time, not row order: `fillDays` gives every day in the range, a
// day without a row drawn as an empty slot. Each bar carries its day and value
// as a `<title>`, and the figure as a whole is described in words for a screen
// reader, which has no use for 365 rectangles.

import { useMemo } from "react";

import type { RoomsUsageRow } from "@/lib/wire-types";

export type DayMetric = "bytes" | "files" | "uploads" | "downloads" | "egressBytes";

const WIDTH = 720;
const HEIGHT = 140;
const GAP = 1;

export function DayChart({
  days,
  metric,
  format,
  label,
}: {
  days: readonly { date: string; row: RoomsUsageRow | null }[];
  metric: DayMetric;
  /** How a value reads ("1.2 GB", "14"). */
  format: (n: number) => string;
  /** What the chart shows, for its accessible name ("Bytes held per day"). */
  label: string;
}) {
  const { values, max, peak } = useMemo(() => {
    const values = days.map((d) => d.row?.[metric] ?? 0);
    const max = Math.max(0, ...values);
    const peakAt = values.indexOf(max);
    return { values, max, peak: peakAt >= 0 ? days[peakAt]?.date : undefined };
  }, [days, metric]);

  if (days.length === 0) return null;
  const slot = WIDTH / days.length;
  const bar = Math.max(1, slot - GAP);
  const first = days[0]!.date;
  const last = days[days.length - 1]!.date;
  const summary =
    max === 0
      ? `${label}: none from ${first} to ${last}.`
      : `${label} from ${first} to ${last}. Highest ${format(max)} on ${peak}; latest ${format(values[values.length - 1]!)}.`;

  return (
    <figure className="rooms-chart">
      <svg
        viewBox={`0 0 ${WIDTH} ${HEIGHT}`}
        preserveAspectRatio="none"
        role="img"
        aria-label={summary}
      >
        <line className="rooms-chart-axis" x1={0} y1={HEIGHT - 0.5} x2={WIDTH} y2={HEIGHT - 0.5} />
        {values.map((v, i) => {
          const h = max === 0 ? 0 : Math.max(v > 0 ? 1 : 0, (v / max) * (HEIGHT - 4));
          return (
            <rect
              key={days[i]!.date}
              className={days[i]!.row ? "rooms-chart-bar" : "rooms-chart-bar empty"}
              x={i * slot}
              y={HEIGHT - h}
              width={bar}
              height={h}
            >
              <title>{`${days[i]!.date}: ${format(v)}`}</title>
            </rect>
          );
        })}
      </svg>
      <figcaption className="muted rooms-sub rooms-chart-caption">
        <span>{first}</span>
        <span>{max === 0 ? "nothing in this range" : `peak ${format(max)}`}</span>
        <span>{last}</span>
      </figcaption>
    </figure>
  );
}
