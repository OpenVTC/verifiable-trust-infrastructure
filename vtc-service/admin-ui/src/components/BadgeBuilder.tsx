// A badge picture for someone without artwork: a colour, an icon, a shape and,
// on a banner, the badge's name.
//
// The preview is the picture: the same SVG is serialised and drawn onto a
// canvas at the size a picture is sent, and the PNG that comes out goes
// through the ordinary upload (`vtc/badges/images/upload`), where the
// community re-encodes it like any other picture (VTI-BDG-050). Nothing here
// is a new kind of picture, and nothing about how it was made is sent.

import { useEffect, useId, useRef, useState } from "react";
import {
  Award,
  BookOpen,
  Code,
  Coffee,
  HandHeart,
  Heart,
  Lightbulb,
  Megaphone,
  PartyPopper,
  Rocket,
  Sparkles,
  Sprout,
  Star,
  Trophy,
  Users,
  Wrench,
  type LucideIcon,
} from "lucide-react";

import "./BadgeBuilder.css";

/** The colours offered: each carries white at 4.5:1 or better. */
export const BUILDER_COLOURS = [
  { name: "Blue", value: "#1d4ed8" },
  { name: "Teal", value: "#0f766e" },
  { name: "Green", value: "#15803d" },
  { name: "Amber", value: "#b45309" },
  { name: "Red", value: "#b91c1c" },
  { name: "Purple", value: "#7e22ce" },
  { name: "Pink", value: "#be185d" },
  { name: "Slate", value: "#334155" },
] as const;

/** An icon the builder offers, by the name read out for it. */
export interface BuilderIcon {
  name: string;
  Icon: LucideIcon;
}

const FIRST: BuilderIcon = { name: "Award", Icon: Award };

/** The icons offered before anyone searches, by the name read out for each. */
export const BUILDER_ICONS: readonly BuilderIcon[] = [
  FIRST,
  { name: "Star", Icon: Star },
  { name: "Trophy", Icon: Trophy },
  { name: "Heart", Icon: Heart },
  { name: "Helping hand", Icon: HandHeart },
  { name: "Sparkles", Icon: Sparkles },
  { name: "Celebration", Icon: PartyPopper },
  { name: "Rocket", Icon: Rocket },
  { name: "Idea", Icon: Lightbulb },
  { name: "Book", Icon: BookOpen },
  { name: "Code", Icon: Code },
  { name: "Tools", Icon: Wrench },
  { name: "Megaphone", Icon: Megaphone },
  { name: "People", Icon: Users },
  { name: "Sprout", Icon: Sprout },
  { name: "Coffee", Icon: Coffee },
];

/** The most icons a search shows at once. */
export const SEARCH_LIMIT = 60;

/** The name read out for a lucide icon: `BadgeCheck` is "Badge check". */
export function iconLabel(key: string): string {
  const words = key
    .replace(/([a-z0-9])([A-Z])/g, "$1 $2")
    .replace(/([A-Z])([A-Z][a-z])/g, "$1 $2")
    .toLowerCase();
  return words.charAt(0).toUpperCase() + words.slice(1);
}

/**
 * The icons of `all` whose name holds every word of `query`, the offered ones
 * (whose names may differ, "Tools" for the wrench) first, at most `limit`.
 */
export function findIcons(
  all: Record<string, LucideIcon>,
  query: string,
  limit = SEARCH_LIMIT,
): { matches: BuilderIcon[]; total: number } {
  const words = query.toLowerCase().split(/\s+/).filter(Boolean);
  const fits = (name: string) => {
    const n = name.toLowerCase();
    return words.every((w) => n.includes(w));
  };
  const seen = new Set<LucideIcon>();
  const found: BuilderIcon[] = [];
  for (const i of BUILDER_ICONS) {
    if (fits(i.name)) {
      seen.add(i.Icon);
      found.push(i);
    }
  }
  for (const [key, Icon] of Object.entries(all)) {
    const name = iconLabel(key);
    if (!seen.has(Icon) && fits(name)) {
      seen.add(Icon);
      found.push({ name, Icon });
    }
  }
  return { matches: found.slice(0, limit), total: found.length };
}

/** Loads the whole set, once, the first time someone searches. */
let allIcons: Promise<Record<string, LucideIcon>> | null = null;
function loadAllIcons(): Promise<Record<string, LucideIcon>> {
  allIcons ??= import("./badge-icons").then((m) => m.icons as Record<string, LucideIcon>);
  allIcons.catch(() => {
    allIcons = null;
  });
  return allIcons;
}

export type BuilderShape = "square" | "banner";

/** Each shape's drawing box, and the pixel width it is drawn at. */
const SHAPES: Record<BuilderShape, { w: number; h: number; px: number; label: string }> = {
  square: { w: 120, h: 120, px: 512, label: "Square" },
  banner: { w: 300, h: 100, px: 1024, label: "Banner" },
};

/** The longest name a banner shows before it is shortened. */
const BANNER_CHARS = 22;

/** The name a banner shows: trimmed and, past {@link BANNER_CHARS}, cut with an ellipsis. */
export function bannerText(name: string): string {
  const chars = [...name.trim()];
  return chars.length > BANNER_CHARS ? chars.slice(0, BANNER_CHARS - 1).join("").trimEnd() + "…" : chars.join("");
}

/**
 * Draw `svg` onto a canvas `width` pixels wide and answer it as a PNG. The SVG
 * is self-contained (no fonts or images it fetches), so the drawing never
 * taints the canvas.
 */
export async function rasterise(svg: SVGSVGElement, width: number, height: number): Promise<Blob> {
  const source = new XMLSerializer().serializeToString(svg);
  const url = URL.createObjectURL(new Blob([source], { type: "image/svg+xml" }));
  try {
    const img = new Image();
    img.decoding = "sync";
    await new Promise<void>((resolve, reject) => {
      img.onload = () => resolve();
      img.onerror = () => reject(new Error("The picture couldn't be drawn."));
      img.src = url;
    });
    const canvas = document.createElement("canvas");
    canvas.width = width;
    canvas.height = height;
    const ctx = canvas.getContext("2d");
    if (!ctx) throw new Error("This browser can't draw the picture.");
    ctx.drawImage(img, 0, 0, width, height);
    const png = await new Promise<Blob | null>((r) => canvas.toBlob(r, "image/png"));
    if (!png) throw new Error("This browser can't draw the picture.");
    return png;
  } finally {
    URL.revokeObjectURL(url);
  }
}

/** The picture itself, as an SVG the builder both shows and draws. */
function Art({
  shape,
  colour,
  Icon,
  text,
  svgRef,
}: {
  shape: BuilderShape;
  colour: string;
  Icon: LucideIcon;
  text: string;
  svgRef?: React.Ref<SVGSVGElement>;
}) {
  const { w, h } = SHAPES[shape];
  const banner = shape === "banner";
  const icon = banner ? 56 : 72;
  const words = bannerText(text);
  return (
    <svg
      ref={svgRef}
      xmlns="http://www.w3.org/2000/svg"
      viewBox={`0 0 ${w} ${h}`}
      width={w}
      height={h}
      className="badge-builder-art"
      role="img"
      aria-label={banner && words ? `Preview: ${words}` : "Preview"}
    >
      <rect x="0" y="0" width={w} height={h} rx={banner ? 14 : 24} fill={colour} />
      <circle
        cx={banner ? 50 : w / 2}
        cy={h / 2}
        r={banner ? 38 : 48}
        fill="none"
        stroke="#ffffff"
        strokeOpacity="0.35"
        strokeWidth="3"
      />
      <Icon
        x={(banner ? 50 : w / 2) - icon / 2}
        y={h / 2 - icon / 2}
        width={icon}
        height={icon}
        color="#ffffff"
        strokeWidth={1.75}
        aria-hidden="true"
      />
      {banner && words && (
        <text
          x="100"
          y={h / 2}
          dominantBaseline="central"
          fill="#ffffff"
          fontFamily="system-ui, -apple-system, 'Segoe UI', Roboto, sans-serif"
          fontWeight="700"
          fontSize={words.length > 14 ? 17 : 22}
        >
          {words}
        </text>
      )}
    </svg>
  );
}

/**
 * Build a badge picture from a colour, an icon and a shape. `onUse` receives
 * the PNG, which the caller uploads as it would a chosen file.
 */
export function BadgeBuilder({
  name,
  busy = false,
  onUse,
  onCancel,
  draw = rasterise,
  buttons = { primary: "primary sm", secondary: "secondary sm" },
}: {
  /** The badge's name, shown on a banner. */
  name: string;
  /** While the caller is sending the last picture. */
  busy?: boolean;
  onUse: (png: Blob) => void;
  onCancel?: () => void;
  /** How the preview becomes a PNG; replaced in tests, where no canvas draws. */
  draw?: (svg: SVGSVGElement, width: number, height: number) => Promise<Blob>;
  /** The button classes of the page it sits on: the console's by default. */
  buttons?: { primary: string; secondary: string };
}) {
  const id = useId();
  const [shape, setShape] = useState<BuilderShape>("banner");
  const [colour, setColour] = useState<string>(BUILDER_COLOURS[0].value);
  const [icon, setIcon] = useState<BuilderIcon>(FIRST);
  const [query, setQuery] = useState("");
  const [all, setAll] = useState<Record<string, LucideIcon> | null>(null);
  const [loadError, setLoadError] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [drawing, setDrawing] = useState(false);
  const svg = useRef<SVGSVGElement>(null);
  const Icon = icon.Icon;
  const searching = query.trim() !== "";

  useEffect(() => {
    if (!searching || all) return;
    let live = true;
    loadAllIcons().then(
      (icons) => live && setAll(icons),
      () => live && setLoadError(true),
    );
    return () => {
      live = false;
    };
  }, [searching, all]);

  const found = searching && all ? findIcons(all, query) : null;
  const shown = searching ? (found?.matches ?? []) : BUILDER_ICONS;
  const status = !searching
    ? null
    : loadError
      ? "The full set of icons couldn't be loaded."
      : !found
        ? "Loading the icons…"
        : found.total === 0
          ? `No icon matches “${query.trim()}”.`
          : found.total > found.matches.length
            ? `Showing ${found.matches.length} of ${found.total} icons: add a word to narrow it.`
            : `${found.total} ${found.total === 1 ? "icon matches" : "icons match"}.`;

  const use = async () => {
    if (!svg.current) return;
    const { w, h, px } = SHAPES[shape];
    setDrawing(true);
    setError(null);
    try {
      onUse(await draw(svg.current, px, Math.round((px * h) / w)));
    } catch (e) {
      setError((e as Error).message || "The picture couldn't be drawn.");
    } finally {
      setDrawing(false);
    }
  };

  return (
    <div className="badge-builder">
      <div className="badge-builder-preview">
        <Art shape={shape} colour={colour} Icon={Icon} text={name} svgRef={svg} />
      </div>
      <fieldset className="badge-builder-group">
        <legend>Shape</legend>
        <div className="badge-builder-row">
          {(Object.keys(SHAPES) as BuilderShape[]).map((s) => (
            <label key={s} className="badge-builder-choice">
              <input type="radio" name={`${id}-shape`} checked={shape === s} onChange={() => setShape(s)} />
              {SHAPES[s].label}
            </label>
          ))}
        </div>
      </fieldset>
      <fieldset className="badge-builder-group">
        <legend>Colour</legend>
        <div className="badge-builder-row">
          {BUILDER_COLOURS.map((c) => (
            <label key={c.value} className="badge-builder-swatch" title={c.name}>
              <input
                type="radio"
                name={`${id}-colour`}
                aria-label={c.name}
                checked={colour === c.value}
                onChange={() => setColour(c.value)}
              />
              <span style={{ background: c.value }} aria-hidden="true" />
            </label>
          ))}
        </div>
      </fieldset>
      <fieldset className="badge-builder-group">
        <legend>Icon</legend>
        <input
          type="search"
          className="badge-builder-search"
          aria-label="Find an icon"
          placeholder={`Find an icon, such as “bug”`}
          value={query}
          onChange={(e) => {
            setQuery(e.target.value);
            setLoadError(false);
          }}
        />
        <p className="muted badge-builder-status" aria-live="polite">
          {status ?? `Chosen: ${icon.name}. Search to choose from all of them.`}
        </p>
        <div className="badge-builder-row">
          {shown.map((choice) => (
            <label key={choice.name} className="badge-builder-icon" title={choice.name}>
              <input
                type="radio"
                name={`${id}-icon`}
                aria-label={choice.name}
                checked={icon.Icon === choice.Icon}
                onChange={() => setIcon(choice)}
              />
              <span aria-hidden="true">
                <choice.Icon size={20} />
              </span>
            </label>
          ))}
        </div>
      </fieldset>
      {shape === "banner" && !name.trim() && <p className="muted">Give the badge a name to show it on the banner.</p>}
      {error && (
        <p className="field-error" role="alert">
          {error}
        </p>
      )}
      <div className="badge-builder-actions">
        {onCancel && (
          <button type="button" className={buttons.secondary} onClick={onCancel}>
            Cancel
          </button>
        )}
        <button type="button" className={buttons.primary} disabled={busy || drawing} onClick={() => void use()}>
          {busy || drawing ? "Sending…" : "Use this picture"}
        </button>
      </div>
    </div>
  );
}
