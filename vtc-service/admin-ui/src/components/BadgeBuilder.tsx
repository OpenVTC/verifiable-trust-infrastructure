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
  X,
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
  /** Words lucide files the icon under besides its name: "insect" for the bug. */
  tags?: readonly string[];
}

/** The whole set: every lucide icon by its key, and the words each is filed under. */
export interface IconSet {
  icons: Record<string, LucideIcon>;
  tags: Record<string, readonly string[]>;
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

/** Every icon of `set` once, the offered ones first under their own names, each with its tags. */
const catalogues = new WeakMap<IconSet, BuilderIcon[]>();
function catalogue(set: IconSet): BuilderIcon[] {
  const known = catalogues.get(set);
  if (known) return known;
  const tagsOf = new Map<LucideIcon, readonly string[]>();
  for (const [key, Icon] of Object.entries(set.icons)) tagsOf.set(Icon, set.tags[key] ?? []);
  const offered = new Set<LucideIcon>(BUILDER_ICONS.map((i) => i.Icon));
  const all: BuilderIcon[] = BUILDER_ICONS.map((i) => ({ ...i, tags: tagsOf.get(i.Icon) ?? [] }));
  for (const [key, Icon] of Object.entries(set.icons)) {
    if (!offered.has(Icon)) all.push({ name: iconLabel(key), Icon, tags: set.tags[key] ?? [] });
  }
  catalogues.set(set, all);
  return all;
}

/**
 * The icons of `set` that every word of `query` finds, in the name or in the
 * words lucide files it under ("insect" finds the bug), at most `limit`: those
 * whose name holds every word first, the offered ones (whose names may differ,
 * "Tools" for the wrench) leading each group. Every icon for an empty query.
 */
export function findIcons(
  set: IconSet,
  query: string,
  limit = SEARCH_LIMIT,
): { matches: BuilderIcon[]; total: number } {
  const words = query.toLowerCase().split(/[\s-]+/).filter(Boolean);
  const byName: BuilderIcon[] = [];
  const byTag: BuilderIcon[] = [];
  for (const i of catalogue(set)) {
    const name = i.name.toLowerCase();
    const tags = (i.tags ?? []).map((t) => t.toLowerCase());
    if (words.every((w) => name.includes(w))) byName.push(i);
    else if (words.every((w) => name.includes(w) || tags.some((t) => t.includes(w)))) byTag.push(i);
  }
  const found = [...byName, ...byTag];
  return { matches: found.slice(0, limit), total: found.length };
}

/** Loads the whole set, once, the first time someone searches or browses. */
let allIcons: Promise<IconSet> | null = null;
function loadAllIcons(): Promise<IconSet> {
  allIcons ??= import("./badge-icons").then((m) => ({
    icons: m.icons as Record<string, LucideIcon>,
    tags: m.tags,
  }));
  allIcons.catch(() => {
    allIcons = null;
  });
  return allIcons;
}

/** What an icon is filed under, for its title: "Bug: issue, report, insect". */
function described(i: BuilderIcon): string {
  return i.tags?.length ? `${i.name}: ${i.tags.join(", ")}` : i.name;
}

/** The status line for a search of `query` that `found` answered. */
function searchStatus(query: string, loadError: boolean, found: { matches: BuilderIcon[]; total: number } | null): string {
  if (loadError) return "The full set of icons couldn't be loaded.";
  if (!found) return "Loading the icons…";
  if (found.total === 0) return `No icon matches “${query.trim()}”. Try another word, such as what it means.`;
  if (found.total > found.matches.length)
    return `Showing ${found.matches.length} of ${found.total} icons: add a word to narrow it, or browse them all.`;
  return `${found.total} ${found.total === 1 ? "icon matches" : "icons match"}.`;
}

/**
 * Every icon in a dialog, to look through rather than guess a name: the same
 * search, without a cap, over the whole set. Choosing one closes it.
 */
function IconBrowser({
  set,
  loadError,
  initialQuery,
  chosen,
  returnTo,
  onChoose,
  onClose,
}: {
  set: IconSet | null;
  loadError: boolean;
  initialQuery: string;
  chosen: LucideIcon;
  /** Where focus goes back to on closing: the button that opened it, which a
   *  click does not focus in every browser. */
  returnTo: HTMLElement | null;
  onChoose: (icon: BuilderIcon) => void;
  onClose: () => void;
}) {
  const titleId = useId();
  const [query, setQuery] = useState(initialQuery);
  const searchRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    const opener = returnTo ?? (document.activeElement as HTMLElement | null);
    searchRef.current?.focus();
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    window.addEventListener("keydown", onKey);
    return () => {
      window.removeEventListener("keydown", onKey);
      if (opener?.isConnected) opener.focus();
    };
  }, [onClose, returnTo]);

  const found = set ? findIcons(set, query, Number.POSITIVE_INFINITY) : null;
  const status = query.trim()
    ? searchStatus(query, loadError, found)
    : loadError
      ? "The full set of icons couldn't be loaded."
      : found
        ? `All ${found.total} icons. Type to narrow them, by name or by meaning.`
        : "Loading the icons…";
  return (
    <div
      className="badge-builder-scrim"
      onClick={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div role="dialog" aria-modal="true" aria-labelledby={titleId} className="badge-builder-browse">
        <div className="badge-builder-browse-head">
          <h3 id={titleId}>All icons</h3>
          <button type="button" className="badge-builder-close" aria-label="Close" onClick={onClose}>
            <X size={16} aria-hidden="true" />
          </button>
        </div>
        <input
          ref={searchRef}
          type="search"
          className="badge-builder-search"
          aria-label="Find among all icons"
          placeholder="A name or a meaning, such as “prize”"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
        />
        <p className="muted badge-builder-status" aria-live="polite">
          {status}
        </p>
        <div className="badge-builder-browse-grid" role="list">
          {(found?.matches ?? []).map((choice) => (
            <div role="listitem" key={choice.name}>
              <button
                type="button"
                className={`badge-builder-pick${choice.Icon === chosen ? " is-chosen" : ""}`}
                title={described(choice)}
                aria-label={choice.name}
                aria-pressed={choice.Icon === chosen}
                onClick={() => onChoose(choice)}
              >
                <choice.Icon size={22} aria-hidden="true" />
                <span>{choice.name}</span>
              </button>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
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
  const [all, setAll] = useState<IconSet | null>(null);
  const [browsing, setBrowsing] = useState(false);
  const [loadError, setLoadError] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [drawing, setDrawing] = useState(false);
  const svg = useRef<SVGSVGElement>(null);
  const browseButton = useRef<HTMLButtonElement>(null);
  const Icon = icon.Icon;
  const searching = query.trim() !== "";

  useEffect(() => {
    if (!(searching || browsing) || all) return;
    let live = true;
    loadAllIcons().then(
      (set) => live && setAll(set),
      () => live && setLoadError(true),
    );
    return () => {
      live = false;
    };
  }, [searching, browsing, all]);

  const found = searching && all ? findIcons(all, query) : null;
  const shown = searching ? (found?.matches ?? []) : BUILDER_ICONS;
  const status = searching ? searchStatus(query, loadError, found) : null;

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
        <div className="badge-builder-find">
          <input
            type="search"
            className="badge-builder-search"
            aria-label="Find an icon"
            placeholder="A name or a meaning, such as “bug” or “prize”"
            value={query}
            onChange={(e) => {
              setQuery(e.target.value);
              setLoadError(false);
            }}
          />
          <button
            ref={browseButton}
            type="button"
            className={buttons.secondary}
            aria-haspopup="dialog"
            onClick={() => {
              setLoadError(false);
              setBrowsing(true);
            }}
          >
            Browse all icons
          </button>
        </div>
        <p className="muted badge-builder-status" aria-live="polite">
          {status ?? `Chosen: ${icon.name}. Search by name or meaning, or browse them all.`}
        </p>
        <div className="badge-builder-row">
          {shown.map((choice) => (
            <label key={choice.name} className="badge-builder-icon" title={described(choice)}>
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
      {browsing && (
        <IconBrowser
          set={all}
          loadError={loadError}
          initialQuery={query}
          chosen={icon.Icon}
          returnTo={browseButton.current}
          onChoose={(choice) => {
            setIcon(choice);
            setBrowsing(false);
          }}
          onClose={() => setBrowsing(false)}
        />
      )}
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
