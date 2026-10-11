// The command palette: ⌘K (Ctrl+K off Apple platforms), or "Jump to…" in the
// top bar. Type to filter every screen the viewer can see — plugins
// registered with `registerPlugin` included — and a short list of common
// actions; Enter runs the highlighted one. What it offers and how it ranks
// them is `lib/commands.ts`.
//
// Accessibility, after the ARIA combobox pattern with a listbox popup:
//
// - A modal dialog (`aria-modal`), labelled; the rest of the console is
//   `inert` while it is open, and focus is trapped on its input (Tab and
//   Shift+Tab stay there). Escape, a click outside it, or running a command
//   closes it and returns focus to where it was.
// - The input is a `combobox` controlling a `listbox`; the highlighted
//   option is `aria-activedescendant`, so focus never leaves the input and
//   typing keeps working. Up/Down move, Home/End jump (when the input is
//   empty), Enter runs. Options are grouped (Screens, Actions) with labelled
//   `group`s.
// - A polite live region says how many results there are.

import {
  useCallback,
  useEffect,
  useId,
  useMemo,
  useRef,
  useState,
  type KeyboardEvent,
} from "react";
import { createPortal } from "react-dom";
import { useNavigate } from "react-router-dom";
import { CornerDownLeft, Search, Zap } from "lucide-react";

import { PluginIcon } from "@/components/PluginIcon";
import {
  actionCommands,
  filterCommands,
  isPaletteShortcut,
  queryCommands,
  screenCommands,
  type ActionSpec,
  type Command,
  type ScreenSource,
} from "@/lib/commands";

/** Open and close the palette from ⌘K / Ctrl+K anywhere on the page. */
export function usePaletteShortcut(toggle: () => void, enabled = true): void {
  useEffect(() => {
    if (!enabled) return;
    const onKey = (e: globalThis.KeyboardEvent) => {
      if (!isPaletteShortcut(e)) return;
      e.preventDefault();
      toggle();
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [toggle, enabled]);
}

const GROUP_LABEL: Record<Command["kind"], string> = {
  screen: "Screens",
  action: "Actions",
};

export function CommandPalette({
  open,
  onClose,
  screens,
  actions,
}: {
  open: boolean;
  onClose: () => void;
  /** Every screen the viewer can see, in nav order, with its group heading. */
  screens: readonly ScreenSource[];
  /** The actions on offer (filtered here by the screens visible). */
  actions: readonly ActionSpec[];
}) {
  if (!open) return null;
  return createPortal(
    <PaletteDialog onClose={onClose} screens={screens} actions={actions} />,
    document.body,
  );
}

function PaletteDialog({
  onClose,
  screens,
  actions,
}: {
  onClose: () => void;
  screens: readonly ScreenSource[];
  actions: readonly ActionSpec[];
}) {
  const navigate = useNavigate();
  const [query, setQuery] = useState("");
  const [active, setActive] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);
  const returnTo = useRef<Element | null>(null);
  const baseId = useId();
  const listId = `${baseId}-list`;
  const optionId = (i: number) => `${baseId}-opt-${i}`;

  const visible = useMemo(() => new Set(screens.map((s) => s.plugin.id)), [screens]);
  const all = useMemo(
    () => [...screenCommands(screens), ...actionCommands(actions, visible)],
    [screens, actions, visible],
  );
  const results = useMemo(
    () => [...filterCommands(all, query), ...queryCommands(query, visible)],
    [all, query, visible],
  );
  // Grouped for display, screens first; `order` is the flat order the arrow
  // keys walk, which is the displayed order.
  const groups = useMemo(() => {
    const out: { kind: Command["kind"]; items: Command[] }[] = [];
    for (const kind of ["screen", "action"] as const) {
      const items = results.filter((c) => c.kind === kind);
      if (items.length) out.push({ kind, items });
    }
    return out;
  }, [results]);
  const order = useMemo(() => groups.flatMap((g) => g.items), [groups]);
  const current = order.length ? Math.min(active, order.length - 1) : -1;

  // Focus the input on open; give focus back on close. The rest of the page
  // is inert meanwhile, so nothing behind the dialog can take focus or be
  // clicked through.
  useEffect(() => {
    returnTo.current = document.activeElement;
    inputRef.current?.focus();
    const root = document.getElementById("root");
    const wasInert = root?.hasAttribute("inert") ?? false;
    if (root && !wasInert) root.setAttribute("inert", "");
    return () => {
      if (root && !wasInert) root.removeAttribute("inert");
      const back = returnTo.current;
      if (back instanceof HTMLElement && back.isConnected) back.focus();
    };
  }, []);

  // Keep the highlighted option in view.
  useEffect(() => {
    if (current < 0) return;
    const el = document.getElementById(optionId(current));
    el?.scrollIntoView?.({ block: "nearest" });
  }, [current]);

  const run = useCallback(
    (c: Command) => {
      onClose();
      if (c.to) navigate(c.to);
      c.run?.();
    },
    [navigate, onClose],
  );

  const onKeyDown = (e: KeyboardEvent<HTMLInputElement>) => {
    switch (e.key) {
      case "ArrowDown":
        e.preventDefault();
        if (order.length) setActive((current + 1) % order.length);
        break;
      case "ArrowUp":
        e.preventDefault();
        if (order.length) setActive((current - 1 + order.length) % order.length);
        break;
      case "Home":
        if (!query) {
          e.preventDefault();
          setActive(0);
        }
        break;
      case "End":
        if (!query) {
          e.preventDefault();
          setActive(Math.max(0, order.length - 1));
        }
        break;
      case "Enter":
        e.preventDefault();
        if (current >= 0) run(order[current]!);
        break;
      case "Escape":
        e.preventDefault();
        e.stopPropagation();
        onClose();
        break;
      case "Tab":
        // The input is the dialog's one stop: trap focus on it.
        e.preventDefault();
        break;
    }
  };

  let index = -1;
  return (
    <div
      className="palette-backdrop"
      onMouseDown={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div
        className="palette"
        role="dialog"
        aria-modal="true"
        aria-label="Command palette"
      >
        <div className="palette-search">
          <Search className="palette-search-icon" aria-hidden="true" />
          <input
            ref={inputRef}
            type="text"
            role="combobox"
            aria-label="Jump to a screen or run an action"
            aria-expanded="true"
            aria-controls={listId}
            aria-autocomplete="list"
            aria-activedescendant={current >= 0 ? optionId(current) : undefined}
            placeholder="Jump to a screen or run an action…"
            autoComplete="off"
            spellCheck={false}
            value={query}
            onChange={(e) => {
              setQuery(e.target.value);
              setActive(0);
            }}
            onKeyDown={onKeyDown}
          />
          <kbd className="palette-esc" aria-hidden="true">
            Esc
          </kbd>
        </div>

        <div className="palette-results" id={listId} role="listbox" aria-label="Results">
          {groups.map((g) => {
            const headingId = `${baseId}-group-${g.kind}`;
            return (
              <div key={g.kind} role="group" aria-labelledby={headingId} className="palette-group">
                <div id={headingId} className="palette-group-label" role="presentation">
                  {GROUP_LABEL[g.kind]}
                </div>
                {g.items.map((c) => {
                  index += 1;
                  const i = index;
                  const selected = i === current;
                  return (
                    <div
                      key={c.id}
                      id={optionId(i)}
                      role="option"
                      aria-selected={selected}
                      className={`palette-option${selected ? " active" : ""}`}
                      onMouseMove={() => {
                        if (!selected) setActive(i);
                      }}
                      onMouseDown={(e) => e.preventDefault()}
                      onClick={() => run(c)}
                    >
                      <span className="palette-option-icon" aria-hidden="true">
                        {c.plugin ? <PluginIcon plugin={c.plugin} /> : <Zap />}
                      </span>
                      <span className="palette-option-text">
                        <span className="palette-option-label">{c.label}</span>
                        {c.hint && <span className="palette-option-hint">{c.hint}</span>}
                      </span>
                      {selected && (
                        <CornerDownLeft className="palette-option-enter" aria-hidden="true" />
                      )}
                    </div>
                  );
                })}
              </div>
            );
          })}
          {order.length === 0 && (
            <p className="palette-empty">Nothing matches “{query.trim()}”.</p>
          )}
        </div>

        <p className="visually-hidden" aria-live="polite">
          {order.length === 0
            ? "No results"
            : `${order.length} result${order.length === 1 ? "" : "s"}`}
        </p>
        <div className="palette-foot" aria-hidden="true">
          <span>
            <kbd>↑</kbd>
            <kbd>↓</kbd> to move
          </span>
          <span>
            <kbd>↵</kbd> to open
          </span>
          <span>
            <kbd>Esc</kbd> to close
          </span>
        </div>
      </div>
    </div>
  );
}
