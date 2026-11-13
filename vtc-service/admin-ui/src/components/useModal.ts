// The one keyboard contract every modal dialog keeps (#2610).
//
// Promoted from the Repos dialogs (`plugins/repos/ui.tsx`), which were the
// only ones that held all of it. A dialog that sets `aria-modal="true"` and
// does not keep it lets Tab walk into the page behind the scrim — a keyboard
// user could activate a control under a "type the DID to remove this
// administrator" dialog — and one that does not return focus drops the user
// at `<body>`, back at the top of the page.
//
// Shared by both bundles: it imports nothing from the console shell.

import { useEffect, useRef, type RefObject } from "react";

import { activeElementOf } from "@/components/Protected";

/** The open modals, the most recently opened last. */
const OPEN: symbol[] = [];

const TABBABLE =
  "button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), a[href], summary, [tabindex]:not([tabindex='-1'])";

/**
 * The element that has focus, through any shadow roots: a decision surface
 * is drawn in one (`Protected`), where `document.activeElement` is the host,
 * not the button that opened the dialog.
 */
export function deepActiveElement(): HTMLElement | null {
  let el: Element | null = document.activeElement;
  while (el?.shadowRoot?.activeElement) el = el.shadowRoot.activeElement;
  return el instanceof HTMLElement ? el : null;
}

export interface ModalOptions {
  /** While true (something in flight), Escape and the scrim do nothing. */
  locked?: boolean;
  /** What takes focus on open; by default the first field or button. A
   *  confirmation passes its Cancel, so Enter never fires the act. */
  initialFocus?: RefObject<HTMLElement | null>;
  /** Where focus goes back to on close, when it is not what had focus on
   *  open (a click does not focus a button in every browser). */
  returnTo?: HTMLElement | null;
}

/**
 * Focus moves in on open (`initialFocus`, else the first field or button), Tab
 * and Shift-Tab stay inside, Escape closes — unless `locked` — and focus goes
 * back to whatever opened the dialog when it closes.
 *
 * Call it from the component that renders the surface, *inside* `Protected`:
 * `Protected` portals its children a render after it mounts, so a hook above
 * it would run before the dialog exists. Returns the scrim's click handler.
 */
export function useModal(
  surfaceRef: RefObject<HTMLElement | null>,
  onClose: () => void,
  options: ModalOptions | boolean = {},
): () => void {
  const { locked = false, initialFocus, returnTo } =
    typeof options === "boolean" ? ({ locked: options } as ModalOptions) : options;
  const lockedRef = useRef(locked);
  lockedRef.current = locked;
  const closeRef = useRef(onClose);
  closeRef.current = onClose;
  const initialRef = useRef(initialFocus);
  initialRef.current = initialFocus;
  const returnRef = useRef(returnTo);
  returnRef.current = returnTo;

  useEffect(() => {
    // Captured before focus moves in.
    const opener = returnRef.current ?? deepActiveElement();
    const surface = surfaceRef.current;
    (initialRef.current?.current ?? surface?.querySelector<HTMLElement>("select, input, textarea, button"))?.focus();
    // A confirmation opened from a dialog sits on top of it: only the top one
    // answers the keyboard, so Escape closes one dialog, not both.
    const self = Symbol("modal");
    OPEN.push(self);
    const onKey = (e: KeyboardEvent) => {
      if (OPEN[OPEN.length - 1] !== self) return;
      if (e.key === "Escape") {
        e.preventDefault();
        if (!lockedRef.current) closeRef.current();
        return;
      }
      if (e.key !== "Tab") return;
      const tabbable = surfaceRef.current?.querySelectorAll<HTMLElement>(TABBABLE);
      if (!tabbable || tabbable.length === 0) return;
      const first = tabbable[0]!;
      const last = tabbable[tabbable.length - 1]!;
      const active = activeElementOf(first);
      const inside = active !== null && surfaceRef.current?.contains(active);
      if (e.shiftKey && (active === first || !inside)) {
        e.preventDefault();
        last.focus();
      } else if (!e.shiftKey && (active === last || !inside)) {
        e.preventDefault();
        first.focus();
      }
    };
    window.addEventListener("keydown", onKey);
    return () => {
      window.removeEventListener("keydown", onKey);
      const at = OPEN.lastIndexOf(self);
      if (at >= 0) OPEN.splice(at, 1);
      if (opener && opener.isConnected) opener.focus();
    };
  }, [surfaceRef]);

  /** For the scrim: a click on it closes, unless locked. */
  return () => {
    if (!lockedRef.current) closeRef.current();
  };
}
