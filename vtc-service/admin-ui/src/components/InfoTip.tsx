// A small "what does this mean?" marker: an (i) that shows an explanation on
// hover or keyboard focus.
//
// A real button rather than a `title` attribute: `title` never appears on
// touch screens or to a keyboard user, and its text is not announced reliably.
// The explanation is the button's accessible description, so a screen reader
// reads it with the control, and it is in the DOM (hidden until hover/focus)
// so tests and find-in-page see it.

import { useId, type ReactNode } from "react";
import { Info } from "lucide-react";

export function InfoTip({
  children,
  label = "What does this mean?",
  side = "top",
}: {
  /** The explanation. Keep it to a sentence or three. */
  children: ReactNode;
  /** The button's accessible name. */
  label?: string;
  /** Which side of the marker the bubble opens on. */
  side?: "top" | "bottom";
}) {
  const id = useId();
  return (
    <span className={`info-tip ${side}`}>
      <button
        type="button"
        className="info-tip-btn"
        aria-label={label}
        aria-describedby={id}
        // A click is a hover on touch screens; keep it from submitting forms
        // or following a parent link.
        onClick={(e) => {
          e.preventDefault();
          e.stopPropagation();
        }}
      >
        <Info size={13} strokeWidth={2} aria-hidden="true" />
      </button>
      <span role="tooltip" id={id} className="info-tip-bubble">
        {children}
      </span>
    </span>
  );
}
