// A toggle switch: one setting that is on or off and takes effect as such
// ("Name vetters automatically", "Show system events"). Not for choosing
// several items from a list (capabilities, vetting methods) or for consenting
// to something ("I understand this is destructive") — those stay checkboxes.
//
// A native `<input type="checkbox" role="switch">` under a drawn track, so it
// keeps everything a checkbox gets for free: the label click, Space to
// toggle, form semantics, `disabled`, and `onChange` with `e.target.checked`.
// Assistive technology announces it as a switch, "on" / "off".
//
//   [●—]  Name vetters automatically
//         On: the sweep runs on the schedule below.

import type { InputHTMLAttributes, ReactNode } from "react";

export interface SwitchProps
  extends Omit<InputHTMLAttributes<HTMLInputElement>, "type" | "role" | "children"> {
  /** The setting's name. Rendered as the label; becomes the accessible name. */
  label: ReactNode;
  /** A line under the label, such as what the current state means. */
  description?: ReactNode;
  /** Put the label before the track rather than after it. */
  labelFirst?: boolean;
}

export function Switch({
  label,
  description,
  labelFirst = false,
  className,
  ...input
}: SwitchProps) {
  const text = (
    <span className="switch-text">
      <span className="switch-label">{label}</span>
      {description && <span className="switch-description muted">{description}</span>}
    </span>
  );
  return (
    <label
      className={`switch${labelFirst ? " switch--label-first" : ""}${
        input.disabled ? " switch--disabled" : ""
      }${className ? ` ${className}` : ""}`}
    >
      {labelFirst && text}
      <span className="switch-control">
        <input type="checkbox" role="switch" className="switch-input" {...input} />
        <span className="switch-track" aria-hidden="true">
          <span className="switch-thumb" />
        </span>
      </span>
      {!labelFirst && text}
    </label>
  );
}
