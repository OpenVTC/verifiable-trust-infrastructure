import type { ReactNode } from "react";

// A labelled form field, used by every screen.
//
// Two shapes, one look:
//
// - **Wrapping** (no `htmlFor`): `<label class="field"><span
//   class="field-label">…</span>{control}</label>`. The label wraps the
//   control, so nothing needs an id. The shape the design language locked at
//   phase 2, and still the common case. With a hint or an error the wrapper
//   becomes a `<div class="field">` around that label, so neither is read as
//   part of the control's name.
// - **Pointing** (`htmlFor`): `<div class="field"><label for=…>…</label>
//   {control}</div>`, for a control that cannot sit inside a `<label>` — a
//   group of checkboxes, a combobox with its own popup, a field whose hint
//   holds a link.
//
// `hint` and `error` render as `.field-hint` / `.field-error` under the
// control. Give them ids (`hintId`, `errorId`) when the control should name
// them in `aria-describedby`; an error is announced (`role="alert"`) only when
// `errorRole` asks for it, so a screen that validated as you type keeps doing
// so quietly.
export function Field({
  label,
  children,
  hint,
  hintId,
  error,
  errorId,
  errorRole,
  htmlFor,
  inline,
  className,
}: {
  label: ReactNode;
  children: ReactNode;
  hint?: ReactNode;
  hintId?: string;
  error?: ReactNode;
  errorId?: string;
  errorRole?: "alert";
  /** The control's id: renders the pointing shape. */
  htmlFor?: string;
  /** Label and control side by side, for toolbars. */
  inline?: boolean;
  className?: string;
}) {
  const cls = ["field", inline ? "inline" : null, className].filter(Boolean).join(" ");
  const extra = (
    <>
      {hint && (
        <span className="field-hint" id={hintId}>
          {hint}
        </span>
      )}
      {error && (
        <span className="field-error" id={errorId} role={errorRole}>
          {error}
        </span>
      )}
    </>
  );
  if (htmlFor) {
    return (
      <div className={cls}>
        <label className="field-label" htmlFor={htmlFor}>
          {label}
        </label>
        {children}
        {extra}
      </div>
    );
  }
  if (hint || error) {
    // The hint and error stay outside the <label>: inside it they would be
    // read as part of the control's name.
    return (
      <div className={cls}>
        <label className="field-wrap">
          <span className="field-label">{label}</span>
          {children}
        </label>
        {extra}
      </div>
    );
  }
  return (
    <label className={cls}>
      <span className="field-label">{label}</span>
      {children}
    </label>
  );
}
