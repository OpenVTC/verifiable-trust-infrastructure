// Small pieces the vetting panels share: status chips, a plain-words
// explanation with its code, labelled form fields with a hint and an error,
// and the paths other plugins are reached by.

import type { ReactNode } from "react";

import type { Explained, Tone } from "@/lib/vetting";

/** Where the vetting plugin is mounted (`src/plugins/index.ts`). */
export const VETTING_PATH = "/vetting";

export const memberPath = (did: string) => `/members/${encodeURIComponent(did)}`;
export const joinRequestPath = (id: string) =>
  `/join-requests/${encodeURIComponent(id)}`;

/** A date without its time, for validity windows and profile updates. */
export function formatDay(iso: string): string {
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleDateString();
}

export function errorMessage(err: unknown): string {
  if (err && typeof err === "object" && "message" in err) {
    const message = (err as { message: unknown }).message;
    if (typeof message === "string" && message) return message;
  }
  return String(err);
}

export function errorStatus(err: unknown): number | undefined {
  if (err && typeof err === "object" && "status" in err) {
    const status = (err as { status: unknown }).status;
    if (typeof status === "number") return status;
  }
  return undefined;
}

const CHIP_CLASS: Record<Tone | "neutral", string> = {
  ok: "chip success",
  warn: "chip warning",
  bad: "chip danger",
  neutral: "chip",
};

export const FINDING_CLASS: Record<Tone, string> = {
  ok: "finding ok",
  warn: "finding warn",
  bad: "finding error",
};

export function ToneChip({
  tone,
  title,
  children,
}: {
  tone: Tone | "neutral";
  title?: string;
  children: ReactNode;
}) {
  return (
    <span className={CHIP_CLASS[tone]} title={title}>
      {children}
    </span>
  );
}

/** The sentence, with the daemon's code shown after it and on hover. */
export function ExplainedText({ item }: { item: Explained }) {
  return (
    <span title={item.code}>
      {item.text}
      {item.code !== item.text && (
        <>
          {" "}
          <code className="explained-code">{item.code}</code>
        </>
      )}
    </span>
  );
}

/**
 * A labelled control with an optional hint and error, tied to the control by
 * `id`. The control itself sets `aria-describedby={describedBy(…)}` and
 * `aria-invalid`, so a screen reader reads the error with the field.
 */
export function FormField({
  id,
  label,
  hint,
  error,
  className = "field",
  children,
}: {
  id: string;
  label: string;
  hint?: ReactNode;
  error?: string | null;
  className?: string;
  children: ReactNode;
}) {
  return (
    <div className={className}>
      <label className="field-label" htmlFor={id}>
        {label}
      </label>
      {children}
      {hint && (
        <span className="field-hint" id={`${id}-hint`}>
          {hint}
        </span>
      )}
      {error && (
        <span className="field-error" id={`${id}-error`}>
          {error}
        </span>
      )}
    </div>
  );
}

export function describedBy(
  id: string,
  hint: boolean,
  error?: string | null,
): string | undefined {
  const ids = [hint ? `${id}-hint` : "", error ? `${id}-error` : ""].filter(
    Boolean,
  );
  return ids.length ? ids.join(" ") : undefined;
}

export function LoadError({ what, error }: { what: string; error: unknown }) {
  return (
    <section className="card error" role="alert">
      <h3>Could not load {what}</h3>
      <p>{errorMessage(error)}</p>
      <p className="muted">
        Reload the page to try again. If it keeps failing, sign in again: your
        session may have ended.
      </p>
    </section>
  );
}
