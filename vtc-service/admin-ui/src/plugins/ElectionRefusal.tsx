// A refused election task, with what to do about it when the refusal is one an
// administrator can act on (`refusalHint`). Shared by the elections pages and
// the manifest builder.

import { ErrorOrParked } from "@/components/ParkedNotice";
import { refusalHint } from "@/lib/elections-api";

function codeOf(e: unknown): string | undefined {
  const c = (e as { code?: unknown } | null)?.code;
  return typeof c === "string" ? c : undefined;
}

export function Refusal({ title, error }: { title: string; error: unknown }) {
  if (!error) return null;
  const hint = refusalHint(codeOf(error));
  return (
    <>
      <ErrorOrParked title={title} error={error} />
      {hint && <p className="community-fix">{hint}</p>}
    </>
  );
}
