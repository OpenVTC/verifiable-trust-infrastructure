// A refusal from a `vtc/rooms/community/*` task, with what fixes it
// (`refusalFix`): an operator error should say what to do, not only what went
// wrong.

import { refusalFix, refusalMessage } from "@/lib/community-rooms-api";

export function RefusalCard({ title, error }: { title: string; error: unknown }) {
  if (!error) return null;
  const fix = refusalFix(error);
  const code = (error as { code?: unknown } | null)?.code;
  return (
    <section className="card error" role="alert">
      <h3>{title}</h3>
      <p>{refusalMessage(error)}</p>
      {fix && <p className="community-fix">{fix}</p>}
      {typeof code === "string" && (
        <p className="muted rooms-sub">
          <code>{code}</code>
        </p>
      )}
    </section>
  );
}
