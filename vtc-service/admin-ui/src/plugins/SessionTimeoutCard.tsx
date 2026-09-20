// How long an admin may sit idle before the console signs them out.
//
// It lives on Access control because that is where an operator decides who
// may do what here; how long a decision stays in force is the same
// question. The value is `auth.admin_idle_timeout`, and it is the only
// auth timing the console exposes — the access-token lifetime beneath it
// is a rotation cadence the operator has no reason to think about now that
// renewal is automatic.
//
// Save is two calls, not one. `PATCH /v1/admin/config` persists the
// db-layer override; the running config only changes on
// `POST /v1/admin/config/reload`. `saveConfig` does both, because a Save
// that stopped at the PATCH would report success and change nothing.

import { useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { fetchEffectiveConfig, saveConfig } from "@/lib/api";
import { useToast } from "@/lib/toast";
import type { EffectiveField } from "@/lib/wire-types";

const KEY = "auth.admin_idle_timeout";

/** Matches the daemon's `U64Range` bound on the key. */
const MIN_SECS = 60;
const MAX_SECS = 86_400;

/** The choices worth offering; anything else can go in via the API. */
const PRESETS = [
  { secs: 900, label: "15 minutes" },
  { secs: 1_800, label: "30 minutes" },
  { secs: 3_600, label: "1 hour" },
  { secs: 14_400, label: "4 hours" },
  { secs: 28_800, label: "8 hours" },
] as const;

function describe(secs: number): string {
  if (secs % 3_600 === 0) {
    const h = secs / 3_600;
    return `${h} hour${h === 1 ? "" : "s"}`;
  }
  if (secs % 60 === 0) {
    const m = secs / 60;
    return `${m} minute${m === 1 ? "" : "s"}`;
  }
  return `${secs} seconds`;
}

export function SessionTimeoutCard() {
  const qc = useQueryClient();
  const toast = useToast();
  const query = useQuery({
    queryKey: ["admin-config"],
    queryFn: fetchEffectiveConfig,
  });

  const field: EffectiveField | undefined = query.data?.fields.find(
    (f) => f.key === KEY,
  );
  const current = typeof field?.value === "number" ? field.value : null;
  // An env override beats the db layer a PATCH writes, so offering an
  // editable control here would be offering one whose Save does nothing.
  const envPinned = field?.source === "env";

  const [draft, setDraft] = useState<number | null>(null);
  useEffect(() => {
    if (current !== null) setDraft(current);
  }, [current]);

  const save = useMutation({
    mutationFn: (secs: number) => saveConfig({ [KEY]: secs }),
    onSuccess: (result, secs) => {
      const refused = result.rejected.find((r) => r.key === KEY);
      if (refused) {
        toast.push("error", `The daemon refused that value: ${refused.reason}`);
        return;
      }
      void qc.invalidateQueries({ queryKey: ["admin-config"] });
      toast.push(
        "success",
        `Admins are now signed out after ${describe(secs)} of inactivity. Sessions already open pick this up on their next renewal.`,
      );
    },
    onError: (err) => toast.pushFromError(err, "Could not save the timeout"),
  });

  if (query.error) {
    return (
      <section className="card error">
        <h3>Failed to load the session timeout</h3>
        <p>{(query.error as Error).message}</p>
      </section>
    );
  }

  return (
    <section className="card" aria-labelledby="session-timeout-title">
      <h3 id="session-timeout-title">Session timeout</h3>
      <p className="lead">
        How long an admin can be inactive before this console signs them out.
        Working in the console keeps a session alive indefinitely; the clock
        only runs while nobody is doing anything.
      </p>

      {query.isPending && <p className="muted">Loading the current setting…</p>}

      {field && envPinned && (
        <div className="finding warn">
          <strong>
            Set by the environment, so this console cannot change it.
          </strong>
          <p className="muted">
            <code>VTC_AUTH_ADMIN_IDLE_TIMEOUT</code> is{" "}
            {current === null ? "set" : describe(current)}. An environment
            override outranks anything saved here — unset it on the daemon to
            manage the timeout from this page.
          </p>
        </div>
      )}

      {field && !envPinned && draft !== null && (
        <>
          <label className="field">
            <span className="field-label" id="idle-timeout-label">
              Sign out after
            </span>
            <select
              aria-labelledby="idle-timeout-label"
              value={PRESETS.some((p) => p.secs === draft) ? draft : "custom"}
              disabled={save.isPending}
              onChange={(e) => {
                if (e.target.value === "custom") return;
                setDraft(Number(e.target.value));
              }}
            >
              {PRESETS.map((p) => (
                <option key={p.secs} value={p.secs}>
                  {p.label}
                </option>
              ))}
              {!PRESETS.some((p) => p.secs === draft) && (
                <option value="custom">{describe(draft)} (current)</option>
              )}
            </select>
          </label>
          <p className="muted">
            Between {describe(MIN_SECS)} and {describe(MAX_SECS)}. The daemon
            enforces the same bounds, so a value set through the API is held to
            them too.
          </p>
          <div className="form-actions">
            <button
              type="button"
              className="primary"
              disabled={save.isPending || draft === current}
              onClick={() => save.mutate(draft)}
            >
              {save.isPending ? "Saving…" : "Save timeout"}
            </button>
          </div>
        </>
      )}
    </section>
  );
}
