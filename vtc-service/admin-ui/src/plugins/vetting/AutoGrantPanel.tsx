// Automatic vetter grants — the sweep's settings and its last result.
//
// Who the sweep names is the `vetterEligibility` policy's call. That policy is
// edited where every other policy is — the Ceremonies surface, under "Other
// policies" — so this panel links there rather than growing an editor of its
// own.

import { type FormEvent, useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "react-router-dom";

import { formatIso } from "@/lib/format";
import { fetchActivePolicy } from "@/lib/policies-api";
import { useToast } from "@/lib/toast";
import { DAY_SECONDS, sweepMinutesError, validityDaysError } from "@/lib/vetting";
import type { AutoGrantStatus } from "@/lib/wire-types";

import { fetchAutoGrant, saveAutoGrant, vettingKeys } from "./api";
import { describedBy, errorMessage, FormField, LoadError } from "./ui";

/** Opens the `vetterEligibility` policy in the Ceremonies plugin. */
export const ELIGIBILITY_POLICY_PATH = "/ceremonies?purpose=vetterEligibility";

interface Draft {
  enabled: boolean;
  sweepMinutes: string;
  validityDays: string;
}

const draftOf = (status: AutoGrantStatus): Draft => ({
  enabled: status.enabled,
  sweepMinutes: String(status.sweepMinutes),
  validityDays: String(status.validitySeconds / DAY_SECONDS),
});

export function AutoGrantPanel() {
  const queryClient = useQueryClient();
  const toast = useToast();
  const status = useQuery({
    queryKey: vettingKeys.autoGrant,
    queryFn: fetchAutoGrant,
  });
  // Same key the Ceremonies policy manager uses, so the two share one read.
  const policy = useQuery({
    queryKey: ["active-policy", "vetterEligibility"],
    queryFn: () => fetchActivePolicy("vetterEligibility"),
  });
  const [draft, setDraft] = useState<Draft | null>(null);

  useEffect(() => {
    if (status.data && draft === null) setDraft(draftOf(status.data));
  }, [status.data, draft]);

  const save = useMutation({
    mutationFn: saveAutoGrant,
    onSuccess: (next) => {
      queryClient.setQueryData(vettingKeys.autoGrant, next);
      setDraft(draftOf(next));
      toast.push(
        "success",
        next.enabled
          ? `Automatic grants are on. The sweep runs every ${next.sweepMinutes} minutes.`
          : "Automatic grants are off. Grants the sweep already issued stay until they expire or you revoke them.",
      );
    },
  });

  if (status.error) {
    return (
      <LoadError what="the automatic grant settings" error={status.error} />
    );
  }
  if (!status.data || !draft) {
    return (
      <section className="card">
        <h3>Automatic vetter grants</h3>
        <p className="muted">Loading…</p>
      </section>
    );
  }

  const minutesError = sweepMinutesError(draft.sweepMinutes);
  const daysError = validityDaysError(draft.validityDays);
  const saved = draftOf(status.data);
  const dirty =
    draft.enabled !== saved.enabled ||
    draft.sweepMinutes.trim() !== saved.sweepMinutes ||
    draft.validityDays.trim() !== saved.validityDays;
  const invalid = Boolean(minutesError || daysError);
  const last = status.data.lastSweep;

  const onSubmit = (e: FormEvent) => {
    e.preventDefault();
    if (!dirty || invalid) return;
    save.mutate({
      enabled: draft.enabled,
      sweepMinutes: Number(draft.sweepMinutes),
      validitySeconds: Number(draft.validityDays) * DAY_SECONDS,
    });
  };

  return (
    <>
      <form
        className="card"
        onSubmit={onSubmit}
        aria-labelledby="auto-grant-title"
        noValidate
      >
        <h3 id="auto-grant-title">Automatic vetter grants</h3>
        <p className="lead">
          When this is on, the community checks every active member against the
          vetter eligibility policy on a schedule. It names a vetter each member
          the policy allows, and revokes the grants it issued itself when the
          policy stops allowing a member. It never revokes a grant an admin made.
        </p>

        <label className="switch-field" htmlFor="auto-grant-enabled">
          <input
            id="auto-grant-enabled"
            type="checkbox"
            role="switch"
            checked={draft.enabled}
            onChange={(e) => setDraft({ ...draft, enabled: e.target.checked })}
          />
          <span className="switch-text">
            <strong>Name vetters automatically</strong>
            <span className="muted">
              {draft.enabled
                ? "On: the sweep runs on the schedule below."
                : "Off: only admins name vetters."}
            </span>
          </span>
        </label>

        <div className="filter-grid">
          <FormField
            id="auto-grant-minutes"
            label="Sweep every (minutes)"
            hint="From 5 minutes to 1440 (once a day)."
            error={minutesError}
          >
            <input
              id="auto-grant-minutes"
              type="number"
              inputMode="numeric"
              min={5}
              max={1440}
              step={1}
              value={draft.sweepMinutes}
              onChange={(e) => setDraft({ ...draft, sweepMinutes: e.target.value })}
              aria-invalid={Boolean(minutesError)}
              aria-describedby={describedBy("auto-grant-minutes", true, minutesError)}
            />
          </FormField>
          <FormField
            id="auto-grant-days"
            label="Automatic grants last (days)"
            hint="From 1 day to 730 (two years). A grant an admin makes sets its own validity."
            error={daysError}
          >
            <input
              id="auto-grant-days"
              type="number"
              inputMode="numeric"
              min={1}
              max={730}
              step={1}
              value={draft.validityDays}
              onChange={(e) => setDraft({ ...draft, validityDays: e.target.value })}
              aria-invalid={Boolean(daysError)}
              aria-describedby={describedBy("auto-grant-days", true, daysError)}
            />
          </FormField>
        </div>

        {save.error && (
          <section className="card error" role="alert">
            <h3>Could not save the automatic grant settings</h3>
            <p>{errorMessage(save.error)}</p>
            <p className="muted">
              The settings are unchanged. Correct the values and save again.
            </p>
          </section>
        )}

        <div className="form-actions">
          <button
            type="submit"
            className="primary"
            disabled={!dirty || invalid || save.isPending}
          >
            {save.isPending ? "Saving…" : "Save settings"}
          </button>
          <button
            type="button"
            className="secondary"
            disabled={!dirty || save.isPending}
            onClick={() => {
              setDraft(saved);
              save.reset();
            }}
          >
            Discard changes
          </button>
        </div>
      </form>

      <section className="card" aria-labelledby="auto-grant-last-title">
        <h3 id="auto-grant-last-title">Last sweep</h3>
        {last ? (
          <>
            <dl>
              <dt>Finished</dt>
              <dd>{formatIso(last.ranAt)}</dd>
              <dt>Granted</dt>
              <dd>
                {last.granted} {last.granted === 1 ? "member" : "members"}
              </dd>
              <dt>Revoked</dt>
              <dd>
                {last.revoked} automatic {last.revoked === 1 ? "grant" : "grants"}
              </dd>
              <dt>Undecided</dt>
              <dd>
                {last.errors} {last.errors === 1 ? "member" : "members"}
              </dd>
            </dl>
            {last.errors > 0 && (
              <p className="finding warn">
                <strong>
                  The sweep could not act on {last.errors}{" "}
                  {last.errors === 1 ? "member" : "members"}.
                </strong>
                <span className="muted">
                  The policy answered neither allow nor deny, or granting or
                  revoking failed. Check the vetter eligibility policy, then the
                  audit trail for VetterAutoGrantSwept.
                </span>
              </p>
            )}
          </>
        ) : (
          <p className="muted">
            No sweep has run yet.
            {status.data.enabled ? "" : " Turn automatic grants on to start it."}
          </p>
        )}
      </section>

      <section className="card" aria-labelledby="auto-grant-policy-title">
        <h3 id="auto-grant-policy-title">Who the sweep names</h3>
        <p>
          The <code>vetterEligibility</code> policy (package{" "}
          <code>vtc.vetter_eligibility</code>) decides, member by member. It sees
          each member's status, roles, days since joining, how they were
          admitted, whether a statement behind their admission has been
          withdrawn, and how many vetting steps separate them from a founding
          member. The shipped policy allows only founding members who are not
          under review.
        </p>
        <p className="muted">
          {policy.isPending
            ? "Loading the active policy…"
            : policy.error
              ? `Could not read the active policy: ${errorMessage(policy.error)}`
              : policy.data
                ? `Active: version ${policy.data.version}, updated ${formatIso(policy.data.updatedAt)}.`
                : "No revision of this policy is active."}
        </p>
        <div className="form-actions">
          <Link className="button secondary" to={ELIGIBILITY_POLICY_PATH}>
            View or edit the policy
          </Link>
        </div>
      </section>
    </>
  );
}
