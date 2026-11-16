// Vetters — every vetter grant, and what an admin does with them: name a
// member a vetter, send a grant's credential again, revoke a grant, and — on a
// build with hidden vetting — reset a vetter's hidden-vetting key binding
// after they lost the key (`vtc/vetting/vetters/pcs-binding/reset/0.1`).
//
// `live` comes from the daemon (`GET /v1/vetting/vetters`), so this panel
// never decides whether a grant is in force; `grantState` only says why one
// that is not live is not.

import { type FormEvent, useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { BadgeCheck } from "lucide-react";

import { useConfirm } from "@/components/ConfirmDialog";
import { DataTable, useSortedRows, type Column } from "@/components/DataTable";
import { EmptyState } from "@/components/EmptyState";
import { NamedDid } from "@/components/NamedDid";
import { formatDate, formatIso, shortenDid } from "@/lib/format";
import { useNameBook } from "@/lib/names";
import { useToast } from "@/lib/toast";
import {
  DAY_SECONDS,
  filterGrants,
  GRANT_STATE_LABELS,
  grantState,
  methodLabel,
  validityDaysError,
  type GrantFilter,
  type GrantState,
  type Tone,
} from "@/lib/vetting";
import type {
  MemberRow,
  VetterGrantRow,
  VetterProfileSummary,
} from "@/lib/wire-types";

import {
  fetchActiveMembers,
  fetchAutoGrant,
  fetchGrants,
  fetchPcsBindingResetServed,
  grantVetter,
  PCS_BINDING_RESET_NOT_BOUND,
  resendGrant,
  resetPcsBinding,
  revokeGrant,
  vettingKeys,
} from "./api";
import {
  describedBy,
  errorMessage,
  errorStatus,
  formatDay,
  FormField,
  LoadError,
  memberPath,
  ToneChip,
} from "./ui";

const STATE_TONE: Record<GrantState, Tone | "neutral"> = {
  live: "ok",
  revoked: "bad",
  expired: "warn",
  inactive: "neutral",
};

type GrantSortKey = "member" | "status" | "validity";

const GRANT_COLUMNS: readonly Column<GrantSortKey>[] = [
  { key: "member", label: "Member", sortKey: "member" },
  { key: "status", label: "Status", sortKey: "status" },
  { key: "validity", label: "Validity", sortKey: "validity" },
  { key: "profile", label: "Vetter profile" },
  { key: "actions", label: <span className="visually-hidden">Actions</span> },
];

const VALIDITY_PRESETS = [
  { value: "30", label: "30 days" },
  { value: "90", label: "90 days" },
  { value: "365", label: "1 year" },
  { value: "730", label: "2 years (the longest allowed)" },
  { value: "custom", label: "Another number of days" },
] as const;

function resendErrorText(err: unknown, name: string): string {
  switch (errorStatus(err)) {
    case 404:
      return `${name} holds no live grant whose credential the community kept. Revoke the grant and grant the role again to issue a new credential.`;
    case 503:
      return "The credential could not be handed to the messaging transport. Check the mediator on the dashboard, then try again.";
    default:
      return errorMessage(err);
  }
}

export function VettersPanel() {
  const queryClient = useQueryClient();
  const book = useNameBook();
  const toast = useToast();
  const confirm = useConfirm();
  const grants = useQuery({ queryKey: vettingKeys.grants, queryFn: fetchGrants });
  const autoGrant = useQuery({
    queryKey: vettingKeys.autoGrant,
    queryFn: fetchAutoGrant,
  });
  const [filter, setFilter] = useState<GrantFilter>({
    state: "all",
    origin: "all",
    search: "",
  });

  const rows = useMemo(
    () => filterGrants(grants.data ?? [], filter),
    [grants.data, filter],
  );
  // The grants are read whole, so their columns sort here.
  const sorted = useSortedRows(rows, (row: VetterGrantRow, key: GrantSortKey) => {
    switch (key) {
      case "member":
        return book.nameOrDid(row.memberDid);
      case "status":
        return GRANT_STATE_LABELS[grantState(row)];
      case "validity":
        return row.validUntil ? Date.parse(row.validUntil) || null : null;
    }
  });
  const liveDids = useMemo(
    () =>
      new Set((grants.data ?? []).filter((g) => g.live).map((g) => g.memberDid)),
    [grants.data],
  );

  const refresh = () => {
    void queryClient.invalidateQueries({ queryKey: ["vetting"] });
    void queryClient.invalidateQueries({ queryKey: ["member-vetter-grants"] });
  };

  const revoke = useMutation({
    mutationFn: (row: VetterGrantRow) => revokeGrant(row.endorsementId),
    onSuccess: (_res, row) => {
      toast.push(
        "success",
        `Revoked ${book.nameOrDid(row.memberDid)}'s vetter role. Their statements no longer count.`,
      );
      refresh();
    },
  });

  const resend = useMutation({
    mutationFn: (row: VetterGrantRow) => resendGrant(row.memberDid),
    onSuccess: (res, row) => {
      toast.push(
        "success",
        `Sent ${book.nameOrDid(row.memberDid)} their vetter credential again. It is valid until ${formatDay(res.validUntil)}.`,
      );
    },
  });

  const onRevoke = async (row: VetterGrantRow) => {
    const name = book.nameOrDid(row.memberDid);
    const ok = await confirm({
      title: `Revoke ${name}'s vetter role?`,
      message:
        `Every statement ${name} signed stops counting toward join requests decided from now on, including statements made while they were a vetter. ` +
        `Their vetter credential is marked revoked and their published vetter profile is deleted.` +
        (autoGrant.data?.enabled
          ? " Automatic grants are on: if the vetter eligibility policy still allows them, the next sweep names them a vetter again."
          : ""),
      confirmLabel: "Revoke vetter role",
      destructive: true,
    });
    if (ok) revoke.mutate(row);
  };

  const isBusy = (row: VetterGrantRow) =>
    (revoke.isPending && revoke.variables?.endorsementId === row.endorsementId) ||
    (resend.isPending && resend.variables?.endorsementId === row.endorsementId);

  return (
    <>
      <GrantForm liveDids={liveDids} onGranted={refresh} />

      <section className="card" aria-labelledby="vetters-title">
        <h3 id="vetters-title">Vetter grants</h3>
        <div className="toolbar">
          <FormField id="vetters-state" label="Status" inline>
            <select
              id="vetters-state"
              value={filter.state}
              onChange={(e) =>
                setFilter({
                  ...filter,
                  state: e.target.value as GrantFilter["state"],
                })
              }
            >
              <option value="all">All grants</option>
              <option value="live">Live</option>
              <option value="revoked">Revoked</option>
              <option value="expired">Expired</option>
              <option value="inactive">Not in force (holder left)</option>
            </select>
          </FormField>
          <FormField id="vetters-origin" label="Granted by" inline>
            <select
              id="vetters-origin"
              value={filter.origin}
              onChange={(e) =>
                setFilter({
                  ...filter,
                  origin: e.target.value as GrantFilter["origin"],
                })
              }
            >
              <option value="all">Anyone</option>
              <option value="manual">An admin</option>
              <option value="auto">The automatic sweep</option>
            </select>
          </FormField>
          <FormField id="vetters-search" label="Search" inline>
            <input
              id="vetters-search"
              type="search"
              placeholder="Display name or DID"
              value={filter.search}
              onChange={(e) => setFilter({ ...filter, search: e.target.value })}
            />
          </FormField>
        </div>

        {grants.error && <LoadError what="the vetter grants" error={grants.error} />}
        {revoke.error && (
          <section className="card error" role="alert">
            <h3>Could not revoke the vetter role</h3>
            <p>{errorMessage(revoke.error)}</p>
            <p className="muted">
              The grant is unchanged. Reload the list to see its current state,
              then try again.
            </p>
          </section>
        )}
        {resend.error && resend.variables && (
          <section className="card error" role="alert">
            <h3>Could not resend the credential</h3>
            <p>
              {resendErrorText(
                resend.error,
                book.nameOrDid(resend.variables.memberDid),
              )}
            </p>
          </section>
        )}

        <div className="table-scroll">
          <DataTable columns={GRANT_COLUMNS} sort={sorted.sort} onSort={sorted.onSort}>
            {grants.isPending && (
              <tr>
                <td colSpan={5}>Loading…</td>
              </tr>
            )}
            {grants.data && rows.length === 0 && (
              <tr>
                <td colSpan={5}>
                  <EmptyState
                    icon={BadgeCheck}
                    title={
                      grants.data.length === 0
                        ? "No vetters yet"
                        : "No grant matches these filters"
                    }
                  >
                    {grants.data.length === 0
                      ? "Grant a member the vetter role above, or turn on automatic grants."
                      : "Change the status, origin or search to see more grants."}
                  </EmptyState>
                </td>
              </tr>
            )}
            {sorted.rows.map((row) => {
              const state = grantState(row);
              const name = book.nameOrDid(row.memberDid);
              const busy = isBusy(row);
              return (
                <tr key={row.endorsementId}>
                  <td>
                    <Link to={memberPath(row.memberDid)}>
                      <NamedDid book={book} did={row.memberDid} />
                    </Link>
                  </td>
                  <td>
                    <ToneChip tone={STATE_TONE[state]}>
                      {GRANT_STATE_LABELS[state]}
                    </ToneChip>
                    <span
                      className="chip"
                      title={
                        row.origin === "auto"
                          ? "Issued by the automatic sweep"
                          : "Granted by an admin"
                      }
                    >
                      {row.origin === "auto" ? "Automatic" : "Manual"}
                    </span>
                  </td>
                  <td>
                    {formatDay(row.validFrom)} to{" "}
                    {row.validUntil ? (
                      formatDay(row.validUntil)
                    ) : (
                      <span className="muted">no end recorded</span>
                    )}
                    {row.revokedAt && (
                      <div className="muted">Revoked {formatIso(row.revokedAt)}</div>
                    )}
                  </td>
                  <td>
                    <ProfileSummary profile={row.profile} />
                  </td>
                  <td>
                    {row.live && (
                      <div className="row-actions">
                        <button
                          type="button"
                          className="secondary sm"
                          disabled={busy}
                          aria-label={`Resend vetter credential to ${name}`}
                          onClick={() => resend.mutate(row)}
                        >
                          {resend.isPending &&
                          resend.variables?.endorsementId === row.endorsementId
                            ? "Resending…"
                            : "Resend"}
                        </button>
                        <button
                          type="button"
                          className="secondary destructive sm"
                          disabled={busy}
                          aria-label={`Revoke vetter role for ${name}`}
                          onClick={() => void onRevoke(row)}
                        >
                          {revoke.isPending &&
                          revoke.variables?.endorsementId === row.endorsementId
                            ? "Revoking…"
                            : "Revoke"}
                        </button>
                      </div>
                    )}
                  </td>
                </tr>
              );
            })}
          </DataTable>
        </div>
      </section>

      <PcsResetCard memberDids={grants.data?.map((g) => g.memberDid) ?? []} />
    </>
  );
}

/**
 * Reset a vetter's hidden-vetting key binding. A vetter is bound to the PCS
 * identifier they first enrolled with, and revoking and re-granting the role
 * does not change that; a vetter whose key is truly lost asks for this. The
 * community then accepts a new key from them once no label the old one
 * enrolled under is live. Shown only when the build serves the task.
 */
function PcsResetCard({ memberDids }: { memberDids: readonly string[] }) {
  const book = useNameBook();
  const toast = useToast();
  const confirm = useConfirm();
  const served = useQuery({
    queryKey: vettingKeys.pcsResetServed,
    queryFn: fetchPcsBindingResetServed,
  });
  const [memberDid, setMemberDid] = useState("");
  const [reason, setReason] = useState("");
  const [attempted, setAttempted] = useState(false);
  const choices = useMemo(() => [...new Set(memberDids)], [memberDids]);

  const reset = useMutation({
    mutationFn: resetPcsBinding,
    onSuccess: (res) => {
      const name = book.nameOrDid(res.memberDid);
      toast.push(
        "success",
        res.open
          ? `Reset ${name}'s hidden-vetting key. Their next enrolment can use a new key.`
          : `Reset ${name}'s hidden-vetting key. A new key is accepted once ${res.waitingOn.join(", ")} ${res.waitingOn.length === 1 ? "is" : "are"} no longer live.`,
      );
      setMemberDid("");
      setReason("");
      setAttempted(false);
    },
  });

  if (!served.data) return null;

  const memberError = memberDid ? null : "Choose the vetter whose key was lost.";
  const reasonError = reason.trim()
    ? reason.length > 500
      ? "500 characters at most."
      : null
    : "Say why. It is kept in the audit log.";

  const onSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setAttempted(true);
    if (memberError || reasonError) return;
    const name = book.nameOrDid(memberDid);
    const ok = await confirm({
      title: `Reset ${name}'s hidden-vetting key?`,
      message:
        `Do this only when ${name} cannot recover their key. ` +
        `The community will accept a new hidden-vetting key from them once no vetter label their old key enrolled under is live — usually by next month — and those labels can never be made live again. ` +
        `If they find the old key first, enrolling with it cancels the reset. This does not grant or revoke the vetter role.`,
      confirmLabel: "Reset hidden-vetting key",
      destructive: true,
    });
    if (ok) reset.mutate({ memberDid, reason: reason.trim() });
  };

  const err = reset.error as { code?: string } | null;
  return (
    <form
      className="card"
      onSubmit={(e) => void onSubmit(e)}
      aria-labelledby="pcs-reset-title"
      noValidate
    >
      <h3 id="pcs-reset-title">Reset a hidden-vetting key</h3>
      <p className="lead">
        A vetter stays bound to the hidden-vetting key they first enrolled
        with, even if their role is revoked and granted again. If their key is
        lost and cannot be recovered, reset it here.
      </p>
      <div className="filter-grid">
        <FormField
          id="pcs-reset-member"
          label="Vetter"
          error={attempted ? memberError : null}
        >
          <select
            id="pcs-reset-member"
            value={memberDid}
            onChange={(e) => setMemberDid(e.target.value)}
            aria-invalid={Boolean(attempted && memberError)}
            aria-describedby={describedBy(
              "pcs-reset-member",
              false,
              attempted ? memberError : null,
            )}
          >
            <option value="">Choose a vetter</option>
            {choices.map((did) => (
              <option key={did} value={did}>
                {book.nameOrDid(did)}
              </option>
            ))}
          </select>
        </FormField>
        <FormField
          id="pcs-reset-reason"
          label="Reason"
          hint="Kept in the audit log."
          error={attempted ? reasonError : null}
        >
          <input
            id="pcs-reset-reason"
            value={reason}
            maxLength={500}
            onChange={(e) => setReason(e.target.value)}
            aria-invalid={Boolean(attempted && reasonError)}
            aria-describedby={describedBy(
              "pcs-reset-reason",
              true,
              attempted ? reasonError : null,
            )}
          />
        </FormField>
      </div>
      {reset.error && (
        <section className="card error" role="alert">
          <h3>Could not reset the key</h3>
          <p>
            {err?.code === PCS_BINDING_RESET_NOT_BOUND
              ? `${book.nameOrDid(reset.variables?.memberDid ?? "")} has never enrolled for hidden vetting, so there is no key to reset.`
              : errorMessage(reset.error)}
          </p>
        </section>
      )}
      <div className="form-actions">
        <button
          type="submit"
          className="secondary destructive"
          disabled={reset.isPending}
        >
          {reset.isPending ? "Resetting…" : "Reset hidden-vetting key"}
        </button>
      </div>
    </form>
  );
}

function ProfileSummary({ profile }: { profile?: VetterProfileSummary | null }) {
  if (!profile) return <span className="muted">No profile published</span>;
  const details = [
    profile.country,
    profile.languages?.join(", "),
    profile.methods?.map(methodLabel).join(", "),
    `${profile.eventCount} ${profile.eventCount === 1 ? "event" : "events"}`,
  ].filter(Boolean);
  return (
    <div>
      <ToneChip
        tone={profile.listed ? "ok" : "neutral"}
        title={
          profile.listed
            ? "Applicants can find this vetter"
            : "Kept, but left out of the listing applicants see"
        }
      >
        {profile.listed ? "Listed" : "Unlisted"}
      </ToneChip>
      {profile.displayName && <strong>{profile.displayName}</strong>}
      <div className="muted">{details.join(" · ")}</div>
      <div className="muted">Updated {formatDay(profile.updatedAt)}</div>
    </div>
  );
}

function memberOptionLabel(member: MemberRow): string {
  const did = shortenDid(member.did);
  return `${member.label ? `${member.label} · ${did}` : did} (${member.role})`;
}

function GrantForm({
  liveDids,
  onGranted,
}: {
  liveDids: ReadonlySet<string>;
  onGranted: () => void;
}) {
  const book = useNameBook();
  const toast = useToast();
  const confirm = useConfirm();
  const members = useQuery({
    queryKey: vettingKeys.activeMembers,
    queryFn: fetchActiveMembers,
  });
  const [search, setSearch] = useState("");
  const [memberDid, setMemberDid] = useState("");
  const [preset, setPreset] = useState<string>("365");
  const [customDays, setCustomDays] = useState("");
  const [attempted, setAttempted] = useState(false);

  const days = preset === "custom" ? customDays : preset;
  const daysError = validityDaysError(days);
  const memberError = memberDid ? null : "Choose the member to name a vetter.";
  const shownMemberError = attempted ? memberError : null;
  const shownDaysError =
    preset === "custom" && (attempted || customDays !== "") ? daysError : null;

  const needle = search.trim().toLowerCase();
  const eligible = (members.data ?? []).filter((m) => !liveDids.has(m.did));
  const candidates = eligible.filter(
    (m) =>
      m.did === memberDid ||
      !needle ||
      m.did.toLowerCase().includes(needle) ||
      (m.label ?? "").toLowerCase().includes(needle),
  );

  const grant = useMutation({
    mutationFn: grantVetter,
    onSuccess: (res, vars) => {
      toast.push(
        "success",
        `Named ${book.nameOrDid(vars.memberDid)} a vetter until ${formatDay(res.validUntil)}. If their wallet does not receive the credential, resend it from the list below.`,
      );
      setMemberDid("");
      setSearch("");
      setAttempted(false);
      onGranted();
    },
  });

  const onSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setAttempted(true);
    if (memberError || daysError) return;
    const n = Number(days);
    const name = book.nameOrDid(memberDid);
    const until = formatDate(Date.now() + n * DAY_SECONDS * 1000);
    const ok = await confirm({
      title: `Name ${name} a vetter?`,
      message: `${name} receives a vetter role credential valid until ${until}. While it is live, the identity-vetting statements they sign count toward applicants' admissions. You can revoke it at any time.`,
      confirmLabel: "Grant vetter role",
    });
    if (ok) grant.mutate({ memberDid, validitySeconds: n * DAY_SECONDS });
  };

  return (
    <form
      className="card"
      onSubmit={(e) => void onSubmit(e)}
      aria-labelledby="grant-title"
      noValidate
    >
      <h3 id="grant-title">Grant the vetter role</h3>
      <p className="lead">
        A vetter checks who an applicant is and signs a statement the community
        counts toward their admission. Name members you trust to do that.
      </p>

      <div className="filter-grid">
        <FormField
          id="grant-search"
          label="Find a member"
          hint="Narrows the member list by name or DID."
        >
          <input
            id="grant-search"
            type="search"
            placeholder="Name or DID"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            aria-describedby="grant-search-hint"
          />
        </FormField>
        <FormField
          id="grant-member"
          label="Member"
          hint={
            members.data
              ? `${eligible.length} of ${members.data.length} current members can be named. Members who already hold a live grant are left out.`
              : undefined
          }
          error={shownMemberError}
        >
          <select
            id="grant-member"
            value={memberDid}
            disabled={members.isPending}
            onChange={(e) => setMemberDid(e.target.value)}
            aria-invalid={Boolean(shownMemberError)}
            aria-describedby={describedBy(
              "grant-member",
              Boolean(members.data),
              shownMemberError,
            )}
          >
            <option value="">
              {members.isPending
                ? "Loading members…"
                : candidates.length
                  ? "Choose a member"
                  : "No member matches"}
            </option>
            {candidates.map((m) => (
              <option key={m.did} value={m.did}>
                {memberOptionLabel(m)}
              </option>
            ))}
          </select>
        </FormField>
        <FormField
          id="grant-validity"
          label="Valid for"
          hint="From 1 day to 2 years. Applicants' clients stop accepting the credential when it expires."
        >
          <select
            id="grant-validity"
            value={preset}
            onChange={(e) => setPreset(e.target.value)}
            aria-describedby="grant-validity-hint"
          >
            {VALIDITY_PRESETS.map((p) => (
              <option key={p.value} value={p.value}>
                {p.label}
              </option>
            ))}
          </select>
        </FormField>
        {preset === "custom" && (
          <FormField id="grant-days" label="Days" error={shownDaysError}>
            <input
              id="grant-days"
              type="number"
              inputMode="numeric"
              min={1}
              max={730}
              step={1}
              value={customDays}
              onChange={(e) => setCustomDays(e.target.value)}
              aria-invalid={Boolean(shownDaysError)}
              aria-describedby={describedBy("grant-days", false, shownDaysError)}
            />
          </FormField>
        )}
      </div>

      {members.error && (
        <p className="finding error" role="alert">
          <strong>Could not load the member list.</strong>
          <span className="muted">
            {errorMessage(members.error)} Reload the page to try again.
          </span>
        </p>
      )}
      {grant.error && (
        <section className="card error" role="alert">
          <h3>Could not grant the vetter role</h3>
          <p>{errorMessage(grant.error)}</p>
          {errorStatus(grant.error) === 400 && (
            <p className="muted">
              Only a current member can be named a vetter, for 1 day to 2 years.
              Check the member is still listed under Members.
            </p>
          )}
        </section>
      )}

      <div className="form-actions">
        <button type="submit" className="primary" disabled={grant.isPending}>
          {grant.isPending ? "Granting…" : "Grant vetter role"}
        </button>
      </div>
    </form>
  );
}
