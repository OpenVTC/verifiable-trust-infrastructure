// ACL plugin — list, create, edit and revoke.
//
// The canonical `acl/*` family, each verb a signed document. Administration is
// role-based (`docs/05-design-notes/vtc-admin-roles.md`): each entry shows its
// administrative role and what it may administer — its capabilities, narrowed
// and qualified as granted — beside the community role its membership carries.
// Add entry picks an administrative role and may narrow its capabilities, with
// a resource for the ones that take one. Edit narrows or widens an existing
// entry's capabilities. Revoke removes the entry.

import { useEffect, useState } from "react";
import {
  useMutation,
  useQuery,
  useQueryClient,
} from "@tanstack/react-query";
import { Copy, Mail, Pencil, Plus, RefreshCw, ShieldCheck, X } from "lucide-react";

import { postSignedRead, postSignedTrustTask } from "@/lib/api";
import {
  ADMIN_ROLES,
  NO_ADMIN_ROLE,
  adminRoleInfo,
  capabilityInfo,
  communityRoleOf,
  describeAuthority,
  fetchAclPage,
  grantAcl,
  grantLabel,
  grantRequest,
  isUnrestricted,
  labelSelfSet,
  ownEntryEdits,
  revokeAcl,
  revokeAclNow,
  suspensionOf,
  updateAcl,
  type AclEntry,
  type AclGrantRequest,
  type AclListResponse,
  type CapabilityScope,
} from "@/lib/acl";
import {
  gestureFromConfirm,
  parkedOf,
  postSignedWithStepUp,
  type ConfirmGesture,
} from "@/lib/signed-act";
import { useConfirm } from "@/components/ConfirmDialog";
import { TypedConfirmDialog } from "@/components/TypedConfirmDialog";
import { immediateConfirmMatches } from "@/lib/immediate";
import { Field } from "@/components/Field";
import { DataTable } from "@/components/DataTable";
import { EmptyState } from "@/components/EmptyState";
import { PageHeader } from "@/components/PageHeader";
import { formatIso, shorten, shortenDid } from "@/lib/format";
import { useToast } from "@/lib/toast";
import { SessionTimeoutCard } from "@/plugins/SessionTimeoutCard";
import { useSingleAdminMode } from "@/lib/action-badge";
import { useViewerDid } from "@/lib/viewer";

// The ACL verbs are signed documents (`lib/acl.ts`); the invites are REST.
const TRUST_TASK_INVITES_LIST =
  "https://trusttasks.org/spec/vtc/admin/invites/list/0.1";
const TRUST_TASK_INVITES_CREATE =
  "https://trusttasks.org/spec/vtc/admin/invites/create/0.1";
const TRUST_TASK_INVITES_REVOKE =
  "https://trusttasks.org/spec/vtc/admin/invites/revoke/0.1";

import type {
  CreateInviteResponse,
  InviteSummary,
  InvitesListResponse,
} from "@/lib/wire-types";

const fetchAcl = (role: string | null): Promise<AclListResponse> =>
  fetchAclPage(role ? { role } : {});

// Widening administrative authority asks for a passkey gesture bound to this
// one grant (#1645), and granting an authority-conferring capability is then
// parked for its other holders' approval (VTI-APV-018): the grant throws a
// `ParkedAction`, which the toast shows as a success linking to the action.
const createAcl = (req: AclGrantRequest, confirmGesture: ConfirmGesture): Promise<AclEntry> =>
  grantAcl(req, confirmGesture);

// Revoking an administrator needs a passkey gesture bound to this one
// revocation, and taking authority-conferring capabilities away another
// holder's approval (VTI-APV-019).
const deleteAcl = (subject: string, confirmGesture: ConfirmGesture): Promise<void> =>
  revokeAcl(subject, confirmGesture);

// A label edit is an `acl/update/0.2` that replaces the label and nothing
// else, so it widens nothing and asks for no gesture — on your own entry too
// (VTI-ACL-052 item 2), where the VTC marks it self-set.
async function patchAclLabel(args: {
  entry: AclEntry;
  label: string;
  confirmGesture: ConfirmGesture;
}): Promise<AclEntry> {
  return updateAcl(
    {
      subject: args.entry.subject,
      label: args.label === "" ? null : args.label,
      reason: "label updated from the admin UI",
    },
    args.confirmGesture,
  );
}

// ── Admin invites ────────────────────────────────────────────

interface CreateInviteRequest {
  did: string;
  ttlSeconds?: number;
  label?: string;
}

async function fetchInvites(): Promise<InvitesListResponse> {
  return postSignedRead<InvitesListResponse>(TRUST_TASK_INVITES_LIST, {});
}

/**
 * Mint an admin invite, a signed document. Inviting someone who is not an
 * admin yet writes a community-administrator entry, so it costs what
 * `acl/grant` of one costs: a passkey gesture bound to this invite — asked for
 * with `confirmGesture` when the VTC refuses for want of one — and another
 * community administrator's approval (VTI-APV-018), for which the invite is
 * parked as an action and thrown as a `ParkedAction`. Its install URL and
 * claim code are then shown once, to the requester, on the completed action
 * (Actions page).
 */
async function createInvite(
  req: CreateInviteRequest,
  confirmGesture: ConfirmGesture,
): Promise<CreateInviteResponse> {
  return postSignedWithStepUp<CreateInviteResponse>(
    TRUST_TASK_INVITES_CREATE,
    req,
    confirmGesture,
  );
}

async function revokeInvite(jti: string): Promise<void> {
  await postSignedTrustTask<unknown>(TRUST_TASK_INVITES_REVOKE, { jti });
}

export function Acl() {
  const [roleFilter, setRoleFilter] = useState("");
  const [showCreate, setShowCreate] = useState(false);
  const [editing, setEditing] = useState<AclEntry | null>(null);
  const queryClient = useQueryClient();
  const toast = useToast();
  const confirm = useConfirm();
  const me = useViewerDid();
  const singleAdminMode = useSingleAdminMode();

  const query = useQuery({
    queryKey: ["acl", roleFilter],
    queryFn: () => fetchAcl(roleFilter || null),
    placeholderData: (prev) => prev,
  });

  const revoke = useMutation({
    mutationFn: (subject: string) => deleteAcl(subject, gestureFromConfirm(confirm)),
    onSuccess: (_, did) => {
      toast.push("success", `Revoked ACL entry for ${did}`);
      void queryClient.invalidateQueries({ queryKey: ["acl"] });
    },
    onError: (err) => toast.pushFromError(err, "Revoke failed"),
  });
  // Remove now (single-administrator mode, vtc-action-list.md §8.5): the
  // subject's DID typed back, then a gesture bound to the immediate removal.
  const [removingNow, setRemovingNow] = useState<AclEntry | null>(null);
  const removeNow = useMutation({
    mutationFn: (args: { subject: string; typed: string }) =>
      revokeAclNow(args.subject, args.typed, gestureFromConfirm(confirm)),
    onSuccess: (_, args) => {
      toast.push("success", `Removed ${args.subject} now, without the cooling-off`);
      void queryClient.invalidateQueries({ queryKey: ["acl"] });
      void queryClient.invalidateQueries({ queryKey: ["actions"] });
    },
    onError: (err) => toast.pushFromError(err, "Remove now failed"),
  });

  return (
    <section className="page">
      <PageHeader title="Access control" />

      <SessionTimeoutCard />

      <section className="card">
        <div className="toolbar">
          <Field label="Filter by administrative role" inline>
            <select
              aria-label="Filter by administrative role"
              value={roleFilter}
              onChange={(e) => setRoleFilter(e.target.value)}
            >
              <option value="">all entries</option>
              {ADMIN_ROLES.map((r) => (
                <option key={r.id} value={r.id}>
                  {r.title}
                </option>
              ))}
              <option value={NO_ADMIN_ROLE}>no administrative role</option>
            </select>
          </Field>
          <div className="spacer" />
          <button
            type="button"
            className={showCreate ? "secondary" : "primary"}
            onClick={() => setShowCreate((v) => !v)}
          >
            {showCreate ? (
              <>
                <X size={14} aria-hidden="true" /> Cancel
              </>
            ) : (
              <>
                <Plus size={14} aria-hidden="true" /> Add entry
              </>
            )}
          </button>
        </div>
      </section>

      {showCreate && (
        <CreateAclForm
          onSuccess={() => {
            setShowCreate(false);
            void queryClient.invalidateQueries({ queryKey: ["acl"] });
          }}
        />
      )}

      {editing && (
        <EditCapabilitiesForm
          entry={editing}
          onDone={() => {
            setEditing(null);
            void queryClient.invalidateQueries({ queryKey: ["acl"] });
          }}
        />
      )}

      {removingNow && (
        <TypedConfirmDialog
          title="Remove this administrator now?"
          message={
            <p>
              Single-administrator mode: {removingNow.subject} loses every right at once, with no
              cooling-off{suspensionOf(removingNow) ? " (the one already open lands now)" : ""}.
              This cannot be undone. You will then be asked for a passkey gesture bound to this
              removal.
            </p>
          }
          prompt="Type the administrator's DID to confirm"
          matches={(t) => immediateConfirmMatches(t, removingNow.subject)}
          confirmLabel="Remove now"
          busy={removeNow.isPending}
          onCancel={() => setRemovingNow(null)}
          onConfirm={(typed) => {
            const subject = removingNow.subject;
            setRemovingNow(null);
            removeNow.mutate({ subject, typed });
          }}
        />
      )}

      {query.error && (
        <section className="card error">
          <h3>Failed to load ACL</h3>
          <p>{(query.error as Error).message}</p>
        </section>
      )}

      <section className="card">
        <DataTable
          columns={[
            { key: "did", label: "DID" },
            { key: "administrative-role", label: "Administrative role" },
            { key: "administers", label: "Administers" },
            { key: "community-role", label: "Community role" },
            { key: "label", label: "Label" },
            { key: "expires", label: "Expires" },
            { key: "actions", label: "" },
          ]}
        >
          {query.isPending && (
            <tr>
              <td colSpan={7}>Loading…</td>
            </tr>
          )}
          {query.data?.entries.length === 0 && (
            <tr>
              <td colSpan={7}>
                <EmptyState icon={ShieldCheck} title="No ACL entries match this filter">
                  Use <strong>Add entry</strong> to grant access,
                  or clear the role filter to see every entry.
                </EmptyState>
              </td>
            </tr>
          )}
          {query.data?.entries.map((e) => {
            const review = e.ext?.["org.openvtc"]?.delegationReview;
            // Your own entry (VTI-ACL-052): the label always; anything else
            // only where the VTC would allow it, explained otherwise.
            const own = me !== null && e.subject === me ? ownEntryEdits(e, singleAdminMode) : null;
            const suspended = suspensionOf(e);
            // Another unrestricted administrator: in single-administrator
            // mode, removing them may skip the cooling-off (§8.5).
            const mayRemoveNow = singleAdminMode && own === null && isUnrestricted(e);
            return (
              <tr key={e.subject}>
                <td>
                  <code title={e.subject}>{shortenDid(e.subject)}</code>
                  {own && (
                    <span className="chip" title="This is the entry you are signed in as">
                      you
                    </span>
                  )}
                </td>
                <td>
                  {e.role === NO_ADMIN_ROLE ? (
                    <span className="muted">none</span>
                  ) : (
                    <code>{e.role}</code>
                  )}
                  {review && (
                    <span
                      className="chip warning"
                      title={`Granted by ${review.granter}, who has left or narrowed. Withdrawn at ${review.deadline} unless an administrator re-affirms it (Edit, then Save).`}
                    >
                      under review
                    </span>
                  )}
                  {suspended && (
                    <span
                      className="chip danger"
                      data-testid="suspended"
                      title={`A reduction of this entry is cooling off (action ${suspended.actionId}, requested by ${suspended.requester}). Until it lands or is cancelled the entry authorizes nothing; cancelling restores it.`}
                    >
                      suspended — removal lands {formatIso(suspended.landsAt)}
                    </span>
                  )}
                </td>
                <td data-testid="administers">
                  <AuthorityCell entry={e} />
                </td>
                <td>
                  <code>{communityRoleOf(e)}</code>
                </td>
                <td>
                  <EditableLabelCell entry={e} label={e.label ?? null} />
                  {labelSelfSet(e) && (
                    <span
                      className="chip warning"
                      title="Set by the entry's own subject, not by another administrator (VTI-ACL-052)"
                    >
                      self-set
                    </span>
                  )}
                </td>
                <td>
                  {e.expiresAt ? (
                    <span title={String(e.expiresAt)}>
                      {formatIso(e.expiresAt)}
                    </span>
                  ) : (
                    <span className="muted">never</span>
                  )}
                </td>
                <td>
                  <div className="row-actions">
                    {e.role !== NO_ADMIN_ROLE && (
                      <button
                        type="button"
                        className="secondary"
                        disabled={own !== null && !own.other}
                        title={
                          own === null
                            ? undefined
                            : own.other
                              ? "Single-administrator mode: your passkey gesture, bound to this change, is asked for (VTI-ACL-052)"
                              : (own.why ?? undefined)
                        }
                        onClick={() => setEditing(e)}
                      >
                        Edit
                      </button>
                    )}
                    <button
                      type="button"
                      className="secondary destructive"
                      disabled={revoke.isPending || own !== null}
                      title={
                        own !== null
                          ? "You cannot revoke your own entry (VTI-ACL-052) — another administrator can"
                          : undefined
                      }
                      onClick={async () => {
                        const ok = await confirm({
                          title: "Revoke ACL entry?",
                          message: isUnrestricted(e)
                            ? `${e.subject} is an unrestricted administrator. With nobody else to consent, the removal waits out a cooling-off, during which they are suspended — their entry authorizes nothing — and you can cancel it. Otherwise another administrator approves it.`
                            : `${e.subject} loses access immediately. This cannot be undone.`,
                          confirmLabel: "Revoke",
                          destructive: true,
                        });
                        if (ok) revoke.mutate(e.subject);
                      }}
                    >
                      Revoke
                    </button>
                    {mayRemoveNow && (
                      <button
                        type="button"
                        className="secondary destructive"
                        disabled={removeNow.isPending}
                        title="Single-administrator mode: remove at once, without the cooling-off — after typing their DID and a passkey gesture bound to this removal"
                        onClick={() => setRemovingNow(e)}
                      >
                        Remove now
                      </button>
                    )}
                  </div>
                  {own && !own.other && e.role !== NO_ADMIN_ROLE && (
                    <p className="muted own-entry-note">{own.why}</p>
                  )}
                </td>
              </tr>
            );
          })}
        </DataTable>
      </section>

      <InvitesPanel />
    </section>
  );
}

/**
 * What an entry may administer. "everything" only for a community
 * administrator holding its full ceiling, and "nothing" for no administrative
 * role — never one word for both (#746).
 */
function AuthorityCell({ entry }: { entry: AclEntry }) {
  const text = describeAuthority(entry);
  if (text === "everything") return <strong>everything</strong>;
  if (text === "nothing") return <span className="muted">nothing</span>;
  if (entry.capabilities.scope === "listed" && entry.act.scope === "all") {
    return (
      <>
        {entry.capabilities.grants.map((g) => (
          <code key={grantLabel(g)} className="chip">
            {grantLabel(g)}
          </code>
        ))}
      </>
    );
  }
  return <span>{text}</span>;
}

// ─────────────────────────────────────────────────────────────
// Admin invites
// ─────────────────────────────────────────────────────────────

function InvitesPanel() {
  const queryClient = useQueryClient();
  const toast = useToast();
  const confirm = useConfirm();
  const confirmGesture = gestureFromConfirm(confirm);
  const [showCreate, setShowCreate] = useState(false);
  const [regenerated, setRegenerated] = useState<CreateInviteResponse | null>(
    null,
  );

  const query = useQuery({
    queryKey: ["admin-invites"],
    queryFn: fetchInvites,
  });

  const revoke = useMutation({
    mutationFn: revokeInvite,
    onSuccess: (_, jti) => {
      toast.push("success", `Removed invite ${shorten(jti)}`);
      void queryClient.invalidateQueries({ queryKey: ["admin-invites"] });
    },
    onError: (err) => toast.pushFromError(err, "Remove failed"),
  });

  const regenerate = useMutation({
    mutationFn: async (args: { oldJti: string; targetDid: string }) => {
      // Mint a fresh invite first so a failure here leaves the
      // existing invite intact — the operator can retry without
      // losing access to a working URL. Only after the new invite
      // is in hand do we revoke the old one.
      const fresh = await createInvite({ did: args.targetDid }, confirmGesture);
      try {
        await revokeInvite(args.oldJti);
      } catch (err) {
        // Surface the warning but keep the new invite: the worst
        // case is two valid invites for the same DID, which is
        // not a security regression (the new code is required to
        // claim either one).
        toast.push(
          "info",
          `New invite minted but old one (${shorten(args.oldJti)}) wasn't revoked: ${
            (err as Error).message
          }`,
        );
      }
      return fresh;
    },
    onSuccess: (fresh, args) => {
      toast.push("success", `Regenerated invite for ${args.targetDid}`);
      void queryClient.invalidateQueries({ queryKey: ["admin-invites"] });
      setRegenerated(fresh);
    },
    onError: (err) => toast.pushFromError(err, "Regenerate failed"),
  });

  const invites = query.data?.invites ?? [];

  return (
    <>
      <section className="card">
        <div className="toolbar">
          <h3 className="acl-invites-title">Admin invites</h3>
          <p className="lead acl-invites-lead">
            Mint one-shot install URLs for new community administrators.
            Each invite grants its <code>did</code> the community-admin
            role on first passkey claim.
          </p>
          <button
            type="button"
            className={showCreate ? "secondary" : "primary"}
            onClick={() => setShowCreate((v) => !v)}
          >
            {showCreate ? (
              <>
                <X size={14} aria-hidden="true" /> Cancel
              </>
            ) : (
              <>
                <Plus size={14} aria-hidden="true" /> Invite admin
              </>
            )}
          </button>
        </div>
      </section>

      {showCreate && (
        <CreateInviteForm onClose={() => setShowCreate(false)} />
      )}

      {query.error && (
        <section className="card error">
          <h3>Failed to load invites</h3>
          <p>{(query.error as Error).message}</p>
        </section>
      )}

      <section className="card">
        <DataTable
          columns={[
            { key: "target-did", label: "Target DID" },
            { key: "jti", label: "JTI" },
            { key: "status", label: "Status" },
            { key: "expires-consumed", label: "Expires / consumed" },
            { key: "actions", label: "" },
          ]}
        >
          {query.isPending && (
            <tr>
              <td colSpan={5}>Loading…</td>
            </tr>
          )}
          {!query.isPending && invites.length === 0 && (
            <tr>
              <td colSpan={5}>
                <EmptyState icon={Mail} title="No outstanding invites">
                  Use <strong>Invite admin</strong> to mint an install URL.
                </EmptyState>
              </td>
            </tr>
          )}
          {invites.map((i) => (
            <tr key={i.jti}>
              <td>
                {i.targetDid ? (
                  <code title={i.targetDid}>{shortenDid(i.targetDid)}</code>
                ) : (
                  <span className="muted">unknown</span>
                )}
              </td>
              <td>
                <code className="truncate" title={i.jti}>
                  {shorten(i.jti)}
                </code>
              </td>
              <td>
                <span className={`chip ${chipForStatus(i.status)}`}>
                  {i.status}
                </span>
              </td>
              <td>
                {i.status === "consumed" && i.consumedAt
                  ? `consumed ${formatIso(i.consumedAt)}`
                  : i.expiresAt
                    ? formatIso(i.expiresAt)
                    : "—"}
              </td>
              <td>
                <div className="row-actions">
                  <button
                    type="button"
                    className="secondary"
                    disabled={
                      regenerate.isPending ||
                      i.status === "consumed" ||
                      !i.targetDid
                    }
                    title={
                      i.status === "consumed"
                        ? "Consumed invites cannot be regenerated"
                        : !i.targetDid
                          ? "Legacy invite — no stored target DID, revoke instead"
                          : "Revoke this invite and mint a fresh URL + claim code for the same DID"
                    }
                    onClick={async () => {
                      if (!i.targetDid) return;
                      const ok = await confirm({
                        title: `Regenerate invite for ${i.targetDid}?`,
                        message: `Revokes ${shorten(i.jti)} and mints a fresh URL + claim code. The old install URL stops working immediately.`,
                        confirmLabel: "Regenerate",
                      });
                      if (ok) {
                        regenerate.mutate({
                          oldJti: i.jti,
                          targetDid: i.targetDid,
                        });
                      }
                    }}
                  >
                    <RefreshCw size={12} aria-hidden="true" />{" "}
                    Regenerate
                  </button>
                  <button
                    type="button"
                    className="secondary destructive"
                    disabled={revoke.isPending}
                    title={
                      i.status === "issued"
                        ? "Revoke this invite — the install URL stops working immediately"
                        : "Remove this row from the list (the install URL is already inert)"
                    }
                    onClick={async () => {
                      const isIssued = i.status === "issued";
                      const ok = await confirm({
                        title: isIssued
                          ? `Revoke invite ${shorten(i.jti)}?`
                          : `Remove ${i.status} invite?`,
                        message: isIssued
                          ? "The install URL stops working immediately."
                          : `${shorten(i.jti)} will be cleared from the list. The install URL is already inert.`,
                        confirmLabel: isIssued ? "Revoke" : "Remove",
                        destructive: true,
                      });
                      if (ok) revoke.mutate(i.jti);
                    }}
                  >
                    {i.status === "issued" ? "Revoke" : "Remove"}
                  </button>
                </div>
              </td>
            </tr>
          ))}
        </DataTable>
      </section>

      {regenerated && (
        <RegeneratedInviteCard
          invite={regenerated}
          onDismiss={() => setRegenerated(null)}
        />
      )}
    </>
  );
}

function CreateInviteForm({ onClose }: { onClose: () => void }) {
  const [did, setDid] = useState("");
  const [label, setLabel] = useState("");
  const [ttlMinutes, setTtlMinutes] = useState("15");
  const [issued, setIssued] = useState<CreateInviteResponse | null>(null);
  const toast = useToast();
  const queryClient = useQueryClient();
  const confirmGesture = gestureFromConfirm(useConfirm());

  const mutation = useMutation({
    mutationFn: (req: CreateInviteRequest) => createInvite(req, confirmGesture),
    onSuccess: (resp) => {
      // Refresh the list + ACL tables in the background so the new
      // row shows up after the operator dismisses the success card.
      // Do NOT close the form here — the install URL + claim code
      // are returned exactly once and must remain on screen until
      // the operator copies them.
      void queryClient.invalidateQueries({ queryKey: ["admin-invites"] });
      void queryClient.invalidateQueries({ queryKey: ["acl"] });
      setIssued(resp);
      toast.push(
        "success",
        resp.aclEntryCreated
          ? `Invited ${did} (ACL admin grant created)`
          : `Invited ${did} (ACL already had admin grant)`,
      );
    },
    onError: (err) => {
      // A parked invite is a success: the toast links to the action, whose
      // completed card shows the install URL and claim code.
      toast.pushFromError(err, "Invite failed");
      if (parkedOf(err)) onClose();
    },
  });

  const onSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    const ttl = Number(ttlMinutes);
    mutation.mutate({
      did: did.trim(),
      ttlSeconds: Number.isFinite(ttl) && ttl > 0 ? ttl * 60 : undefined,
      label: label.trim() === "" ? undefined : label.trim(),
    });
  };

  if (issued) {
    return (
      <section className="card">
        <h3>Invite minted</h3>
        <p className="lead">
          Send the install URL and claim code to the new admin{" "}
          <strong>through separate channels</strong> (URL via Slack,
          code via Signal — whatever doesn't share the same
          attacker view). Both are required to claim the passkey.
          Expires <strong>{formatIso(issued.expiresAt)}</strong>.
        </p>
        <Field label="Install URL">
          <input type="text" readOnly value={issued.installUrl} />
        </Field>
        <Field label="Claim code (shown once — copy it now)">
          <input type="text" readOnly value={issued.claimCode} />
        </Field>
        <div className="form-actions">
          <button
            type="button"
            className="primary"
            onClick={() => {
              void navigator.clipboard
                .writeText(issued.installUrl)
                .then(() => toast.push("success", "Install URL copied"))
                .catch(() => toast.push("error", "Clipboard write failed"));
            }}
          >
            <Copy size={14} aria-hidden="true" /> Copy URL
          </button>
          <button
            type="button"
            className="primary"
            onClick={() => {
              void navigator.clipboard
                .writeText(issued.claimCode)
                .then(() => toast.push("success", "Claim code copied"))
                .catch(() => toast.push("error", "Clipboard write failed"));
            }}
          >
            <Copy size={14} aria-hidden="true" /> Copy claim code
          </button>
          <button
            type="button"
            className="secondary"
            onClick={() => setIssued(null)}
          >
            Mint another
          </button>
          <button type="button" className="secondary" onClick={onClose}>
            Done
          </button>
        </div>
      </section>
    );
  }

  return (
    <form onSubmit={onSubmit} className="card form-stack">
      <h3>Invite a new admin</h3>
      <p className="lead">
        Mirrors the <code>vtc admin invite</code> CLI: ensures a
        community-admin grant for the DID, then mints a single-use install
        URL the recipient claims with a passkey.
      </p>
      <Field label="DID">
        <input
          type="text"
          placeholder="did:key:z6Mk…"
          value={did}
          onChange={(e) => setDid(e.target.value)}
          required
        />
      </Field>
      <Field label="Label (optional)">
        <input
          type="text"
          placeholder="e.g. ‘Sara — ops on-call’"
          value={label}
          onChange={(e) => setLabel(e.target.value)}
        />
      </Field>
      <Field label="TTL (minutes; max 1440)">
        <input
          type="number"
          min={1}
          max={1440}
          value={ttlMinutes}
          onChange={(e) => setTtlMinutes(e.target.value)}
          required
        />
      </Field>

      <div className="form-actions">
        <button type="submit" className="primary" disabled={mutation.isPending}>
          {mutation.isPending ? "Minting…" : "Mint invite"}
        </button>
      </div>
    </form>
  );
}

function RegeneratedInviteCard({
  invite,
  onDismiss,
}: {
  invite: CreateInviteResponse;
  onDismiss: () => void;
}) {
  const toast = useToast();
  return (
    <section className="card">
      <h3>Regenerated invite</h3>
      <p className="lead">
        Fresh single-use URL + claim code minted. The previous
        invite has been revoked. Deliver these to the new admin
        through <strong>separate channels</strong> (URL via Slack,
        code via Signal — whatever doesn't share the same attacker
        view). Both are required to claim the passkey. Expires{" "}
        <strong>{formatIso(invite.expiresAt)}</strong>.
      </p>
      <Field label="Install URL">
        <input type="text" readOnly value={invite.installUrl} />
      </Field>
      <Field label="Claim code (shown once — copy it now)">
        <input type="text" readOnly value={invite.claimCode} />
      </Field>
      <div className="form-actions">
        <button
          type="button"
          className="primary"
          onClick={() => {
            void navigator.clipboard
              .writeText(invite.installUrl)
              .then(() => toast.push("success", "Install URL copied"))
              .catch(() => toast.push("error", "Clipboard write failed"));
          }}
        >
          <Copy size={14} aria-hidden="true" /> Copy URL
        </button>
        <button
          type="button"
          className="primary"
          onClick={() => {
            void navigator.clipboard
              .writeText(invite.claimCode)
              .then(() => toast.push("success", "Claim code copied"))
              .catch(() => toast.push("error", "Clipboard write failed"));
          }}
        >
          <Copy size={14} aria-hidden="true" /> Copy claim code
        </button>
        <button type="button" className="secondary" onClick={onDismiss}>
          Done
        </button>
      </div>
    </section>
  );
}

function chipForStatus(status: InviteSummary["status"]): string {
  switch (status) {
    case "issued":
      return "accent";
    case "consumed":
      return "success";
    case "expired":
      return "warning";
  }
}

/**
 * Pick capabilities from a role's ceiling, each optionally at a resource. An
 * empty selection means the role's full ceiling (nothing narrowed) — except
 * for a role held only at a resource, where every pick needs one.
 */
function CapabilityPicker({
  role,
  selected,
  onChange,
}: {
  role: string;
  selected: Record<string, string | null>;
  onChange: (next: Record<string, string | null>) => void;
}) {
  const info = adminRoleInfo(role);
  if (!info || info.approveOnly) return null;
  return (
    <fieldset className="field cap-picker">
      <legend className="field-label">
        {info.qualifiedOnly
          ? "Capabilities (each needs a resource)"
          : "Narrow to these capabilities (none ticked = the role's full ceiling)"}
      </legend>
      {info.ceiling.map((cap) => {
        const meta = capabilityInfo(cap);
        const ticked = cap in selected;
        return (
          <div key={cap} className="cap-row">
            <label className="checkbox">
              <input
                type="checkbox"
                aria-label={cap}
                checked={ticked}
                onChange={(e) => {
                  const next = { ...selected };
                  if (e.target.checked) next[cap] = null;
                  else delete next[cap];
                  onChange(next);
                }}
              />
              <span className="checkbox-text">
                <code>{cap}</code> <span className="muted">{meta?.gates}</span>
                {meta?.conferring && (
                  <span className="chip warning" title="Granting it needs another holder's approval">
                    confers authority
                  </span>
                )}
              </span>
            </label>
            {ticked && meta && meta.qualifiers.length > 0 && (
              <input
                type="text"
                aria-label={`${cap} resource`}
                placeholder={`${meta.qualifiers.join(" | ")}:…${info.qualifiedOnly ? "" : " (optional)"}`}
                value={selected[cap] ?? ""}
                onChange={(e) =>
                  onChange({ ...selected, [cap]: e.target.value === "" ? null : e.target.value })
                }
              />
            )}
          </div>
        );
      })}
    </fieldset>
  );
}

/** The picker's selection as `cap` / `cap@resource` strings. */
const pickedCapabilities = (selected: Record<string, string | null>): string[] =>
  Object.entries(selected).map(([cap, res]) => (res ? `${cap}@${res.trim()}` : cap));

function CreateAclForm({ onSuccess }: { onSuccess: () => void }) {
  const [did, setDid] = useState("");
  const [role, setRole] = useState<string>(NO_ADMIN_ROLE);
  const [selected, setSelected] = useState<Record<string, string | null>>({});
  const [approve, setApprove] = useState(false);
  const [label, setLabel] = useState("");
  const [expiresAt, setExpiresAt] = useState("");
  const toast = useToast();
  const confirmGesture = gestureFromConfirm(useConfirm());

  const mutation = useMutation({
    mutationFn: (req: AclGrantRequest) => createAcl(req, confirmGesture),
    onSuccess: (entry) => {
      toast.push("success", `Created ACL entry for ${entry.subject}`);
      onSuccess();
    },
    onError: (err) => {
      // A parked grant is a success: the toast says so, and the form closes.
      toast.pushFromError(err, "Create failed");
      if (parkedOf(err)) onSuccess();
    },
  });

  const info = adminRoleInfo(role);
  const confers = pickedOrCeiling(role, selected).some((c) => capabilityInfo(c)?.conferring);

  const onSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    const exp = expiresAt.trim();
    mutation.mutate(
      grantRequest({
        subject: did.trim(),
        role,
        capabilities: pickedCapabilities(selected),
        approve,
        // Blank optional fields are omitted, not null: the payload schema
        // types `label` and `expiresAt` as strings, so null is a 400.
        label: label.trim() === "" ? undefined : label.trim(),
        // Canonical `expiresAt` is RFC3339. Accept either an ISO string or a
        // unix epoch typed by the operator and normalise.
        expiresAt:
          exp === ""
            ? undefined
            : /^\d+$/.test(exp)
              ? new Date(Number(exp) * 1000).toISOString()
              : exp,
      }),
    );
  };

  return (
    <form onSubmit={onSubmit} className="card form-stack">
      <h3>New ACL entry</h3>
      <Field label="DID">
        <input
          type="text"
          placeholder="did:key:z6Mk…"
          value={did}
          onChange={(e) => setDid(e.target.value)}
          required
        />
      </Field>
      <Field label="Administrative role">
        <select
          aria-label="Administrative role"
          value={role}
          onChange={(e) => {
            setRole(e.target.value);
            setSelected({});
          }}
        >
          <option value={NO_ADMIN_ROLE}>none — a member with no administrative role</option>
          {ADMIN_ROLES.map((r) => (
            <option key={r.id} value={r.id}>
              {r.title} ({r.id})
            </option>
          ))}
        </select>
        {confers && (
          <p className="muted">
            This role gives authority to create authority. Granting it asks for
            your passkey, then waits for another holder's approval.
          </p>
        )}
      </Field>
      <CapabilityPicker role={role} selected={selected} onChange={setSelected} />
      {info && !info.approveOnly && (
        <label className="checkbox">
          <input
            type="checkbox"
            checked={approve}
            onChange={(e) => setApprove(e.target.checked)}
          />
          <span className="checkbox-text">May approve others' actions within this role</span>
        </label>
      )}
      <Field label="Label (optional)">
        <input
          type="text"
          placeholder="e.g. ‘Ops on-call rotation 2026 Q1’"
          value={label}
          onChange={(e) => setLabel(e.target.value)}
        />
      </Field>
      <Field label="Expires at (unix seconds; blank = never)">
        <input
          type="number"
          placeholder="1735689600"
          value={expiresAt}
          onChange={(e) => setExpiresAt(e.target.value)}
        />
      </Field>

      <div className="form-actions">
        <button type="submit" className="primary" disabled={mutation.isPending}>
          {mutation.isPending ? "Creating…" : "Create entry"}
        </button>
      </div>
    </form>
  );
}

/** The capabilities a create form would grant: the ticked ones, or the
 *  role's ceiling when none is ticked. */
function pickedOrCeiling(role: string, selected: Record<string, string | null>): string[] {
  const picked = Object.keys(selected);
  return picked.length > 0 ? picked : (adminRoleInfo(role)?.ceiling ?? []);
}

/** The picker's starting selection for an entry's capability scope. */
function selectionOf(scope: CapabilityScope): Record<string, string | null> {
  if (scope.scope !== "listed") return {};
  return Object.fromEntries(scope.grants.map((g) => [g.capability, g.resource ?? null]));
}

/**
 * Narrow or widen an existing entry's capabilities (`acl/update/0.2`).
 * Narrowing an administrator asks for your passkey, and taking an
 * authority-conferring capability away another holder's approval; widening
 * asks for your passkey, and an authority-conferring capability its other
 * holders' approval. Saving unchanged re-affirms a delegation under review.
 */
function EditCapabilitiesForm({ entry, onDone }: { entry: AclEntry; onDone: () => void }) {
  const [selected, setSelected] = useState<Record<string, string | null>>(
    selectionOf(entry.capabilities),
  );
  const toast = useToast();
  const confirmGesture = gestureFromConfirm(useConfirm());
  const mutation = useMutation({
    mutationFn: () => {
      const picked = pickedCapabilities(selected);
      const capabilities: CapabilityScope =
        picked.length === 0
          ? { scope: "ceiling" }
          : grantRequest({ subject: entry.subject, role: entry.role, capabilities: picked }).entry
              .capabilities;
      return updateAcl(
        { subject: entry.subject, capabilities, reason: "capabilities edited in the admin UI" },
        confirmGesture,
      );
    },
    onSuccess: () => {
      toast.push("success", `Updated ${entry.subject}`);
      onDone();
    },
    onError: (err) => {
      toast.pushFromError(err, "Update failed");
      if (parkedOf(err)) onDone();
    },
  });
  return (
    <form
      className="card form-stack"
      onSubmit={(e) => {
        e.preventDefault();
        mutation.mutate();
      }}
    >
      <h3>
        Edit <code>{shortenDid(entry.subject)}</code> — <code>{entry.role}</code>
      </h3>
      <p className="muted">Holds now: {describeAuthority(entry)}</p>
      <CapabilityPicker role={entry.role} selected={selected} onChange={setSelected} />
      <div className="form-actions">
        <button type="submit" className="primary" disabled={mutation.isPending}>
          {mutation.isPending ? "Saving…" : "Save"}
        </button>
        <button type="button" className="secondary" onClick={onDone}>
          Cancel
        </button>
      </div>
    </form>
  );
}

function EditableLabelCell({
  entry,
  label,
}: {
  entry: AclEntry;
  label: string | null;
}) {
  const queryClient = useQueryClient();
  const toast = useToast();
  const [editing, setEditing] = useState(false);
  const [draft, setDraft] = useState(label ?? "");
  const confirmGesture = gestureFromConfirm(useConfirm());

  const mutation = useMutation({
    mutationFn: (args: { entry: AclEntry; label: string }) =>
      patchAclLabel({ ...args, confirmGesture }),
    onSuccess: () => {
      toast.push("success", "Label updated");
      void queryClient.invalidateQueries({ queryKey: ["acl"] });
      setEditing(false);
    },
    onError: (err) => {
      toast.pushFromError(err, "Label update failed");
      // Stay in edit mode so the operator can fix and retry.
    },
  });

  // Seed the draft whenever the prop changes from below (e.g.
  // another browser updated the entry) — but only when not
  // actively editing, so we don't clobber the operator's typing.
  // Previously a setState-during-render which fires a second
  // render every time `label` arrived fresh and loops under
  // StrictMode. useEffect runs after commit so the loop closes.
  useEffect(() => {
    if (!editing) {
      setDraft(label ?? "");
    }
    // `editing` is intentionally excluded — re-syncing while the
    // operator is typing would clobber their input.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [label]);

  const commit = () => {
    const next = draft.trim();
    // No-op on unchanged value.
    if (next === (label ?? "")) {
      setEditing(false);
      return;
    }
    mutation.mutate({ entry, label: next });
  };

  const cancel = () => {
    setDraft(label ?? "");
    setEditing(false);
    mutation.reset();
  };

  if (editing) {
    return (
      <input
        type="text"
        value={draft}
        autoFocus
        disabled={mutation.isPending}
        onChange={(e) => setDraft(e.target.value)}
        onBlur={commit}
        onKeyDown={(e) => {
          if (e.key === "Enter") {
            e.preventDefault();
            commit();
          } else if (e.key === "Escape") {
            e.preventDefault();
            cancel();
          }
        }}
        // Inline edit shouldn't take the full default 36px height
        // — match the surrounding row.
        className="acl-label-input"
      />
    );
  }

  return (
    <button
      type="button"
      onClick={() => setEditing(true)}
      title="Click to edit label"
      // Reuse `button.link` styling so it blends with the row;
      // a normal button would render as a chunky default button.
      className={`link acl-label-edit${label ? "" : " empty"}`}
    >
      {label ?? <em>add label</em>}
      <Pencil size={12} aria-hidden="true" className="acl-label-pencil" />
    </button>
  );
}
