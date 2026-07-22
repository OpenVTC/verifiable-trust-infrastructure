// ACL plugin — list + create + revoke.
//
// Wraps the `/v1/acl` endpoint family. List supports an optional
// context filter (server-side). Create form takes DID, role,
// optional label + allowed contexts + expires_at. Revoke is a
// DELETE on the entry's DID. Edit (PATCH) lands in a follow-up if
// needed — operators can also revoke + recreate today.

import { useEffect, useState } from "react";
import {
  useMutation,
  useQuery,
  useQueryClient,
} from "@tanstack/react-query";
import { Copy, Mail, Pencil, Plus, RefreshCw, ShieldCheck, X } from "lucide-react";

import { deleteJson, getJson, postJson } from "@/lib/api";
import { useConfirm } from "@/components/ConfirmDialog";
import { Field } from "@/components/Field";
import { formatIso, shorten, shortenDid } from "@/lib/format";
import { useToast } from "@/lib/toast";

// One canonical task per verb (the two combined `acl/legacy/*` tasks
// were retired in phase 2d).
const TRUST_TASK_LIST = "https://trusttasks.org/spec/acl/list/0.1";
const TRUST_TASK_GRANT = "https://trusttasks.org/spec/acl/grant/0.1";
const TRUST_TASK_REVOKE = "https://trusttasks.org/spec/acl/revoke/0.1";
const TRUST_TASK_INVITES_MANAGE =
  "https://trusttasks.org/openvtc/vtc/admin/invites/manage/1.0";
const TRUST_TASK_INVITES_REVOKE =
  "https://trusttasks.org/openvtc/vtc/admin/invites/revoke/1.0";

// Canonical `acl/_shared` AclEntry. `did` -> `subject`,
// `allowed_contexts` -> `scopes`, and every timestamp is now an
// RFC3339 string rather than a unix epoch.
interface AclEntry {
  subject: string;
  role: string;
  label?: string | null;
  scopes: string[];
  createdAt: string;
  createdBy: string;
  updatedAt?: string | null;
  updatedBy?: string | null;
  expiresAt?: string | null;
}

interface AclListResponse {
  entries: AclEntry[];
  truncated: boolean;
  cursor?: string | null;
}

// `acl/grant` wraps the entry; server-owned provenance is not settable.
interface CreateAclRequest {
  entry: {
    subject: string;
    role: string;
    label?: string | null;
    scopes: string[];
    expiresAt?: string | null;
  };
  reason?: string;
}

async function fetchAcl(scope: string | null): Promise<AclListResponse> {
  const q = new URLSearchParams();
  if (scope) q.set("scope", scope);
  const suffix = q.toString();
  return getJson<AclListResponse>(`/v1/acl${suffix ? `?${suffix}` : ""}`, {
    trustTask: TRUST_TASK_LIST,
  });
}

async function createAcl(req: CreateAclRequest): Promise<AclEntry> {
  return postJson<AclEntry>("/v1/acl", req, { trustTask: TRUST_TASK_GRANT });
}

async function deleteAcl(subject: string): Promise<void> {
  await deleteJson<unknown>(`/v1/acl/${encodeURIComponent(subject)}`, {
    trustTask: TRUST_TASK_REVOKE,
  });
}

// A label edit is not a role change, so it goes through `acl/grant`
// re-stating the entry with its existing role — `acl/change-role` is
// role-only and would reject this.
async function patchAclLabel(args: {
  entry: AclEntry;
  label: string;
}): Promise<AclEntry> {
  return postJson<AclEntry>(
    "/v1/acl",
    {
      entry: {
        subject: args.entry.subject,
        role: args.entry.role,
        label: args.label,
        scopes: args.entry.scopes,
        expiresAt: args.entry.expiresAt ?? null,
      },
      reason: "label updated from the admin UI",
    },
    { trustTask: TRUST_TASK_GRANT },
  );
}

// ── Admin invites ────────────────────────────────────────────

interface InviteSummary {
  jti: string;
  status: "issued" | "consumed" | "expired";
  /**
   * Admin DID the invite was minted for. Missing on legacy rows
   * from before the daemon started persisting the target DID;
   * those can be cleared with Revoke (Regenerate can't act on
   * them — there's nothing to re-invite).
   */
  targetDid?: string;
  expiresAt?: string;
  consumedAt?: string;
}

interface InvitesListResponse {
  invites: InviteSummary[];
}

interface CreateInviteRequest {
  did: string;
  ttlSeconds?: number;
  label?: string;
}

interface CreateInviteResponse {
  jti: string;
  installUrl: string;
  /**
   * Out-of-band claim code the invitee must type alongside the URL
   * to claim their passkey. Returned by the daemon once on invite
   * creation; not persisted plaintext. Operators deliver URL and
   * code through separate channels.
   */
  claimCode: string;
  expiresAt: string;
  aclEntryCreated: boolean;
}

async function fetchInvites(): Promise<InvitesListResponse> {
  return getJson<InvitesListResponse>("/v1/admin/invites", {
    trustTask: TRUST_TASK_INVITES_MANAGE,
  });
}

async function createInvite(
  req: CreateInviteRequest,
): Promise<CreateInviteResponse> {
  return postJson<CreateInviteResponse>("/v1/admin/invites", req, {
    trustTask: TRUST_TASK_INVITES_MANAGE,
  });
}

async function revokeInvite(jti: string): Promise<void> {
  await deleteJson<unknown>(`/v1/admin/invites/${encodeURIComponent(jti)}`, {
    trustTask: TRUST_TASK_INVITES_REVOKE,
  });
}

export function Acl() {
  const [contextFilter, setContextFilter] = useState("");
  const [showCreate, setShowCreate] = useState(false);
  const queryClient = useQueryClient();
  const toast = useToast();
  const confirm = useConfirm();

  const query = useQuery({
    queryKey: ["acl", contextFilter],
    queryFn: () => fetchAcl(contextFilter || null),
    placeholderData: (prev) => prev,
  });

  const revoke = useMutation({
    mutationFn: deleteAcl,
    onSuccess: (_, did) => {
      toast.push("success", `Revoked ACL entry for ${did}`);
      void queryClient.invalidateQueries({ queryKey: ["acl"] });
    },
    onError: (err) => toast.pushFromError(err, "Revoke failed"),
  });

  return (
    <section className="page">
      <h2>Access control</h2>

      <section className="card">
        <div className="toolbar">
          <label className="field inline">
            <span className="field-label">Filter by context</span>
            <input
              type="search"
              placeholder="default / ctx-prod / …"
              value={contextFilter}
              onChange={(e) => setContextFilter(e.target.value)}
            />
          </label>
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

      {query.error && (
        <section className="card error">
          <h3>Failed to load ACL</h3>
          <p>{(query.error as Error).message}</p>
        </section>
      )}

      <section className="card">
        <table className="data-table">
          <thead>
            <tr>
              <th>DID</th>
              <th>Role</th>
              <th>Label</th>
              <th>Contexts</th>
              <th>Expires</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {query.isPending && (
              <tr>
                <td colSpan={6}>Loading…</td>
              </tr>
            )}
            {query.data?.entries.length === 0 && (
              <tr>
                <td colSpan={6}>
                  <div className="empty-state">
                    <span className="empty-icon" aria-hidden="true">
                      <ShieldCheck />
                    </span>
                    <h4>No ACL entries match this filter</h4>
                    <p>
                      Use <strong>Add entry</strong> to grant access,
                      or clear the context filter to see every entry.
                    </p>
                  </div>
                </td>
              </tr>
            )}
            {query.data?.entries.map((e) => (
              <tr key={e.subject}>
                <td>
                  <code title={e.subject}>{shortenDid(e.subject)}</code>
                </td>
                <td>
                  <code>{e.role}</code>
                </td>
                <td>
                  <EditableLabelCell entry={e} label={e.label ?? null} />
                </td>
                <td>
                  {e.scopes.length === 0 ? (
                    <span className="muted">all</span>
                  ) : (
                    e.scopes.map((c) => (
                      <code key={c} className="chip">
                        {c}
                      </code>
                    ))
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
                  <button
                    type="button"
                    className="secondary destructive"
                    disabled={revoke.isPending}
                    onClick={async () => {
                      const ok = await confirm({
                        title: "Revoke ACL entry?",
                        message: `${e.subject} loses access immediately. This cannot be undone.`,
                        confirmLabel: "Revoke",
                        destructive: true,
                      });
                      if (ok) revoke.mutate(e.subject);
                    }}
                  >
                    Revoke
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>

      <InvitesPanel />
    </section>
  );
}

// ─────────────────────────────────────────────────────────────
// Admin invites
// ─────────────────────────────────────────────────────────────

function InvitesPanel() {
  const queryClient = useQueryClient();
  const toast = useToast();
  const confirm = useConfirm();
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
      const fresh = await createInvite({ did: args.targetDid });
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
          <h3 style={{ margin: 0 }}>Admin invites</h3>
          <p className="lead" style={{ margin: 0, flex: "1 1 auto" }}>
            Mint one-shot install URLs for new admins. Each invite
            grants its <code>did</code> the Admin role on first
            passkey claim.
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
        <table className="data-table">
          <thead>
            <tr>
              <th>Target DID</th>
              <th>JTI</th>
              <th>Status</th>
              <th>Expires / consumed</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {query.isPending && (
              <tr>
                <td colSpan={5}>Loading…</td>
              </tr>
            )}
            {!query.isPending && invites.length === 0 && (
              <tr>
                <td colSpan={5}>
                  <div className="empty-state">
                    <span className="empty-icon" aria-hidden="true">
                      <Mail />
                    </span>
                    <h4>No outstanding invites</h4>
                    <p>Use <strong>Invite admin</strong> to mint an install URL.</p>
                  </div>
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
          </tbody>
        </table>
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

  const mutation = useMutation({
    mutationFn: createInvite,
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
    onError: (err) => toast.pushFromError(err, "Invite failed"),
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
        Mirrors the <code>vtc admin invite</code> CLI: ensures an
        Admin ACL grant for the DID, then mints a single-use install
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
      <label className="field">
        <span className="field-label">Install URL</span>
        <input type="text" readOnly value={invite.installUrl} />
      </label>
      <label className="field">
        <span className="field-label">
          Claim code (shown once — copy it now)
        </span>
        <input type="text" readOnly value={invite.claimCode} />
      </label>
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

function CreateAclForm({ onSuccess }: { onSuccess: () => void }) {
  const [did, setDid] = useState("");
  const [role, setRole] = useState("member");
  const [label, setLabel] = useState("");
  const [contexts, setContexts] = useState("");
  const [expiresAt, setExpiresAt] = useState("");
  const toast = useToast();

  const mutation = useMutation({
    mutationFn: createAcl,
    onSuccess: (entry) => {
      toast.push("success", `Created ACL entry for ${entry.subject}`);
      onSuccess();
    },
    onError: (err) => toast.pushFromError(err, "Create failed"),
  });

  const onSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    const scopes = contexts
      .split(",")
      .map((c) => c.trim())
      .filter((c) => c.length > 0);
    const exp = expiresAt.trim();
    mutation.mutate({
      entry: {
        subject: did.trim(),
        role: role.trim(),
        label: label.trim() === "" ? null : label.trim(),
        scopes,
        // Canonical `expiresAt` is RFC3339. Accept either an ISO
        // string or a unix epoch typed by the operator and normalise,
        // rather than sending an integer the server now rejects.
        expiresAt:
          exp === ""
            ? null
            : /^\d+$/.test(exp)
              ? new Date(Number(exp) * 1000).toISOString()
              : exp,
      },
    });
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
      <Field label="Role">
        <input
          type="text"
          placeholder="admin / moderator / member / custom:editor"
          value={role}
          onChange={(e) => setRole(e.target.value)}
          required
        />
      </Field>
      <Field label="Label (optional)">
        <input
          type="text"
          placeholder="e.g. ‘Ops on-call rotation 2026 Q1’"
          value={label}
          onChange={(e) => setLabel(e.target.value)}
        />
      </Field>
      <Field label="Allowed contexts (comma-separated; blank = all)">
        <input
          type="text"
          placeholder="default, ctx-prod"
          value={contexts}
          onChange={(e) => setContexts(e.target.value)}
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

  const mutation = useMutation({
    mutationFn: patchAclLabel,
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
        style={{ height: 28, padding: "0 8px" }}
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
      className="link"
      style={{
        display: "inline-flex",
        alignItems: "center",
        gap: 6,
        color: label ? "inherit" : "var(--text-muted)",
        textAlign: "left",
        font: "inherit",
      }}
    >
      {label ?? <em>add label</em>}
      <Pencil size={12} aria-hidden="true" style={{ opacity: 0.5 }} />
    </button>
  );
}
