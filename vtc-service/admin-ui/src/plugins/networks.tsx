// Networks — this community's memberships of Verifiable Trust Networks
// (`vtc/networks/*/0.2`, docs/03-vtc/networks.md), for holders of
// `vtc.config.admin`.
//
// A network lists a community first (VTI-VTN-010) and sends its administrators
// an invitation: the network's URL and DID, often as a link to this page,
// `/admin/networks?join=<url>&network=<did>`. Joining is the community's
// acknowledgement, and the credential exchange (VTI-VTN-013): the community
// verifies the network's listing of it, registers one of its groups for each of
// the network's roles, signs the acknowledgement of the network's offer, and
// verifies the membership grant the network answers with. Every write is the
// community signing a statement to the network, so the VTC asks for the
// administrator's step-up bound to that one document — after every check that
// would refuse it, so a join that cannot succeed costs no gesture.

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Network as NetworkIcon } from "lucide-react";
import { useEffect, useState } from "react";
import { useSearchParams } from "react-router-dom";

import { useConfirm } from "@/components/ConfirmDialog";
import { DidText } from "@/components/DidText";
import { EmptyState } from "@/components/EmptyState";
import { Field } from "@/components/Field";
import { PageHeader } from "@/components/PageHeader";
import { formatIso } from "@/lib/format";
import { listGroups } from "@/lib/groups";
import {
  STATE_LABEL,
  invitationOf,
  joinDraftErrors,
  joinNetwork,
  joinPayload,
  leaveNetwork,
  listNetworks,
  networkKeys,
  networkRefusal,
  previewable,
  previewNetwork,
  repudiateNetwork,
  showNetwork,
  unassignedRoleOf,
  withRequiredRoles,
  type RoleRow,
} from "@/lib/networks";
import { gestureFromConfirm, GestureDeclinedError, parkedOf } from "@/lib/signed-act";
import { useToast } from "@/lib/toast";
import type { NetworkMembership, NetworkPreviewResponse } from "@/lib/wire-types";
import { messageOf } from "@/lib/messages";

const STATE_CHIP: Record<NetworkMembership["state"], string> = {
  acknowledged: "chip success",
  repudiated: "chip warning",
  departed: "chip",
};

/** A refusal as the page shows it: what it means, then the VTC's own words. */
function refusalText(err: unknown): string {
  const meaning = networkRefusal(err);
  const said = messageOf(err);
  return meaning ? `${meaning} (${said})` : said;
}

const ENTRY_STATE_LABEL: Record<string, string> = {
  listed: "Listed, waiting for this community to accept",
  acknowledged: "Member",
  repudiated: "This community rejected the listing",
  suspended: "Membership suspended by the network",
};

/** What the network says about itself, and where this community stands with it, from
 *  `vtc/networks/preview`. */
export function NetworkPreviewCard({ found }: { found: NetworkPreviewResponse }) {
  const required = found.roles.filter((r) => r.required);
  return (
    <section className="card" aria-label="The network">
      <h3>{found.name || "Unnamed network"}</h3>
      {found.description && <p className="muted">{found.description}</p>}
      <dl className="verifier-fields">
        <dt>DID</dt>
        <dd>
          <DidText did={found.network} />
        </dd>
        {found.owner && (
          <>
            <dt>Owner</dt>
            <dd>{found.owner}</dd>
          </>
        )}
        {found.framework && (
          <>
            <dt>Governance</dt>
            <dd>
              {/^https?:\/\//.test(found.framework.iri) ? (
                <a href={found.framework.iri} target="_blank" rel="noopener noreferrer">
                  {found.framework.iri}
                </a>
              ) : (
                found.framework.iri
              )}{" "}
              v{found.framework.version}
            </dd>
          </>
        )}
        <dt>Roles</dt>
        <dd>
          {found.roles.length === 0
            ? "None"
            : found.roles.map((r) => `${r.name}${r.required ? " (required)" : ""}`).join(", ")}
        </dd>
        <dt>This community</dt>
        <dd>
          {found.listed ? (
            <span className={found.entryState === "acknowledged" ? "chip success" : "chip"}>
              {ENTRY_STATE_LABEL[found.entryState ?? "listed"] ?? found.entryState}
            </span>
          ) : (
            <span className="chip warning">Not listed</span>
          )}
        </dd>
      </dl>
      {!found.listed && (
        <p className="warning" role="status">
          This network does not list this community yet, so there is nothing to accept. Ask its
          administrators to invite it first.
          {found.notListedReason ? ` (${found.notListedReason})` : ""}
        </p>
      )}
      {found.listed && required.length > 0 && found.entryState !== "acknowledged" && (
        <p className="muted">
          Assign a group to {required.length === 1 ? "the required role" : "each required role"}{" "}
          below: {required.map((r) => r.name).join(", ")}.
        </p>
      )}
    </section>
  );
}

function Credential({ label, value }: { label: string; value: unknown }) {
  if (!value || typeof value !== "object") return null;
  return (
    <details>
      <summary>{label}</summary>
      <pre>{JSON.stringify(value, null, 2)}</pre>
    </details>
  );
}

function MembershipDetail({ network, onClose }: { network: string; onClose: () => void }) {
  const confirm = useConfirm();
  const toast = useToast();
  const queryClient = useQueryClient();
  const [reason, setReason] = useState("");
  const query = useQuery({
    queryKey: networkKeys.show(network),
    queryFn: () => showNetwork(network),
  });
  const leave = useMutation({
    mutationFn: () => leaveNetwork(network, reason, gestureFromConfirm(confirm)),
    onSuccess: () => {
      toast.push("success", "Left the network.");
      void queryClient.invalidateQueries({ queryKey: networkKeys.all });
    },
    onError: (err) => {
      if (err instanceof GestureDeclinedError) return;
      if (parkedOf(err)) void queryClient.invalidateQueries({ queryKey: ["actions"] });
    },
  });
  const m = query.data;

  const askLeave = async () => {
    const ok = await confirm({
      title: "Leave this network?",
      message:
        "The community repudiates the network's membership grant, and the network revokes " +
        "what it issued for the community. Joining again needs a new listing.",
      confirmLabel: "Leave",
      destructive: true,
    });
    if (ok) leave.mutate();
  };

  return (
    <section className="card" aria-label="Network membership">
      <h3>
        {m?.name ?? "Network"} {m && <span className={STATE_CHIP[m.state]}>{STATE_LABEL[m.state]}</span>}
      </h3>
      {query.isPending && <p>Loading…</p>}
      {query.isError && <p className="error">Could not read the membership: {String(query.error)}</p>}
      {m && (
        <>
          <dl className="verifier-fields">
            <dt>DID</dt>
            <dd>
              <DidText did={m.network} />
            </dd>
            <dt>URL</dt>
            <dd>
              <code>{m.url}</code>
            </dd>
            {m.joinedAt && (
              <>
                <dt>Joined</dt>
                <dd>{formatIso(m.joinedAt)}</dd>
              </>
            )}
            <dt>Updated</dt>
            <dd>{formatIso(m.updatedAt)}</dd>
            <dt>Groups</dt>
            <dd>
              {(m.groups ?? []).length === 0 ? (
                <span className="muted">none registered</span>
              ) : (
                <ul>
                  {(m.groups ?? []).map((g) => (
                    <li key={g.role}>
                      <code>{g.role}</code> → {g.groupId} <DidText did={g.groupDid} />
                    </li>
                  ))}
                </ul>
              )}
            </dd>
          </dl>
          <Credential label="The network's listing of this community" value={m.listing} />
          <Credential label="The network's membership grant" value={m.grant} />
          <Credential label="This community's acknowledgement" value={m.acknowledgement} />
          <Credential label="This community's repudiation" value={m.repudiation} />
          {m.state === "acknowledged" && (
            <>
              <Field label="Reason (kept in this community's audit trail)" htmlFor="leave-reason">
                <input
                  id="leave-reason"
                  value={reason}
                  maxLength={500}
                  onChange={(e) => setReason(e.target.value)}
                />
              </Field>
              {leave.isError && !(leave.error instanceof GestureDeclinedError) && (
                <p className="error" role="alert">
                  {refusalText(leave.error)}
                </p>
              )}
            </>
          )}
        </>
      )}
      <div className="form-actions">
        {m?.state === "acknowledged" && (
          <button
            type="button"
            className="destructive"
            disabled={leave.isPending}
            onClick={() => void askLeave()}
          >
            Leave network
          </button>
        )}
        <button type="button" className="secondary" onClick={onClose}>
          Close
        </button>
      </div>
    </section>
  );
}

function JoinForm({
  initial,
  onDone,
}: {
  initial: { url: string; network: string } | null;
  onDone: () => void;
}) {
  const confirm = useConfirm();
  const toast = useToast();
  const queryClient = useQueryClient();
  const [url, setUrl] = useState(initial?.url ?? "");
  const [network, setNetwork] = useState(initial?.network ?? "");
  const [rows, setRows] = useState<RoleRow[]>([]);
  const [reason, setReason] = useState("");
  const [required, setRequired] = useState<string | null>(null);
  const groups = useQuery({ queryKey: ["groups", "list"], queryFn: listGroups });
  // Only a group with an identity of its own can serve a network's role.
  const eligible = (groups.data ?? []).map((item) => item.group).filter((g) => g.groupDid);

  useEffect(() => {
    if (initial) {
      setUrl(initial.url);
      setNetwork(initial.network);
    }
  }, [initial?.url, initial?.network]); // eslint-disable-line react-hooks/exhaustive-deps

  // Read the network as soon as there is a URL to read, a moment after typing stops.
  const [debounced, setDebounced] = useState({ url: url.trim(), network: network.trim() });
  useEffect(() => {
    const t = window.setTimeout(() => setDebounced({ url: url.trim(), network: network.trim() }), 400);
    return () => window.clearTimeout(t);
  }, [url, network]);
  const preview = useQuery({
    queryKey: networkKeys.preview(debounced.url, debounced.network),
    queryFn: () => previewNetwork(debounced.url, debounced.network),
    enabled: previewable(debounced.url),
    retry: false,
    staleTime: 30_000,
  });
  const found = preview.data;
  // The DID the network answers as fills an empty field; the roles it requires get a row.
  useEffect(() => {
    if (!found) return;
    if (!network.trim()) setNetwork(found.network);
    setRows((rs) => withRequiredRoles(rs, found.roles));
  }, [found]); // eslint-disable-line react-hooks/exhaustive-deps

  const errors = joinDraftErrors(url, network, rows);
  const notListed = found !== undefined && !found.listed;
  const alreadyMember = found?.membershipState === "acknowledged";
  const sendable = Object.keys(errors).length === 0 && !notListed && !alreadyMember;

  const onRefused = (err: unknown) => {
    if (err instanceof GestureDeclinedError) return;
    if (parkedOf(err)) {
      void queryClient.invalidateQueries({ queryKey: ["actions"] });
      return;
    }
    // The network requires a group for a role: add a row for it to fill in.
    const role = unassignedRoleOf(err);
    if (role) {
      setRequired(role);
      setRows((rs) => (rs.some((r) => r.role === role) ? rs : [...rs, { role, groupId: "" }]));
    }
  };

  const join = useMutation({
    mutationFn: () => joinNetwork(joinPayload(url, network, rows), gestureFromConfirm(confirm)),
    onSuccess: () => {
      toast.push("success", "Joined the network: its membership grant is verified and stored.");
      void queryClient.invalidateQueries({ queryKey: networkKeys.all });
      onDone();
    },
    onError: onRefused,
  });
  const repudiate = useMutation({
    mutationFn: () =>
      repudiateNetwork(
        joinPayload(url, network, []).url,
        network.trim(),
        reason,
        gestureFromConfirm(confirm),
      ),
    onSuccess: () => {
      toast.push("success", "Rejected the network's listing.");
      void queryClient.invalidateQueries({ queryKey: networkKeys.all });
      onDone();
    },
    onError: onRefused,
  });

  const askRepudiate = async () => {
    const ok = await confirm({
      title: "Reject this network's listing?",
      message:
        "The community signs a repudiation of the listing, and the network must publish it " +
        "beside the listing (VTI-VTN-012).",
      confirmLabel: "Reject listing",
      destructive: true,
    });
    if (ok) repudiate.mutate();
  };

  const failed = join.isError ? join.error : repudiate.isError ? repudiate.error : null;
  const busy = join.isPending || repudiate.isPending;
  const setRow = (i: number, patch: Partial<RoleRow>) =>
    setRows((rs) => rs.map((r, j) => (j === i ? { ...r, ...patch } : r)));

  return (
    <section className="card" aria-label="Join a network">
      <h2>Join a network</h2>
      <p className="muted">
        A network lists a community first, then its administrators send the network's URL and
        DID. Joining acknowledges that listing: this community verifies the network's listing of
        it, registers a group for each of the network's roles, signs its acknowledgement, and
        verifies the membership grant the network returns.
      </p>
      <form
        onSubmit={(e) => {
          e.preventDefault();
          if (sendable) join.mutate();
        }}
      >
        <Field label="Network URL" htmlFor="join-url" error={url ? errors.url : undefined}>
          <input
            id="join-url"
            type="url"
            placeholder="https://network.example"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
          />
        </Field>
        <Field label="Network DID" htmlFor="join-network" error={network ? errors.network : undefined}>
          <input
            id="join-network"
            placeholder="did:webvh:…"
            value={network}
            onChange={(e) => setNetwork(e.target.value)}
          />
        </Field>

        {preview.isFetching && !found && <p className="muted">Reading the network…</p>}
        {preview.isError && (
          <p className="error" role="alert">
            {refusalText(preview.error)}
          </p>
        )}
        {found && <NetworkPreviewCard found={found} />}
        {alreadyMember && (
          <p className="muted" role="status">
            This community is already a member of this network.
          </p>
        )}

        <fieldset>
          <legend>Groups for the network's roles</legend>
          <p className="muted">
            A network can ask a member community for a group to serve each of its roles, such as{" "}
            <code>admins</code>: its broadcasts to that role reach the group's members. The network
            learns the group's DID, never who is in it.
          </p>
          {required && (
            <p className="warning" role="status">
              The network requires a group for the role <code>{required}</code>.
            </p>
          )}
          {groups.isError && (
            <p className="error">Could not read the community's groups: {String(groups.error)}</p>
          )}
          {rows.map((row, i) => (
            <div className="form-row" key={i}>
              <Field label="Role" htmlFor={`role-${i}`}>
                <input
                  id={`role-${i}`}
                  value={row.role}
                  placeholder="admins"
                  onChange={(e) => setRow(i, { role: e.target.value })}
                />
              </Field>
              <Field label="Group" htmlFor={`group-${i}`}>
                <select
                  id={`group-${i}`}
                  value={row.groupId}
                  onChange={(e) => setRow(i, { groupId: e.target.value })}
                >
                  <option value="">Pick a group…</option>
                  {eligible.map((g) => (
                    <option key={g.groupId} value={g.groupId}>
                      {g.name}
                    </option>
                  ))}
                </select>
              </Field>
              <button
                type="button"
                className="link"
                onClick={() => setRows((rs) => rs.filter((_, j) => j !== i))}
              >
                Remove
              </button>
            </div>
          ))}
          {groups.isSuccess && eligible.length === 0 && (
            <p className="muted">
              No group here has an identity of its own yet. Create one under Groups first if the
              network requires a role.
            </p>
          )}
          {errors.roles && <p className="error">{errors.roles}</p>}
          <button
            type="button"
            className="secondary"
            onClick={() => setRows((rs) => [...rs, { role: "", groupId: "" }])}
          >
            Add a role
          </button>
        </fieldset>

        {failed !== null && !(failed instanceof GestureDeclinedError) && !parkedOf(failed) && (
          <p className="error" role="alert">
            {refusalText(failed)}
          </p>
        )}

        <div className="form-actions">
          <button type="submit" className="primary" disabled={!sendable || busy}>
            {join.isPending ? "Joining…" : "Join network"}
          </button>
          <button type="button" className="secondary" onClick={onDone} disabled={busy}>
            Cancel
          </button>
        </div>
      </form>

      <details>
        <summary>Not this community's network? Reject the listing</summary>
        <Field label="Reason (kept in this community's audit trail)" htmlFor="repudiate-reason">
          <input
            id="repudiate-reason"
            value={reason}
            maxLength={500}
            onChange={(e) => setReason(e.target.value)}
          />
        </Field>
        <button
          type="button"
          className="destructive"
          disabled={busy || !!errors.url || !!errors.network}
          onClick={() => void askRepudiate()}
        >
          Reject listing
        </button>
      </details>
    </section>
  );
}

export function Networks() {
  const [params, setParams] = useSearchParams();
  const invitation = invitationOf(params);
  const [joining, setJoining] = useState(invitation !== null);
  const [selected, setSelected] = useState<string | null>(null);
  const query = useQuery({ queryKey: networkKeys.list, queryFn: listNetworks });
  const items = query.data ?? [];

  useEffect(() => {
    if (invitation) setJoining(true);
  }, [invitation?.url, invitation?.network]); // eslint-disable-line react-hooks/exhaustive-deps

  const closeJoin = () => {
    setJoining(false);
    if (invitation) setParams({}, { replace: true });
  };

  return (
    <section className="page">
      <PageHeader
        count={query.isPending ? undefined : items.length}
        countLabel={`${items.length} networks`}
        lead={
          <>
            The Verifiable Trust Networks this community belongs to. A network lists a community
            first; it becomes a member only when an administrator here joins (VTI-VTN-013).
          </>
        }
        actions={
          !joining && (
            <button type="button" className="primary" onClick={() => setJoining(true)}>
              Join a network
            </button>
          )
        }
      />

      {joining && <JoinForm initial={invitation} onDone={closeJoin} />}

      {query.isPending && (
        <section className="card">
          <p>Loading…</p>
        </section>
      )}
      {query.isError && (
        <section className="card">
          <p className="error">Could not read the memberships: {String(query.error)}</p>
        </section>
      )}

      {query.isSuccess && items.length === 0 && !joining && (
        <section className="card">
          <EmptyState icon={NetworkIcon} title="Not in any network yet">
            When a network lists this community, its administrators send an invitation. Open its
            link, or choose <b>Join a network</b> and enter the network's URL and DID.
          </EmptyState>
        </section>
      )}

      {items.length > 0 && (
        <section className="card" aria-label="Memberships">
          <table className="data-table">
            <thead>
              <tr>
                <th>Network</th>
                <th>DID</th>
                <th>State</th>
                <th>Groups</th>
                <th>Updated</th>
              </tr>
            </thead>
            <tbody>
              {items.map((m) => (
                <tr key={m.network}>
                  <td>
                    <button type="button" className="link" onClick={() => setSelected(m.network)}>
                      {m.name ?? m.url}
                    </button>
                  </td>
                  <td>
                    <DidText did={m.network} />
                  </td>
                  <td>
                    <span className={STATE_CHIP[m.state]}>{STATE_LABEL[m.state]}</span>
                  </td>
                  <td>{(m.groups ?? []).length}</td>
                  <td>{formatIso(m.updatedAt)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>
      )}

      {selected && <MembershipDetail network={selected} onClose={() => setSelected(null)} />}
    </section>
  );
}
