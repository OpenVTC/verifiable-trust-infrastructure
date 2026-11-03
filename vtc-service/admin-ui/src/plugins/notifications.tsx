// Notifications — what other parties told this community exists, and the
// administrator's decision to pass one on to members (`lib/notifications-api.ts`,
// `vtc/notifications/{list,show,relay}/0.1`, VTI-NTF-070 – VTI-NTF-074).
//
// Holding a notification tells nobody anything; the community relays one only
// when an administrator decides it here. A relay discloses something about the
// community (for an election, that it is a member of the community holding
// it), so the statement is shown and acknowledged by the administrator's own
// tick before the decision is sent (VTI-NTF-046) — never on their behalf.
//
// A decision answers with a count. Who was reached is never shown, here or
// anywhere else in the console.

import { useState } from "react";
import { Link, Route, Routes, useParams } from "react-router-dom";
import { useInfiniteQuery, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Bell } from "lucide-react";

import { useConfirm } from "@/components/ConfirmDialog";
import { DataTable } from "@/components/DataTable";
import { EmptyState } from "@/components/EmptyState";
import { Field } from "@/components/Field";
import { NamedDid } from "@/components/NamedDid";
import { ErrorOrParked } from "@/components/ParkedNotice";
import { PageHeader } from "@/components/PageHeader";
import { Switch } from "@/components/Switch";
import { formatIso } from "@/lib/format";
import { listGroups } from "@/lib/groups";
import { useNameBook, type NameBook } from "@/lib/names";
import {
  NOTIFICATIONS_KEY,
  NOTIFICATIONS_RELAY,
  listNotifications,
  notificationRefusalHint,
  relayNotification,
  relayStanding,
  relayedMessage,
  showNotification,
  type ReceivedNotification,
  type RecipientScope,
  type Recipients,
} from "@/lib/notifications-api";
import { gestureFromConfirm } from "@/lib/signed-act";
import { useToast } from "@/lib/toast";
import { holds, useCapabilities } from "@/lib/viewer";

export function Notifications() {
  return (
    <Routes>
      <Route index element={<NotificationList />} />
      <Route path=":recordId" element={<NotificationRoute />} />
    </Routes>
  );
}

const KIND_LABEL: Record<string, string> = { election: "Election" };

function kindLabel(kind: string): string {
  return KIND_LABEL[kind] ?? kind;
}

function statusLabel(n: ReceivedNotification): string {
  return n.notification.status === "withdrawn" ? "Withdrawn" : "Available";
}

function period(n: ReceivedNotification): string {
  const { validFrom, validUntil } = n.notification;
  if (validFrom && validUntil) return `${formatIso(validFrom)} to ${formatIso(validUntil)}`;
  if (validUntil) return `Until ${formatIso(validUntil)}`;
  if (validFrom) return `From ${formatIso(validFrom)}`;
  return "—";
}

function scopeLabel(r: Recipients, groupName?: (id: string) => string | undefined): string {
  switch (r.scope) {
    case "allMembers":
      return "All members";
    case "group":
      return `Group ${groupName?.(r.groupId) ?? r.groupId}`;
    case "role":
      return `Role ${r.role}`;
  }
}

function codeOf(e: unknown): string | undefined {
  const c = (e as { code?: unknown } | null)?.code;
  return typeof c === "string" ? c : undefined;
}

function Refusal({ title, error }: { title: string; error: unknown }) {
  if (!error) return null;
  const hint = notificationRefusalHint(codeOf(error));
  return (
    <>
      <ErrorOrParked title={title} error={error} />
      {hint && <p className="community-fix">{hint}</p>}
    </>
  );
}

function NotificationList() {
  const [includeLapsed, setIncludeLapsed] = useState(false);
  const book = useNameBook();
  const list = useInfiniteQuery({
    queryKey: [...NOTIFICATIONS_KEY, "list", { includeLapsed }],
    queryFn: ({ pageParam }) => listNotifications({ includeLapsed }, pageParam),
    initialPageParam: undefined as string | undefined,
    getNextPageParam: (last) => last.nextCursor,
  });
  const items = list.data?.pages.flatMap((p) => p.items) ?? [];
  return (
    <>
      <PageHeader
        count={list.data ? items.length : null}
        countLabel={list.data ? `${items.length} notifications` : undefined}
        lead="What other parties told this community exists — an election another community holds, say. Holding one tells nobody anything: the community passes it on to its members only when an administrator decides to."
      />
      <div className="toolbar list-toolbar">
        <Switch
          label="Include lapsed"
          description="Also show notifications that are withdrawn or past their end."
          checked={includeLapsed}
          onChange={(e) => setIncludeLapsed(e.target.checked)}
        />
      </div>
      {list.isError && <Refusal title="Could not read the notifications" error={list.error} />}
      <section className="card table-card">
        <DataTable
          caption="Notifications"
          columns={[
            { key: "kind", label: "Kind" },
            { key: "originator", label: "From" },
            { key: "holder", label: "Held by" },
            { key: "audience", label: "Audience" },
            { key: "status", label: "Status" },
            { key: "period", label: "Period" },
            { key: "received", label: "Received" },
            { key: "relayed", label: "Relayed by" },
            { key: "relay", label: "Relay" },
          ]}
        >
          {list.isSuccess && items.length === 0 && (
            <tr>
              <td colSpan={9}>
                <EmptyState icon={Bell} title="No notifications">
                  {includeLapsed
                    ? "The community holds none."
                    : "None the community holds can still be acted on."}
                </EmptyState>
              </td>
            </tr>
          )}
          {items.map((n) => (
            <tr key={n.recordId}>
              <td>
                <Link to={encodeURIComponent(n.recordId)}>{kindLabel(n.notification.kind)}</Link>
                <div className="muted rooms-sub">
                  <code>{n.notification.subject.id}</code>
                </div>
              </td>
              <td>
                <NamedDid book={book} did={n.originator} />
              </td>
              <td>
                <NamedDid book={book} did={n.notification.subject.heldBy} />
              </td>
              <td>
                <NamedDid book={book} did={n.notification.audience} />
              </td>
              <td>{statusLabel(n)}</td>
              <td>{period(n)}</td>
              <td>{formatIso(n.receivedAt)}</td>
              <td>
                <RelayChain book={book} chain={n.relayedBy} />
              </td>
              <td>
                {n.mayRelay ? "May be relayed" : "Not relayable"}
                <DecisionsSummary decisions={n.relayDecisions} />
              </td>
            </tr>
          ))}
        </DataTable>
      </section>
      {list.hasNextPage && (
        <div className="form-actions">
          <button
            type="button"
            className="secondary"
            onClick={() => void list.fetchNextPage()}
            disabled={list.isFetchingNextPage}
          >
            Show more
          </button>
        </div>
      )}
    </>
  );
}

function RelayChain({ book, chain }: { book: NameBook; chain: string[] }) {
  if (chain.length === 0) return <span className="muted">Sent directly</span>;
  return (
    <ol>
      {chain.map((d, i) => (
        <li key={`${i}-${d}`}>
          <NamedDid book={book} did={d} />
        </li>
      ))}
    </ol>
  );
}

function DecisionsSummary({ decisions }: { decisions: ReceivedNotification["relayDecisions"] }) {
  if (decisions.length === 0) return null;
  return (
    <ul className="muted rooms-sub">
      {decisions.map((d, i) => (
        <li key={`${d.decidedAt}-${i}`}>
          {scopeLabel(d.recipients)}: {d.recipientCount}
        </li>
      ))}
    </ul>
  );
}

function NotificationRoute() {
  const { recordId = "" } = useParams<{ recordId: string }>();
  return <NotificationPage recordId={recordId} />;
}

function NotificationPage({ recordId }: { recordId: string }) {
  const book = useNameBook();
  const caps = useCapabilities();
  const shown = useQuery({
    queryKey: [...NOTIFICATIONS_KEY, "show", recordId],
    queryFn: () => showNotification(recordId),
  });
  const n = shown.data?.item;
  const mayRelayHere = holds(caps, NOTIFICATIONS_RELAY, "*");
  return (
    <>
      <PageHeader
        title={n ? kindLabel(n.notification.kind) : "Notification"}
        trail={[{ label: n ? kindLabel(n.notification.kind) : recordId }]}
        actions={<Link to="..">All notifications</Link>}
      />
      {shown.isError && <Refusal title="Could not read the notification" error={shown.error} />}
      {n && shown.data && (
        <>
          <section className="card">
            <dl className="kv">
              <dt>Kind</dt>
              <dd>{kindLabel(n.notification.kind)}</dd>
              <dt>From</dt>
              <dd>
                <NamedDid book={book} did={n.originator} />
              </dd>
              <dt>Held by</dt>
              <dd>
                <NamedDid book={book} did={n.notification.subject.heldBy} />
                <div className="muted">
                  <code>{n.notification.subject.id}</code>, opened with{" "}
                  <code>{n.notification.subject.openWith}</code>
                </div>
              </dd>
              <dt>Audience</dt>
              <dd>
                <NamedDid book={book} did={n.notification.audience} />
              </dd>
              <dt>Status</dt>
              <dd>{statusLabel(n)}</dd>
              <dt>Period</dt>
              <dd>{period(n)}</dd>
              <dt>Revision</dt>
              <dd>{n.notification.revision}</dd>
              <dt>Received</dt>
              <dd>{formatIso(n.receivedAt)}</dd>
              <dt>Relayed by</dt>
              <dd>
                <RelayChain book={book} chain={n.relayedBy} />
              </dd>
              <dt>Relay</dt>
              <dd>{n.mayRelay ? "This community may relay it" : "This community may not relay it"}</dd>
              {n.relayDisclosure && (
                <>
                  <dt>A relay discloses</dt>
                  <dd>{n.relayDisclosure}</dd>
                </>
              )}
            </dl>
          </section>
          <section className="card">
            <h2>Relay decisions</h2>
            <p className="muted">
              Each decision records the selection and how many members it added — never who they
              are. Every later revision, a withdrawal included, goes to the same members.
            </p>
            {n.relayDecisions.length === 0 ? (
              <p className="muted">None yet.</p>
            ) : (
              <ul>
                {n.relayDecisions.map((d, i) => (
                  <li key={`${d.decidedAt}-${i}`}>
                    {formatIso(d.decidedAt)}: {scopeLabel(d.recipients)}, {d.recipientCount}{" "}
                    {d.recipientCount === 1 ? "member" : "members"} added, decided by{" "}
                    <NamedDid book={book} did={d.decidedBy} />
                  </li>
                ))}
              </ul>
            )}
          </section>
          <details className="card">
            <summary>The document as received</summary>
            <p className="muted">
              Exactly as it reached this community, so its proofs can be checked independently.
            </p>
            <pre className="mono">{JSON.stringify(shown.data.document, null, 2)}</pre>
          </details>
          {mayRelayHere && n.mayRelay && <RelayForm n={n} />}
        </>
      )}
    </>
  );
}

function RelayForm({ n }: { n: ReceivedNotification }) {
  const caps = useCapabilities();
  const standing = relayStanding(caps);
  const confirm = useConfirm();
  const toast = useToast();
  const queryClient = useQueryClient();
  const groups = useQuery({ queryKey: ["groups", "list"], queryFn: listGroups });

  const scopes: { value: RecipientScope; label: string; detail: string }[] = standing.anywhere
    ? [
        { value: "allMembers", label: "All members", detail: "Every active member. Confirmed with your passkey or approver." },
        { value: "group", label: "One group", detail: "The active members of one community group." },
        { value: "role", label: "One role", detail: "The active members holding one community role." },
      ]
    : [{ value: "group", label: "One group", detail: "The active members of a group you may relay to." }];

  const [scope, setScope] = useState<RecipientScope>(scopes[0]!.value);
  const [groupId, setGroupId] = useState("");
  const [role, setRole] = useState("");
  const [acknowledged, setAcknowledged] = useState(false);
  // A disclosure the community named in refusing, when the listing carried none.
  const [refusedDisclosure, setRefusedDisclosure] = useState<string | null>(null);
  const disclosure = n.relayDisclosure ?? refusedDisclosure;

  const groupChoices = (groups.data ?? [])
    .map(({ group }) => group)
    .filter((g) => standing.anywhere || standing.groups.includes(g.groupId));
  const groupName = (id: string) => groupChoices.find((g) => g.groupId === id)?.name;

  const recipients: Recipients | null =
    scope === "allMembers"
      ? { scope: "allMembers" }
      : scope === "group"
        ? groupId
          ? { scope: "group", groupId }
          : null
        : role.trim()
          ? { scope: "role", role: role.trim() }
          : null;
  const ready = recipients !== null && (!disclosure || acknowledged);

  const relay = useMutation({
    mutationFn: async () => {
      if (!recipients) throw new Error("Choose who to relay to.");
      const ok = await confirm({
        title: `Relay to ${scopeLabel(recipients, groupName).toLowerCase()}?`,
        message:
          "Each member it reaches is told the community received this notification and passed it on. That cannot be taken back, and every later revision goes to them too.",
        confirmLabel: "Relay",
        destructive: true,
      });
      if (!ok) throw new Error("Not relayed.");
      return relayNotification(
        n.recordId,
        recipients,
        !!disclosure && acknowledged,
        gestureFromConfirm(confirm),
      );
    },
    onSuccess: (r) => {
      toast.push("success", relayedMessage(r.recipientCount));
      void queryClient.invalidateQueries({ queryKey: NOTIFICATIONS_KEY });
    },
    onError: (e) => {
      if (codeOf(e) === "vtc/notifications/relay:disclosureNotAcknowledged") {
        const d = (e as { details?: { relayDisclosure?: unknown } }).details?.relayDisclosure;
        if (typeof d === "string") setRefusedDisclosure(d);
        setAcknowledged(false);
      }
    },
  });

  return (
    <section className="card">
      <h2>Relay to members</h2>
      <p className="muted">
        The community sends the notification exactly as it received it, one copy to each member the
        selection reaches — never to itself, the originator or anyone who relayed it here. You see
        how many members it reached, never who.
      </p>
      <form
        className="form-stack"
        onSubmit={(e) => {
          e.preventDefault();
          if (ready) relay.mutate();
        }}
      >
        <fieldset className="choice-group">
          <legend className="field-label">Relay to</legend>
          {scopes.map((o) => (
            <label key={o.value} className="checkbox">
              <input
                type="radio"
                name="relay-scope"
                value={o.value}
                checked={scope === o.value}
                onChange={() => setScope(o.value)}
              />
              <span className="checkbox-text">
                <strong>{o.label}</strong>
                <span className="choice-hint">{o.detail}</span>
              </span>
            </label>
          ))}
        </fieldset>
        {scope === "group" && (
          <Field label="Group">
            <select value={groupId} onChange={(e) => setGroupId(e.target.value)}>
              <option value="">Choose a group</option>
              {groupChoices.map((g) => (
                <option key={g.groupId} value={g.groupId}>
                  {g.name}
                </option>
              ))}
            </select>
          </Field>
        )}
        {scope === "role" && (
          <Field
            label="Community role"
            hint="As members' records name it — for example member, moderator, or custom:editor."
          >
            <input list="relay-roles" value={role} onChange={(e) => setRole(e.target.value)} />
          </Field>
        )}
        <datalist id="relay-roles">
          <option value="member" />
          <option value="moderator" />
          <option value="admin" />
        </datalist>
        {disclosure && (
          <div className="finding warn">
            <p>
              <strong>What a relay discloses about this community:</strong> <span>{disclosure}</span>
            </p>
            <label className="checkbox">
              <input
                type="checkbox"
                checked={acknowledged}
                onChange={(e) => setAcknowledged(e.target.checked)}
              />
              <span className="checkbox-text">
                I understand that relaying this discloses the above to every member it reaches.
              </span>
            </label>
          </div>
        )}
        <div className="form-actions">
          <button type="submit" className="primary" disabled={!ready || relay.isPending}>
            Relay to members
          </button>
        </div>
      </form>
      <Refusal title="Not relayed" error={relay.error} />
    </section>
  );
}
