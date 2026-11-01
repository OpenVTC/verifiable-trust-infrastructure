// The community's groups (`vtc/groups/*`, docs/03-vtc/groups.md).
//
//   /groups        Every group this administrator may see; create one.
//   /groups/:id    One group: its settings, members, requests to join and
//                  managers, and deleting it.
//
// Creating a group takes `vtc.groups.manage` at the community; the rest of a
// group is its managers'. Each group's identity is minted and held by the
// community's VTA, so a create can be refused because the VTA did not answer —
// the refusal says what to do. Members are named by their directory entry and
// shown with their directory name and picture.

import { useMemo, useState } from "react";
import { Route, Routes, useNavigate, useParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { DoorOpen, KeyRound, Plus, Trash2, UserMinus, UserPlus, Users } from "lucide-react";

import { useConfirm } from "@/components/ConfirmDialog";
import { DataTable } from "@/components/DataTable";
import { DidText } from "@/components/DidText";
import { DirectoryAvatar } from "@/components/DirectoryAvatar";
import { EmptyState } from "@/components/EmptyState";
import { Field } from "@/components/Field";
import { DidHostingCard } from "@/plugins/DidHostingCard";
import { DidPresentationCard } from "@/plugins/DidPresentationCard";
import { type DynamicRule, RuleEditor, emptyRule, ruleReady, wireRule } from "@/plugins/GroupRule";
import { PageHeader } from "@/components/PageHeader";
import { COMMUNITY_ROOMS_LIST_KEY, ROOMS_MANAGE, fetchCommunityRooms } from "@/lib/community-rooms-api";
import { listAllEntries } from "@/lib/directory";
import {
  AUDIENCES,
  GROUPS_MANAGE,
  JOIN_POLICIES,
  addGroupBinding,
  addGroupManager,
  addGroupMember,
  audienceWithin,
  confersAuthority,
  createGroup,
  decideGroupRequest,
  deleteGroup,
  listGroupBindings,
  listGroupMembers,
  listGroupRequests,
  listGroups,
  removeGroupBinding,
  removeGroupManager,
  removeGroupMember,
  showGroup,
  updateGroup,
  type Audience,
  type JoinPolicy,
} from "@/lib/groups";
import { CAPABILITIES } from "@/lib/acl";
import { listRoles } from "@/lib/roles";
import { gestureFromConfirm } from "@/lib/signed-act";
import { useToast } from "@/lib/toast";
import { holds, useCapabilities } from "@/lib/viewer";
import type { Group } from "@/lib/wire-types";

const GROUPS_KEY = ["groups", "list"] as const;

function audienceLabel(a: string): string {
  return AUDIENCES.find((x) => x.id === a)?.label ?? a;
}

function joinLabel(j: string | undefined): string {
  return JOIN_POLICIES.find((x) => x.id === j)?.label ?? j ?? "";
}

/** How a group's members come to be in it: its join policy, or its rule. */
function membershipLabel(group: Group): string {
  return group.kind === "dynamic" ? "By rule" : joinLabel(group.joinPolicy);
}

/** Each directory entry's name and picture, by entry, for naming members. */
function useEntryFaces() {
  const q = useQuery({
    queryKey: ["directory", "entries", "all"],
    queryFn: listAllEntries,
    retry: false,
    staleTime: 60_000,
  });
  return useMemo(() => {
    const out = new Map<string, { name: string | null; avatar: unknown }>();
    for (const e of q.data ?? []) {
      const name =
        typeof e.fields.displayName === "string"
          ? e.fields.displayName
          : typeof e.fields.nickname === "string"
            ? e.fields.nickname
            : null;
      out.set(e.entryId, { name, avatar: e.fields.avatar });
    }
    return out;
  }, [q.data]);
}

function EntryName({
  entryId,
  faces,
}: {
  entryId: string;
  faces: Map<string, { name: string | null; avatar: unknown }>;
}) {
  const face = faces.get(entryId);
  return (
    <span className="dir-name-cell">
      <DirectoryAvatar entryId={entryId} value={face?.avatar} name={face?.name} colourKey={entryId} />
      {face?.name ?? <span className="muted">(no name)</span>}
    </span>
  );
}

export function Groups() {
  return (
    <section className="page">
      <Routes>
        <Route index element={<GroupsList />} />
        <Route path=":id" element={<GroupPage />} />
      </Routes>
    </section>
  );
}

function GroupsList() {
  const caps = useCapabilities();
  const navigate = useNavigate();
  const [creating, setCreating] = useState(false);
  const list = useQuery({ queryKey: GROUPS_KEY, queryFn: listGroups });
  const items = list.data ?? [];
  const manages = holds(caps, GROUPS_MANAGE);
  return (
    <>
      <PageHeader
        count={list.data ? items.length : null}
        countLabel={list.data ? `${items.length} groups` : undefined}
        lead="A group has an identity of its own, held by the community's VTA, and gives each member a credential others can check. Who sees a group, and who sees its members, are separate choices."
        actions={
          manages && (
            <button
              type="button"
              className={creating ? "secondary" : "primary"}
              onClick={() => setCreating(!creating)}
            >
              <Plus size={14} aria-hidden="true" /> New group
            </button>
          )
        }
      />
      {creating && <CreateGroupForm onDone={() => setCreating(false)} />}
      {list.error && (
        <section className="card error">
          <h3>Failed to read the groups</h3>
          <p>{(list.error as Error).message}</p>
        </section>
      )}
      <section className="card table-card">
        <DataTable
          caption="Groups"
          columns={[
            { key: "name", label: "Group" },
            { key: "join", label: "Joining" },
            { key: "visibility", label: "Seen by" },
            { key: "members", label: "Members" },
          ]}
        >
          {list.isSuccess && items.length === 0 && (
            <tr>
              <td colSpan={4}>
                <EmptyState icon={Users} title="No groups yet">
                  A working group, a chapter, the people running an event
                  {manages ? ": create one with New group." : "."}
                </EmptyState>
              </td>
            </tr>
          )}
          {items.map(({ group }) => (
            <tr
              key={group.groupId}
              className="clickable"
              onClick={() => navigate(encodeURIComponent(group.groupId))}
            >
              <td>
                <div className="group-name-cell">
                  <strong>{group.name}</strong>
                  {group.description && <span className="muted">{group.description}</span>}
                </div>
              </td>
              <td>{membershipLabel(group)}</td>
              <td>{audienceLabel(group.visibility)}</td>
              <td>{group.memberCount ?? <span className="muted">—</span>}</td>
            </tr>
          ))}
        </DataTable>
      </section>
      {holds(caps, "vtc.config.admin") && <DidHostingCard />}
      {holds(caps, "vtc.config.admin") && <DidPresentationCard />}
    </>
  );
}

function CreateGroupForm({ onDone }: { onDone: () => void }) {
  const qc = useQueryClient();
  const toast = useToast();
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [joinPolicy, setJoinPolicy] = useState<JoinPolicy>("request");
  const [dynamic, setDynamic] = useState(false);
  const [rule, setRule] = useState<DynamicRule>(emptyRule);
  const [visibility, setVisibility] = useState<Audience>("members");
  const [showMembers, setShowMembers] = useState<Audience>("groupMembers");
  const [issues, setIssues] = useState(true);
  const [reason, setReason] = useState("");
  const create = useMutation({
    mutationFn: () =>
      createGroup({
        name: name.trim(),
        ...(description.trim() ? { description: description.trim() } : {}),
        ...(dynamic ? { kind: "dynamic", rule: wireRule(rule) } : { kind: "static", joinPolicy }),
        visibility,
        showMembers,
        issuesCredentials: issues,
        reason: reason.trim(),
      } as never),
    onSuccess: (g) => {
      void qc.invalidateQueries({ queryKey: GROUPS_KEY });
      toast.push("success", `Created ${g.name}.`);
      onDone();
    },
    onError: (err) => toast.pushFromError(err, "The group was not created"),
  });
  const ok =
    name.trim() && reason.trim() && audienceWithin(showMembers, visibility) && (!dynamic || ruleReady(rule));
  return (
    <section className="card" aria-labelledby="new-group-title">
      <h3 id="new-group-title">New group</h3>
      <form
        className="form-stack"
        onSubmit={(e) => {
          e.preventDefault();
          if (ok) create.mutate();
        }}
      >
        <div className="form-grid">
          <Field label="Name">
            <input value={name} maxLength={128} onChange={(e) => setName(e.target.value)} />
          </Field>
          <Field
            label="Members"
            hint={
              dynamic
                ? "Whoever the rule admits, re-checked as facts change; a member may opt out."
                : "Added by a manager, joined, or asked for."
            }
          >
            <select
              aria-label="Members"
              value={dynamic ? "dynamic" : "static"}
              onChange={(e) => setDynamic(e.target.value === "dynamic")}
            >
              <option value="static">Chosen</option>
              <option value="dynamic">By rule</option>
            </select>
          </Field>
          <Field label="Description" className="span-2" hint="Optional. Shown to whoever sees the group.">
            <textarea
              className="prose"
              rows={2}
              value={description}
              maxLength={1000}
              onChange={(e) => setDescription(e.target.value)}
            />
          </Field>
          {dynamic ? (
            <RuleEditor value={rule} onChange={setRule} className="span-2" />
          ) : (
            <JoinPolicyField value={joinPolicy} onChange={setJoinPolicy} className="span-2" />
          )}
          <AudienceSelects
            visibility={visibility}
            showMembers={showMembers}
            onVisibility={setVisibility}
            onShowMembers={setShowMembers}
          />
          <label className="checkbox span-2">
            <input type="checkbox" checked={issues} onChange={(e) => setIssues(e.target.checked)} />
            <span className="checkbox-text">Give each member a group credential others can check</span>
          </label>
          <Field label="Why" className="span-2" hint="Recorded in the audit trail.">
            <input
              value={reason}
              maxLength={1024}
              placeholder="e.g. the identity working group starts"
              onChange={(e) => setReason(e.target.value)}
            />
          </Field>
        </div>
        <div className="form-actions">
          <button type="submit" className="primary" disabled={!ok || create.isPending}>
            {create.isPending ? "Creating…" : "Create"}
          </button>
          <button type="button" className="secondary" onClick={onDone}>
            Cancel
          </button>
        </div>
      </form>
    </section>
  );
}

function JoinPolicyField({
  value,
  onChange,
  className,
}: {
  value: JoinPolicy;
  onChange: (j: JoinPolicy) => void;
  className?: string;
}) {
  const chosen = JOIN_POLICIES.find((j) => j.id === value);
  return (
    <Field label="Joining" className={className} hint={chosen?.help}>
      <select value={value} onChange={(e) => onChange(e.target.value as JoinPolicy)}>
        {JOIN_POLICIES.map((j) => (
          <option key={j.id} value={j.id}>
            {j.label}
          </option>
        ))}
      </select>
    </Field>
  );
}

function AudienceSelects({
  visibility,
  showMembers,
  onVisibility,
  onShowMembers,
}: {
  visibility: Audience;
  showMembers: Audience;
  onVisibility: (a: Audience) => void;
  onShowMembers: (a: Audience) => void;
}) {
  return (
    <>
      <Field label="Who sees the group">
        <select
          value={visibility}
          onChange={(e) => {
            const v = e.target.value as Audience;
            onVisibility(v);
            if (!audienceWithin(showMembers, v)) onShowMembers(v);
          }}
        >
          {AUDIENCES.map((a) => (
            <option key={a.id} value={a.id}>
              {a.label}
            </option>
          ))}
        </select>
      </Field>
      <Field label="Who sees its members" hint="Never more widely than the group itself.">
        <select value={showMembers} onChange={(e) => onShowMembers(e.target.value as Audience)}>
          {AUDIENCES.filter((a) => audienceWithin(a.id, visibility)).map((a) => (
            <option key={a.id} value={a.id}>
              {a.label}
            </option>
          ))}
        </select>
      </Field>
    </>
  );
}

function GroupPage() {
  const { id = "" } = useParams();
  const groupId = decodeURIComponent(id);
  const navigate = useNavigate();
  const q = useQuery({ queryKey: ["groups", "show", groupId], queryFn: () => showGroup(groupId) });
  const group = q.data?.group;
  const manages = Array.isArray(group?.managers);
  return (
    <>
      <PageHeader
        trail={[{ label: group?.name ?? "…" }]}
        title={group?.name ?? "Group"}
        lead={group?.description}
      />
      {q.error && (
        <section className="card error">
          <h3>Failed to read the group</h3>
          <p>{(q.error as Error).message}</p>
        </section>
      )}
      {group && (
        <>
          <GroupSummary group={group} />
          {manages && <GroupSettings group={group} />}
          {/* A dynamic group's rule decides its members: nobody adds or removes one. */}
          <GroupMembers group={group} manages={manages && group.kind !== "dynamic"} />
          {manages && <GroupRequests group={group} />}
          {manages && <GroupManagers group={group} />}
          {manages && <GroupRooms group={group} />}
          {manages && group.kind !== "dynamic" && <GroupAuthority group={group} />}
          {manages && <DeleteGroup group={group} onDeleted={() => navigate("..")} />}
        </>
      )}
    </>
  );
}

function GroupSummary({ group }: { group: Group }) {
  return (
    <section className="card" aria-label="About this group">
      <dl className="kv">
        <div>
          <dt>Joining</dt>
          <dd>{membershipLabel(group)}</dd>
        </div>
        <div>
          <dt>Seen by</dt>
          <dd>{audienceLabel(group.visibility)}</dd>
        </div>
        <div>
          <dt>Members seen by</dt>
          <dd>{audienceLabel(group.showMembers)}</dd>
        </div>
        <div>
          <dt>Identity</dt>
          <dd>
            <DidText did={group.groupDid} />
          </dd>
        </div>
        <div>
          <dt>Credentials</dt>
          <dd>
            {group.issuesCredentials
              ? `Each member holds one${group.credentialAuthorityValidUntil ? `; the group may issue them until ${new Date(group.credentialAuthorityValidUntil).toLocaleDateString()}` : ""}`
              : "None"}
          </dd>
        </div>
      </dl>
    </section>
  );
}

function GroupSettings({ group }: { group: Group }) {
  const qc = useQueryClient();
  const toast = useToast();
  const [name, setName] = useState(group.name);
  const [description, setDescription] = useState(group.description ?? "");
  const [joinPolicy, setJoinPolicy] = useState<JoinPolicy>((group.joinPolicy ?? "closed") as JoinPolicy);
  const dynamic = group.kind === "dynamic";
  const [rule, setRule] = useState<DynamicRule>(
    (group.rule as DynamicRule | undefined) ?? emptyRule(),
  );
  const [visibility, setVisibility] = useState<Audience>(group.visibility as Audience);
  const [showMembers, setShowMembers] = useState<Audience>(group.showMembers as Audience);
  const save = useMutation({
    mutationFn: () =>
      updateGroup({
        groupId: group.groupId,
        name: name.trim(),
        ...(description.trim() ? { description: description.trim() } : {}),
        // A dynamic group has a rule, never a join policy.
        ...(dynamic ? { rule: wireRule(rule) } : { joinPolicy }),
        visibility,
        showMembers,
      } as never),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["groups"] });
      toast.push("success", "Saved.");
    },
    onError: (err) => toast.pushFromError(err, "The group was not changed"),
  });
  return (
    <details className="card">
      <summary>Settings</summary>
      <form
        className="form-stack"
        onSubmit={(e) => {
          e.preventDefault();
          save.mutate();
        }}
      >
        <div className="form-grid">
          <Field label="Name" className="span-2">
            <input value={name} maxLength={128} onChange={(e) => setName(e.target.value)} />
          </Field>
          <Field label="Description" className="span-2">
            <textarea
              className="prose"
              rows={2}
              value={description}
              maxLength={1000}
              onChange={(e) => setDescription(e.target.value)}
            />
          </Field>
          {dynamic ? (
            <RuleEditor value={rule} onChange={setRule} className="span-2" />
          ) : (
            <JoinPolicyField value={joinPolicy} onChange={setJoinPolicy} className="span-2" />
          )}
          <AudienceSelects
            visibility={visibility}
            showMembers={showMembers}
            onVisibility={setVisibility}
            onShowMembers={setShowMembers}
          />
        </div>
        <div className="form-actions">
          <button
            type="submit"
            className="primary"
            disabled={!name.trim() || (dynamic && !ruleReady(rule)) || save.isPending}
          >
            {save.isPending ? "Saving…" : "Save"}
          </button>
        </div>
      </form>
    </details>
  );
}

function GroupMembers({ group, manages }: { group: Group; manages: boolean }) {
  const qc = useQueryClient();
  const toast = useToast();
  const confirm = useConfirm();
  const faces = useEntryFaces();
  const [adding, setAdding] = useState("");
  const members = useQuery({
    queryKey: ["groups", "members", group.groupId],
    queryFn: () => listGroupMembers(group.groupId),
    retry: false,
  });
  const refresh = () => void qc.invalidateQueries({ queryKey: ["groups"] });
  const add = useMutation({
    mutationFn: (entryId: string) => addGroupMember(group.groupId, entryId),
    onSuccess: () => {
      setAdding("");
      refresh();
      toast.push("success", "Added.");
    },
    onError: (err) => toast.pushFromError(err, "Not added"),
  });
  const remove = useMutation({
    mutationFn: (entryId: string) => removeGroupMember(group.groupId, entryId),
    onSuccess: () => {
      refresh();
      toast.push("success", "Removed.");
    },
    onError: (err) => toast.pushFromError(err, "Not removed"),
  });
  if (members.error) return null;
  const inGroup = new Set((members.data ?? []).map((m) => m.entryId));
  const candidates = [...faces.entries()].filter(([e]) => !inGroup.has(e));
  const rows = members.data ?? [];
  return (
    <section className="card" aria-labelledby="group-members-title">
      <h3 id="group-members-title">
        Members {members.data && <span className="muted">({members.data.length})</span>}
      </h3>
      {manages && (
        <form
          className="toolbar"
          onSubmit={(e) => {
            e.preventDefault();
            if (adding) add.mutate(adding);
          }}
        >
          <Field label="Add a member" inline>
            <select aria-label="Member to add" value={adding} onChange={(e) => setAdding(e.target.value)}>
              <option value="">Choose a member…</option>
              {candidates.map(([entryId, f]) => (
                <option key={entryId} value={entryId}>
                  {f.name ?? entryId}
                </option>
              ))}
            </select>
          </Field>
          <button type="submit" className="secondary" disabled={!adding || add.isPending}>
            <UserPlus size={14} aria-hidden="true" /> Add
          </button>
        </form>
      )}
      {members.isSuccess && rows.length === 0 ? (
        <EmptyState compact title="Nobody is in this group yet." />
      ) : (
        <DataTable
          caption="Members"
          columns={[
            { key: "member", label: "Member" },
            { key: "how", label: "Joined" },
            { key: "credential", label: "Credential until" },
            ...(manages ? [{ key: "act", label: "" }] : []),
          ]}
        >
          {rows.map((m) => (
            <tr key={m.entryId}>
              <td>
                <EntryName entryId={m.entryId} faces={faces} />
              </td>
              <td>
                {m.source === "added" ? "Added" : m.source === "joined" ? "Joined" : "By request"}{" "}
                <span className="muted">{new Date(m.since).toLocaleDateString()}</span>
              </td>
              <td>
                {m.credentialValidUntil ? (
                  new Date(m.credentialValidUntil).toLocaleDateString()
                ) : (
                  <span className="muted">—</span>
                )}
              </td>
              {manages && (
                <td>
                  <div className="row-actions">
                    <button
                      type="button"
                      className="secondary"
                      onClick={async () => {
                        const ok = await confirm({
                          title: "Remove from the group?",
                          message: "Their group credential stops renewing and lapses at its expiry.",
                          confirmLabel: "Remove",
                          destructive: true,
                        });
                        if (ok) remove.mutate(m.entryId);
                      }}
                    >
                      <UserMinus size={14} aria-hidden="true" /> Remove
                    </button>
                  </div>
                </td>
              )}
            </tr>
          ))}
        </DataTable>
      )}
    </section>
  );
}

function GroupRequests({ group }: { group: Group }) {
  const qc = useQueryClient();
  const toast = useToast();
  const faces = useEntryFaces();
  const requests = useQuery({
    queryKey: ["groups", "requests", group.groupId],
    queryFn: () => listGroupRequests(group.groupId),
    retry: false,
  });
  const decide = useMutation({
    mutationFn: ({ id, decision }: { id: string; decision: "approve" | "decline" }) =>
      decideGroupRequest(id, decision),
    onSuccess: (r) => {
      void qc.invalidateQueries({ queryKey: ["groups"] });
      toast.push("success", r.state === "approved" ? "Approved." : "Declined.");
    },
    onError: (err) => toast.pushFromError(err, "Not decided"),
  });
  const items = requests.data ?? [];
  if (group.joinPolicy !== "request" && items.length === 0) return null;
  return (
    <section className="card" aria-labelledby="group-requests-title">
      <h3 id="group-requests-title">
        Requests to join {items.length > 0 && <span className="muted">({items.length})</span>}
      </h3>
      {items.length === 0 ? (
        <EmptyState compact title="No requests waiting." />
      ) : (
        <ul className="group-list">
          {items.map(({ request }) => (
            <li key={request.requestId}>
              <EntryName entryId={request.entryId} faces={faces} />
              <div className="row-actions">
                <button
                  type="button"
                  className="primary"
                  onClick={() => decide.mutate({ id: request.requestId, decision: "approve" })}
                  disabled={decide.isPending}
                >
                  Approve
                </button>
                <button
                  type="button"
                  className="secondary"
                  onClick={() => decide.mutate({ id: request.requestId, decision: "decline" })}
                  disabled={decide.isPending}
                >
                  Decline
                </button>
              </div>
              {request.message && <p className="group-request-note">{request.message}</p>}
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}

function GroupManagers({ group }: { group: Group }) {
  const qc = useQueryClient();
  const toast = useToast();
  const faces = useEntryFaces();
  const [adding, setAdding] = useState("");
  const managers = group.managers ?? [];
  const refresh = () => void qc.invalidateQueries({ queryKey: ["groups"] });
  const add = useMutation({
    mutationFn: (entryId: string) => addGroupManager(group.groupId, entryId),
    onSuccess: () => {
      setAdding("");
      refresh();
      toast.push("success", "Appointed.");
    },
    onError: (err) => toast.pushFromError(err, "Not appointed"),
  });
  const remove = useMutation({
    mutationFn: (entryId: string) => removeGroupManager(group.groupId, entryId),
    onSuccess: () => {
      refresh();
      toast.push("success", "Appointment ended.");
    },
    onError: (err) => toast.pushFromError(err, "Not changed"),
  });
  return (
    <section className="card" aria-labelledby="group-managers-title">
      <h3 id="group-managers-title">Managers</h3>
      <p className="muted">
        Managers add and remove members, decide requests and change the group&rsquo;s settings.
        Administrators who manage every group are not listed.
      </p>
      {managers.length === 0 ? (
        <EmptyState compact title="No managers appointed." />
      ) : (
        <ul className="group-list">
          {managers.map((e) => (
            <li key={e}>
              <EntryName entryId={e} faces={faces} />
              <div className="row-actions">
                <button type="button" className="secondary" onClick={() => remove.mutate(e)}>
                  End appointment
                </button>
              </div>
            </li>
          ))}
        </ul>
      )}
      <form
        className="toolbar"
        onSubmit={(e) => {
          e.preventDefault();
          if (adding) add.mutate(adding);
        }}
      >
        <Field label="Appoint a manager" inline>
          <select aria-label="Member to appoint" value={adding} onChange={(e) => setAdding(e.target.value)}>
            <option value="">Choose a member…</option>
            {[...faces.entries()]
              .filter(([e]) => !managers.includes(e))
              .map(([entryId, f]) => (
                <option key={entryId} value={entryId}>
                  {f.name ?? entryId}
                </option>
              ))}
          </select>
        </Field>
        <button type="submit" className="secondary" disabled={!adding || add.isPending}>
          Appoint
        </button>
      </form>
    </section>
  );
}

const ROOM_ACTIONS = ["read", "write", "curate"] as const;
type RoomAction = (typeof ROOM_ACTIONS)[number];

/** Rooms the group's members are admitted to (`vtc/groups/bindings/*`). Binding takes
 *  `vtc.rooms.manage` as well as managing the group, and the requester's gesture. */
function GroupRooms({ group }: { group: Group }) {
  const qc = useQueryClient();
  const toast = useToast();
  const confirm = useConfirm();
  const caps = useCapabilities();
  const mayBind = holds(caps, ROOMS_MANAGE);
  const bindings = useQuery({
    queryKey: ["groups", "bindings", group.groupId],
    queryFn: () => listGroupBindings(group.groupId),
  });
  const rooms = useQuery({
    queryKey: COMMUNITY_ROOMS_LIST_KEY,
    queryFn: fetchCommunityRooms,
    enabled: mayBind,
  });
  const [roomId, setRoomId] = useState("");
  const [actions, setActions] = useState<RoomAction[]>(["read", "write"]);
  const [days, setDays] = useState("30");
  const [reason, setReason] = useState("");
  const n = Number(days);
  const ready =
    roomId !== "" && actions.length > 0 && Number.isInteger(n) && n >= 1 && n <= 3650 && reason.trim() !== "";
  const labelOf = (id: string) =>
    rooms.data?.rooms.find((r) => r.room.roomId === id)?.label ?? id;
  const refresh = () => void qc.invalidateQueries({ queryKey: ["groups"] });
  const add = useMutation({
    mutationFn: () =>
      addGroupBinding(
        group.groupId,
        { kind: "room", roomId, actions, validFor: `P${n}D` },
        reason.trim(),
        gestureFromConfirm(confirm),
      ),
    onSuccess: () => {
      setRoomId("");
      setReason("");
      refresh();
      toast.push("success", `Every member of ${group.name} is being offered a place in “${labelOf(roomId)}”.`);
    },
    onError: (err) => toast.pushFromError(err, "Not bound"),
  });
  const remove = useMutation({
    mutationFn: (bindingId: string) =>
      removeGroupBinding(group.groupId, bindingId, "Ended from the group's page.", gestureFromConfirm(confirm)),
    onSuccess: (r) => {
      refresh();
      toast.push(
        "success",
        r.state === "removing"
          ? "Ending: members who are in the room only through this group are being removed."
          : "Ended.",
      );
    },
    onError: (err) => toast.pushFromError(err, "Not ended"),
  });
  const items = (bindings.data ?? []).filter((b) => !confersAuthority(b.binding as { kind?: string }));
  return (
    <section className="card" aria-labelledby="group-rooms-title">
      <h3 id="group-rooms-title">
        <DoorOpen size={14} aria-hidden="true" /> Rooms
      </h3>
      <p className="muted">
        Members of this group are offered a place in these community rooms, keep it while they stay,
        and lose it when they leave — unless they were admitted to the room directly too.
      </p>
      {bindings.error && <p className="field-error">{(bindings.error as Error).message}</p>}
      {items.length === 0 && bindings.isSuccess ? (
        <EmptyState compact title="Not bound to any room." />
      ) : (
        <ul className="group-list">
          {items.map((b) => {
            const spec = b.binding as { kind: string; roomId?: string; actions?: string[]; validFor?: string };
            return (
              <li key={b.bindingId}>
                <span>
                  <strong>{spec.kind === "room" ? labelOf(spec.roomId ?? "") : spec.kind}</strong>
                  {spec.actions && <span className="muted"> — {spec.actions.join(", ")}</span>}
                  {spec.validFor && (
                    <span className="muted">, renewed every {spec.validFor.slice(1, -1)} days</span>
                  )}
                  {b.state !== "active" && <span className="chip warning">{b.state}</span>}
                </span>
                {mayBind && b.state === "active" && (
                  <div className="row-actions">
                    <button
                      type="button"
                      className="secondary"
                      disabled={remove.isPending}
                      onClick={() => remove.mutate(b.bindingId)}
                    >
                      End
                    </button>
                  </div>
                )}
              </li>
            );
          })}
        </ul>
      )}
      {mayBind && (
        <form
          className="form-stack"
          onSubmit={(e) => {
            e.preventDefault();
            if (ready) add.mutate();
          }}
        >
          <div className="form-grid">
            <Field label="Room">
              <select aria-label="Room to bind" value={roomId} onChange={(e) => setRoomId(e.target.value)}>
                <option value="">Choose a community room…</option>
                {(rooms.data?.rooms ?? []).map((r) => (
                  <option key={r.room.roomId} value={r.room.roomId}>
                    {r.label}
                  </option>
                ))}
              </select>
            </Field>
            <Field label="Admission lasts" hint="Days before each member's admission is renewed.">
              <input
                type="number"
                aria-label="Days each admission lasts before it is renewed"
                min={1}
                max={3650}
                value={days}
                onChange={(e) => setDays(e.target.value)}
              />
            </Field>
            <fieldset className="field span-2">
              <legend className="field-label">What members may do</legend>
              <div className="form-actions">
                {ROOM_ACTIONS.map((a) => (
                  <label key={a} className="checkbox">
                    <input
                      type="checkbox"
                      checked={actions.includes(a)}
                      onChange={(e) =>
                        setActions((cur) => (e.target.checked ? [...cur, a] : cur.filter((x) => x !== a)))
                      }
                    />
                    <span className="checkbox-text">{a}</span>
                  </label>
                ))}
              </div>
            </fieldset>
            <Field label="Why" className="span-2" hint="Recorded in the audit trail.">
              <input
                aria-label="Why bind the room"
                placeholder="e.g. the working group's drafting room"
                value={reason}
                maxLength={1024}
                onChange={(e) => setReason(e.target.value)}
              />
            </Field>
          </div>
          <div className="form-actions">
            <button type="submit" className="primary" disabled={!ready || add.isPending}>
              Bind room
            </button>
          </div>
        </form>
      )}
    </section>
  );
}

/** What this group confers on its members (`grants` and `role` bindings,
 *  VTI-DIR-100 – 105): written onto each member's access-control entry, inside
 *  their role's ceiling. Binding something authority-conferring, and every later
 *  change to who holds it, waits for another administrator's approval. */
function GroupAuthority({ group }: { group: Group }) {
  const qc = useQueryClient();
  const toast = useToast();
  const confirm = useConfirm();
  const caps = useCapabilities();
  const bindings = useQuery({
    queryKey: ["groups", "bindings", group.groupId],
    queryFn: () => listGroupBindings(group.groupId),
  });
  const roles = useQuery({ queryKey: ["roles", "list"], queryFn: () => listRoles(true) });
  const [kind, setKind] = useState<"grants" | "role">("grants");
  const [chosen, setChosen] = useState<string[]>([]);
  const [role, setRole] = useState("");
  const [reason, setReason] = useState("");
  // A binder binds only what they hold themselves (VTI-ACL-071).
  const bindable = CAPABILITIES.filter((c) => holds(caps, c.id));
  const closed = group.joinPolicy === "closed";
  const ready =
    reason.trim() !== "" && (kind === "grants" ? chosen.length > 0 : role.trim() !== "");
  const refresh = () => void qc.invalidateQueries({ queryKey: ["groups"] });
  const add = useMutation({
    mutationFn: () =>
      addGroupBinding(
        group.groupId,
        kind === "grants"
          ? { kind: "grants", grants: chosen.map((capability) => ({ capability })) }
          : { kind: "role", role: role.trim() },
        reason.trim(),
        gestureFromConfirm(confirm),
      ),
    onSuccess: () => {
      setChosen([]);
      setRole("");
      setReason("");
      refresh();
      toast.push("success", `Members of ${group.name} hold it now, where their role admits it.`);
    },
    onError: (err) => {
      refresh();
      toast.pushFromError(err, "Not bound");
    },
  });
  const remove = useMutation({
    mutationFn: (bindingId: string) =>
      removeGroupBinding(group.groupId, bindingId, "Ended from the group's page.", gestureFromConfirm(confirm)),
    onSuccess: () => {
      refresh();
      toast.push("success", "Ended: what it gave the group's members is taken away.");
    },
    onError: (err) => {
      refresh();
      toast.pushFromError(err, "Not ended");
    },
  });
  const items = (bindings.data ?? []).filter((b) => confersAuthority(b.binding as { kind?: string }));
  const conferring = (id: string) => CAPABILITIES.find((c) => c.id === id)?.conferring ?? false;
  return (
    <section className="card" aria-labelledby="group-authority-title">
      <h3 id="group-authority-title">
        <KeyRound size={14} aria-hidden="true" /> Authority
      </h3>
      <p className="muted">
        What this group gives its members is written onto each member&rsquo;s access-control entry,
        inside their administrative role, and taken away when they leave. A member whose role does
        not admit it cannot be added. Giving authority that creates authority — and every later
        change to who holds it through the group — waits for another administrator&rsquo;s approval.
      </p>
      {bindings.error && <p className="field-error">{(bindings.error as Error).message}</p>}
      {items.length === 0 && bindings.isSuccess ? (
        <EmptyState compact title="It gives its members nothing." />
      ) : (
        <ul className="group-list">
          {items.map((b) => {
            const spec = b.binding as { kind: string; grants?: { capability: string; resource?: string }[]; role?: string };
            return (
              <li key={b.bindingId}>
                <span>
                  {spec.kind === "role"
                    ? `The ${spec.role} role's capabilities`
                    : (spec.grants ?? [])
                        .map((g) => (g.resource ? `${g.capability}@${g.resource}` : g.capability))
                        .join(", ")}
                  {b.state !== "active" && <span className="chip warning">{b.state}</span>}
                </span>
                {b.state === "active" && (
                  <div className="row-actions">
                    <button
                      type="button"
                      className="secondary"
                      disabled={remove.isPending}
                      onClick={() => remove.mutate(b.bindingId)}
                    >
                      End
                    </button>
                  </div>
                )}
              </li>
            );
          })}
        </ul>
      )}
      {!closed && (
        <p className="muted">
          Only a closed group can give authority: close it first, so that only its managers add
          members.
        </p>
      )}
      {closed && (
        <form
          className="form-stack"
          onSubmit={(e) => {
            e.preventDefault();
            if (ready) add.mutate();
          }}
        >
          <fieldset className="field">
            <legend className="field-label">Give its members</legend>
            <div className="form-actions">
              <label className="checkbox">
                <input
                  type="radio"
                  name="authority-kind"
                  checked={kind === "grants"}
                  onChange={() => setKind("grants")}
                />
                <span className="checkbox-text">Capabilities</span>
              </label>
              <label className="checkbox">
                <input
                  type="radio"
                  name="authority-kind"
                  checked={kind === "role"}
                  onChange={() => setKind("role")}
                />
                <span className="checkbox-text">A role&rsquo;s capabilities</span>
              </label>
            </div>
          </fieldset>
          {kind === "grants" && (
            <fieldset className="field group-cap-list">
              <legend className="field-label">Capabilities you hold</legend>
              {bindable.length === 0 && <p className="muted">You hold no capability to give.</p>}
              {bindable.map((c) => (
                <label key={c.id} className="checkbox">
                  <input
                    type="checkbox"
                    checked={chosen.includes(c.id)}
                    onChange={(e) =>
                      setChosen((cur) => (e.target.checked ? [...cur, c.id] : cur.filter((x) => x !== c.id)))
                    }
                  />
                  <span className="checkbox-text">
                    <code>{c.id}</code> <span className="muted">— {c.gates}</span>
                    {c.conferring && <span className="chip warning">needs approval</span>}
                  </span>
                </label>
              ))}
            </fieldset>
          )}
          {kind === "role" && (
            <Field label="Role">
              {roles.data ? (
                <select aria-label="Role" value={role} onChange={(e) => setRole(e.target.value)}>
                  <option value="">Choose a role…</option>
                  {roles.data.map((r) => (
                    <option key={r.name} value={r.name}>
                      {r.name}
                    </option>
                  ))}
                </select>
              ) : (
                <input
                  aria-label="Role"
                  placeholder="A role's name, e.g. moderator"
                  value={role}
                  maxLength={64}
                  onChange={(e) => setRole(e.target.value)}
                />
              )}
            </Field>
          )}
          <Field
            label="Why"
            hint={
              kind === "grants" && chosen.some(conferring)
                ? "This creates authority, so another administrator approves it before anyone holds it."
                : "Recorded in the audit trail."
            }
          >
            <input
              aria-label="Why give it"
              placeholder="e.g. working group members may invite"
              value={reason}
              maxLength={1024}
              onChange={(e) => setReason(e.target.value)}
            />
          </Field>
          <div className="form-actions">
            <button type="submit" className="primary" disabled={!ready || add.isPending}>
              Give
            </button>
          </div>
        </form>
      )}
    </section>
  );
}

function DeleteGroup({ group, onDeleted }: { group: Group; onDeleted: () => void }) {
  const qc = useQueryClient();
  const toast = useToast();
  const confirm = useConfirm();
  const [reason, setReason] = useState("");
  const del = useMutation({
    mutationFn: () => deleteGroup(group.groupId, reason.trim()),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["groups"] });
      toast.push("success", `Deleted ${group.name}.`);
      onDeleted();
    },
    onError: (err) => toast.pushFromError(err, "Not deleted"),
  });
  return (
    <details className="card">
      <summary>Delete this group</summary>
      <p className="muted">
        Every membership ends, its managers&rsquo; appointments go, and the group&rsquo;s authority
        to issue credentials is revoked. Credentials it issued lapse at their expiry.
      </p>
      <form
        className="toolbar"
        onSubmit={async (e) => {
          e.preventDefault();
          if (!reason.trim()) return;
          const ok = await confirm({
            title: `Delete ${group.name}?`,
            message: "This cannot be undone.",
            confirmLabel: "Delete",
            destructive: true,
          });
          if (ok) del.mutate();
        }}
      >
        <Field label="Why" inline>
          <input
            aria-label="Why delete the group"
            placeholder="e.g. the working group wound up"
            value={reason}
            maxLength={1024}
            onChange={(e) => setReason(e.target.value)}
          />
        </Field>
        <button type="submit" className="destructive" disabled={!reason.trim() || del.isPending}>
          <Trash2 size={14} aria-hidden="true" /> Delete
        </button>
      </form>
    </details>
  );
}
