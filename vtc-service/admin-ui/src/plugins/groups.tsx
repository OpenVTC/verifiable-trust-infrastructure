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
import { DoorOpen, KeyRound, Plus, Trash2, UserMinus, UserPlus } from "lucide-react";

import { useConfirm } from "@/components/ConfirmDialog";
import { DataTable } from "@/components/DataTable";
import { DirectoryAvatar } from "@/components/DirectoryAvatar";
import { EmptyState } from "@/components/EmptyState";
import { DidHostingCard } from "@/plugins/DidHostingCard";
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
  return (
    <>
      <PageHeader
        count={list.data ? items.length : null}
        actions={
          holds(caps, GROUPS_MANAGE) && (
            <button type="button" onClick={() => setCreating(!creating)}>
              <Plus size={14} aria-hidden="true" /> New group
            </button>
          )
        }
      />
      <p className="muted">
        A group has an identity of its own, held by the community&rsquo;s VTA, and gives each
        member a credential others can check. Who sees a group, and who sees its members, are
        separate choices.
      </p>
      {creating && <CreateGroupForm onDone={() => setCreating(false)} />}
      {holds(caps, "vtc.config.admin") && <DidHostingCard />}
      {list.error && (
        <section className="card error">
          <h3>Failed to read the groups</h3>
          <p>{(list.error as Error).message}</p>
        </section>
      )}
      <section className="card">
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
                <EmptyState title="No groups yet">
                  A working group, a chapter, the people running an event: create one above.
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
                <strong>{group.name}</strong>
                {group.description && <div className="muted">{group.description}</div>}
              </td>
              <td>{joinLabel(group.joinPolicy)}</td>
              <td>{audienceLabel(group.visibility)}</td>
              <td>{group.memberCount ?? <span className="muted">—</span>}</td>
            </tr>
          ))}
        </DataTable>
      </section>
    </>
  );
}

function CreateGroupForm({ onDone }: { onDone: () => void }) {
  const qc = useQueryClient();
  const toast = useToast();
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [joinPolicy, setJoinPolicy] = useState<JoinPolicy>("request");
  const [visibility, setVisibility] = useState<Audience>("members");
  const [showMembers, setShowMembers] = useState<Audience>("groupMembers");
  const [issues, setIssues] = useState(true);
  const [reason, setReason] = useState("");
  const create = useMutation({
    mutationFn: () =>
      createGroup({
        name: name.trim(),
        ...(description.trim() ? { description: description.trim() } : {}),
        kind: "static",
        joinPolicy,
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
  const ok = name.trim() && reason.trim() && audienceWithin(showMembers, visibility);
  return (
    <section className="card">
      <h3>New group</h3>
      <form
        className="stack"
        onSubmit={(e) => {
          e.preventDefault();
          if (ok) create.mutate();
        }}
      >
        <label>
          Name
          <input value={name} maxLength={128} onChange={(e) => setName(e.target.value)} />
        </label>
        <label>
          Description
          <textarea
            value={description}
            maxLength={1000}
            onChange={(e) => setDescription(e.target.value)}
          />
        </label>
        <label>
          Joining
          <select value={joinPolicy} onChange={(e) => setJoinPolicy(e.target.value as JoinPolicy)}>
            {JOIN_POLICIES.map((j) => (
              <option key={j.id} value={j.id}>
                {j.label} — {j.help}
              </option>
            ))}
          </select>
        </label>
        <AudienceSelects
          visibility={visibility}
          showMembers={showMembers}
          onVisibility={setVisibility}
          onShowMembers={setShowMembers}
        />
        <label className="checkbox">
          <input type="checkbox" checked={issues} onChange={(e) => setIssues(e.target.checked)} />
          Give each member a group credential others can check
        </label>
        <label>
          Why
          <input
            value={reason}
            maxLength={1024}
            placeholder="e.g. the identity working group starts"
            onChange={(e) => setReason(e.target.value)}
          />
        </label>
        <div className="actions">
          <button type="submit" disabled={!ok || create.isPending}>
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
      <label>
        Who sees the group
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
      </label>
      <label>
        Who sees its members
        <select value={showMembers} onChange={(e) => onShowMembers(e.target.value as Audience)}>
          {AUDIENCES.filter((a) => audienceWithin(a.id, visibility)).map((a) => (
            <option key={a.id} value={a.id}>
              {a.label}
            </option>
          ))}
        </select>
      </label>
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
        trail={[{ label: "Groups", to: ".." }, { label: group?.name ?? "…" }]}
        title={group?.name ?? "Group"}
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
          <GroupMembers group={group} manages={manages} />
          {manages && <GroupRequests group={group} />}
          {manages && <GroupManagers group={group} />}
          {manages && <GroupRooms group={group} />}
          {manages && <GroupAuthority group={group} />}
          {manages && <DeleteGroup group={group} onDeleted={() => navigate("..")} />}
        </>
      )}
    </>
  );
}

function GroupSummary({ group }: { group: Group }) {
  return (
    <section className="card">
      <dl className="kv">
        {group.description && (
          <div>
            <dt>About</dt>
            <dd>{group.description}</dd>
          </div>
        )}
        <div>
          <dt>Joining</dt>
          <dd>{joinLabel(group.joinPolicy)}</dd>
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
            <code>{group.groupDid}</code>
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
  const [visibility, setVisibility] = useState<Audience>(group.visibility as Audience);
  const [showMembers, setShowMembers] = useState<Audience>(group.showMembers as Audience);
  const save = useMutation({
    mutationFn: () =>
      updateGroup({
        groupId: group.groupId,
        name: name.trim(),
        ...(description.trim() ? { description: description.trim() } : {}),
        joinPolicy,
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
        className="stack"
        onSubmit={(e) => {
          e.preventDefault();
          save.mutate();
        }}
      >
        <label>
          Name
          <input value={name} maxLength={128} onChange={(e) => setName(e.target.value)} />
        </label>
        <label>
          Description
          <textarea
            value={description}
            maxLength={1000}
            onChange={(e) => setDescription(e.target.value)}
          />
        </label>
        <label>
          Joining
          <select value={joinPolicy} onChange={(e) => setJoinPolicy(e.target.value as JoinPolicy)}>
            {JOIN_POLICIES.map((j) => (
              <option key={j.id} value={j.id}>
                {j.label}
              </option>
            ))}
          </select>
        </label>
        <AudienceSelects
          visibility={visibility}
          showMembers={showMembers}
          onVisibility={setVisibility}
          onShowMembers={setShowMembers}
        />
        <div className="actions">
          <button type="submit" disabled={!name.trim() || save.isPending}>
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
  return (
    <section className="card">
      <h3>Members {members.data && <span className="muted">({members.data.length})</span>}</h3>
      {manages && (
        <form
          className="inline-form"
          onSubmit={(e) => {
            e.preventDefault();
            if (adding) add.mutate(adding);
          }}
        >
          <select aria-label="Member to add" value={adding} onChange={(e) => setAdding(e.target.value)}>
            <option value="">Choose a member…</option>
            {candidates.map(([entryId, f]) => (
              <option key={entryId} value={entryId}>
                {f.name ?? entryId}
              </option>
            ))}
          </select>
          <button type="submit" className="secondary" disabled={!adding || add.isPending}>
            <UserPlus size={14} aria-hidden="true" /> Add
          </button>
        </form>
      )}
      <DataTable
        caption="Members"
        columns={[
          { key: "member", label: "Member" },
          { key: "how", label: "Joined" },
          { key: "credential", label: "Credential until" },
          { key: "act", label: "" },
        ]}
      >
        {(members.data ?? []).map((m) => (
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
            <td>
              {manages && (
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
              )}
            </td>
          </tr>
        ))}
      </DataTable>
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
    <section className="card">
      <h3>Requests to join</h3>
      {items.length === 0 ? (
        <p className="muted">No requests waiting.</p>
      ) : (
        <ul className="group-requests">
          {items.map(({ request }) => (
            <li key={request.requestId}>
              <EntryName entryId={request.entryId} faces={faces} />
              {request.message && <p className="group-request-note">{request.message}</p>}
              <div className="actions">
                <button
                  type="button"
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
    <section className="card">
      <h3>Managers</h3>
      <p className="muted">
        Managers add and remove members, decide requests and change the group&rsquo;s settings.
        Administrators who manage every group are not listed.
      </p>
      <ul className="group-managers">
        {managers.map((e) => (
          <li key={e}>
            <EntryName entryId={e} faces={faces} />
            <button type="button" className="secondary" onClick={() => remove.mutate(e)}>
              End appointment
            </button>
          </li>
        ))}
      </ul>
      <form
        className="inline-form"
        onSubmit={(e) => {
          e.preventDefault();
          if (adding) add.mutate(adding);
        }}
      >
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
    <section className="card">
      <h3>
        <DoorOpen size={16} aria-hidden="true" /> Rooms
      </h3>
      <p className="muted">
        Members of this group are offered a place in these community rooms, keep it while they stay,
        and lose it when they leave — unless they were admitted to the room directly too.
      </p>
      {bindings.error && <p className="error">{(bindings.error as Error).message}</p>}
      {items.length === 0 && bindings.isSuccess && <p className="muted">Not bound to any room.</p>}
      <ul className="group-managers">
        {items.map((b) => {
          const spec = b.binding as { kind: string; roomId?: string; actions?: string[]; validFor?: string };
          return (
            <li key={b.bindingId}>
              <span>
                {spec.kind === "room" ? labelOf(spec.roomId ?? "") : spec.kind}
                {spec.actions && <span className="muted"> — {spec.actions.join(", ")}</span>}
                {spec.validFor && <span className="muted">, renewed every {spec.validFor.slice(1, -1)} days</span>}
                {b.state !== "active" && <span className="pill">{b.state}</span>}
              </span>
              {mayBind && b.state === "active" && (
                <button
                  type="button"
                  className="secondary"
                  disabled={remove.isPending}
                  onClick={() => remove.mutate(b.bindingId)}
                >
                  End
                </button>
              )}
            </li>
          );
        })}
      </ul>
      {mayBind && (
        <form
          className="stack"
          onSubmit={(e) => {
            e.preventDefault();
            if (ready) add.mutate();
          }}
        >
          <select aria-label="Room to bind" value={roomId} onChange={(e) => setRoomId(e.target.value)}>
            <option value="">Choose a community room…</option>
            {(rooms.data?.rooms ?? []).map((r) => (
              <option key={r.room.roomId} value={r.room.roomId}>
                {r.label}
              </option>
            ))}
          </select>
          <fieldset className="inline-form">
            <legend>What members may do</legend>
            {ROOM_ACTIONS.map((a) => (
              <label key={a}>
                <input
                  type="checkbox"
                  checked={actions.includes(a)}
                  onChange={(e) =>
                    setActions((cur) => (e.target.checked ? [...cur, a] : cur.filter((x) => x !== a)))
                  }
                />{" "}
                {a}
              </label>
            ))}
          </fieldset>
          <label>
            Days each admission lasts before it is renewed
            <input
              type="number"
              min={1}
              max={3650}
              value={days}
              onChange={(e) => setDays(e.target.value)}
            />
          </label>
          <input
            aria-label="Why bind the room"
            placeholder="Why, e.g. the working group's drafting room"
            value={reason}
            maxLength={1024}
            onChange={(e) => setReason(e.target.value)}
          />
          <button type="submit" className="secondary" disabled={!ready || add.isPending}>
            Bind room
          </button>
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
    <section className="card">
      <h3>
        <KeyRound size={16} aria-hidden="true" /> Authority
      </h3>
      <p className="muted">
        What this group gives its members is written onto each member&rsquo;s access-control entry,
        inside their administrative role, and taken away when they leave. A member whose role does
        not admit it cannot be added. Giving authority that creates authority — and every later
        change to who holds it through the group — waits for another administrator&rsquo;s approval.
      </p>
      {bindings.error && <p className="error">{(bindings.error as Error).message}</p>}
      {items.length === 0 && bindings.isSuccess && <p className="muted">It gives its members nothing.</p>}
      <ul className="group-managers">
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
                {b.state !== "active" && <span className="pill">{b.state}</span>}
              </span>
              {b.state === "active" && (
                <button
                  type="button"
                  className="secondary"
                  disabled={remove.isPending}
                  onClick={() => remove.mutate(b.bindingId)}
                >
                  End
                </button>
              )}
            </li>
          );
        })}
      </ul>
      {!closed && (
        <p className="muted">
          Only a closed group can give authority: close it first, so that only its managers add
          members.
        </p>
      )}
      {closed && (
        <form
          className="stack"
          onSubmit={(e) => {
            e.preventDefault();
            if (ready) add.mutate();
          }}
        >
          <fieldset className="inline-form">
            <legend>Give its members</legend>
            <label>
              <input type="radio" name="authority-kind" checked={kind === "grants"} onChange={() => setKind("grants")} />{" "}
              Capabilities
            </label>
            <label>
              <input type="radio" name="authority-kind" checked={kind === "role"} onChange={() => setKind("role")} />{" "}
              A role&rsquo;s capabilities
            </label>
          </fieldset>
          {kind === "grants" && (
            <fieldset className="stack">
              <legend>Capabilities you hold</legend>
              {bindable.length === 0 && <p className="muted">You hold no capability to give.</p>}
              {bindable.map((c) => (
                <label key={c.id}>
                  <input
                    type="checkbox"
                    checked={chosen.includes(c.id)}
                    onChange={(e) =>
                      setChosen((cur) => (e.target.checked ? [...cur, c.id] : cur.filter((x) => x !== c.id)))
                    }
                  />{" "}
                  <code>{c.id}</code> <span className="muted">— {c.gates}</span>
                  {c.conferring && <span className="pill">needs approval</span>}
                </label>
              ))}
            </fieldset>
          )}
          {kind === "role" &&
            (roles.data ? (
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
            ))}
          <input
            aria-label="Why give it"
            placeholder="Why, e.g. working group members may invite"
            value={reason}
            maxLength={1024}
            onChange={(e) => setReason(e.target.value)}
          />
          {kind === "grants" && chosen.some(conferring) && (
            <p className="muted">
              This creates authority, so another administrator approves it before anyone holds it.
            </p>
          )}
          <button type="submit" className="secondary" disabled={!ready || add.isPending}>
            Give
          </button>
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
        className="inline-form"
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
        <input
          aria-label="Why delete the group"
          placeholder="Why, e.g. the working group wound up"
          value={reason}
          maxLength={1024}
          onChange={(e) => setReason(e.target.value)}
        />
        <button type="submit" className="danger" disabled={!reason.trim() || del.isPending}>
          <Trash2 size={14} aria-hidden="true" /> Delete
        </button>
      </form>
    </details>
  );
}
