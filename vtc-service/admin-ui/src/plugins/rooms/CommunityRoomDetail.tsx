// One room the community owns, `/rooms/community/<roomId>` — the owner's view
// (`vtc/rooms/community/get/0.1`) and its members (`…/members/{list,add,remove}`).
//
// **Admission is an offer.** Adding a member has the community's VTA issue the
// room's invitation, membership and authority credentials to them, and the VTC
// keeps those as an offer the member collects with their own VTA
// (`pnm rooms offers accept`); nothing is delivered, because a member's VTA has
// no inbound address. So the list says who was **offered** and who has
// **admitted** themselves by accepting, and an offer can be withdrawn.
//
// **Removal says what it does before it is signed** (members/remove producer
// item 1): the confirmation names the tier's consequences and the member's
// `validUntil`, before the document is signed and before the gesture bound to
// it. Its answer is reported from the structured members (`validUntil`,
// `epoch`), never as recalling what the member already read (item 2).
//
// Each change takes the requester's passkey (or step-up approver) bound to that
// one document, and is audited with its reason; none is parked.

import { useState } from "react";
import { Link, useParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { UserMinus, UserPlus, Users } from "lucide-react";

import { useConfirm } from "@/components/ConfirmDialog";
import { CopyButton } from "@/components/CopyButton";
import { DataTable } from "@/components/DataTable";
import { EmptyState } from "@/components/EmptyState";
import { Field } from "@/components/Field";
import { NamedDid } from "@/components/NamedDid";
import { PageHeader } from "@/components/PageHeader";
import { Tabs } from "@/components/Tabs";
import { TypedConfirmDialog } from "@/components/TypedConfirmDialog";
import {
  MEMBER_ACTIONS,
  addCommunityRoomMember,
  fetchCommunityRoom,
  roomRenewalOf,
  fetchCommunityRoomMembers,
  removalOutcome,
  removalPreview,
  removeCommunityRoomMember,
  validUntilIn,
} from "@/lib/community-rooms-api";
import { formatIso } from "@/lib/format";
import { useNameBook } from "@/lib/names";
import { gestureFromConfirm } from "@/lib/signed-act";
import { useToast } from "@/lib/toast";
import { OFFLINE_POLL_MS } from "@/lib/use-live-events";
import { useCan } from "@/lib/viewer";
import type {
  CommunityRoom,
  CommunityRoomMember,
  CommunityRoomMemberAction,
  CommunityRoomMemberState,
} from "@/lib/wire-types";

import { RefusalCard } from "./CommunityRefusal";
import { AuthorityExpiry, COMMUNITY_ROOMS_KEY, RenewalFailing } from "./CommunityRooms";
import { COMMUNITY_PATH, LifecyclePill, TIER_BLURB, roomPath, type Tier } from "./shared";

type StateFilter = "all" | CommunityRoomMemberState;

const STATE_FILTERS: { id: StateFilter; label: string }[] = [
  { id: "all", label: "All" },
  { id: "offered", label: "Offered" },
  { id: "admitted", label: "Admitted" },
  { id: "removed", label: "Removed" },
];

/** How long an admission lasts unless the administrator says otherwise. */
const DEFAULT_VALID_DAYS = 90;

export function CommunityRoomDetail() {
  // Already decoded by the router; decoding again could change the identifier.
  const { roomId = "" } = useParams();
  const q = useQuery({
    queryKey: [...COMMUNITY_ROOMS_KEY, "get", roomId],
    queryFn: () => fetchCommunityRoom(roomId),
    enabled: roomId !== "",
    refetchInterval: OFFLINE_POLL_MS,
  });
  const trail = [{ label: "Community rooms", to: COMMUNITY_PATH }, { label: q.data?.room.label ?? "Room" }];

  if (q.isPending) {
    return (
      <section className="page">
        <PageHeader title="Community room" trail={trail} />
        <section className="card">
          <p>Reading the room…</p>
        </section>
      </section>
    );
  }
  if (q.isError) {
    return (
      <section className="page">
        <PageHeader title="Community room" trail={trail} />
        <RefusalCard title="The room could not be read" error={q.error} />
        <p>
          <Link to={COMMUNITY_PATH}>Back to community rooms</Link>
        </p>
      </section>
    );
  }
  const room = q.data.room;
  return (
    <section className="page">
      <PageHeader
        title={room.label}
        trail={trail}
        lead="A room this community owns. Its VTA holds the room's keys; the community admits and removes its members."
      />
      <RoomFacts room={room} renewal={roomRenewalOf(q.data.ext)} />
      <Members room={room} />
    </section>
  );
}

function RoomFacts({
  room,
  renewal,
}: {
  room: CommunityRoom;
  renewal: ReturnType<typeof roomRenewalOf>;
}) {
  const nameBook = useNameBook();
  const hostAdmin = useCan("vtc.rooms.admin", "*");
  const r = room.room;
  return (
    <section className="card">
      <h2>Room</h2>
      <dl className="rooms-facts">
        <dt>Identifier</dt>
        <dd>
          <code className="rooms-id">{r.roomId}</code> <CopyButton value={r.roomId} label="Copy the room's DID" />
        </dd>
        <dt>Tier</dt>
        <dd>
          {r.visibility}
          <div className="muted rooms-sub">{TIER_BLURB[r.visibility as Tier]}</div>
        </dd>
        <dt>Lifecycle</dt>
        <dd>
          <LifecyclePill value={r.lifecycle} /> epoch {r.epoch}
        </dd>
        <dt>Members</dt>
        <dd>
          {room.admitted} admitted, {room.offered} offered
        </dd>
        <dt>Community&rsquo;s authority until</dt>
        <dd>
          <AuthorityExpiry until={room.ownerAuthorityValidUntil} />
          <RenewalFailing renewal={renewal} />
          <div className="muted rooms-sub">
            After this the community can no longer admit or remove anyone here. The VTC renews it at
            the community&rsquo;s VTA
            {renewal?.renewWithinDays ? ` from ${renewal.renewWithinDays} days before it lapses` : " before it lapses"}
            {renewal?.lastRenewedAt ? `; last renewed ${formatIso(renewal.lastRenewedAt)}` : ""}.
          </div>
        </dd>
        {room.storageConfig && (
          <>
            <dt>Storage</dt>
            <dd>
              <code>{room.storageConfig}</code>
            </dd>
          </>
        )}
        {room.createdBy && (
          <>
            <dt>Created by</dt>
            <dd>
              <NamedDid did={room.createdBy} book={nameBook} /> on {new Date(r.createdAt * 1000).toLocaleString()}
            </dd>
          </>
        )}
      </dl>
      {hostAdmin && (
        <p className="muted rooms-sub">
          Its usage, limits and storage, as this community hosts it:{" "}
          <Link to={roomPath(r.roomId)}>the room on the Rooms tab</Link>.
        </p>
      )}
    </section>
  );
}

function Members({ room }: { room: CommunityRoom }) {
  const roomId = room.room.roomId;
  const [filter, setFilter] = useState<StateFilter>("all");
  const [adding, setAdding] = useState(false);
  const [removed, setRemoved] = useState<{ outcome: string | null; error: unknown }>({
    outcome: null,
    error: null,
  });
  const q = useQuery({
    queryKey: [...COMMUNITY_ROOMS_KEY, "members", roomId, filter],
    queryFn: () => fetchCommunityRoomMembers(roomId, filter === "all" ? undefined : filter),
    refetchInterval: OFFLINE_POLL_MS,
  });
  const items = q.data?.items ?? [];

  return (
    <section className="card" aria-labelledby="community-room-members">
      <div className="rooms-toolbar">
        <h2 id="community-room-members">Members</h2>
        {!adding && (
          <button type="button" onClick={() => setAdding(true)}>
            <UserPlus aria-hidden="true" /> Add a member
          </button>
        )}
      </div>
      <p className="muted">
        Adding a member makes them an <b>offer</b>: the room&rsquo;s credentials, kept here for them
        to collect with their own VTA (<code>pnm rooms offers accept</code>). They are{" "}
        <b>admitted</b> once they accept.
      </p>
      {adding && <AddMember room={room} onDone={() => setAdding(false)} />}
      <Tabs variant="segmented" label="Show" items={STATE_FILTERS} value={filter} onChange={setFilter} />
      {q.isPending && <p>Reading the members…</p>}
      {q.isError && <RefusalCard title="The members could not be read" error={q.error} />}
      {q.data && items.length === 0 && (
        <EmptyState icon={Users} title={filter === "all" ? "Nobody yet" : `Nobody ${filter}`} compact />
      )}
      {removed.outcome && (
        <p className="success" role="status">
          {removed.outcome}
        </p>
      )}
      <RefusalCard title="Not removed" error={removed.error} />
      {items.length > 0 && (
        <MembersTable
          room={room}
          members={items}
          onRemoved={(outcome, error) => setRemoved({ outcome, error })}
        />
      )}
      {q.data?.truncated && <p className="muted rooms-sub">More members exist than this page reads.</p>}
    </section>
  );
}

function stateChip(state: CommunityRoomMemberState) {
  const tone = state === "admitted" ? "success" : state === "offered" ? "warning" : "";
  return <span className={`chip ${tone}`}>{state}</span>;
}

function MembersTable({
  room,
  members,
  onRemoved,
}: {
  room: CommunityRoom;
  members: CommunityRoomMember[];
  onRemoved: (outcome: string | null, err: unknown) => void;
}) {
  const nameBook = useNameBook();
  return (
    <DataTable
      columns={[
        { key: "member", label: "Member" },
        { key: "state", label: "State" },
        { key: "actions", label: "Actions" },
        { key: "valid", label: "Valid until" },
        { key: "when", label: "When" },
        { key: "remove", label: "" },
      ]}
    >
      {members.map((m) => (
        <tr key={m.member}>
          <td>
            <NamedDid did={m.member} book={nameBook} />
          </td>
          <td>{stateChip(m.state)}</td>
          <td>{m.actions.join(", ")}</td>
          <td>{formatIso(m.validUntil)}</td>
          <td className="muted">
            offered {formatIso(m.offeredAt)}
            {m.admittedAt && <div className="rooms-sub">admitted {formatIso(m.admittedAt)}</div>}
            {m.removedAt && <div className="rooms-sub">removed {formatIso(m.removedAt)}</div>}
          </td>
          <td>{m.state !== "removed" && <RemoveMember room={room} member={m} onResult={onRemoved} />}</td>
        </tr>
      ))}
    </DataTable>
  );
}

function useMembersChanged() {
  const queryClient = useQueryClient();
  return () => void queryClient.invalidateQueries({ queryKey: COMMUNITY_ROOMS_KEY });
}

function AddMember({ room, onDone }: { room: CommunityRoom; onDone: () => void }) {
  const confirm = useConfirm();
  const toast = useToast();
  const changed = useMembersChanged();
  const [member, setMember] = useState("");
  const [actions, setActions] = useState<CommunityRoomMemberAction[]>(["read", "write"]);
  const [days, setDays] = useState(String(DEFAULT_VALID_DAYS));
  const [reason, setReason] = useState("");

  const n = Number(days);
  const daysValid = Number.isInteger(n) && n >= 1 && n <= 3650;
  const did = member.trim();
  const ready = did.startsWith("did:") && actions.length > 0 && daysValid && reason.trim() !== "";

  const add = useMutation({
    mutationFn: () =>
      addCommunityRoomMember(
        {
          roomId: room.room.roomId,
          member: did,
          actions,
          validUntil: validUntilIn(n),
          reason: reason.trim(),
        },
        gestureFromConfirm(confirm),
      ),
    onSuccess: (r) => {
      toast.push(
        "success",
        `Offered ${r.member.member} a place in “${room.label}”. They are admitted once they accept it.`,
      );
      changed();
      onDone();
    },
  });

  const toggle = (a: CommunityRoomMemberAction) =>
    setActions((cur) => (cur.includes(a) ? cur.filter((x) => x !== a) : [...cur, a]));

  return (
    <section className="card" aria-labelledby="add-community-room-member">
      <h3 id="add-community-room-member">Add a member</h3>
      <form
        className="form-stack"
        onSubmit={(e) => {
          e.preventDefault();
          if (ready) add.mutate();
        }}
      >
        <Field label="Member" hint="An active member of this community, by the DID they are a member under.">
          <input
            required
            placeholder="did:webvh:…"
            value={member}
            onChange={(e) => setMember(e.target.value)}
          />
        </Field>
        <fieldset className="community-choices inline">
          <legend className="field-label">Actions</legend>
          {MEMBER_ACTIONS.map((a) => (
            <label key={a.id} title={a.hint}>
              <input type="checkbox" checked={actions.includes(a.id)} onChange={() => toggle(a.id)} /> {a.id}
            </label>
          ))}
        </fieldset>
        <Field
          label="Valid for (days)"
          hint={
            daysValid
              ? `Until ${formatIso(validUntilIn(n))}.${room.room.visibility === "open" ? " On an open room removal withdraws nothing cryptographically, so keep this short." : ""}`
              : undefined
          }
          error={daysValid ? undefined : "A whole number of days, 1 to 3650."}
        >
          <input inputMode="numeric" value={days} onChange={(e) => setDays(e.target.value)} />
        </Field>
        <Field label="Reason" hint="Recorded in the audit trail.">
          <input required maxLength={500} value={reason} onChange={(e) => setReason(e.target.value)} />
        </Field>
        <div className="form-actions">
          <button type="submit" className="primary" disabled={!ready || add.isPending}>
            {add.isPending ? "Offering…" : "Offer a place"}
          </button>
          <button type="button" className="secondary" onClick={onDone}>
            Cancel
          </button>
        </div>
      </form>
      <RefusalCard title="Not added" error={add.error} />
    </section>
  );
}

function RemoveMember({
  room,
  member,
  onResult,
}: {
  room: CommunityRoom;
  member: CommunityRoomMember;
  /** What became of it — shown above the table, where it stays to be read. */
  onResult: (outcome: string | null, err: unknown) => void;
}) {
  const confirm = useConfirm();
  const changed = useMembersChanged();
  const [asking, setAsking] = useState(false);
  const withdrawing = member.state === "offered";
  const remove = useMutation({
    mutationFn: (reason: string) =>
      removeCommunityRoomMember(
        { roomId: room.room.roomId, member: member.member, reason },
        gestureFromConfirm(confirm),
      ),
    onMutate: () => onResult(null, null),
    onSuccess: (r) => {
      onResult(removalOutcome(r), null);
      changed();
    },
    onError: (err) => onResult(null, err),
  });
  return (
    <>
      <button
        type="button"
        className="secondary"
        disabled={remove.isPending}
        onClick={() => setAsking(true)}
      >
        <UserMinus size={14} aria-hidden="true" /> {withdrawing ? "Withdraw" : "Remove"}
      </button>
      {asking && (
        // What removal does on this tier, and until when the member's
        // authority is honoured, shown before anything is signed.
        <TypedConfirmDialog
          title={withdrawing ? "Withdraw this offer?" : "Remove this member?"}
          message={removalPreview(room.room.visibility, member)}
          prompt="Reason (recorded in the audit trail)"
          matches={(typed) => typed.trim() !== "" && typed.trim().length <= 500}
          confirmLabel={withdrawing ? "Withdraw" : "Remove"}
          busy={remove.isPending}
          onCancel={() => setAsking(false)}
          onConfirm={(typed) => {
            setAsking(false);
            remove.mutate(typed.trim());
          }}
        />
      )}
    </>
  );
}
