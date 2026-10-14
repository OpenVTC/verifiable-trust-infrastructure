// Rooms plugin — the data rooms this community hosts, and the one decision it
// gets to make about them.
//
// ## What a host knows, and why so little is not a bug
//
// A host cannot read a room's records and holds no member list. Both are by
// construction: records arrive sealed under a key the host never sees, and
// authorisation for every operation is a credential the *room* issued, checked
// against the room's own DID rather than against anything stored here. That is
// invariant I5, and it is what lets a room change hosts without reissuing a
// single credential.
//
// So this screen shows the row and nothing derived from a room's contents.
// There is no records view to add later and no member list to fetch — an
// operator asking for either is asking for the property the tier removed.
//
// **The owner is visible at every tier, including `private`, on purpose.** A
// room whose contents nobody here can read still has a party this operator must
// be able to reach about quota, abuse, and the reclamation notice the lifecycle
// obliges them to send. An operator who cannot list their rooms cannot send it,
// which is why invariant I1 exists.
//
// ## The lifecycle column, and what each state actually means
//
// `live` → `lapsed` → `dormant` → `reclaimable`, computed from the epoch's
// expiry and never stored — **minting an epoch is the renewal**, so a room in
// use renews itself in the course of being used and a stored state would be a
// second thing to keep true. A single renewal returns a room to `live` from any
// of the three.
//
// **None of them is an outage, and the screen must not read like one.** A
// lapsed room is read-only: nothing is destroyed, nothing is hidden, and reads
// keep working right up to the moment a reclaimed room's bytes are deleted —
// because the members’ choice at every stage is renew or take it with you.
//
// The two that mean something to an operator:
//
//   - **dormant** is where the owner is owed the notice, and where a nominated
//     successor may claim the room. Not `lapsed` — an expired epoch is
//     frequently somebody on holiday, and admitting a claim there would make
//     every holiday a takeover window.
//   - **reclaimable** is past the retention period stated at creation. The
//     notice has already been sent; deletion is a separate, deliberate act this
//     screen does not perform.
//
// ## The decision this community actually makes
//
// Creation, and only creation. The `rooms` policy decides whether to lend the
// disk; once a room exists this community's roster has no say. The shipped
// default permits `open` and `attributed` to members and **denies `private`** —
// not because a private room is dangerous, but because a community that has not
// decided should not discover it is hosting rooms whose membership it cannot
// see.
//
// That default is a surprise worth putting on screen rather than leaving in a
// Rego file, so the second card asks the live policy the question directly, per
// tier, using the same `data.vtc.rooms.decision` query and the same input shape
// the real creation path builds. A probe against a different input would answer
// a different question, which is worse than not asking.

import { useMemo, useState } from "react";
import { Link, Route, Routes } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { DoorOpen, RefreshCw } from "lucide-react";

import { postSignedRead } from "@/lib/api";
import { fetchActivePolicy } from "@/lib/policies-api";
import { formatEpoch, shorten } from "@/lib/format";
import { NamedDid } from "@/components/NamedDid";
import { DataTable } from "@/components/DataTable";
import { EmptyState } from "@/components/EmptyState";
import { PageHeader } from "@/components/PageHeader";
import { useNameBook } from "@/lib/names";
import { formatBytes } from "@/lib/rooms-api";
import type { HostedRoom, PolicyTestResponse, RoomScopeLimits } from "@/lib/wire-types";

import { RoomDetail } from "./rooms/RoomDetail";
import { LifecyclePill, TIER_BLURB, TIERS, roomPath, type Tier } from "./rooms/shared";

const TRUST_TASK_TEST = "https://trusttasks.org/spec/vtc/policies/test/0.1";
/** `vtc/rooms/list/0.1` — under `vtc/`, not `rooms/`: it is answered from the
 *  host's own admin authority, which invariant I5 forbids any `rooms/*` task. */
const TRUST_TASK_ROOMS_LIST = "https://trusttasks.org/spec/vtc/rooms/list/0.1";

/** The query the real creation path evaluates. Anything else probes a different rule. */
const DECISION_QUERY = "data.vtc.rooms.decision";

/**
 * The rooms this community hosts.
 *
 * A signed read of the host's own admin view: `vtc/rooms/list/0.1`, not a
 * `rooms/*` task. Every `rooms/*` task is authorised by a credential the ROOM
 * issued, checked against the room's own identifier (invariant I5); this asks
 * the opposite question — what is this *operator* storing — from the host's
 * admin authority.
 */
interface RoomsListing {
  rooms: HostedRoom[];
  /** Whether this community takes room files. `null` from a VTC too old to say. */
  filesEnabled: boolean | null;
  /** What its configuration holds every room to, when files are on. */
  defaults: FileDefaults | null;
}

/** `ext["org.openvtc"].roomFiles` on `vtc/rooms/list`, when files are on: the
 *  limits the configuration file sets, which a room's override or the rooms
 *  policy may replace. */
interface FileDefaults {
  room: RoomScopeLimits;
  member: RoomScopeLimits;
  maxFileBytes: number;
  storageCapacityBytes?: number;
  orphanGraceHours?: number;
}

function defaultsOf(v: unknown): FileDefaults | null {
  const f = v as {
    defaults?: { room?: RoomScopeLimits; member?: RoomScopeLimits };
    maxFileBytes?: unknown;
    storageCapacityBytes?: unknown;
    orphanGraceHours?: unknown;
  } | null;
  if (!f?.defaults || typeof f.maxFileBytes !== "number") return null;
  return {
    room: f.defaults.room ?? {},
    member: f.defaults.member ?? {},
    maxFileBytes: f.maxFileBytes,
    ...(typeof f.storageCapacityBytes === "number"
      ? { storageCapacityBytes: f.storageCapacityBytes }
      : {}),
    ...(typeof f.orphanGraceHours === "number" ? { orphanGraceHours: f.orphanGraceHours } : {}),
  };
}

async function fetchRooms(): Promise<RoomsListing> {
  const rooms: HostedRoom[] = [];
  let filesEnabled: boolean | null = null;
  let defaults: FileDefaults | null = null;
  let cursor: string | null = null;
  for (let page = 0; page < 20; page++) {
    const body: {
      items: HostedRoom[];
      nextCursor?: string | null;
      ext?: { "org.openvtc"?: { roomFiles?: { enabled?: unknown } } };
    } = await postSignedRead(TRUST_TASK_ROOMS_LIST, { limit: 100, ...(cursor ? { cursor } : {}) });
    rooms.push(...body.items);
    const roomFiles = body.ext?.["org.openvtc"]?.roomFiles;
    if (typeof roomFiles?.enabled === "boolean") filesEnabled = roomFiles.enabled;
    defaults ??= defaultsOf(roomFiles);
    cursor = body.nextCursor ?? null;
    if (!cursor) break;
  }
  return { rooms, filesEnabled, defaults };
}

/** What an operator adds to turn room files on. The paths are examples: absolute
 *  directories on this host, writable by the VTC. */
const ROOM_FILES_SNIPPET = `[rooms.files]
local_storage_bases = ["/var/lib/vtc/room-storage"]
blob_dir = "/var/lib/vtc/room-blobs"`;

/**
 * Room files are off: the configuration has no `[rooms.files]` section, which is
 * every configuration written before files existed. Said here, with the section
 * to add, rather than discovered as a refused upload.
 */
function RoomFilesOff() {
  return (
    <section className="card">
      <h2>Room files are off</h2>
      <p className="muted">
        Rooms work without them — records are stored and served as before — but
        members cannot add files. To let them, add a <code>[rooms.files]</code>{" "}
        section to this VTC&rsquo;s configuration file and restart it:
      </p>
      <pre className="rooms-config-snippet">{ROOM_FILES_SNIPPET}</pre>
      <p className="muted rooms-sub">
        Use absolute paths on this host that the VTC can write to.{" "}
        <code>blob_dir</code> is where files go at first; <code>local_storage_bases</code>{" "}
        are the directories an administrator may later point a storage location
        at. Files are encrypted by members before they arrive, so this host stores
        ciphertext it cannot read. Neither directory is in a VTC backup: back them
        up beside the data directory.
      </p>
    </section>
  );
}

function limitsText(l: RoomScopeLimits): string {
  const parts = [
    l.maxFiles !== undefined ? `${l.maxFiles.toLocaleString()} files` : null,
    l.maxBytes !== undefined ? `${formatBytes(l.maxBytes)} in all` : null,
    l.maxFileBytes !== undefined ? `${formatBytes(l.maxFileBytes)} a file` : null,
  ].filter(Boolean);
  return parts.length ? parts.join(", ") : "no limit";
}

/**
 * What every room is held to unless the rooms policy or an override on the room
 * says otherwise — the `[rooms.files]` section of the configuration file. Shown,
 * not edited: it changes with the file and a restart, and saying where is more
 * use than a form that could not save it.
 */
function FileDefaultsCard({ d }: { d: FileDefaults }) {
  return (
    <section className="card">
      <h3>Defaults</h3>
      <p className="muted">
        What each room is held to unless the rooms policy or an override on the room
        says otherwise. Change a single room from its own page; where its files go is
        on the <Link to="/storage">Storage</Link> page.
      </p>
      <dl className="rooms-facts">
        <dt>Each room</dt>
        <dd>{limitsText(d.room)}</dd>
        <dt>Each member, per room</dt>
        <dd>
          {limitsText(d.member)}
          <div className="muted rooms-sub">Not applied on private rooms, whose members this host cannot tell apart.</div>
        </dd>
        <dt>Largest file anywhere</dt>
        <dd>{formatBytes(d.maxFileBytes)}</dd>
        {d.storageCapacityBytes !== undefined && (
          <>
            <dt>Storage capacity</dt>
            <dd>{formatBytes(d.storageCapacityBytes)}</dd>
          </>
        )}
        {d.orphanGraceHours !== undefined && (
          <>
            <dt>Deleted files kept for</dt>
            <dd>{d.orphanGraceHours} hours, then removed from storage</dd>
          </>
        )}
      </dl>
      <p className="muted rooms-sub">
        To change these, edit <code>[rooms.files]</code>, <code>[rooms.files.room]</code>{" "}
        and <code>[rooms.files.member]</code> in this VTC&rsquo;s configuration file and
        restart it.
      </p>
    </section>
  );
}

/**
 * Ask the active `rooms` policy what it would say.
 *
 * The input is the shape `RoomCreationFacts` serialises to, because a probe
 * built from a guess answers about a policy nobody runs. `member: true` with no
 * role is the ordinary case the default policy is written around; a stranger is
 * denied by the `default decision` and tells the operator nothing they did not
 * already know.
 */
async function probeTier(policyId: string, tier: Tier): Promise<PolicyTestResponse> {
  return postSignedRead<PolicyTestResponse>(TRUST_TASK_TEST, {
    id: policyId,
    query: DECISION_QUERY,
    input: {
      now: new Date().toISOString(),
      actor: { did: "did:example:a-member-of-this-community", member: true },
      room: {
        roomId: "did:example:a-room",
        visibility: tier,
        ownerDid: "did:example:a-member-of-this-community",
      },
    },
  });
}

interface Verdict {
  effect: string;
  code?: string;
  reason?: string;
}

function pluckDecision(resp: PolicyTestResponse): Verdict | null {
  const value = (
    resp as unknown as {
      result?: { result?: { expressions?: { value?: unknown }[] }[] };
    }
  ).result?.result?.[0]?.expressions?.[0]?.value;
  if (!value || typeof value !== "object") return null;
  const v = value as { effect?: unknown; with?: { code?: unknown; reason?: unknown } };
  if (typeof v.effect !== "string") return null;
  return {
    effect: v.effect,
    code: typeof v.with?.code === "string" ? v.with.code : undefined,
    reason: typeof v.with?.reason === "string" ? v.with.reason : undefined,
  };
}

function RoomsTable({ rooms }: { rooms: HostedRoom[] }) {
  const nameBook = useNameBook();
  return (
    <DataTable
      columns={[
        { key: "room", label: "Room" },
        { key: "owner", label: "Owner" },
        { key: "tier", label: "Tier" },
        { key: "epoch", label: "Epoch" },
        { key: "lifecycle", label: "Lifecycle" },
        { key: "retention", label: "Retention" },
        { key: "created", label: "Created" },
      ]}
    >
      {rooms.map((r) => (
        <tr key={r.roomId}>
          <td>
            <Link to={roomPath(r.roomId)} title={r.roomId}>
              <code>{shorten(r.roomId)}</code>
            </Link>
            {r.mirrorOf && (
              <div className="muted rooms-sub">
                read-only copy of {shorten(r.mirrorOf)}
              </div>
            )}
          </td>
          <td>
            <NamedDid did={r.ownerDid} book={nameBook} />
          </td>
          <td>{r.visibility}</td>
          <td>
            {r.epoch}
            {r.epochExpiresAt ? (
              <div className="muted rooms-sub">
                expires {formatEpoch(r.epochExpiresAt)}
              </div>
            ) : null}
          </td>
          <td>
            <LifecyclePill value={r.lifecycle} />
          </td>
          <td>
            {r.retentionDays}d
            <div className="muted rooms-sub">
              {r.retentionPolicy === "chained" ? "history kept" : "from join"}
            </div>
          </td>
          <td>{formatEpoch(r.createdAt)}</td>
        </tr>
      ))}
    </DataTable>
  );
}

/**
 * What the live policy says, per tier.
 *
 * Three questions rather than a rendering of the Rego, because the question an
 * operator has is a yes/no about a tier and the answer is whatever the module
 * actually returns — including for a policy they wrote themselves, which no
 * amount of reading the shipped default would predict.
 */
function CreationPolicy() {
  const [ran, setRan] = useState(false);

  const activeQuery = useQuery({
    queryKey: ["policies", "active", "rooms"],
    queryFn: () => fetchActivePolicy("rooms"),
  });

  const policyId = activeQuery.data?.id;

  const probesQuery = useQuery({
    queryKey: ["rooms", "policy-probe", policyId],
    enabled: ran && Boolean(policyId),
    queryFn: async () => {
      const out: Record<Tier, Verdict | null> = {
        open: null,
        attributed: null,
        private: null,
      };
      for (const tier of TIERS) {
        out[tier] = pluckDecision(await probeTier(policyId!, tier));
      }
      return out;
    },
  });

  return (
    <section className="card">
      <h3>Who may create a room here</h3>
      <p className="lead">
        Creation is the only part of a room's life this community decides. Once a
        room exists every operation on it is authorised by credentials the room
        itself issued, and this community's roster has no say — which is what
        lets a room move to another host without a credential being reissued.
      </p>

      {activeQuery.isPending && <p>Reading the active rooms policy…</p>}

      {activeQuery.isError && (
        <p className="muted">
          The active rooms policy could not be read, so this cannot say what the
          community permits. That is a failure to ask, not a community with no
          policy — creation is still being decided by whatever is active.
        </p>
      )}

      {!activeQuery.isPending && !activeQuery.isError && !policyId && (
        <p className="muted">
          No rooms policy is active. A room creation evaluated against nothing is
          a <b>deny</b>: a missing rule is not read as consent here, so nobody can
          create a room until one is activated.
        </p>
      )}

      {policyId && (
        <>
          <p className="muted">
            Asked of the module actually in force, using the same query and input
            shape a real registration builds — for an ordinary member of this
            community.
          </p>
          <button
            type="button"
            className="secondary"
            onClick={() => setRan(true)}
            disabled={probesQuery.isFetching}
          >
            <RefreshCw aria-hidden="true" />
            {probesQuery.isFetching ? "Asking…" : ran ? "Ask again" : "Ask the policy"}
          </button>

          {probesQuery.isError && (
            <p className="muted">The policy could not be evaluated.</p>
          )}

          {probesQuery.data && (
            <DataTable
              className="rooms-tiers"
              columns={[
                { key: "tier", label: "Tier" },
                { key: "a-member-may-create", label: "A member may create" },
                { key: "what-the-policy-said", label: "What the policy said" },
              ]}
            >
              {TIERS.map((tier) => {
                const v = probesQuery.data[tier];
                const allowed = v?.effect === "allow";
                return (
                  <tr key={tier}>
                    <td>
                      {tier}
                      <div className="muted rooms-sub">
                        {TIER_BLURB[tier]}
                      </div>
                    </td>
                    <td>
                      <span className={`chip ${allowed ? "success" : "warning"}`}>
                        {v ? (allowed ? "yes" : "no") : "no decision"}
                      </span>
                    </td>
                    <td className="muted">
                      {v
                        ? (v.reason ?? v.code ?? v.effect)
                        : "The module returned nothing for this input, which this host treats as a deny."}
                    </td>
                  </tr>
                );
              })}
            </DataTable>
          )}
        </>
      )}

      <p className="muted rooms-policy-note">
        To change any of it, edit the <b>rooms</b> policy under Policies. The
        shipped default denies the private tier deliberately: a community that has
        not decided should not find out it is hosting rooms whose membership it
        cannot see.
      </p>
    </section>
  );
}

export function Rooms() {
  return (
    <Routes>
      <Route index element={<RoomsList />} />
      <Route path=":roomId" element={<RoomDetail />} />
    </Routes>
  );
}

function RoomsList() {
  const roomsQuery = useQuery({ queryKey: ["rooms"], queryFn: fetchRooms });
  const rooms = roomsQuery.data?.rooms ?? [];
  const filesOff = roomsQuery.data?.filesEnabled === false;

  // Worth surfacing above the table: these two are the states that ask the
  // operator to do something, and they are invisible in a long list.
  const { dormant, reclaimable } = useMemo(
    () => ({
      dormant: rooms.filter((r) => r.lifecycle === "dormant").length,
      reclaimable: rooms.filter((r) => r.lifecycle === "reclaimable").length,
    }),
    [rooms],
  );

  return (
    <section className="page">
      <PageHeader
        title="Data rooms"
        lead={
          <>
          Rooms this community stores. It cannot read their records and holds no
          member list — both by construction — so this is the row and nothing
          derived from a room's contents. The owner is shown at every tier,
          including private, because they are the party a quota or reclamation
          notice has to reach.
          </>
        }
      />

      {filesOff && <RoomFilesOff />}

      {roomsQuery.isPending && (
        <section className="card">
          <p>Loading rooms…</p>
        </section>
      )}

      {roomsQuery.isError && (
        <section className="card">
          <p className="muted">
            The room list could not be read. This is a failure to ask — not a
            community hosting none.
          </p>
        </section>
      )}

      {!roomsQuery.isPending && !roomsQuery.isError && rooms.length === 0 && (
        <section className="card">
          <EmptyState icon={DoorOpen} title="No rooms hosted here">
            A room appears once its owner registers it with this community. The
            policy below decides who may.
          </EmptyState>
        </section>
      )}

      {rooms.length > 0 && (
        <section className="card">
          {dormant > 0 && (
            <p className="muted">
              {dormant} {dormant === 1 ? "room is" : "rooms are"} <b>dormant</b> —
              unrenewed past the grace window. This is where the owner is owed the
              notice, and where a successor the room nominated may claim it.
            </p>
          )}
          {reclaimable > 0 && (
            <p className="muted">
              {reclaimable} {reclaimable === 1 ? "room is" : "rooms are"}{" "}
              <b>reclaimable</b> — past the retention agreed at creation, so this
              host may delete {reclaimable === 1 ? "it" : "them"}. Deletion is a
              separate, deliberate act and does not happen from this screen; until
              it does, {reclaimable === 1 ? "the room" : "they"} still read
              normally.
            </p>
          )}
          <RoomsTable rooms={rooms} />
        </section>
      )}

      {roomsQuery.data?.defaults && <FileDefaultsCard d={roomsQuery.data.defaults} />}

      <CreationPolicy />
    </section>
  );
}
