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
import { useQuery } from "@tanstack/react-query";
import { DoorOpen, RefreshCw } from "lucide-react";

import { getJsonExempt, postJson } from "@/lib/api";
import { fetchActivePolicy } from "@/lib/policies-api";
import { formatEpoch, shorten } from "@/lib/format";
import { NamedDid } from "@/components/NamedDid";
import { useNameBook } from "@/lib/names";
import type { HostedRoom, PolicyTestResponse } from "@/lib/wire-types";

const TRUST_TASK_TEST = "https://trusttasks.org/spec/vtc/policies/test/0.1";

/** The query the real creation path evaluates. Anything else probes a different rule. */
const DECISION_QUERY = "data.vtc.rooms.decision";

const TIERS = ["open", "attributed", "private"] as const;
type Tier = (typeof TIERS)[number];

const TIER_BLURB: Record<Tier, string> = {
  open: "Records are stored in the clear. This host can read every one of them.",
  attributed: "Records are sealed, and this host sees who wrote which.",
  private: "Records are sealed and this host cannot see the membership at all.",
};

/**
 * The rooms this community hosts.
 *
 * **Exempt on purpose, and the one place in a plugin where that is not a
 * smell.** Every `rooms/*` Trust Task is authorised by a credential the ROOM
 * issued, checked against the room's own identifier — invariant I5, and what
 * lets a room change hosts. This asks the opposite question: what is this
 * *operator* storing. It is answered from the host's own admin authority, so
 * pairing it with a room task would claim a room governs an answer it has no
 * view of. The daemon mounts it off the Trust-Task router for exactly that
 * reason, so sending a header here would be inventing a task URI that names
 * nothing.
 */
async function fetchRooms(): Promise<HostedRoom[]> {
  return getJsonExempt<HostedRoom[]>("/v1/rooms");
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
  return postJson<PolicyTestResponse>(
    `/v1/policies/${policyId}/test`,
    {
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
    },
    { trustTask: TRUST_TASK_TEST },
  );
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

const LIFECYCLE_MEANS: Record<string, string> = {
  live: "Renewed. Accepting writes.",
  lapsed:
    "The epoch expired, so the room is read-only. Nothing is destroyed or hidden, and one renewal returns it to live \u2014 often this is just somebody on holiday.",
  dormant:
    "Still unrenewed after the grace window. The owner is owed the notice, and a successor the room nominated may claim it from here.",
  reclaimable:
    "Past the retention period agreed at creation. The host may delete it; reads keep working until it does.",
};

function LifecyclePill({ value }: { value: string }) {
  // `lapsed` must not read as a failure — the room is intact and one renewal
  // fixes it. `reclaimable` is the only state where anything is at risk.
  const tone =
    value === "live" ? "success" : value === "reclaimable" ? "danger" : "warning";
  return (
    <span className={`chip ${tone}`} title={LIFECYCLE_MEANS[value] ?? value}>
      {value}
    </span>
  );
}

function RoomsTable({ rooms }: { rooms: HostedRoom[] }) {
  const nameBook = useNameBook();
  return (
    <table className="data-table">
      <thead>
        <tr>
          <th>Room</th>
          <th>Owner</th>
          <th>Tier</th>
          <th>Epoch</th>
          <th>Lifecycle</th>
          <th>Retention</th>
          <th>Created</th>
        </tr>
      </thead>
      <tbody>
        {rooms.map((r) => (
          <tr key={r.roomId}>
            <td>
              <code title={r.roomId}>{shorten(r.roomId)}</code>
              {r.mirrorOf && (
                <div className="muted" style={{ fontSize: "0.85em" }}>
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
                <div className="muted" style={{ fontSize: "0.85em" }}>
                  expires {formatEpoch(r.epochExpiresAt)}
                </div>
              ) : null}
            </td>
            <td>
              <LifecyclePill value={r.lifecycle} />
            </td>
            <td>
              {r.retentionDays}d
              <div className="muted" style={{ fontSize: "0.85em" }}>
                {r.retentionPolicy === "chained" ? "history kept" : "from join"}
              </div>
            </td>
            <td>{formatEpoch(r.createdAt)}</td>
          </tr>
        ))}
      </tbody>
    </table>
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
            <table className="data-table" style={{ marginTop: "var(--space-4)" }}>
              <thead>
                <tr>
                  <th>Tier</th>
                  <th>A member may create</th>
                  <th>What the policy said</th>
                </tr>
              </thead>
              <tbody>
                {TIERS.map((tier) => {
                  const v = probesQuery.data[tier];
                  const allowed = v?.effect === "allow";
                  return (
                    <tr key={tier}>
                      <td>
                        {tier}
                        <div className="muted" style={{ fontSize: "0.85em" }}>
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
              </tbody>
            </table>
          )}
        </>
      )}

      <p className="muted" style={{ marginTop: "var(--space-4)" }}>
        To change any of it, edit the <b>rooms</b> policy under Ceremonies. The
        shipped default denies the private tier deliberately: a community that has
        not decided should not find out it is hosting rooms whose membership it
        cannot see.
      </p>
    </section>
  );
}

export function Rooms() {
  const roomsQuery = useQuery({ queryKey: ["rooms"], queryFn: fetchRooms });
  const rooms = roomsQuery.data ?? [];

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
      <h2>Data rooms</h2>
      <p className="lead">
        Rooms this community stores. It cannot read their records and holds no
        member list — both by construction — so this is the row and nothing
        derived from a room's contents. The owner is shown at every tier,
        including private, because they are the party a quota or reclamation
        notice has to reach.
      </p>

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
          <div className="empty-state">
            <span className="empty-icon" aria-hidden="true">
              <DoorOpen />
            </span>
            <h4>No rooms hosted here</h4>
            <p>
              A room appears once its owner registers it with this community. The
              policy below decides who may.
            </p>
          </div>
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

      <CreationPolicy />
    </section>
  );
}
