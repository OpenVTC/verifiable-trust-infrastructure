// The Community rooms tab of the Data rooms page (`plugins/dataRooms.tsx`) —
// rooms this community **owns**, run by its administrators
// (`lib/community-rooms-api.ts`, docs/03-vtc/community-rooms.md).
//
// The Rooms tab beside it is the host's view of every room the community
// stores, most of which members own; this one is the owner's: each room's
// label and description, its tags, tier, how many members it has admitted and
// offered, and when the community's own authority over it lapses. Tags filter
// the list (`?tag=`); they are administrators' filing and never reach a member. It answers `vtc.rooms.manage`, and
// a viewer who holds only `vtc.rooms.admin` does not see it.
//
// **Off until the operator turns it on.** An upgraded VTC has no
// `[rooms.community]` section, and the list then carries the section to add in
// `ext["org.openvtc"].communityRooms` — shown here rather than discovered as a
// refused create.
//
// **Re-reading.** A create registers a room, which the live channel's `rooms`
// topic hints about (to `vtc.rooms.admin` holders), and every query here sits
// under the `["rooms"]` key that hint invalidates. Who was offered or admitted
// is the owner's record, which no topic carries, so these pages also poll at
// the ordinary pace whether or not the stream is live, and re-read after every
// change made from them.

import { useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Plus, Users } from "lucide-react";

import { useConfirm } from "@/components/ConfirmDialog";
import { DataTable } from "@/components/DataTable";
import { EmptyState } from "@/components/EmptyState";
import { Field } from "@/components/Field";
import {
  AUTHORITY_WARN_DAYS,
  COMMUNITY_ROOMS_LIST_KEY,
  MAX_DESCRIPTION,
  createCommunityRoom,
  daysUntil,
  fetchCommunityRooms,
  parseTags,
  tagsOf,
  type AuthorityRenewal,
  type CommunityRoomsSetting,
  type VtaAccess,
} from "@/lib/community-rooms-api";
import { formatIso, shorten } from "@/lib/format";
import { gestureFromConfirm } from "@/lib/signed-act";
import { fetchStorageConfigs } from "@/lib/storage-api";
import { useToast } from "@/lib/toast";
import { OFFLINE_POLL_MS } from "@/lib/use-live-events";
import { useCan } from "@/lib/viewer";
import type { CommunityRoom, CommunityRoomCreatePayload } from "@/lib/wire-types";

import { RefusalCard, VtaFixCommands } from "./CommunityRefusal";
import { LifecyclePill, TIER_BLURB, communityRoomPath } from "./shared";

/** The query key of the owner's list. Under `["rooms"]`, which a live `rooms`
 *  hint invalidates. */
export const COMMUNITY_ROOMS_KEY = ["rooms", "community"] as const;

/** The page header's primary action on this tab. */
export function NewCommunityRoomButton() {
  const [params, setParams] = useSearchParams();
  if (params.get("create") === "1") return null;
  return (
    <button type="button" onClick={() => setParams({ create: "1" })}>
      <Plus aria-hidden="true" />
      New community room
    </button>
  );
}

/** Community rooms are off: the section to add, as the VTC itself words it. */
function CommunityRoomsOff({ setting }: { setting: CommunityRoomsSetting }) {
  const noEntry = setting.vtaAccess?.fixes.find((f) => f.id === "noEntry");
  return (
    <section className="card">
      <h2>Community rooms are off</h2>
      <p className="muted">
        This community cannot own a room until its operator says which context at the
        community&rsquo;s VTA holds the rooms&rsquo; keys. Add this section to the VTC&rsquo;s
        configuration file and restart it:
      </p>
      <pre className="rooms-config-snippet">
        {setting.configure ??
          '[rooms.community]\ncontext = "<the context at the community\'s VTA the rooms\' keys are minted in>"'}
      </pre>
      <p className="muted rooms-sub">
        The VTC also needs its link to that VTA (<code>vta_did</code> and{" "}
        <code>[messaging]</code>, already there on a VTA-provisioned VTC), and at the VTA its own
        DID needs an entry covering the context that holds the VTC&rsquo;s DID as well as the
        rooms context, that may mint DIDs, issue credentials and keep them (<code>key-mint</code>,{" "}
        <code>credential-write</code>, <code>vault-write</code>). Where each room&rsquo;s DID is
        published, and the rest, is in the community rooms guide (docs/03-vtc/community-rooms.md).
      </p>
      {noEntry && <VtaFixCommands fix={noEntry} />}
    </section>
  );
}

/** The VTC's configuration looks wrong for its entry at its VTA: say so, with the
 *  commands, before anything is refused. */
function VtaAccessWarning({ access }: { access: VtaAccess }) {
  const scope = access.fixes.find((f) => f.id === "scope");
  return (
    <section className="card warning" role="status">
      <h2>Check the community&rsquo;s entry at its VTA</h2>
      <p>{access.warning}</p>
      {scope && <VtaFixCommands fix={scope} />}
    </section>
  );
}

/** A renewal of the community's own authority that is failing, and why. The
 *  VTC renews it itself; this is what an administrator sees when it cannot. */
export function RenewalFailing({ renewal }: { renewal?: AuthorityRenewal | null }) {
  if (renewal?.state !== "failing") return null;
  return (
    <div className="rooms-sub">
      <span className="chip danger" title={renewal.lastError}>
        renewal failing{renewal.attempts ? ` (${renewal.attempts}×)` : ""}
      </span>
      {renewal.lastError && <div className="muted">{renewal.lastError}</div>}
      {renewal.nextAttemptAt && (
        <div className="muted">Next attempt {formatIso(renewal.nextAttemptAt)}.</div>
      )}
    </div>
  );
}

/** When the community's own authority over a room lapses, said as a warning
 *  once it is near. */
export function AuthorityExpiry({ until }: { until?: string }) {
  if (!until) return <span className="muted">—</span>;
  const days = daysUntil(until);
  const tone = days === null ? "" : days < 0 ? "danger" : days <= AUTHORITY_WARN_DAYS ? "warning" : "";
  return (
    <>
      {formatIso(until)}
      {tone && (
        <div className="rooms-sub">
          <span className={`chip ${tone}`}>
            {days! < 0 ? "lapsed" : `${days} day${days === 1 ? "" : "s"} left`}
          </span>
        </div>
      )}
    </>
  );
}

/** A room's tags, as chips. With `onPick`, each is a button that filters by it. */
export function TagChips({ tags, onPick }: { tags: readonly string[]; onPick?: (tag: string) => void }) {
  return (
    <span className="rooms-tags">
      {tags.map((t) =>
        onPick ? (
          <button
            key={t}
            type="button"
            className="chip accent"
            title={`Only rooms tagged ${t}`}
            onClick={() => onPick(t)}
          >
            {t}
          </button>
        ) : (
          <span key={t} className="chip accent">
            {t}
          </span>
        ),
      )}
    </span>
  );
}

/** Filter by one tag, or none. */
function TagFilter({
  tags,
  value,
  onChange,
}: {
  tags: readonly string[];
  value: string | null;
  onChange: (tag: string | null) => void;
}) {
  return (
    <div className="rooms-tag-filter" role="group" aria-label="Filter by tag">
      <span className="muted rooms-sub">Tags:</span>
      <button type="button" className="chip" aria-pressed={value === null} onClick={() => onChange(null)}>
        All
      </button>
      {tags.map((t) => (
        <button
          key={t}
          type="button"
          className="chip"
          aria-pressed={value === t}
          onClick={() => onChange(value === t ? null : t)}
        >
          {t}
        </button>
      ))}
    </div>
  );
}

function CommunityRoomsTable({
  rooms,
  renewal,
  onTag,
}: {
  rooms: CommunityRoom[];
  renewal: Record<string, AuthorityRenewal>;
  onTag: (tag: string) => void;
}) {
  return (
    <DataTable
      columns={[
        { key: "room", label: "Room" },
        { key: "tier", label: "Tier" },
        { key: "lifecycle", label: "Lifecycle" },
        { key: "members", label: "Members" },
        { key: "authority", label: "Community's authority until" },
        { key: "created", label: "Created" },
      ]}
    >
      {rooms.map((r) => (
        <tr key={r.room.roomId}>
          <td>
            <Link to={communityRoomPath(r.room.roomId)} title={r.room.roomId}>
              {r.label}
            </Link>
            {r.description && (
              <div className="muted rooms-sub rooms-description-preview" title={r.description}>
                {r.description}
              </div>
            )}
            {r.tags && r.tags.length > 0 && (
              <div className="rooms-sub">
                <TagChips tags={r.tags} onPick={onTag} />
              </div>
            )}
            <div className="muted rooms-sub">
              <code>{shorten(r.room.roomId)}</code>
            </div>
          </td>
          <td>{r.room.visibility}</td>
          <td>
            <LifecyclePill value={r.room.lifecycle} />
          </td>
          <td>
            {r.admitted} admitted
            <div className="muted rooms-sub">{r.offered} offered</div>
          </td>
          <td>
            <AuthorityExpiry until={r.ownerAuthorityValidUntil} />
            <RenewalFailing renewal={renewal[r.room.roomId]} />
          </td>
          <td>{new Date(r.room.createdAt * 1000).toLocaleDateString()}</td>
        </tr>
      ))}
    </DataTable>
  );
}

/** The tiers a community room may be created at here, and why one is not. */
const CREATE_TIERS = [
  { id: "attributed", note: TIER_BLURB.attributed },
  { id: "open", note: TIER_BLURB.open },
  {
    id: "private",
    note: "Not served for community rooms yet, and the shipped rooms policy refuses it.",
    disabled: true,
  },
] as const;

function NewCommunityRoom({ onDone }: { onDone: () => void }) {
  const confirm = useConfirm();
  const toast = useToast();
  const queryClient = useQueryClient();
  const hostAdmin = useCan("vtc.rooms.admin", "*");
  const [label, setLabel] = useState("");
  const [description, setDescription] = useState("");
  const [tagText, setTagText] = useState("");
  const [visibility, setVisibility] = useState<"attributed" | "open">("attributed");
  const [retentionPolicy, setRetentionPolicy] = useState<"chained" | "fromJoin">("chained");
  const [retentionDays, setRetentionDays] = useState("");
  const [storageConfig, setStorageConfig] = useState("");
  const [reason, setReason] = useState("");

  // Where the room's files go: only a holder of the host's authority can list
  // the locations; anyone else gets the community's default.
  const configs = useQuery({
    queryKey: ["storage", "list"],
    queryFn: fetchStorageConfigs,
    enabled: hostAdmin,
  });
  const active = (configs.data ?? []).filter((c) => c.config.state === "active");

  const days = retentionDays.trim() === "" ? undefined : Number(retentionDays);
  const daysValid = days === undefined || (Number.isInteger(days) && days >= 1 && days <= 36500);
  const parsedTags = parseTags(tagText);
  const tags = "tags" in parsedTags ? parsedTags.tags : null;

  const create = useMutation({
    mutationFn: () => {
      const payload: CommunityRoomCreatePayload = {
        label: label.trim(),
        visibility,
        reason: reason.trim(),
        ...(description.trim() ? { description: description.trim() } : {}),
        ...(tags && tags.length > 0 ? { tags } : {}),
        ...(retentionPolicy !== "chained" ? { retentionPolicy } : {}),
        ...(days !== undefined ? { retentionDays: days } : {}),
        ...(storageConfig ? { storageConfig } : {}),
      };
      return createCommunityRoom(payload, gestureFromConfirm(confirm));
    },
    onSuccess: (r) => {
      toast.push("success", `Created the community room “${r.room.label}”.`);
      void queryClient.invalidateQueries({ queryKey: ["rooms"] });
    },
  });

  if (create.isSuccess) {
    const room = create.data.room;
    return (
      <section className="card success" role="status">
        <h2>Created</h2>
        <p>
          <b>{room.label}</b> is the community&rsquo;s, at <code>{room.room.roomId}</code>. Its VTA
          holds the room&rsquo;s keys, and the community holds its own <code>admin</code> authority
          over it until {room.ownerAuthorityValidUntil ? formatIso(room.ownerAuthorityValidUntil) : "it expires"}.
        </p>
        <p>
          <Link to={communityRoomPath(room.room.roomId)}>Add its members</Link>
        </p>
        <button type="button" className="secondary" onClick={onDone}>
          Close
        </button>
      </section>
    );
  }

  return (
    <section className="card" aria-labelledby="new-community-room-title">
      <h2 id="new-community-room-title">New community room</h2>
      <p className="muted">
        The community&rsquo;s VTA mints the room&rsquo;s identity and holds its keys; the community
        holds its own <code>admin</code> authority over it and is its host. This takes your passkey
        (or step-up approver) for this one request, and is audited with your reason.
      </p>
      <form
        className="form-stack"
        onSubmit={(e) => {
          e.preventDefault();
          create.mutate();
        }}
      >
        <Field label="Label" hint="How administrators and members see the room, such as “Board pack”.">
          <input required maxLength={128} value={label} onChange={(e) => setLabel(e.target.value)} />
        </Field>
        <Field
          label="Description"
          hint="What the room is for, shown beside its label to administrators and to members offered a place. Optional; not personal data."
        >
          <textarea
            rows={3}
            maxLength={MAX_DESCRIPTION}
            value={description}
            onChange={(e) => setDescription(e.target.value)}
          />
        </Field>
        <Field
          label="Tags"
          hint="Optional, up to 8, separated by commas — such as “board, finance” — to filter the list by. For administrators only."
          error={"error" in parsedTags ? parsedTags.error : undefined}
        >
          <input placeholder="board, finance" value={tagText} onChange={(e) => setTagText(e.target.value)} />
        </Field>
        <fieldset className="community-choices">
          <legend className="field-label">Tier — fixed for the room&rsquo;s life</legend>
          {CREATE_TIERS.map((t) => (
            <label key={t.id} className={"disabled" in t && t.disabled ? "muted" : undefined}>
              <input
                type="radio"
                name="community-room-tier"
                value={t.id}
                checked={visibility === t.id}
                disabled={"disabled" in t && t.disabled}
                onChange={() => setVisibility(t.id as "attributed" | "open")}
              />{" "}
              {t.id}
              <div className="muted rooms-sub">{t.note}</div>
            </label>
          ))}
        </fieldset>
        <Field
          label="History"
          hint="Whether a member admitted later reads what was written before they joined."
        >
          <select
            value={retentionPolicy}
            onChange={(e) => setRetentionPolicy(e.target.value as "chained" | "fromJoin")}
          >
            <option value="chained">Kept — later members read the history</option>
            <option value="fromJoin">From join — each member reads from their admission on</option>
          </select>
        </Field>
        <Field
          label="Retention (days)"
          hint="The retention period agreed at creation: once a room is past it, this host may reclaim it. Empty: 90."
          error={daysValid ? undefined : "A whole number of days, 1 to 36500."}
        >
          <input
            inputMode="numeric"
            placeholder="90"
            value={retentionDays}
            onChange={(e) => setRetentionDays(e.target.value)}
          />
        </Field>
        {hostAdmin && active.length > 0 && (
          <Field label="Storage" hint="Where its files go. Empty: the community's default location.">
            <select value={storageConfig} onChange={(e) => setStorageConfig(e.target.value)}>
              <option value="">Default</option>
              {active.map((c) => (
                <option key={c.config.id} value={c.config.id}>
                  {c.config.label}
                  {c.config.isDefault ? " (default)" : ""}
                </option>
              ))}
            </select>
          </Field>
        )}
        <Field label="Reason" hint="Recorded in the audit trail.">
          <input required maxLength={500} value={reason} onChange={(e) => setReason(e.target.value)} />
        </Field>
        <div className="form-actions">
          <button
            type="submit"
            className="primary"
            disabled={!label.trim() || !reason.trim() || !daysValid || !tags || create.isPending}
          >
            {create.isPending ? "Creating…" : "Create room"}
          </button>
          <button type="button" className="secondary" onClick={onDone}>
            Cancel
          </button>
        </div>
      </form>
      <RefusalCard title="Not created" error={create.error} />
    </section>
  );
}

/** The Community rooms tab of the Data rooms page. */
export function CommunityRoomsList() {
  const [params, setParams] = useSearchParams();
  const creating = params.get("create") === "1";
  const q = useQuery({
    queryKey: COMMUNITY_ROOMS_LIST_KEY,
    queryFn: fetchCommunityRooms,
    // No live topic carries the owner's record; see the header.
    refetchInterval: OFFLINE_POLL_MS,
  });
  const off = q.data?.setting.enabled === false;
  const all = q.data?.rooms ?? [];
  const tags = tagsOf(all);
  // A tag no room carries any longer filters nothing: show them all.
  const wanted = params.get("tag");
  const tag = wanted !== null && tags.includes(wanted) ? wanted : null;
  const rooms = tag === null ? all : all.filter((r) => r.tags?.includes(tag));
  const setTag = (t: string | null) => {
    const next = new URLSearchParams(params);
    if (t === null) next.delete("tag");
    else next.set("tag", t);
    setParams(next);
  };

  return (
    <>
      {off && <CommunityRoomsOff setting={q.data!.setting} />}
      {q.data?.setting.vtaAccess?.warning && <VtaAccessWarning access={q.data.setting.vtaAccess} />}
      {creating && <NewCommunityRoom onDone={() => setParams({})} />}

      {q.isPending && (
        <section className="card">
          <p>Reading the community&rsquo;s rooms…</p>
        </section>
      )}
      {q.isError && <RefusalCard title="The community's rooms could not be read" error={q.error} />}

      {q.data && all.length === 0 && !creating && (
        <section className="card">
          <EmptyState icon={Users} title="The community owns no rooms yet">
            A room the community owns is run by its administrators and outlives any of them — the
            board&rsquo;s papers, a working group&rsquo;s drafts, a members&rsquo; library.
            {off ? " Turn community rooms on first." : " Create one with New community room."}
          </EmptyState>
        </section>
      )}

      {all.length > 0 && (
        <section className="card">
          {tags.length > 0 && <TagFilter tags={tags} value={tag} onChange={setTag} />}
          <CommunityRoomsTable rooms={rooms} renewal={q.data?.renewal ?? {}} onTag={setTag} />
          {q.data?.truncated && (
            <p className="muted rooms-sub">More rooms exist than this page reads.</p>
          )}
        </section>
      )}
    </>
  );
}
