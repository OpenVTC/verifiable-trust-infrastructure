// The community's groups in the member portal (`vtc/groups/*`):
//
//   #/groups          The groups you belong to, and the ones you may join.
//   #/groups/<id>     One group: what it is, who is in it where it shows them,
//                     and joining or leaving it.
//
// Signed by this browser's portal key for the member, as the directory is.
// Each group's members are listed only where the group shows them to you; the
// community decides that, not this page.

import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { LogIn, LogOut, Users } from "lucide-react";

import type { Group } from "@/lib/wire-types";

import { DirectoryError } from "./directory-api";
import { joinGroup, leaveGroup, listGroups, listMembers, showGroup } from "./groups-api";
import { Crumbs, MemberAvatar, nameOf } from "./member-card";

const JOINING: Record<string, string> = {
  closed: "Its managers add its members",
  request: "Ask to join; a manager decides",
  open: "Anyone in the community may join",
};

function standingLabel(m: string): string | null {
  switch (m) {
    case "member":
      return "You're a member";
    case "pending":
      return "Your membership is pending";
    case "requested":
      return "You've asked to join";
    default:
      return null;
  }
}

function Unavailable({ error }: { error: unknown }) {
  const e = error instanceof DirectoryError ? error : null;
  return (
    <div className="alert" role="status">
      {e?.needsWallet ? (
        <>
          <p className="alert-title">Sign in with your wallet to see the groups.</p>
          <p>
            Your wallet lets this browser act for you in the community for this session. Sign out,
            then sign in again with &ldquo;Sign in with your wallet&rdquo;.
          </p>
        </>
      ) : (
        <>
          <p className="alert-title">The groups aren&rsquo;t available right now.</p>
          <p>{(error as Error)?.message}</p>
        </>
      )}
    </div>
  );
}

function GroupTile({ group, mine }: { group: Group; mine: string }) {
  const standing = standingLabel(mine);
  return (
    <a className="card group-tile" href={`#/groups/${encodeURIComponent(group.groupId)}`}>
      <span className="group-tile-name">
        <Users size={18} aria-hidden="true" /> {group.name}
      </span>
      {group.description && <span className="directory-bio">{group.description}</span>}
      <span className="pills">
        {standing && <span className="pill pill-ok">{standing}</span>}
        {group.joinPolicy && mine === "none" && (
          <span className="pill">{JOINING[group.joinPolicy] ?? group.joinPolicy}</span>
        )}
        {typeof group.memberCount === "number" && (
          <span className="pill">
            {group.memberCount} member{group.memberCount === 1 ? "" : "s"}
          </span>
        )}
      </span>
    </a>
  );
}

export function GroupsPage() {
  const list = useQuery({ queryKey: ["groups", "list"], queryFn: listGroups, retry: false });
  const items = list.data?.items ?? [];
  const mine = items.filter((i) => i.myMembership !== "none");
  const others = items.filter((i) => i.myMembership === "none");
  return (
    <main className="home" id="main">
      <Crumbs trail={[{ label: "Groups" }]} />
      <section className="welcome">
        <p className="eyebrow">Groups</p>
        <h1>Groups</h1>
        <p className="lead">
          Working groups, chapters and teams in the community. Each group gives its members a
          credential others can check.
        </p>
      </section>
      {list.isPending && <p className="muted">Loading…</p>}
      {list.isError && <Unavailable error={list.error} />}
      {list.isSuccess && items.length === 0 && (
        <p className="muted">There are no groups you can see yet.</p>
      )}
      {mine.length > 0 && (
        <section>
          <h2>Your groups</h2>
          <ul className="directory-grid">
            {mine.map(({ group, myMembership }) => (
              <li key={group.groupId}>
                <GroupTile group={group} mine={myMembership} />
              </li>
            ))}
          </ul>
        </section>
      )}
      {others.length > 0 && (
        <section>
          <h2>{mine.length > 0 ? "Other groups" : "Groups in the community"}</h2>
          <ul className="directory-grid">
            {others.map(({ group, myMembership }) => (
              <li key={group.groupId}>
                <GroupTile group={group} mine={myMembership} />
              </li>
            ))}
          </ul>
        </section>
      )}
    </main>
  );
}

export function GroupPage({ groupId }: { groupId: string }) {
  const qc = useQueryClient();
  const [message, setMessage] = useState("");
  const [note, setNote] = useState<string | null>(null);
  const q = useQuery({
    queryKey: ["groups", "show", groupId],
    queryFn: () => showGroup(groupId),
    retry: false,
  });
  const group = q.data?.group;
  const mine = q.data?.myMembership ?? "none";
  const members = useQuery({
    queryKey: ["groups", "members", groupId],
    queryFn: () => listMembers(groupId),
    retry: false,
    enabled: Boolean(group),
  });
  const refresh = () => void qc.invalidateQueries({ queryKey: ["groups"] });
  const join = useMutation({
    mutationFn: () => joinGroup(groupId, message.trim() || undefined),
    onSuccess: (a) => {
      setMessage("");
      setNote(
        a.outcome === "joined"
          ? "You're in. Your wallet receives the group's credential."
          : "You've asked to join. A manager decides.",
      );
      refresh();
    },
    onError: (e) => setNote((e as Error).message),
  });
  const leave = useMutation({
    mutationFn: () => leaveGroup(groupId),
    onSuccess: (a) => {
      setNote(a.state === "requestWithdrawn" ? "Your request is withdrawn." : "You've left the group.");
      refresh();
    },
    onError: (e) => setNote((e as Error).message),
  });

  return (
    <main className="home" id="main">
      <Crumbs trail={[{ label: "Groups", href: "#/groups" }, { label: group?.name ?? "Group" }]} />
      {q.isPending && <p className="muted">Loading…</p>}
      {q.isError && <Unavailable error={q.error} />}
      {group && (
        <>
          <section className="welcome">
            <p className="eyebrow">Group</p>
            <h1>{group.name}</h1>
            {group.description && <p className="lead">{group.description}</p>}
            <p className="muted">{group.joinPolicy ? JOINING[group.joinPolicy] : null}</p>
          </section>
          {note && (
            <p className="note" role="status">
              {note}
            </p>
          )}
          <section className="card group-actions">
            {mine === "member" || mine === "pending" ? (
              <button
                type="button"
                className="btn btn-ghost"
                onClick={() => leave.mutate()}
                disabled={leave.isPending}
              >
                <LogOut size={16} aria-hidden="true" /> Leave this group
              </button>
            ) : group.joinPolicy === "open" || group.joinPolicy === "request" ? (
              <form
                className="stack"
                onSubmit={(e) => {
                  e.preventDefault();
                  join.mutate();
                }}
              >
                {group.joinPolicy === "request" && (
                  <label>
                    A note for its managers (optional)
                    <textarea
                      value={message}
                      maxLength={280}
                      onChange={(e) => setMessage(e.target.value)}
                    />
                  </label>
                )}
                <button type="submit" className="btn btn-primary" disabled={join.isPending}>
                  <LogIn size={16} aria-hidden="true" />{" "}
                  {group.joinPolicy === "open" ? "Join" : "Ask to join"}
                </button>
              </form>
            ) : (
              <p className="muted">Its managers add its members.</p>
            )}
          </section>
          {members.isSuccess && (
            <section>
              <h2>Members</h2>
              <ul className="directory-grid">
                {members.data.items.map((m) => {
                  const fields = (m.fields ?? {}) as Record<string, unknown>;
                  const name = nameOf(fields);
                  return (
                    <li key={m.entryId}>
                      <a
                        className="card directory-entry"
                        href={`#/directory/${encodeURIComponent(m.entryId)}`}
                      >
                        <span className="directory-entry-head">
                          <MemberAvatar
                            entryId={m.entryId}
                            value={fields.avatar}
                            name={name}
                            size={40}
                          />
                          <span className="directory-name">{name ?? "A member"}</span>
                        </span>
                      </a>
                    </li>
                  );
                })}
              </ul>
            </section>
          )}
        </>
      )}
    </main>
  );
}
