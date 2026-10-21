// The member directory in the portal: find other members, and decide what
// your own card shows and to whom (docs/03-vtc/member-directory.md).
//
//   #/directory              browse and search
//   #/directory/<entryId>    one member's entry, as you are allowed to see it
//   #/card                   your own card
//
// Every page signs with this browser's sign-in key, which the member let act
// for them in the directory for this session (`./directory-api`). What another
// member's entry shows is the community's projection for you: their choices,
// the field's ceiling and the community's policy. What you set here is
// exactly what the community will apply to your values; it never widens
// anything on its own.
//
// Values other members typed are rendered as text, never as markup, and a
// picture is shown only once its bytes match the digest its card names.

import { useEffect, useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { BookUser, Contact, Copy, ExternalLink, Globe, ImagePlus, Pencil, Search, Star, Trash2 } from "lucide-react";

import type {
  DirectoryCard,
  DirectoryCardBlobRef,
  DirectoryCardUpdatePayload,
  DirectoryFieldDefinition,
} from "@/lib/wire-types";

import {
  DirectoryError,
  listEntries,
  listFields,
  showCard,
  showEntry,
  updateCard,
  uploadImage,
} from "./directory-api";
import { PictureError, prepare, toBase64Url } from "./picture";
import {
  Crumbs,
  FieldPicture,
  Verified,
  verifiedOf,
  MemberAvatar,
  blobRef,
  hueOf,
  nameOf,
  safeUrl,
  saveVcard,
  text,
  vcardOf,
} from "./member-card";
import { memberFetch, vtcDid, type MemberMe } from "./api";
import {
  starredFirst,
  useEnableMarks,
  useMark,
  useMarks,
  useNewList,
  walletMarks,
  type EntryMark,
  type Marks,
} from "./wallet-marks";

/** The wallet's directory channel (`window.vtaWallet.directory`), where the
 *  member's wallet offers one: it publishes the card after showing the member
 *  every value, signed by them. Absent: the portal says to use the wallet. */
interface WalletDirectory {
  publishCard(p: { hostDid: string; member?: string }): Promise<{ state: string }>;
}

function walletDirectory(): WalletDirectory | null {
  const w = (window as { vtaWallet?: { directory?: WalletDirectory } }).vtaWallet;
  return w?.directory && typeof w.directory.publishCard === "function" ? w.directory : null;
}

type Audience = DirectoryFieldDefinition["ceiling"];

const AUDIENCES: readonly { id: Audience; label: string }[] = [
  { id: "admins", label: "Only administrators" },
  { id: "groups", label: "People in my groups" },
  { id: "connections", label: "My connections" },
  { id: "members", label: "All members" },
  { id: "public", label: "Anyone" },
];

/** The daemon's audience order: `groups` and `connections` cover neither. */
export function within(inner: Audience, outer: Audience): boolean {
  if (inner === outer || inner === "admins") return true;
  if ((inner === "groups" || inner === "connections") && (outer === "members" || outer === "public"))
    return true;
  return inner === "members" && outer === "public";
}

/**
 * What "show every field to `wanted`" sets one field to: `wanted` where the
 * field's ceiling allows it, otherwise the widest the field allows within it —
 * its ceiling, or only administrators where the two do not nest (`groups`
 * against `connections`). Never wider than the member asked for.
 */
export function baselineFor(wanted: Audience, ceiling: Audience): Audience {
  if (within(wanted, ceiling)) return wanted;
  if (within(ceiling, wanted)) return ceiling;
  return "admins";
}

/** Shown in place of a page when this browser may not act in the directory. */
function NeedsWallet({ error }: { error: unknown }) {
  const e = error instanceof DirectoryError ? error : null;
  return (
    <div className="alert" role="status">
      {e?.needsWallet ? (
        <>
          <p className="alert-title">Sign in with your wallet to use the directory.</p>
          <p>
            Your wallet lets this browser read the directory and edit your card for this session.
            Sign out, then sign in again with &ldquo;Sign in with your wallet&rdquo;.
          </p>
        </>
      ) : (
        <>
          <p className="alert-title">The directory isn&rsquo;t available right now.</p>
          <p>{(error as Error)?.message}</p>
        </>
      )}
    </div>
  );
}

/** A member's role and the badges this viewer may see, as pills. */
function Pills({ fields, connected }: { fields: Record<string, unknown>; connected?: boolean }) {
  return (
    <span className="pills">
      {text(fields.role) && <span className="pill cap">{text(fields.role)}</span>}
      {fields.personhood === true && <span className="pill pill-ok">Verified person</span>}
      {connected === true && <span className="pill pill-ok">Connected</span>}
    </span>
  );
}

// ─── browse and search ────────────────────────────────────────────────────

type ListedEntry = { entryId: string; fields: Record<string, unknown>; connected?: boolean };

/** One member, as the grid shows them. */
/** The member's star on an entry, as a toggle. */
function StarToggle({ entryId, mark, name }: { entryId: string; mark: EntryMark | undefined; name: string }) {
  const set = useMark();
  const on = mark?.starred ?? false;
  return (
    <button
      type="button"
      className={`star-toggle${on ? " star-on" : ""}`}
      aria-pressed={on}
      aria-label={on ? `Unstar ${name}` : `Star ${name}`}
      title={on ? "Starred — only you see this" : "Star — only you see this"}
      disabled={set.isPending}
      onClick={() => set.mutate({ entryId, starred: !on })}
    >
      <Star size={16} aria-hidden="true" fill={on ? "currentColor" : "none"} />
    </button>
  );
}

function MemberTile({ entry, marks }: { entry: ListedEntry; marks?: Marks | null }) {
  const mark = marks?.entries[entry.entryId];
  const name = nameOf(entry.fields);
  const nickname = text(entry.fields.nickname);
  const subtitle = [
    nickname && nickname !== name ? `“${nickname}”` : "",
    text(entry.fields.pronouns),
  ]
    .filter(Boolean)
    .join(" · ");
  // The star sits beside the link, never inside it.
  return (
    <div className="directory-tile">
    <a className="card directory-entry" href={`#/directory/${encodeURIComponent(entry.entryId)}`}>
      <span className="directory-entry-head">
        <MemberAvatar entryId={entry.entryId} value={entry.fields.avatar} name={name} size={52} />
        <span className="directory-entry-names">
          <span className="directory-name">{name ?? "A member"}</span>
          {subtitle && <span className="muted directory-sub">{subtitle}</span>}
          {/* Marked as the member's own, never passing for the member's name. */}
          {mark?.petname && <span className="muted directory-sub petname">Your name for them: {mark.petname}</span>}
        </span>
      </span>
      {text(entry.fields.bio) && <span className="directory-bio">{text(entry.fields.bio)}</span>}
      <Pills fields={entry.fields} connected={entry.connected} />
    </a>
      {marks && <StarToggle entryId={entry.entryId} mark={mark} name={name ?? "this member"} />}
    </div>
  );
}

export function DirectoryPage() {
  const [draft, setDraft] = useState("");
  const [query, setQuery] = useState<string | undefined>(undefined);
  const [showNameless, setShowNameless] = useState(false);
  const list = useQuery({
    queryKey: ["directory", "entries", query ?? ""],
    queryFn: () => listEntries({ ...(query ? { query } : {}), limit: 50 }),
    retry: false,
  });
  const marks = useMarks();
  const enable = useEnableMarks();
  const [onList, setOnList] = useState<string | null>(null);
  const m = marks.data ?? null;
  // Applied here, to what the directory answered: the community is asked the
  // same thing whatever the member starred or listed.
  const all = starredFirst((list.data?.items ?? []) as ListedEntry[], m);
  const items = onList && m ? all.filter((e) => m.entries[e.entryId]?.lists?.includes(onList)) : all;
  // Members who show no name are folded away while browsing: a wall of "A
  // member" tells nobody anything. A search shows whatever matched.
  const named = query ? items : items.filter((e) => nameOf(e.fields) !== null);
  const nameless = query ? [] : items.filter((e) => nameOf(e.fields) === null);

  return (
    <main className="home" id="main">
      <Crumbs trail={[{ label: "Directory" }]} />
      <section className="welcome">
        <p className="eyebrow">Directory</p>
        <h1>Members</h1>
        <p className="lead">
          Each member decides what you see here. <a href="#/card">Edit your own card</a>.
        </p>
        {walletMarks() && !m && (
          <p className="muted">
            <button
              type="button"
              className="btn btn-ghost btn-sm"
              disabled={enable.isPending}
              onClick={() => enable.mutate()}
            >
              <Star size={14} aria-hidden="true" /> Show my stars and lists
            </button>{" "}
            Your wallet keeps them, not this community; it asks you once before showing them here.
          </p>
        )}
        {enable.isError && <p className="muted">{(enable.error as Error).message}</p>}
        {m && m.lists.length > 0 && (
          <div className="pills" role="group" aria-label="My lists">
            <button
              type="button"
              className={`pill${onList === null ? " pill-ok" : ""}`}
              aria-pressed={onList === null}
              onClick={() => setOnList(null)}
            >
              Everyone
            </button>
            {m.lists.map((l) => (
              <button
                key={l.listId}
                type="button"
                className={`pill${onList === l.listId ? " pill-ok" : ""}`}
                aria-pressed={onList === l.listId}
                onClick={() => setOnList(onList === l.listId ? null : l.listId)}
              >
                {l.name}
              </button>
            ))}
          </div>
        )}
      </section>
      <form
        className="search"
        role="search"
        onSubmit={(e) => {
          e.preventDefault();
          const q = draft.trim();
          setQuery(q === "" ? undefined : q);
        }}
      >
        <input
          aria-label="Search members"
          placeholder="Name or nickname"
          value={draft}
          onChange={(e) => setDraft(e.target.value)}
        />
        <button type="submit" className="btn btn-primary">
          <Search size={16} aria-hidden="true" /> Search
        </button>
      </form>
      {list.isError ? (
        list.error instanceof DirectoryError && list.error.code === "queryTooShort" ? (
          <p className="muted">Type at least three letters, or someone&rsquo;s whole nickname.</p>
        ) : (
          <NeedsWallet error={list.error} />
        )
      ) : list.isPending ? (
        <p className="muted">Loading…</p>
      ) : items.length === 0 ? (
        <p className="muted">{query ? "No one matches." : "No one is listed yet."}</p>
      ) : (
        <>
          {named.length > 0 ? (
            <ul className="directory-grid">
              {named.map((e) => (
                <li key={e.entryId}>
                  <MemberTile entry={e} marks={m} />
                </li>
              ))}
            </ul>
          ) : (
            <p className="muted">No one has added a name to their card yet.</p>
          )}
          {nameless.length > 0 && (
            <div className="nameless">
              <button
                type="button"
                className="btn btn-ghost btn-sm"
                aria-expanded={showNameless}
                onClick={() => setShowNameless(!showNameless)}
              >
                {nameless.length === 1
                  ? "1 member hasn't added a name yet"
                  : `${nameless.length} members haven't added a name yet`}
                {showNameless ? " — hide" : " — show"}
              </button>
              {showNameless && (
                <ul className="directory-grid">
                  {nameless.map((e) => (
                    <li key={e.entryId}>
                      <MemberTile entry={e} marks={m} />
                    </li>
                  ))}
                </ul>
              )}
            </div>
          )}
        </>
      )}
      {typeof list.data?.nextCursor === "string" && (
        <p className="muted">Showing the first 50. Search to narrow it down.</p>
      )}
    </main>
  );
}

// ─── one entry ────────────────────────────────────────────────────────────

/** The fields the profile header and its sections draw themselves. */
const DRAWN = new Set([
  "displayName", "nickname", "pronouns", "avatar", "bio", "links", "role", "joinedAt",
  "personhood", "did",
]);

function CopyDid({ did }: { did: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <span className="did-row">
      <code className="wrap">{did}</code>
      <button
        type="button"
        className="btn btn-ghost btn-sm"
        onClick={() => {
          void navigator.clipboard?.writeText(did).then(() => setCopied(true));
        }}
      >
        <Copy size={14} aria-hidden="true" /> {copied ? "Copied" : "Copy"}
      </button>
    </span>
  );
}

export function EntryPage({ entryId }: { entryId: string }) {
  const qc = useQueryClient();
  const entry = useQuery({
    queryKey: ["directory", "entry", entryId],
    queryFn: () => showEntry(entryId),
    retry: false,
  });
  const fields = useQuery({ queryKey: ["directory", "fields"], queryFn: listFields, retry: false });
  // The member's own card, to know whether this entry is theirs.
  const mine = useQuery({ queryKey: ["directory", "card"], queryFn: showCard, retry: false });
  const own = mine.data?.card.entryId === entryId;
  const marks = useMarks();
  const labels = useMemo(
    () => new Map((fields.data?.fields ?? []).map((f) => [f.key, f.label])),
    [fields.data],
  );
  const pictures = useMemo(
    () => new Set((fields.data?.fields ?? []).filter((f) => f.type === "image").map((f) => f.key)),
    [fields.data],
  );
  const f = (entry.data?.entry.fields ?? {}) as Record<string, unknown>;
  const name = nameOf(f);
  const nickname = text(f.nickname);
  const subtitle = [nickname && nickname !== name ? `“${nickname}”` : "", text(f.pronouns)]
    .filter(Boolean)
    .join(" · ");
  const links = (Array.isArray(f.links) ? f.links.map(String) : []).filter((l) => safeUrl(l));
  const rest = Object.entries(f).filter(([k]) => !DRAWN.has(k));
  const community =
    qc.getQueryData<MemberMe>(["member-me"])?.community.name ?? "This community";

  return (
    <main className="home" id="main">
      <Crumbs trail={[{ label: "Directory", href: "#/directory" }, { label: name ?? "A member" }]} />
      {entry.isError ? (
        entry.error instanceof DirectoryError && entry.error.code === "notFound" ? (
          <p className="muted">This member isn&rsquo;t in the directory, or shows you nothing.</p>
        ) : (
          <NeedsWallet error={entry.error} />
        )
      ) : entry.isPending ? (
        <p className="muted">Loading…</p>
      ) : (
        <article className="card profile">
          <header className="profile-head" style={{ ["--avatar-hue" as string]: hueOf(entryId) }}>
            <MemberAvatar entryId={entryId} value={f.avatar} name={name} size={104} />
            <div className="profile-names">
              <h1>{name ?? "A member"}</h1>
              {subtitle && <p className="muted profile-sub">{subtitle}</p>}
              <Pills fields={f} connected={entry.data.entry.connected} />
              {text(f.joinedAt) && (
                <p className="muted profile-since">
                  Member since {new Date(text(f.joinedAt)).toLocaleDateString()}
                </p>
              )}
            </div>
            <div className="profile-actions">
              {marks.data && !own && (
                <StarToggle entryId={entryId} mark={marks.data.entries[entryId]} name={name ?? "this member"} />
              )}
              {own && (
                <a className="btn btn-primary btn-sm" href="#/card">
                  <Pencil size={14} aria-hidden="true" /> Edit my card
                </a>
              )}
              <button
                type="button"
                className="btn btn-ghost btn-sm"
                onClick={() => saveVcard(vcardOf(entryId, f, labels, community), name ?? "member")}
              >
                <Contact size={14} aria-hidden="true" /> Save contact
              </button>
            </div>
          </header>
          {marks.data && !own && <YourMarks entryId={entryId} marks={marks.data} />}
          {text(f.bio) && (
            <section className="profile-section">
              <h2>{labels.get("bio") ?? "About"}</h2>
              <p className="profile-bio">{text(f.bio)}</p>
            </section>
          )}
          {links.length > 0 && (
            <section className="profile-section">
              <h2>{labels.get("links") ?? "Links"}</h2>
              <ul className="profile-links">
                {links.map((l) => (
                  <li key={l}>
                    <a href={safeUrl(l)!} target="_blank" rel="noopener noreferrer nofollow">
                      <ExternalLink size={14} aria-hidden="true" /> {new URL(l).host}
                      {new URL(l).pathname !== "/" ? new URL(l).pathname : ""}
                    </a>
                  </li>
                ))}
              </ul>
            </section>
          )}
          {(rest.length > 0 || text(f.did)) && (
            <section className="profile-section">
              <h2>Details</h2>
              <dl className="facts">
                {rest.map(([k, v]) => (
                  <div key={k}>
                    <dt>{labels.get(k) ?? k}</dt>
                    <dd className="wrap">
                      {pictures.has(k) ? (
                        <FieldPicture entryId={entryId} field={k} value={v} />
                      ) : verifiedOf(v) ? (
                        <Verified value={verifiedOf(v)!} />
                      ) : typeof v === "boolean" ? (
                        v ? "Yes" : "No"
                      ) : (
                        text(v)
                      )}
                    </dd>
                  </div>
                ))}
                {text(f.did) && (
                  <div>
                    <dt>{labels.get("did") ?? "DID"}</dt>
                    <dd>
                      <CopyDid did={text(f.did)} />
                    </dd>
                  </div>
                )}
              </dl>
            </section>
          )}
        </article>
      )}
    </main>
  );
}

// ─── my card ──────────────────────────────────────────────────────────────

type Listing = DirectoryCard["discoverability"]["listing"];
type SearchMode = DirectoryCard["discoverability"]["search"];
type Introductions = DirectoryCard["introductions"];

/** The fields a member edits here: active, written by them or derived but
 *  theirs to show (`did`), and of a type this page can edit. */
/** The member's own petname and lists for one entry — kept by their wallet,
 *  seen by nobody else, the entry's member included. */
function YourMarks({ entryId, marks }: { entryId: string; marks: Marks }) {
  const mark = marks.entries[entryId];
  const set = useMark();
  const newList = useNewList();
  const [petname, setPetname] = useState(mark?.petname ?? "");
  const [listName, setListName] = useState("");
  useEffect(() => setPetname(mark?.petname ?? ""), [mark?.petname]);
  const onLists = new Set(mark?.lists ?? []);
  const toggle = (listId: string) => {
    const next = new Set(onLists);
    if (next.has(listId)) next.delete(listId);
    else next.add(listId);
    set.mutate({ entryId, lists: [...next] });
  };
  return (
    <section className="profile-section">
      <h2>Only you see this</h2>
      <form
        className="stack"
        onSubmit={(e) => {
          e.preventDefault();
          const p = petname.trim();
          if (p === (mark?.petname ?? "")) return;
          set.mutate(p ? { entryId, petname: p } : { entryId, removePetname: true });
        }}
      >
        <label>
          Your name for them
          <input value={petname} maxLength={128} onChange={(e) => setPetname(e.target.value)} />
        </label>
        <button type="submit" className="btn btn-ghost btn-sm" disabled={set.isPending}>
          Save
        </button>
      </form>
      <fieldset className="stack">
        <legend>Your lists</legend>
        {marks.lists.map((l) => (
          <label key={l.listId}>
            <input
              type="checkbox"
              checked={onLists.has(l.listId)}
              disabled={set.isPending}
              onChange={() => toggle(l.listId)}
            />{" "}
            {l.name}
          </label>
        ))}
        <form
          className="inline-form"
          onSubmit={(e) => {
            e.preventDefault();
            const n = listName.trim();
            if (!n) return;
            newList.mutate(n, {
              onSuccess: (l) => {
                setListName("");
                set.mutate({ entryId, lists: [...onLists, l.listId] });
              },
            });
          }}
        >
          <input
            aria-label="New list"
            placeholder="New list, e.g. Mentors"
            value={listName}
            maxLength={64}
            onChange={(e) => setListName(e.target.value)}
          />
          <button type="submit" className="btn btn-ghost btn-sm" disabled={newList.isPending}>
            Add to a new list
          </button>
        </form>
      </fieldset>
      {(set.isError || newList.isError) && (
        <p className="muted">{((set.error ?? newList.error) as Error).message}</p>
      )}
    </section>
  );
}

function editable(f: DirectoryFieldDefinition): boolean {
  if (f.state !== "active") return false;
  if (f.source === "derived") return f.key === "did";
  return f.type !== "claim";
}

/** Choose, send and remove one picture field. */
function PictureField({
  entryId,
  field,
  current,
  onChange,
}: {
  entryId: string;
  field: DirectoryFieldDefinition;
  current: DirectoryCardBlobRef | null;
  onChange: (next: DirectoryCardBlobRef | null) => void;
}) {
  const [error, setError] = useState<string | null>(null);
  const send = useMutation({
    mutationFn: async (file: File) => {
      const { mediaType, bytes } = await prepare(file);
      return (await uploadImage({ mediaType, data: toBase64Url(bytes) })).image;
    },
    onSuccess: (image) => {
      setError(null);
      onChange(image as DirectoryCardBlobRef);
    },
    onError: (e) =>
      setError(
        e instanceof PictureError || e instanceof DirectoryError
          ? e.message
          : "The picture couldn't be sent.",
      ),
  });
  return (
    <div className="picture-field">
      {current ? (
        field.key === "avatar" ? (
          <MemberAvatar entryId={entryId} value={current} name={null} size={72} />
        ) : (
          <FieldPicture entryId={entryId} field={field.key} value={current} size={72} />
        )
      ) : (
        <span className="muted">(no picture)</span>
      )}
      <label className="btn">
        <ImagePlus size={16} aria-hidden="true" /> {send.isPending ? "Sending…" : "Choose a picture"}
        <input
          type="file"
          accept="image/png,image/jpeg,image/webp"
          aria-label={`Choose ${field.label}`}
          hidden
          disabled={send.isPending}
          onChange={(e) => {
            const file = e.target.files?.[0];
            e.target.value = "";
            if (file) send.mutate(file);
          }}
        />
      </label>
      {current && (
        <button type="button" className="btn" onClick={() => onChange(null)}>
          <Trash2 size={16} aria-hidden="true" /> Remove
        </button>
      )}
      <p className="muted">
        The community keeps a smaller copy, with nothing about where or how it was taken.
      </p>
      {error && (
        <p className="alert" role="alert">
          {error}
        </p>
      )}
    </div>
  );
}

/** Where the member's card stands beyond the community, and the one thing
 *  this browser may do about it: stop publishing. Publishing is the member's
 *  own signature, from their wallet. */
function ExternalCardStatus({
  card,
  onStop,
  stopping,
  publish,
}: {
  card: DirectoryCard;
  onStop: () => void;
  stopping: boolean;
  /** Present when the wallet offers to publish from here. */
  publish: { run: () => void; busy: boolean; error: string | null } | null;
}) {
  const external = card.externalCard;
  const publishButton = (words: string) =>
    publish ? (
      <button type="button" className="btn" onClick={publish.run} disabled={publish.busy}>
        {publish.busy ? "Waiting for your wallet…" : words}
      </button>
    ) : null;
  const publishError = publish?.error ? (
    <p className="alert" role="alert">
      {publish.error}
    </p>
  ) : null;
  if (!card.discoverability.external || !external) {
    return (
      <div>
        <p className="muted">
          Your card is seen only inside this community. To publish what you show to
          &ldquo;Anyone&rdquo; so that anyone can find it, use your wallet: it shows you exactly
          what would be published before you sign.
        </p>
        {publishButton("Publish from your wallet")}
        {publishError}
      </div>
    );
  }
  return (
    <div className="alert" role="status">
      {external.state === "published" ? (
        <>
          <p className="alert-title">Your card is published beyond the community.</p>
          <p>
            Anyone can read what you show to &ldquo;Anyone&rdquo;, exactly as you signed it.
          </p>
        </>
      ) : (
        <>
          <p className="alert-title">Your published card was withdrawn.</p>
          <p>
            What you show to &ldquo;Anyone&rdquo; changed after you signed, so the community stopped
            publishing it. Publish it again from your wallet, or stop publishing.
          </p>
        </>
      )}
      {external.state === "awaitingSignature" && publishButton("Sign again from your wallet")}
      <button type="button" className="btn" onClick={onStop} disabled={stopping}>
        {stopping ? "Stopping…" : "Stop publishing"}
      </button>
      {publishError}
    </div>
  );
}

export function MyCardPage() {
  const qc = useQueryClient();
  const card = useQuery({ queryKey: ["directory", "card"], queryFn: showCard, retry: false });
  const fields = useQuery({ queryKey: ["directory", "fields"], queryFn: listFields, retry: false });
  const [values, setValues] = useState<Record<string, string>>({});
  const [pictures, setPictures] = useState<Record<string, DirectoryCardBlobRef | null>>({});
  const [visibility, setVisibility] = useState<Record<string, Audience>>({});
  const [listing, setListing] = useState<Listing>("listed");
  const [search, setSearch] = useState<SearchMode>("byName");
  const [intros, setIntros] = useState<Introductions>("anyone");
  const [saved, setSaved] = useState<string | null>(null);
  const [baseline, setBaseline] = useState<Audience>("members");
  const [baselineNote, setBaselineNote] = useState<string | null>(null);
  const wallet = walletDirectory();
  const publish = useMutation({
    mutationFn: async () => {
      if (!wallet) throw new Error("Your wallet does not offer to publish a card here.");
      const [hostDid, me] = await Promise.all([
        vtcDid(),
        memberFetch<MemberMe>("/v1/member/me").catch(() => null),
      ]);
      // The signed-in DID is a hint: the wallet chooses among its own identities.
      return wallet.publishCard({ hostDid, ...(me?.did ? { member: me.did } : {}) });
    },
    onSuccess: (r) => {
      void qc.invalidateQueries({ queryKey: ["directory", "card"] });
      setSaved(r.state === "published" ? "Your card is published." : null);
    },
  });

  useEffect(() => {
    if (!card.data || !fields.data) return;
    const c = card.data.card;
    setValues(
      Object.fromEntries(
        fields.data.fields
          .filter((f) => editable(f) && f.type !== "image")
          .map((f) => [f.key, text(c.values?.[f.key])]),
      ),
    );
    setPictures(
      Object.fromEntries(
        fields.data.fields
          .filter((f) => editable(f) && f.type === "image")
          .map((f) => [f.key, blobRef(c.values?.[f.key])]),
      ),
    );
    setVisibility(
      Object.fromEntries(
        fields.data.fields
          .filter(editable)
          .map((f) => [f.key, (c.visibility?.[f.key] as Audience | undefined) ?? f.defaultVisibility]),
      ),
    );
    setListing(c.discoverability.listing);
    setSearch(c.discoverability.search);
    setIntros(c.introductions);
  }, [card.data, fields.data]);

  const save = useMutation({
    mutationFn: () => {
      const defs = (fields.data?.fields ?? []).filter(editable);
      const before = card.data!.card;
      // Only what the member changed: a field left alone keeps following the
      // community's default, rather than being pinned to today's.
      const changedPictures = defs
        .filter((f) => f.source === "member" && f.type === "image")
        .flatMap((f): [string, DirectoryCardBlobRef | null][] => {
          const now = pictures[f.key] ?? null;
          const was = blobRef(before.values?.[f.key]);
          return now?.sha256 === was?.sha256 ? [] : [[f.key, now]];
        });
      const changedValues = Object.fromEntries(
        defs
          .filter((f) => f.source === "member" && f.type !== "image")
          .flatMap((f): [string, string | string[] | null][] => {
            const v = (values[f.key] ?? "").trim();
            if (v === text(before.values?.[f.key])) return [];
            if (v === "") return [[f.key, null]];
            if (f.type === "multiEnum" || f.key === "links") {
              return [[f.key, v.split(",").map((x) => x.trim()).filter(Boolean)]];
            }
            return [[f.key, v]];
          }),
      );
      const changedVisibility = Object.fromEntries(
        defs.flatMap((f): [string, Audience][] => {
          const was = (before.visibility?.[f.key] as Audience | undefined) ?? f.defaultVisibility;
          const now = visibility[f.key] ?? was;
          return now === was ? [] : [[f.key, now]];
        }),
      );
      const payload: DirectoryCardUpdatePayload = {
        values: { ...changedValues, ...Object.fromEntries(changedPictures) },
        visibility: changedVisibility,
        // Publication is never changed by saving: a published card stays
        // published (and is withdrawn by the community if what it shows
        // anyone changed), and only "Stop publishing" turns it off.
        discoverability: { listing, search, external: before.discoverability.external },
        introductions: intros,
        expectedRevision: before.revision,
      };
      return updateCard(payload);
    },
    onSuccess: (r) => {
      qc.setQueryData(["directory", "card"], r);
      void qc.invalidateQueries({ queryKey: ["directory", "entries"] });
      setSaved("Saved.");
    },
    onError: () => setSaved(null),
  });

  const stop = useMutation({
    mutationFn: () => {
      const before = card.data!.card;
      return updateCard({
        discoverability: { ...before.discoverability, external: false },
        expectedRevision: before.revision,
      });
    },
    onSuccess: (r) => {
      qc.setQueryData(["directory", "card"], r);
      setSaved("Your card is no longer published.");
    },
  });

  if (card.isError || fields.isError) {
    return (
      <main className="home" id="main">
        <NeedsWallet error={card.error ?? fields.error} />
      </main>
    );
  }
  if (!card.data || !fields.data) {
    return (
      <main className="home" id="main">
        <p className="muted">Loading…</p>
      </main>
    );
  }
  const defs = fields.data.fields.filter(editable);
  const missing = card.data.missingRequired;
  const error = save.error instanceof DirectoryError ? save.error : null;

  const applyBaseline = () => {
    const next = { ...visibility };
    const capped: string[] = [];
    for (const f of defs) {
      next[f.key] = baselineFor(baseline, f.ceiling);
      if (next[f.key] !== baseline) capped.push(f.label);
    }
    setVisibility(next);
    setSaved(null);
    const who = AUDIENCES.find((a) => a.id === baseline)?.label.toLowerCase() ?? baseline;
    setBaselineNote(
      capped.length === 0
        ? `Every field is now shown to ${who}. Change any field below, then save.`
        : `Every field is now shown to ${who}, except ${capped.join(", ")}, which this community ` +
            `shows no wider than its limit. Change any field below, then save.`,
    );
  };

  return (
    <main className="home" id="main">
      <Crumbs trail={[{ label: "Directory", href: "#/directory" }, { label: "Your card" }]} />
      <section className="welcome">
        <p className="eyebrow">Directory</p>
        <h1>Your card</h1>
        <p className="lead">
          You choose who sees each part of your card, up to the widest this community allows.
          Showing anything to anyone outside the community needs your wallet.
        </p>
        {card.data?.card.entryId && (
          <a className="btn btn-ghost btn-sm" href={`#/directory/${encodeURIComponent(card.data.card.entryId)}`}>
            See your card as members do
          </a>
        )}
      </section>
      {missing.length > 0 && (
        <div className="alert" role="status">
          <p className="alert-title">Members won&rsquo;t find you when browsing yet.</p>
          <p>Fill in {missing.join(", ")} to be listed.</p>
        </div>
      )}
      <form
        className="card card-form"
        onSubmit={(e) => {
          e.preventDefault();
          setSaved(null);
          save.mutate();
        }}
      >
        <div className="card-head">
          <BookUser size={18} aria-hidden="true" />
          <h2>What your card shows</h2>
        </div>
        <div className="card-field baseline-field">
          <label>
            <span>Show every field to</span>
            <select
              aria-label="Show every field to"
              value={baseline}
              onChange={(e) => setBaseline(e.target.value as Audience)}
            >
              {AUDIENCES.filter((a) => a.id !== "public").map((a) => (
                <option key={a.id} value={a.id}>
                  {a.label}
                </option>
              ))}
            </select>
          </label>
          <button type="button" className="btn" onClick={applyBaseline}>
            Apply to every field
          </button>
          <p className="muted">
            A starting point: each field below can still be changed on its own. Nothing changes until
            you save.
          </p>
          {baselineNote && (
            <p className="muted" role="status">
              {baselineNote}
            </p>
          )}
        </div>
        {defs.map((f) => (
          <fieldset key={f.key} className="card-field">
            <legend>{f.label}</legend>
            {f.description && <p className="muted">{f.description}</p>}
            {f.source === "member" ? (
              f.type === "image" ? (
                <PictureField
                  entryId={card.data.card.entryId}
                  field={f}
                  current={pictures[f.key] ?? null}
                  onChange={(next) => setPictures({ ...pictures, [f.key]: next })}
                />
              ) : f.type === "enum" ? (
                <select
                  aria-label={f.label}
                  value={values[f.key] ?? ""}
                  onChange={(e) => setValues({ ...values, [f.key]: e.target.value })}
                >
                  <option value="">(not set)</option>
                  {(f.constraints?.options ?? []).map((o) => (
                    <option key={o.value} value={o.value}>
                      {o.label}
                    </option>
                  ))}
                </select>
              ) : f.type === "longText" ? (
                <textarea
                  aria-label={f.label}
                  value={values[f.key] ?? ""}
                  maxLength={f.constraints?.maxLength ?? undefined}
                  onChange={(e) => setValues({ ...values, [f.key]: e.target.value })}
                />
              ) : (
                <input
                  aria-label={f.label}
                  value={values[f.key] ?? ""}
                  maxLength={f.constraints?.maxLength ?? undefined}
                  placeholder={f.key === "links" ? "https://…, https://…" : undefined}
                  onChange={(e) => setValues({ ...values, [f.key]: e.target.value })}
                />
              )
            ) : f.source === "derived" ? (
              <p className="muted">Your membership DID. Choose who may see it.</p>
            ) : (
              <p>
                {verifiedOf(card.data.card.values?.[f.key]) ? (
                  <Verified value={verifiedOf(card.data.card.values?.[f.key])!} />
                ) : text(card.data.card.values?.[f.key]) ? (
                  text(card.data.card.values?.[f.key])
                ) : f.source === "credential" ? (
                  <span className="muted">(not set — filled when you present a credential from your wallet)</span>
                ) : (
                  <span className="muted">(not set)</span>
                )}
              </p>
            )}
            <label>
              <span className="muted">Shown to </span>
              <select
                aria-label={`Who sees ${f.label}`}
                value={visibility[f.key] ?? f.defaultVisibility}
                onChange={(e) => setVisibility({ ...visibility, [f.key]: e.target.value as Audience })}
              >
                {AUDIENCES.filter((a) => within(a.id, f.ceiling) && a.id !== "public").map((a) => (
                  <option key={a.id} value={a.id}>
                    {a.label}
                  </option>
                ))}
              </select>
            </label>
          </fieldset>
        ))}

        <div className="card-head">
          <h2>Finding you</h2>
        </div>
        <div className="card-field">
          <span>
            <Globe size={16} aria-hidden="true" /> Beyond the community
          </span>
          <ExternalCardStatus
            card={card.data.card}
            onStop={() => stop.mutate()}
            stopping={stop.isPending}
            publish={
              wallet
                ? {
                    run: () => publish.mutate(),
                    busy: publish.isPending,
                    error: publish.error instanceof Error ? publish.error.message : null,
                  }
                : null
            }
          />
        </div>
        <label className="card-field">
          <span>In the directory</span>
          <select aria-label="Listing" value={listing} onChange={(e) => setListing(e.target.value as Listing)}>
            <option value="listed">Listed — members see me when they browse</option>
            <option value="findable">Findable — only when someone searches for me</option>
            <option value="hidden">Hidden — no member finds me</option>
          </select>
        </label>
        <label className="card-field">
          <span>Searches may match</span>
          <select aria-label="Search" value={search} onChange={(e) => setSearch(e.target.value as SearchMode)}>
            <option value="byName">My name or nickname</option>
            <option value="exactNickname">Only my exact nickname</option>
            <option value="off">Nothing</option>
          </select>
        </label>
        <label className="card-field">
          <span>Who may ask to be introduced</span>
          <select aria-label="Introductions" value={intros} onChange={(e) => setIntros(e.target.value as Introductions)}>
            <option value="anyone">Any member</option>
            <option value="groups">People in my groups</option>
            <option value="connections">My connections</option>
            <option value="off">No one</option>
          </select>
        </label>

        {error && (
          <div className="alert" role="alert">
            <p className="alert-title">Not saved.</p>
            <p>
              {error.code === "superseded"
                ? "Your card changed somewhere else. Reload the page and try again."
                : error.message}
            </p>
          </div>
        )}
        {saved && <p className="muted" role="status">{saved}</p>}
        <button type="submit" className="btn btn-primary" disabled={save.isPending}>
          {save.isPending ? "Saving…" : "Save"}
        </button>
      </form>
    </main>
  );
}
