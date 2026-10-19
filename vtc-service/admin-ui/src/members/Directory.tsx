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
import { BookUser, Globe, ImagePlus, Search, Trash2, UserRound } from "lucide-react";

import type {
  DirectoryCard,
  DirectoryCardBlobRef,
  DirectoryCardUpdatePayload,
  DirectoryFieldDefinition,
} from "@/lib/wire-types";

import {
  DirectoryError,
  getImage,
  listEntries,
  listFields,
  showCard,
  showEntry,
  updateCard,
  uploadImage,
} from "./directory-api";
import { PictureError, pictureUrl, prepare, toBase64Url } from "./picture";

type Audience = DirectoryFieldDefinition["ceiling"];

const AUDIENCES: readonly { id: Audience; label: string }[] = [
  { id: "admins", label: "Only administrators" },
  { id: "groups", label: "People in my groups" },
  { id: "connections", label: "My connections" },
  { id: "members", label: "All members" },
  { id: "public", label: "Anyone" },
];

/** The daemon's audience order: `groups` and `connections` cover neither. */
function within(inner: Audience, outer: Audience): boolean {
  if (inner === outer || inner === "admins") return true;
  if ((inner === "groups" || inner === "connections") && (outer === "members" || outer === "public"))
    return true;
  return inner === "members" && outer === "public";
}

function text(v: unknown): string {
  if (v === null || v === undefined) return "";
  if (Array.isArray(v)) return v.join(", ");
  if (typeof v === "object") return "";
  return String(v);
}

/** `v` as a picture reference, if it is one. */
function blobRef(v: unknown): DirectoryCardBlobRef | null {
  if (!v || typeof v !== "object" || Array.isArray(v)) return null;
  const r = v as Partial<DirectoryCardBlobRef>;
  return typeof r.sha256 === "string" && typeof r.mediaType === "string"
    ? (r as DirectoryCardBlobRef)
    : null;
}

async function sha256Hex(bytes: Uint8Array): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", bytes as BufferSource);
  return Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, "0")).join("");
}

/** One picture on an entry, read through the projection — or the plain icon
 *  when there is none, or it is not this reader's to see. */
function Picture({
  entryId,
  field,
  value,
  size = 28,
}: {
  entryId: string;
  field: string;
  value: unknown;
  size?: number;
}) {
  const ref = blobRef(value);
  const picture = useQuery({
    queryKey: ["directory", "image", entryId, field, ref?.sha256 ?? ""],
    enabled: ref !== null,
    retry: false,
    staleTime: Infinity,
    queryFn: async () => {
      const got = await getImage(entryId, field, ref!.sha256);
      const b64 = got.data.replace(/-/g, "+").replace(/_/g, "/");
      const bytes = Uint8Array.from(atob(b64 + "=".repeat((4 - (b64.length % 4)) % 4)), (c) =>
        c.charCodeAt(0),
      );
      // Shown only when the bytes are the ones the card names.
      if ((await sha256Hex(bytes)) !== ref!.sha256) throw new Error("picture digest mismatch");
      return pictureUrl(got.image.mediaType, got.data);
    },
  });
  if (!picture.data) return <UserRound size={size} aria-hidden="true" />;
  return (
    <img
      className="avatar"
      src={picture.data}
      alt=""
      width={size}
      height={size}
      style={{ width: size, height: size }}
    />
  );
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

// ─── browse and search ────────────────────────────────────────────────────

export function DirectoryPage() {
  const [draft, setDraft] = useState("");
  const [query, setQuery] = useState<string | undefined>(undefined);
  const list = useQuery({
    queryKey: ["directory", "entries", query ?? ""],
    queryFn: () => listEntries({ ...(query ? { query } : {}), limit: 50 }),
    retry: false,
  });

  return (
    <main className="home" id="main">
      <section className="welcome">
        <p className="eyebrow">Directory</p>
        <h1>Members</h1>
        <p className="lead">
          Each member decides what you see here. <a href="#/card">Edit your own card</a>.
        </p>
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
      ) : list.data.items.length === 0 ? (
        <p className="muted">{query ? "No one matches." : "No one is listed yet."}</p>
      ) : (
        <ul className="directory-grid">
          {list.data.items.map((e) => (
            <li key={e.entryId}>
              <a className="card directory-entry" href={`#/directory/${encodeURIComponent(e.entryId)}`}>
                <Picture entryId={e.entryId} field="avatar" value={e.fields.avatar} size={40} />
                <span className="directory-name">
                  {text(e.fields.displayName) || text(e.fields.nickname) || "A member"}
                </span>
                {text(e.fields.pronouns) && <span className="muted">{text(e.fields.pronouns)}</span>}
                {text(e.fields.role) && <span className="pill cap">{text(e.fields.role)}</span>}
                {e.connected === true && <span className="pill pill-ok">Connected</span>}
              </a>
            </li>
          ))}
        </ul>
      )}
      {typeof list.data?.nextCursor === "string" && (
        <p className="muted">Showing the first 50. Search to narrow it down.</p>
      )}
    </main>
  );
}

// ─── one entry ────────────────────────────────────────────────────────────

export function EntryPage({ entryId }: { entryId: string }) {
  const entry = useQuery({
    queryKey: ["directory", "entry", entryId],
    queryFn: () => showEntry(entryId),
    retry: false,
  });
  const fields = useQuery({ queryKey: ["directory", "fields"], queryFn: listFields, retry: false });
  const labels = useMemo(
    () => new Map((fields.data?.fields ?? []).map((f) => [f.key, f.label])),
    [fields.data],
  );
  const pictures = useMemo(
    () => new Set((fields.data?.fields ?? []).filter((f) => f.type === "image").map((f) => f.key)),
    [fields.data],
  );
  return (
    <main className="home" id="main">
      <p>
        <a href="#/directory">&larr; Directory</a>
      </p>
      {entry.isError ? (
        entry.error instanceof DirectoryError && entry.error.code === "notFound" ? (
          <p className="muted">This member isn&rsquo;t in the directory, or shows you nothing.</p>
        ) : (
          <NeedsWallet error={entry.error} />
        )
      ) : entry.isPending ? (
        <p className="muted">Loading…</p>
      ) : (
        <section className="card">
          <div className="card-head">
            <Picture entryId={entryId} field="avatar" value={entry.data.entry.fields.avatar} size={64} />
            <h1>{text(entry.data.entry.fields.displayName) || "A member"}</h1>
          </div>
          <dl className="facts">
            {Object.entries(entry.data.entry.fields)
              .filter(([k]) => k !== "displayName" && k !== "avatar")
              .map(([k, v]) => (
                <div key={k}>
                  <dt>{labels.get(k) ?? k}</dt>
                  <dd className="wrap">
                    {pictures.has(k) ? (
                      <Picture entryId={entryId} field={k} value={v} size={96} />
                    ) : (
                      text(v)
                    )}
                  </dd>
                </div>
              ))}
          </dl>
          {entry.data.entry.connected === true && (
            <p>
              <span className="pill pill-ok">You have a verified relationship</span>
            </p>
          )}
        </section>
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
        <Picture entryId={entryId} field={field.key} value={current} size={72} />
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
}: {
  card: DirectoryCard;
  onStop: () => void;
  stopping: boolean;
}) {
  const external = card.externalCard;
  if (!card.discoverability.external || !external) {
    return (
      <p className="muted">
        Your card is seen only inside this community. To publish it so that anyone can find it,
        use your wallet: it shows you exactly what would be published before you sign.
      </p>
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
      <button type="button" className="btn" onClick={onStop} disabled={stopping}>
        {stopping ? "Stopping…" : "Stop publishing"}
      </button>
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

  return (
    <main className="home" id="main">
      <section className="welcome">
        <p className="eyebrow">Directory</p>
        <h1>Your card</h1>
        <p className="lead">
          You choose who sees each part of your card, up to the widest this community allows.
          Showing anything to anyone outside the community needs your wallet.
        </p>
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
              <p>{text(card.data.card.values?.[f.key]) || <span className="muted">(not set)</span>}</p>
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
          <ExternalCardStatus card={card.data.card} onStop={() => stop.mutate()} stopping={stop.isPending} />
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
