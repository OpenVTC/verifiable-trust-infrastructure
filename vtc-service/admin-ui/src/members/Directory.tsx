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
// Values other members typed are rendered as text, never as markup.

import { useEffect, useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { BookUser, Search, UserRound } from "lucide-react";

import type {
  DirectoryCard,
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
} from "./directory-api";

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
                <UserRound size={28} aria-hidden="true" />
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
            <UserRound size={18} aria-hidden="true" />
            <h1>{text(entry.data.entry.fields.displayName) || "A member"}</h1>
          </div>
          <dl className="facts">
            {Object.entries(entry.data.entry.fields)
              .filter(([k]) => k !== "displayName")
              .map(([k, v]) => (
                <div key={k}>
                  <dt>{labels.get(k) ?? k}</dt>
                  <dd className="wrap">{text(v)}</dd>
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
  return f.type !== "image" && f.type !== "claim";
}

export function MyCardPage() {
  const qc = useQueryClient();
  const card = useQuery({ queryKey: ["directory", "card"], queryFn: showCard, retry: false });
  const fields = useQuery({ queryKey: ["directory", "fields"], queryFn: listFields, retry: false });
  const [values, setValues] = useState<Record<string, string>>({});
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
        fields.data.fields.filter(editable).map((f) => [f.key, text(c.values?.[f.key])]),
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
      const changedValues = Object.fromEntries(
        defs
          .filter((f) => f.source === "member")
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
        values: changedValues,
        visibility: changedVisibility,
        discoverability: { listing, search, external: false },
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
              f.type === "enum" ? (
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
