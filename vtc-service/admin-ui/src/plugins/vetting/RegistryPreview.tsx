// Registry preview — the vetter listing as an applicant receives it.
//
// `POST /v1/vetting/vetters/list` is the admin-session route onto the same
// `vtc/vetting/vetters/list/0.1` listing an applicant sends to
// `POST /v1/trust-tasks`; both run one function on the daemon. So an admin can
// check that a vetter is findable, with the filters an applicant would use,
// before pointing applicants at them.

import { type FormEvent, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { ArrowLeft, ArrowRight, BadgeCheck, ExternalLink } from "lucide-react";

import { CopyButton } from "@/components/CopyButton";
import { shortenDid } from "@/lib/format";
import {
  buildListBody,
  EMPTY_LIST_DRAFT,
  methodLabel,
  VETTING_METHODS,
  type ListDraft,
} from "@/lib/vetting";
import type {
  ListedVetter,
  VetterListBody,
  VetterLocation,
  VettingMethod,
} from "@/lib/wire-types";

import { fetchListing, vettingKeys } from "./api";
import { describedBy, errorMessage, errorStatus, formatDay, FormField } from "./ui";

const PAGE_SIZES = [10, 25, 50, 100];
const DEFAULT_PAGE_SIZE = 25;

function placeName(location?: VetterLocation | null): string | null {
  if (!location) return null;
  return [location.city, location.region, location.country]
    .filter(Boolean)
    .join(", ");
}

export function RegistryPreview() {
  const [draft, setDraft] = useState<ListDraft>(EMPTY_LIST_DRAFT);
  const [limit, setLimit] = useState(DEFAULT_PAGE_SIZE);
  const [applied, setApplied] = useState<VetterListBody>({
    limit: DEFAULT_PAGE_SIZE,
  });
  // `nextCursor`s of the pages before this one; empty on the first page.
  const [cursors, setCursors] = useState<string[]>([]);
  const [attempted, setAttempted] = useState(false);

  const { body, errors } = buildListBody(draft);
  const shown = attempted ? errors : {};
  const cursor = cursors.at(-1) ?? null;
  const filtered = Object.keys(applied).some((k) => k !== "limit");

  const query = useQuery({
    queryKey: vettingKeys.listing(applied, cursor),
    queryFn: () => fetchListing(cursor ? { ...applied, cursor } : applied),
    placeholderData: (previous) => previous,
  });

  const update =
    (key: keyof ListDraft) =>
    (e: { target: { value: string } }) =>
      setDraft({ ...draft, [key]: e.target.value });

  const onSubmit = (e: FormEvent) => {
    e.preventDefault();
    setAttempted(true);
    if (Object.keys(errors).length > 0) return;
    // A cursor is only good for the filters it was issued with.
    setApplied({ ...body, limit });
    setCursors([]);
  };

  const onClear = () => {
    setDraft(EMPTY_LIST_DRAFT);
    setAttempted(false);
    setApplied({ limit });
    setCursors([]);
  };

  const text = (
    key: "language" | "country" | "region" | "city" | "eventName",
    label: string,
    hint: string,
    placeholder: string,
  ) => {
    const id = `registry-${key}`;
    return (
      <FormField id={id} label={label} hint={hint} error={shown[key]}>
        <input
          id={id}
          type="text"
          value={draft[key]}
          placeholder={placeholder}
          autoComplete="off"
          spellCheck={false}
          onChange={update(key)}
          aria-invalid={Boolean(shown[key])}
          aria-describedby={describedBy(id, true, shown[key])}
        />
      </FormField>
    );
  };

  return (
    <>
      <form
        className="card"
        onSubmit={onSubmit}
        aria-labelledby="registry-title"
        noValidate
      >
        <h3 id="registry-title">What applicants see</h3>
        <p className="lead">
          Applicants look for a vetter in this list. It shows members who hold a
          live vetter grant and chose to list their profile, and discloses
          nothing beyond that profile, their DID and when their grant expires.
          Filter it the way an applicant can.
        </p>

        <div className="filter-grid">
          {text("language", "Language", "A language tag. de also finds de-AT.", "de")}
          {text("country", "Country", "Two letters, like AT.", "AT")}
          {text("region", "Region", "The whole name; case is ignored.", "Tyrol")}
          {text("city", "City", "The whole name; case is ignored.", "Vienna")}
          <FormField id="registry-method" label="Method">
            <select
              id="registry-method"
              value={draft.method}
              onChange={(e) =>
                setDraft({ ...draft, method: e.target.value as VettingMethod | "" })
              }
            >
              <option value="">Any method</option>
              {VETTING_METHODS.map((m) => (
                <option key={m} value={m}>
                  {methodLabel(m)}
                </option>
              ))}
            </select>
          </FormField>
          <FormField
            id="registry-eventFrom"
            label="Events from"
            hint="Leave empty for no start."
            error={shown.eventFrom}
          >
            <input
              id="registry-eventFrom"
              type="date"
              value={draft.eventFrom}
              onChange={update("eventFrom")}
              aria-invalid={Boolean(shown.eventFrom)}
              aria-describedby={describedBy("registry-eventFrom", true, shown.eventFrom)}
            />
          </FormField>
          <FormField
            id="registry-eventTo"
            label="Events to"
            hint="Leave empty for no end."
            error={shown.eventTo}
          >
            <input
              id="registry-eventTo"
              type="date"
              value={draft.eventTo}
              onChange={update("eventTo")}
              aria-invalid={Boolean(shown.eventTo)}
              aria-describedby={describedBy("registry-eventTo", true, shown.eventTo)}
            />
          </FormField>
          {text("eventName", "Event name", "Any part of the name.", "Maintainers Meetup")}
          <FormField id="registry-limit" label="Vetters per page">
            <select
              id="registry-limit"
              value={limit}
              onChange={(e) => setLimit(Number(e.target.value))}
            >
              {PAGE_SIZES.map((n) => (
                <option key={n} value={n}>
                  {n}
                </option>
              ))}
            </select>
          </FormField>
        </div>
        <p className="muted">
          An event filter matches a vetter with an event that has not ended and
          overlaps the dates. With an event filter, the earliest matching event
          comes first; otherwise vetters are listed by display name.
        </p>

        <div className="form-actions">
          <button type="submit" className="primary">
            Show vetters
          </button>
          <button type="button" className="secondary" onClick={onClear}>
            Clear filters
          </button>
        </div>
      </form>

      <section
        className="card"
        aria-labelledby="registry-results-title"
        aria-busy={query.isFetching}
      >
        <h3 id="registry-results-title">Listed vetters</h3>
        {query.error && (
          <p className="finding error" role="alert">
            <strong>
              {errorStatus(query.error) === 400
                ? "The listing refused these filters."
                : "Could not load the listing."}
            </strong>
            <span className="muted">{errorMessage(query.error)}</span>
          </p>
        )}
        {query.isPending && <p className="muted">Loading…</p>}
        {query.data && query.data.vetters.length === 0 && (
          <div className="empty-state">
            <span className="empty-icon" aria-hidden="true">
              <BadgeCheck />
            </span>
            <h4>
              {filtered
                ? "No listed vetter matches these filters"
                : "No vetter is listed"}
            </h4>
            <p>
              Only members with a live vetter grant who published a listed
              profile appear. A vetter publishes their profile from their own
              client.
              {filtered ? " Clear the filters to see every listed vetter." : ""}
            </p>
          </div>
        )}
        {query.data && query.data.vetters.length > 0 && (
          <ul className="vet-registry">
            {query.data.vetters.map((vetter) => (
              <li key={vetter.vetterDid} className="vet-listing">
                <ListedVetterCard vetter={vetter} />
              </li>
            ))}
          </ul>
        )}

        <div className="pagination">
          <button
            type="button"
            className="secondary"
            disabled={cursors.length === 0}
            onClick={() => setCursors(cursors.slice(0, -1))}
          >
            <ArrowLeft size={12} aria-hidden="true" /> Previous page
          </button>
          <button
            type="button"
            className="secondary"
            disabled={!query.data?.nextCursor}
            onClick={() => {
              const next = query.data?.nextCursor;
              if (next) setCursors([...cursors, next]);
            }}
          >
            Next page <ArrowRight size={12} aria-hidden="true" />
          </button>
          <span className="muted">Page {cursors.length + 1}</span>
        </div>
      </section>
    </>
  );
}

function ListedVetterCard({ vetter }: { vetter: ListedVetter }) {
  const where = placeName(vetter.location);
  return (
    <article>
      <header>
        <h4>{vetter.displayName ?? "No display name"}</h4>
        <code title={vetter.vetterDid}>{shortenDid(vetter.vetterDid)}</code>
        <CopyButton
          value={vetter.vetterDid}
          label="Copy vetter DID"
          successMessage="Vetter DID copied"
        />
      </header>
      <dl>
        <dt>Where</dt>
        <dd>{where ?? <span className="muted">No location published</span>}</dd>
        <dt>Languages</dt>
        <dd>{vetter.languages.length ? vetter.languages.join(", ") : "None listed"}</dd>
        <dt>Methods</dt>
        <dd>{vetter.methods.map(methodLabel).join(", ")}</dd>
        <dt>Documents</dt>
        <dd>
          {vetter.acceptsDocumentation.length
            ? vetter.acceptsDocumentation.join(", ")
            : "None listed"}
        </dd>
        {vetter.availability && (
          <>
            <dt>Availability</dt>
            <dd>{vetter.availability}</dd>
          </>
        )}
        {vetter.contactHint && (
          <>
            <dt>Getting a ticket</dt>
            <dd>{vetter.contactHint}</dd>
          </>
        )}
        <dt>Grant valid until</dt>
        <dd>{formatDay(vetter.grantValidUntil)}</dd>
        <dt>Profile updated</dt>
        <dd>{formatDay(vetter.updatedAt)}</dd>
      </dl>
      {vetter.events.length > 0 && (
        <>
          <h5 className="vet-subhead">Upcoming events</h5>
          <ul className="vet-list">
            {vetter.events.map((event) => {
              const eventWhere = placeName(event.location);
              return (
                <li key={`${event.name}-${event.startDate}`}>
                  {event.name},{" "}
                  {event.startDate === event.endDate
                    ? event.startDate
                    : `${event.startDate} to ${event.endDate}`}
                  {eventWhere ? `, ${eventWhere}` : ""}
                  {event.url && (
                    <>
                      {" "}
                      <a href={event.url} target="_blank" rel="noopener noreferrer">
                        Event page <ExternalLink size={12} aria-hidden="true" />
                      </a>
                    </>
                  )}
                </li>
              );
            })}
          </ul>
        </>
      )}
    </article>
  );
}
