// Who wrote what in a room, as the member directory names them to this member.
//
// The wallet's reading of the room names an author only by the name they gave
// themselves in that room (`conversation.ts`); where it gives none, the portal
// asks the community's directory for that DID (`vtc/directory/query/0.2`,
// signed with the portal's delegated key, `./directory-api`), whose answer
// also names the member's directory entry — what their picture and their full
// card are read by. A community that predates 0.2 is asked at 0.1, and its
// card has no picture or link. The community
// answers only where the member shows their DID to this viewer, so "not found"
// is the ordinary answer, and the page falls back to the DID.
//
// Asked only for a room whose host already sees who wrote what (`open`,
// `attributed`): asking about the authors of a private room would tell the
// community who writes there.

import { useQueries } from "@tanstack/react-query";

import type { DirectoryQueryResponse, DirectoryQueryResponseV2 } from "@/lib/wire-types";

import { DirectoryError, send } from "./directory-api";
import { nameOf, text } from "./member-card";
import type { ConversationRecord } from "./wallet-rooms";

export const DIRECTORY_QUERY_TASK = "https://trusttasks.org/spec/vtc/directory/query/0.2";
/** The version a community older than 0.2 serves: no entry in its answer. */
export const DIRECTORY_QUERY_TASK_V1 = "https://trusttasks.org/spec/vtc/directory/query/0.1";

/** How much of a member's bio the card shows. */
export const BIO_EXCERPT = 140;

/** The most authors one conversation looks up. */
export const MAX_AUTHOR_LOOKUPS = 50;

/** What the directory shows this member of an author. */
export interface AuthorCard {
  did: string;
  name: string | null;
  nickname: string;
  pronouns: string;
  role: string;
  /** A short start of their bio, as text. Empty when none is shown. */
  bio: string;
  /** Their directory entry: what their picture and full card are read by. Absent from a community older than query 0.2. */
  entryId?: string;
  /** Their avatar's reference, read through the projection by `entryId`. */
  avatar?: unknown;
}

/** Whether a room's authors may be looked up: only where its host already sees them. */
export function mayLookUpAuthors(visibility: string | undefined): boolean {
  return visibility === "open" || visibility === "attributed";
}

/** Every DID a conversation names — authors, rewriters, reactors — but the member's own, in order, at most `max`. */
export function authorsOf(
  records: readonly Pick<ConversationRecord, "author" | "rewrite" | "reactions">[],
  me: string | undefined,
  max = MAX_AUTHOR_LOOKUPS,
): string[] {
  const seen = new Set<string>();
  const add = (d: string | undefined) => {
    if (d && d !== me && seen.size < max) seen.add(d);
  };
  for (const r of records) {
    add(r.author);
    add(r.rewrite?.by);
    for (const x of r.reactions) for (const a of x.authors) add(a);
  }
  return [...seen];
}

/** An author's card from the directory's projection; `null` when it shows them no name or field we use. */
export function cardOf(did: string, fields: Record<string, unknown>, entryId?: string): AuthorCard | null {
  const bio = text(fields.bio).replace(/\s+/g, " ").trim();
  const card: AuthorCard = {
    did,
    name: nameOf(fields),
    nickname: text(fields.nickname).trim(),
    pronouns: text(fields.pronouns).trim(),
    role: text(fields.role).trim(),
    bio: [...bio].length > BIO_EXCERPT ? `${[...bio].slice(0, BIO_EXCERPT - 1).join("")}…` : bio,
    ...(entryId ? { entryId } : {}),
    ...(fields.avatar !== undefined ? { avatar: fields.avatar } : {}),
  };
  return card.name || card.pronouns || card.role ? card : null;
}

/** Ask the directory about one DID. `null`: nothing shown to this member, or no key to ask with. */
export async function lookUpAuthor(did: string): Promise<AuthorCard | null> {
  try {
    try {
      const got = await send<DirectoryQueryResponseV2>(DIRECTORY_QUERY_TASK, { subject: did });
      return cardOf(did, (got.fields ?? {}) as Record<string, unknown>, got.entryId);
    } catch (e) {
      // A community that predates 0.2: ask as before, for a card without a picture.
      if (!(e instanceof DirectoryError && e.code === "unsupportedType")) throw e;
      const got = await send<DirectoryQueryResponse>(DIRECTORY_QUERY_TASK_V1, { subject: did });
      return cardOf(did, (got.fields ?? {}) as Record<string, unknown>);
    }
  } catch (e) {
    // Not a member, not shown to this viewer, or a portal key that may not ask:
    // each is "no name", never an error on the page.
    if (e instanceof DirectoryError) return null;
    throw e;
  }
}

/** The directory's card for each of `dids`, once answered. Nothing is asked when `enabled` is false. */
export function useAuthorCards(dids: readonly string[], enabled: boolean): Map<string, AuthorCard> {
  const results = useQueries({
    queries: dids.map((did) => ({
      queryKey: ["directory", "query", did],
      queryFn: () => lookUpAuthor(did),
      enabled,
      retry: false,
      staleTime: 5 * 60_000,
    })),
  });
  const cards = new Map<string, AuthorCard>();
  results.forEach((r, i) => {
    if (r.data) cards.set(dids[i]!, r.data);
  });
  return cards;
}
