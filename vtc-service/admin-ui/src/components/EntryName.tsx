// A directory entry named as the console names a member: picture and display name, by entry, or
// the shortened DID when the member has given no name. Shared by the pages that appoint members to
// run something (a group's managers, a board's facilitators).

import { useMemo } from "react";
import { useQuery } from "@tanstack/react-query";

import { DirectoryAvatar } from "@/components/DirectoryAvatar";
import { listAllEntries } from "@/lib/directory";
import { shortenDid } from "@/lib/format";

export type EntryFaces = Map<string, { name: string | null; avatar: unknown; did: string | null }>;

/** Each directory entry's name and picture, by entry, for naming members. */
export function useEntryFaces(): EntryFaces {
  const q = useQuery({
    queryKey: ["directory", "entries", "all"],
    queryFn: listAllEntries,
    retry: false,
    staleTime: 60_000,
  });
  return useMemo(() => {
    const out: EntryFaces = new Map();
    for (const e of q.data ?? []) {
      const name =
        typeof e.fields.displayName === "string"
          ? e.fields.displayName
          : typeof e.fields.nickname === "string"
            ? e.fields.nickname
            : null;
      const did = typeof e.fields.did === "string" ? e.fields.did : null;
      out.set(e.entryId, { name, avatar: e.fields.avatar, did });
    }
    return out;
  }, [q.data]);
}

type Face = { name: string | null; did: string | null };

/**
 * A member as one line of text, for a list to choose from: "Name · did:…short", the shortened
 * DID alone when they have given no name, and never the directory's own entry identifier.
 */
export function faceLabel(face: Face | undefined): string {
  const did = face?.did ? shortenDid(face.did) : null;
  if (face?.name) return did ? `${face.name} · ${did}` : face.name;
  return did ?? "A member with no name";
}

/** Named members first, by name, then the unnamed by DID. */
export function byFace([, a]: [string, Face], [, b]: [string, Face]): number {
  if (a.name && b.name) return a.name.localeCompare(b.name);
  if (a.name || b.name) return a.name ? -1 : 1;
  return (a.did ?? "").localeCompare(b.did ?? "");
}

/** Whether a member's name or DID holds what was typed. */
export function faceMatches(face: Face, query: string): boolean {
  const q = query.trim().toLowerCase();
  return !q || `${face.name ?? ""} ${face.did ?? ""}`.toLowerCase().includes(q);
}

export function EntryName({ entryId, faces }: { entryId: string; faces: EntryFaces }) {
  const face = faces.get(entryId);
  return (
    <span className="dir-name-cell">
      <DirectoryAvatar entryId={entryId} value={face?.avatar} name={face?.name} colourKey={entryId} />
      {face?.name ?? (face?.did ? <code title={face.did}>{shortenDid(face.did)}</code> : <span className="muted">(no name)</span>)}
    </span>
  );
}
