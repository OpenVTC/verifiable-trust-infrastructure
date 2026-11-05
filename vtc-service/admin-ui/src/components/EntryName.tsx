// A directory entry named as the console names a member: picture and display name, by entry,
// never by DID. Shared by the pages that appoint members to run something (a group's managers, a
// board's facilitators).

import { useMemo } from "react";
import { useQuery } from "@tanstack/react-query";

import { DirectoryAvatar } from "@/components/DirectoryAvatar";
import { listAllEntries } from "@/lib/directory";

export type EntryFaces = Map<string, { name: string | null; avatar: unknown }>;

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
      out.set(e.entryId, { name, avatar: e.fields.avatar });
    }
    return out;
  }, [q.data]);
}

export function EntryName({ entryId, faces }: { entryId: string; faces: EntryFaces }) {
  const face = faces.get(entryId);
  return (
    <span className="dir-name-cell">
      <DirectoryAvatar entryId={entryId} value={face?.avatar} name={face?.name} colourKey={entryId} />
      {face?.name ?? <span className="muted">(no name)</span>}
    </span>
  );
}
