// The member's own marks on other members — a star, a petname, their lists —
// read and changed through their wallet (`window.vtaWallet.directory`).
//
// They live in the member's own VTA, never here: the community stores none of
// them, and no request this portal makes to the community carries one. The
// portal reads the directory exactly as it would without them and applies
// them on the page — stars sorted first, petnames beside names, lists as
// filters — so nothing the community sees changes with them
// (`persona/contact/put/1.2`, Correlation).
//
// The wallet asks the member once per community before it hands this page
// any. So the page never asks on its own: the member turns them on here, and
// this browser remembers that they did.

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { memberFetch, vtcDid, type MemberMe } from "./api";

export interface EntryMark {
  starred: boolean;
  petname?: string;
  lists?: string[];
}

export interface MarkList {
  listId: string;
  name: string;
  colour?: string;
  order: number;
  contactCount: number;
}

export interface Marks {
  entries: Record<string, EntryMark>;
  lists: MarkList[];
}

interface WalletMarks {
  marks(p: { hostDid: string; member?: string }): Promise<Marks>;
  mark(p: {
    hostDid: string;
    member?: string;
    entryId: string;
    starred?: boolean;
    petname?: string;
    removePetname?: true;
    lists?: string[];
  }): Promise<EntryMark>;
  putList(p: {
    hostDid: string;
    member?: string;
    listId?: string;
    name?: string;
  }): Promise<MarkList>;
  deleteList(p: {
    hostDid: string;
    member?: string;
    listId: string;
  }): Promise<{ deleted: boolean }>;
}

/** The wallet's marks calls, where it offers them. */
export function walletMarks(): WalletMarks | null {
  const d = (window as { vtaWallet?: { directory?: Partial<WalletMarks> } })
    .vtaWallet?.directory;
  return d && typeof d.marks === "function" && typeof d.mark === "function"
    ? (d as WalletMarks)
    : null;
}

const ENABLED_KEY = "vtc-member-marks";

/** Whether the member turned their marks on in this browser. */
export function marksEnabled(): boolean {
  try {
    return localStorage.getItem(ENABLED_KEY) === "1";
  } catch {
    return false;
  }
}

function setMarksEnabled(on: boolean) {
  try {
    if (on) localStorage.setItem(ENABLED_KEY, "1");
    else localStorage.removeItem(ENABLED_KEY);
  } catch {
    /* a private window: asked again next time */
  }
}

export const MARKS_KEY = ["directory", "marks"] as const;

/** Who the wallet speaks for here, and which community: the signed-in member is
 *  a hint among the wallet's identities. */
async function target(): Promise<{ hostDid: string; member?: string }> {
  const [hostDid, me] = await Promise.all([
    vtcDid(),
    memberFetch<MemberMe>("/v1/member/me").catch(() => null),
  ]);
  return { hostDid, ...(me?.did ? { member: me.did } : {}) };
}

/** The member's marks, once they turned them on; `null` until then. */
export function useMarks() {
  const wallet = walletMarks();
  return useQuery({
    queryKey: MARKS_KEY,
    queryFn: async () => (wallet ? wallet.marks(await target()) : null),
    enabled: wallet !== null && marksEnabled(),
    retry: false,
    staleTime: 60_000,
  });
}

/** Turn marks on: the wallet asks the member, once for this community. */
export function useEnableMarks() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async () => {
      const wallet = walletMarks();
      if (!wallet)
        throw new Error("Your wallet doesn't keep marks on members.");
      const got = await wallet.marks(await target());
      setMarksEnabled(true);
      return got;
    },
    onSuccess: (got) => qc.setQueryData(MARKS_KEY, got),
  });
}

/** Change the member's marks on one entry. */
export function useMark() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (p: {
      entryId: string;
      starred?: boolean;
      petname?: string;
      removePetname?: true;
      lists?: string[];
    }) => {
      const wallet = walletMarks();
      if (!wallet)
        throw new Error("Your wallet doesn't keep marks on members.");
      return {
        entryId: p.entryId,
        mark: await wallet.mark({ ...(await target()), ...p }),
      };
    },
    onSuccess: ({ entryId, mark }) =>
      qc.setQueryData<Marks | null>(MARKS_KEY, (old) =>
        old ? { ...old, entries: { ...old.entries, [entryId]: mark } } : old,
      ),
  });
}

/** Create one of the member's lists. */
export function useNewList() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (name: string) => {
      const wallet = walletMarks();
      if (!wallet) throw new Error("Your wallet doesn't keep lists.");
      return wallet.putList({ ...(await target()), name });
    },
    onSuccess: (list) =>
      qc.setQueryData<Marks | null>(MARKS_KEY, (old) =>
        old ? { ...old, lists: [...old.lists, list] } : old,
      ),
  });
}

/** Entries in the order the page shows them: the member's stars first, each
 *  group in the directory's own order. Local only — nothing is read for it. */
export function starredFirst<T extends { entryId: string }>(
  items: T[],
  marks: Marks | null | undefined,
): T[] {
  if (!marks) return items;
  const starred = items.filter((e) => marks.entries[e.entryId]?.starred);
  const rest = items.filter((e) => !marks.entries[e.entryId]?.starred);
  return [...starred, ...rest];
}
