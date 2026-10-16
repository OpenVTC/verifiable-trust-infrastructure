// A refusal from a `vtc/rooms/community/*` task, with what fixes it
// (`refusalFix`): an operator error should say what to do, not only what went
// wrong.
//
// When the community's VTA refused for lack of permission, the fix is the `pnm`
// commands an administrator of that VTA runs, filled in with this VTC's DID and
// contexts. They come from the community-rooms list
// (`ext["org.openvtc"].communityRooms.vtaAccess`), read from the same cache the
// list page uses: a refusal's message may not name the VTA's contexts, so the
// VTC says them only on that authorized read (`vtc_service::rooms::vta_access`).

import { useQuery } from "@tanstack/react-query";

import { CopyButton } from "@/components/CopyButton";
import {
  COMMUNITY_ROOMS_LIST_KEY,
  fetchCommunityRooms,
  refusalFix,
  refusalMessage,
  vtaFixFor,
  type VtaFix,
} from "@/lib/community-rooms-api";

/** Whether a refusal could be one the VTC's entry at its VTA explains. */
function mayBeVtaPermission(error: unknown): boolean {
  const code = (error as { code?: unknown } | null)?.code;
  return (
    typeof code === "string" &&
    code.startsWith("vtc/rooms/community/") &&
    (code.endsWith(":keyHolderRefused") || code.endsWith(":noKeyHolder"))
  );
}

/** One command, copyable, under what it is for. */
export function CommandBlock({ purpose, command }: { purpose?: string; command: string }) {
  return (
    <div className="rooms-command">
      {purpose && <p className="muted rooms-sub">{purpose}</p>}
      <div className="rooms-command-line">
        <pre className="rooms-config-snippet">{command}</pre>
        <CopyButton value={command} label="Copy command" successMessage="Command copied" />
      </div>
    </div>
  );
}

/** The `pnm` commands that fix the VTC's entry at its VTA. */
export function VtaFixCommands({ fix }: { fix: VtaFix }) {
  return (
    <div className="community-fix vta-fix" data-fix={fix.id}>
      <p>{fix.summary}</p>
      {fix.commands.map((c) => (
        <CommandBlock key={c.command} purpose={c.purpose} command={c.command} />
      ))}
      <CommandBlock purpose="then check the entry" command={fix.check} />
      <p className="muted rooms-sub">{fix.note}</p>
    </div>
  );
}

export function RefusalCard({ title, error }: { title: string; error: unknown }) {
  const candidate = !!error && mayBeVtaPermission(error);
  const listing = useQuery({
    queryKey: COMMUNITY_ROOMS_LIST_KEY,
    queryFn: fetchCommunityRooms,
    enabled: candidate,
  });
  if (!error) return null;
  const vtaFix = candidate ? vtaFixFor(error, listing.data?.setting.vtaAccess) : null;
  const fix = vtaFix ? null : refusalFix(error);
  const code = (error as { code?: unknown } | null)?.code;
  return (
    <section className="card error" role="alert">
      <h3>{title}</h3>
      <p>{refusalMessage(error)}</p>
      {vtaFix && <VtaFixCommands fix={vtaFix} />}
      {fix && <p className="community-fix">{fix}</p>}
      {typeof code === "string" && (
        <p className="muted rooms-sub">
          <code>{code}</code>
        </p>
      )}
    </section>
  );
}
