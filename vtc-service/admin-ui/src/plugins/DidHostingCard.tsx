// Where the identities this community mints are published — its groups' and
// its own rooms' — as the runtime key `dids.webvh_server` says
// (`vtc-service/src/did_hosting.rs`, docs/03-vtc/groups.md).
//
// Either this community serves each identity's `did.jsonl` itself, or its VTA
// publishes it on a `did:webvh` hosting server registered there. A change
// applies to the next identity minted; one already minted stays where it is,
// because its DID names its host.

import { useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { useConfirm } from "@/components/ConfirmDialog";
import { Field } from "@/components/Field";
import { fetchEffectiveConfig, postSignedRead } from "@/lib/api";
import { saveConfig } from "@/lib/config-api";
import { gestureFromConfirm } from "@/lib/signed-act";
import { useToast } from "@/lib/toast";
import type { DidHostingListResponse, EffectiveField } from "@/lib/wire-types";

export const DID_HOSTING_KEY = "dids.webvh_server";
export const LOCAL = "local";
export const DID_HOSTING_LIST_TASK = "https://trusttasks.org/spec/vtc/config/did-hosting/list/0.1";
/** The daemon's bound on a server id (`did_hosting::validate`). */
const SERVER_ID = /^[A-Za-z0-9._:-]{1,128}$/;

export function DidHostingCard() {
  const qc = useQueryClient();
  const toast = useToast();
  const confirmGesture = gestureFromConfirm(useConfirm());
  const query = useQuery({ queryKey: ["admin-config"], queryFn: fetchEffectiveConfig });
  const field: EffectiveField | undefined = query.data?.fields.find(
    (f) => f.key === DID_HOSTING_KEY,
  );
  const current = typeof field?.value === "string" ? field.value : null;
  // The hosting servers the community's VTA reports. A community without a VTA
  // link, or a VTA that does not answer, leaves the id to be typed.
  const servers = useQuery({
    queryKey: ["did-hosting", "servers"],
    queryFn: () => postSignedRead<DidHostingListResponse>(DID_HOSTING_LIST_TASK, {}),
    retry: false,
  });
  const listed = servers.data?.servers ?? [];
  const envPinned = field?.source === "env";

  const [mode, setMode] = useState<"local" | "server">("local");
  const [server, setServer] = useState("");
  useEffect(() => {
    if (current && current !== LOCAL) {
      setMode("server");
      setServer(current);
    } else {
      setMode("local");
    }
  }, [current]);

  const value = mode === "local" ? LOCAL : server.trim();
  const valid = mode === "local" || SERVER_ID.test(value);
  const save = useMutation({
    mutationFn: () => saveConfig({ [DID_HOSTING_KEY]: value }, confirmGesture),
    onSuccess: (result) => {
      const refused = result.rejected.find((r) => r.key === DID_HOSTING_KEY);
      if (refused) {
        toast.push("error", `The daemon refused that value: ${refused.reason}`);
        return;
      }
      void qc.invalidateQueries({ queryKey: ["admin-config"] });
      toast.push(
        "success",
        value === LOCAL
          ? "New group and room identities will be served by this community."
          : `New group and room identities will be published on “${value}” by the community's VTA.`,
      );
    },
    onError: (err) => toast.pushFromError(err, "Could not save where identities are published"),
  });

  if (query.error) return null;
  return (
    <details className="card" aria-labelledby="did-hosting-title">
      <summary id="did-hosting-title">Where identities are published</summary>
      <p className="muted">
        Each group and each community room has a <code>did:webvh</code> identity of its own. This
        community can serve each one itself, at its public URL, or its VTA can publish it on a
        hosting server registered there. A change applies to identities minted from now on; one
        already minted stays where it is.
      </p>
      {field && !current && (
        <p className="muted">
          Not set here: each kind follows <code>[groups] webvh_server</code> and{" "}
          <code>[rooms.community] webvh_server</code> in <code>config.toml</code>, and is served
          by this community where those are absent.
        </p>
      )}
      {field && envPinned && (
        <div className="finding warn">
          <strong>Set by the environment, so this console cannot change it.</strong>
          <p className="muted">
            <code>VTC_DIDS_WEBVH_SERVER</code> is <code>{current}</code>.
          </p>
        </div>
      )}
      {field && !envPinned && (
        <>
          <fieldset className="stack">
            <label>
              <input
                type="radio"
                name="did-hosting"
                checked={mode === "local"}
                onChange={() => setMode("local")}
              />{" "}
              This community serves them
            </label>
            <label>
              <input
                type="radio"
                name="did-hosting"
                checked={mode === "server"}
                onChange={() => setMode("server")}
              />{" "}
              A hosting server at the community&rsquo;s VTA
            </label>
          </fieldset>
          {mode === "server" && listed.length > 0 && (
            <Field label="Hosting server at the VTA" labelId="did-hosting-server">
              <select
                aria-labelledby="did-hosting-server"
                value={server}
                onChange={(e) => setServer(e.target.value)}
              >
                <option value="">Choose a server…</option>
                {listed.map((s) => (
                  <option key={s.id} value={s.id}>
                    {s.label ? `${s.label} (${s.id})` : s.id}
                  </option>
                ))}
                {server && !listed.some((s) => s.id === server) && (
                  <option value={server}>{server} (current, not listed by the VTA)</option>
                )}
              </select>
            </Field>
          )}
          {mode === "server" && listed.length === 0 && (
            <>
              <Field label="Server id at the VTA" labelId="did-hosting-server">
                <input
                  aria-labelledby="did-hosting-server"
                  placeholder="e.g. hosting"
                  value={server}
                  maxLength={128}
                  onChange={(e) => setServer(e.target.value)}
                />
              </Field>
              {servers.error && (
                <p className="muted">
                  The VTA&rsquo;s hosting servers could not be listed (
                  {(servers.error as Error).message}); type the server&rsquo;s id as it is
                  registered there.
                </p>
              )}
            </>
          )}
          <div className="form-actions">
            <button
              type="button"
              className="primary"
              disabled={save.isPending || !valid || value === current}
              onClick={() => save.mutate()}
            >
              {save.isPending ? "Saving…" : "Save"}
            </button>
          </div>
        </>
      )}
    </details>
  );
}
