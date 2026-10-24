// How the identities this community mints are presented — its groups' and its
// own rooms' — as the runtime keys `dids.default_did_method` and
// `dids.scid_also_known_as` say (`vtc-service/src/did_hosting.rs`, VTI-VTC-004).
//
// Every identity is a `did:webvh` log. It can be given out as that DID or as its
// `did:scid:vh:1` DID, which the same log verifies but which does not name its
// host; and the log can list its did:scid alias, linking the two as one
// subject. The community states these to its VTA on each mint; unset, the VTA's
// own `[dids]` decides.

import { useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { useConfirm } from "@/components/ConfirmDialog";
import { Field } from "@/components/Field";
import { fetchEffectiveConfig } from "@/lib/api";
import { saveConfig } from "@/lib/config-api";
import { gestureFromConfirm } from "@/lib/signed-act";
import { useToast } from "@/lib/toast";
import type { EffectiveField } from "@/lib/wire-types";

export const DID_METHOD_KEY = "dids.default_did_method";
export const SCID_ALIAS_KEY = "dids.scid_also_known_as";

export function DidPresentationCard() {
  const qc = useQueryClient();
  const toast = useToast();
  const confirmGesture = gestureFromConfirm(useConfirm());
  const query = useQuery({ queryKey: ["admin-config"], queryFn: fetchEffectiveConfig });
  const methodField: EffectiveField | undefined = query.data?.fields.find(
    (f) => f.key === DID_METHOD_KEY,
  );
  const aliasField: EffectiveField | undefined = query.data?.fields.find(
    (f) => f.key === SCID_ALIAS_KEY,
  );
  const currentMethod = typeof methodField?.value === "string" ? methodField.value : null;
  const currentAlias = typeof aliasField?.value === "boolean" ? aliasField.value : null;

  const [method, setMethod] = useState<"webvh" | "scid">("webvh");
  const [alias, setAlias] = useState(true);
  useEffect(() => {
    setMethod(currentMethod === "scid" ? "scid" : "webvh");
  }, [currentMethod]);
  useEffect(() => {
    setAlias(currentAlias ?? true);
  }, [currentAlias]);

  // A did:scid identity always lists its alias (VTI-KEY-166).
  const effectiveAlias = method === "scid" ? true : alias;
  const unchanged = method === currentMethod && effectiveAlias === currentAlias;
  const envPinned = methodField?.source === "env" || aliasField?.source === "env";

  const save = useMutation({
    mutationFn: () =>
      saveConfig({ [DID_METHOD_KEY]: method, [SCID_ALIAS_KEY]: effectiveAlias }, confirmGesture),
    onSuccess: (result) => {
      const refused = result.rejected[0];
      if (refused) {
        toast.push("error", `The daemon refused ${refused.key}: ${refused.reason}`);
        return;
      }
      void qc.invalidateQueries({ queryKey: ["admin-config"] });
      toast.push(
        "success",
        method === "scid"
          ? "New group and room identities will be given out as their did:scid."
          : "New group and room identities will be given out as their did:webvh.",
      );
    },
    onError: (err) => toast.pushFromError(err, "Could not save how identities are presented"),
  });

  if (query.error || !methodField || !aliasField) return null;
  return (
    <details className="card" aria-labelledby="did-presentation-title">
      <summary id="did-presentation-title">How identities are presented</summary>
      <p className="muted">
        Each group and room identity is a <code>did:webvh</code> log. It can be given out as that
        DID, or as its <code>did:scid</code> DID, which the same log verifies but which does not
        name its host, so it survives a move. A change applies to identities minted from now on.
      </p>
      {!currentMethod && currentAlias === null && (
        <p className="muted">
          Not set here: the community&rsquo;s VTA decides, by its own <code>[dids]</code>.
        </p>
      )}
      {envPinned && (
        <div className="finding warn">
          <strong>Set by the environment, so this console cannot change it.</strong>
        </div>
      )}
      {!envPinned && (
        <>
          <Field label="Give new identities out as" labelId="did-presentation-method">
            <select
              aria-labelledby="did-presentation-method"
              value={method}
              onChange={(e) => setMethod(e.target.value === "scid" ? "scid" : "webvh")}
            >
              <option value="webvh">did:webvh</option>
              <option value="scid">did:scid</option>
            </select>
          </Field>
          <label>
            <input
              type="checkbox"
              checked={effectiveAlias}
              disabled={method === "scid"}
              onChange={(e) => setAlias(e.target.checked)}
            />{" "}
            List the did:scid alias, so the identity is known by both names
          </label>
          <div className="form-actions">
            <button
              type="button"
              className="primary"
              disabled={save.isPending || unchanged}
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
