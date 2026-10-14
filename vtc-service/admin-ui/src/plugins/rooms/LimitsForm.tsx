// Override, or clear the override of, one scope's limits on one room —
// `vtc/rooms/limits/set/0.1` with a `room`, `memberDefault` or `member` target.
//
// The override replaces any previous one at that target wholesale, so the form
// starts from the limits in force and sends every field: an emptied field is
// "no limit of this kind at this scope", and the next wider scope (or the
// host's ceiling) governs. Clearing returns the target to the policy's or the
// community's default.
//
// Not parked for another administrator: an allowance can be reversed and loses
// nothing, and lowering one deletes nothing either — a room already over a new
// limit keeps every file and only new uploads are refused. The reason is
// required and goes to the audit trail with the change.

import { useState, type FormEvent } from "react";
import { useQueryClient } from "@tanstack/react-query";

import { Field } from "@/components/Field";
import { useToast } from "@/lib/toast";
import { exactBytes, formatBytes, parseBytes, parseCount, setRoomLimits } from "@/lib/rooms-api";
import type { RoomLimitTarget, RoomScopeLimits } from "@/lib/wire-types";

/** The transfer ceiling no limit may exceed (`BlobManifest`). */
const TRANSFER_CEILING = 2 ** 30;
const REASON_MAX = 500;

const countText = (n: number | undefined) => (n === undefined ? "" : String(n));
const bytesText = (n: number | undefined) => (n === undefined ? "" : exactBytes(n));

export function LimitsForm({
  roomId,
  target,
  current,
  hostCeilingBytes,
  onDone,
}: {
  roomId: string;
  target: RoomLimitTarget;
  /** The limits in force at this target now, which the form starts from. */
  current: RoomScopeLimits | undefined;
  hostCeilingBytes: number | undefined;
  onDone: () => void;
}) {
  const toast = useToast();
  const queryClient = useQueryClient();
  const [mode, setMode] = useState<"set" | "clear">("set");
  const [maxFiles, setMaxFiles] = useState(countText(current?.maxFiles));
  const [maxBytes, setMaxBytes] = useState(bytesText(current?.maxBytes));
  const [maxFileBytes, setMaxFileBytes] = useState(bytesText(current?.maxFileBytes));
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState(false);

  const ceiling = Math.min(hostCeilingBytes ?? TRANSFER_CEILING, TRANSFER_CEILING);
  const files = parseCount(maxFiles);
  const bytes = parseBytes(maxBytes);
  const fileBytes = parseBytes(maxFileBytes);
  const errors = {
    maxFiles: files === null ? "A whole number of files, or empty for no limit." : null,
    maxBytes: bytes === null ? "A size such as 5 GB or 500 MB, or empty for no limit." : null,
    maxFileBytes:
      fileBytes === null
        ? "A size such as 100 MB, or empty for no limit."
        : fileBytes !== undefined && fileBytes > ceiling
          ? `At most ${formatBytes(ceiling)}, the host's ceiling on one file.`
          : null,
  };
  const reasonTrimmed = reason.trim();
  const valid =
    reasonTrimmed.length > 0 &&
    reasonTrimmed.length <= REASON_MAX &&
    (mode === "clear" || Object.values(errors).every((e) => e === null));

  async function submit(e: FormEvent) {
    e.preventDefault();
    if (!valid || busy) return;
    setBusy(true);
    try {
      const limits: RoomScopeLimits = {
        ...(files !== undefined && files !== null ? { maxFiles: files } : {}),
        ...(bytes !== undefined && bytes !== null ? { maxBytes: bytes } : {}),
        ...(fileBytes !== undefined && fileBytes !== null ? { maxFileBytes: fileBytes } : {}),
      };
      const out = await setRoomLimits({
        roomId,
        target,
        reason: reasonTrimmed,
        ...(mode === "clear" ? { clear: true } : { limits }),
      });
      toast.push("success", mode === "clear" ? "Override cleared." : "Limits saved.");
      if (out.overLimit) {
        toast.push(
          "info",
          "This scope already holds more than the new limits allow. Nothing is deleted; new uploads are refused until it is back under them.",
        );
      }
      await queryClient.invalidateQueries({ queryKey: ["rooms"] });
      await queryClient.invalidateQueries({ queryKey: ["room-usage"] });
      onDone();
    } catch (err) {
      toast.pushFromError(err, "Could not change the limits");
    } finally {
      setBusy(false);
    }
  }

  return (
    <form className="rooms-limits-form" onSubmit={submit}>
      <fieldset className="rooms-limits-mode">
        <legend className="field-label">Change</legend>
        <label>
          <input
            type="radio"
            name="limits-mode"
            checked={mode === "set"}
            onChange={() => setMode("set")}
          />{" "}
          Set these limits
        </label>
        <label>
          <input
            type="radio"
            name="limits-mode"
            checked={mode === "clear"}
            onChange={() => setMode("clear")}
          />{" "}
          Clear the override, back to the default
        </label>
      </fieldset>

      {mode === "set" && (
        <div className="rooms-limits-fields">
          <Field label="Most files" hint="Empty: no limit at this scope." error={errors.maxFiles}>
            <input
              inputMode="numeric"
              value={maxFiles}
              onChange={(e) => setMaxFiles(e.target.value)}
              aria-invalid={errors.maxFiles !== null}
            />
          </Field>
          <Field
            label="Most space"
            hint={bytes ? `${formatBytes(bytes)}, reserved uploads included.` : "Empty: no limit at this scope."}
            error={errors.maxBytes}
          >
            <input
              value={maxBytes}
              onChange={(e) => setMaxBytes(e.target.value)}
              placeholder="5 GB"
              aria-invalid={errors.maxBytes !== null}
            />
          </Field>
          <Field
            label="Largest file"
            hint={fileBytes ? formatBytes(fileBytes) : `Empty: up to ${formatBytes(ceiling)}.`}
            error={errors.maxFileBytes}
          >
            <input
              value={maxFileBytes}
              onChange={(e) => setMaxFileBytes(e.target.value)}
              placeholder="100 MB"
              aria-invalid={errors.maxFileBytes !== null}
            />
          </Field>
        </div>
      )}

      <Field
        label="Reason"
        hint="Recorded with the change in the audit trail. No personal data."
        error={reasonTrimmed.length > REASON_MAX ? `At most ${REASON_MAX} characters.` : null}
      >
        <textarea
          rows={2}
          value={reason}
          onChange={(e) => setReason(e.target.value)}
          required
        />
      </Field>

      <div className="rooms-form-actions">
        <button type="submit" disabled={!valid || busy}>
          {busy ? "Saving…" : mode === "clear" ? "Clear override" : "Save limits"}
        </button>
        <button type="button" className="secondary" onClick={onDone} disabled={busy}>
          Cancel
        </button>
      </div>
    </form>
  );
}
