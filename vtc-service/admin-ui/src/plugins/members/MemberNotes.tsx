// Administrators' notes about one member (`vtc/directory/notes/*`,
// VTI-DIR-030 – 033), on the member's page in the console.
//
// Notes live apart from the member's card and no directory read carries one;
// only holders of `vtc.directory.notes` see this card at all — for anyone
// else the community refuses the read and the card says nothing. A note is
// never edited: Withdraw writes a later note that redacts it, and its text
// then appears only in the export a member's data request is answered with,
// which takes the operator's passkey bound to that one export.

import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { useConfirm } from "@/components/ConfirmDialog";
import { Field } from "@/components/Field";
import { Protected } from "@/components/Protected";
import { useToast } from "@/lib/toast";
import {
  appendNote,
  exportNotes,
  listNotes,
  redactNote,
  saveJson,
  showEntryByDid,
} from "@/lib/directory";
import { gestureFromConfirm } from "@/lib/signed-act";
import { formatDateTime } from "@/lib/format";

export function MemberNotesCard({ did }: { did: string }) {
  const qc = useQueryClient();
  const toast = useToast();
  const confirm = useConfirm();
  const entry = useQuery({
    queryKey: ["directory", "entry-by-did", did],
    queryFn: () => showEntryByDid(did),
    retry: false,
  });
  const entryId = entry.data?.entry.entryId;
  const notes = useQuery({
    queryKey: ["directory", "notes", entryId],
    queryFn: () => listNotes(entryId!),
    enabled: !!entryId,
    retry: false,
  });
  const [text, setText] = useState("");
  const [followUp, setFollowUp] = useState("");
  const [reason, setReason] = useState("");

  const refresh = () => void qc.invalidateQueries({ queryKey: ["directory", "notes", entryId] });
  const add = useMutation({
    mutationFn: () => appendNote(entryId!, text.trim(), followUp || undefined),
    onSuccess: () => {
      setText("");
      setFollowUp("");
      refresh();
    },
    onError: (e) => toast.pushFromError(e, "Couldn't save the note"),
  });
  const withdraw = useMutation({
    mutationFn: (noteId: string) => redactNote(entryId!, noteId),
    onSuccess: refresh,
    onError: (e) => toast.pushFromError(e, "Couldn't save the note"),
  });
  const exp = useMutation({
    mutationFn: () => exportNotes(entryId!, reason.trim(), gestureFromConfirm(confirm)),
    onSuccess: (r) => {
      saveJson(r, `notes-${entryId}.json`);
      setReason("");
      toast.push("success", "The member's notes were exported and recorded in the audit log.");
    },
    onError: (e) => toast.pushFromError(e, "Export failed"),
  });

  // Not a notes holder, or no directory entry: nothing to show.
  if (!entryId || notes.isError) return null;
  const items = notes.data?.items ?? [];
  // Withdrawing a note, and releasing the notes to their member: out of the
  // community theme's reach (vtc/community/theme/show/0.1, client item 2).
  return (
    <Protected ground="card">
    <section className="card" aria-labelledby="member-notes-heading">
      <h3 id="member-notes-heading">Administrators&rsquo; notes</h3>
      <p className="muted">
        Seen only by holders of <code>vtc.directory.notes</code>, never on the member&rsquo;s card or
        in any directory read. A note can&rsquo;t be edited; withdraw it and write a new one.
      </p>
      {items.length === 0 ? (
        <p className="muted">No notes yet.</p>
      ) : (
        <ul className="notes">
          {items.map((n) => (
            <li key={n.noteId} className={n.redactedBy ? "note note-redacted" : "note"}>
              <div className="note-meta muted">
                {formatDateTime(n.createdAt)} · <code title={n.author}>{n.author.slice(0, 28)}…</code>
                {n.followUp && <> · follow up by {n.followUp}</>}
              </div>
              {n.redacts ? (
                <div className="muted">Withdrew an earlier note.</div>
              ) : n.redactedBy ? (
                <div className="muted">Withdrawn.</div>
              ) : (
                <div className="note-text">{n.text}</div>
              )}
              {!n.redacts && !n.redactedBy && (
                <button
                  type="button"
                  className="link"
                  disabled={withdraw.isPending}
                  onClick={() => withdraw.mutate(n.noteId)}
                >
                  Withdraw
                </button>
              )}
            </li>
          ))}
        </ul>
      )}
      <form
        className="form-stack"
        onSubmit={(e) => {
          e.preventDefault();
          if (text.trim()) add.mutate();
        }}
      >
        <Field label="Add a note">
          <textarea
            className="prose"
            aria-label="Add a note"
            value={text}
            maxLength={2000}
            onChange={(e) => setText(e.target.value)}
          />
        </Field>
        <Field label="Follow up by" hint="Optional.">
          <input type="date" aria-label="Follow up by" value={followUp} onChange={(e) => setFollowUp(e.target.value)} />
        </Field>
        <div className="form-actions">
          <button type="submit" className="primary" disabled={!text.trim() || add.isPending}>
            {add.isPending ? "Adding…" : "Add note"}
          </button>
        </div>
      </form>
      <details>
        <summary>Export these notes for the member&rsquo;s data request</summary>
        <p className="muted">
          Every note, withdrawn ones included, as written. It takes your passkey and is recorded in
          the audit log at its highest severity.
        </p>
        <form
          className="toolbar"
          onSubmit={(e) => {
            e.preventDefault();
            if (reason.trim()) exp.mutate();
          }}
        >
          <Field label="Why" inline>
            <input
              aria-label="Why export the notes"
              value={reason}
              maxLength={1024}
              placeholder="e.g. the member's subject-access request of 19 October"
              onChange={(e) => setReason(e.target.value)}
            />
          </Field>
          <button type="submit" className="secondary" disabled={!reason.trim() || exp.isPending}>
            {exp.isPending ? "Exporting…" : "Export notes"}
          </button>
        </form>
      </details>
    </section>
    </Protected>
  );
}
