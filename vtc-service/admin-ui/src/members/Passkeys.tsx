// The member's portal passkeys. Adding and removing need a wallet sign-in
// (the DID is the anchor); a passkey session sees the list and why.

import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { KeyRound, Plus, Trash2 } from "lucide-react";

import { memberFetch, type MemberPasskey } from "./api";
import { addPasskey, passkeysSupported } from "./auth";

function shortId(id: string): string {
  return id.length > 16 ? `${id.slice(0, 8)}…${id.slice(-6)}` : id;
}

export function Passkeys({ canManage }: { canManage: boolean }) {
  const qc = useQueryClient();
  const [label, setLabel] = useState("");
  const [error, setError] = useState<string | null>(null);

  const list = useQuery({
    queryKey: ["member-passkeys"],
    queryFn: () => memberFetch<MemberPasskey[]>("/v1/member/passkeys"),
  });

  const add = useMutation({
    mutationFn: () => addPasskey(label),
    onSuccess: () => {
      setLabel("");
      setError(null);
      void qc.invalidateQueries({ queryKey: ["member-passkeys"] });
    },
    onError: (e) =>
      setError(
        e instanceof DOMException && e.name === "NotAllowedError"
          ? "Passkey creation was cancelled."
          : e instanceof Error
            ? e.message
            : String(e),
      ),
  });

  const remove = useMutation({
    mutationFn: (id: string) =>
      memberFetch<void>(`/v1/member/passkeys/${encodeURIComponent(id)}`, {
        method: "DELETE",
      }),
    onSuccess: () => void qc.invalidateQueries({ queryKey: ["member-passkeys"] }),
    onError: (e) => setError(e instanceof Error ? e.message : String(e)),
  });

  const passkeys = list.data ?? [];

  return (
    <section className="card" aria-labelledby="passkeys-heading">
      <div className="card-head">
        <KeyRound size={18} aria-hidden="true" />
        <h2 id="passkeys-heading">Passkeys</h2>
      </div>
      <p className="muted">
        A passkey signs you in to this portal on this device without opening
        your wallet. It works here only — never in the operator console.
      </p>

      {list.isPending ? (
        <p className="muted">Loading…</p>
      ) : passkeys.length === 0 ? (
        <p className="empty">No passkeys yet.</p>
      ) : (
        <ul className="passkey-list">
          {passkeys.map((p) => (
            <li key={p.credentialId}>
              <div>
                <strong>{p.label || "Passkey"}</strong>
                <span className="muted">
                  {" "}
                  · added {new Date(p.registeredAt).toLocaleDateString()} ·{" "}
                  <code>{shortId(p.credentialId)}</code>
                </span>
              </div>
              {canManage && (
                <button
                  type="button"
                  className="btn btn-ghost btn-sm"
                  onClick={() => remove.mutate(p.credentialId)}
                  disabled={remove.isPending}
                  aria-label={`Remove ${p.label || "passkey"}`}
                >
                  <Trash2 size={14} aria-hidden="true" /> Remove
                </button>
              )}
            </li>
          ))}
        </ul>
      )}

      {canManage ? (
        <form
          className="passkey-add"
          onSubmit={(e) => {
            e.preventDefault();
            add.mutate();
          }}
        >
          <label htmlFor="passkey-label" className="sr-only">
            Name for this passkey
          </label>
          <input
            id="passkey-label"
            type="text"
            maxLength={64}
            placeholder="Name it, e.g. “Work laptop”"
            value={label}
            onChange={(e) => setLabel(e.target.value)}
          />
          <button
            type="submit"
            className="btn btn-primary"
            disabled={add.isPending || !passkeysSupported()}
          >
            <Plus size={16} aria-hidden="true" />
            {add.isPending ? "Waiting for your device…" : "Add a passkey"}
          </button>
        </form>
      ) : (
        <p className="muted">
          You signed in with a passkey. To add or remove passkeys, sign out and
          sign in with your wallet.
        </p>
      )}

      {error && (
        <div className="alert" role="alert">
          <p>{error}</p>
        </div>
      )}
    </section>
  );
}
