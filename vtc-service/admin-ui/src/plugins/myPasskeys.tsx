// My passkeys plugin — list, register additional, revoke.
//
// The calls are `lib/my-passkeys-api.ts`: signed `auth/passkey/*` documents
// from this browser's console key, each step-up verified by a passkey you
// already hold.

import { useState } from "react";
import {
  useMutation,
  useQuery,
  useQueryClient,
} from "@tanstack/react-query";
import { KeyRound, Plus, X } from "lucide-react";

import { fetchPasskeys, registerPasskey, revokePasskey } from "@/lib/my-passkeys-api";
import { useConfirm } from "@/components/ConfirmDialog";
import { formatIso as formatDate } from "@/lib/format";
import { useViewerDid } from "@/lib/viewer";
import { ApproverDevicesCard } from "@/plugins/members/StepUpApprovers";
import { Field } from "@/components/Field";
import { DataTable } from "@/components/DataTable";
import { EmptyState } from "@/components/EmptyState";
import { PageHeader } from "@/components/PageHeader";

export function MyPasskeys() {
  const queryClient = useQueryClient();
  const confirm = useConfirm();
  const [showRegister, setShowRegister] = useState(false);
  const [label, setLabel] = useState("");
  const viewer = useViewerDid();

  const query = useQuery({
    queryKey: ["my-passkeys"],
    queryFn: fetchPasskeys,
  });

  // `register/start` challenges an existing credential before issuing a new
  // one, so the button is only meaningful once at least one is enrolled.
  const canRegister = (query.data?.credentials.length ?? 0) > 0;

  const registerMutation = useMutation({
    mutationFn: (args: { label: string }) => registerPasskey(args),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["my-passkeys"] });
      setShowRegister(false);
      setLabel("");
    },
  });

  const revokeMutation = useMutation({
    mutationFn: (args: { credentialId: string }) => revokePasskey(args),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["my-passkeys"] });
    },
  });

  const passkeys = query.data?.credentials ?? [];
  const onlyOne = passkeys.length === 1;

  return (
    <section className="page">
      <PageHeader
        title="My passkeys"
        lead={
          <>
          Manage the passkeys bound to your admin DID. Register a
          backup before losing access to your primary device — losing
          your only passkey means using <code>vtc admin emergency-bootstrap</code>{" "}
          on the host to recover.
          </>
        }
      />

      {query.error && (
        <section className="card error">
          <h3>Failed to load passkeys</h3>
          <p>{(query.error as Error).message}</p>
        </section>
      )}

      {/* Registering steps up against a passkey you already hold, so it
          cannot mint the first one — the bootstrap path is the install URL.
          Offering the button with none enrolled sent operators at a ceremony
          that answers 404 from `register/start`, on the page whose whole
          purpose is to tell them how to get one. */}
      {canRegister && (
      <section className="card">
        <div className="toolbar">
          <div className="spacer" />
          <button
            type="button"
            className={showRegister ? "secondary" : "primary"}
            onClick={() => setShowRegister((v) => !v)}
          >
            {showRegister ? (
              <>
                <X size={14} aria-hidden="true" /> Cancel
              </>
            ) : (
              <>
                <Plus size={14} aria-hidden="true" /> Register new passkey
              </>
            )}
          </button>
        </div>
      </section>
      )}

      {showRegister && (
        <section className="card">
          <h3>Register additional passkey</h3>
          <p className="lead">
            Your browser will prompt twice — once to create the new
            credential, then to verify your existing passkey.
          </p>
          <form
            onSubmit={(e) => {
              e.preventDefault();
              registerMutation.mutate({ label });
            }}
            className="form-stack"
          >
            <Field label="Label">
              <input
                type="text"
                placeholder="e.g. ‘YubiKey 5C — work’"
                value={label}
                onChange={(e) => setLabel(e.target.value)}
                required
              />
            </Field>

            {registerMutation.error && (
              <section className="card error">
                <h3>Register failed</h3>
                <p>{(registerMutation.error as Error).message}</p>
              </section>
            )}

            <div className="form-actions">
              <button
                type="submit"
                className="primary"
                disabled={registerMutation.isPending || label.trim() === ""}
              >
                {registerMutation.isPending
                  ? "Verifying…"
                  : "Register"}
              </button>
            </div>
          </form>
        </section>
      )}

      {revokeMutation.error && (
        <section className="card error">
          <h3>Revoke failed</h3>
          <p>{(revokeMutation.error as Error).message}</p>
        </section>
      )}

      <section className="card">
        <DataTable
          columns={[
            { key: "label", label: "Label" },
            { key: "credential-id", label: "Credential ID" },
            { key: "registered", label: "Registered" },
            { key: "last-used", label: "Last used" },
            { key: "actions", label: "" },
          ]}
        >
          {query.isPending && (
            <tr>
              <td colSpan={5}>Loading…</td>
            </tr>
          )}
          {passkeys.length === 0 && !query.isPending && (
            <tr>
              <td colSpan={5}>
                <EmptyState icon={KeyRound} title="No passkeys registered">
                  Your session is authenticated another way — by your VTA
                  wallet — so there is no passkey here to add a second
                  device against. Registering one starts from an install
                  URL, which an operator mints on the host with{" "}
                  <code>vtc admin invite --did &lt;your-did&gt;</code>.
                </EmptyState>
              </td>
            </tr>
          )}
          {passkeys.map((p) => (
            <tr key={p.credentialId}>
              <td>{p.deviceLabel ?? <span className="muted">—</span>}</td>
              <td>
                <code className="truncate" title={p.credentialId}>
                  {p.credentialId}
                </code>
              </td>
              <td>{formatDate(p.registeredAt)}</td>
              <td>
                {p.lastUsedAt ? (
                  formatDate(p.lastUsedAt)
                ) : (
                  <span className="muted">never</span>
                )}
              </td>
              <td>
                <button
                  type="button"
                  className="secondary destructive"
                  disabled={revokeMutation.isPending || onlyOne}
                  title={
                    onlyOne
                      ? "Cannot revoke your last passkey"
                      : undefined
                  }
                  onClick={async () => {
                    const ok = await confirm({
                      title: p.deviceLabel
                        ? `Revoke "${p.deviceLabel}"?`
                        : "Revoke this passkey?",
                      message:
                        "You'll need to verify with another passkey. The revoked passkey can no longer sign in.",
                      confirmLabel: "Revoke",
                      destructive: true,
                    });
                    if (ok) {
                      revokeMutation.mutate({
                        credentialId: p.credentialId,
                      });
                    }
                  }}
                >
                  Revoke
                </button>
              </td>
            </tr>
          ))}
        </DataTable>
        {onlyOne && (
          <p className="muted">
            The Revoke button is disabled because you only have one
            passkey. Register a second one first.
          </p>
        )}
      </section>

      {/* A wallet administrator's step-up factor is an approver device, not a
          passkey — their own, listed and managed here. */}
      {viewer && <ApproverDevicesCard did={viewer} self />}
    </section>
  );
}

