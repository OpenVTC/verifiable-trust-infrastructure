// My passkeys plugin — list, register additional, revoke.
//
// Wraps the `/v1/admin/passkeys/*` endpoint family. Register is a
// dual-ceremony: a new-credential `create` plus a step-up UV
// `get` against an existing passkey in the same start/finish pair.
// Revoke is a single UV ceremony.

import { useState } from "react";
import {
  useMutation,
  useQuery,
  useQueryClient,
} from "@tanstack/react-query";
import { KeyRound, Plus, X } from "lucide-react";

import { getJson, postJson } from "@/lib/api";
import { useConfirm } from "@/components/ConfirmDialog";
import { formatIso as formatDate } from "@/lib/format";
import {
  decodePublicKeyOptions,
  serializeAssertion,
  serializeRegistration,
  type JsonPublicKeyOptions,
} from "@/lib/webauthn";

// Canonical `auth/passkey/*` tasks (trust-tasks-tf#145). One task per
// ceremony leg — the retired `admin/passkeys/{register,revoke}/1.0` pair
// had start and finish sharing a URI.
const TRUST_TASK_LIST = "https://trusttasks.org/spec/auth/passkey/list/0.1";
const TRUST_TASK_ENROLL_START =
  "https://trusttasks.org/spec/auth/passkey/enroll/start/0.2";
const TRUST_TASK_ENROLL_FINISH =
  "https://trusttasks.org/spec/auth/passkey/enroll/finish/0.2";
const TRUST_TASK_REVOKE_START =
  "https://trusttasks.org/spec/auth/passkey/revoke/start/0.1";
const TRUST_TASK_REVOKE_FINISH =
  "https://trusttasks.org/spec/auth/passkey/revoke/finish/0.1";


// The shared `RegisteredCredential` component of `auth/passkey/list/0.1`.
// `deviceLabel` and `lastUsedAt` are both genuinely optional: the schema is
// explicit that a consumer must not invent a label, "because an invented one is
// indistinguishable from a chosen one to somebody deciding which credential to
// revoke", so an unlabelled credential renders as unlabelled.
interface RegisteredCredential {
  credentialId: string;
  deviceLabel?: string;
  transports: string[];
  registeredAt: string;
  lastUsedAt?: string;
}

interface ListResponse {
  credentials: RegisteredCredential[];
}

// `enroll/start/0.2` sends the *inner* WebAuthn options — the value that goes
// in `navigator.credentials.create({ publicKey: … })` — not the wrapper. The
// daemon used to send `{publicKey: …}` and this file unwrapped it only to
// re-wrap it one line later; #1112 removed that round trip.
interface RegisterStartResponse {
  enrollmentId: string;
  options: JsonPublicKeyOptions;
  uvOptions: JsonPublicKeyOptions;
}

interface RevokeStartResponse {
  revocationId: string;
  uvOptions: JsonPublicKeyOptions;
}

async function fetchPasskeys(): Promise<ListResponse> {
  return getJson<ListResponse>("/v1/admin/passkeys", {
    trustTask: TRUST_TASK_LIST,
  });
}

async function registerPasskey(args: {
  label: string;
}): Promise<void> {
  // /register/start returns BOTH a create challenge (for the new
  // passkey) and a UV challenge (against existing passkeys, for
  // step-up). The browser runs both ceremonies, then /register/
  // finish takes both responses.
  const start = await postJson<RegisterStartResponse>(
    "/v1/admin/passkeys/register/start",
    undefined,
    {
      trustTask: TRUST_TASK_ENROLL_START,
      requires: ["enrollmentId", "options.challenge", "uvOptions.challenge"],
    },
  );

  const createPublicKey = decodePublicKeyOptions(
    start.options,
  ) as PublicKeyCredentialCreationOptions;
  const newCred = (await navigator.credentials.create({
    publicKey: createPublicKey,
  })) as PublicKeyCredential | null;
  if (!newCred) {
    throw new Error("Passkey creation returned no credential");
  }

  const uvPublicKey = decodePublicKeyOptions(
    start.uvOptions,
  ) as PublicKeyCredentialRequestOptions;
  const uvCred = (await navigator.credentials.get({
    publicKey: uvPublicKey,
  })) as PublicKeyCredential | null;
  if (!uvCred) {
    throw new Error("Step-up UV returned no credential");
  }

  await postJson<unknown>(
    "/v1/admin/passkeys/register/finish",
    {
      registration_id: start.enrollmentId,
      register_response: serializeRegistration(newCred),
      uv_response: serializeAssertion(uvCred),
      label: args.label,
      transports: [],
    },
    { trustTask: TRUST_TASK_ENROLL_FINISH },
  );
}

async function revokePasskey(args: {
  credentialId: string;
}): Promise<void> {
  const start = await postJson<RevokeStartResponse>(
    "/v1/admin/passkeys/revoke/start",
    { credential_id: args.credentialId },
    {
      trustTask: TRUST_TASK_REVOKE_START,
      requires: ["revocationId", "uvOptions.challenge"],
    },
  );

  const uvPublicKey = decodePublicKeyOptions(
    start.uvOptions,
  ) as PublicKeyCredentialRequestOptions;
  const uvCred = (await navigator.credentials.get({
    publicKey: uvPublicKey,
  })) as PublicKeyCredential | null;
  if (!uvCred) {
    throw new Error("Step-up UV returned no credential");
  }

  await postJson<unknown>(
    "/v1/admin/passkeys/revoke/finish",
    {
      revocation_id: start.revocationId,
      uv_response: serializeAssertion(uvCred),
    },
    { trustTask: TRUST_TASK_REVOKE_FINISH },
  );
}

export function MyPasskeys() {
  const queryClient = useQueryClient();
  const confirm = useConfirm();
  const [showRegister, setShowRegister] = useState(false);
  const [label, setLabel] = useState("");

  const query = useQuery({
    queryKey: ["my-passkeys"],
    queryFn: fetchPasskeys,
  });

  // `register/start` challenges an existing credential before issuing a new
  // one, so the button is only meaningful once at least one is enrolled.
  const canRegister = (query.data?.credentials.length ?? 0) > 0;

  const registerMutation = useMutation({
    mutationFn: registerPasskey,
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["my-passkeys"] });
      setShowRegister(false);
      setLabel("");
    },
  });

  const revokeMutation = useMutation({
    mutationFn: revokePasskey,
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["my-passkeys"] });
    },
  });

  const passkeys = query.data?.credentials ?? [];
  const onlyOne = passkeys.length === 1;

  return (
    <section className="page">
      <h2>My passkeys</h2>
      <p className="lead">
        Manage the passkeys bound to your admin DID. Register a
        backup before losing access to your primary device — losing
        your only passkey means using <code>vtc admin emergency-bootstrap</code>{" "}
        on the host to recover.
      </p>

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
            <label className="field">
              <span className="field-label">Label</span>
              <input
                type="text"
                placeholder="e.g. ‘YubiKey 5C — work’"
                value={label}
                onChange={(e) => setLabel(e.target.value)}
                required
              />
            </label>

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
        <table className="data-table">
          <thead>
            <tr>
              <th>Label</th>
              <th>Credential ID</th>
              <th>Registered</th>
              <th>Last used</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {query.isPending && (
              <tr>
                <td colSpan={5}>Loading…</td>
              </tr>
            )}
            {passkeys.length === 0 && !query.isPending && (
              <tr>
                <td colSpan={5}>
                  <div className="empty-state">
                    <span className="empty-icon" aria-hidden="true">
                      <KeyRound />
                    </span>
                    <h4>No passkeys registered</h4>
                    <p>
                      Your session is authenticated another way — by your VTA
                      wallet — so there is no passkey here to add a second
                      device against. Registering one starts from an install
                      URL, which an operator mints on the host with{" "}
                      <code>vtc admin invite --did &lt;your-did&gt;</code>.
                    </p>
                  </div>
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
          </tbody>
        </table>
        {onlyOne && (
          <p className="muted">
            The Revoke button is disabled because you only have one
            passkey. Register a second one first.
          </p>
        )}
      </section>
    </section>
  );
}

