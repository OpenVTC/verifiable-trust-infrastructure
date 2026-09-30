// `/admin/install?token=<jwt>` — install-claim ceremony.
//
// Distinct from a plugin: the install URL is the public entry point
// for an unauthenticated operator, so it lives outside the plugin
// routing tree (which is gated on auth once login lands). Reads
// `?token=` from the URL, drives `navigator.credentials.create`,
// signs and posts `vtc/install/claim/{start,finish}/0.2` and
// `vtc/admin/bootstrap/0.1` to the shared `POST /v1/trust-tasks` door —
// these have no dedicated REST route any more; each verb's own bearer
// artifact (the install JWT, the `registrationId` `start` minted, the
// setup-session JWT `finish` minted) is the credential, not a proof, so
// the documents are unsigned (`postUnsignedTrustTask`).
//
// Modelled on `affinidi-webvh-service/webvh-ui/lib/passkey.ts` +
// `app/enroll.tsx`: standard WebAuthn registration with no custom
// binding-signature step. The admin DID is carried in the install
// token, not derived from the passkey.

import { useState } from "react";
import { useSearchParams } from "react-router-dom";

import { postUnsignedTrustTask, type ApiError } from "@/lib/api";
import {
  decodePublicKeyOptions,
  serializeRegistration,
  type JsonPublicKeyOptions,
} from "@/lib/webauthn";

const TRUST_TASK_START =
  "https://trusttasks.org/spec/vtc/install/claim/start/0.2";
const TRUST_TASK_FINISH =
  "https://trusttasks.org/spec/vtc/install/claim/finish/0.2";
const TRUST_TASK_BOOTSTRAP =
  "https://trusttasks.org/spec/vtc/admin/bootstrap/0.1";

// No browser identity exists at any point in this ceremony — the admin DID is
// decided server-side from the install token, not derived from a console key
// this browser holds. The framework binds a document's `issuer` to its proof
// only when one is present (SPEC §7.2 item 7); none of these three documents
// carries one, so this placeholder claims nothing and is never checked.
const ANONYMOUS_ISSUER = "did:key:z6MkVtcInstallAnonymous";

type Phase =
  | { kind: "awaiting-code" }
  | { kind: "registering" }
  | { kind: "success"; adminDid: string; setupSessionToken: string }
  | { kind: "error"; title: string; message: string; hint?: string };

interface ClaimStartResponse {
  registrationId: string;
  options: { publicKey: JsonPublicKeyOptions };
}

interface ClaimFinishResponse {
  adminDid: string;
  setupSessionToken: string;
}

interface BootstrapResponse {
  adminDid: string;
  eventId: string;
}

export function Install() {
  const [params] = useSearchParams();
  const token = params.get("token");
  const [phase, setPhase] = useState<Phase>(
    token
      ? { kind: "awaiting-code" }
      : {
          kind: "error",
          title: "Missing install token",
          message: "The install URL must include `?token=<jwt>`.",
          hint: "Re-open the URL the wizard or admin console issued.",
        },
  );
  const [claimCode, setClaimCode] = useState("");

  const runCeremony = async (code: string) => {
    if (!token) return;
    setPhase({ kind: "registering" });

    // ── claim/start ──
    let startBody: ClaimStartResponse;
    try {
      startBody = await postUnsignedTrustTask<ClaimStartResponse>(
        TRUST_TASK_START,
        {
          installToken: token,
          claimSecret: code.trim() === "" ? undefined : code.trim(),
        },
        ANONYMOUS_ISSUER,
      );
    } catch (err) {
      const e = err as ApiError;
      // `vtc/install/claim/start:invalidToken` covers a missing/wrong claim
      // code as well as an expired or already-claimed token — the published
      // spec declares one code for the whole family (unlike the retired
      // bearer route's bespoke 401 variants), distinguished only by the
      // message this daemon still stamps with a `claim_secret_*` prefix.
      if (e.code === "vtc/install/claim/start:invalidToken") {
        if (e.message.startsWith("claim_secret_required")) {
          setPhase({
            kind: "error",
            title: "Claim code required",
            message:
              "This install URL is paired with an out-of-band claim code. Ask whoever sent you the URL for the matching code, then try again.",
          });
          return;
        }
        if (e.message.startsWith("claim_secret_invalid")) {
          setPhase({
            kind: "error",
            title: "Wrong claim code",
            message:
              "The claim code you typed doesn't match the one the daemon stored. Double-check the code and retry — repeated wrong attempts will not lock the invite, but they slow you down.",
          });
          return;
        }
        setPhase({
          kind: "error",
          title: "Install URL expired or already used",
          message:
            "The install URL is single-use and expires 15 minutes after it's minted.",
          hint:
            "Ask the daemon operator to mint a new one via `vtc admin invite` or the admin console's Invites panel.",
        });
        return;
      }
      if (e.details?.reason === "conflict") {
        setPhase({
          kind: "error",
          title: "Install ceremony already in progress",
          message: "Another browser session is mid-ceremony with this token.",
          hint:
            "Wait a few minutes for it to time out, then retry — or ask the operator for a fresh URL.",
        });
        return;
      }
      setPhase({
        kind: "error",
        title: `Server error (${e.status})`,
        message: e.message || "Unexpected response from the daemon.",
      });
      return;
    }

    // ── browser WebAuthn create ──
    const publicKey = decodePublicKeyOptions(
      startBody.options.publicKey,
    ) as PublicKeyCredentialCreationOptions;

    let credential: PublicKeyCredential | null = null;
    try {
      credential = (await navigator.credentials.create({
        publicKey,
      })) as PublicKeyCredential | null;
    } catch (err) {
      const e = err as Error;
      setPhase({
        kind: "error",
        title: "Passkey registration cancelled or failed",
        message: e.message || String(err),
        hint:
          "Try again, or use a different authenticator (USB security key, platform passkey).",
      });
      return;
    }
    if (!credential) {
      setPhase({
        kind: "error",
        title: "Passkey registration returned no credential",
        message:
          "Your browser dismissed the ceremony without producing a credential.",
        hint: "Retry the install URL.",
      });
      return;
    }

    // ── claim/finish ──
    let finishBody: ClaimFinishResponse;
    try {
      finishBody = await postUnsignedTrustTask<ClaimFinishResponse>(
        TRUST_TASK_FINISH,
        {
          installToken: token,
          registrationId: startBody.registrationId,
          webauthnResponse: serializeRegistration(credential),
        },
        ANONYMOUS_ISSUER,
      );
    } catch (err) {
      const e = err as ApiError;
      setPhase({
        kind: "error",
        title: `Install ceremony failed (${e.code ?? e.status})`,
        message: e.message || "The daemon rejected the WebAuthn response.",
        hint:
          e.code === "vtc/install/claim/finish:invalidToken"
            ? "The install token may have expired between start and finish — ask the operator for a fresh URL."
            : "Check the daemon logs for the rejection reason.",
      });
      return;
    }

    // ── admin/bootstrap ──
    // This is the ONLY place the first admin's ACL entry (VtcAclEntry) is
    // written, so without it passkey login fails with "DID not in ACL".
    // Drive it here so the install link fully sets up the admin in one go.
    // `alreadyBootstrapped` = an admin already exists — i.e. this is an
    // *invited* admin whose ACL was already granted by `vtc admin invite`,
    // or a re-claim — which is fine: the passkey is registered and the DID
    // is already authorised.
    try {
      await postUnsignedTrustTask<BootstrapResponse>(
        TRUST_TASK_BOOTSTRAP,
        // Passed straight through. `claim/finish` returns `setupSessionToken`
        // and `admin/bootstrap` accepts that same name.
        { setupSessionToken: finishBody.setupSessionToken },
        ANONYMOUS_ISSUER,
      );
    } catch (err) {
      const e = err as ApiError;
      if (e.code !== "vtc/admin/bootstrap:alreadyBootstrapped") {
        setPhase({
          kind: "error",
          title: `Admin bootstrap failed (${e.code ?? e.status})`,
          message:
            e.message ||
            "Your passkey registered, but finalising admin access failed.",
          hint: "Check the daemon logs, then re-open the install URL to retry.",
        });
        return;
      }
    }

    setPhase({
      kind: "success",
      adminDid: finishBody.adminDid,
      setupSessionToken: finishBody.setupSessionToken,
    });
  };

  const onSubmitCode = (e: React.FormEvent) => {
    e.preventDefault();
    void runCeremony(claimCode);
  };

  return (
    <section className="page install-page">
      <h2>Claim Admin Passkey</h2>
      <p className="lead">
        One-shot install ceremony for the first administrator of this
        Verifiable Trust Community.
      </p>

      {phase.kind === "awaiting-code" && (
        <section className="card">
          <h3>Enter your claim code</h3>
          <p>
            The operator who sent you this URL also sent a short
            claim code through a separate channel (Signal, SMS, in
            person). Type the code below to start the passkey
            ceremony — the URL alone is not enough to claim the
            invite.
          </p>
          <form onSubmit={onSubmitCode} className="form-stack">
            <label className="field">
              <span className="field-label">Claim code</span>
              <input
                type="text"
                inputMode="text"
                autoComplete="off"
                spellCheck={false}
                placeholder="e.g. ABCDEFGHJK"
                value={claimCode}
                onChange={(e) => setClaimCode(e.target.value.toUpperCase())}
                required
                autoFocus
              />
            </label>
            <div className="form-actions">
              <button type="submit" className="primary">
                Continue
              </button>
            </div>
          </form>
        </section>
      )}

      {phase.kind === "registering" && (
        <section className="card">
          <h3>Registering passkey…</h3>
          <p>
            Follow your browser's prompts to register a passkey for
            this server. The admin DID is decided server-side from
            the install token, so any passkey algorithm your
            authenticator offers (ES256, RS256, EdDSA) is fine.
          </p>
        </section>
      )}

      {phase.kind === "success" && (
        <section className="card">
          <h3>Admin set up ✅</h3>
          <dl>
            <dt>Admin DID</dt>
            <dd>
              <code>{phase.adminDid}</code>
            </dd>
          </dl>
          <p>
            Your passkey is registered and this DID is now an admin. Open the
            VTC admin UI and sign in with your passkey.
          </p>
          <details>
            <summary>Setup-session token (advanced / CNM CLI)</summary>
            <pre>{phase.setupSessionToken}</pre>
          </details>
        </section>
      )}

      {phase.kind === "error" && (
        <section className="card error">
          <h3>{phase.title}</h3>
          <p>{phase.message}</p>
          {phase.hint && <p className="lead">{phase.hint}</p>}
          {token &&
            (phase.title === "Claim code required" ||
              phase.title === "Wrong claim code") && (
              <div className="form-actions">
                <button
                  type="button"
                  className="primary"
                  onClick={() => {
                    setClaimCode("");
                    setPhase({ kind: "awaiting-code" });
                  }}
                >
                  Try again
                </button>
              </div>
            )}
        </section>
      )}

      <footer>
        <p className="lead">
          The install URL is single-use and expires after 15 minutes.
          If yours has expired, the daemon operator can mint a fresh
          one via <code>vtc admin invite --did &lt;admin-did&gt;</code>.
        </p>
      </footer>
    </section>
  );
}

