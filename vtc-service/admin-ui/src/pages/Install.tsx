// `/admin/install?token=<jwt>` — the install claim, for the first
// administrator of a community or one invited to administer it.
//
// Distinct from a plugin: the install URL is the public entry point for an
// unauthenticated operator, so it lives outside the plugin routing tree.
// Reads `?token=` from the URL and runs one of two ceremonies, chosen by the
// token itself:
//
// - **A passkey invitation** (the token names no DID): the passkey install,
//   `vtc/install/claim/passkey/{start,finish}/0.1`. `start` answers WebAuthn
//   creation options (EdDSA or ES256 only) and `assertionOptions`, a second
//   challenge; the page creates the passkey, then signs one assertion with it
//   over that challenge — the proof the installer holds it — and `finish`
//   answers the administrator's DID, the `did:key` of the passkey's own key.
//   Each verb's own bearer artifact (the install JWT, the `registrationId`,
//   the setup-session JWT) is the credential, so the documents are unsigned
//   (`postUnsignedTrustTask`).
// - **A wallet invitation** (the token names a DID): a founder or invitee who
//   holds that DID in a VTA wallet claims with **0.3**: `claim/start/0.3`
//   (unsigned — the token and the claim code are the gate) answers the DID
//   and a challenge; the plugin's approver signs its enrolment statement over
//   that challenge, bound to the `claimId`; and `claim/finish/0.3` is signed
//   by the wallet **as that DID**, carrying the statement.
//
// Both answer `{adminDid, setupSessionToken}`, and `vtc/admin/bootstrap/0.1`
// follows: on a fresh community it writes the first administrator (and binds
// a 0.3 founder's approver); on one that already has an administrator it
// answers `alreadyBootstrapped`, which is fine — a passkey invitation's entry
// was written by `finish`, a wallet invitation's by the invite.

import { useEffect, useState } from "react";
import { useSearchParams } from "react-router-dom";

import {
  addressedDocument,
  postSignedDocument,
  postUnsignedTrustTask,
  type ApiError,
} from "@/lib/api";
import type { SignedTrustTaskDocument } from "@/lib/console-key";
import {
  attestApproverWithWallet,
  isWalletApproverEnrolmentAvailable,
  signWithWallet,
} from "@/lib/wallet";
import {
  base64urlToBuffer,
  decodePublicKeyOptions,
  serializeAssertion,
  serializeRegistration,
  type JsonPublicKeyOptions,
} from "@/lib/webauthn";
import { Field } from "@/components/Field";

export const TRUST_TASK_START =
  "https://trusttasks.org/spec/vtc/install/claim/passkey/start/0.1";
export const TRUST_TASK_FINISH =
  "https://trusttasks.org/spec/vtc/install/claim/passkey/finish/0.1";
export const TRUST_TASK_START_V0_3 =
  "https://trusttasks.org/spec/vtc/install/claim/start/0.3";
export const TRUST_TASK_FINISH_V0_3 =
  "https://trusttasks.org/spec/vtc/install/claim/finish/0.3";
export const TRUST_TASK_BOOTSTRAP =
  "https://trusttasks.org/spec/vtc/admin/bootstrap/0.1";

// No browser identity signs these documents — the administrator's DID is the
// passkey's (derived server-side from the registered key) or the wallet's,
// never a console key this browser holds. The framework binds a document's `issuer` to its proof
// only when one is present (SPEC §7.2 item 7); none of these three documents
// carries one, so this placeholder claims nothing and is never checked.
const ANONYMOUS_ISSUER = "did:key:z6MkVtcInstallAnonymous";

type Via = "passkey" | "wallet";

type Phase =
  | { kind: "awaiting-code" }
  | { kind: "registering"; via: Via }
  | { kind: "success"; via: Via; adminDid: string; setupSessionToken: string }
  | { kind: "error"; title: string; message: string; hint?: string };

/** `vtc/install/claim/passkey/start/0.1#response`. */
interface ClaimStartResponse {
  registrationId: string;
  options: { publicKey: JsonPublicKeyOptions };
  assertionOptions: { publicKey: JsonPublicKeyOptions };
}

/**
 * Which ceremony the install token is for: a wallet invitation names the DID
 * it is for (`admin_did`), a passkey invitation names none. `undefined` when
 * the token cannot be read here — then both are offered and the daemon
 * refuses the wrong one.
 */
export function invitationKind(token: string): Via | undefined {
  const part = token.split(".")[1];
  if (!part) return undefined;
  try {
    const claims = JSON.parse(new TextDecoder().decode(base64urlToBuffer(part))) as {
      admin_did?: unknown;
    };
    if (typeof claims !== "object" || claims === null) return undefined;
    return typeof claims.admin_did === "string" && claims.admin_did !== ""
      ? "wallet"
      : "passkey";
  } catch {
    return undefined;
  }
}

/** What to tell an installer whose passkey claim was refused. */
function passkeyFinishError(e: ApiError): { title: string; message: string; hint?: string } {
  switch (e.code) {
    case "vtc/install/claim/passkey/finish:possessionUnproven":
      return {
        title: "Your passkey did not prove itself",
        message:
          "The community needs one signature by the passkey you just created, over its challenge, before it makes you an administrator. That signature did not verify, so nothing was claimed.",
        hint: "Re-open the install URL and try again, using the same passkey for both prompts.",
      };
    case "vtc/install/claim/passkey/finish:unsupportedAlgorithm":
      return {
        title: "This passkey cannot name an administrator",
        message:
          "Your administrator DID is your passkey's own key, which must be Ed25519 or P-256. Your authenticator created another kind.",
        hint: "Re-open the install URL and use a different authenticator (a platform passkey or a security key).",
      };
    case "vtc/install/claim/passkey/finish:invalidToken":
      return {
        title: "Install URL expired or already used",
        message: e.message || "The install token expired between start and finish, or was used.",
        hint: "Ask the operator for a fresh URL and claim code.",
      };
    case "vtc/install/claim/passkey/finish:bindingInvalid":
    case "vtc/install/claim/passkey/finish:registrationMismatch":
      return {
        title: "The passkey registration was refused",
        message: e.message || "The daemon rejected the WebAuthn registration.",
        hint: "Re-open the install URL and try again.",
      };
    default:
      return {
        title: `Install ceremony failed (${e.code ?? e.status ?? "error"})`,
        message: e.message || "The daemon rejected the claim.",
        hint: "Check the daemon logs for the rejection reason.",
      };
  }
}

/** `vtc/install/claim/start/0.3#response`. */
interface ClaimStartV03Response {
  claimId: string;
  adminDid: string;
  challenge: string;
  audience: string;
  expiresAt: string;
}

/** What to tell a founder whose 0.3 claim was refused. */
function walletClaimError(e: ApiError): { title: string; message: string; hint?: string } {
  switch (e.code) {
    case "vtc/install/claim/start:invalidToken":
      // One code for every start failure, so it is no oracle for which half
      // was wrong.
      return {
        title: "This install URL and claim code do not open a claim",
        message:
          "The claim code may be wrong, or the install URL expired or was already used. Five wrong codes void the URL.",
        hint: "Check the code, or ask the operator for a fresh URL and code.",
      };
    case "vtc/install/claim/start:tokenNamesNoDid":
      return {
        title: "This install URL is for a passkey claim",
        message:
          "The install token names no administrator DID, so it cannot be claimed with a wallet: your administrator DID will be your passkey's own key.",
        hint: "Re-open the URL and register a passkey instead.",
      };
    case "vtc/install/claim/finish:subjectMismatch":
      return {
        title: "Signed as the wrong identity",
        message:
          "The claim must be signed by the DID the install token names, with a key of its own DID document.",
        hint: "Choose that persona in your VTA wallet and try again.",
      };
    case "vtc/install/claim/finish:didUnresolvable":
      return {
        title: "Your DID could not be resolved",
        message: "The VTC could not resolve the DID the install token names to check the signature.",
        hint: "Make sure the DID is published, then try again.",
      };
    case "vtc/install/claim/finish:statementInvalid":
      return {
        title: "The approver's statement was refused",
        message: "Your wallet's step-up approver did not prove possession of its key for this claim.",
        hint: "Start again from the install URL.",
      };
    case "vtc/install/claim/finish:approverNotDistinct":
      return {
        title: "The approver is not a separate key",
        message:
          "A step-up approver must be a key the founder does not already sign with, and not one already bound here.",
      };
    case "vtc/install/claim/finish:registrationMismatch":
    case "vtc/install/claim/finish:invalidToken":
      return {
        title: "The claim lapsed",
        message: "The claim is no longer open, or the install token expired or was used.",
        hint: "Start again from the install URL, or ask the operator for a fresh one.",
      };
    default:
      return {
        title: `Install ceremony failed (${e.code ?? e.status ?? "error"})`,
        message: e.message || String(e),
      };
  }
}

interface ClaimFinishResponse {
  adminDid: string;
  setupSessionToken: string;
}

interface BootstrapResponse {
  adminDid: string;
  eventId: string;
}

/** How long the page waits for the wallet's provider before saying it has none. */
export const WALLET_PROBE_MS = 3000;
const WALLET_PROBE_INTERVAL_MS = 100;

/**
 * Whether the wallet can enrol its approver here, re-read until it can. The
 * extension's content script adds its page-world provider as a module
 * `<script>`, which may run after this page first renders, so a single read at
 * mount says "no wallet" in a browser that has one. Probes for
 * `WALLET_PROBE_MS`, and again on the wallet's own lifecycle events.
 */
function useWalletApproverEnrolment(): boolean {
  const [ready, setReady] = useState(isWalletApproverEnrolmentAvailable);
  useEffect(() => {
    if (ready) return;
    const check = () => {
      if (isWalletApproverEnrolmentAvailable()) setReady(true);
    };
    const timer = window.setInterval(check, WALLET_PROBE_INTERVAL_MS);
    const stop = window.setTimeout(() => window.clearInterval(timer), WALLET_PROBE_MS);
    window.addEventListener("vtawallet:ready", check);
    window.addEventListener("vtawallet:unlocked", check);
    return () => {
      window.clearInterval(timer);
      window.clearTimeout(stop);
      window.removeEventListener("vtawallet:ready", check);
      window.removeEventListener("vtawallet:unlocked", check);
    };
  }, [ready]);
  return ready;
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
  const walletReady = useWalletApproverEnrolment();
  // A passkey invitation can only be claimed with a passkey; a wallet one
  // only by the wallet holding the DID it names.
  const kind = token ? invitationKind(token) : undefined;
  const offerWallet = walletReady && kind !== "passkey";
  const offerPasskey = kind !== "wallet";

  // ── admin/bootstrap ──
  // This is the ONLY place the first admin's ACL entry (VtcAclEntry) is
  // written, so without it login fails with "DID not in ACL". Drive it here so
  // the install link fully sets up the admin in one go — and, after a 0.3
  // claim, it is also what binds the founder's step-up approver.
  // `alreadyBootstrapped` = an admin already exists — i.e. this is an
  // invitation, whose entry the passkey `finish` (or, for a wallet
  // invitation, the invite) already wrote — which is fine.
  const bootstrapAndFinish = async (finishBody: ClaimFinishResponse, via: Via) => {
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
            (via === "wallet"
              ? "Your claim was accepted, but finalising admin access failed."
              : "Your passkey registered, but finalising admin access failed."),
          hint: "Check the daemon logs, then re-open the install URL to retry.",
        });
        return;
      }
    }

    setPhase({
      kind: "success",
      via,
      adminDid: finishBody.adminDid,
      setupSessionToken: finishBody.setupSessionToken,
    });
  };

  // ── claim 0.3: a founder who already holds a DID in a VTA wallet ──
  const runWalletClaim = async (code: string) => {
    if (!token) return;
    setPhase({ kind: "registering", via: "wallet" });
    let finishBody: ClaimFinishResponse;
    try {
      const started = await postUnsignedTrustTask<ClaimStartV03Response>(
        TRUST_TASK_START_V0_3,
        { token, claimCode: code.trim() },
        ANONYMOUS_ISSUER,
      );
      // The approver proves possession over the claim's challenge, bound to
      // its id, for the DID the token names (never one the browser chose).
      const { statement, approverDid } = await attestApproverWithWallet({
        purpose: "enrol",
        subject: started.adminDid,
        audience: started.audience,
        challenge: started.challenge,
        boundTo: started.claimId,
      });
      const envelope = await addressedDocument(
        TRUST_TASK_FINISH_V0_3,
        { claimId: started.claimId, approverDid, statement },
        started.adminDid,
      );
      const signed = await signWithWallet({ ...envelope }, started.adminDid);
      finishBody = await postSignedDocument<ClaimFinishResponse>(
        signed as unknown as SignedTrustTaskDocument,
      );
    } catch (err) {
      const e = err as ApiError;
      if (typeof e?.code === "string") {
        setPhase({ kind: "error", ...walletClaimError(e) });
      } else {
        setPhase({
          kind: "error",
          title: "The wallet claim did not complete",
          message: (err as Error | null)?.message || String(err),
          hint: "Approve both wallet prompts — the approver's statement and the claim signed as your DID — then retry the install URL.",
        });
      }
      return;
    }
    await bootstrapAndFinish(finishBody, "wallet");
  };

  const runCeremony = async (code: string) => {
    if (!token) return;
    setPhase({ kind: "registering", via: "passkey" });

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
      // `vtc/install/claim/passkey/start:invalidToken` covers a missing/wrong claim
      // code as well as an expired or already-claimed token — the published
      // spec declares one code for the whole family (unlike the retired
      // bearer route's bespoke 401 variants), distinguished only by the
      // message this daemon still stamps with a `claim_secret_*` prefix.
      if (e.code === "vtc/install/claim/passkey/start:invalidToken") {
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

    // ── prove possession: one assertion by the new passkey ──
    // Over start's second challenge, naming only the credential just created
    // (`assertionOptions` carries no `allowCredentials`: it did not exist).
    let assertion: PublicKeyCredential | null = null;
    try {
      const request = decodePublicKeyOptions(
        startBody.assertionOptions.publicKey,
      ) as PublicKeyCredentialRequestOptions;
      assertion = (await navigator.credentials.get({
        publicKey: {
          ...request,
          allowCredentials: [{ type: "public-key", id: credential.rawId }],
        },
      })) as PublicKeyCredential | null;
    } catch (err) {
      const e = err as Error;
      setPhase({
        kind: "error",
        title: "Passkey confirmation cancelled or failed",
        message: e.message || String(err),
        hint: "Your passkey must sign once to prove you hold it. Re-open the install URL and try again.",
      });
      return;
    }
    if (!assertion) {
      setPhase({
        kind: "error",
        title: "Passkey confirmation returned nothing",
        message: "Your browser dismissed the confirmation without a signature.",
        hint: "Re-open the install URL and try again.",
      });
      return;
    }

    // ── claim/passkey/finish ──
    let finishBody: ClaimFinishResponse;
    try {
      finishBody = await postUnsignedTrustTask<ClaimFinishResponse>(
        TRUST_TASK_FINISH,
        {
          installToken: token,
          registrationId: startBody.registrationId,
          webauthnResponse: serializeRegistration(credential),
          webauthnAssertion: serializeAssertion(assertion),
        },
        ANONYMOUS_ISSUER,
      );
    } catch (err) {
      setPhase({ kind: "error", ...passkeyFinishError(err as ApiError) });
      return;
    }

    await bootstrapAndFinish(finishBody, "passkey");
  };

  const onSubmitCode = (e: React.FormEvent) => {
    e.preventDefault();
    if (offerPasskey) void runCeremony(claimCode);
    else if (offerWallet) void runWalletClaim(claimCode);
  };

  return (
    <section className="page install-page">
      <h2>Claim administrator access</h2>
      <p className="lead">
        One-shot install ceremony for an administrator of this Verifiable
        Trust Community.
      </p>

      {phase.kind === "awaiting-code" && (
        <section className="card">
          <h3>Enter your claim code</h3>
          <p>
            The operator who sent you this URL also sent a short
            claim code through a separate channel (Signal, SMS, in
            person). Type the code below to claim the invite — the
            URL alone is not enough.
          </p>
          <form onSubmit={onSubmitCode} className="form-stack">
            <Field label="Claim code">
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
            </Field>
            {kind === "passkey" && (
              <p className="muted">
                You will register a passkey. Your administrator DID is your passkey's own key,
                so it needs no wallet.
              </p>
            )}
            {kind === "wallet" && !walletReady && (
              <p className="muted">
                This invitation is for a DID held in a VTA wallet: claim it with the browser
                plugin holding that DID, which signs the claim as it. This page cannot see the
                plugin: install it and make sure it has access to this site, then reload this
                page.
              </p>
            )}
            {kind === undefined && walletReady && (
              <p className="muted">
                If the operator invited a DID you already hold in your VTA wallet, claim with
                the wallet: it signs the claim as that DID and enrols your wallet's step-up
                approver. Otherwise register a passkey.
              </p>
            )}
            <div className="form-actions">
              {offerWallet && (
                <button
                  type="button"
                  className="primary"
                  disabled={claimCode.trim() === ""}
                  onClick={() => void runWalletClaim(claimCode)}
                >
                  Claim with my VTA wallet
                </button>
              )}
              {offerPasskey && (
                <button type="submit" className={offerWallet ? "secondary" : "primary"}>
                  {offerWallet ? "Register a passkey instead" : "Continue"}
                </button>
              )}
            </div>
          </form>
        </section>
      )}

      {phase.kind === "registering" && phase.via === "wallet" && (
        <section className="card">
          <h3>Waiting for your wallet…</h3>
          <p>
            Your VTA wallet asks you twice: to unlock your step-up approver so it can prove it
            holds its key, and to sign the claim as your DID.
          </p>
        </section>
      )}

      {phase.kind === "registering" && phase.via === "passkey" && (
        <section className="card">
          <h3>Registering passkey…</h3>
          <p>
            Follow your browser's prompts twice: once to create a passkey
            for this community, then once to sign with it, proving you
            hold it. Your administrator DID is the passkey's own key, so
            the passkey must be Ed25519 or P-256 — what platform passkeys
            and security keys create.
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
          {phase.via === "wallet" ? (
            <p>
              This DID is now an admin, and your wallet's step-up approver is bound to it.
              Open the VTC admin UI and sign in with your VTA wallet.
            </p>
          ) : (
            <p>
              Your passkey is registered, and this DID — your passkey's own key — is
              now an admin. Open the VTC admin UI and sign in with your passkey.
            </p>
          )}
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
              phase.title === "Wrong claim code" ||
              phase.title === "This install URL and claim code do not open a claim") && (
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
          one via <code>vtc admin invite</code> (a passkey invitation) or
          <code>vtc admin invite --did &lt;did&gt;</code> (a wallet one).
        </p>
      </footer>
    </section>
  );
}

