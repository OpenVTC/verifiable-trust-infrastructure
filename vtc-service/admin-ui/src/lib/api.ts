// Tiny fetch wrapper for the daemon's JSON endpoints.
//
// Every call sends credentials so the `vtc_admin_session` cookie
// rides along. Mutating requests (POST/PUT/DELETE/PATCH) mirror the
// `csrf` cookie's value into the `X-CSRF-Token` header for the
// double-submit check in `routing::csrf`.
//
// It also keeps the session alive: `request` renews the cookie before a
// call when the access token is nearly out, so an operator who is using
// the console is not signed out mid-task. See `lib/session.ts`.

import { renewIfNeeded, resetSession, setSessionExpiry } from "@/lib/session";

// `GET /health` is unauth and deliberately minimal: it carries only
// `{status, version, vtc_did}`. The `vta_did` / `mediator_url` /
// `mediator_did` infrastructure detail moved to the admin-gated
// `/v1/health/diagnostics` (P3.7) so it isn't a free unauth recon
// oracle — read those from `DiagnosticsResponse` instead.
export interface HealthResponse {
  status: string;
  version: string;
  vtc_did?: string;
}

// `GET /v1/health/diagnostics` — admin-gated. Surfaces the trust-registry
// reconciler state plus the identity/mediator detail that used to live on
// `/health` (P3.7).
//
// These three shapes used to be declared here by hand, beside the fetch, in
// exactly the way #1186 taught us not to: `wire-types.ts` had already aliased
// the generated schemas, nothing imported them, and the hand-written copies
// won at the call site. They had drifted before anyone read them — the daemon
// serialises `messagingStatus` and `transports` unconditionally, the local
// copy called both optional — and `tsc` could not notice, because the local
// interface *is* what it checks the console against. Re-export the generated
// aliases instead, so a response change fails to compile rather than arriving
// as `undefined`.
import type {
  ConfigPatchResponse,
  EffectiveConfig,
  DiagnosticsResponse,
  RegistryRecordsResponse,
  SyncJobsDiscardResponse,
  SyncJobsListResponse,
  SyncJobsRetryResponse,
} from "./wire-types";

export type {
  DiagnosticsExt,
  DiagnosticsResponse,
  DriftEntry,
  DriftSnapshot,
  FailedSyncJob,
  RegistryRecordRow,
  RegistryRecordsResponse,
  SyncJobRow,
  SyncJobsDiscardResponse,
  SyncJobsListResponse,
  SyncJobsRetryResponse,
  RegistryTransport,
  TransportFinding,
  TransportFindingCode,
  TransportStatus,
} from "./wire-types";

export interface BuildInfo {
  version: string;
  mode: string;
  indexSha256: string;
}

export interface ApiError {
  status: number;
  /** Daemon-formatted error message when the body is JSON. */
  message: string;
  /** A signed Trust Task's refusal code (`permissionDenied`,
   *  `git-ns:selfGrantNotAllowed`, …), where the answer was a
   *  `trust-task-error` document. */
  code?: string;
  /** That refusal's `details` — where an operation-bound step-up puts its
   *  ceremony (`details.stepUpRequest`). */
  details?: Record<string, unknown>;
  /** The signed document that was refused — so a refusal that asks for an
   *  operation-bound step-up can be answered and the *same* document sent
   *  again (`postSignedDocument`). */
  document?: SignedTrustTaskDocument;
}

/**
 * The daemon's own error message for a failed response, falling back to the
 * status line when the body isn't the JSON error shape.
 *
 * `vti_common::error::AppError` serialises as `{ "error": "<display>" }` for
 * every variant bar the Trust-Task ones, which carry `message`. Reading it
 * matters most where the status code alone is ambiguous: `/auth/challenge`
 * answers 403 for "DID not in ACL", "ACL entry expired" and "DID is not
 * permitted to authenticate on this VTC" alike, and only the body says which.
 *
 * Consumes the response body, so call it at most once per response.
 */
export async function daemonErrorMessage(
  res: Response,
  fallback: string = `${res.status} ${res.statusText}`,
): Promise<string> {
  try {
    const body = (await res.json()) as { error?: string; message?: string };
    return body.error || body.message || fallback;
  } catch {
    /* non-JSON body */
    return fallback;
  }
}

function csrfTokenFromCookie(): string | null {
  // The CSRF cookie is set by login (`/v1/auth/passkey-login/finish`
  // or `/v1/auth/admin-session`). HttpOnly is **not** set on this
  // cookie precisely so JS can read it.
  const match = document.cookie.match(/(?:^|;\s*)csrf=([^;]+)/);
  return match?.[1] ?? null;
}

const REFRESH_TASK = "https://trusttasks.org/spec/auth/refresh/0.1";

/**
 * The renewal call itself, kept out of `request` so it cannot recurse
 * through the pre-flight renewal check.
 *
 * Posts an empty body: the browser presents `vtc_admin_refresh`, and the
 * daemon's cookie path reads the token from there. The csrf header is
 * still required — the endpoint stopped being CSRF-exempt the moment a
 * cookie alone could authenticate it.
 *
 * Returns the new expiry, or `null` when the daemon refused (an idled-out
 * session, a rotated-away token, a revoked ACL entry).
 */
async function renewSession(): Promise<number | null> {
  const headers = new Headers({ "Trust-Task": REFRESH_TASK });
  const csrf = csrfTokenFromCookie();
  if (csrf) headers.set("X-CSRF-Token", csrf);
  const res = await fetch("/v1/auth/refresh", {
    method: "POST",
    credentials: "include",
    headers,
  });
  if (!res.ok) return null;
  const body = (await res.json()) as { session?: { expiresAt?: string } };
  const expiresAt = body.session?.expiresAt;
  return expiresAt ? Math.floor(new Date(expiresAt).getTime() / 1000) : null;
}

async function request<T>(
  path: string,
  init: RequestInit = {},
  requires?: string[],
): Promise<T> {
  // Renew first if the token is nearly out. A no-op unless we know the
  // expiry (i.e. unless `whoami` has run), so the login ceremony's own
  // unauthenticated calls are untouched.
  if (path !== "/v1/auth/refresh") {
    await renewIfNeeded(renewSession);
  }
  const method = (init.method ?? "GET").toUpperCase();
  const headers = new Headers(init.headers);
  if (method !== "GET" && method !== "HEAD") {
    const csrf = csrfTokenFromCookie();
    if (csrf) headers.set("X-CSRF-Token", csrf);
  }
  if (init.body && !headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json");
  }

  const res = await fetch(path, {
    ...init,
    method,
    credentials: "include",
    headers,
  });

  if (!res.ok) {
    const message = await daemonErrorMessage(res);
    // 401/403 on a request issued *while authenticated* means the
    // session has expired (cookie cleared server-side, JWT past
    // `exp`, or admin role revoked). Dispatch a window event so the
    // shell can re-probe whoami and flip to Login — but only when a
    // session was actually present. The Login page itself triggers
    // 401s during its own ceremony; the listener filters those out
    // by checking the current whoami cache.
    if (res.status === 401 || res.status === 403) {
      try {
        window.dispatchEvent(
          new CustomEvent("vtc-session-expired", {
            detail: { path, status: res.status },
          }),
        );
      } catch {
        /* event dispatch never fails in browsers; the guard keeps
         * SSR / non-DOM callers safe. */
      }
    }
    const err: ApiError = { status: res.status, message };
    throw err;
  }

  if (res.status === 204) {
    return undefined as T;
  }
  const body = (await res.json()) as T;
  assertShape(path, body, requires);
  return body;
}

/**
 * Fail loudly, and where the cause is, when a response is missing something
 * the caller is about to read.
 *
 * The console and the daemon ship as **one artefact** — `build.rs` bakes this
 * bundle into the binary — so a missing member is never a version negotiation
 * that failed. It means the two halves were built from sources that disagreed,
 * or that something between the browser and the daemon is serving a stale
 * bundle. Either way it is a deployment fact, and saying so is more use to an
 * operator than the value they would otherwise get, which is `undefined`.
 *
 * Why this exists at all: the generated wire types (`wire.ts`) make this class
 * of mismatch a compile error, so in a correctly-built console these checks can
 * never fire. They are here for the console that was *not* correctly built —
 * the one an operator is actually looking at when something has gone wrong. The
 * cost of being wrong in that moment was measured: a passkey sign-in against a
 * daemon newer than the bundle threw `Cannot read properties of undefined
 * (reading 'challenge')` from inside a WebAuthn helper, three frames below the
 * response that was actually at fault, with no passkey prompt and nothing on
 * screen naming the endpoint, the field, or the daemon.
 */
function assertShape(path: string, body: unknown, requires?: string[]): void {
  if (!requires?.length) return;
  const missing = requires.filter((p) => !hasPath(body, p));
  if (missing.length === 0) return;

  const present =
    body && typeof body === "object" ? Object.keys(body).join(", ") : typeof body;
  const err: ApiError = {
    status: 200,
    message:
      `${path} answered without ${missing.map((m) => `\`${m}\``).join(", ")}. ` +
      `It sent: ${present || "(nothing)"}. This console is built into the ` +
      `daemon binary, so the two cannot disagree unless the bundle being ` +
      `served is not the one this daemon was built with. Two things do that: ` +
      `a browser holding a cached copy — hard-reload with Cmd/Ctrl-Shift-R — ` +
      `or a daemon built with VTC_SKIP_ADMIN_UI_BUILD=1 over a stale ` +
      `admin-ui/dist/, which embeds it as-is. Compare /admin/build-info with ` +
      `the daemon's source tree to tell which.`,
  };
  throw err;
}

/** Is `path` (dotted) present and not null/undefined on `value`? */
function hasPath(value: unknown, path: string): boolean {
  let at: unknown = value;
  for (const key of path.split(".")) {
    if (at === null || at === undefined || typeof at !== "object") return false;
    at = (at as Record<string, unknown>)[key];
  }
  return at !== undefined && at !== null;
}

// Every `/v1/*` route is gated by `TrustTaskRouter::
// route_with_task(path, handler, trust_task)`, which requires an
// exact-match `Trust-Task` header. Forgetting it means a runtime
// `TrustTaskMissing` rejection, not a compile error — a regression
// class we hit once already. Making `trustTask` a required field
// here forces every caller to pick the right task URL up front;
// endpoints that genuinely don't need one (the daemon's
// Trust-Task-exempt routes — `/health`, `/admin/*`) use the
// `*Exempt` variants below.

export interface TrustTaskOpts {
  trustTask: string;
  /**
   * Dotted paths this caller is about to read, checked against the response
   * before it is handed back. See [`assertShape`] for why — briefly: the
   * generated wire types make a mismatch a compile error, so these only fire
   * on a console that was not built with the daemon serving it, which is
   * precisely when a legible error is worth the most.
   *
   * Worth declaring on any call whose failure the operator would otherwise
   * meet as `undefined` several frames away — the sign-in ceremony above all,
   * where there is no other screen to fall back to.
   */
  requires?: string[];
}

export const getJson = <T>(
  path: string,
  extra: TrustTaskOpts,
): Promise<T> =>
  request<T>(path, {
    method: "GET",
    headers: { "Trust-Task": extra.trustTask },
  }, extra.requires);

export const postJson = <T>(
  path: string,
  body: unknown,
  extra: TrustTaskOpts,
): Promise<T> =>
  request<T>(path, {
    method: "POST",
    body: body === undefined ? undefined : JSON.stringify(body),
    headers: { "Trust-Task": extra.trustTask },
  }, extra.requires);

export const putJson = <T>(
  path: string,
  body: unknown,
  extra: TrustTaskOpts,
): Promise<T> =>
  request<T>(path, {
    method: "PUT",
    body: body === undefined ? undefined : JSON.stringify(body),
    headers: { "Trust-Task": extra.trustTask },
  }, extra.requires);

export const patchJson = <T>(
  path: string,
  body: unknown,
  extra: TrustTaskOpts,
): Promise<T> =>
  request<T>(path, {
    method: "PATCH",
    body: body === undefined ? undefined : JSON.stringify(body),
    headers: { "Trust-Task": extra.trustTask },
  }, extra.requires);

export const deleteJson = <T>(
  path: string,
  extra: TrustTaskOpts & { body?: unknown },
): Promise<T> =>
  request<T>(path, {
    method: "DELETE",
    body: extra.body === undefined ? undefined : JSON.stringify(extra.body),
    headers: { "Trust-Task": extra.trustTask },
  }, extra.requires);

// ---------------------------------------------------------------------------
// The signed door — `POST /v1/trust-tasks`
// ---------------------------------------------------------------------------
//
// One seam, deliberately. `pnm-browser-plugin` puts signing in the channel
// rather than at ~116 call sites, and the same reasoning applies here: a
// plugin that built and signed its own document would be a second definition
// of what a Trust Task document is, and the first one to drift verifies
// nowhere.
//
// What arrives here is a task URI and a payload. What goes on the wire is a
// `trust_tasks_rs::TrustTask` document — `{id, type, issuer, recipient,
// issuedAt, payload, proof}` — issued by *this browser's* console `did:key`,
// addressed to the VTC's own DID, and carrying an `eddsa-jcs-2022` proof. The
// daemon verifies the proof against the document's own `issuer` (SPEC §4.7),
// bounds `issuedAt` (10 minutes, VTI-OPS-024), checks the `recipient` binding
// and records the `id` against replay; the verb handler then reads the
// **signer's** authority — for a console key, the delegating admin's ACL row,
// resolved at execution time (#1692).
//
// Three things this path deliberately does not do:
//
//  - **No bearer token.** The route reads none. The session cookie rides along
//    because `credentials: "include"` is how this console talks to the daemon,
//    and the CSRF header goes with it because the route sits behind the same
//    middleware, but neither is what authorises the call.
//  - **No `vtc-session-expired` event.** The generic `request` helper fires one
//    on any 401/403, which is right for a bearer route and wrong here: the
//    signed door answers 403 for "your delegation was revoked" and for "your
//    admin row no longer permits this", and signing the operator out of a
//    working session because a *document* was refused would be a bug that
//    reads as a flaky console.
//  - **No `Trust-Task` header.** The document's own `type` is the routing key.

import {
  buildTrustTaskDocument,
  ed25519Available,
  loadConsoleKey,
  signTrustTaskDocument,
  type SignedTrustTaskDocument,
  type UnsignedTrustTaskDocument,
} from "./console-key";

/**
 * Thrown when this browser cannot produce a signed document — no WebCrypto
 * Ed25519, or no console key enrolled yet.
 *
 * A distinct type because it is not a failure: every call site catches it and
 * falls back to the bearer route, which is exactly what keeps the console
 * working on a browser that has never enrolled. Anything else thrown by
 * `postSignedTrustTask` is a real error and must not be swallowed.
 */
export class SigningUnavailableError extends Error {
  constructor(readonly reason: "no-ed25519" | "no-key") {
    super(
      reason === "no-ed25519"
        ? "this browser has no WebCrypto Ed25519, so the console cannot sign documents"
        : "no console signing key is enrolled in this browser",
    );
    this.name = "SigningUnavailableError";
  }
}

/** The community DID a signed document must be addressed to. Cached per load. */
let vtcDidPromise: Promise<string> | null = null;

async function communityDid(): Promise<string> {
  if (!vtcDidPromise) {
    const pending = (async () => {
      const health = await fetchHealth();
      if (!health.vtc_did) {
        // A VTC mid-setup has no DID, and `dispatch_trust_task_core` skips the
        // recipient binding in that state — but a document with no `recipient`
        // is refused outright by SPEC §4.8.2 audience binding, so there is
        // nothing to address and nothing to sign.
        throw new Error(
          "this VTC has no DID configured yet, so a signed document has nothing to address",
        );
      }
      return health.vtc_did;
    })();
    // Never cache a rejection. A `/health` that failed once — a reload
    // mid-restart is the ordinary case — would otherwise leave every signed
    // call in this tab failing for the life of the page.
    pending.catch(() => {
      if (vtcDidPromise === pending) vtcDidPromise = null;
    });
    vtcDidPromise = pending;
  }
  return vtcDidPromise;
}

/** Can this browser sign right now? Drives which door a screen offers. */
export async function signingAvailable(): Promise<boolean> {
  if (!(await ed25519Available())) return false;
  return (await loadConsoleKey()) !== null;
}

/**
 * A `trust-task-error` document's payload, as the framework defines it.
 * `code` is the machine-readable one (`permissionDenied`, `taskFailed`,
 * `malformedRequest`, …); `message` is safe to show.
 */
interface TrustTaskErrorPayload {
  code?: string;
  message?: string;
  details?: Record<string, unknown>;
}

/**
 * Send `payload` as a signed Trust Task document and return the `#response`
 * document's payload.
 *
 * Throws [`SigningUnavailableError`] when this browser cannot sign — the
 * caller falls back to the bearer route — and an [`ApiError`] for everything
 * else, so existing error rendering is unchanged.
 */
export async function postSignedTrustTask<T>(
  typeUri: string,
  payload: unknown,
): Promise<T> {
  return postSignedDocument<T>(await signTrustTask(typeUri, payload));
}

/**
 * Build and sign `payload` as a Trust Task document from this browser's
 * console key, without sending it.
 *
 * Split out for the one flow that sends the **same** document twice: an
 * operation-bound step-up (`crate::acl::bound_step_up`) is keyed by a digest
 * of the document's type and payload, and the spine releases a refused
 * document's `id`, so once the passkey gesture is recorded the identical
 * signed document — carried on the refusal as `ApiError.document` — is sent
 * again with [`postSignedDocument`]. Signing a fresh one would still match the
 * digest, but would be a second act the operator never saw.
 */
async function signTrustTask(
  typeUri: string,
  payload: unknown,
): Promise<SignedTrustTaskDocument> {
  if (!(await ed25519Available())) {
    throw new SigningUnavailableError("no-ed25519");
  }
  const key = await loadConsoleKey();
  if (!key) throw new SigningUnavailableError("no-key");

  const recipient = await communityDid();
  const unsigned = buildTrustTaskDocument({
    typeUri,
    payload,
    // The document is issued by the console key's own DID, not the operator's.
    // SPEC §4.7 binds the proof to the in-band `issuer`, so they must be the
    // same DID; the delegation is what connects that DID to the operator's
    // authority, and it is read server-side on every document.
    issuer: key.consoleDid,
    recipient,
  });
  return signTrustTaskDocument(unsigned, key);
}

/**
 * Post an already-signed document to `POST /v1/trust-tasks` and return its
 * `#response` payload. A refusal throws an [`ApiError`] carrying the
 * `trust-task-error`'s `code` and `details`.
 */
export async function postSignedDocument<T>(signed: SignedTrustTaskDocument): Promise<T> {
  return postDocument<T>(signed);
}

/**
 * Post `payload` as an **unsigned** Trust Task document issued as `issuer`.
 *
 * For exactly one case: answering an operation-bound step-up with a passkey
 * (`auth/step-up/approve-response` with `evidence.kind = webauthn`) from a
 * browser that holds no key this community knows — a member who is no console
 * user, answering with a step-up passkey. The WebAuthn assertion is the gate;
 * the VTC reads nothing from the document's issuer (approve-response 0.4 makes
 * the proof optional for webauthn evidence).
 */
export async function postUnsignedTrustTask<T>(
  typeUri: string,
  payload: unknown,
  issuer: string,
): Promise<T> {
  const recipient = await communityDid();
  return postDocument<T>(buildTrustTaskDocument({ typeUri, payload, issuer, recipient }));
}

async function postDocument<T>(
  signed: UnsignedTrustTaskDocument | SignedTrustTaskDocument,
): Promise<T> {
  const headers = new Headers({ "Content-Type": "application/json" });
  const csrf = csrfTokenFromCookie();
  if (csrf) headers.set("X-CSRF-Token", csrf);

  const res = await fetch("/v1/trust-tasks", {
    method: "POST",
    credentials: "include",
    headers,
    body: JSON.stringify(signed),
  });

  const body = (await res.json().catch(() => null)) as {
    payload?: unknown;
  } | null;

  if (!res.ok) {
    const err = (body?.payload ?? {}) as TrustTaskErrorPayload;
    const apiError: ApiError = {
      status: res.status,
      message:
        err.message ??
        err.code ??
        `${res.status} ${res.statusText} from the signed Trust Task endpoint`,
    };
    if (typeof err.code === "string") apiError.code = err.code;
    if (err.details && typeof err.details === "object") apiError.details = err.details;
    // Only a signed document is worth re-sending unchanged.
    if ("proof" in signed) apiError.document = signed as SignedTrustTaskDocument;
    throw apiError;
  }

  if (!body || !("payload" in body)) {
    const apiError: ApiError = {
      status: res.status,
      message:
        "the signed Trust Task endpoint answered without a `payload` — the response was not a Trust Task document",
    };
    throw apiError;
  }
  return body.payload as T;
}

/**
 * Send this as a signed document if the browser can, and over the task's
 * transitional bearer route if it cannot.
 *
 * The fallback catches [`SigningUnavailableError`] and **nothing else**: a
 * browser without WebCrypto Ed25519, or an operator who has not yet enabled
 * signing here, keeps working exactly as before. A signed call that is
 * *refused* — a revoked delegation, an ACL row that no longer permits it —
 * propagates, because silently retrying it over a bearer token would use the
 * session as the authority the signed door exists to stop relying on, and
 * would hide a revocation from the operator who performed it.
 *
 * Both doors run the same inner function server-side (#1681 moved each
 * handler's body into a transport-free inner both call), so they cannot answer
 * differently — but they are not equivalent: the signed door additionally
 * verifies a proof, binds the recipient, bounds the document's age and records
 * its id against replay, and reads authority from the ACL at execution time.
 * The bearer routes stay mounted only until every client can sign; each
 * carries its removal point in its OpenAPI description.
 */
export async function signedOrBearer<T>(
  typeUri: string,
  payload: unknown,
  bearer: () => Promise<T>,
): Promise<T> {
  try {
    return await postSignedTrustTask<T>(typeUri, payload);
  } catch (e) {
    if (e instanceof SigningUnavailableError) return bearer();
    throw e;
  }
}

// ---------------------------------------------------------------------------
// Exempt helpers — for `/health`, `/admin/build-info.json`,
// `/admin/plugins.json`, and any future route that's outside the
// `TrustTaskRouter`. Spelling the carve-out explicitly at the call
// site is the whole point: a `getJsonExempt` in a plugin is a smell.
// ---------------------------------------------------------------------------

export const getJsonExempt = <T>(path: string): Promise<T> =>
  request<T>(path, { method: "GET" });

// The daemon also mounts a handful of admin REST routes with no Trust Task
// binding at all, because no published task describes them: the vetter grant
// listing, automatic vetter grants, vetting withdrawal notices, a join
// request's vetting facts, community branding, and the community schema store
// (`/v1/schemas/*`, which `routes::mod` mounts outside the soft-gate). Sending
// them a task URI would claim a contract that does not exist, so they use these
// helpers too — and the smell is intended: each call site names why its route
// has no task.
export const putJsonExempt = <T>(path: string, body: unknown): Promise<T> =>
  request<T>(path, {
    method: "PUT",
    body: body === undefined ? undefined : JSON.stringify(body),
  });

export const postJsonExempt = <T>(path: string, body: unknown): Promise<T> =>
  request<T>(path, {
    method: "POST",
    body: body === undefined ? undefined : JSON.stringify(body),
  });

export const deleteJsonExempt = <T>(path: string): Promise<T> =>
  request<T>(path, { method: "DELETE" });

// `/health` and `GET /v1/rooms` are the daemon's two Trust-Task-exempt
// endpoints, for unrelated reasons: `/health` predates the router, and the
// rooms listing is the host's own view of what it stores — every `rooms/*`
// task is authorised by a credential the ROOM issued, so naming one here
// would claim a room governs an answer it has no view of.
// `/admin/build-info.json` lives on the admin router (not the
// TrustTaskRouter). All are header-less by design.
export const fetchHealth = (): Promise<HealthResponse> =>
  getJsonExempt<HealthResponse>("/health");

export const fetchBuildInfo = (): Promise<BuildInfo> =>
  getJsonExempt<BuildInfo>("/admin/build-info.json");

const DIAGNOSTICS_TASK =
  "https://trusttasks.org/spec/vtc/registry/diagnostics/0.1";

// Admin-gated identity + reconciler diagnostics. The dashboard reads
// `vta_did` / `mediator_did` from here since P3.7 stripped them off
// the unauth `/health` payload.
export const fetchDiagnostics = (): Promise<DiagnosticsResponse> =>
  getJson<DiagnosticsResponse>("/v1/health/diagnostics", {
    trustTask: DIAGNOSTICS_TASK,
  });

// ── Trust-registry operator surface ─────────────────────────────────────
//
// `vtc/registry/{sync-jobs,records}/…`. The offline `vtc sync-jobs` CLI does
// the same three things against a stopped daemon; these are the online half,
// and they share the daemon's eligibility rule rather than re-deriving it.
const SYNC_JOBS_LIST_TASK =
  "https://trusttasks.org/spec/vtc/registry/sync-jobs/list/0.1";
const SYNC_JOBS_RETRY_TASK =
  "https://trusttasks.org/spec/vtc/registry/sync-jobs/retry/0.1";
const SYNC_JOBS_DISCARD_TASK =
  "https://trusttasks.org/spec/vtc/registry/sync-jobs/discard/0.1";
const REGISTRY_RECORDS_TASK =
  "https://trusttasks.org/spec/vtc/registry/records/list/0.1";

export const fetchSyncJobs = (
  state?: "pending" | "inFlight" | "failed",
): Promise<SyncJobsListResponse> =>
  getJson<SyncJobsListResponse>(
    `/v1/registry/sync-jobs${state ? `?state=${state}` : ""}`,
    { trustTask: SYNC_JOBS_LIST_TASK },
  );

/**
 * Requeue one job, or every failed job.
 *
 * `allFailed` is spelled as its own member rather than an omitted `jobId`,
 * exactly as the specification requires: a bug that dropped the identifier
 * would otherwise turn one operator's retry into a bulk requeue.
 */
export const retrySyncJob = (
  target: { jobId: string } | { allFailed: true },
): Promise<SyncJobsRetryResponse> =>
  postJson<SyncJobsRetryResponse>("/v1/registry/sync-jobs/retry", target, {
    trustTask: SYNC_JOBS_RETRY_TASK,
  });

export const discardSyncJob = (
  jobId: string,
): Promise<SyncJobsDiscardResponse> =>
  postJson<SyncJobsDiscardResponse>(
    "/v1/registry/sync-jobs/discard",
    { jobId },
    { trustTask: SYNC_JOBS_DISCARD_TASK },
  );

export const fetchRegistryRecords = (
  source: "registry" | "local",
): Promise<RegistryRecordsResponse> =>
  getJson<RegistryRecordsResponse>(`/v1/registry/records?source=${source}`, {
    trustTask: REGISTRY_RECORDS_TASK,
  });

/**
 * The canonical `Session` shape, as published by the `auth/whoami/0.1`
 * component. Nested under `session` — #1112 moved the whole payload here
 * from the flat `{did, role, sessionId, accessExpiresAt, allowedContexts}`
 * this console used to read.
 */
export interface SessionView {
  id: string;
  /** The DID this session authenticates — was the top-level `did`. */
  subject: string;
  /** RFC3339. The JWT's `iat`. */
  issuedAt: string;
  /** RFC3339. Was the epoch-seconds `accessExpiresAt`. */
  expiresAt: string;
  /** Authentication methods per RFC 8176. Omitted when the token records none. */
  amr?: string[];
  /** Authentication context class per OIDC Core §2. Omitted when unrecorded. */
  acr?: string;
}

/** Shape returned by `GET /v1/auth/whoami`. */
export interface WhoamiResponse {
  session: SessionView;
  /** The caller's roles. A single role is one entry — was the scalar `role`. */
  roles: string[];
  /** The contexts this session may act in — was `allowedContexts`. */
  scopes: string[];
}

const WHOAMI_TASK = "https://trusttasks.org/spec/auth/whoami/0.1";
const SIGN_OUT_TASK = "https://trusttasks.org/spec/auth/revoke-session/0.1";

/** Fetch the caller's session identity. Throws on 401/403. */
export const fetchWhoami = (): Promise<WhoamiResponse> =>
  getJson<WhoamiResponse>("/v1/auth/whoami", {
    trustTask: WHOAMI_TASK,
    // The shell renders the session badge from this before anything else, so
    // a mismatch here takes the whole console down rather than one view. That
    // is how #1186 was reported: `shortenDid(undefined)`, on load, with the
    // stack in minified bundle frames.
    requires: ["session.subject", "roles", "scopes"],
  });

// ── Runtime config ──────────────────────────────────────────────────────
//
// The console's first client for `/v1/admin/config`. Note the two-step
// Save: PATCH writes the db-layer override but does **not** touch the
// running config, so a Save that stopped there would report success and
// change nothing until the daemon happened to restart. `reload` is what
// folds the overlay onto the live `AppConfig`.

const CONFIG_SHOW_TASK = "https://trusttasks.org/spec/config/show/0.1";
const CONFIG_PATCH_TASK = "https://trusttasks.org/spec/config/patch/0.1";
const CONFIG_RELOAD_TASK = "https://trusttasks.org/spec/config/reload/0.1";

export const fetchEffectiveConfig = (): Promise<EffectiveConfig> =>
  getJson<EffectiveConfig>("/v1/admin/config", {
    trustTask: CONFIG_SHOW_TASK,
    requires: ["fields"],
  });

/**
 * Write config overrides and put them into effect.
 *
 * Returns the PATCH response so a caller can surface `rejected` — the
 * daemon validates bounds server-side, so a value the console let through
 * can still come back refused, and the reason is worth showing.
 */
export async function saveConfig(
  overrides: Record<string, unknown>,
): Promise<ConfigPatchResponse> {
  const result = await patchJson<ConfigPatchResponse>(
    "/v1/admin/config",
    { overrides },
    { trustTask: CONFIG_PATCH_TASK, requires: ["applied", "rejected"] },
  );
  if (result.applied.length > 0) {
    await postJson<unknown>("/v1/admin/config/reload", undefined, {
      trustTask: CONFIG_RELOAD_TASK,
    });
  }
  return result;
}

/** Revoke the server-side session and clear browser cookies. */
export const signOut = async (): Promise<void> => {
  await postJson<void>("/v1/auth/sign-out", undefined, { trustTask: SIGN_OUT_TASK });
  // Drop the expiry so a subsequent sign-in starts from that session's
  // own deadline rather than renewing against the dead one's.
  resetSession();
};

// ---------------------------------------------------------------------------
// Invitations — issue a VIC for a prospective member (operator side of the
// VIC auto-join ceremony).
// ---------------------------------------------------------------------------

const ISSUE_INVITATION_TASK =
  "https://trusttasks.org/spec/vtc/invitations/issue/0.1";
const LIST_INVITATIONS_TASK =
  "https://trusttasks.org/spec/vtc/invitations/list/0.1";

export interface IssueInvitationResponse {
  subjectDid: string;
  validUntil?: string;
  /** The signed Invitation Credential — handed to the invitee out-of-band. */
  vic: unknown;
}

/** Issue an Invitation Credential bound to `subjectDid`, optionally granting a
 * role (`member` / `moderator` / `issuer`; `admin` is refused server-side). */
export const issueInvitation = (
  subjectDid: string,
  validityDays?: number,
  role?: string,
): Promise<IssueInvitationResponse> => {
  const body: Record<string, unknown> = { subjectDid };
  if (validityDays !== undefined) body.validityDays = validityDays;
  if (role) body.role = role;
  return postJson<IssueInvitationResponse>("/v1/invitations", body, {
    trustTask: ISSUE_INVITATION_TASK,
  });
};

const REVOKE_INVITATION_TASK =
  "https://trusttasks.org/spec/vtc/invitations/revoke/0.1";

export interface InvitationListItem {
  id: string;
  subjectDid: string;
  role?: string;
  issuedBy: string;
  issuedAt: string;
  validUntil?: string;
  revokedAt?: string;
}

/** List issued invitations (newest first). Its own Trust Task: listing the
 * registry and minting a bearer credential are different contracts, even
 * though GET and POST share the /invitations path. */
export const listInvitations = (): Promise<{ invitations: InvitationListItem[] }> =>
  getJson<{ invitations: InvitationListItem[] }>("/v1/invitations", {
    trustTask: LIST_INVITATIONS_TASK,
  });

/** Revoke an outstanding invitation by VIC id (flips its revocation bit). */
export const revokeInvitation = (
  id: string,
): Promise<{ id: string; revokedAt: string; newlyRevoked: boolean }> =>
  deleteJson<{ id: string; revokedAt: string; newlyRevoked: boolean }>(
    `/v1/invitations/${encodeURIComponent(id)}`,
    { trustTask: REVOKE_INVITATION_TASK },
  );

const DELIVER_INVITATION_TASK =
  "https://trusttasks.org/spec/vtc/invitations/deliver/0.1";

/** `message`: push an offer to the invited DID. `offer`: return it for a QR. */
export type DeliverChannel = "message" | "offer";

export interface DeliverInvitationResponse {
  id: string;
  channel: DeliverChannel;
  /** OID4VCI Credential Offer — present on the `offer` channel only. */
  offer?: Record<string, unknown>;
  expiresAt: string;
}

/** Deliver an issued invitation to the DID it admits. The offer redeems only
 * for that DID's key, so it is safe to show as a QR code; delivering again
 * withdraws the previous offer. */
export const deliverInvitation = (
  id: string,
  channel: DeliverChannel,
): Promise<DeliverInvitationResponse> =>
  postJson<DeliverInvitationResponse>(
    "/v1/invitations/deliver",
    { id, channel },
    { trustTask: DELIVER_INVITATION_TASK },
  );

const RELATIONSHIPS_GRAPH_TASK =
  "https://trusttasks.org/spec/vtc/relationships/graph/0.2";

export interface GraphNode {
  did: string;
}
/** One published edge credential: a directed half of an edge. Either a VRC
 *  between two members, or one of the two VMCs of a membership edge — DTG Core
 *  Credentials makes both subtypes of *edge credential*, and "in both cases, a
 *  bi-directional pair of credentials forms a complete DTG edge". */
export interface GraphHalf {
  id: string;
  issuerDid: string;
  subjectDid: string;
  createdAt: string;
  /** The persona (P-DID) the edge's issuer has asserted on it, via a VPC.
   *  Absent unless they chose to. Two edges sharing one `personaDid` are the
   *  same party, said so by that party — the only correlation the graph is
   *  entitled to draw between two pairwise identifiers. */
  personaDid?: string;
}
/** One edge between a pair of identifiers. A DTG edge is *two* credentials,
 * one in each direction; `complete` says whether both stand. A half-edge is one
 * party's unilateral claim, not a mutual relationship.
 *
 * An edge with the community's own DID as an endpoint is a **membership** edge
 * (the VMC pair); anything else is a relationship edge (the VRC pair). The
 * response carries no `kind` field to say so — `relationships/graph/0.2` pins
 * the shape with `additionalProperties: false` — and none is needed: the
 * community knows its own DID. */
export interface GraphEdge {
  /** The two endpoints, DID-sorted. Always length 2. */
  endpoints: string[];
  /** Every VRC published between them, oldest first. */
  halves: GraphHalf[];
  complete: boolean;
}
export interface RelationshipsGraph {
  nodes: GraphNode[];
  edges: GraphEdge[];
}

/** The community's trust graph — every edge, membership (VMC pairs) and
 * relationship (VRC pairs) alike, for the connections-graph view.
 * Admin-gated. */
export const fetchRelationshipsGraph = (): Promise<RelationshipsGraph> =>
  getJson<RelationshipsGraph>("/v1/relationships/graph", {
    trustTask: RELATIONSHIPS_GRAPH_TASK,
  });

const MEMBER_RELATIONSHIPS_TASK =
  "https://trusttasks.org/spec/vtc/relationships/list/0.2";

/** One relationship row as the community stored it, credential body included.
 *  Unlike `GraphHalf` — which is body-free by design, because the graph shows
 *  the shape of the network rather than credential contents — this is the
 *  credential itself, for an operator who needs to read one. */
export interface MemberRelationship {
  id: string;
  issuerDid: string;
  subjectDid: string;
  vrcJsonld: unknown;
  createdAt: string;
}

/** Every relationship credential naming this member, either direction.
 *  Paginated server-side; the console reads the first page, which is the
 *  operator-relevant case — a member with more than 50 published edges is a
 *  graph question, not a credential-inspection one. */
export const fetchMemberRelationships = (
  did: string,
): Promise<{ items: MemberRelationship[]; nextCursor?: string | null }> =>
  getJson<{ items: MemberRelationship[]; nextCursor?: string | null }>(
    `/v1/members/${encodeURIComponent(did)}/relationships`,
    { trustTask: MEMBER_RELATIONSHIPS_TASK },
  );

const RECOGNITION_CHECK_TASK =
  "https://trusttasks.org/spec/vtc/recognition/check/0.1";

export interface RecognitionCheck {
  did: string;
  recognised: boolean;
  registryConfigured: boolean;
  error?: string;
}

/** Ask whether this community recognises (trusts) a foreign issuer/community
 * DID — the operator's per-DID window into the recognition graph. */
export const checkRecognition = (did: string): Promise<RecognitionCheck> =>
  getJson<RecognitionCheck>(
    `/v1/recognition/check?did=${encodeURIComponent(did)}`,
    { trustTask: RECOGNITION_CHECK_TASK },
  );

/** Probe: returns the whoami response when signed in, null when not. */
export async function probeSession(): Promise<WhoamiResponse | null> {
  try {
    const who = await fetchWhoami();
    // The one place the console learns when its cookie dies. It has
    // always been in this response; nothing read it until renewal
    // needed something to schedule against.
    setSessionExpiry(who.session?.expiresAt ?? null);
    return who;
  } catch (e) {
    const err = e as ApiError;
    if (err.status === 401 || err.status === 403) {
      resetSession();
      return null;
    }
    throw e;
  }
}
