// Tiny fetch wrapper for the daemon's JSON endpoints.
//
// Every call sends credentials so the `vtc_admin_session` cookie
// rides along. Mutating requests (POST/PUT/DELETE/PATCH) mirror the
// `csrf` cookie's value into the `X-CSRF-Token` header for the
// double-submit check in `routing::csrf`.

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

// `GET /v1/health/diagnostics` — admin-gated. Surfaces the
// trust-registry reconciler state plus the identity/mediator detail
// that used to live on `/health`. The dashboard only needs the
// identity fields; the rest are typed for future diagnostics views.
export interface DiagnosticsResponse {
  registry_status: string;
  queue_depth: number;
  rtbf_batched_count: number;
  failed_count: number;
  oldest_pending_age_seconds?: number;
  last_success_at?: string;
  last_failure_at?: string;
  last_error?: string;
  vta_did?: string;
  mediator_url?: string;
  mediator_did?: string;
  syncer_enabled: boolean;
  syncer_running: boolean;
  syncer_restarts: number;
}

export interface BuildInfo {
  version: string;
  mode: string;
  indexSha256: string;
}

export interface ApiError {
  status: number;
  /** Daemon-formatted error message when the body is JSON. */
  message: string;
}

function csrfTokenFromCookie(): string | null {
  // The CSRF cookie is set by login (`/v1/auth/passkey-login/finish`
  // or `/v1/auth/admin-login`). HttpOnly is **not** set on this
  // cookie precisely so JS can read it.
  const match = document.cookie.match(/(?:^|;\s*)csrf=([^;]+)/);
  return match?.[1] ?? null;
}

async function request<T>(
  path: string,
  init: RequestInit = {},
): Promise<T> {
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
    let message = `${res.status} ${res.statusText}`;
    try {
      const body = (await res.json()) as { error?: string; message?: string };
      if (body.error) message = body.error;
      else if (body.message) message = body.message;
    } catch {
      /* non-JSON body */
    }
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
  return (await res.json()) as T;
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
}

export const getJson = <T>(
  path: string,
  extra: TrustTaskOpts,
): Promise<T> =>
  request<T>(path, {
    method: "GET",
    headers: { "Trust-Task": extra.trustTask },
  });

export const postJson = <T>(
  path: string,
  body: unknown,
  extra: TrustTaskOpts,
): Promise<T> =>
  request<T>(path, {
    method: "POST",
    body: body === undefined ? undefined : JSON.stringify(body),
    headers: { "Trust-Task": extra.trustTask },
  });

export const putJson = <T>(
  path: string,
  body: unknown,
  extra: TrustTaskOpts,
): Promise<T> =>
  request<T>(path, {
    method: "PUT",
    body: body === undefined ? undefined : JSON.stringify(body),
    headers: { "Trust-Task": extra.trustTask },
  });

export const patchJson = <T>(
  path: string,
  body: unknown,
  extra: TrustTaskOpts,
): Promise<T> =>
  request<T>(path, {
    method: "PATCH",
    body: body === undefined ? undefined : JSON.stringify(body),
    headers: { "Trust-Task": extra.trustTask },
  });

export const deleteJson = <T>(
  path: string,
  extra: TrustTaskOpts & { body?: unknown },
): Promise<T> =>
  request<T>(path, {
    method: "DELETE",
    body: extra.body === undefined ? undefined : JSON.stringify(extra.body),
    headers: { "Trust-Task": extra.trustTask },
  });

// ---------------------------------------------------------------------------
// Exempt helpers — for `/health`, `/admin/build-info.json`,
// `/admin/plugins.json`, and any future route that's outside the
// `TrustTaskRouter`. Spelling the carve-out explicitly at the call
// site is the whole point: a `getJsonExempt` in a plugin is a smell.
// ---------------------------------------------------------------------------

export const getJsonExempt = <T>(path: string): Promise<T> =>
  request<T>(path, { method: "GET" });

// `/health` is the daemon's single Trust-Task-exempt endpoint.
// `/admin/build-info.json` lives on the admin router (not the
// TrustTaskRouter). Both are header-less by design.
export const fetchHealth = (): Promise<HealthResponse> =>
  getJsonExempt<HealthResponse>("/health");

export const fetchBuildInfo = (): Promise<BuildInfo> =>
  getJsonExempt<BuildInfo>("/admin/build-info.json");

const DIAGNOSTICS_TASK =
  "https://trusttasks.org/openvtc/vtc/health/diagnostics/1.0";

// Admin-gated identity + reconciler diagnostics. The dashboard reads
// `vta_did` / `mediator_did` from here since P3.7 stripped them off
// the unauth `/health` payload.
export const fetchDiagnostics = (): Promise<DiagnosticsResponse> =>
  getJson<DiagnosticsResponse>("/v1/health/diagnostics", {
    trustTask: DIAGNOSTICS_TASK,
  });

/** Shape returned by `GET /v1/auth/whoami`. */
export interface WhoamiResponse {
  did: string;
  role: string;
  sessionId: string;
  accessExpiresAt: number;
  allowedContexts: string[];
}

const WHOAMI_TASK = "https://trusttasks.org/spec/auth/whoami/0.1";
const SIGN_OUT_TASK = "https://trusttasks.org/spec/auth/revoke-session/0.1";

/** Fetch the caller's session identity. Throws on 401/403. */
export const fetchWhoami = (): Promise<WhoamiResponse> =>
  getJson<WhoamiResponse>("/v1/auth/whoami", { trustTask: WHOAMI_TASK });

/** Revoke the server-side session and clear browser cookies. */
export const signOut = (): Promise<void> =>
  postJson<void>("/v1/auth/sign-out", undefined, { trustTask: SIGN_OUT_TASK });

// ---------------------------------------------------------------------------
// Invitations — issue a VIC for a prospective member (operator side of the
// VIC auto-join ceremony).
// ---------------------------------------------------------------------------

const ISSUE_INVITATION_TASK =
  "https://trusttasks.org/openvtc/vtc/invitations/issue/1.0";

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
  "https://trusttasks.org/openvtc/vtc/invitations/revoke/1.0";

export interface InvitationListItem {
  id: string;
  subjectDid: string;
  role?: string;
  issuedBy: string;
  issuedAt: string;
  validUntil?: string;
  revokedAt?: string;
}

/** List issued invitations (newest first). Reuses the issue Trust Task (GET +
 * POST share the /invitations mount). */
export const listInvitations = (): Promise<{ invitations: InvitationListItem[] }> =>
  getJson<{ invitations: InvitationListItem[] }>("/v1/invitations", {
    trustTask: ISSUE_INVITATION_TASK,
  });

/** Revoke an outstanding invitation by VIC id (flips its revocation bit). */
export const revokeInvitation = (
  id: string,
): Promise<{ id: string; revokedAt: string; newlyRevoked: boolean }> =>
  deleteJson<{ id: string; revokedAt: string; newlyRevoked: boolean }>(
    `/v1/invitations/${encodeURIComponent(id)}`,
    { trustTask: REVOKE_INVITATION_TASK },
  );

const RELATIONSHIPS_GRAPH_TASK =
  "https://trusttasks.org/openvtc/vtc/relationships/graph/1.0";

export interface GraphNode {
  did: string;
}
export interface GraphEdge {
  id: string;
  issuerDid: string;
  subjectDid: string;
  createdAt: string;
}
export interface RelationshipsGraph {
  nodes: GraphNode[];
  edges: GraphEdge[];
}

/** The community's member-relationship (VRC) graph — every trust edge between
 * members, for the connections-graph view. Admin-gated. */
export const fetchRelationshipsGraph = (): Promise<RelationshipsGraph> =>
  getJson<RelationshipsGraph>("/v1/relationships/graph", {
    trustTask: RELATIONSHIPS_GRAPH_TASK,
  });

const RECOGNITION_CHECK_TASK =
  "https://trusttasks.org/openvtc/vtc/recognition/check/1.0";

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
    return await fetchWhoami();
  } catch (e) {
    const err = e as ApiError;
    if (err.status === 401 || err.status === 403) return null;
    throw e;
  }
}
