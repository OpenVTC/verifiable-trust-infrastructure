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
/** One protocol's state on this VTC's own DID document. */
export interface TransportStatus {
  /** "tsp" | "didcomm" | "rest" */
  protocol: string;
  /** The DID document advertises it, so a resolving client will find it. */
  advertised: boolean;
  /** This build can answer on it right now (compiled in + live mediator). */
  serviceable: boolean;
  /** Mediator DID for TSP/DIDComm, base URL for REST. */
  endpoint?: string;
}

/**
 * How the VTC reaches its trust registry.
 *
 * `advertised` is the registry's own claim (read from its DID document);
 * `active` is what the last call actually chose. They are separate because a
 * registry can be configured and unreachable at once — advertising a transport
 * this VTC cannot answer — and one merged field would have to drop half of it.
 */
export interface RegistryTransport {
  did?: string;
  url?: string;
  advertised: string[];
  active?: string;
  error?: string;
}

export interface DiagnosticsResponse {
  registryStatus: string;
  queueDepth: number;
  rtbfBatchedCount: number;
  failedCount: number;
  oldestPendingAgeSeconds?: number;
  lastSuccessAt?: string;
  lastFailureAt?: string;
  lastError?: string;
  vtaDid?: string;
  mediatorUrl?: string;
  mediatorDid?: string;
  syncerEnabled: boolean;
  syncerRunning: boolean;
  syncerRestarts: number;
  messagingStatus?: string;
  registryTransport?: RegistryTransport;
  transports?: TransportStatus[];
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

async function request<T>(
  path: string,
  init: RequestInit = {},
  requires?: string[],
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
  "https://trusttasks.org/spec/vtc/registry/diagnostics/0.1";

// Admin-gated identity + reconciler diagnostics. The dashboard reads
// `vta_did` / `mediator_did` from here since P3.7 stripped them off
// the unauth `/health` payload.
export const fetchDiagnostics = (): Promise<DiagnosticsResponse> =>
  getJson<DiagnosticsResponse>("/v1/health/diagnostics", {
    trustTask: DIAGNOSTICS_TASK,
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

/** Revoke the server-side session and clear browser cookies. */
export const signOut = (): Promise<void> =>
  postJson<void>("/v1/auth/sign-out", undefined, { trustTask: SIGN_OUT_TASK });

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
    return await fetchWhoami();
  } catch (e) {
    const err = e as ApiError;
    if (err.status === 401 || err.status === 403) return null;
    throw e;
  }
}
