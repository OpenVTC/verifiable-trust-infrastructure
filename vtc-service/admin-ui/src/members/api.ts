// The member portal's HTTP client.
//
// Deliberately not `@/lib/api`: that is the console's client, and it mirrors
// the console's `csrf` cookie and speaks the console's routes. The portal talks
// only to `/v1/member/*` and mirrors `vtc_member_csrf` — the two applications
// share an origin, and keeping their clients apart is what keeps one from
// ever sending the other's credentials (`crate::member_portal`).

const CSRF_COOKIE = "vtc_member_csrf";

export class MemberApiError extends Error {
  constructor(
    message: string,
    readonly status: number,
  ) {
    super(message);
    this.name = "MemberApiError";
  }
}

export function memberCsrfToken(): string | null {
  if (typeof document === "undefined") return null;
  const m = document.cookie.match(
    new RegExp(`(?:^|;\\s*)${CSRF_COOKIE}=([^;]+)`),
  );
  return m && m[1] ? decodeURIComponent(m[1]) : null;
}

async function errorMessage(res: Response): Promise<string> {
  try {
    const body = (await res.json()) as { message?: string; error?: string };
    return body.message ?? body.error ?? `${res.status} ${res.statusText}`;
  } catch {
    return `${res.status} ${res.statusText}`;
  }
}

async function send(path: string, init: RequestInit): Promise<Response> {
  const headers = new Headers(init.headers);
  if (init.body !== undefined) headers.set("Content-Type", "application/json");
  const method = (init.method ?? "GET").toUpperCase();
  if (method !== "GET") {
    const csrf = memberCsrfToken();
    if (csrf) headers.set("X-CSRF-Token", csrf);
  }
  return fetch(path, { ...init, headers, credentials: "same-origin" });
}

// One renewal in flight at a time; concurrent 401s wait on the same one.
let renewing: Promise<boolean> | null = null;

/** Renew the cookie session from the refresh cookie. `false` when there is
 *  none, or it was refused — the caller is signed out. */
export function renewSession(): Promise<boolean> {
  renewing ??= send("/v1/member/auth/refresh", { method: "POST" })
    .then((r) => r.ok)
    .catch(() => false)
    .finally(() => {
      renewing = null;
    });
  return renewing;
}

/** Call a member route. A 401 renews the session once and retries. */
export async function memberFetch<T>(
  path: string,
  init: RequestInit = {},
): Promise<T> {
  let res = await send(path, init);
  if (res.status === 401 && (await renewSession())) {
    res = await send(path, init);
  }
  if (!res.ok) throw new MemberApiError(await errorMessage(res), res.status);
  if (res.status === 204) return undefined as T;
  return (await res.json()) as T;
}

export function postMember<T>(path: string, body?: unknown): Promise<T> {
  return memberFetch<T>(path, {
    method: "POST",
    body: body === undefined ? undefined : JSON.stringify(body),
  });
}

/** `GET /v1/member/me`. */
export interface MemberMe {
  did: string;
  sessionId: string;
  accessExpiresAt: number;
  amr: string[];
  joinedAt: string;
  role: string;
  personhood: boolean;
  canManagePasskeys: boolean;
  community: { name?: string | null; logoUrl?: string | null; did?: string | null };
}

export interface MemberPasskey {
  credentialId: string;
  label?: string | null;
  registeredAt: string;
}

/** This VTC's own DID, which the wallet's SIOP `id_token` is addressed to. */
export async function vtcDid(): Promise<string> {
  const res = await fetch("/health", { credentials: "same-origin" });
  if (!res.ok) throw new MemberApiError(await errorMessage(res), res.status);
  const health = (await res.json()) as { vtc_did?: string | null };
  if (!health.vtc_did) {
    throw new MemberApiError(
      "This community has not finished setting up, so sign-in isn't available yet.",
      503,
    );
  }
  return health.vtc_did;
}
