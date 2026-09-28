// A stand-in for `postSignedRead` in component tests: the same request to
// `POST /v1/trust-tasks`, carrying `{ type, payload }` unsigned, so a test's
// `mockFetch` table answers the read without a console key in the test
// browser. A refusal throws what `postSignedDocument` throws — an `ApiError`
// with the `trust-task-error`'s `code` — so the screens see what they would.
//
// Only ever installed through `vi.mock("@/lib/api", …)`; the console itself
// signs every read. It stands in for `postSignedTrustTask` too, as
// [`unsignedTask`], where a test drives a signed change through `mockFetch`.

import type { ApiError } from "@/lib/api";

export async function unsignedRead<T>(typeUri: string, payload: unknown): Promise<T> {
  const res = await fetch("/v1/trust-tasks", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ type: typeUri, payload }),
  });
  const body = (await res.json().catch(() => null)) as {
    payload?: { code?: string; message?: string } & Record<string, unknown>;
  } | null;
  if (!res.ok) {
    const err: ApiError = {
      status: res.status,
      message: body?.payload?.message ?? body?.payload?.code ?? `${res.status}`,
    };
    if (typeof body?.payload?.code === "string") err.code = body.payload.code;
    throw err;
  }
  return body?.payload as T;
}

/** [`unsignedRead`], standing in for `postSignedTrustTask`. */
export const unsignedTask = unsignedRead;
