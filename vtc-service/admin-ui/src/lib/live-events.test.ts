// The live channel against a mocked stream: the `#response` first, hints
// after, the session's one subscription re-signed with `since` on reconnect,
// offline at once on silence or an ended stream, and refusals that stop or
// back off as subscribe 0.1 rule 10 says.

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { QueryClient } from "@tanstack/react-query";

import {
  ALL_TOPICS,
  EVENT_TASK,
  LiveEvents,
  SseParser,
  STREAM_ACCEPT,
  SUBSCRIBE_TASK,
  type LiveStatus,
  type SignedSubscribe,
  type Topic,
} from "./live-events";
import { invalidateTopics, keysFor } from "./use-live-events";
import { WAITING_COUNT_KEY } from "./action-badge";
import { MEMBER_COUNT_KEY, PENDING_JOIN_REQUESTS_KEY } from "./community-counts";

const COMMUNITY = "did:web:community.example";
const CONSOLE = "did:key:z6MkConsole";

function controlledStream() {
  let ctrl!: ReadableStreamDefaultController<Uint8Array>;
  const stream = new ReadableStream<Uint8Array>({
    start(c) {
      ctrl = c;
    },
  });
  const enc = new TextEncoder();
  return {
    stream,
    push: (s: string) => ctrl.enqueue(enc.encode(s)),
    close: () => ctrl.close(),
  };
}

function sse(doc: unknown, id?: string): string {
  return `${id ? `id: ${id}\n` : ""}data: ${JSON.stringify(doc)}\n\n`;
}

function response(
  payload: Record<string, unknown>,
  over: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    id: "urn:uuid:resp",
    type: `${SUBSCRIBE_TASK}#response`,
    issuer: COMMUNITY,
    recipient: CONSOLE,
    payload: { heartbeatSeconds: 25, resumed: false, resumeToken: "tok0", ...payload },
    ...over,
  };
}

function hint(
  topic: string,
  token: string,
  count?: number,
  over: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    id: `urn:uuid:${token}`,
    type: EVENT_TASK,
    issuer: COMMUNITY,
    recipient: CONSOLE,
    payload: {
      topic,
      at: "2026-10-03T09:12:40Z",
      resumeToken: token,
      ...(count !== undefined ? { count } : {}),
    },
    ...over,
  };
}

function streamResponse(stream: ReadableStream<Uint8Array>): Response {
  return new Response(stream, {
    status: 200,
    headers: { "Content-Type": "text/event-stream" },
  });
}

function jsonRefusal(code: string, status = 422): Response {
  return new Response(
    JSON.stringify({ type: "https://trusttasks.org/spec/trust-task-error/0.5", payload: { code } }),
    { status, headers: { "Content-Type": "application/json" } },
  );
}

interface Harness {
  client: LiveEvents;
  hints: Array<[Topic, number | undefined]>;
  resyncs: Array<readonly Topic[]>;
  statuses: LiveStatus[];
  signed: Array<{ topics: Topic[]; since?: string }>;
  fetch: ReturnType<typeof vi.fn>;
}

function harness(responses: Array<() => Response>): Harness {
  const h: Omit<Harness, "client" | "fetch"> = {
    hints: [],
    resyncs: [],
    statuses: [],
    signed: [],
  };
  const fetch = vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
    const next = responses.shift();
    if (!next) throw new TypeError("network down");
    const res = next();
    // Abort cancels the body, as a real fetch does.
    init?.signal?.addEventListener("abort", () => void res.body?.cancel().catch(() => {}));
    return res;
  });
  const client = new LiveEvents(
    ALL_TOPICS,
    {
      onHint: (t, c) => h.hints.push([t, c]),
      onResync: (t) => h.resyncs.push(t),
      onStatus: (s) => h.statuses.push(s),
    },
    {
      sign: async (payload) => {
        h.signed.push(payload);
        return { issuer: CONSOLE, recipient: COMMUNITY, payload } as SignedSubscribe;
      },
      fetch: fetch as unknown as typeof globalThis.fetch,
      csrf: () => "csrf-token",
      random: () => 0.5,
    },
  );
  return { ...h, client, fetch } as Harness;
}

const settle = () => vi.advanceTimersByTimeAsync(0);

beforeEach(() => {
  vi.useFakeTimers();
});
afterEach(() => {
  vi.useRealTimers();
});

describe("SseParser", () => {
  it("frames one document per event, ignores comments, honours CRLF and split chunks", () => {
    const p = new SseParser();
    expect(p.push(": heartbeat\n\n")).toEqual([]);
    expect(p.push("id: a\r\ndata: {\"x\":")).toEqual([]);
    const [ev] = p.push("1}\r\n\r\n");
    expect(ev).toEqual({ id: "a", data: '{"x":1}', dataLines: 1 });
    p.push("retry: 4000\n\n");
    expect(p.retryMs).toBe(4000);
    const [two] = p.push("data: a\ndata: b\nevent: x\n\n");
    expect(two?.dataLines).toBe(2);
    expect(two?.event).toBe("x");
  });
});

describe("LiveEvents", () => {
  it("goes live on the #response, re-reads everything when not resumed, and hands hints on", async () => {
    const s = controlledStream();
    const h = harness([() => streamResponse(s.stream)]);
    h.client.start();
    await settle();

    const [, init] = h.fetch.mock.calls[0]!;
    const headers = (init as RequestInit).headers as Record<string, string>;
    expect(headers.Accept).toBe(STREAM_ACCEPT);
    expect(headers["X-CSRF-Token"]).toBe("csrf-token");
    expect((init as RequestInit).method).toBe("POST");
    expect(h.signed[0]).toEqual({ topics: [...ALL_TOPICS] });

    s.push(sse(response({ topics: ["actions", "members"] }), "tok0"));
    await settle();
    expect(h.client.status).toBe("live");
    expect(h.resyncs).toEqual([["actions", "members"]]);

    s.push(sse(hint("actions", "tok1", 2), "tok1"));
    // Not an effective topic: discarded.
    s.push(sse(hint("config", "tok2"), "tok2"));
    // A count on a topic that has none is ignored.
    s.push(sse(hint("members", "tok3", 9), "tok3"));
    await settle();
    expect(h.hints).toEqual([
      ["actions", 2],
      ["members", undefined],
    ]);
    expect(h.client.resumeToken).toBe("tok3");
    h.client.stop();
  });

  it("shows offline at once when the stream ends, then re-subscribes with a fresh signature and `since`", async () => {
    const first = controlledStream();
    const second = controlledStream();
    const h = harness([() => streamResponse(first.stream), () => streamResponse(second.stream)]);
    h.client.start();
    await settle();
    first.push(sse(response({ topics: ["actions"] }), "tok0"));
    first.push(sse(hint("actions", "tok1", 1), "tok1"));
    await settle();
    expect(h.client.status).toBe("live");

    first.close();
    await settle();
    expect(h.client.status).toBe("offline");
    // Fallen back to polling: every topic re-read now.
    expect(h.resyncs.at(-1)).toEqual(["actions"]);

    await vi.advanceTimersByTimeAsync(2_000);
    expect(h.fetch).toHaveBeenCalledTimes(2);
    expect(h.signed[1]).toEqual({ topics: [...ALL_TOPICS], since: "tok1" });
    const [, init] = h.fetch.mock.calls[1]!;
    expect(((init as RequestInit).headers as Record<string, string>)["Last-Event-ID"]).toBe("tok1");

    second.push(sse(response({ topics: ["actions"], resumed: true, resumeToken: "tok1" }), "tok1"));
    await settle();
    expect(h.client.status).toBe("live");
    h.client.stop();
  });

  it("treats twice the heartbeat of silence as a dead stream", async () => {
    const s = controlledStream();
    const h = harness([() => streamResponse(s.stream)]);
    h.client.start();
    await settle();
    s.push(sse(response({ topics: ["actions"], heartbeatSeconds: 10 }), "tok0"));
    await settle();
    expect(h.client.status).toBe("live");

    // A heartbeat comment keeps it alive…
    await vi.advanceTimersByTimeAsync(15_000);
    s.push(": heartbeat\n\n");
    await settle();
    await vi.advanceTimersByTimeAsync(15_000);
    expect(h.client.status).toBe("live");

    // …and twenty seconds of nothing does not.
    await vi.advanceTimersByTimeAsync(6_000);
    expect(h.client.status).not.toBe("live");
    expect(h.statuses).toContain("offline");
    h.client.stop();
  });

  it("stops for the session on a refusal retrying cannot fix", async () => {
    const h = harness([() => jsonRefusal("vtc/admin/events/subscribe:streamUnavailable")]);
    h.client.start();
    await settle();
    await vi.advanceTimersByTimeAsync(120_000);
    expect(h.fetch).toHaveBeenCalledTimes(1);
    expect(h.client.status).toBe("offline");
    h.client.stop();
  });

  it("backs off and retries tooManyStreams", async () => {
    const s = controlledStream();
    const h = harness([
      () => jsonRefusal("vtc/admin/events/subscribe:tooManyStreams"),
      () => streamResponse(s.stream),
    ]);
    h.client.start();
    await settle();
    expect(h.client.status).toBe("offline");
    await vi.advanceTimersByTimeAsync(2_000);
    expect(h.fetch).toHaveBeenCalledTimes(2);
    s.push(sse(response({ topics: ["actions"] }), "tok0"));
    await settle();
    expect(h.client.status).toBe("live");
    h.client.stop();
  });

  it("closes a stream whose first event is not the #response, or whose documents are not addressed to it", async () => {
    const a = controlledStream();
    const b = controlledStream();
    const h = harness([() => streamResponse(a.stream), () => streamResponse(b.stream)]);
    h.client.start();
    await settle();
    a.push(sse(hint("actions", "tok1", 1), "tok1"));
    await settle();
    expect(h.client.status).toBe("offline");
    expect(h.hints).toEqual([]);

    await vi.advanceTimersByTimeAsync(2_000);
    b.push(sse(response({ topics: ["actions"] }), "tok0"));
    await settle();
    expect(h.client.status).toBe("live");
    b.push(sse(hint("actions", "tok9", 1, { recipient: "did:key:z6MkSomeoneElse" }), "tok9"));
    await settle();
    expect(h.hints).toEqual([]);
    expect(h.client.status).toBe("offline");
    h.client.stop();
  });
});

describe("hint to query keys", () => {
  it("re-reads the badge, page, tile and banner keys each topic names", () => {
    const has = (t: Topic, key: readonly unknown[]) =>
      keysFor(t).some((k) => JSON.stringify(k) === JSON.stringify(key));
    expect(has("actions", WAITING_COUNT_KEY)).toBe(true);
    expect(has("actions", ["actions"])).toBe(true);
    expect(has("acknowledgements", WAITING_COUNT_KEY)).toBe(true);
    expect(has("singleAdminMode", WAITING_COUNT_KEY)).toBe(true);
    // Prefixes: the page, the badge count and the dashboard tile all sit under them.
    expect(PENDING_JOIN_REQUESTS_KEY[0]).toBe("join-requests");
    expect(has("joinRequests", ["join-requests"])).toBe(true);
    expect(MEMBER_COUNT_KEY[0]).toBe("members");
    expect(has("members", ["members"])).toBe(true);
    expect(has("config", ["admin-config"])).toBe(true);
  });

  it("invalidates each key once", () => {
    const qc = new QueryClient();
    const spy = vi.spyOn(qc, "invalidateQueries");
    invalidateTopics(qc, ["actions", "acknowledgements", "singleAdminMode"]);
    expect(spy).toHaveBeenCalledTimes(2);
  });
});
