// The console's live channel: one `vtc/admin/events/subscribe/0.1` stream per
// session, read over the HTTPS binding's streamed response (0.3 §2.1).
//
// What it carries is hints — "this topic changed", and for the badge topics
// "your count is now n" — never records. A hint is acted on only by
// re-fetching that topic's own signed read (the react-query keys the screens
// already use, `lib/use-live-events.ts`), so authorization stays on every read
// and a forged hint costs at most one unnecessary request.
//
// Why `fetch` and not `EventSource`: the binding accepts only a signed
// `POST /v1/trust-tasks`. `EventSource` can only `GET`, cannot carry the
// document, and reconnects by itself without one — so this reads the body as
// a stream and reconnects with a freshly signed subscribe carrying `since`.
//
// Live or offline, never latched (subscribe 0.1 rules 8–10, R6.2): `live`
// only while bytes arrive at intervals no longer than twice
// `heartbeatSeconds`. Silence that long, an ended stream or any failure shows
// `offline` at once, closes the connection, re-reads every topic, and the
// polls the screens already run speed back up. Reconnection backs off
// exponentially with jitter, taking a server `retry:` as the floor. A refusal
// that will not change this session (`streamUnavailable`, `unsupportedType`,
// `notAdministrator`, `permissionDenied`) stops trying; `tooManyStreams` backs
// off and tries again.

export const SUBSCRIBE_TASK = "https://trusttasks.org/spec/vtc/admin/events/subscribe/0.1";
export const EVENT_TASK = "https://trusttasks.org/spec/vtc/admin/events/event/0.1";
const RESPONSE_TYPE = `${SUBSCRIBE_TASK}#response`;

/** What the binding asks for: a stream, or JSON from a server that cannot. */
export const STREAM_ACCEPT = "text/event-stream, application/json;q=0.5";

/** The shared `Topic` of `vtc/admin/events/_shared/0.1`. */
export type Topic =
  | "actions"
  | "acknowledgements"
  | "joinRequests"
  | "members"
  | "singleAdminMode"
  | "config";

/** Every topic the console renders — one subscription for all of them. */
export const ALL_TOPICS: readonly Topic[] = [
  "actions",
  "acknowledgements",
  "joinRequests",
  "members",
  "singleAdminMode",
  "config",
];

/** The topics whose hints carry a count; any other's `count` is ignored. */
export const COUNT_TOPICS: readonly Topic[] = ["actions", "acknowledgements", "joinRequests"];

export type LiveStatus = "connecting" | "live" | "offline";

/** The first and the longest wait before a re-subscribe. */
export const BACKOFF_BASE_MS = 1_000;
export const BACKOFF_MAX_MS = 60_000;
/** The longest heartbeat the specification allows: until the `#response`
 *  names the real one, silence is judged against it. */
export const MAX_HEARTBEAT_MS = 60_000;

/** A signed subscribe, ready to send. */
export interface SignedSubscribe {
  issuer: string;
  recipient: string;
  [member: string]: unknown;
}

export interface LiveEventsDeps {
  /** Sign a fresh subscribe document (new `id`, `issuedAt`, proof). */
  sign: (payload: { topics: Topic[]; since?: string }) => Promise<SignedSubscribe>;
  fetch: typeof fetch;
  csrf?: () => string | null;
  /** `[0, 1)`; jitter. */
  random?: () => number;
}

export interface LiveEventsHandlers {
  /** A hint for an effective topic: re-read it. `count` only on a count topic. */
  onHint: (topic: Topic, count: number | undefined) => void;
  /** Changes may have been missed: re-read every one of `topics`. */
  onResync: (topics: readonly Topic[]) => void;
  onStatus: (status: LiveStatus) => void;
}

/** Codes after which the session stops trying (subscribe 0.1 rule 10). */
const FINAL_CODES = [
  "streamUnavailable",
  "unsupportedType",
  "unsupportedVersion",
  "notAdministrator",
  "permissionDenied",
];

function localCode(code: unknown): string {
  if (typeof code !== "string") return "";
  const i = code.lastIndexOf(":");
  return i >= 0 ? code.slice(i + 1) : code;
}

// ─── Server-Sent Events framing ─────────────────────────────────────────

export interface SseEvent {
  id?: string;
  data: string;
  /** Set when the event carried an `event:` field — the binding forbids one. */
  event?: string;
  /** How many `data:` lines it had — the binding allows exactly one. */
  dataLines: number;
}

/**
 * An incremental `text/event-stream` parser (WHATWG HTML §9.2.6), fed decoded
 * text in whatever chunks the network delivers.
 */
export class SseParser {
  private buf = "";
  private data: string[] = [];
  private id: string | undefined;
  private event: string | undefined;
  /** The last `retry:` the server sent, in ms. */
  retryMs: number | undefined;

  push(text: string): SseEvent[] {
    this.buf += text;
    const out: SseEvent[] = [];
    for (;;) {
      const m = /\r\n|\r|\n/.exec(this.buf);
      if (!m) break;
      // A lone `\r` at the very end may be the first half of `\r\n`.
      if (m[0] === "\r" && m.index === this.buf.length - 1) break;
      const line = this.buf.slice(0, m.index);
      this.buf = this.buf.slice(m.index + m[0].length);
      const ev = this.line(line);
      if (ev) out.push(ev);
    }
    return out;
  }

  private line(line: string): SseEvent | null {
    if (line === "") {
      if (this.data.length === 0) {
        this.event = undefined;
        return null;
      }
      const ev: SseEvent = {
        data: this.data.join("\n"),
        dataLines: this.data.length,
        ...(this.id !== undefined ? { id: this.id } : {}),
        ...(this.event !== undefined ? { event: this.event } : {}),
      };
      this.data = [];
      this.event = undefined;
      return ev;
    }
    if (line.startsWith(":")) return null; // a comment: the heartbeat
    const colon = line.indexOf(":");
    const field = colon < 0 ? line : line.slice(0, colon);
    let value = colon < 0 ? "" : line.slice(colon + 1);
    if (value.startsWith(" ")) value = value.slice(1);
    switch (field) {
      case "data":
        this.data.push(value);
        break;
      case "id":
        if (!value.includes("\0")) this.id = value;
        break;
      case "event":
        this.event = value;
        break;
      case "retry":
        if (/^\d+$/.test(value)) this.retryMs = Number(value);
        break;
    }
    return null;
  }
}

// ─── the client ─────────────────────────────────────────────────────────

/** Why one connection ended — decides whether and how soon to retry. */
type Ended = { final: true } | { final: false };

export class LiveEvents {
  private stopped = true;
  private controller: AbortController | null = null;
  private since: string | undefined;
  private effective: Topic[] = [];
  private heartbeatMs = 0;
  private silenceTimer: ReturnType<typeof setTimeout> | null = null;
  private retryTimer: ReturnType<typeof setTimeout> | null = null;
  private attempt = 0;
  private retryFloorMs = 0;
  private current: LiveStatus = "offline";

  constructor(
    private readonly topics: readonly Topic[],
    private readonly handlers: LiveEventsHandlers,
    private readonly deps: LiveEventsDeps,
  ) {}

  get status(): LiveStatus {
    return this.current;
  }

  /** The latest resume token held — only in memory, only for this session. */
  get resumeToken(): string | undefined {
    return this.since;
  }

  start(): void {
    if (!this.stopped) return;
    this.stopped = false;
    void this.connect();
  }

  stop(): void {
    this.stopped = true;
    this.clearTimers();
    this.controller?.abort();
    this.controller = null;
    this.setStatus("offline");
  }

  private setStatus(s: LiveStatus): void {
    if (s === this.current) return;
    this.current = s;
    this.handlers.onStatus(s);
  }

  private clearTimers(): void {
    if (this.silenceTimer) clearTimeout(this.silenceTimer);
    if (this.retryTimer) clearTimeout(this.retryTimer);
    this.silenceTimer = null;
    this.retryTimer = null;
  }

  /** Bytes arrived: the stream is alive for another two heartbeats. */
  private touch(): void {
    if (this.silenceTimer) clearTimeout(this.silenceTimer);
    if (this.heartbeatMs <= 0) return;
    this.silenceTimer = setTimeout(() => {
      // Silent for twice the heartbeat: dead (binding 0.3 §2.1.2 item 5).
      this.controller?.abort();
    }, this.heartbeatMs * 2);
  }

  private async connect(): Promise<void> {
    if (this.stopped) return;
    this.setStatus("connecting");
    const controller = new AbortController();
    this.controller = controller;
    // Nothing at all — not even the #response — for twice the longest
    // heartbeat is as dead as a silent stream.
    this.heartbeatMs = MAX_HEARTBEAT_MS;
    this.touch();
    let ended: Ended;
    try {
      ended = await this.once(controller);
    } catch {
      ended = { final: false };
    }
    if (this.silenceTimer) clearTimeout(this.silenceTimer);
    this.silenceTimer = null;
    controller.abort();
    if (this.stopped) return;
    // Offline at once, and every topic re-read: the polls take over.
    const wasLive = this.current === "live";
    this.setStatus("offline");
    if (wasLive) this.handlers.onResync(this.effective);
    if (ended.final) return;
    const exp = Math.min(BACKOFF_MAX_MS, BACKOFF_BASE_MS * 2 ** this.attempt);
    const random = this.deps.random ?? Math.random;
    const delay = Math.max(this.retryFloorMs, exp / 2 + (random() * exp) / 2);
    this.attempt = Math.min(this.attempt + 1, 16);
    this.retryTimer = setTimeout(() => void this.connect(), delay);
  }

  /** One subscribe and, if it opens, the stream it opened. */
  private async once(controller: AbortController): Promise<Ended> {
    let doc: SignedSubscribe;
    try {
      doc = await this.deps.sign({
        topics: [...this.topics],
        ...(this.since ? { since: this.since } : {}),
      });
    } catch (e) {
      // No key or no Ed25519 in this browser: nothing to sign with, so
      // nothing will change by retrying.
      return { final: (e as Error)?.name === "SigningUnavailableError" };
    }
    const headers: Record<string, string> = {
      "Content-Type": "application/json",
      Accept: STREAM_ACCEPT,
    };
    const csrf = this.deps.csrf?.();
    if (csrf) headers["X-CSRF-Token"] = csrf;
    // Diagnostics only: the server resumes from `since`, in-band.
    if (this.since) headers["Last-Event-ID"] = this.since;

    const res = await this.deps.fetch("/v1/trust-tasks", {
      method: "POST",
      credentials: "include",
      headers,
      body: JSON.stringify(doc),
      signal: controller.signal,
    });
    const type = res.headers.get("Content-Type") ?? "";
    if (!type.startsWith("text/event-stream") || !res.body) {
      // Answered in JSON: a refusal, or a server that does not stream.
      const body = (await res.json().catch(() => null)) as {
        payload?: { code?: unknown };
      } | null;
      const code = localCode(body?.payload?.code);
      if (res.ok && !code) return { final: true }; // a 0.2 server: poll
      return { final: FINAL_CODES.includes(code) };
    }
    return this.read(res.body, doc, controller);
  }

  private async read(
    body: ReadableStream<Uint8Array>,
    doc: SignedSubscribe,
    controller: AbortController,
  ): Promise<Ended> {
    const reader = body.getReader();
    const onAbort = () => void reader.cancel().catch(() => undefined);
    controller.signal.addEventListener("abort", onAbort);
    const decoder = new TextDecoder();
    const parser = new SseParser();
    let opened = false;
    try {
      for (;;) {
        const { done, value } = await reader.read();
        if (done || controller.signal.aborted) return { final: false };
        this.touch();
        for (const ev of parser.push(decoder.decode(value, { stream: true }))) {
          if (parser.retryMs !== undefined) this.retryFloorMs = parser.retryMs;
          const result = this.handle(ev, doc, opened);
          if (result === "close") return { final: false };
          if (result === "opened") {
            opened = true;
            this.touch();
          }
        }
      }
    } finally {
      controller.signal.removeEventListener("abort", onAbort);
    }
  }

  /** One event. A framing or identity fault closes the stream (§2.1.2, §2.1.5). */
  private handle(
    ev: SseEvent,
    doc: SignedSubscribe,
    opened: boolean,
  ): "opened" | "ok" | "close" {
    if (ev.event !== undefined || ev.dataLines !== 1) return "close";
    let parsed: {
      type?: unknown;
      issuer?: unknown;
      recipient?: unknown;
      payload?: Record<string, unknown>;
    };
    try {
      parsed = JSON.parse(ev.data);
    } catch {
      return "close";
    }
    if (!parsed || typeof parsed !== "object" || typeof parsed.type !== "string") {
      return "close";
    }
    // Streamed documents come from the community the subscribe addressed, to
    // the key that signed it; anything else has no business here.
    if (parsed.issuer !== doc.recipient || parsed.recipient !== doc.issuer) return "close";
    const payload = parsed.payload ?? {};

    if (!opened) {
      // The #response is first, or this is not the stream we asked for.
      if (parsed.type !== RESPONSE_TYPE) return "close";
      const topics = Array.isArray(payload.topics)
        ? (payload.topics as unknown[]).filter((t): t is Topic =>
            (ALL_TOPICS as readonly unknown[]).includes(t),
          )
        : [];
      const hb = Number(payload.heartbeatSeconds);
      if (topics.length === 0 || !Number.isFinite(hb) || hb < 5 || hb > 60) return "close";
      this.effective = topics;
      this.heartbeatMs = hb * 1000;
      if (typeof payload.resumeToken === "string") this.since = payload.resumeToken;
      this.attempt = 0;
      this.setStatus("live");
      // Not resumed: changes may have been missed while away.
      if (payload.resumed !== true) this.handlers.onResync(topics);
      return "opened";
    }

    if (parsed.type !== EVENT_TASK) return "ok"; // not a hint: discard
    const topic = payload.topic as Topic;
    if (!this.effective.includes(topic)) return "ok"; // not ours: discard
    if (typeof payload.resumeToken === "string") this.since = payload.resumeToken;
    const count =
      COUNT_TOPICS.includes(topic) && typeof payload.count === "number"
        ? payload.count
        : undefined;
    this.handlers.onHint(topic, count);
    return "ok";
  }
}
