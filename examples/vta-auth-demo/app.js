// VTA auth demo — vanilla JS, no build step.
//
// Five flows exercised here:
//
//   2. Bootstrap auth — paste a JWT from `pnm auth show-token` to
//      skip passkey login. Unlocks the enrol + session + trust-task
//      panels.
//   3. Enrol a passkey VM — POST challenge → navigator.credentials.create()
//      → compute publicKeyMultibase from the SPKI → POST submit.
//   4. Passkey login — POST start → navigator.credentials.get() →
//      POST finish → JWT.
//   5. Session inspection + revoke — the auth/sessions/list/0.1 and
//      auth/revoke-session/0.2 Trust Tasks (the REST session routes are gone).
//   6. Trust-task dispatch — POST /api/trust-tasks with a typed
//      envelope.
//
// The legacy challenge/authenticate flow is DIDComm-message-based and
// not browser-friendly; use `pnm auth` for that path. See README.

// ─── State ────────────────────────────────────────────────────────────

const state = {
  vtaUrl: null,
  loginSessionId: null,
  loginChallenge: null,
  loginAllowCredentials: [],
  accessToken: null,
  refreshToken: null,
  accessExpiresAt: null,
  currentSessionId: null,
  role: null,
};

// Known trust-task URIs. Curated subset of vta-sdk::trust_tasks::ALL_URIS
// — the ones a freshly-authenticated operator can actually exercise
// without other setup. The dropdown drives the type field; the
// payload textarea is operator-editable.
const KNOWN_URIS = [
  {
    label: "discovery/capabilities — list VTA features",
    type: "https://trusttasks.org/spec/vta/discovery/capabilities/1.0",
    payload: {},
  },
  {
    label: "config/get — read VTA configuration",
    type: "https://trusttasks.org/spec/vta/config/get/1.0",
    payload: {},
  },
  {
    label: "acl/list — list ACL entries",
    type: "https://trusttasks.org/spec/vta/acl/list/1.0",
    payload: {},
  },
  {
    label: "contexts/list — list contexts",
    type: "https://trusttasks.org/spec/vta/contexts/list/1.0",
    payload: {},
  },
  {
    label: "keys/list — list keys",
    type: "https://trusttasks.org/spec/vta/keys/list/1.0",
    payload: {},
  },
  {
    label: "seeds/list — list seed records",
    type: "https://trusttasks.org/spec/vta/seeds/list/1.0",
    payload: {},
  },
  {
    label: "audit/list-logs — list audit log entries",
    type: "https://trusttasks.org/spec/vta/audit/list-logs/1.0",
    payload: {},
  },
];

// ─── DOM ──────────────────────────────────────────────────────────────

const $ = (id) => document.getElementById(id);

const els = {
  vtaUrl: $("vtaUrl"),
  checkHealth: $("checkHealth"),
  healthStatus: $("healthStatus"),

  bootstrapJwt: $("bootstrapJwt"),
  bootstrapApply: $("bootstrapApply"),
  bootstrapStatus: $("bootstrapStatus"),

  enrolDid: $("enrolDid"),
  enrolLabel: $("enrolLabel"),
  enrolStart: $("enrolStart"),
  enrolOutput: $("enrolOutput"),

  loginDid: $("loginDid"),
  loginStart: $("loginStart"),
  loginFinish: $("loginFinish"),
  loginOutput: $("loginOutput"),

  sessionSection: $("sessionSection"),
  tokenDisplay: $("tokenDisplay"),
  sessionIdDisplay: $("sessionIdDisplay"),
  roleDisplay: $("roleDisplay"),
  expiresIn: $("expiresIn"),
  listSessions: $("listSessions"),
  revokeCurrent: $("revokeCurrent"),
  signOut: $("signOut"),
  sessionsOutput: $("sessionsOutput"),

  trustTasksSection: $("trustTasksSection"),
  taskUri: $("taskUri"),
  taskPayload: $("taskPayload"),
  sendTask: $("sendTask"),
  taskOutput: $("taskOutput"),

  dcRecipientDid: $("dcRecipientDid"),
  dcBody: $("dcBody"),
  dcResolve: $("dcResolve"),
  dcPack: $("dcPack"),
  dcOutput: $("dcOutput"),

  daVtaDid: $("daVtaDid"),
  daGenerate: $("daGenerate"),
  daAuthenticate: $("daAuthenticate"),
  daRefresh: $("daRefresh"),
  daOutput: $("daOutput"),

  dmVtaDid: $("dmVtaDid"),
  dmMediatorDid: $("dmMediatorDid"),
  dmConnect: $("dmConnect"),
  dmOutput: $("dmOutput"),
};

// ─── Utilities ────────────────────────────────────────────────────────

function baseUrl() {
  return els.vtaUrl.value.trim().replace(/\/+$/, "");
}

function setOutput(el, text, kind = "ok") {
  el.textContent = text;
  el.className = `output ${kind}`;
}

function clearOutput(el) {
  el.textContent = "";
  el.className = "output";
}

// base64url ⇄ Uint8Array helpers. WebAuthn surfaces ArrayBuffers; the
// wire format is base64url-without-padding.
function b64urlEncode(bytes) {
  let bin = "";
  bytes.forEach((b) => (bin += String.fromCharCode(b)));
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function b64urlDecode(s) {
  const pad = (s.length % 4 === 0) ? "" : "=".repeat(4 - (s.length % 4));
  const std = (s + pad).replace(/-/g, "+").replace(/_/g, "/");
  const bin = atob(std);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function hexToBytes(hex) {
  if (hex.length % 2 !== 0) throw new Error("hex string has odd length");
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function decodeJwtPayload(jwt) {
  const parts = jwt.split(".");
  if (parts.length !== 3) return null;
  try {
    const padded = parts[1] + "=".repeat((4 - (parts[1].length % 4)) % 4);
    const std = padded.replace(/-/g, "+").replace(/_/g, "/");
    return JSON.parse(atob(std));
  } catch {
    return null;
  }
}

function asJson(obj) {
  return JSON.stringify(obj, null, 2);
}

// Wrap fetch with a uniform error path: non-2xx becomes a thrown
// Error with the response body included so the operator can see what
// the VTA said. Saves rewriting error handling in every flow.
async function vtaFetch(path, opts = {}) {
  const url = `${baseUrl()}${path}`;
  const res = await fetch(url, opts);
  const text = await res.text();
  let body;
  try {
    body = text ? JSON.parse(text) : null;
  } catch {
    body = text;
  }
  if (!res.ok) {
    const detail = typeof body === "string" ? body : asJson(body);
    throw new Error(`HTTP ${res.status} ${res.statusText}\n${detail}`);
  }
  return body;
}

// ─── Multikey computation (ES256 only) ────────────────────────────────
//
// The VTA's passkey-VM submit endpoint requires `publicKeyMultibase`
// to match what the server re-derives from the attestation
// authenticatorData. Mismatches are rejected as `PublicKeyMismatch`.
//
// We compute it browser-side from the WebAuthn AttestationResponse's
// `getPublicKey()` output (SPKI-encoded), which is a much simpler
// path than parsing the attestationObject's CBOR ourselves.
//
// Only ES256 (P-256, COSE algorithm -7) is supported here. Modern
// platform authenticators (Touch ID, Face ID, Windows Hello) all use
// ES256 by default; if your authenticator returns Ed25519, the
// `enrolPasskey` path errors out and you'll need to extend this.

// Compress a SEC1 uncompressed P-256 point (04 || X[32] || Y[32]) to
// 33-byte compressed form (02/03 || X[32]) based on Y's parity.
function compressP256(uncompressed) {
  if (uncompressed.length !== 65 || uncompressed[0] !== 0x04) {
    throw new Error(
      `expected SEC1 uncompressed P-256 point (65 bytes starting 04); got ${uncompressed.length} bytes starting ${uncompressed[0]}`,
    );
  }
  const x = uncompressed.slice(1, 33);
  const y = uncompressed.slice(33, 65);
  const prefix = (y[31] & 1) === 0 ? 0x02 : 0x03;
  const out = new Uint8Array(33);
  out[0] = prefix;
  out.set(x, 1);
  return out;
}

// Extract the SEC1 uncompressed point from an SPKI-encoded P-256
// public key. SPKI for a P-256 pubkey ends with a BIT STRING whose
// content is `00 04 X Y` — we walk the DER just enough to land on
// the trailing 65 bytes.
//
// Rather than implementing a full DER parser, we exploit that
// SPKI(P-256) has a fixed 26-byte algorithm-identifier prefix
// followed by `03 42 00 04 X Y`. The trailing 66 bytes are
// predictable: `03 42 00 04 X[32] Y[32]`.
function spkiToSec1P256(spki) {
  if (spki.length < 66) {
    throw new Error(`SPKI too short for P-256 (${spki.length} bytes)`);
  }
  const tail = spki.slice(spki.length - 66);
  if (tail[0] !== 0x03 || tail[1] !== 0x42 || tail[2] !== 0x00 || tail[3] !== 0x04) {
    throw new Error(
      `SPKI tail doesn't match P-256 BIT STRING shape (got ${Array.from(tail.slice(0, 4))
        .map((b) => b.toString(16).padStart(2, "0"))
        .join(" ")})`,
    );
  }
  return tail.slice(3); // 04 X[32] Y[32]
}

// Encode a byte sequence as base58btc per the multibase spec.
const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

function base58btcEncode(bytes) {
  if (bytes.length === 0) return "";
  // Count leading zero bytes.
  let zeros = 0;
  while (zeros < bytes.length && bytes[zeros] === 0) zeros++;

  const digits = [];
  for (let i = zeros; i < bytes.length; i++) {
    let carry = bytes[i];
    for (let j = 0; j < digits.length; j++) {
      carry += digits[j] << 8;
      digits[j] = carry % 58;
      carry = (carry / 58) | 0;
    }
    while (carry > 0) {
      digits.push(carry % 58);
      carry = (carry / 58) | 0;
    }
  }

  let s = "";
  for (let i = 0; i < zeros; i++) s += "1";
  for (let i = digits.length - 1; i >= 0; i--) s += B58[digits[i]];
  return s;
}

// Build a P-256 Multikey from the WebAuthn AttestationResponse.
// Returns the base58btc-encoded multibase string (`z…`).
function p256AttestationToMultikey(attestationResponse) {
  const spki = new Uint8Array(attestationResponse.getPublicKey());
  const sec1 = spkiToSec1P256(spki);
  const compressed = compressP256(sec1);
  // Multicodec 0x1200 (p256-pub) in unsigned-varint = 0x80 0x24.
  const multikey = new Uint8Array(2 + compressed.length);
  multikey[0] = 0x80;
  multikey[1] = 0x24;
  multikey.set(compressed, 2);
  return "z" + base58btcEncode(multikey);
}

// ─── Health ───────────────────────────────────────────────────────────

els.checkHealth.addEventListener("click", async () => {
  els.healthStatus.textContent = "checking…";
  els.healthStatus.className = "status muted";
  try {
    const body = await vtaFetch("/health");
    els.healthStatus.textContent = `OK · ${body?.status ?? "responding"}`;
    els.healthStatus.className = "status ok";
  } catch (e) {
    // Either the VTA is down, the URL is wrong, or CORS is blocking us.
    // The browser console will have the CORS message in the latter case.
    els.healthStatus.textContent = `error · ${e.message.split("\n")[0]}`;
    els.healthStatus.className = "status err";
  }
});

// ─── Bootstrap (paste JWT) ────────────────────────────────────────────

els.bootstrapApply.addEventListener("click", () => {
  const raw = els.bootstrapJwt.value.trim();
  if (!raw) {
    els.bootstrapStatus.textContent = "paste a JWT first";
    els.bootstrapStatus.className = "status err";
    return;
  }
  const claims = decodeJwtPayload(raw);
  if (!claims) {
    els.bootstrapStatus.textContent = "doesn't look like a JWT (need three dot-separated segments)";
    els.bootstrapStatus.className = "status err";
    return;
  }
  // Synthesize an AuthenticateResponse-shaped object so the same
  // storeAuth() path the passkey-login Finish step uses also handles
  // the paste case.
  storeAuth({
    sessionId: claims.session_id || null,
    data: {
      accessToken: raw,
      accessExpiresAt: claims.exp || 0,
      refreshToken: null,
      refreshExpiresAt: null,
    },
  });
  els.bootstrapStatus.textContent = `JWT accepted · role=${claims.role ?? "unknown"} · exp=${claims.exp ? new Date(claims.exp * 1000).toISOString() : "n/a"}`;
  els.bootstrapStatus.className = "status ok";
});

// ─── Passkey enrolment ───────────────────────────────────────────────

els.enrolStart.addEventListener("click", async () => {
  clearOutput(els.enrolOutput);
  if (!state.accessToken) {
    setOutput(els.enrolOutput, "No access token. Paste one in Step 2 first.", "err");
    return;
  }
  const did = els.enrolDid.value.trim();
  if (!did) {
    setOutput(els.enrolOutput, "Target DID is required.", "err");
    return;
  }
  const label = els.enrolLabel.value.trim() || null;

  try {
    // 1. Request a registration challenge from the VTA.
    const ceremony = await vtaFetch(
      `/did/verification-methods/passkey/challenge?did=${encodeURIComponent(did)}`,
      {
        method: "POST",
        headers: {
          "content-type": "application/json",
          authorization: `Bearer ${state.accessToken}`,
        },
        body: JSON.stringify({ did, label }),
      },
    );

    // 2. Run the WebAuthn registration ceremony.
    //
    // `challenge` and `userHandle` arrive as base64url-encoded byte
    // strings; the WebAuthn API wants ArrayBuffers of those bytes.
    const publicKey = {
      challenge: b64urlDecode(ceremony.challenge),
      rp: { id: ceremony.rpId, name: ceremony.rpName },
      user: {
        id: b64urlDecode(ceremony.userHandle),
        name: ceremony.userName,
        displayName: ceremony.userDisplayName,
      },
      pubKeyCredParams: [
        { type: "public-key", alg: -7 }, // ES256 (P-256). Only ES256 is supported in this demo.
      ],
      timeout: ceremony.timeoutMs || 60_000,
      authenticatorSelection: {
        // `platform` = Touch ID / Face ID / Windows Hello. Use
        // `cross-platform` for security keys / hybrid (phone). Leave
        // unset to accept any.
        userVerification: "preferred",
        residentKey: "preferred",
      },
      attestation: "none",
    };

    const credential = await navigator.credentials.create({ publicKey });
    if (!credential) {
      setOutput(els.enrolOutput, "Browser returned no credential.", "err");
      return;
    }

    // 3. Extract the public key and compute the multikey.
    //
    // `getPublicKeyAlgorithm()` and `getPublicKey()` are WebAuthn L3
    // additions (Chrome 85+, Safari 15.4+, Firefox 119+). They give
    // us the COSE algorithm number and the SPKI-encoded public key —
    // simpler than parsing the attestationObject CBOR ourselves.
    const alg = credential.response.getPublicKeyAlgorithm();
    if (alg !== -7) {
      setOutput(
        els.enrolOutput,
        `This demo only supports ES256 (-7). Authenticator returned algorithm ${alg}. Use a platform authenticator (Touch ID / Face ID / Windows Hello), which default to ES256.`,
        "err",
      );
      return;
    }
    const publicKeyMultibase = p256AttestationToMultikey(credential.response);

    // 4. Build the submit body and POST.
    const ad = new Uint8Array(credential.response.getAuthenticatorData());
    const ao = new Uint8Array(credential.response.attestationObject);
    const cd = new Uint8Array(credential.response.clientDataJSON);
    const rawId = new Uint8Array(credential.rawId);
    const transports =
      typeof credential.response.getTransports === "function"
        ? credential.response.getTransports()
        : [];

    const submitBody = {
      did,
      ceremonyId: ceremony.ceremonyId,
      credentialId: b64urlEncode(rawId),
      publicKeyMultibase,
      coseAlgorithm: alg,
      attestationObject: b64urlEncode(ao),
      clientDataJson: b64urlEncode(cd),
      authenticatorData: b64urlEncode(ad),
      transports,
      label,
    };

    const result = await vtaFetch("/did/verification-methods/passkey", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${state.accessToken}`,
      },
      body: JSON.stringify(submitBody),
    });

    setOutput(
      els.enrolOutput,
      `Passkey enrolled.\n\nMultikey: ${publicKeyMultibase}\nVM id: ${result.verificationMethod.id}\nWebVH version: ${result.webvhVersion}\n\nFull response:\n${asJson(result)}`,
      "ok",
    );
    // Helpful default: pre-fill the login DID so the operator can
    // immediately test passkey login with the just-enrolled VM.
    if (!els.loginDid.value.trim()) {
      els.loginDid.value = did;
    }
  } catch (e) {
    setOutput(els.enrolOutput, e.message, "err");
  }
});

// ─── Passkey login ────────────────────────────────────────────────────

els.loginStart.addEventListener("click", async () => {
  const did = els.loginDid.value.trim();
  if (!did) {
    setOutput(els.loginOutput, "DID is required", "err");
    return;
  }
  clearOutput(els.loginOutput);
  try {
    const resp = await vtaFetch("/auth/passkey-login/start", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ did }),
    });
    state.loginSessionId = resp.sessionId;
    state.loginChallenge = resp.challenge;
    state.loginAllowCredentials = resp.allowCredentials || [];
    setOutput(
      els.loginOutput,
      `Challenge received:\n${asJson(resp)}\n\nClick "Finish" to invoke the browser's WebAuthn API.`,
      "ok",
    );
    els.loginFinish.disabled = false;
  } catch (e) {
    setOutput(els.loginOutput, e.message, "err");
  }
});

els.loginFinish.addEventListener("click", async () => {
  clearOutput(els.loginOutput);
  if (!state.loginSessionId || !state.loginChallenge) {
    setOutput(els.loginOutput, "Run Start first.", "err");
    return;
  }
  try {
    // Server-side challenge is hex-encoded 32 bytes; WebAuthn wants
    // an ArrayBuffer of those bytes.
    const challengeBytes = hexToBytes(state.loginChallenge);
    const allowCredentials = state.loginAllowCredentials.map((id) => ({
      id: b64urlDecode(id),
      type: "public-key",
    }));

    const assertion = await navigator.credentials.get({
      publicKey: {
        challenge: challengeBytes,
        allowCredentials,
        userVerification: "preferred",
        timeout: 60_000,
      },
    });

    if (!assertion) {
      setOutput(els.loginOutput, "Browser returned no credential.", "err");
      return;
    }

    const ad = new Uint8Array(assertion.response.authenticatorData);
    const cd = new Uint8Array(assertion.response.clientDataJSON);
    const sig = new Uint8Array(assertion.response.signature);
    const credId = new Uint8Array(assertion.rawId);

    // The browser doesn't tell us which DID-doc VM was used — the
    // server resolves the DID and matches credential_id against the
    // published verificationMethods.
    const reqBody = {
      sessionId: state.loginSessionId,
      credentialId: b64urlEncode(credId),
      authenticatorData: b64urlEncode(ad),
      clientDataJSON: b64urlEncode(cd),
      signature: b64urlEncode(sig),
      verificationMethod: "",
    };

    const resp = await vtaFetch("/auth/passkey-login/finish", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(reqBody),
    });

    storeAuth(resp);
    setOutput(els.loginOutput, `Authenticated.\n${asJson(resp)}`, "ok");
  } catch (e) {
    setOutput(els.loginOutput, e.message, "err");
  }
});

// ─── Auth state UI ────────────────────────────────────────────────────

function storeAuth(authResponse) {
  state.accessToken = authResponse.data.accessToken;
  state.refreshToken = authResponse.data.refreshToken || null;
  state.accessExpiresAt = authResponse.data.accessExpiresAt;
  state.currentSessionId = authResponse.sessionId || null;

  const claims = decodeJwtPayload(state.accessToken);
  state.role = claims?.role || null;

  els.tokenDisplay.textContent = state.accessToken;
  els.sessionIdDisplay.textContent = state.currentSessionId || "(unknown)";
  els.roleDisplay.textContent = state.role || "(unknown)";

  els.sessionSection.classList.remove("hidden");
  els.trustTasksSection.classList.remove("hidden");
  els.loginFinish.disabled = true;

  renderExpiresIn();
}

let expiresTimer = null;
function renderExpiresIn() {
  if (expiresTimer) clearInterval(expiresTimer);
  const tick = () => {
    if (!state.accessExpiresAt) return;
    const nowSec = Math.floor(Date.now() / 1000);
    const remaining = state.accessExpiresAt - nowSec;
    if (remaining <= 0) {
      els.expiresIn.textContent = "EXPIRED";
      els.expiresIn.style.color = "var(--err)";
      clearInterval(expiresTimer);
      return;
    }
    const mins = Math.floor(remaining / 60);
    const secs = remaining % 60;
    els.expiresIn.textContent = `${mins}m ${secs}s`;
    els.expiresIn.style.color = remaining < 60 ? "var(--warn)" : "var(--ok)";
  };
  tick();
  expiresTimer = setInterval(tick, 1000);
}

function clearAuth() {
  state.accessToken = null;
  state.refreshToken = null;
  state.accessExpiresAt = null;
  state.currentSessionId = null;
  state.role = null;
  if (expiresTimer) clearInterval(expiresTimer);
  els.sessionSection.classList.add("hidden");
  els.trustTasksSection.classList.add("hidden");
  els.bootstrapJwt.value = "";
  els.bootstrapStatus.textContent = "";
  els.bootstrapStatus.className = "status muted";
  clearOutput(els.loginOutput);
  clearOutput(els.sessionsOutput);
  clearOutput(els.taskOutput);
  clearOutput(els.enrolOutput);
}

els.signOut.addEventListener("click", clearAuth);

// ─── Session list + revoke ────────────────────────────────────────────
//
// Trust Tasks, through the same POST path as Step 6. Both declare their
// request proof REQUIRED, and this demo holds only a bearer token — no key to
// sign with — so a VTA enforcing the specification answers `proofRequired`.
// The request/response pair is shown either way; sign with `pnm` for the real
// thing.

const TASK_SESSIONS_LIST = "https://trusttasks.org/spec/auth/sessions/list/0.1";
const TASK_REVOKE_SESSION = "https://trusttasks.org/spec/auth/revoke-session/0.2";

els.listSessions.addEventListener("click", async () => {
  clearOutput(els.sessionsOutput);
  try {
    const { envelope, resp } = await postTrustTask(TASK_SESSIONS_LIST, {});
    setOutput(
      els.sessionsOutput,
      `Request:\n${asJson(envelope)}\n\nResponse:\n${asJson(resp)}`,
      "ok",
    );
  } catch (e) {
    setOutput(els.sessionsOutput, e.message, "err");
  }
});

els.revokeCurrent.addEventListener("click", async () => {
  if (!state.currentSessionId) {
    setOutput(els.sessionsOutput, "No current session id (re-login).", "err");
    return;
  }
  if (!confirm(`Revoke session ${state.currentSessionId}?`)) return;
  clearOutput(els.sessionsOutput);
  try {
    const { envelope, resp } = await postTrustTask(TASK_REVOKE_SESSION, {
      sessionId: state.currentSessionId,
      reason: "logout",
    });
    setOutput(
      els.sessionsOutput,
      `Request:\n${asJson(envelope)}\n\nResponse:\n${asJson(resp)}\n\n` +
        "revokedCount 1: the token will no longer authenticate.",
      "ok",
    );
    // Don't fully clearAuth() so the operator can see the 401 by
    // re-trying — that's an educational side-effect of the demo.
  } catch (e) {
    setOutput(els.sessionsOutput, e.message, "err");
  }
});

// ─── Trust-task dispatch ──────────────────────────────────────────────

// POST a Trust Task document to the VTA's HTTPS binding on the bearer
// session. `issuedAt` is required: the VTA bounds its replay record by it.
async function postTrustTask(type, payload) {
  const envelope = {
    id: `urn:uuid:${crypto.randomUUID()}`,
    type,
    issuedAt: new Date().toISOString().replace(/\.\d{3}Z$/, "Z"),
    payload,
  };
  const resp = await vtaFetch("/trust-tasks", {
    method: "POST",
    headers: {
      "content-type": "application/json",
      authorization: `Bearer ${state.accessToken}`,
    },
    body: JSON.stringify(envelope),
  });
  return { envelope, resp };
}

function populateUriDropdown() {
  els.taskUri.innerHTML = "";
  KNOWN_URIS.forEach((u, i) => {
    const opt = document.createElement("option");
    opt.value = i;
    opt.textContent = u.label;
    els.taskUri.appendChild(opt);
  });
  // Initialise payload to the first entry's body.
  els.taskPayload.value = asJson(KNOWN_URIS[0].payload);
}

els.taskUri.addEventListener("change", () => {
  const idx = parseInt(els.taskUri.value, 10);
  els.taskPayload.value = asJson(KNOWN_URIS[idx].payload);
});

els.sendTask.addEventListener("click", async () => {
  clearOutput(els.taskOutput);
  const idx = parseInt(els.taskUri.value, 10);
  const type = KNOWN_URIS[idx].type;
  let payload;
  try {
    payload = JSON.parse(els.taskPayload.value);
  } catch (e) {
    setOutput(els.taskOutput, `Payload is not valid JSON: ${e.message}`, "err");
    return;
  }
  try {
    const { envelope, resp } = await postTrustTask(type, payload);
    setOutput(
      els.taskOutput,
      `Request:\n${asJson(envelope)}\n\nResponse:\n${asJson(resp)}`,
      "ok",
    );
  } catch (e) {
    setOutput(els.taskOutput, e.message, "err");
  }
});

// ─── Section 7: DIDComm primitives (vti-didcomm-js) ──────────────────
//
// Smoke-test for the browser-side DIDComm stack:
//   - Resolve the recipient DID (did:key offline, did:webvh over HTTPS).
//   - If a keyAgreement key exists, generate an ephemeral sender DID
//     and pack an authcrypt JWE addressed to it.
//
// The JWE is shown verbatim — there is no VTA round-trip from this
// section. The point is "the lib works in the browser".
//
// The vti-didcomm-js bundle is built via `npm run build:demo` in
// `vti-didcomm-js/`. We load it lazily on first click so the demo's
// other sections don't pay the 100 KB cost on initial page load.

let didcommLib = null;
async function loadDidcommLib() {
  if (didcommLib) return didcommLib;
  try {
    didcommLib = await import("./vendor/vti-didcomm-js.js");
  } catch (e) {
    throw new Error(
      `Failed to load ./vendor/vti-didcomm-js.js — run "npm run build:demo" in vti-didcomm-js/ to (re)generate it. (${e.message})`,
    );
  }
  return didcommLib;
}

/**
 * Find the first keyAgreement verification method on a DID document
 * and return its raw 32-byte X25519 public key + the multibase-encoded
 * `kid` for use as the recipient's `kid` in pack().
 */
function findKeyAgreement(didDocument, lib) {
  const ka = didDocument.keyAgreement;
  if (!ka || ka.length === 0) {
    throw new Error("DID document has no keyAgreement entries");
  }
  // `keyAgreement[i]` is either a fully-embedded verificationMethod
  // object or a reference (string id) into `verificationMethod[]`.
  let vm = ka[0];
  if (typeof vm === "string") {
    const found = (didDocument.verificationMethod ?? []).find((v) => v.id === vm);
    if (!found) throw new Error(`keyAgreement reference ${vm} not resolvable in verificationMethod[]`);
    vm = found;
  }
  if (!vm.publicKeyMultibase) {
    throw new Error("first keyAgreement entry has no publicKeyMultibase (only Multikey is supported in this demo)");
  }
  const { codec, key } = lib.multibase.decodeMultikey(vm.publicKeyMultibase);
  if (codec[0] !== 0xec || codec[1] !== 0x01) {
    throw new Error(`keyAgreement key is not X25519 (multicodec ${codec[0].toString(16)}${codec[1].toString(16)})`);
  }
  return { kid: vm.id, x25519Pub: key };
}

els.dcResolve.addEventListener("click", async () => {
  clearOutput(els.dcOutput);
  const did = els.dcRecipientDid.value.trim();
  if (!did) {
    setOutput(els.dcOutput, "Enter a recipient DID first.", "err");
    return;
  }
  try {
    const lib = await loadDidcommLib();
    const { didDocument, didDocumentMetadata } = await lib.resolve(did);
    setOutput(
      els.dcOutput,
      `Resolved ${did}\n\nDID Document:\n${asJson(didDocument)}\n\nMetadata:\n${asJson(didDocumentMetadata)}`,
      "ok",
    );
  } catch (e) {
    setOutput(els.dcOutput, e.message, "err");
  }
});

els.dcPack.addEventListener("click", async () => {
  clearOutput(els.dcOutput);
  const did = els.dcRecipientDid.value.trim();
  if (!did) {
    setOutput(els.dcOutput, "Enter a recipient DID first.", "err");
    return;
  }

  let body;
  try {
    body = JSON.parse(els.dcBody.value || "{}");
  } catch (e) {
    setOutput(els.dcOutput, `Message body is not valid JSON: ${e.message}`, "err");
    return;
  }

  try {
    const lib = await loadDidcommLib();

    // Step 1: resolve the recipient and locate its keyAgreement key.
    const { didDocument } = await lib.resolve(did);
    const recipient = findKeyAgreement(didDocument, lib);
    const recipientPublicJwk = lib.jwk.publicJwk("X25519", recipient.x25519Pub);

    // Step 2: generate an ephemeral X25519-only sender did:key.
    // authcrypt's sender binding is via ECDH-1PU's static-static
    // shared secret, so all we need is an X25519 keypair — no
    // Ed25519 signing key is needed for this showcase.
    const senderKeypair = lib.x25519.generateKeyPair();
    const senderPublicMultikey = lib.multibase.encodeMultikey(
      lib.multibase.MULTICODEC.X25519_PUB,
      senderKeypair.publicKey,
    );
    const senderDid = `did:key:${senderPublicMultikey}`;
    const senderKid = `${senderDid}#${senderPublicMultikey}`;
    const senderPrivateJwk = lib.jwk.privateJwk("X25519", senderKeypair.privateKey, senderKeypair.publicKey);

    // Step 3: pack.
    const message = {
      id: `urn:uuid:${crypto.randomUUID()}`,
      type: "https://example.com/demo/1.0",
      from: senderDid,
      to: [did],
      created_time: Math.floor(Date.now() / 1000),
      body,
    };
    const jwe = await lib.pack({
      message,
      sender: { kid: senderKid, privateJwk: senderPrivateJwk },
      recipient: { kid: recipient.kid, publicJwk: recipientPublicJwk },
    });

    setOutput(
      els.dcOutput,
      [
        `Ephemeral sender: ${senderDid}`,
        ``,
        `Plaintext message:`,
        asJson(message),
        ``,
        `Authcrypt JWE (${jwe.length} bytes):`,
        prettyJson(jwe),
        ``,
        `Recipient keyAgreement kid: ${recipient.kid}`,
        `Note: not delivered. This is a library smoke-test, not a transport.`,
      ].join("\n"),
      "ok",
    );
  } catch (e) {
    setOutput(els.dcOutput, e.message, "err");
  }
});

function prettyJson(s) {
  try {
    return JSON.stringify(JSON.parse(s), null, 2);
  } catch {
    return s;
  }
}

// ─── Section 8: DIDComm-packed /auth/ (vti-didcomm-js) ───────────────
//
// Drives the legacy challenge-response auth flow end-to-end from the
// browser, the same one PNM uses via the Rust auth_light client. On
// success we hand the JWT to `storeAuth(...)` so Sections 5/6 light up
// just like passkey login.

const ephemeralClient = {
  did: null,
  kid: null,
  privateKey: null,
  publicKey: null,
};

els.daGenerate.addEventListener("click", async () => {
  clearOutput(els.daOutput);
  try {
    const lib = await loadDidcommLib();
    const c = lib.vtaRestAuth.generateEphemeralClient();
    ephemeralClient.did = c.did;
    ephemeralClient.kid = c.kid;
    ephemeralClient.privateKey = c.privateKey;
    ephemeralClient.publicKey = c.publicKey;
    els.daAuthenticate.disabled = false;
    els.dmConnect.disabled = false;
    setOutput(
      els.daOutput,
      [
        `Generated ephemeral client DID:`,
        ``,
        `  ${c.did}`,
        ``,
        `Add it to the VTA's ACL before clicking Authenticate, e.g.:`,
        ``,
        `  pnm acl create --did ${c.did} --role admin --contexts <ctx>`,
        ``,
        `(The /auth/challenge handler ACL-gates the request — an unregistered`,
        `did:key will 403 at step 1.)`,
      ].join("\n"),
      "ok",
    );
  } catch (e) {
    setOutput(els.daOutput, e.message, "err");
  }
});

els.daAuthenticate.addEventListener("click", async () => {
  if (!ephemeralClient.privateKey) {
    setOutput(els.daOutput, "Generate an ephemeral client first.", "err");
    return;
  }
  const vtaDid = els.daVtaDid.value.trim();
  if (!vtaDid) {
    setOutput(els.daOutput, "Enter the VTA's DID first.", "err");
    return;
  }
  clearOutput(els.daOutput);

  try {
    const lib = await loadDidcommLib();
    const result = await lib.vtaRestAuth.authenticate({
      baseUrl: baseUrl(),
      vtaDid,
      clientDid: ephemeralClient.did,
      clientX25519Private: ephemeralClient.privateKey,
      clientX25519Public: ephemeralClient.publicKey,
      clientKid: ephemeralClient.kid,
    });

    // Reuse the existing session-store helper so Sections 5/6 light up
    // identically to passkey login.
    storeAuth({
      sessionId: result.sessionId,
      data: {
        accessToken: result.accessToken,
        accessExpiresAt: result.accessExpiresAt,
        refreshToken: result.refreshToken,
        refreshExpiresAt: result.refreshExpiresAt,
      },
    });

    // Enable refresh only if the VTA actually issued a refresh token.
    els.daRefresh.disabled = !result.refreshToken;

    setOutput(
      els.daOutput,
      [
        `Authenticated as: ${ephemeralClient.did}`,
        `Session id: ${result.sessionId ?? "(unknown)"}`,
        `Access token (truncated): ${result.accessToken.slice(0, 32)}…`,
        `Expires at: ${new Date(result.accessExpiresAt * 1000).toISOString()}`,
        result.refreshToken
          ? `Refresh token present (expires ${new Date((result.refreshExpiresAt ?? 0) * 1000).toISOString()}) — "Refresh access token" enabled.`
          : `No refresh token`,
      ].join("\n"),
      "ok",
    );
  } catch (e) {
    setOutput(els.daOutput, e.message, "err");
  }
});

els.daRefresh.addEventListener("click", async () => {
  if (!ephemeralClient.privateKey) {
    setOutput(els.daOutput, "Authenticate via Section 8 first.", "err");
    return;
  }
  if (!state.refreshToken) {
    setOutput(els.daOutput, "No refresh token in state — authenticate first.", "err");
    return;
  }
  const vtaDid = els.daVtaDid.value.trim();
  if (!vtaDid) {
    setOutput(els.daOutput, "Enter the VTA's DID first.", "err");
    return;
  }
  clearOutput(els.daOutput);

  try {
    const lib = await loadDidcommLib();
    const result = await lib.vtaRestAuth.refresh({
      baseUrl: baseUrl(),
      vtaDid,
      clientDid: ephemeralClient.did,
      clientX25519Private: ephemeralClient.privateKey,
      clientX25519Public: ephemeralClient.publicKey,
      clientKid: ephemeralClient.kid,
      // RFC 6749 §10.4 rotation: this token is single-use. storeAuth
      // below overwrites state.refreshToken with the rotated one.
      refreshToken: state.refreshToken,
    });

    storeAuth({
      sessionId: result.sessionId,
      data: {
        accessToken: result.accessToken,
        accessExpiresAt: result.accessExpiresAt,
        refreshToken: result.refreshToken,
        refreshExpiresAt: result.refreshExpiresAt,
      },
    });
    els.daRefresh.disabled = !result.refreshToken;

    setOutput(
      els.daOutput,
      [
        `Refreshed access token.`,
        `New access token (truncated): ${result.accessToken.slice(0, 32)}…`,
        `Expires at: ${new Date(result.accessExpiresAt * 1000).toISOString()}`,
        result.refreshToken
          ? `Refresh token rotated (the previous one is now single-use spent).`
          : `No new refresh token returned.`,
      ].join("\n"),
      "ok",
    );
  } catch (e) {
    setOutput(els.daOutput, e.message, "err");
  }
});

// ─── Section 9: DIDComm via mediator (vti-didcomm-js) ────────────────
//
// Routes a trust-ping browser → mediator → VTA → mediator → browser
// over a live WebSocket (message-pickup 3.0 live delivery), proving
// the mediator transport end-to-end. Reuses the Step 8 ephemeral
// client. The mediator DID is auto-derived from the VTA's
// #vta-didcomm service when the field is left blank.

const TRUST_PING_TYPE = "https://didcomm.org/trust-ping/2.0/ping";

/** Find the mediator DID in the VTA's DIDCommMessaging service. */
function deriveMediatorDid(vtaDidDocument) {
  const services = Array.isArray(vtaDidDocument.service) ? vtaDidDocument.service : [];
  const dc = services.find((s) => {
    const t = s?.type;
    return t === "DIDCommMessaging" || (Array.isArray(t) && t.includes("DIDCommMessaging"));
  });
  if (!dc) return null;
  const eps = Array.isArray(dc.serviceEndpoint) ? dc.serviceEndpoint : [dc.serviceEndpoint];
  for (const ep of eps) {
    const uri = typeof ep === "string" ? ep : ep?.uri;
    // The DIDComm service endpoint URI is the mediator's DID.
    if (typeof uri === "string" && uri.startsWith("did:")) return uri;
  }
  return null;
}

els.dmConnect.addEventListener("click", async () => {
  if (!ephemeralClient.privateKey) {
    setOutput(els.dmOutput, "Generate an ephemeral client DID in Step 8 first.", "err");
    return;
  }
  const vtaDid = els.dmVtaDid.value.trim();
  if (!vtaDid) {
    setOutput(els.dmOutput, "Enter the VTA's DID first.", "err");
    return;
  }
  clearOutput(els.dmOutput);

  let client = null;
  try {
    const lib = await loadDidcommLib();

    // Resolve the VTA to derive the mediator DID if not supplied.
    let mediatorDid = els.dmMediatorDid.value.trim();
    if (!mediatorDid) {
      const { didDocument } = await lib.resolve(vtaDid);
      mediatorDid = deriveMediatorDid(didDocument);
      if (!mediatorDid) {
        setOutput(
          els.dmOutput,
          "Could not auto-derive a mediator DID from the VTA's #vta-didcomm service — enter one manually.",
          "err",
        );
        return;
      }
    }

    setOutput(
      els.dmOutput,
      `Connecting via mediator…\n  VTA:      ${vtaDid}\n  Mediator: ${mediatorDid}\n  Client:   ${ephemeralClient.did}`,
      "ok",
    );

    client = await lib.connectVtaViaMediator({
      vtaDid,
      mediatorDid,
      clientDid: ephemeralClient.did,
      clientX25519Private: ephemeralClient.privateKey,
      clientX25519Public: ephemeralClient.publicKey,
      clientKid: ephemeralClient.kid,
    });

    const t0 = performance.now();
    const response = await client.sendAndWait(
      TRUST_PING_TYPE,
      { response_requested: true },
      30000,
    );
    const ms = Math.round(performance.now() - t0);

    setOutput(
      els.dmOutput,
      [
        `Round-trip OK via mediator (${ms} ms).`,
        ``,
        `Sent:     trust-ping  →  ${vtaDid}`,
        `Received: ${response.type}`,
        `thid:     ${response.thid ?? "(none)"}`,
        ``,
        `Full browser → mediator → VTA → mediator → browser DIDComm`,
        `round-trip proven. No VTA REST endpoint was used.`,
      ].join("\n"),
      "ok",
    );
  } catch (e) {
    setOutput(els.dmOutput, e.message, "err");
  } finally {
    if (client) client.close();
  }
});

// ─── Init ─────────────────────────────────────────────────────────────

populateUriDropdown();
