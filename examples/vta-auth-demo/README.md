# VTA Auth Demo

A static-file harness for exercising the VTA's authentication surface
from a browser. Zero build step — open `index.html` via a local HTTP
server and click around.

## What it exercises

| Step | Flow                                  | Surface                                                | Status |
|---|------------------------------------------|--------------------------------------------------------|---|
| 1 | Health check                              | `GET /health`                                         | implemented |
| 2 | Bootstrap auth (paste JWT)                | (purely client-side; needed when there's no passkey VM yet) | implemented |
| 3 | Enrol a passkey VM                        | `POST /did/verification-methods/passkey/challenge` + browser WebAuthn API + `POST /did/verification-methods/passkey` | implemented |
| 4 | Passkey login (DID-VM-resolved WebAuthn)  | `POST /auth/passkey-login/start` + browser WebAuthn API + `POST /auth/passkey-login/finish` | implemented |
| 5 | Session inspection + revoke               | `auth/sessions/list/0.1`, `auth/revoke-session/0.2` Trust Tasks | implemented (unsigned — see Step 5) |
| 6 | Trust-task dispatch                       | `POST /api/trust-tasks` with bearer auth              | implemented |
| 7 | DIDComm primitives smoke-test             | (purely client-side; resolve + pack against any DID)  | implemented |
| 8 | DIDComm-packed `/auth/` + refresh end-to-end | `POST /auth/challenge` + `POST /auth/` + `POST /auth/refresh` | implemented |
| 9 | DIDComm via mediator (no VTA REST) | mediator `/authenticate` + WS live delivery + `routing/2.0/forward` | implemented |

The legacy challenge/authenticate **and** refresh flows are now driven
from the browser via `vti-didcomm-js` (Step 8) — same authcrypt format
the VTA's `affinidi-messaging-didcomm-0.13` decrypt path actually
accepts. Refresh rotates the token (RFC 6749 §10.4): each refresh
returns a new refresh token and the old one is single-use.

## Prerequisites

- A running VTA reachable from your machine (typically
  `http://localhost:8100`).
- An existing admin DID set up via `pnm` (your cold-start operator
  identity). PNM authenticates via the legacy DIDComm-based flow, so
  this works against an unmodified VTA.
- The VTA's `[server] cors_origins` must include this page's origin
  (default `http://localhost:8000`). See "Configuring the VTA" below.
- A WebVH-managed DID where you want to enrol a passkey VM. Easiest
  option: mint one with `pnm webvh create-did --context <ctx>` and
  grant it admin role with `pnm acl create --did <new-did> --role admin
  --contexts <ctx>`. You can also use an existing one.
- A static-file server. Anything will do. Two easy options:

  ```sh
  # Python
  cd examples/vta-auth-demo
  python3 -m http.server 8000

  # or any other static server you have lying around
  npx http-server -p 8000 examples/vta-auth-demo
  ```

  WebAuthn requires a "secure context"; `localhost` is one of those
  even over HTTP, so no TLS dance is needed for the demo.

## Configuring the VTA for cross-origin access

The demo runs at `http://localhost:8000` and fetches the VTA at
`http://localhost:8100`. Different origins → browser CORS preflight
→ VTA needs to advertise that the demo's origin is allowed.

Add this to your VTA's config TOML:

```toml
[server]
host = "127.0.0.1"
port = 8100
cors_origins = ["http://localhost:8000"]
```

Reload the VTA after changing the config (`pnm vta restart` or kill
+ restart the binary). The CORS layer only activates when
`cors_origins` is non-empty — production VTAs leave it empty by
default.

Wildcards are not accepted. Add only the specific origins you want
allowed. The bearer token is the only cross-origin credential, so a
loose CORS policy means a loose authorisation policy.

## Where the JWT for Step 2 comes from

The demo's Step 2 (Bootstrap) needs an existing JWT, because Step 3
(enrolment) is admin-gated and there's no passkey-derived JWT yet.

Get one from the CLI:

```sh
pnm auth show-token
```

This prints the current admin JWT to stdout (re-authenticating first
if the cached one expired). Copy the output and paste it into the
"Access token (JWT)" box in Step 2.

Once a passkey VM is enrolled (Step 3), you can use Step 4 (passkey
login) instead — it produces a JWT directly, no `pnm auth show-token`
needed.

## Running through the flows

1. **Step 1 — Connect**: confirm "Check /health" returns OK. CORS
   errors in the browser console mean the VTA's `cors_origins`
   doesn't include this page's origin.

2. **Step 2 — Bootstrap**:
   - Run `pnm auth show-token` in your terminal; copy the output.
   - Paste into the textarea, click "Use this token".
   - Status line shows the JWT's role and expiry.
   - Sessions + trust-task panels (Steps 5/6) are now unlocked.

3. **Step 3 — Enrol a passkey VM**:
   - Enter a WebVH-managed DID your operator has admin role on.
   - Optional label (e.g. `"MacBook Touch ID"`).
   - Click "Enrol passkey".
   - Browser invokes WebAuthn registration; touch your authenticator.
   - On success the demo shows the new VM's `id`, the computed
     multikey, and the WebVH version that recorded the change.
   - The enrolled DID is pre-filled into Step 4's input.

4. **Step 4 — Passkey login** (you can do this fresh after enrolment
   or after signing out):
   - Click "Start" to fetch the challenge.
   - Click "Finish" to invoke `navigator.credentials.get(...)` and
     submit the assertion.
   - On success the session panel (Step 5) appears with the new JWT.

5. **Step 5 — Session inspection**:
   - "List active sessions" sends `auth/sessions/list/0.1`: the caller's own
     sessions (no task lists anyone else's).
   - "Revoke current session" sends `auth/revoke-session/0.2` with the JWT's
     `sessionId`; once it answers `revokedCount: 1`, subsequent calls return
     401.
   - Both tasks require a request proof, and this demo holds only a bearer
     token, so a VTA enforcing the specification answers `proofRequired`. The
     request and response are shown either way; `pnm` signs them.
   - "Sign out" clears local demo state without touching the VTA.

6. **Step 6 — Trust-task dispatch**:
   - Pick a URI from the dropdown (e.g. `discovery/capabilities/1.0`).
   - Edit the payload textarea for URIs that take parameters
     (e.g. `keys/get/1.0` needs `{"key_id": "..."}`).
   - Click "Send"; the response payload is printed.

7. **Step 7 — DIDComm primitives smoke-test**:
   - Paste any DID into "Recipient DID". `did:key:z…` resolves
     offline; `did:webvh:…` fetches its `did.jsonl` over HTTPS.
   - "Resolve DID" runs the resolver and shows the resolved DID
     document + metadata.
   - "Resolve + pack" additionally:
     - finds the recipient's first `keyAgreement` X25519 key,
     - generates an ephemeral X25519 sender keypair,
     - packs the textarea body as a DIDComm v2 authcrypt JWE
       (ECDH-1PU + A256CBC-HS512),
     - prints the JWE — but does NOT deliver it. This is a
       library smoke-test, not a transport.
   - The bundled crypto stack is at `./vendor/vti-didcomm-js.js`
     (~100 KB minified, loaded lazily on first click).

8. **Step 8 — DIDComm-packed `/auth/` end-to-end**:
   - Paste the VTA's DID (the one served by the running VTA —
     e.g. from `pnm webvh list-dids`).
   - Click "Generate ephemeral client DID". The demo prints the
     `did:key:z…` it minted along with the exact `pnm acl create`
     command you need to run (the `/auth/challenge` handler
     ACL-gates the request; an unregistered DID will 403).
   - Run that command in your terminal.
   - Click "Authenticate". The demo:
     - POSTs `{ did }` to `/auth/challenge` and reads back
       `{ sessionId, data: { challenge } }`.
     - Resolves the VTA's DID to find its keyAgreement X25519 key.
     - Builds a DIDComm v2 plaintext message of type
       `https://affinidi.com/atm/1.0/authenticate` with body
       `{ challenge, session_id }`, authcrypt-packs it (ECDH-1PU
       + A256CBC-HS512), and POSTs the JWE to `/auth/` as
       `text/plain`.
     - Stores the returned JWT — Sections 5/6 light up just like
       passkey login.
   - This is the browser-side equivalent of `pnm auth show-token`;
     useful for testing the wire flow without a CLI dependency.
   - **Refresh access token** (enabled after a successful auth that
     returned a refresh token) packs a `.../authenticate/refresh`
     message to the VTA, POSTs it to `/auth/refresh`, and stores the
     rotated token pair. Reuses the same ephemeral client identity —
     so it only works for a session established via Step 8, not one
     from passkey login.

9. **Step 9 — DIDComm via mediator** (the VTA-not-reachable path):
   - Reuses the Step 8 ephemeral client DID (generate it there first).
   - Enter the VTA DID; leave the mediator DID blank to auto-derive it
     from the VTA's `#vta-didcomm` service endpoint.
   - Click "Connect via mediator + trust-ping". The demo:
     - authenticates to the mediator (challenge → authcrypt response →
       mediator JWT),
     - opens a WebSocket to the mediator using the **subprotocol
       bearer** (`new WebSocket(url, ["bearer."+jwt])`) and enables
       message-pickup 3.0 live delivery,
     - packs a `trust-ping` authcrypt'd to the VTA, wraps it in
       `routing/2.0/forward` addressed to the mediator (`next` = VTA),
       and sends it over the WS,
     - awaits the VTA's `ping-response`, correlated by `thid`, pushed
       back over the same WS by the mediator.
   - On success it reports the round-trip time. **No VTA REST endpoint
     is used** — this is the path for VTAs that aren't reachable over
     HTTPS. Trust-ping needs no VTA ACL entry; the only requirement is
     that the mediator lets the client connect.

## What the multikey computation does

WebAuthn enrolment is a multi-step ceremony, and the VTA's submit
endpoint requires `publicKeyMultibase` to match what the server
re-derives from the attestation. The demo computes it from the
attestation's SPKI bytes (via `getPublicKey()`):

1. Take the SPKI-encoded public key (DER).
2. Extract the trailing 65-byte uncompressed P-256 point
   (`04 || X[32] || Y[32]`).
3. Compress to 33 bytes (`02|03 || X`) based on Y's parity.
4. Prefix with multicodec varint `0x80 0x24` (p256-pub = 0x1200).
5. Base58btc-encode with a `z` multibase prefix.

This only works for ES256 (P-256, COSE algorithm -7). Modern platform
authenticators (Touch ID, Face ID, Windows Hello) all default to
ES256; if you have an authenticator that returns Ed25519 or RSA, the
enrol path errors out and you'll need to extend `p256AttestationToMultikey`.

## Source layout

```
examples/vta-auth-demo/
├── index.html                       UI structure (nine numbered sections)
├── app.js                           Flow logic + multikey computation (vanilla ES modules)
├── styles.css                       Minimal dark-theme styling
├── vendor/vti-didcomm-js.js         Bundled DIDComm v2 stack used by Steps 7-9
└── README.md                        This file
```

The DIDComm library now lives in its own repository
([`OpenVTC/vti-didcomm-js`](https://github.com/OpenVTC/vti-didcomm-js),
published as `@openvtc/vti-didcomm-js`). To regenerate
`vendor/vti-didcomm-js.js` after a library change, build a browser
bundle from a checkout of that repo and copy it here, e.g.:

```sh
# from a vti-didcomm-js checkout
npx esbuild src/index.js --bundle --format=esm --platform=browser \
  --target=es2022 --minify --legal-comments=inline \
  --outfile=/path/to/verifiable-trust-infrastructure/examples/vta-auth-demo/vendor/vti-didcomm-js.js
```

This produces a minified ESM bundle (currently ~100 KB) including
`didwebvh-ts` and `@noble/curves`. The bundle is checked in so the demo
stays zero-build at runtime.

## Related crates

- **vti-webauthn** — the server-side verifier the passkey-login
  finish endpoint calls into. Server-side counterpart to the
  WebAuthn assertion the demo's Finish step sends.
- **vta-sdk** — the Rust client library. Programmatic equivalents of
  the trust-task dispatch flow (`VtaClient::post_trust_task`).
- **vta-service::routes::auth** — the route handlers behind every
  `/auth/*` endpoint.
- **vta-service::routes::passkey_vms** — the routes Step 3 hits.
- **vta-service::routes::trust_tasks** — the dispatcher behind
  `POST /api/trust-tasks` that fans out to per-slice handlers.

## Known limitations

- **ES256 only** for enrolment. Other COSE algorithms surface as a
  clear error in Step 3.
- **Legacy challenge/auth & refresh** are DIDComm-message-based and
  not callable from a browser without a DIDComm pack/unpack stack.
  Out of scope for this demo. Use `pnm auth` or the SDK.
- **No persistence**: the demo holds the JWT in memory. Reloading
  the page loses the session — you'll need to re-bootstrap or
  re-login.
- **The login Finish step passes `verificationMethod: ""`** — the
  server matches on `credential_id` to find the right VM. If a
  future passkey-login wire format requires the client to declare
  the VM explicitly, the demo will need updating.
- **Step 7 is a primitive showcase, not a transport.** It packs
  but doesn't deliver. See Step 8 for the actual delivery path,
  or future work for the mediator-routed transport.
- **Step 8 requires the ephemeral client DID to be pre-registered**
  in the VTA's ACL. The demo prints the exact `pnm acl create`
  command; run it before clicking Authenticate or the
  `/auth/challenge` call will 403.
