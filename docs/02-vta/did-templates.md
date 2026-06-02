# DID templates — authoring guide

DID templates are JSON files that describe the **shape** of a DID document with
`{TOKEN}` placeholders. The VTA renders them server-side during DID creation,
filling in keys it just minted, context metadata, and caller-supplied
variables, and hands the result to the underlying DID-method library
(`didwebvh-rs` today).

One template replaces ad-hoc "build a DID document" code across every setup
wizard, provisioning script, and CLI consumer. Swap the template → every
consumer gets the new shape on the next create. No redeploy.

## Why templates

- **Data, not code.** An operator can ship a new agent kind by dropping a JSON
  file, no recompile. The built-ins (`didcomm-mediator`, `push-gateway`,
  `vta-admin`, `vtc-host`, `did-host-http-didcomm`, `did-host-http`,
  `did-host-didcomm`)
  are baseline shapes, not the only shapes.
- **Method-agnostic.** Same format works for `did:webvh`, `did:web`, or
  `did:key` — the loader only knows about `{TOKEN}` placeholders. Method-
  specific details (SCID, log endpoints) are just placeholders the VTA fills.
- **Single source of truth.** The mediator setup wizard, `pnm webvh
  create-did --template …`, and any future provisioning surface all go
  through the same template.

## The format

A template is a single JSON file:

```json
{
  "schemaVersion": 1,
  "name": "didcomm-mediator",
  "kind": "mediator",
  "description": "DIDComm v2 routing mediator",
  "methods": ["webvh", "web"],
  "requiredVars": ["URL", "WS_URL"],
  "optionalVars": { "ACCEPT": ["didcomm/v2"], "ROUTING_KEYS": [] },
  "defaults": { "preRotationCount": 2, "portable": true },
  "document": {
    "@context": ["https://www.w3.org/ns/did/v1"],
    "id": "{DID}",
    "verificationMethod": [{
      "id": "{DID}#key-0",
      "type": "Multikey",
      "controller": "{DID}",
      "publicKeyMultibase": "{SIGNING_KEY_MB}"
    }],
    "service": [{
      "id": "{DID}#service",
      "type": ["DIDCommMessaging"],
      "serviceEndpoint": [
        { "uri": "{URL}",    "accept": "{ACCEPT}", "routingKeys": "{ROUTING_KEYS}" },
        { "uri": "{WS_URL}", "accept": "{ACCEPT}", "routingKeys": "{ROUTING_KEYS}" }
      ]
    }]
  }
}
```

### Required fields

| Field | Type | Notes |
|---|---|---|
| `schemaVersion` | integer | Currently `1`. The loader rejects versions it doesn't support. |
| `name` | string | `[a-z0-9-]+`, 1–64 chars. Unique per scope. |
| `kind` | string | Classification hint (e.g. `"mediator"`, `"webvh-hosting"`, `"custom"`). Not interpreted by the renderer; consumed by setup wizards and listing UX. |
| `document` | object | The DID document body with `{TOKEN}` placeholders. Must have an `id` field containing `{DID}`. |

### Optional fields

| Field | Type | Notes |
|---|---|---|
| `description` | string | Human-readable, shown in listings. |
| `methods` | array of strings | DID methods this template is designed for (advisory only). |
| `requiredVars` | array of strings | Variables the caller MUST supply at render time. Names must not be in the reserved set. |
| `optionalVars` | object | Variables with default values. Caller-supplied values override. |
| `defaults` | object | Hints for setup wizards (e.g. `preRotationCount`, `portable`). Not consumed by the renderer itself. |

### Substitution rules

- **Embedded token** — `{TOKEN}` inside a larger string is replaced with the
  string form of the variable value (compact JSON for non-string types).
- **Whole-string token** — a JSON string value that is *exactly* `"{TOKEN}"`
  is replaced with the variable's native JSON type. This lets a template
  write `"routingKeys": "{ROUTING_KEYS}"` and get back an array, not a
  string containing `"[]"`.
- **Object keys** are substituted the same way as values (but only as
  strings — whole-string substitution doesn't apply to keys).
- **Lowercase braces** like `{did}` are ignored. Token names must match
  `[A-Z_][A-Z0-9_]*`.

### Rendering semantics

At render time the engine:

1. Starts with `optionalVars` defaults.
2. Merges server-supplied ambient vars.
3. Merges caller-supplied vars (these override ambient and defaults).
4. Fails loud if any `requiredVars` is missing.
5. Substitutes placeholders throughout `document`.
6. Fails loud if any `{TOKEN}` remains for a variable the caller didn't
   supply — catches typos and missing ambient vars immediately.

## Variables

### Reserved (ambient) — supplied automatically

These are filled by the server during a DID-create flow. **Never put them in
`requiredVars` or `optionalVars` — the loader rejects that.**

| Name | When available | Source |
|---|---|---|
| `DID` | always during create | passthrough sentinel; `didwebvh-rs` substitutes the final DID string after SCID computation |
| `SIGNING_KEY_MB` | always during create | multibase-encoded public signing key the VTA just minted |
| `KA_KEY_MB` | when a KA key is in play | multibase-encoded public key-agreement key |
| `VTA_DID` | always | from VTA config |
| `VTA_URL` | always | from VTA config |
| `CONTEXT_ID` | always | the context the DID is being provisioned in |
| `CONTEXT_DID` | when the context has a DID set | useful for cross-reference service endpoints |
| `NOW` | always | RFC 3339 UTC timestamp |

### Caller-supplied

Anything else. Declare them in `requiredVars` (must be provided) or
`optionalVars` (with a default). Common examples:

- `URL` — the public endpoint (mediator URL, hosting URL, etc.)
- `ACCEPT` — DIDComm accept list
- `ROUTING_KEYS` — DIDComm routing DIDs
- `HOSTING_PATH` — where a hosting server publishes DID logs

## Scopes and resolution

Templates live in one of three scopes. Resolution order when a caller names a
template without explicit scope is **context → global → builtin**:

- **Built-in** — embedded in the SDK at compile time. Always available. Fork
  with `pnm did-templates init <kind>`. Current built-ins:
  - `didcomm-mediator` — DIDComm v2 routing mediator with a URL-based service
    endpoint.
  - `push-gateway` — push wake-up gateway identity: signing + key-agreement
    methods and a `DIDCommMessaging` service so devices, VTAs, and mediators
    can authcrypt `push/*` Trust Tasks (register / provision / wake) to it.
    Requires `URL` (the gateway's DIDComm endpoint). Provisioned like the
    mediator; implements the push wake-up binding.
  - `vta-admin` — did:key admin DID for provision-integration admin rollover.
  - `vtc-host` — Verifiable Trust Community (VTC) service identity. Mints
    the did:webvh under which a `vtc-service` binary operates and advertises
    its REST endpoint plus a placeholder URL for the BitstringStatusList
    credentials (populated in Phase 2 of the VTC MVP). DIDComm is not
    advertised by default — communities that need a mediator add it later
    via the runtime-service-management flow (see
    `runtime-service-management.md`). Requires `URL`; optional
    `STATUS_LIST_PATH` (default `/v1/status-lists`). `URL` must not have a
    trailing slash.
    The `did-host-*` names describe the DID-document shape the template
    mints — `http` = a `WebVHHosting` (HTTP resolution) endpoint,
    `didcomm` = a `DIDCommMessaging` endpoint — not the service that uses
    it.
  - `did-host-http-didcomm` — node whose DID exposes both a `WebVHHosting`
    service (URL-based) **and** a `DIDCommMessaging` service routed through
    a mediator. Use for nodes that publish DID logs over HTTP and accept
    DIDComm (admin RPC, witness coordination, control-plane traffic).
  - `did-host-http` — node whose DID exposes a `WebVHHosting` service and
    **no** DIDComm. Use for nodes whose only role is hosting DID logs. If
    you also need DIDComm, use `did-host-http-didcomm`.
  - `did-host-didcomm` — node whose DID exposes a `DIDCommMessaging` service
    via a shared mediator and **no** HTTP resolution endpoint. Use for
    witness, watcher, or any service consumed via DIDComm only.

  Legacy template names from two earlier generations still resolve to the
  renamed templates for one release: `webvh-control` / `webvh-daemon` /
  `webvh-server` and `did-hosting-control` / `did-hosting-daemon` /
  `did-hosting-server` all map to the `did-host-*` canonical names. Update
  operator configs to the canonical names before the aliases are removed.
- **Global** (`tpl:global:<name>`) — super-admin-managed. Visible across every
  context.
- **Context** (`tpl:ctx:<id>:<name>`) — context-admin-managed (or super
  admin). Visible only inside the named context. May share a name with a
  global template; the context version shadows the global one during
  resolution.

Use the same `name` at different scopes to get natural overrides — a context
can customize `mediator` without affecting any other context.

## CLI

### Offline (never touches the VTA)

```sh
# Scaffold a starter by forking a built-in
pnm did-templates init mediator > my-mediator.json

# Lint a local file
pnm did-templates validate my-mediator.json

# See what ships with the SDK
pnm did-templates list-builtins
```

### Online (stored templates)

```sh
# Global scope (super admin only)
pnm did-templates create --file my-mediator.json
pnm did-templates list
pnm did-templates show didcomm-mediator
pnm did-templates update didcomm-mediator --file my-mediator.json
pnm did-templates delete didcomm-mediator

# Context scope (context admin or super admin)
pnm did-templates create --context my-ctx --file my-mediator.json
pnm did-templates list --context my-ctx
pnm did-templates show didcomm-mediator --context my-ctx

# Preview the rendered output without creating a DID
pnm did-templates show didcomm-mediator \
  --rendered \
  --var URL=https://mediator.example.com \
  --var DID=did:webvh:example.com:test \
  --var SIGNING_KEY_MB=z6MkPreview \
  --var KA_KEY_MB=z6LSPreview

# Portability + drift detection
pnm did-templates export didcomm-mediator > backup.json
pnm did-templates diff didcomm-mediator --file local.json
```

Every command is mirrored on `cnm` — context admins running primarily in
CNM use the same surface.

### Using a template to create a DID

```sh
pnm did-mgmt dids create \
  --context my-ctx \
  --did-url https://mediator.example.com/.well-known/did/did.jsonl \
  --template didcomm-mediator \
  --var URL=https://mediator.example.com
```

`--template-context` defaults to the DID's `--context`, so a stored
context-local `didcomm-mediator` shadows the global one (or the built-in)
automatically. Override with `--template-context other-ctx` to pull a
template from a different scope.

`--template` is mutually exclusive with `--did-document` and `--did-log`
— you can't supply a template AND a hand-crafted document in the same
request.

## Validation

Every load (file, stored, or built-in) runs the validator:

- `schemaVersion` within supported range
- `name` matches `[a-z0-9-]+` and is 1–64 chars
- `kind` is non-empty
- `document.id` contains `{DID}`
- Reserved variable names not in `requiredVars` or `optionalVars`
- No overlap between `requiredVars` and `optionalVars`
- Every `{TOKEN}` in the document is declared (required, optional, or
  reserved ambient) — typos fail at validate time, not render time

At render time, additional checks catch missing required vars and
unresolved placeholders (for ambient vars the caller forgot to supply).

## Audit

Writes emit audit entries:

- `did_template.created`
- `did_template.updated`
- `did_template.deleted`

Renders are **not** audited — they're read-only, frequent, and the
consuming operation (like `did.created`) already records the resulting DID
document.

## Versioning

`schemaVersion` is checked at load. The SDK declares a supported range; bumping
the major version means a breaking format change. New optional fields are
accepted transparently — unknown fields round-trip through
serialize/deserialize, so a newer VTA's extra metadata survives an older CLI's
edit-then-upload cycle.

## Tips

- Prefer **one template per concern**. If you need "mediator with TLS" and
  "mediator without TLS", ship two templates rather than one with conditionals
  (the format is deliberately declarative — no conditionals, loops, or
  includes).
- Keep `defaults` in sync with the actual recommended operational settings.
  Setup wizards read `defaults.preRotationCount`, `defaults.portable`, etc. to
  pre-fill prompts.
- When forking a built-in, change the `name` and `description` first. Keeping
  the built-in name at a global scope shadows the embedded version, which may
  surprise future operators.
- Use `pnm did-templates diff` in CI to catch drift between a repo-committed
  template and what's actually installed on a given VTA.
