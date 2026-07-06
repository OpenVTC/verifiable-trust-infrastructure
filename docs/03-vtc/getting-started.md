# Getting started with a VTC

A working VTC in 10 minutes, assuming you already have an
**already-running VTA**. If you don't, run through
[`02-vta/cold-start.md`](../02-vta/cold-start.md) first — a VTC
cannot exist without a VTA to mint its identity.

## What you'll end up with

```mermaid
graph LR
    VTA[VTA<br/>:8100]
    VTC[VTC<br/>:8200]
    Admin[Admin SPA<br/>/admin/*]
    Public[Public site<br/>/]
    Member[Member<br/>cnm-cli]

    VTA -- vtc-host template<br/>at setup --> VTC
    Admin --> VTC
    Public --> VTC
    Member -->|join request| VTC
    Member -->|VMC + VEC| VTC

    classDef vta fill:#d4e6f9,stroke:#3a6fb0,color:#08305f
    classDef vtc fill:#e9d7f7,stroke:#7e3fa6,color:#3a0a5a
    class VTA vta
    class VTC,Admin,Public,Member vtc
```

A running `vtc` binary on port 8200 with:

- A `vtc_did` minted by your VTA's `vtc-host` template.
- A `config.toml` written by the setup wizard.
- A populated fjall store at `<data_dir>/`.
- An admin DID with a bearer JWT credential (kept in the OS keyring
  by default).
- A default landing page at `GET /` and the admin SPA at
  `/admin/*`.

## Prerequisites

- A running VTA reachable over HTTPS (`https://vta.example.com`).
- An ephemeral admin DID authorised on the VTA for the context that
  will host this VTC. The PNM CLI prints one during the VTC setup
  wizard; you'll paste it into `pnm acl create --did ... --role
  admin --contexts <ctx> --expires 1h`.
- Rust 1.95.0+ + `cargo` on your local box.
- OS keyring support (default — see the alternatives in the
  [secret backends doc](../02-vta/secret-backends.md), which apply
  equally to the VTC).

## Setup flow

```mermaid
sequenceDiagram
    participant Op as Operator
    participant CLI as vtc CLI
    participant VTA as VTA
    participant VTC as vtc daemon

    Op->>CLI: vtc setup
    CLI->>Op: Prompt config path<br/>VTC base URL<br/>VTA DID<br/>context
    CLI->>VTA: Resolve VTA DID<br/>(mediator + REST endpoint)
    CLI->>Op: DIDComm messaging choice
    CLI->>CLI: Mint ephemeral did:key<br/>(round-trip identity)
    CLI->>Op: Print ephemeral DID
    Op->>VTA: pnm contexts create / acl create<br/>--admin-did <eph> --admin-expires 1h
    Op->>CLI: Confirm ACL grant
    CLI->>VTA: Authenticate ephemeral key<br/>List did-hosting servers + domains
    CLI->>Op: Pick did-hosting server / domain / path<br/>then secrets backend
    CLI->>VTA: Provision-integration<br/>(VP, template=vtc-host)
    VTA->>VTA: Mint VTC keys<br/>Render template<br/>Issue admin VC<br/>Seal bundle
    VTA-->>CLI: Sealed bundle (HPKE)
    CLI->>CLI: Open bundle<br/>Write VtcKeyBundle + did.jsonl<br/>Write config.toml<br/>Initialise fjall keyspaces<br/>Mint install token
    CLI->>Op: Print install URL
    Op->>VTC: vtc (start daemon)
    Op->>VTC: Open install URL in browser<br/>(WebAuthn passkey ceremony)
    VTC-->>Op: Admin claimed
```

## Step 1 — Run the setup wizard

```sh
cargo run --package vtc-service -- setup
```

The wizard prompts:

| # | Prompt | Notes |
|---|---|---|
| 1 | Config path | Default `config.toml` |
| 2 | VTC base URL | The URL the daemon will publish (e.g. `https://community.example.com`) |
| 3 | VTA DID | The VTA's `did:webvh:...` identifier. Transport endpoints are resolved from the DID document — no separate VTA URL prompt |
| 4 | Context name | The context inside the VTA that will own this VTC (created via `cnm contexts create` if it doesn't already exist) |
| 5 | DIDComm messaging | Use the VTA's mediator, supply a different one, or skip |

The wizard prints an ephemeral `did:key` and pauses. **Authorise it
on the VTA** (this is the operator's choice — it's how you prove
to the VTA that you control this VTC provisioning attempt):

```sh
# On a workstation that has admin access to the VTA:
pnm acl create \
    --did "did:key:z6Mk..." \
    --role admin \
    --contexts mycommunity \
    --expires 1h
```

Press Enter in the VTC setup wizard. Now that the ephemeral key is
authorised, the wizard authenticates to the VTA and asks **where the
VTC DID should be published**:

- **did-hosting server** — pick a registered DID-hosting server from
  the VTA's live catalogue, or choose *serverless* to self-host the
  `did.jsonl` at the VTC base URL.
- **tenant domain** — when the chosen server is multi-tenant, pick
  the domain the DID is allocated under (otherwise the server's
  default is used). *(hosted mode only)*
- **path** — the optional `<path>` label in
  `did:webvh:<scid>:<host>:<path>`; blank lets the server assign one.
  *(hosted mode only)* In **serverless** mode there is no path: the
  DID is `did:webvh:<scid>:<host>`, which resolves to
  `https://<host>/.well-known/did.jsonl` — the daemon serves it
  itself, so the wizard doesn't prompt for a path.

The picker enumerates the catalogue over whichever transport the VTA
advertises (REST when available, otherwise DIDComm), and provisioning
then runs over the auto-selected transport (DIDComm-first when both are
advertised). If the VTA DID can't be resolved or reached, the wizard
falls back to the VTA's own 0-or-1-server auto-selection (no path
prompt — the VTA picks a server or self-hosts).

It then drives the provision-integration round trip against the VTA,
opens the sealed bundle, and writes:

- `<data_dir>/did/<scid>.jsonl` — the `did:webvh` log entry the
  daemon serves at `GET /.well-known/did.jsonl` (the URL the VTC's
  own DID resolves to).
- `config.toml` — the VTC's runtime configuration.
- The `VtcKeyBundle` to the configured secrets backend.

The wizard prints a one-shot **install URL**. Save it.

### Non-interactive setup (`setup --from <toml>`)

For CI, immutable images, or any unattended bring-up, provision from a
TOML file instead of the prompts:

```sh
cargo run --package vtc-service -- setup --from vtc-setup.toml
```

The file mirrors the wizard's decisions — see the fully-commented
[`docs/03-vtc/examples/vtc-setup.example.toml`](examples/vtc-setup.example.toml)
for the schema.

There's one wrinkle: provisioning authenticates to the VTA with an
ephemeral `did:key` that must be ACL-authorised *before* setup runs, and
a non-interactive run can't pause to grant it (the interactive wizard's
"press Enter once authorised" step). So it's a **two-phase** flow — the
same shape the mediator and did-hosting services use:

1. Mint + persist an ephemeral setup key (phase 1), then grant its
   `did:key` an admin ACL at the VTA:

   ```sh
   vtc setup --setup-key-out /srv/vtc/setup-key.json --context mycommunity
   # prints the exact command to run next:
   pnm contexts create --id mycommunity --name "VTC" \
       --admin-did "did:key:z6Mk..." --admin-expires 1h
   # (or `pnm acl create ...` if the context already exists)
   ```

2. Point `setup_key_file` in the TOML at that persisted key and run
   `setup --from`. Setup loads the key (it does not generate a fresh
   one), provisions against the VTA, writes the same `did.jsonl` /
   `config.toml` / sealed bundle as the interactive path, and prints a
   terse `key=value` block (including the install URL + claim code).
   The admin private key is **never** printed in non-interactive mode —
   re-run interactively if you need it.

For the full walkthrough — including the secret-store `backend` selector
and a Kubernetes example — see
[`non-interactive-setup.md`](non-interactive-setup.md).

## Step 2 — Start the daemon

```sh
cargo run --package vtc-service
```

The daemon listens on `0.0.0.0:8200` by default (override via
`VTC_SERVER_HOST` / `VTC_SERVER_PORT`). Verify:

```sh
curl http://localhost:8200/health
```

`200 OK` with a small JSON body.

## Step 3 — Claim the admin passkey

Open the install URL from step 1 in a browser. The page is the
embedded admin SPA serving the install flow:

1. You type the **claim code** the wizard printed alongside the URL.
   URL + code travel through separate channels — a leaked URL alone
   doesn't grant admin.
2. The browser registers a passkey via WebAuthn (any algorithm the
   authenticator supports — ES256, RS256, EdDSA all work).
3. The SPA submits `POST /v1/install/claim/start` and `…/finish`.
4. The token row transitions `Issued` → `Consumed` and can never be
   redeemed again.
5. The page prints the admin DID + a one-time admin credential
   bundle.

Import the bundle into the CNM CLI:

```sh
cnm auth login <paste-bundle-here>
```

The CLI imports the credential into the OS keyring, runs the
challenge-response handshake, caches the JWT, and confirms the
identity. Subsequent commands authenticate automatically:

```sh
cnm health
cnm community profile show
```

## Step 4 — Configure policy (optional)

Out of the box, the VTC ships default Rego policies that admit
nothing (`join.rego` and `removal.rego` default-deny) so a fresh
community has zero implicit members. Upload your own policies via:

```sh
# Upload a custom join policy
cnm policies upload --purpose join --rego ./my-join.rego

# Activate it
cnm policies activate --id <returned-policy-id>
```

See [`community-lifecycle.md`](community-lifecycle.md) for the
canonical Rego inputs each policy receives and worked examples.

## Step 5 — Receive your first join request

A prospective member presents a Verifiable Presentation containing
the evidence credentials your policy demands, then POSTs the VP to
`/v1/join-requests`:

```sh
# Member-side, with their own DID + signing key
curl https://community.example.com/v1/join-requests \
  -H 'Content-Type: application/json' \
  -H 'Trust-Task: https://trusttasks.org/openvtc/vtc/join-requests/submit/1.0' \
  --data @join-request.json
```

The VTC evaluates the active `join.rego` against the presented
evidence. On `allow`, it persists the request and notifies admins;
on `deny`, it returns 403 with the rule failure reason.

Admins approve via:

```sh
cnm join approve <request-id>
```

The VTC issues a VMC + (optionally) VECs, allocates a status-list
slot for revocation, and returns the credential bundle to the
member.

## Step 6 — Configure a public website (optional)

By default the VTC serves a small in-tree landing page at `GET /`.
To replace it with your community's site:

```toml
# config.toml
[website]
root_dir = "/var/lib/community/site"
deploy_mode = "live"          # or "managed" for generation-based deploys
```

Drop files into `/var/lib/community/site/` directly (`scp`, `rsync`,
`git pull`) or upload a bundle via `POST /v1/website/deploy`. See
[`website-and-admin.md`](website-and-admin.md) for the
full surface.

## Where to go next

| If you want to… | Read |
|---|---|
| Understand the module layout | [`architecture.md`](architecture.md) |
| Author policies + manage members | [`community-lifecycle.md`](community-lifecycle.md) |
| Issue credentials + revoke them | [`credentials.md`](credentials.md) |
| Publish to a trust registry | [`trust-registry.md`](trust-registry.md) |
| Assert personhood + manage the VRC graph | [`personhood-and-graph.md`](personhood-and-graph.md) |
| Host a public website + admin UX | [`website-and-admin.md`](website-and-admin.md) |
| See the full VTC spec | [`../05-design-notes/vtc-mvp.md`](../05-design-notes/vtc-mvp.md) |
