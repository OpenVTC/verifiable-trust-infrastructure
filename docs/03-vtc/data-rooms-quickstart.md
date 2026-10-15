# Data rooms on a VTC — a test run from scratch

This walks one sealed (`attributed`) data room end to end on a VTC: two people,
each with their own VTA and persona, sharing records and a file, then one of
them leaving. Every command below was run, in this order, against a VTC and two
VTAs on one machine. Where something does not work yet, it says so in place.

For what a room *is* and why each step exists, read
[Data rooms](../02-vta/data-rooms.md); this page is only the path.

## What you are building

| | Port | Who |
|---|---|---|
| VTA A | 3100 | Alice's agent. Holds her persona, the room's key, and her room group |
| VTA B | 3200 | Bob's agent. Holds his persona and his room group |
| VTC | 8200 | The community. Hosts the room: ciphertext, epochs, files |
| DID file server | 8500 | Publishes the personas' and the room's `did.jsonl` |

Every party in a room is a **persona DID** — a DID a person's VTA holds for
them in one of their contexts. The `pnm` you type into is only a client: its
own key never appears in a room.

Local endpoints need one switch, set in every shell below:

```bash
export VTA_ALLOW_PRIVATE_ENDPOINTS=1   # localhost DIDs; never in a deployment
```

On a real deployment, drop it and give every service a public `https://` URL.

## 0. Build

```bash
cargo build --release -p vta-service -p vtc-service -p pnm-cli
export PATH="$PWD/target/release:$PATH"
```

To keep this run out of your real `pnm` profile, give each person their own
`PNM_HOME`. Building `pnm` with `--no-default-features --features
config-session,tsp` also keeps its session in that directory rather than the
OS keychain.

## 1. Two VTAs

For each of A (3100) and B (3200), write a setup file:

```toml
# vta-a.toml — for B, change the paths and 3100 → 3200
config_path      = "/tmp/vdr/vta-a/config.toml"
data_dir         = "/tmp/vdr/vta-a/data"
public_url       = "http://localhost:3100"
data_dir_exists  = "delete"
overwrite_config = true

[server]
host = "127.0.0.1"
port = 3100

[secrets]
backend = "plaintext"      # test only

[messaging]
kind = "skip"              # REST only; no mediator needed for this run

[vta_did]
kind = "create_webvh"
url  = "http://localhost:3100"
```

Then, per VTA (shown for A):

```bash
vta setup --from vta-a.toml                       # prints the VTA DID
export PNM_HOME=/tmp/vdr/pnm-alice
pnm setup --name "Alice VTA"                      # prints a temporary admin did:key
vta --config /tmp/vdr/vta-a/config.toml import-did --did <that did:key> --role admin
vta --config /tmp/vdr/vta-a/config.toml &          # start it
pnm setup continue alice-vta --vta-did <VTA A DID>
pnm health                                         # "healthy": true
pnm contexts create --id alice --name Alice
```

Do the same for B with `PNM_HOME=/tmp/vdr/pnm-bob` and context `bob`.

## 2. A persona for each person

A persona here is a serverless `did:webvh` minted in the person's context. It
must be published where it says it lives, because the VTC resolves it to check
every signature the person makes.

```bash
mkdir -p /tmp/vdr/didhost && (cd /tmp/vdr/didhost && python3 -m http.server 8500 --bind 127.0.0.1 &)

PNM_HOME=/tmp/vdr/pnm-alice pnm did-mgmt dids create --context alice \
    --did-url http://localhost:8500/alice/did.jsonl --label "Alice persona"
# → ALICE=did:webvh:…:localhost%3A8500:alice
mkdir -p /tmp/vdr/didhost/alice
PNM_HOME=/tmp/vdr/pnm-alice pnm did-mgmt dids get-log "$ALICE" --out /tmp/vdr/didhost/alice/did.jsonl
```

Bob: the same against his own VTA, at `…/bob/did.jsonl`, giving `BOB`.

Re-publish a persona's log whenever it changes (`dids get-log` again): the VTA
that minted a serverless DID does not serve it.

## 3. The VTC

Headless setup, provisioned from a VTA (here A's, in its own context):

```bash
PNM_HOME=/tmp/vdr/pnm-alice pnm contexts create --id vtc --name Community
mkdir -p /tmp/vdr/vtc && cd /tmp/vdr/vtc
vtc setup --setup-key-out /tmp/vdr/vtc/setup-key.json --context vtc   # prints a did:key
PNM_HOME=/tmp/vdr/pnm-alice pnm acl create --did <that did:key> --role admin \
    --contexts vtc --expires 1h --handoff
```

```toml
# vtc-setup.toml
config_path       = "/tmp/vdr/vtc/config.toml"
base_url          = "http://localhost:8200"     # no /v1
vta_did           = "<VTA A DID>"
setup_key_file    = "/tmp/vdr/vtc/setup-key.json"
context           = "vtc"
single_admin_mode = true                        # one administrator, for a test

[secrets]
backend = "plaintext"
```

```bash
vtc setup --from vtc-setup.toml       # prints vtc_did=…, install_url=…, claim_code=…
```

Turn room files on — they are off until this section exists — then start it:

```toml
# appended to /tmp/vdr/vtc/config.toml
[rooms.files]
local_storage_bases = ["/tmp/vdr/vtc/room-storage"]
blob_dir            = "/tmp/vdr/vtc/room-storage/local"
```

```bash
vtc --config /tmp/vdr/vtc/config.toml &
curl -s http://localhost:8200/health
export VTC=<vtc_did>
```

Open the `install_url` in a browser, enter the claim code and register your
passkey: that is the console's first administrator.

## 4. Make Alice's persona a community member

A VTC hosts rooms only for its members: its default `rooms` policy refuses a
room whose owner is not one (and refuses `private` rooms outright).

In the console: **Members → Add a member**, DID = `$ALICE`, role `member`.

(There is no CLI for this yet: `vtc/members/admit` has no published
specification, so neither `cnm` nor `pnm` can send it.)

Bob does **not** need to be a member of the community to be in a room — room
membership is the room's own statement.

## 5. The room

The room has its own DID, minted from the `room` template in the owner's
context. Keep the signing key id it prints.

```bash
export PNM_HOME=/tmp/vdr/pnm-alice
pnm did-mgmt dids create --context alice --template room \
    --did-url http://localhost:8500/rooms/northwind/did.jsonl \
    --var WEBVH_SERVER=http://localhost:8500 --var MEDIATOR_DID=<VTA A DID> \
    --var 'LABEL=Northwind deal room' --label "Northwind room"
# → ROOM=did:webvh:…:rooms:northwind   ROOMKEY="$ROOM#key-1"
mkdir -p /tmp/vdr/didhost/rooms/northwind
pnm did-mgmt dids get-log "$ROOM" --out /tmp/vdr/didhost/rooms/northwind/did.jsonl
```

Register it on the VTC. Alice's VTA signs the registration **as her persona**
and calls the VTC itself — outbound only:

```bash
pnm rooms owner register --room "$ROOM" --host-did "$VTC" \
    --owner "$ALICE" --visibility attributed
# → the room is at epoch 1
```

Issue Alice the room's credentials, kept in her own VTA, and found the room's
group:

```bash
pnm rooms owner issue-membership --room "$ROOM" --signing-key "$ROOMKEY" \
    --subject "$ALICE" --valid-for 365d --out alice-vmc.json --store
pnm rooms owner issue-authority  --room "$ROOM" --signing-key "$ROOMKEY" \
    --subject "$ALICE" --action read,write,curate,admin --valid-for 90d \
    --out alice-vac.json --store
pnm rooms owner group-create --room "$ROOM" --signing-key "$ROOMKEY" --member "$ALICE"
```

Write and read a sealed record. For a VTC, `--host` ends in `/v1` and
`--host-did` is required:

```bash
H=(--room "$ROOM" --host http://localhost:8200/v1 --host-did "$VTC")
pnm rooms put r-0001 "We agreed not to reprice." "${H[@]}" --title "Pricing holds" --expected-version 0
pnm rooms list "${H[@]}"
pnm rooms get r-0001 "${H[@]}"
```

## 6. Bob joins

Joining takes both sides: Alice invites, Bob's VTA consents with a KeyPackage,
Alice admits it, Bob's VTA processes the Welcome. Files move between them
directly — never through the host.

```bash
# Alice
PNM_HOME=/tmp/vdr/pnm-alice pnm rooms owner invite --room "$ROOM" \
    --signing-key "$ROOMKEY" --subject "$BOB" --valid-for 7d --out invite.json
# Bob
PNM_HOME=/tmp/vdr/pnm-bob pnm rooms keys key-package --room "$ROOM" \
    --invitation invite.json --out kp.b64
# Alice: advances the room at the VTC first, then writes the Welcome
PNM_HOME=/tmp/vdr/pnm-alice pnm rooms owner group-add --room "$ROOM" \
    --host-did "$VTC" --member "$BOB" --key-package kp.b64 --out welcome.json
# Bob
PNM_HOME=/tmp/vdr/pnm-bob pnm rooms keys welcome --room "$ROOM" \
    --invitation invite.json --welcome welcome.json
```

Alice issues Bob's credentials; Bob keeps them in his VTA:

```bash
PNM_HOME=/tmp/vdr/pnm-alice pnm rooms owner issue-membership --room "$ROOM" \
    --signing-key "$ROOMKEY" --subject "$BOB" --valid-for 365d --out bob-vmc.json
PNM_HOME=/tmp/vdr/pnm-alice pnm rooms owner issue-authority --room "$ROOM" \
    --signing-key "$ROOMKEY" --subject "$BOB" --action read,write --valid-for 90d \
    --out bob-vac.json
PNM_HOME=/tmp/vdr/pnm-bob pnm cred-vault receive --credential-file bob-vmc.json
PNM_HOME=/tmp/vdr/pnm-bob pnm cred-vault receive --credential-file bob-vac.json
```

Bob reads what was written before he joined by fetching the room's history:

```bash
PNM_HOME=/tmp/vdr/pnm-bob pnm rooms keys backfill --room "$ROOM" --host-did "$VTC"
PNM_HOME=/tmp/vdr/pnm-bob pnm rooms get r-0001 "${H[@]}"
PNM_HOME=/tmp/vdr/pnm-bob pnm rooms put r-0002 "Confirmed with finance." "${H[@]}" --expected-version 0
PNM_HOME=/tmp/vdr/pnm-alice pnm rooms get r-0002 "${H[@]}"
```

## 7. A file

```bash
PNM_HOME=/tmp/vdr/pnm-alice pnm rooms file put ./term-sheet.pdf "${H[@]}" --title "Term sheet v3"
PNM_HOME=/tmp/vdr/pnm-alice pnm rooms list "${H[@]}"              # its record key
PNM_HOME=/tmp/vdr/pnm-bob   pnm rooms file get <record-key> "${H[@]}"
```

The file is sealed and opened on each person's machine with that one file's key
from their VTA; the VTC holds only ciphertext. `get` checks the result against
the digest the writer signed.

## 8. Membership changes

Every change moves the room to a new epoch. Members who stay catch up from the
VTC's relay; a member who is removed cannot read anything written after.

```bash
PNM_HOME=/tmp/vdr/pnm-alice pnm rooms owner group-remove --room "$ROOM" \
    --host-did "$VTC" --member "$BOB" --reason "left the deal team"
PNM_HOME=/tmp/vdr/pnm-alice pnm rooms put r-0003 "Final price." "${H[@]}" --expected-version 0

PNM_HOME=/tmp/vdr/pnm-bob pnm rooms keys commit --room "$ROOM" \
    --host http://localhost:8200/v1 --host-did "$VTC"
# → "this commit removed this holder from the group …"
PNM_HOME=/tmp/vdr/pnm-bob pnm rooms get r-0003 "${H[@]}"   # does not open
PNM_HOME=/tmp/vdr/pnm-bob pnm rooms get r-0002 "${H[@]}"   # still does
```

A member who stays runs the same `keys commit --host` after every change made
by someone else; until they do, newer records answer *"a commit has not been
delivered"*.

## What does not work yet

Found in this run; each is being fixed.

- **Files are still attributed to the client.** `pnm rooms put`, `get`, `list`,
  `curate` and `keys commit --host` now act as the persona (`rooms/keys/act`,
  `rooms/keys/seal` 0.2), and `keys backfill` / `read` / `browse` present as the
  persona from any client allowed to act in its context. `pnm rooms file put/get`
  still sign their transfer with the CLI's own key until they move to the
  `rooms/blobs/*` 0.2 tasks.
- **Making a member needs the console.** No CLI until `vtc/members/admit` is
  specified.
- **`private` rooms are not served yet** — use `attributed`.
- **Don't `pnm rooms renew` a sealed room**: it advances the host's epoch
  without a group commit.
