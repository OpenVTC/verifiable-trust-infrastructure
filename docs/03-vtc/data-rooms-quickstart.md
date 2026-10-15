# Data rooms on a VTC — a test run from scratch

This walks one sealed (`attributed`) data room end to end on a VTC: two people,
each with their own VTA and persona, sharing records and files, one of them
leaving, the room renewed, and finally files moving straight between a member
and an S3 bucket (LocalStack) without passing through the VTC. Every command
below was run, in this order, against a VTC and three VTAs on one machine.
Where something does not work yet, it says so in place.

For what a room *is* and why each step exists, read
[Data rooms](../02-vta/data-rooms.md); this page is only the path.

## What you are building

| | Port | Who |
|---|---|---|
| VTA A | 3100 | Alice's agent. Holds her persona, the room's key, and her room group |
| VTA B | 3200 | Bob's agent. Holds his persona and his room group |
| VTA C | 3300 | The community's agent. Mints the VTC's keys; in §10 it presigns the bucket's requests |
| VTC | 8200 | The community. Hosts the room: ciphertext, epochs, files |
| DID file server | 8500 | Publishes the personas' and the room's `did.jsonl` |
| Mediator | 7037 | §10 only: the channel between the VTC and VTA C |
| LocalStack | 4566 | §10 only: the S3 bucket |

Every party in a room is a **persona DID** — a DID a person's VTA holds for
them in one of their contexts. The `pnm` you type into is only a client: its
own key never appears in a room.

The community runs on a VTA of its own. It could share Alice's, but the VTA
that presigns the community's storage must be connected to a mediator.

A member's VTA always sends the room requests it signs *as the member*
(`pnm rooms owner register`, `group-add`, `group-remove`, `group-renew`,
`keys backfill`) over the VTC's Trust-Task HTTPS endpoint, whether or not
either side is on a mediator. TSP and DIDComm would authenticate the VTA's own
DID rather than the member's, and the VTC refuses a document whose signer is
not its sender (`identityMismatch`). So a VTC must keep advertising its HTTPS
endpoint (`TrustTaskHTTPS`) for members' VTAs to reach it.

Local endpoints need one switch, set in every shell below:

```bash
export VTA_ALLOW_PRIVATE_ENDPOINTS=1   # localhost DIDs; never in a deployment
```

On a real deployment, drop it and give every service a public `https://` URL.

## 0. Build

```bash
cargo build --release -p vta-service -p vtc-service
cargo build --release -p pnm-cli --no-default-features --features config-session,tsp
export PATH="$PWD/target/release:$PATH"
```

The second build keeps `pnm`'s session in its profile directory rather than
the OS keychain (`--features` applies to every package of one `cargo build`,
hence two). To keep this run out of your real `pnm` profile, give each person
their own `PNM_HOME`.

## 1. Three VTAs

For each of A (3100), B (3200) and C (3300), write a setup file:

```toml
# vta-a.toml — for B and C, change the paths and the port
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
kind = "skip"              # REST only; no mediator needed

[vta_did]
kind = "create_webvh"
url  = "http://localhost:3100"
```

If you will do §10, start the mediator (§10.1) first and give **C only** a
mediator instead of `kind = "skip"`; A and B stay REST only:

```toml
# vta-c.toml
[messaging]
kind = "existing"
did  = "<MEDIATOR DID>"

[services]
rest    = true
didcomm = true
tsp     = false            # the local mediator routes DIDComm only
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

`pnm setup continue` ends by repeating the `vta import-did` line whether or not
you already ran it; `pnm health` is what says the profile works. Do the same
for B with `PNM_HOME=/tmp/vdr/pnm-bob` and context `bob`, and for C with
`PNM_HOME=/tmp/vdr/pnm-community` and context `vtc`.

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

Headless setup, provisioned from the community's VTA (C):

```bash
mkdir -p /tmp/vdr/vtc && cd /tmp/vdr/vtc
vtc setup --setup-key-out /tmp/vdr/vtc/setup-key.json --context vtc   # prints a did:key
PNM_HOME=/tmp/vdr/pnm-community pnm acl create --did <that did:key> --role admin \
    --contexts vtc --expires 1h --handoff
```

```toml
# vtc-setup.toml
config_path       = "/tmp/vdr/vtc/config.toml"
base_url          = "http://localhost:8200"     # no /v1
vta_did           = "<VTA C DID>"
setup_key_file    = "/tmp/vdr/vtc/setup-key.json"
context           = "vtc"
single_admin_mode = true                        # one administrator, for a test

# Only for §10:
# [messaging]
# mediator_did = "<MEDIATOR DID>"
# transports   = ["didcomm"]

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

For a run with no browser, add an administrator offline instead, with the
daemon stopped — `vtc --config /tmp/vdr/vtc/config.toml acl add --did <a
did:key you hold> --role admin` (setup prints the same line as
`offline_admin_grant`, for a key it does not show you). The next start raises
it as an offline write for every administrator to acknowledge.

## 4. Make Alice's persona a community member

A VTC hosts rooms only for its members: its default `rooms` policy refuses a
room whose owner is not one (and refuses `private` rooms outright).

In the console: **Members → Add a member**, DID = `$ALICE`, role `member`.

There is no CLI for this: `vtc/members/admit/0.1` has no published
specification, so neither `cnm` nor `pnm` sends it. Without a browser, sign it
yourself as the offline administrator and post it to
`http://localhost:8200/v1/trust-tasks`, with the payload
`{"subject": "$ALICE", "role": "member", "label": "Alice", "reason": "…"}`;
the answer carries the member's VMC and role VAC.

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
# → ROOM=did:webvh:…:rooms:northwind   "Signing key: $ROOM#key-1"
export ROOMKEY="$ROOM#key-1"
mkdir -p /tmp/vdr/didhost/rooms/northwind
pnm did-mgmt dids get-log "$ROOM" --out /tmp/vdr/didhost/rooms/northwind/did.jsonl
```

Register it on the VTC. Alice's VTA signs the registration **as her persona**
and calls the VTC itself — outbound only:

```bash
pnm rooms owner register --room "$ROOM" --host-did "$VTC" \
    --owner "$ALICE" --visibility attributed
# → Registered … as did:webvh:…:alice; the room is at epoch 1.
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
# → Founded the group of … at epoch 1.
```

Write and read a sealed record. For a VTC, `--host` ends in `/v1` and
`--host-did` is required:

```bash
H=(--room "$ROOM" --host http://localhost:8200/v1 --host-did "$VTC")
pnm rooms put r-0001 "We agreed not to reprice." "${H[@]}" --title "Pricing holds" --expected-version 0
# → Wrote r-0001 at version 1, sealed and signed by did:webvh:…:alice
pnm rooms list "${H[@]}"                          # "author": the persona
pnm rooms get r-0001 "${H[@]}"
```

The VTC records the persona as author, never the `did:key` this `pnm` signs in
with.

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
# → … the room is now at epoch 2.
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

Bob's room work does not need his super-admin profile. Any client that may act
in his persona's context will do — here one with the `application` role in
`bob` only:

```bash
PNM_HOME=/tmp/vdr/pnm-bob-app pnm setup --name "Bob app"     # prints a did:key
PNM_HOME=/tmp/vdr/pnm-bob pnm acl create --did <that did:key> --role application \
    --contexts bob --label "Bob scoped client"
PNM_HOME=/tmp/vdr/pnm-bob-app pnm setup continue bob-app --vta-did <VTA B DID>
```

Bob reads what was written before he joined by fetching the room's history:

```bash
B=/tmp/vdr/pnm-bob-app
PNM_HOME=$B pnm rooms keys backfill --room "$ROOM" --host-did "$VTC"
# → fetched 1 link(s); this VTA now reads back to room epoch 1.
PNM_HOME=$B pnm rooms get r-0001 "${H[@]}"
PNM_HOME=$B pnm rooms put r-0002 "Confirmed with finance." "${H[@]}" --expected-version 0
# → … sealed and signed by did:webvh:…:bob
PNM_HOME=/tmp/vdr/pnm-alice pnm rooms get r-0002 "${H[@]}"
```

## 7. A file

```bash
PNM_HOME=/tmp/vdr/pnm-alice pnm rooms file put ./term-sheet.pdf "${H[@]}" --title "Term sheet v3"
# → { "key": "<record-key>", "mode": "proxied", "size": …, "version": 3 }
PNM_HOME=$B pnm rooms file get <record-key> "${H[@]}"
# → Fetched term-sheet.pdf (… bytes) …, written by did:webvh:…:alice; it matches the digest they signed.
```

The file is sealed and opened on each person's machine with that one file's key
from their VTA; the VTC holds only ciphertext. `get` checks the result against
the digest the writer signed, and writes into the current directory.

With the `local` storage the VTC seeds from `blob_dir`, every transfer is
`proxied`: the bytes move through the VTC as chunk documents. §10 moves them
straight to a bucket.

## 8. Renewing the room

A sealed room renews from the owner's VTA, which advances the group and the
host's epoch together:

```bash
PNM_HOME=/tmp/vdr/pnm-alice pnm rooms owner group-renew --room "$ROOM" \
    --host-did "$VTC" --reason "quarterly renewal"
# → Renewed …; the room is now at epoch 3. Nobody joined or left.
PNM_HOME=$B pnm rooms keys commit --room "$ROOM" \
    --host http://localhost:8200/v1 --host-did "$VTC"
# → applied 1 commit(s); this VTA is at room epoch 3, the host at 3.
```

Until Bob's VTA applies the commit, his writes are refused (`record is sealed
under epoch 2, room … is at 3`). `pnm rooms renew` is for `open` rooms only and
refuses a sealed one, naming `group-renew`: a bare mint would advance the
host's epoch without a group commit.

## 9. Membership changes

Every change moves the room to a new epoch. Members who stay catch up from the
VTC's relay; a member who is removed cannot read anything written after.

```bash
PNM_HOME=/tmp/vdr/pnm-alice pnm rooms owner group-remove --room "$ROOM" \
    --host-did "$VTC" --member "$BOB" --reason "left the deal team"
PNM_HOME=/tmp/vdr/pnm-alice pnm rooms put r-0004 "Final price." "${H[@]}" --expected-version 0

PNM_HOME=$B pnm rooms keys commit --room "$ROOM" \
    --host http://localhost:8200/v1 --host-did "$VTC"
# ✗ … this commit removed this holder from the group: nothing sealed from epoch 4 on will open here
#   You are no longer a member of this room's group. …
PNM_HOME=$B pnm rooms get r-0004 "${H[@]}"   # does not open ("a commit has not been delivered")
PNM_HOME=$B pnm rooms get r-0002 "${H[@]}"   # still does
```

The removal is reported as an error, and the record written after it then
reads as *"a commit has not been delivered"*: the removed member's VTA stays
at its last epoch for good.

A member who stays runs the same `keys commit --host` after every change made
by someone else; until they do, newer records answer *"a commit has not been
delivered"*.

## 10. Files straight to S3

Here the room's new files go to an S3 bucket — LocalStack standing in for it —
and the bytes move between `pnm` and the bucket directly. The VTC never holds a
storage credential: for every object it asks the community's VTA (C) for a
presigned request, over messaging
([§8.2 of the guide](../02-vta/data-rooms.md#82-t2--a-community-vtc),
[external accounts](../02-vta/external-accounts.md)). That needs the VTC and VTA
C on a mediator, and today a fix this run applied locally (the private-address
probe under *What does not work yet*); without it, stop at §9.

### 10.1 A local mediator

VTA C and the VTC must resolve each other's `localhost` DIDs through the
mediator. `affinidi-messaging-test-mediator`'s `standalone` example is the
quickest one, with two changes it has no flag for: its DID resolver refuses
`did:webvh` on `localhost` (`HostPolicy::PublicOnly`), and it refuses direct
delivery between two of its own clients. In a copy of the example, pass to the
`MediatorBuilder`:

```rust
.did_resolver(
    DIDCacheConfigBuilder::default()
        .with_host_policy(affinidi_did_web::HostPolicy::AllowPrivate)
        .build(),
)
```

and build the `TestMediator` with `.local_direct_delivery(true, false)`. Run
it with `TEST_MEDIATOR_LISTEN=127.0.0.1:7037`; it prints `MEDIATOR_DID=…`, a
fresh `did:peer` on every start — restart it and VTA C and the VTC need
setting up again. Then set up VTA C (§1) and the VTC (§3, with `[messaging]`)
against that DID, and check the VTC's log for *VTC messaging connected to
mediator*.

### 10.2 The bucket

```bash
docker run -d --name vdr-s3 -p 4566:4566 -e SERVICES=s3 localstack/localstack:4.4
export AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test AWS_DEFAULT_REGION=us-east-1
aws --endpoint-url http://localhost:4566 s3api create-bucket --bucket vdr-rooms
```

The VTA presigns only `https://` endpoints. LocalStack answers TLS on the same
port as `https://localhost.localstack.cloud:4566`, a public name for
`127.0.0.1` with a valid certificate, so that is the endpoint, path-style.

### 10.3 The account at the community's VTA

```bash
export PNM_HOME=/tmp/vdr/pnm-community
# The VTC's own DID uses the account; `application` holds `external-auth-use`.
pnm acl create --did "$VTC" --role application --contexts vtc --label "community (storage)"

pnm external create localstack-rooms --context vtc --label "LocalStack — rooms" --settings \
  '{"model":"s3-static-presign","endpoint":"https://localhost.localstack.cloud:4566",
    "region":"us-east-1","bucket":"vdr-rooms","pathStyle":true,"accessKeyId":"test"}'
pnm external bind localstack-rooms --context vtc --consumer "$VTC" \
    --prefix rooms/ --prefix probe/ --action put --action get --action delete \
    --max-ttl 900 --rate 120
pnm external setup localstack-rooms --context vtc     # policy, CORS and lifecycle rules
echo test | pnm external secret-set localstack-rooms --context vtc   # LocalStack's dummy secret
pnm external probe localstack-rooms --context vtc     # "ok": true, "complete": true
```

`setup` prints `bucket-lifecycle.json` and `bucket-cors.json`. Its lifecycle
rule names only the first bound prefix (`probe/`), so write the rule for
`rooms/` yourself, then set both:

```bash
cat > lifecycle.json <<'EOF'
{"Rules":[{"ID":"abort-incomplete-room-uploads","Status":"Enabled","Filter":{"Prefix":"rooms/"},
           "AbortIncompleteMultipartUpload":{"DaysAfterInitiation":2}}]}
EOF
aws --endpoint-url http://localhost:4566 s3api put-bucket-lifecycle-configuration \
    --bucket vdr-rooms --lifecycle-configuration file://lifecycle.json
aws --endpoint-url http://localhost:4566 s3api put-bucket-cors \
    --bucket vdr-rooms --cors-configuration file://bucket-cors.json   # AllowedOrigins set to yours
```

LocalStack stores both and reads them back; this run did not see it act on
the lifecycle rule. `pnm` needs no CORS — only a browser does.

### 10.4 The storage config, and the room on it

In the console: **Storage → New storage**, an `s3` (VTA account) config naming
context `vtc`, account `localstack-rooms`, bucket `vdr-rooms`, region
`us-east-1`, endpoint `https://localhost.localstack.cloud:4566`, path-style;
then the room's page sends its new uploads to it. Each takes your passkey, and
in single-administrator mode runs at once. The documents behind those two
buttons:

```json
// vtc/storage/configs/create/0.1
{"id": "localstack", "label": "LocalStack S3 (via the community VTA)", "reason": "…",
 "settings": {"kind": "s3", "bucket": "vdr-rooms", "region": "us-east-1",
              "endpoint": "https://localhost.localstack.cloud:4566", "pathStyle": true},
 "auth": {"mode": "vta-account", "context": "vtc", "account": "localstack-rooms"}}
// vtc/rooms/storage/assign/0.1
{"roomId": "$ROOM", "configId": "localstack", "reason": "…"}
```

Without a browser, each needs the operation-bound step-up some other way: an
approver device enrolled with `vtc admin enrol-approver` (daemon stopped)
answers it ([approver step-up](../05-design-notes/vtc-approver-step-up.md)).
There is no CLI for either side of that yet.

Creating the config asks VTA C once and probes the bucket through it;
`vtc/storage/configs/get/0.1` (`{"configId": "localstack"}`) then shows
`"lastProbeOk": true`. Files already in the room stay where they were written.

### 10.5 Upload and download

`[rooms.files] direct_transfer` defaults to `"not_private"`, so an
`attributed` room transfers directly:

```bash
head -c 3000 /dev/urandom > small.bin
head -c 41943040 /dev/urandom > big.bin            # 40 MiB
PNM_HOME=/tmp/vdr/pnm-alice pnm rooms file put ./small.bin "${H[@]}"   # "mode": "direct"
PNM_HOME=/tmp/vdr/pnm-alice pnm rooms file put ./big.bin   "${H[@]}"   # "mode": "direct"
PNM_HOME=/tmp/vdr/pnm-alice pnm rooms file get <record-key> "${H[@]}"  # "… matches the digest they signed"

aws --endpoint-url http://localhost:4566 s3api list-objects-v2 --bucket vdr-rooms
# rooms/<room hash>/<blobRef>-<upload id>   — ciphertext, a little larger than the file
aws --endpoint-url http://localhost:4566 s3api head-object --bucket vdr-rooms \
    --key <that key> --checksum-mode ENABLED
# big.bin: "ETag": "…-6", "ChecksumType": "COMPOSITE"   — a six-part multipart upload
```

`pnm` sends a file of up to 16 MiB of ciphertext as one `PUT` and cuts a larger
one into 8 MiB parts, so it takes more than 16 MiB to see a multipart upload.
The VTC asks VTA C for each upload's requests in `external/credentials/issue/0.2`
batches of at most 64 (the specification allows 128; the VTA's 256 KiB response
cap fits about 90), and VTA C's log shows those batches and a
`issue/0.1` per read. The VTC's own `room-storage` directory gains nothing.

**For a real S3 bucket**, drop `endpoint` and `pathStyle` from both the account
and the config (virtual-hosted AWS addressing), use the real region, create an
access key holding exactly the policy `pnm external setup` prints, set its
secret with `pnm external secret-set`, and set `AllowedOrigins` in the CORS
rule to the origins your members' browsers load the portal from. For R2, B2 or
MinIO keep `endpoint` (and `pathStyle` where the store needs it).

## 11. Rate limits

Room traffic has its own budgets (`[rooms.rate_limits]`, §8.2 of the guide).
Nothing above came near the defaults. To see one, tighten it and restart:

```toml
[rooms.rate_limits]
presenter_burst       = 3
presenter_interval_ms = 4000
```

Five quick `pnm rooms get`s: the first three answer at once, the fourth and
fifth each wait about 4 s — `pnm` waits out a read's `Retry-After` itself. A
write is not retried:

```text
✗ Error: VTC returned HTTP 429: {"error":"rate_limited","limiter":"room-presenter",…,"retryAfterSecs":4}
```

## What does not work yet

Found in this run; each is being fixed.

- **A VTA cannot probe a bucket on a private address.** The probe uses the
  public-only HTTP client whatever `VTA_ALLOW_PRIVATE_ENDPOINTS` says, so an
  account at LocalStack, or a MinIO on your network, never passes a complete
  probe and never issues.
- **`pnm external setup`'s lifecycle rule** covers only the first bound prefix;
  write it for `rooms/` yourself (§10.3).
- **Making a member needs the console.** No CLI until `vtc/members/admit` is
  specified.
- **Storage configs need the console too** — or an approver device and a
  signer of your own (§10.4).
- **`private` rooms are not served**, and so neither is their commit relay —
  use `attributed`.
- **`rooms/keys/act` sets no `subjectPath`** for a document without a `roomId`
  (a download chunk, a direct upload's commit or abort); those are completed
  only for a member named as `issuer`.
- **Presign batches are 64 requests**, not the specification's 128 (above).
