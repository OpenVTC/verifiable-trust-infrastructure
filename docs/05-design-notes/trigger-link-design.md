# Trigger links — why this shape, and what it does and does not interoperate with

**Status:** Explanatory. No change to the specification is proposed. This note
explains design choices in the [Trigger Links](https://trustoverip.github.io/dtgwg-vti-spec/)
chapter of the VTI specification (`spec/07a-links.md`, VTI-LNK-001 to
VTI-LNK-124) that the chapter states as
rules but does not argue at length, chiefly why a trigger link is not a DIDComm
out-of-band URL. Where this note and the chapter differ, the chapter is correct.

## Summary

A trigger link is an `https` URL with up to four reserved parameters in the
fragment:

```
https://link.trustoverip.org/t#_from=<VID>&_id=<handle>&_exp=<n>&_type=/vti/flow/sign-in/0.1
```

It names whom to contact and which flow to start. It carries no message, no
endpoint and no key. The reader takes the transport from the contact's verified
DID document (VTI-LNK-053), and each flow states the first request it sends
(VTI-LNK-057). VTI's own flows send a Trust Task (VTI-LNK-054); the format
itself can start a DIDComm, OpenID or any other exchange.

Two consequences are deliberate:

- **A trigger link is a new kind of code.** A scanner that only understands
  DIDComm `?_oob=` or `?_oobid=` URLs will not act on it. It is not a variant
  of the DIDComm out-of-band encoding.
- **It is not a VCALM interaction URL.** VCALM bridges to DIDComm by fetching
  the scanned URL; a trigger reader never fetches the link, and a trigger link
  must not cause a fetch by reference (VTI-LNK-072). The two can sit side by
  side on a page, not one inside the other.

## Why not DIDComm's URL encoding

DIDComm Messaging v2 defines two URL forms for an out-of-band message:

- **Standard message encoding**: `https://<domain>/<path>?_oob=<base64url plaintext JWM>`.
  The specification says the full URL "should return human readable
  instructions when loaded in a browser", that "additional path elements or
  query parameters are allowed", and that when `_oob` is detected the URL "may
  be assumed to be an Out Of Band message with a reasonably high confidence".
- **Short URL message retrieval**: `https://example.com/path?_oobid=<GUID>`.
  "On receipt of this form of message, the agent must do an HTTP GET to
  retrieve the associated encoded message."

Using a DIDComm out-of-band invitation as the trigger link was considered early
in the design and set aside, for the reasons below. They apply equally to a
variant that carries a Trust Task document as an attachment and names the flow
in `body.goal_code`. The main reason is architectural; the mechanical reasons
would each be survivable alone but together are decisive.

### The main reason: the link should not pick the protocol

The chapter's first design principle is that the format "names whom to contact
and which flow to start; it does not choose the protocol of the exchange". The
transport comes from the contact's verified DID document and never from the
link, and the reader's own preference order chooses among the bindings the
document offers (VTI-LNK-053).

This is consistent with the transport chapter, which keeps an authorization
decision independent of the transport a request arrived over (VTI-TRN-002,
VTI-TRN-003), though those requirements do not themselves govern links.

A DIDComm out-of-band invitation is a DIDComm message. Making it the link would
make every flow a DIDComm flow at the first step, and every other protocol a
payload inside DIDComm's container. OpenVTC's implementation, for its part,
prefers the Trust Spanning Protocol, then DIDComm, then REST (see
[`tsp-enablement.md`](./tsp-enablement.md) and
[`tsp-vs-didcomm-trust-task-surface.md`](./tsp-vs-didcomm-trust-task-surface.md)).
TSP defines a relationship-forming invite (`TSP_RFI`), but it is sent after
the sender has learned the other party's VID, and TSP leaves that
out-of-band introduction out of scope. A neutral link that defers to the DID
document is what lets one code start an exchange over TSP, DIDComm or HTTPS
without the code changing.

DIDComm is not excluded by this. A flow may define a DIDComm first request
(VTI-LNK-057), and a contact may advertise a `DIDCommMessaging` service that a
reader selects under VTI-LNK-053.

### The mechanical reasons

- **The query reaches the server; the fragment does not.** `_oob` and `_oobid`
  are query parameters, which the link host, a CDN in front of it and any
  link-preview fetch all receive. The trigger link's parameters are in the
  fragment (VTI-LNK-010, VTI-LNK-011), which a client never sends (the
  rationale under VTI-LNK-013). A handle in the query needs the host to promise
  not to log it; a handle in the fragment needs no promise.
- **`_oobid` is a fetch by reference.** Link previews, mail scanners and chat
  unfurlers fetch links nobody tapped. A trigger link "MUST NOT cause a fetch by
  reference", and fetching it must not spend its handle (VTI-LNK-072).
- **Size.** A minimal out-of-band invitation for the chapter's example contact
  gives a 395-byte `?_oob=` URL, against 184 bytes for the chapter's example
  trigger link. A producer must not exceed 251 bytes at QR level M or 177 at
  level Q (VTI-LNK-081). The figures assume the chapter's example `did:webvh`
  as `from`; the GUID from DIDComm's short-URL example as `id`;
  `expires_time` 1791460920; `body.goal_code`
  `org.trustoverip.link.vti.sign-in`, an illustrative code; the required `type`
  `https://didcomm.org/out-of-band/2.0/invitation`; JSON without whitespace;
  base64url without padding; and the host and path
  `https://link.trustoverip.org/t`. The invitation JSON is 269 bytes and the
  `?_oob=` query 365.
- **Nothing makes a DIDComm receiver show the person anything first.**
  `goal_code` is optional, "a self-attested code the receiver may want to
  display to the user or use in automatically deciding what to do". A trigger
  reader, by contrast, must show the person who the contact claims to be,
  marked unverified, before any network activity, and must wait for the person
  to continue except as VTI-LNK-051 allows (VTI-LNK-050).
- **A goal code is not a URI.** DIDComm requires goal codes defined outside its
  specification to use reverse domain name notation. The chapter identifies a
  flow by a whole `https` URI, compared as a string (VTI-LNK-040, VTI-LNK-041),
  at which a link host can serve a page describing the flow (VTI-LNK-092).
- **DIDComm's own privacy guidance points the same way.** "No private
  information may be passed in the message", and identifiers passed in a URL or
  QR code "must no longer be considered private". A trigger link carries a
  contact, a handle and, where used, an expiry and a flow. It confers no
  authority (VTI-LNK-070), and an inviter that treats possession of a handle as
  authority must make the handle single use and short lived (VTI-LNK-071).

### Not to be confused: `auth/oob`

The Trust Tasks behind the `sign-in` flow are the `auth/oob/*` family. That name
refers to sign-in from another device, out of band of the browser. It is not
DIDComm's out-of-band protocol, and a `sign-in` trigger link is not a DIDComm
invitation.

## A new kind of code, on purpose

A scanner that only recognises DIDComm out-of-band URLs will not act on a
trigger link, and a wallet that wants to read trigger links has to add a
reader for them. That cost is accepted for the reasons above. In practice:

- **A scanner needs no picker.** A wallet that reads both formats tells them
  apart by inspecting the text.
- **An inviter that wants to reach DIDComm-only wallets shows two codes**, a
  trigger link and a DIDComm out-of-band code, and the person scans the one
  their wallet reads. No single code reaches both (see the fallbacks below).

**It is a plain `https` link.** Any camera or browser opens it. A link host
must serve, at its trigger path, a page for a person with no wallet, and that
page should say what the code is for and should offer the wallet stores and an
"open in the app" action (VTI-LNK-091). DIDComm's encoding has the same
property, since its full URL "should return human readable instructions when
loaded in a browser".

**It can share a scanner with DIDComm codes, within limits.** A trigger reader
that finds no reserved name in the fragment or the query reports the reason
`not-ours`, whose outcome is `pass-on`: the text goes, unchanged, to the
wallet's other handlers (VTI-LNK-020 step 2, VTI-LNK-021). That is not the
first check. VTI-LNK-020 step 1 reports `too-long` for any text over 1,536 code
points, and step 2 reports `query-form` when the query holds a reserved name
and the fragment none; both have the outcome `invalid`, and the reader shows
"This code can't be used." So a trigger reader consulted first hands on a
DIDComm `?_oob=` or `?_oobid=` URL of up to 1,536 code points whose query has
none of `_from`, `_id`, `_exp` or `_type`, and refuses a longer one (an
invitation with attached requests can exceed that) or one whose query happens
to use a reserved name. The chapter does not say in which order a wallet
consults its handlers. A wallet that reads both can, for example, give text
with `_oob` or `_oobid` in its query to its DIDComm reader first; that is the
wallet's choice.

**A DIDComm-only scanner fails on it, harmlessly.** Released Credo
(`@credo-ts/didcomm` 0.7.4 and 0.6.3) recognises only the `oob`, `c_i` and
`d_m` query parameters. Any other URL it treats as a short URL: it makes an
HTTP `GET` with `Accept: application/json`, and, when the answer is not an
invitation in JSON, looks for those parameters in the final URL and then
fails with its own error. Handed a trigger link, it fetches the link host's
no-wallet page, without the fragment. The handle is not sent and nothing is
spent (VTI-LNK-072), but the person sees that wallet's error rather than a
useful message.

**It can still start a DIDComm exchange.** A flow may define a DIDComm first
request, over a DIDComm service in the contact's document (VTI-LNK-053,
VTI-LNK-057).

## Why `https`, and not a custom scheme

A producer must emit a trigger link as an `https` URL (VTI-LNK-010) and must
never emit one under a custom scheme (VTI-LNK-013). A reader may also accept the
same host, path and fragment under an alias scheme it registers for its own
scanner (VTI-LNK-012).

- **Any app can register a custom scheme.** RFC 8252 notes that several apps can
  register the same scheme, so which one receives the link is indeterminate. A
  shared scheme owned by an ecosystem (for example
  `openid-credential-offer://`) has this weakness regardless of who owns the
  name. For a code whose handle can be spent, the first app to receive it wins.
- **`https` has an owner check.** Which app opens an `https` link is decided by
  the operating system, from association files the link host publishes and from
  what each installed app declares (VTI-LNK-090; the rationale under
  VTI-LNK-013).
- **`https` has a fallback.** With no wallet installed, the link opens the
  host's no-wallet page (VTI-LNK-091). A custom scheme with no handler does
  nothing.
- **Alias schemes are for a wallet's own scanner.** Inside a wallet's scanner
  nothing is dispatched by the operating system, so a private alias costs
  nothing and the reader resolves the flow exactly as for `https`
  (VTI-LNK-041).

A shared link host listed by every participating wallet is what makes one code
open whichever wallet a person has from a camera (the note under VTI-LNK-092).
It is a convenience: a link on any host that meets the host rules is equally
valid (VTI-LNK-012, VTI-LNK-060).

## What survives an outage

Two hosts matter, and they fail differently.

### The link host is down (DNS or HTTP)

Mostly survivable.

- A reader needs nothing from the link host to read the link. Everything it
  uses is in the text: a path-form `_type` is resolved against the link's host
  and compared as a string (VTI-LNK-041), with no request made.
- What follows uses only the contact's DID document and the services it lists
  (VTI-LNK-052, VTI-LNK-053), and the first request goes to the endpoint the
  document names, none of which need the link host.
- So a wallet's own scanner, pasting, and an alias scheme keep working.
- The no-wallet page (VTI-LNK-091) and the flow description pages
  (VTI-LNK-092) are unavailable.
- Opening from a camera may or may not work: it depends on whether the phone
  still holds the host's association data. This is not verified (see below).

### The inviter's DNS, website or DID host is down

Not survivable, by design.

- The reader resolves the contact's DID document afresh for each exchange
  (VTI-LNK-053) and sends nothing if it cannot verify it, stopping with
  `did-document-unverified` (VTI-LNK-052).
- For a contact that qualifies through route B, the reader fetches
  `<origin>/.well-known/did-configuration.json` after the person continues
  (VTI-LNK-120, VTI-LNK-122). Any failure, a failed fetch included, stops the
  exchange with `domain-not-linked`, and nothing is sent to the contact's
  services (VTI-LNK-121, VTI-LNK-123).

Failing closed here is the point: a reader that proceeded on a cached or
unverified document would let a code steer a wallet to an endpoint the inviter
does not currently publish.

## DIDComm fallbacks: possible, and deferred

For an inviter that also wants to reach readers that only understand DIDComm,
three approaches are possible. None is specified, and none is needed for VTI's
flows.

1. **Two codes on one page.** A trigger-link code beside a DIDComm out-of-band
   code. No specification change; the person scans whichever their wallet
   reads. This is the recommended approach if one is needed.
2. **A DIDComm service in the contact's DID document.** A reader that
   understands trigger links already chooses among the bindings the document
   offers (VTI-LNK-053), so an inviter that publishes a `DIDCommMessaging`
   service can be reached over DIDComm by such a reader. This is a fallback for
   the exchange, not for the scan: it does nothing for a DIDComm-only scanner.
3. **One code carrying both**, with `?_oob=` in the query and the reserved
   names in the fragment. A trigger reader never reads the query
   (VTI-LNK-011), so the `_oob` parameter does not disturb it. The DIDComm side
   gains little:
   - **It does not fit.** With the assumptions above, the combined URL is 549
     bytes, well past VTI-LNK-081's 251. Only very short contact identifiers
     could fit.
   - **Released Credo would fetch it.** It does not recognise `_oob`, so it
     treats the combined code as a short URL and makes a `GET`, sending the
     whole invitation in the query to the link host (the fragment is not
     sent). Neither release reads DIDComm v2 invitations, which carry `type`
     rather than `@type`.
   - **`_oobid` instead is a fetch by reference.** `?_oobid=<GUID>` with the
     trigger fragment is 228 bytes, which fits at level M only, and it makes
     every DIDComm reader `GET` the URL, which VTI-LNK-072 rules out for a
     trigger link.
   - **No shared handle.** The query is visible to the link host, so an
     invitation reusing `_id` as its `id` would expose the handle.
   - **The DIDComm path does less.** A DIDComm-only reader does not know the
     flow and is not bound by VTI-LNK-050.

   A profile of this kind would also have to say which half a reader that
   supports both acts on. Given these limits, the first approach is preferred
   and the third is unlikely to be worth a profile.

## VCALM

VCALM (W3C Working Draft, 13 October 2026, §3.7 "Initiating Interactions")
defines an **interaction URL** (§3.7.1): a URL that must contain an `iuv`
query parameter whose value must be `1`, and that should be an `https` URL
containing an interaction-specific identifier, opaque and needing "no URL
syntax processing before it is fetched". An **interaction QR code** (§3.7.2)
must be an interaction URL expressed as a QR code, should not exceed 400
alphanumeric characters, and must not exceed 4,296. Fetching the URL with
`Accept: application/json` returns a `protocols` map from a protocol identifier
to a URL that starts the interaction; with any unrecognised `Accept` value, an
HTML page of directions for a person (§3.7.4). The `didcomm` entry's value
"should be the Out-of-Band (OOB) Invitation URL for the exchange", so a VCALM
QR code bridges to DIDComm by fetch: scan, `GET`, pick `didcomm`, then process
the out-of-band URL. VCALM also defines `interaction:` and `web+interaction:`
scheme prefixes (§3.7.3).

**The natural bridge sits beside the trigger link, not in it.** An inviter can
run a VCALM coordinator whose interaction URL lists a `didcomm` entry and show
that interaction QR code next to a trigger link, as in the first DIDComm
fallback. Nothing in the chapter stands in the way.

**One URL carrying both is grammatically possible but ruled out.** A producer
could put `?iuv=1` in the query of a trigger link: VTI-LNK-010 forbids only the
reserved names in the query, VTI-LNK-011 makes the reader ignore the query, and
the chapter's own examples accept a link with a query inserted before `#`. The
result would look like a VCALM interaction URL, but it is built to be fetched:
a VCALM client learns nothing from it without a `GET`, and the link host would
have to answer that `GET` with a `protocols` map. That is the fetch by
reference that VTI-LNK-072 says a trigger link must not cause. VCALM's
interaction-specific identifier also sits in the path or query, which the
server sees, where the trigger link keeps its handle in the fragment.

**In one wallet**, a VCALM interaction URL, with or without a scheme prefix,
has no reserved names in its fragment, so a trigger reader passes it on to the
wallet's VCALM handler under the same limits as a DIDComm URL (VTI-LNK-020,
VTI-LNK-021). A URL that follows VCALM's 400-character guidance stays well
under 1,536 code points; VCALM's hard limit is 4,296, so a longer conforming
URL would be refused as `too-long`.

A trigger link with a DIDComm first request is a way for a trigger link to start
a DIDComm exchange. It does not put trigger links into VCALM's flow.

Open question: VCALM's table lists the protocol identifiers "supported today"
and says there is interest in moving it to a separate reference. This note did
not find a rule allowing or forbidding other identifiers in a `protocols` map.
If they are allowed, a VCALM coordinator could list a trigger link as one more
protocol. That would be a VCALM-side choice, it would not change the
trigger-link format, and the reader would already have fetched the interaction
URL by then.

## In this workspace

The `sign-in` flow is the one this workspace serves. Where it shows up:

- [`did-templates.md`](../02-vta/did-templates.md#wallet-sign-in-on-a-did-hosting-node-signinportal):
  the `SignInPortal` and `TrustTaskHTTPS` services a DID-hosting node publishes
  so that a wallet can select them (VTI-LNK-053, VTI-LNK-102, VTI-LNK-105).
- [`wallet-sign-in-uv-keys.md`](../02-vta/wallet-sign-in-uv-keys.md): the
  `auth/oob/identify` and `auth/oob/grant` documents a wallet's VTA signs.
- [`website-and-admin.md`](../03-vtc/website-and-admin.md#admin-login) and
  [`member-directory.md`](../03-vtc/member-directory.md): a VTC's console and
  member-portal sign-in with a wallet.

## What is not verified

- **No phone has been tested.** Every statement here about which app opens a
  link, coexistence in one scanner, and the no-wallet page is what the chapter
  specifies, not observed behaviour. The chapter itself notes that whether the
  fragment survives every camera, browser and app hand-off "is not yet verified
  on real devices" (the note under VTI-LNK-092).
- **Camera hand-off during a link-host outage** depends on how each platform
  caches association files. Not checked.
- **DIDComm readers other than Credo** were not checked. The Credo behaviour
  described above was read from the published `@credo-ts/didcomm` 0.7.4 and
  0.6.3 packages (`parseInvitationShortUrl`, `DidCommOutOfBandApi`), not run.
- **VCALM** was read from the 13 October 2026 Working Draft only. No VCALM
  implementation was tried.

## References

- VTI specification, Trigger Links, `spec/07a-links.md`,
  <https://trustoverip.github.io/dtgwg-vti-spec/>:
  VTI-LNK-010 to 013, 020, 021, 040, 041, 050 to 054, 057, 060, 070 to 072,
  081, 090 to 092, 120 to 123. Transports: VTI-TRN-002, VTI-TRN-003.
- DIDComm Messaging v2, Out Of Band Messages: "Standard Message Encoding",
  "Short URL Message Retrieval", "Privacy Considerations", and "Goal Codes",
  <https://identity.foundation/didcomm-messaging/spec/#standard-message-encoding>,
  <https://identity.foundation/didcomm-messaging/spec/#short-url-message-retrieval>.
- W3C VCALM 1.0, §3.7.1 Interaction URL Format, §3.7.2 Interaction QR Code
  Format, §3.7.3 Interaction Scheme Format, §3.7.4 Interaction Protocols
  Response, <https://www.w3.org/TR/vcalm-1.0/>.
- Trust Spanning Protocol specification, "Out of Band Introductions" and
  "Direct Relationship Forming".
- `@credo-ts/didcomm` 0.7.4 and 0.6.3, as published on npm.
- RFC 8252 §8.1 (custom schemes); RFC 9110 (fragments are not sent).
- [`tsp-enablement.md`](./tsp-enablement.md),
  [`tsp-vs-didcomm-trust-task-surface.md`](./tsp-vs-didcomm-trust-task-surface.md).
