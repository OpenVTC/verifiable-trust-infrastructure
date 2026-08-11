### vta-service 0.14.33 — the setup wizard can choose TSP, and minting says so (#933)

`vta setup` offered two transports, REST and DIDComm, in a hardcoded two-item
list, and wrote `services.tsp = false` unconditionally — the wizard's TSP prompt
had been deferred to "a later phase". A build compiled with `--features tsp`
looked exactly like one without it.

**The wizard now offers TSP as a third option**, but only in a build that
compiled it. Without the feature there is no TSP dispatcher, and `#tsp` is the
*first* entry a peer matching on transport preference picks — advertising it
from a binary that can't answer would make the VTA unreachable for exactly the
peers that read its DID document most carefully. An option that can't be served
isn't offered.

It is not pre-ticked. Whether TSP works depends on the operator's mediator,
which nothing here can check, so opting in is a decision rather than a default
someone accepted by pressing enter. Selecting it without DIDComm re-asks: TSP
advertises the *same* mediator as DIDComm (D8), and that mediator is configured
in the DIDComm section. The wizard says all of this at the prompt, including
that `pnm services tsp enable` / `disable` can change it later.

**Minting now advertises what was chosen.** `build_vta_additional_services`
emits the `#tsp` entry (`TSPTransport`, endpoint = the mediator's DID, not a
URL) alongside `VTARest`, using the same fragment and type constants the runtime
`services tsp enable` patcher uses. Before this, `[services] tsp = true` set a
config flag and published nothing — the VTA spoke TSP while its DID document
told nobody, which is the shape of the bug #929 fixed for the VTC, and how the
reference deployment acquired its `#tsp` entry at DID log version 3 by hand.
A TSP-enabled VTA now carries it from log v1.

`build_did_document_inner` ends by sorting `service[]` through
`sort_services_canonical`, the same helper every runtime `with_*_service`
patcher ends with. The entries are appended in construction order — DIDComm
before the caller's additional services, which is where `#tsp` arrives — so
without the sort a minted document would advertise DIDComm ahead of TSP and
invert the preference order it is supposed to encode.

**`--from <toml>`** gains the matching refusal: `services.tsp = true` in a
binary built without the `tsp` feature now fails validation by name, next to the
existing "TSP requires DIDComm" rule. The declarative path can't be protected by
declining to offer a menu item, so it says it out loud.

No capability detection, deliberately — nothing here can verify the named
mediator routes TSP; its services belong to its own controller. The operator is
told that plainly instead.

Wizard test scripts answer the services multi-select **by label** rather than by
index (`Answer::Labels`), the convention the secrets-backend menu already
follows: its option list varies with the compiled feature set, so a positional
answer would mean something different under `--features tsp`. The selection
helpers take the option list as an argument, so the TSP mapping is covered in
CI's default (non-`tsp`) build too, not only where the option appears.
