# vtc-client

Client SDK for a Verifiable Trust Community (VTC) — the VTC counterpart to
[`vta-sdk`](../vta-sdk) (which is the client for VTAs).

Authenticate to a VTC and drive its member-facing / admin-facing surface over
REST: list members (the community roster), run the join ceremony, remove
members, and manage community policy.

It's deliberately thin: authentication reuses `vta-sdk`'s audience-agnostic
challenge-response flow (`auth_light::challenge_response_light`), and the join
wire types are re-exported from `vta_sdk::protocols::join_requests`. Only the
VTC-specific REST shapes (member records, pagination) live here.

Pass the **full** API base including the mount (default `/v1`), e.g.
`https://vtc.example.com/v1`.

## Status

First cut: authentication + member listing. Join / removal / policy methods are
layered on next.
