# Verifiable Trust Network membership

A **Verifiable Trust Network** (VTN) curates communities and networks (`dtgwg-vti-spec`, *The Verifiable Trust Network*, VTI-VTN-001 – 063). A VTN may list this community without asking (VTI-VTN-010). The listing becomes **membership** only when the community acknowledges it (VTI-VTN-013).

This page covers the community's side, `vtc/networks/*` (`vtc-service/src/networks/`). The network side is the `vtn` service in [OpenVTC/verifiable-trust-network](https://github.com/OpenVTC/verifiable-trust-network), and both share the `vti-vtn` crate.

## What an administrator does

| Task | Effect |
|---|---|
| `vtc/networks/join/0.2` `{ url, network, groups }` | Accept a listing. The community checks that the network at `url` answers as `network`, then verifies its listing of the community. It registers each group in `groups` for its role (every role the network marks required must be assigned), signs the acknowledgement, and verifies the grant. |
| `vtc/networks/repudiate/0.2` `{ url, network, reason? }` | Reject a listing. The network must publish the repudiation beside it (VTI-VTN-012). |
| `vtc/networks/leave/0.2` `{ network, reason? }` | Depart by repudiating the network's grant. The network revokes what it issued for the community (VTI-VTN-053). |
| `vtc/networks/groups/register/0.2` `{ network, role, groupId }` | Register, or replace, the group serving one of the network's roles. |
| `vtc/networks/list`, `show` | The memberships, and the credentials that evidence each one. |

**Gating:**
- Every task needs `vtc.config.admin`.
- Every write also needs the administrator's step-up, bound to the document. Each one makes the community sign a statement to a third party.
- The step-up is asked for only after every check that would refuse the write: for `join`, that the network at `url` answers as `network`, lists this community, and has a group assigned to each role it requires; for `repudiate`, the first two; for `leave`, that the community is a member. A write that would fail costs no gesture.
- Every statement is signed **as the community**. A community holding a post-quantum key therefore signs with a proof set, which `vti-vtn` verifies.

## In the operator console

**Community → Networks** (`/admin/networks`, for `vtc.config.admin`) lists the memberships and shows each one's credentials: the network's listing, its membership grant, the community's acknowledgement or repudiation, and the groups registered for its roles. From there an administrator can:
- join a network;
- reject a listing;
- leave a network.

A network's invitation can link straight to the join form, `<public_url>/admin/networks?join=<network URL>&network=<network DID>`, both percent-encoded. When the network requires a group for a role that the form leaves out, the refusal names the role, and the form adds a row to pick a group for it. Only groups with a DID of their own are offered.

A group needs a DID of its own (minted by the community's VTA) to be registered. The network learns the group's DID, never its members.

## Broadcasts

Every registered group has the same delivery endpoint: the community's Trust Task endpoint, `<public_url>/v1/trust-tasks`. `public_url` must be set.

When a network broadcasts to a role, it sends `vtc/networks/deliver/0.1` `{ role, envelope }`, signed by the network. The community then:
1. Refuses unless the signer is a network the community is an acknowledged member of (`vtc/networks/deliver:notMember`), and it registered a group for `role` there (`vtc/networks/deliver:roleUnregistered`).
2. Verifies the envelope end to end (`vtc/networks/deliver:envelopeInvalid` otherwise):
   - the originating network's signature;
   - the hop chain, at most 8 hops;
   - that the last hop is the signer's, addressed to the group registered for `role`.
3. Answers `duplicate` for a message id it has already delivered, and sends nothing.
4. Otherwise pushes the envelope, unchanged, to each active member of the group as `vtc/networks/notice/0.1`, and answers `delivered`. The answer carries no member count, so the network does not learn the group's size.

Each delivery is audited as `NetworkMembershipChanged { event: broadcastRelayed }`.

A group registered under 0.1 named a REST endpoint, `<public_url>/v1/networks/relay/<group id>`, which is gone. Register the group again (`vtc/networks/groups/register/0.2`) so the network delivers to the Trust Task endpoint.

## Room passes

A network can open a room for one of its roles. A member asks for `vtc/networks/evidence/0.2`, which returns the community's registration of each group they are in (its signed `vtn/groups/register` request), plus the network's acceptance. They present that with their group membership credential to get the network's room pass. The evidence is released only to active members of the group.

## Not yet a capability module

Enabling a capability module projects it to the trust registry, which has no `vtn-membership` module yet. Until it does, these tasks are gated by the ACL alone.
