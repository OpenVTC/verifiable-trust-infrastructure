# Verifiable Trust Network membership

A **Verifiable Trust Network** (VTN) curates communities and networks (`dtgwg-vti-spec`, *The Verifiable Trust Network*, VTI-VTN-001 – 063). A VTN may list this community without asking (VTI-VTN-010). The listing becomes **membership** only when the community acknowledges it (VTI-VTN-013).

This page covers the community's side, `vtc/networks/*` (`vtc-service/src/networks/`). The network side is the `vtn` service in [OpenVTC/verifiable-trust-network](https://github.com/OpenVTC/verifiable-trust-network), and both share the `vti-vtn` crate.

## What an administrator does

| Task | Effect |
|---|---|
| `vtc/networks/join/0.1` `{ url, network, groups }` | Accept a listing. The community checks that the network at `url` answers as `network`, then verifies its listing of the community. It registers each group in `groups` for its role (every role the network marks required must be assigned), signs the acknowledgement, and verifies the grant. |
| `vtc/networks/repudiate/0.1` `{ url, network, reason? }` | Reject a listing. The network must publish the repudiation beside it (VTI-VTN-012). |
| `vtc/networks/leave/0.1` `{ network, reason? }` | Depart by repudiating the network's grant. The network revokes what it issued for the community (VTI-VTN-053). |
| `vtc/networks/groups/register/0.1` `{ network, role, groupId }` | Register, or replace, the group serving one of the network's roles. |
| `vtc/networks/list`, `show` | The memberships, and the credentials that evidence each one. |

**Gating:**
- Every task needs `vtc.config.admin`.
- Every write also needs the administrator's step-up, bound to the document. Each one makes the community sign a statement to a third party.
- Every statement is signed **as the community**. A community holding a post-quantum key therefore signs with a proof set, which `vti-vtn` verifies.

A group needs a DID of its own (minted by the community's VTA) to be registered. The network learns the group's DID, never its members.

## Broadcasts

The community gives a network a relay endpoint for each registered group: `<public_url>/v1/networks/relay/<group id>`. `public_url` must be set.

When a network broadcasts to a role, it posts the envelope there. The community then:
1. Verifies the envelope end to end:
   - the originating network's signature;
   - the hop chain;
   - that the last hop is signed by a network the community is an acknowledged member of, delivering to the group it registered there.
2. Drops repeats by message id.
3. Pushes the envelope, unchanged, to each active member of the group as `vtc/networks/notice/0.1`.

A delivery that does not verify is refused with `403`, which the network treats as final. Each relay is audited as `NetworkMembershipChanged { event: broadcastRelayed }`.

## Room passes

A network can open a room for one of its roles. A member asks for `vtc/networks/evidence/0.1`, which returns the community's registration of each group they are in, plus the network's acceptance. They present that with their group membership credential to get the network's room pass. The evidence is released only to active members of the group.

## Not yet a capability module

Enabling a capability module projects it to the trust registry, which has no `vtn-membership` module yet. Until it does, these tasks are gated by the ACL alone.
