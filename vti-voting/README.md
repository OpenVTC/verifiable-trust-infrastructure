# vti-voting

Community voting for the Verifiable Trust Infrastructure (VTI-VOT-001 – 100): a
member proves only that they may vote, never who they are, and anyone permitted
to read the board can count it again.

- **Tickets** are predicate credential system (PCS) class credentials, issued
  blind by the community under one class per election (`registrar`).
- **Casts** are PCS attestations for a public point derived from the election,
  with the ballot bound in; the attestation's tag is the per-election nullifier
  (`voter`).
- **The ballot box** admits casts on the community's published key alone,
  counts one ballot per tag, and keeps an RFC 9162 board with inclusion and
  consistency proofs (`ballot_box`, `board`, `service`).
- **Rules and the count** over the generated `voting/*` wire types (`rules`,
  `tally`).

The VTA runs the voter role, the VTC the registrar, and `vti-voting-service`
the ballot box. The wire is the `voting/*`, `vtc/elections/*` and
`vta/pcs/voter/*` Trust Task families.
