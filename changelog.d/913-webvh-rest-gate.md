### vta-service 0.14.21 — the webvh update route joins the shared gate (#913)

Completes the REST half of the policy gate. `POST /contexts/{ctx}/dids/{scid}/update`
was the last route reaching its operation directly, and it is the one a
`webvh/dids/update` consent rule actually targets — a DID-document update
silently rotates the DID's update key, which is exactly the effect an operator
writes such a rule for.

It needed one step the ACL and context routes did not. The route is addressed by
**SCID** while the gate's payload — and therefore the consent digest an approver
signs — is keyed on the DID, as the trust-task path sends it. Gating on what the
handler holds would have digested the same update differently depending on how it
arrived, so an approval obtained over one transport could not have been consumed
over the other: a subtler failure than no gate at all. `resolve_webvh_did`
resolves the SCID first (reusing `find_record_by_scid`, which already accepts
either identifier form), and the route gates on `{did, …body}`.

The parity test extends to this route, asserting the refusal, that the body
carries the consent `challenge`, and that the DID's update key was **not**
rotated.

One note for whoever writes the next route test: assert on the route you mean.
An earlier draft posted to `…/dids/{scid}` rather than `…/dids/{scid}/update`,
fell through to the 404 fallback, and came back `500 Unable To Extract Key!` —
`tower_governor` failing to extract a peer IP from a `oneshot` request. That
reads like a handler fault and is not one; it cost a full debugging cycle and a
wrong conclusion about where the problem was.
