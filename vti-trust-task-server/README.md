# vti-trust-task-server

The receive side of a Trust Task service: what happens to a document between arriving and being answered, independent of which service answers it.

Used by:
- **`vtc-service`**: the community's `POST /v1/trust-tasks`, and its DIDComm and TSP inbound paths.
- **The VTN service**, in [OpenVTC/verifiable-trust-network](https://github.com/OpenVTC/verifiable-trust-network). It depends on this crate, never the reverse.

## The pipeline

`Spine::receive` runs every document through, in order:

1. Per-type size, before the body is parsed
2. Parse, keeping the received JSON verbatim
3. Freshness: `issuedAt` inside the acceptance window (VTI-OPS-024)
4. Expiry and recipient binding
5. The rules the task's specification declares: `proof`, `recipient` and `issuedAt` REQUIRED, and audience binding
6. Proof verification over the document as received, bound to `issuer`
7. Over DIDComm and TSP, the sender must be the proof's issuer (VTI-OPS-021/093)
8. Optional admission of the verified signer
9. The duplicate-id record (VTI-OPS-025 to 027)
10. Dispatch, then sign the answer. Refusals are signed too.

## What a service supplies

| Trait | What |
|---|---|
| `SpecPolicySource` | The spec policy by Type URI, from the service's generated spec crate |
| `SizeGate` | Per-type size limits. `SizeTable` is the plain table. |
| `ProofVerifier` | Proof verification. `ResolverProofVerifier` wraps a `TrustTaskVmResolver`. |
| `SpineHooks` | The service's DID, plus optional checks before and after the proof |
| `VerifiedAdmission` | Optional per-signer rate limiting |
| `AcceptedIdStore` | The duplicate-id record. `StoreAcceptedIds` keeps it in a `vti-common` keyspace (durable, shared by every binding); `InMemoryAcceptedIds` is for tests. |
| `Dispatcher` | The service's `match type_uri` |
| `ResponseSigner` | Signs every response document |

`http::routes` mounts `POST /v1/trust-tasks` for any `TrustTaskService`. The `reject` module builds `trust-task-error` documents. The `typed` module parses payloads and validates responses against the generated schemas.

This crate depends on no service and no `vti-specs-*` crate. The service decides which tasks exist and what their specifications require.
