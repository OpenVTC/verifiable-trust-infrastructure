#!/usr/bin/env bash
# =============================================================================
# render-tenant-overlay.sh
# =============================================================================
# Produce a per-tenant config overlay envelope for an un-baked (fleet) VTA
# enclave. The parent proxy serves this file to the enclave over vsock:5800; the
# enclave parses it into a typed, allowlisted overlay (deny_unknown_fields) and
# applies it onto its baked fleet-policy base config.
#
# This is a PER-TENANT, repeatable operation — distinct from the per-image,
# one-time build (build-vta.sh). See
# docs/05-design-notes/tenant-config-allowlist.md §3.4/§4.
#
# Only the allowlisted fields can be set. There is deliberately NO flag for
# admin_did, tee.mode, or any allow_* flag: those are baked (fleet policy) and
# the enclave rejects an overlay that tries to carry them.
#
# Usage:
#   render-tenant-overlay.sh \
#     --key-arn arn:aws:kms:us-east-1:1122...:key/abcd \
#     --mediator-did did:webvh:...:mediator \
#     [--vta-did-template 'did:webvh:{SCID}:acme.example.com:vta'] \
#     [--vta-name acme] \
#     [--public-url https://vta.acme.example.com] \
#     [--mediator-url wss://mediator.example.com] \
#     [--anchor-table-name vta-rollback-anchor-acme] \
#     [--anchor-writer-credential-ciphertext <base64>] \
#     [--bootstrap-claim-did did:key:z6Mk...] \
#     [--operation-rate-limit-per-sec 110] \
#     [--operation-rate-limit-burst 220] \
#     [--operation-rate-limit-per-subject-per-sec 30] \
#     [--operation-rate-limit-unauthenticated-per-sec 20] \
#     > tenant-overlay.json
#
# --bootstrap-claim-did is the public DID from `pnm bootstrap claim-did create`;
# only its holder can claim first-boot admin. Without it no claim is accepted.
#
# --operation-rate-limit-* are the operation budgets (appliance, per client,
# DIDComm/TSP senders without standing), sized for the instance it runs on
# (docs/02-vta/rate-limiting.md). Without them each client and the strangers
# are bounded at generous defaults, but the appliance is not, and overload ends
# in a restart.
# =============================================================================
set -euo pipefail

KEY_ARN=""
MEDIATOR_DID=""
MEDIATOR_URL=""
VTA_DID_TEMPLATE=""
VTA_NAME=""
PUBLIC_URL=""
ANCHOR_TABLE_NAME=""
ANCHOR_WRITER_CIPHERTEXT=""
BOOTSTRAP_CLAIM_DID=""
OPERATION_RATE=""
OPERATION_BURST=""
OPERATION_PER_SUBJECT=""
OPERATION_UNAUTHENTICATED=""

die() { echo "ERROR: $*" >&2; exit 1; }

while [ $# -gt 0 ]; do
    case "$1" in
        --key-arn)                              KEY_ARN="$2"; shift 2 ;;
        --mediator-did)                         MEDIATOR_DID="$2"; shift 2 ;;
        --mediator-url)                         MEDIATOR_URL="$2"; shift 2 ;;
        --vta-did-template)                     VTA_DID_TEMPLATE="$2"; shift 2 ;;
        --vta-name)                             VTA_NAME="$2"; shift 2 ;;
        --public-url)                           PUBLIC_URL="$2"; shift 2 ;;
        --anchor-table-name)                    ANCHOR_TABLE_NAME="$2"; shift 2 ;;
        --anchor-writer-credential-ciphertext)  ANCHOR_WRITER_CIPHERTEXT="$2"; shift 2 ;;
        --bootstrap-claim-did)                  BOOTSTRAP_CLAIM_DID="$2"; shift 2 ;;
        --operation-rate-limit-per-sec)         OPERATION_RATE="$2"; shift 2 ;;
        --operation-rate-limit-burst)           OPERATION_BURST="$2"; shift 2 ;;
        --operation-rate-limit-per-subject-per-sec)      OPERATION_PER_SUBJECT="$2"; shift 2 ;;
        --operation-rate-limit-unauthenticated-per-sec)  OPERATION_UNAUTHENTICATED="$2"; shift 2 ;;
        --help|-h)  sed -n '2,41p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *)          die "unknown argument: $1 (see --help)" ;;
    esac
done

command -v jq >/dev/null 2>&1 || die "jq is required"
[ -n "$KEY_ARN" ]           || die "--key-arn is required"
# The fleet base bakes tee.kms.allow_anchor_init = true, so the enclave requires
# an external anchor table (else it drops to manifest-only). Enforce it here too.
[ -n "$ANCHOR_TABLE_NAME" ] || die "--anchor-table-name is required (fleet bakes allow_anchor_init=true)"
# --mediator-did is optional: a REST-only fleet build has no mediator. When
# omitted, no [messaging] block is emitted and the baked base's placeholder is
# left untouched (REST-only enclaves ignore it).

# Basic ARN shape check — the enclave re-validates (account allowlist + shape),
# but fail early with a clear message rather than at enclave boot.
case "$KEY_ARN" in
    arn:aws:kms:*:*:key/*) : ;;
    *) die "--key-arn is not an arn:aws:kms:<region>:<account>:key/<id>: $KEY_ARN" ;;
esac

# Ed25519 did:key only; the enclave decodes and re-validates it at boot.
case "$BOOTSTRAP_CLAIM_DID" in
    ""|did:key:z6Mk*) : ;;
    *) die "--bootstrap-claim-did is not an Ed25519 did:key (did:key:z6Mk...): $BOOTSTRAP_CLAIM_DID" ;;
esac

# Positive integers only; the enclave re-validates the range (1-100000) at boot.
for v in "$OPERATION_RATE" "$OPERATION_BURST" "$OPERATION_PER_SUBJECT" "$OPERATION_UNAUTHENTICATED"; do
    case "$v" in
        "") : ;;
        *[!0-9]*|0*) die "operation rate limits are positive integers without leading zeros: $v" ;;
    esac
done
[ -n "$OPERATION_RATE" ] || [ -z "$OPERATION_BURST" ] \
    || die "--operation-rate-limit-burst needs --operation-rate-limit-per-sec"

# Build the envelope with jq so every value is correctly JSON-escaped. Optional
# fields are dropped (not emitted as null/empty) so the overlay stays minimal.
jq -n \
    --arg key_arn "$KEY_ARN" \
    --arg mediator_did "$MEDIATOR_DID" \
    --arg mediator_url "$MEDIATOR_URL" \
    --arg vta_did_template "$VTA_DID_TEMPLATE" \
    --arg vta_name "$VTA_NAME" \
    --arg public_url "$PUBLIC_URL" \
    --arg anchor_table_name "$ANCHOR_TABLE_NAME" \
    --arg anchor_writer_credential_ciphertext "$ANCHOR_WRITER_CIPHERTEXT" \
    --arg bootstrap_claim_did "$BOOTSTRAP_CLAIM_DID" \
    --arg operation_rate "$OPERATION_RATE" \
    --arg operation_burst "$OPERATION_BURST" \
    --arg operation_per_subject "$OPERATION_PER_SUBJECT" \
    --arg operation_unauthenticated "$OPERATION_UNAUTHENTICATED" \
    '
    def put($k; $v): if $v == "" then . else . + {($k): $v} end;
    def putn($k; $v): if $v == "" then . else . + {($k): ($v | tonumber)} end;

    {
      version: 1,
      overlay: (
        {}
        | put("vta_name"; $vta_name)
        | put("public_url"; $public_url)
        | put("bootstrap_claim_did"; $bootstrap_claim_did)
        | . + { tee_kms: (
              { key_arn: $key_arn }
              | put("vta_did_template"; $vta_did_template)
              | put("anchor_table_name"; $anchor_table_name)
              | put("anchor_writer_credential_ciphertext"; $anchor_writer_credential_ciphertext)
          ) }
        | (if $mediator_did == "" then . else . + { messaging: (
              { mediator_did: $mediator_did }
              | put("mediator_url"; $mediator_url)
          ) } end)
        | ({}
              | putn("operation_rate_limit_per_sec"; $operation_rate)
              | putn("operation_rate_limit_burst"; $operation_burst)
              | putn("operation_rate_limit_per_subject_per_sec"; $operation_per_subject)
              | putn("operation_rate_limit_unauthenticated_per_sec"; $operation_unauthenticated)
          ) as $server
        | (if $server == {} then . else . + { server: $server } end)
      ),
      integrity: null
    }
    '

