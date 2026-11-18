#!/usr/bin/env bash
# Build Dockerfile.nitro twice from nothing and compare the results (#2653).
#
#   scripts/check-nitro-reproducible.sh
#
# The Nitro image's layers feed PCR0, the enclave's attestation anchor. If two
# builds of one commit differ, a third party cannot recompute the PCR0 from
# source, and an operator's rebuild can lock the enclave out of the KMS key
# whose policy names the old PCR0.
#
# Each build runs on its own, newly created BuildKit builder with --no-cache, so
# neither layers nor `RUN --mount=type=cache` contents carry over (a second build
# on the same builder is a cache hit and proves nothing). SOURCE_DATE_EPOCH is
# the commit time and the OCI exporter rewrites file timestamps to it, so a
# clock is not a difference. What is left to differ is content: base images
# (pinned by digest), apk packages (pinned by version), and the compile.
#
# Compares the image manifests; on a mismatch, names each layer that differs
# and the Dockerfile step that produced it. Exit 0 = identical.
set -euo pipefail

root=$(git rev-parse --show-toplevel)
cd "$root"
work=$(mktemp -d)
trap 'rm -rf "$work"; docker buildx rm repro-1 repro-2 >/dev/null 2>&1 || true' EXIT

SOURCE_DATE_EPOCH=$(git log -1 --format=%ct)
export SOURCE_DATE_EPOCH
echo "SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH ($(git log -1 --format=%cI))"

for i in 1 2; do
  echo "::group::build $i"
  docker buildx create --name "repro-$i" --driver docker-container >/dev/null
  docker buildx build --builder "repro-$i" --no-cache \
    -f Dockerfile.nitro \
    --output "type=oci,dest=$work/build-$i.tar,rewrite-timestamp=true" \
    .
  # Removing the builder removes its state volume: the second build cannot see
  # anything the first one compiled, and the disk is free for it.
  docker buildx rm "repro-$i"
  mkdir -p "$work/$i"
  tar -xf "$work/build-$i.tar" -C "$work/$i"
  rm -f "$work/build-$i.tar"
  df -h /
  echo "::endgroup::"
done

# index.json -> image manifest -> config + layers. Python, not jq-only, to walk
# the blobs and print a per-layer comparison.
python3 - "$work/1" "$work/2" <<'PY'
import json, os, sys

def manifest(d):
    idx = json.load(open(os.path.join(d, "index.json")))
    m = idx["manifests"][0]
    blob = lambda dg: os.path.join(d, "blobs", *dg.split(":"))
    body = json.load(open(blob(m["digest"])))
    # An index (multi-platform) wraps the image manifest one level down.
    if "manifests" in body:
        m = body["manifests"][0]
        body = json.load(open(blob(m["digest"])))
    config = json.load(open(blob(body["config"]["digest"])))
    steps = [h.get("created_by", "") for h in config.get("history", []) if not h.get("empty_layer")]
    return m["digest"], body["config"]["digest"], [l["digest"] for l in body["layers"]], steps

a, b = manifest(sys.argv[1]), manifest(sys.argv[2])
print(f"build 1: manifest {a[0]}  config {a[1]}")
print(f"build 2: manifest {b[0]}  config {b[1]}")
if a[0] == b[0]:
    print("identical: the Nitro image is reproducible from this commit")
    sys.exit(0)

print("::error::two builds of the same commit produced different Nitro images")
for n, (la, lb) in enumerate(zip(a[2], b[2])):
    step = a[3][n] if n < len(a[3]) else "?"
    mark = "same" if la == lb else "DIFFERS"
    print(f"  layer {n:2}  {mark:8} {step[:110]}")
if len(a[2]) != len(b[2]):
    print(f"  layer counts differ: {len(a[2])} vs {len(b[2])}")
if a[2] == b[2]:
    print("  every layer is identical; the difference is in the image config")
sys.exit(1)
PY
