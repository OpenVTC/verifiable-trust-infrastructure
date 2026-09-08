#!/usr/bin/env bash
#
# Every authorization-context `type` URI this workspace emits must be declared
# exactly once, as a named constant.
#
# ## What this is protecting
#
# The context under `payload.ext["org.openvtc.authorization-context"]` is what
# an approver's device renders as the approval card, and the card is chosen by
# discriminating on `type`. Two producers sharing a `type` therefore means one
# of them gets the other's card: the approver reads a prompt describing an act
# that is not the one they are authorising.
#
# The consumer side of that is already guarded — the browser plugin refuses a
# context whose `type` is not the one it expects, and there is a test that
# drives a correctly-signed Cierge share ask through the disclosure path and
# requires it to be refused. This is the producer side: it does not stop a
# collision between repositories, which no single repository can, but it stops
# the version of the mistake that happens here, and it makes a new producer's
# `type` a visible, named thing rather than a literal inside a `json!`.
#
# ## What it checks
#
# 1. No two constants declare the same URI.
# 2. No production source inlines the URI pattern outside a constant. A literal
#    is invisible to check 1, so the second producer added that way would
#    collide silently — which is precisely the case this exists for.
#
# Tests are exempt: a fixture asserting the wire value is the point of a
# fixture, and a test that could not name the URI could not check it. That
# means `tests/` directories AND the inline `#[cfg(test)] mod tests` at the foot
# of a `src/` file — two of which already carry the Cierge type as a fixture, so
# without this the guard would fail on day one against code that is correct.
#
# Run it: bash scripts/check-authz-context-types.sh
set -euo pipefail

pattern='https://openvtc\.org/[a-z0-9-]+/authorization-context/[0-9]+\.[0-9]+'
fail=0

# Production Rust only: `*/src/**`, with `tests/` and `benches/` excluded by
# construction rather than by name.
files=$(find . -path ./target -prune -o -path '*/src/*' -name '*.rs' -print 2>/dev/null | sort)

# Strip comments before looking at anything: a doc comment naming another
# producer's type as an example is documentation, not a declaration, and this
# file's own header would otherwise trip its own guard.
# Cut the file at its first module-level `#[cfg(test)]`, then strip comments.
#
# Truncation relies on the Rust convention that the test module comes last. A
# file that put one in the middle would have the rest of it skipped, so the line
# count that was scanned is printed on success — a file that suddenly scans
# almost nothing is visible rather than silently unguarded.
production_part() { sed -e '/^#\[cfg(test)\]/q' "$1" | sed -e 's://[^"]*$::' -e 's:^[[:space:]]*//.*::'; }

declare -a decl_names=() decl_uris=() decl_files=()
while IFS= read -r f; do
  [ -n "$f" ] || continue
  while IFS= read -r line; do
    [ -n "$line" ] || continue
    name=$(printf '%s' "$line" | sed -E 's/.*const[[:space:]]+([A-Z0-9_]+)[[:space:]]*:.*/\1/')
    uri=$(printf '%s' "$line" | grep -oE "$pattern" | head -1)
    [ -n "$uri" ] || continue
    decl_names+=("$name"); decl_uris+=("$uri"); decl_files+=("$f")
  done < <(production_part "$f" | grep -E "const[[:space:]]+[A-Z0-9_]+[[:space:]]*:[[:space:]]*&('static[[:space:]]+)?str[[:space:]]*=.*$pattern" || true)
done <<< "$files"

# 1. No two constants declare the same URI.
for i in "${!decl_uris[@]}"; do
  for j in "${!decl_uris[@]}"; do
    [ "$i" -lt "$j" ] || continue
    if [ "${decl_uris[$i]}" = "${decl_uris[$j]}" ]; then
      echo "::error::${decl_names[$i]} (${decl_files[$i]}) and ${decl_names[$j]} (${decl_files[$j]}) both declare ${decl_uris[$i]}. An approver's card is chosen by discriminating on this URI, so two producers sharing one means one of them renders the other's card — the approver reads a prompt describing an act that is not the one they are authorising. Give the new producer its own namespace segment."
      fail=1
    fi
  done
done

# 2. No inlined literals in production source.
while IFS= read -r f; do
  [ -n "$f" ] || continue
  while IFS= read -r hit; do
    [ -n "$hit" ] || continue
    echo "::error::$f: authorization-context type URI inlined outside a constant — $hit. Declare it as a \`const\` so a collision with another producer is visible to this check; a literal inside a \`json!\` is not."
    fail=1
  done < <(production_part "$f" \
      | grep -vE "const[[:space:]]+[A-Z0-9_]+[[:space:]]*:[[:space:]]*&('static[[:space:]]+)?str[[:space:]]*=" \
      | grep -oE "$pattern" || true)
done <<< "$files"

if [ "$fail" -ne 0 ]; then
  exit 1
fi

scanned=0
while IFS= read -r f; do
  [ -n "$f" ] || continue
  scanned=$(( scanned + $(production_part "$f" | wc -l) ))
done <<< "$files"

echo "OK: ${#decl_uris[@]} authorization-context type constant(s) across $(printf '%s\n' "$files" | grep -c . ) production file(s) ($scanned lines scanned), each declared once and named:"
for i in "${!decl_uris[@]}"; do
  echo "  ${decl_names[$i]} = ${decl_uris[$i]}  (${decl_files[$i]})"
done
