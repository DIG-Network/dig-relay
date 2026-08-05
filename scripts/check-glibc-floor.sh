#!/usr/bin/env bash
#
# Assert that a shipped Linux binary does not require a NEWER glibc than the declared floor.
#
# WHY this gate exists (#2185): dig-relay's `linux-x64` binary silently began requiring glibc >= 2.39
# — not from any code change, but because GitHub moved the `ubuntu-latest` runner to Ubuntu 24.04.
# That single image change broke installation on Ubuntu 22.04 LTS (2.35), Debian 12 (2.36) and
# Amazon Linux 2023 (2.34): the three most common server distros in existence. A supported-floor
# CLAIM in a doc cannot notice that happening; only a gate over the produced artifact can, so the
# release build runs this against every Linux binary it publishes. (Ported from dig-node's proven
# #1736/#1741 pattern.)
#
# Usage: check-glibc-floor.sh <binary> <max-glibc-version>     [env: ALLOW_NO_GLIBC=1]
# Exit:  0 = binary's highest glibc requirement is <= <max-glibc-version>
#        1 = the floor has RISEN (the regression this gate catches)
#        2 = usage error (never silently green — that is how a gate rots into a no-op)
#        3 = the binary is not a glibc build at all (a *-musl target); set ALLOW_NO_GLIBC=1 to
#            declare a deliberate static build
set -uo pipefail

# Overridable so the unit tests can feed exact adversarial symbol tables (scripts/tests/).
READELF="${READELF_BIN:-readelf}"

binary="${1:-}"
floor="${2:-}"

if [ -z "$binary" ] || [ -z "$floor" ]; then
  echo "usage: $(basename "$0") <binary> <max-glibc-version>   e.g. dist/dig-relay-1.2.3-linux-x64 2.31" >&2
  exit 2
fi
if [ ! -f "$binary" ]; then
  echo "check-glibc-floor: no such binary: $binary" >&2
  exit 2
fi

# `-V` reports the .gnu.version_r needs (the authoritative "this binary requires GLIBC_x.y" list);
# `--dyn-syms` catches per-symbol tags such as `memcpy@GLIBC_2.14`. Reading both means neither an
# unusual link layout nor a stripped version section can hide a requirement.
#
# The `[0-9]` after the underscore is load-bearing: it drops the unversioned `GLIBC_PRIVATE` tag,
# which would otherwise pollute the maximum.
requirements="$("$READELF" -V --dyn-syms --wide "$binary" 2>/dev/null |
  grep -oE 'GLIBC_[0-9]+(\.[0-9]+)+' | sed 's/^GLIBC_//' | sort -Vu)"

# FAIL CLOSED on a binary with no versioned glibc symbols at all.
#
# A `*-unknown-linux-gnu` binary ALWAYS carries them, so their absence means the target is not a gnu
# target — in practice a musl build. That is the one substitution the other floor gates cannot see:
# the container assert only compares the CONTAINER's glibc to the declared number (which a musl
# target built inside that container still satisfies), and an execute-on-old-distro check goes green
# because a musl binary starts everywhere. dig-relay ships the -gnu target; accepting a symbol-less
# binary would let "just target musl and delete the container" pass every gate silently.
#
# `ALLOW_NO_GLIBC=1` is the deliberate opt-out for a genuinely intended static build.
if [ -z "$requirements" ]; then
  if [ "${ALLOW_NO_GLIBC:-0}" = "1" ]; then
    echo "check-glibc-floor: $binary has no versioned glibc symbols; ALLOW_NO_GLIBC=1 — OK"
    exit 0
  fi
  cat >&2 <<EOF
check-glibc-floor: FAIL — $binary requires NO versioned glibc symbols.
  A -gnu target always links them, so this is not a glibc build (almost always a *-musl target).
  dig-relay builds the -gnu target inside a pinned old-glibc container precisely so the floor is a
  decision, not an accident. Build for -gnu, or set ALLOW_NO_GLIBC=1 to declare a deliberate static
  build.
EOF
  exit 3
fi

# `sort -V` compares each dotted component NUMERICALLY. A lexical sort would rank glibc 2.4 above
# 2.31 and reject a perfectly old binary, so the version-aware sort is required, not cosmetic.
highest="$(printf '%s\n' "$requirements" | tail -n 1)"
newest_of_pair="$(printf '%s\n%s\n' "$floor" "$highest" | sort -V | tail -n 1)"

echo "check-glibc-floor: $binary requires glibc up to $highest (declared floor $floor)"
# shellcheck disable=SC2086  # deliberate word-split: flatten the newline list to one space-joined line
echo "  all requirements: $(printf '%s ' $requirements)"

if [ "$newest_of_pair" != "$floor" ]; then
  cat >&2 <<EOF
check-glibc-floor: FAIL — $binary requires glibc $highest, above the supported floor $floor.
  The binary will not start on the oldest supported distro. Almost always the BUILDER image moved
  (see .github/workflows/build-binaries.yml: the Linux target builds inside a pinned old-glibc
  container precisely so this cannot drift). Fix the builder, or raise the floor DELIBERATELY in
  the workflow, SPEC.md and the docs together.
EOF
  exit 1
fi

echo "check-glibc-floor: OK"
