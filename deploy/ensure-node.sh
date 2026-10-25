#!/usr/bin/env bash
#
# Makes sure the system Node.js is the supported major (26.x) at or above
# MIN_NODE_VERSION, upgrading the NodeSource package when it isn't.
#
# The minimum tracks Node.js security releases — the app runs on whatever
# system Node an instance was provisioned with, and nothing else ever
# upgrades it. 26.12.1 is the October 2026 security release (CVE-2026-111497,
# a Brotli decoder out-of-bounds write reachable through fetch() responses
# and node:zlib, among others). Raise MIN_NODE_VERSION here when a later
# security release lands.
#
# Called from:
#   - deploy/provision.sh, on a fresh install (fails if Node can't be made
#     current — no point finishing a vulnerable install).
#   - deploy/forensicator-update.sh's do_install(), before the build.
#   - deploy/install-winartifacts-deps.sh, which do_install() runs from the
#     NEW release — the only way an instance whose installed updater
#     predates this script still gets Node upgraded on its next update.
#   With --warn-only on both update paths: an update that can't reach the
#   package mirror still installs (failing would only roll back to the
#   same Node), and says loudly that Node is still outdated.
#
# Idempotent and quick when Node is already current (a version check).
#
# Usage (as root): bash deploy/ensure-node.sh [--warn-only]

set -euo pipefail

NODE_MAJOR=26
MIN_NODE_VERSION="26.12.1"
WARN_ONLY=0
[[ "${1:-}" == "--warn-only" ]] && WARN_ONLY=1

current_version() {
  command -v node >/dev/null 2>&1 || return 0
  node -v 2>/dev/null | sed 's/^v//'
}

# True when $1 >= $2 (dotted numeric versions).
version_gte() {
  [[ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | head -n1)" == "$2" ]]
}

is_current() {
  local v="$1"
  [[ -n "$v" && "${v%%.*}" == "$NODE_MAJOR" ]] && version_gte "$v" "$MIN_NODE_VERSION"
}

fail() {
  if [[ "$WARN_ONLY" -eq 1 ]]; then
    echo "!! WARNING: $1" >&2
    echo "!! Node.js below ${MIN_NODE_VERSION} has known security vulnerabilities — upgrade it manually: apt-get update && apt-get install -y nodejs" >&2
    exit 0
  fi
  echo "ERROR: $1" >&2
  exit 1
}

before="$(current_version)"
if is_current "$before"; then
  echo "Node.js v${before} is current (>= ${MIN_NODE_VERSION})."
  exit 0
fi

echo "==> Node.js ${before:+v${before} }is older than ${MIN_NODE_VERSION} — upgrading the ${NODE_MAJOR}.x package"
export DEBIAN_FRONTEND=noninteractive
if [[ ! -f /etc/apt/sources.list.d/nodesource.list && ! -f /etc/apt/sources.list.d/nodesource.sources ]] || [[ "${before%%.*}" != "$NODE_MAJOR" ]]; then
  curl -fsSL "https://deb.nodesource.com/setup_${NODE_MAJOR}.x" | bash - || fail "Couldn't set up the NodeSource ${NODE_MAJOR}.x repository."
fi
apt-get update -y >/dev/null || fail "apt-get update failed."
apt-get install -y nodejs || fail "Installing nodejs failed."

after="$(current_version)"
is_current "$after" || fail "Node.js is v${after:-missing} after the upgrade — the package mirror doesn't have ${MIN_NODE_VERSION} or later yet."
echo "Node.js upgraded: v${before:-none} -> v${after}"
