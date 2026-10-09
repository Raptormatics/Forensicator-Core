#!/usr/bin/env bash
#
# Builds a signed update package (via build-update-package.sh), writes a
# ready-to-publish latest.json next to it, and — if R2 credentials are
# configured (~/.forensicator/r2-credentials.env or the environment) —
# uploads both to Cloudflare R2 automatically via scripts/upload-to-r2.ts.
# Without credentials configured, it just builds locally and prints what
# to upload by hand.
#
# Forensicator Core shares the same R2 bucket/custom domain as Forensicator
# Enterprise's update packages, under a core/ prefix — same credentials
# file, no separate Cloudflare setup needed:
#
#   dist/Forensicator-Core-<version>.fpk  ->  {base_url}/dist/Forensicator-Core-<version>.fpk
#   <channel>/latest.json                  ->  {base_url}/<channel>/latest.json
#
# (both paths relative to {base_url}, which already includes /core —
# see UPDATE_BASE_URL below — so the actual R2 object keys underneath are
# core/dist/... and core/<channel>/latest.json)
#
# Usage:
#   FORENSICATOR_UPDATE_PRIVATE_KEY=/path/to/key ./scripts/publish-update.sh [channel] [release-notes-file]
#
# Env vars:
#   FORENSICATOR_UPDATE_PRIVATE_KEY   required — path to the Ed25519 signing key
#                                      (Core's own — see scripts/generate-update-keys.ts —
#                                      never Enterprise's; the two editions sign independently)
#   UPDATE_BASE_URL                   default: https://updates.forensicator.io/core

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$HERE"

CHANNEL="${1:-stable}"
RELEASE_NOTES_FILE="${2:-}"
BASE_URL="${UPDATE_BASE_URL:-https://updates.forensicator.io/core}"
BASE_URL="${BASE_URL%/}"

case "$CHANNEL" in
  stable|beta|preview) ;;
  *) echo "Channel must be one of: stable, beta, preview (got: $CHANNEL)" >&2; exit 1 ;;
esac

echo "==> Building signed package"
"${HERE}/scripts/build-update-package.sh" "$RELEASE_NOTES_FILE"

VERSION="$(node -p "require('./package.json').version")"
FPK_NAME="Forensicator-Core-${VERSION}.fpk"
FPK_PATH="dist/${FPK_NAME}"

if [[ ! -f "$FPK_PATH" ]]; then
  echo "Expected ${FPK_PATH} to exist after build-update-package.sh — something went wrong." >&2
  exit 1
fi

echo "==> Hashing package for latest.json (this is the OUTER .fpk hash — different"
echo "    from manifest.json's inner release.tar.gz hash inside the package itself)"
SHA256="$(sha256sum "$FPK_PATH" | awk '{print $1}')"
SIZE="$(stat -c%s "$FPK_PATH" 2>/dev/null || stat -f%z "$FPK_PATH")"
RELEASE_NOTES="$( [[ -n "$RELEASE_NOTES_FILE" && -f "$RELEASE_NOTES_FILE" ]] && cat "$RELEASE_NOTES_FILE" || echo "" )"
PUBLISHED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

mkdir -p "dist/${CHANNEL}"
LATEST_JSON="dist/${CHANNEL}/latest.json"

VERSION="$VERSION" SHA256="$SHA256" SIZE="$SIZE" RELEASE_NOTES="$RELEASE_NOTES" \
  PUBLISHED_AT="$PUBLISHED_AT" PACKAGE_URL="${BASE_URL}/dist/${FPK_NAME}" LATEST_JSON="$LATEST_JSON" \
  node -e '
    const fs = require("fs");
    const manifest = {
      version: process.env.VERSION,
      releaseNotes: process.env.RELEASE_NOTES,
      packageUrl: process.env.PACKAGE_URL,
      packageSha256: process.env.SHA256,
      packageSize: Number(process.env.SIZE),
      publishedAt: process.env.PUBLISHED_AT,
    };
    fs.writeFileSync(process.env.LATEST_JSON, JSON.stringify(manifest, null, 2) + "\n");
  '

echo ""
echo "==> Uploading to R2 (core/ prefix — shares the Enterprise update bucket)"
# The .fpk goes up FIRST, latest.json LAST — an appliance that checks for
# updates between the two uploads must never see a latest.json pointing at
# a package that isn't there yet.
set +e
UPLOAD_OUTPUT="$(npx tsx "${HERE}/scripts/upload-to-r2.ts" "$FPK_PATH" "core/dist/${FPK_NAME}" "application/octet-stream" 2>&1)"
FPK_UPLOAD_STATUS=$?
echo "$UPLOAD_OUTPUT"

if [[ "$FPK_UPLOAD_STATUS" -eq 0 ]]; then
  UPLOAD_OUTPUT="$(npx tsx "${HERE}/scripts/upload-to-r2.ts" "$LATEST_JSON" "core/${CHANNEL}/latest.json" "application/json" 2>&1)"
  LATEST_UPLOAD_STATUS=$?
  echo "$UPLOAD_OUTPUT"
else
  LATEST_UPLOAD_STATUS=$FPK_UPLOAD_STATUS
fi
set -e

echo ""
if [[ "$FPK_UPLOAD_STATUS" -eq 0 && "$LATEST_UPLOAD_STATUS" -eq 0 ]]; then
  echo "==> Published:"
  echo "    ${BASE_URL}/dist/${FPK_NAME}"
  echo "    ${BASE_URL}/${CHANNEL}/latest.json"
elif [[ "$FPK_UPLOAD_STATUS" -eq 2 ]]; then
  echo "==> R2 not configured — built locally only. Upload these two by hand"
  echo "    (to the SAME bucket Enterprise uses, under the core/ prefix):"
  echo "    ${FPK_PATH}  ->  core/dist/${FPK_NAME}  (served at ${BASE_URL}/dist/${FPK_NAME})"
  echo "    ${LATEST_JSON}  ->  core/${CHANNEL}/latest.json  (served at ${BASE_URL}/${CHANNEL}/latest.json)"
else
  echo "==> Upload FAILED — see output above. Nothing was left half-published:" >&2
  echo "    the .fpk only goes live after a successful upload, and latest.json" >&2
  echo "    is never uploaded unless the .fpk upload succeeded first." >&2
  exit 1
fi
echo ""
cat "$LATEST_JSON"
