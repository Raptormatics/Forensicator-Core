#!/usr/bin/env bash
#
# Builds a signed .fpk update package from the current COMMITTED git state
# (uses `git archive` — uncommitted changes are not included).
#
# Usage:
#   FORENSICATOR_UPDATE_PRIVATE_KEY=/path/to/private-key.pem \
#     ./scripts/build-update-package.sh [release-notes-file]
#
# Produces: dist/Forensicator-Core-<version>.fpk
#
# The private key is never read from a committed location — pass its path
# via the env var above. Generate a keypair with:
#   npx tsx scripts/generate-update-keys.ts
#
# Version defaults to whatever's already in package.json — easy to forget
# to bump before running this, which just re-publishes the same version
# again. Pass VERSION=X.Y.Z to have this script bump package.json and
# commit that one small change itself before building, so the archived
# tarball (and the running app's own self-reported version, once
# installed — see src/lib/updates/paths.ts's installedVersion(), which
# reads this exact file from the installed app) actually matches what
# gets published. A bare override that only changed what gets *announced*
# without touching the file itself would ship code that still reports the
# old version — worse than the original mistake, not a fix for it.
#   VERSION=1.2.3 FORENSICATOR_UPDATE_PRIVATE_KEY=/path/to/key \
#     ./scripts/build-update-package.sh

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$HERE"

: "${FORENSICATOR_UPDATE_PRIVATE_KEY:?Set FORENSICATOR_UPDATE_PRIVATE_KEY to the path of the Ed25519 private key (never commit this)}"
if [[ ! -f "$FORENSICATOR_UPDATE_PRIVATE_KEY" ]]; then
  echo "Private key not found at $FORENSICATOR_UPDATE_PRIVATE_KEY" >&2
  exit 1
fi

RELEASE_NOTES_FILE="${1:-}"
CURRENT_VERSION="$(node -p "require('./package.json').version")"

if [[ -n "${VERSION:-}" ]]; then
  if [[ ! "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "VERSION must look like X.Y.Z (got: $VERSION)" >&2
    exit 1
  fi
  if [[ "$VERSION" != "$CURRENT_VERSION" ]]; then
    echo "==> Bumping package.json: ${CURRENT_VERSION} -> ${VERSION}"
    node -e '
      const fs = require("fs");
      const pkg = JSON.parse(fs.readFileSync("package.json", "utf8"));
      pkg.version = process.env.VERSION;
      fs.writeFileSync("package.json", JSON.stringify(pkg, null, 2) + "\n");
    '
    git add package.json
    git commit -m "Bump version to ${VERSION}" --quiet
    echo "    committed: $(git rev-parse --short HEAD)"
  fi
else
  VERSION="$CURRENT_VERSION"
fi

OUT_DIR="$HERE/dist"
WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT
mkdir -p "$OUT_DIR"

echo "==> Building release tarball for v${VERSION} from committed git state"
git archive --format=tar.gz -o "$WORK_DIR/release.tar.gz" HEAD
SHA256="$(sha256sum "$WORK_DIR/release.tar.gz" | awk '{print $1}')"

echo "==> Writing manifest"
VERSION="$VERSION" SHA256="$SHA256" RELEASE_NOTES_FILE="$RELEASE_NOTES_FILE" WORK_DIR="$WORK_DIR" \
  node -e '
    const fs = require("fs");
    const notesFile = process.env.RELEASE_NOTES_FILE;
    const releaseNotes = notesFile && fs.existsSync(notesFile) ? fs.readFileSync(notesFile, "utf8") : "";
    const manifest = {
      version: process.env.VERSION,
      sha256: process.env.SHA256,
      releaseNotes,
      builtAt: new Date().toISOString(),
    };
    fs.writeFileSync(`${process.env.WORK_DIR}/manifest.json`, JSON.stringify(manifest, null, 2));
  '

echo "==> Signing release tarball with the update private key"
# Ed25519 signs the raw bytes directly (it hashes internally) — no separate
# digest step, which avoids any hex-vs-raw-bytes ambiguity at verify time.
# The sha256 in manifest.json above is informational only; the signature
# below is what forensicator-update.sh actually trusts.
FORENSICATOR_UPDATE_PRIVATE_KEY="$FORENSICATOR_UPDATE_PRIVATE_KEY" WORK_DIR="$WORK_DIR" \
  node -e '
    const crypto = require("crypto");
    const fs = require("fs");
    const privateKey = crypto.createPrivateKey(fs.readFileSync(process.env.FORENSICATOR_UPDATE_PRIVATE_KEY, "utf8"));
    const tarball = fs.readFileSync(`${process.env.WORK_DIR}/release.tar.gz`);
    const signature = crypto.sign(null, tarball, privateKey);
    fs.writeFileSync(`${process.env.WORK_DIR}/release.tar.gz.sig`, signature.toString("base64"));
  '

echo "==> Bundling .fpk package"
FPK_NAME="Forensicator-Core-${VERSION}.fpk"
tar -C "$WORK_DIR" -czf "$OUT_DIR/$FPK_NAME" manifest.json release.tar.gz release.tar.gz.sig

echo ""
echo "==> Built $OUT_DIR/$FPK_NAME"
echo "    version: $VERSION"
echo "    sha256:  $SHA256"
