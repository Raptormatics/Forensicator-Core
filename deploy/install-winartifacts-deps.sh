#!/usr/bin/env bash
#
# Installs the system-level tools Windows Artifact Analysis needs:
# python3-libscca (Prefetch — src/lib/windows-artifacts/prefetch-parse.py),
# and a Python venv with regipy[full]/LnkParse3/olefile (registry hives,
# LNK, Jump Lists, Shellbags).
#
# Unlike deploy/install-system-deps.sh (PCAP/RAM Analysis's equivalent),
# which ships from the Enterprise overlay because those are overlay
# features, this lives in Core because Windows Artifact Analysis is a
# Core feature — so it has to run on every plain Core update too, not
# only when an overlay is applied. Called from:
#   - deploy/provision.sh, for a fresh image/first boot.
#   - deploy/forensicator-update.sh's do_install(), on every Core update,
#     so an already-deployed instance picks up these deps the first time
#     it updates to a Core version that introduced them. provision.sh
#     itself never runs again after first boot — without this call from
#     the update path too, every already-deployed instance (overlay or
#     not) would silently keep failing every Prefetch/registry/LNK/Jump
#     List/Shellbag upload forever after updating in place, since nothing
#     else ever installs these.
#
# Idempotent — safe to call on every provision/update.
#
# Usage (as root):
#   APP_DIR=/opt/forensicator SERVICE_USER=forensicator ./install-winartifacts-deps.sh

set -euo pipefail

APP_DIR="${APP_DIR:?Set APP_DIR to the application directory}"
SERVICE_USER="${SERVICE_USER:-forensicator}"

if ! python3 -c "import pyscca" >/dev/null 2>&1; then
  echo "==> Installing python3-libscca (Windows Artifact Analysis Prefetch dependency)"
  DEBIAN_FRONTEND=noninteractive apt-get update -y
  DEBIAN_FRONTEND=noninteractive apt-get install -y python3-venv python3-dev python3-libscca
fi

if [[ ! -x "${APP_DIR}/.venvs/winartifacts/bin/python3" ]]; then
  echo "==> Installing regipy, LnkParse3, olefile (Windows Artifact Analysis registry/LNK/Jump List/Shellbag dependencies)"
  mkdir -p "${APP_DIR}/.venvs"
  chown "${SERVICE_USER}:${SERVICE_USER}" "${APP_DIR}/.venvs"
  runuser -u "$SERVICE_USER" -- bash -lc "
    python3 -m venv '${APP_DIR}/.venvs/winartifacts' &&
    '${APP_DIR}/.venvs/winartifacts/bin/pip' install --upgrade pip &&
    '${APP_DIR}/.venvs/winartifacts/bin/pip' install 'regipy[full]' LnkParse3 olefile
  " || echo "WARNING: regipy/LnkParse3/olefile install failed — Windows Artifact Analysis will be unavailable until installed manually"
fi
