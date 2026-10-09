#!/usr/bin/env bash
#
# Forensicator Core CLI — thin wrapper for admins who prefer console/SSH
# over the Admin UI. Installed to /usr/local/bin/forensicator by
# provision.sh. Requires the invoking user to have their own sudo rights
# on this box (unrelated to the scoped sudoers rule the app's own service
# account gets — this is for a human administrator).

set -euo pipefail

APP_DIR="{{APP_DIR}}"

usage() {
  cat <<EOF
Usage:
  forensicator update <package.fpk> [--allow-downgrade]
  forensicator update --rollback <backup-id>
  forensicator update --list-backups
  forensicator update --overlay <overlay-package.fpk>
EOF
}

if [[ "${1:-}" != "update" ]]; then
  usage
  exit 1
fi
shift

if [[ "${1:-}" == "--list-backups" ]]; then
  ls -1 "${APP_DIR}/backups" 2>/dev/null | grep -v '^\.' || echo "(no backups yet)"
  exit 0
fi

if [[ "${1:-}" == "--rollback" ]]; then
  exec sudo "${APP_DIR}/deploy/forensicator-update.sh" --rollback "${2:?backup id required}"
fi

if [[ "${1:-}" == "--overlay" ]]; then
  exec sudo "${APP_DIR}/deploy/forensicator-update.sh" --overlay "${2:?overlay package path required}"
fi

PACKAGE_PATH="${1:?package path required}"
if [[ "${2:-}" == "--allow-downgrade" ]]; then
  exec sudo "${APP_DIR}/deploy/forensicator-update.sh" --package "$PACKAGE_PATH" --allow-downgrade
fi
exec sudo "${APP_DIR}/deploy/forensicator-update.sh" --package "$PACKAGE_PATH"
