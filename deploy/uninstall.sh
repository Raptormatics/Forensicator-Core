#!/usr/bin/env bash
#
# Forensicator Core — bare-metal uninstaller.
#
# Reverses deploy/provision.sh + deploy/setup.sh: stops and removes the
# systemd units, the sudoers rules, the CLI wrapper, /etc/forensicator,
# and the service account(s) — then backs up and drops the database.
#
# What's left alone by default, on purpose — these are general-purpose
# system resources this box might use for other things, not
# Forensicator-specific, so removing them silently isn't this script's
# call to make:
#   - PostgreSQL, Redis, and Node.js themselves (the apt packages) —
#     pass --purge-packages to remove those too.
#   - The swapfile provision.sh may have added — pass --remove-swap.
#   - This checkout's own files (the git clone itself, APP_DIR) — pass
#     --remove-app-dir. Left alone by default since it might hold
#     uncommitted local changes, and because this script lives inside it.
#
# Not for the Docker/docker-compose path — there's nothing for this
# script to undo there. `docker compose down -v` removes everything
# Docker-side (add -v to also drop the named volumes — database
# included); then just delete the cloned directory yourself.
#
# A full `pg_dump` backup is written before the database is touched,
# unless --no-backup is passed (that flag only skips the database dump —
# the small config files in /etc/forensicator are always copied into the
# same backup directory first, regardless, since they cost nothing to
# keep). Pass --keep-data to leave the database and its role alone
# entirely, if you plan to point a fresh install at the same database
# later.
#
# Usage (as root):
#   sudo ./deploy/uninstall.sh [options]
#
# Options:
#   --yes               Skip the interactive confirmation prompt
#   --dry-run           Print what would happen, change nothing
#   --keep-data         Leave the database and its forensicator role alone
#   --no-backup         Skip the pre-removal pg_dump (ignored with --keep-data)
#   --remove-app-dir    Also delete this checkout (APP_DIR) itself
#   --remove-swap       Also remove /swapfile, if provision.sh added it
#   --purge-packages    Also apt-get remove postgresql/redis-server/nodejs —
#                       asks for its own separate confirmation, since this
#                       can affect other software on a shared box
#   -h, --help          Show this help
#
# SERVICE_USER env var (default: forensicator) — set it to match
# whatever you passed provision.sh, if you ever overrode it there.

set -euo pipefail

APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG_DIR="/etc/forensicator"
ENV_FILE="${CONFIG_DIR}/forensicator.env"
SERVICE_USER="${SERVICE_USER:-forensicator}"
DB_NAME="forensicator"
DB_USER="forensicator"
BACKUP_DIR="/root/forensicator-uninstall-$(date -u +%Y%m%dT%H%M%SZ)"

ASSUME_YES=0
DRY_RUN=0
KEEP_DATA=0
NO_BACKUP=0
REMOVE_APP_DIR=0
REMOVE_SWAP=0
PURGE_PACKAGES=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --yes)              ASSUME_YES=1; shift ;;
    --dry-run)          DRY_RUN=1; shift ;;
    --keep-data)        KEEP_DATA=1; shift ;;
    --no-backup)        NO_BACKUP=1; shift ;;
    --remove-app-dir)   REMOVE_APP_DIR=1; shift ;;
    --remove-swap)      REMOVE_SWAP=1; shift ;;
    --purge-packages)   PURGE_PACKAGES=1; shift ;;
    -h|--help)
      sed -n '2,47p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    *)
      echo "Unknown option: $1 (see --help)" >&2
      exit 1
      ;;
  esac
done

if [[ $EUID -ne 0 ]]; then
  echo "Must be run as root (sudo ./deploy/uninstall.sh)" >&2
  exit 1
fi

run() {
  if [[ "$DRY_RUN" -eq 1 ]]; then
    echo "    [dry-run] $*"
  else
    "$@"
  fi
}

echo "=================================================================="
echo " Forensicator Core uninstaller"
echo "=================================================================="
echo "This will stop and remove:"
echo "  - forensicator.service, forensicator-workers.service"
echo "    (and forensicator-firstboot.service, if present)"
echo "  - /etc/sudoers.d/forensicator-update, /etc/sudoers.d/forensicator-ollama"
echo "  - /usr/local/bin/forensicator (CLI wrapper)"
echo "  - ${CONFIG_DIR}/ (config, any activated Enterprise license, credentials)"
echo "  - the '${SERVICE_USER}' service account, and 'forensicator-admin' if present"
if [[ "$KEEP_DATA" -eq 1 ]]; then
  echo "  - the database: NO — --keep-data was passed, left exactly as-is"
else
  echo "  - the '${DB_NAME}' database and '${DB_USER}' role (backed up first$([[ "$NO_BACKUP" -eq 1 ]] && echo ' — SKIPPED, --no-backup was passed' || echo " to ${BACKUP_DIR}"))"
fi
if [[ "$REMOVE_APP_DIR" -eq 1 ]]; then
  echo "  - this checkout itself: YES — ${APP_DIR}"
else
  echo "  - this checkout itself: left alone (pass --remove-app-dir to also delete ${APP_DIR})"
fi
if [[ "$REMOVE_SWAP" -eq 1 ]]; then
  echo "  - /swapfile: YES, if present"
fi
if [[ "$PURGE_PACKAGES" -eq 1 ]]; then
  echo "  - postgresql, redis-server, nodejs (apt packages): YES — asks separately below"
fi
echo "=================================================================="

if [[ "$DRY_RUN" -eq 1 ]]; then
  echo "DRY RUN — nothing will actually be changed."
fi

if [[ "$ASSUME_YES" -ne 1 && "$DRY_RUN" -ne 1 ]]; then
  echo ""
  echo "This cannot be undone past the backup step above. Type DELETE to continue:"
  read -r confirm
  if [[ "$confirm" != "DELETE" ]]; then
    echo "Aborted — nothing was changed." >&2
    exit 1
  fi
fi

if [[ "$PURGE_PACKAGES" -eq 1 && "$ASSUME_YES" -ne 1 && "$DRY_RUN" -ne 1 ]]; then
  echo ""
  echo "--purge-packages will apt-get remove postgresql/redis-server/nodejs — these"
  echo "may be used by other software on this machine, not just Forensicator."
  echo "Type PURGE to also remove them, or press Enter to skip just this part:"
  read -r purge_confirm
  if [[ "$purge_confirm" != "PURGE" ]]; then
    echo "Skipping package removal — everything else proceeds."
    PURGE_PACKAGES=0
  fi
fi

echo ""
echo "==> Stopping services"
for unit in forensicator.service forensicator-workers.service forensicator-firstboot.service; do
  if systemctl list-unit-files "$unit" --no-legend 2>/dev/null | grep -q "$unit"; then
    run systemctl stop "$unit" 2>/dev/null || true
    run systemctl disable "$unit" 2>/dev/null || true
  fi
done

if [[ -f "$ENV_FILE" ]]; then
  echo "==> Backing up ${CONFIG_DIR} config"
  run mkdir -p "$BACKUP_DIR"
  run cp -a "$CONFIG_DIR" "${BACKUP_DIR}/etc-forensicator" 2>/dev/null || true
fi

if [[ "$KEEP_DATA" -eq 1 ]]; then
  echo "==> Leaving the database alone (--keep-data)"
elif command -v psql >/dev/null 2>&1 && sudo -u postgres psql -tAc "SELECT 1 FROM pg_database WHERE datname='${DB_NAME}'" 2>/dev/null | grep -q 1; then
  if [[ "$NO_BACKUP" -ne 1 ]]; then
    echo "==> Backing up the database to ${BACKUP_DIR}/db.sql.gz"
    run mkdir -p "$BACKUP_DIR"
    if [[ "$DRY_RUN" -ne 1 ]]; then
      sudo -u postgres pg_dump "$DB_NAME" | gzip > "${BACKUP_DIR}/db.sql.gz"
    else
      echo "    [dry-run] sudo -u postgres pg_dump ${DB_NAME} | gzip > ${BACKUP_DIR}/db.sql.gz"
    fi
  else
    echo "==> Skipping database backup (--no-backup)"
  fi
  echo "==> Dropping database '${DB_NAME}' and role '${DB_USER}'"
  run sudo -u postgres dropdb "$DB_NAME" 2>/dev/null || true
  run sudo -u postgres dropuser "$DB_USER" 2>/dev/null || true
else
  echo "==> No '${DB_NAME}' database found — nothing to back up or drop"
fi

echo "==> Removing systemd units"
run rm -f /etc/systemd/system/forensicator.service \
          /etc/systemd/system/forensicator-workers.service \
          /etc/systemd/system/forensicator-firstboot.service
run systemctl daemon-reload

echo "==> Removing sudoers rules and CLI wrapper"
run rm -f /etc/sudoers.d/forensicator-update /etc/sudoers.d/forensicator-ollama
run rm -f /usr/local/bin/forensicator

echo "==> Removing ${CONFIG_DIR}"
run rm -rf "$CONFIG_DIR"

echo "==> Removing service account '${SERVICE_USER}'"
if id "$SERVICE_USER" >/dev/null 2>&1; then
  run userdel -r "$SERVICE_USER" 2>/dev/null || run userdel "$SERVICE_USER" 2>/dev/null || true
fi
if id forensicator-admin >/dev/null 2>&1; then
  echo "==> Removing OS admin account 'forensicator-admin'"
  run userdel -r forensicator-admin 2>/dev/null || run userdel forensicator-admin 2>/dev/null || true
fi

# Only relevant for an install that was ever provisioned with IMAGE_BUILD=1
# (forensicator-firstboot.service disables this to take over the console) —
# harmless no-op otherwise.
if ! systemctl is-enabled getty@tty1.service >/dev/null 2>&1; then
  echo "==> Re-enabling getty@tty1.service"
  run systemctl enable getty@tty1.service 2>/dev/null || true
fi

if [[ "$REMOVE_SWAP" -eq 1 && -f /swapfile ]]; then
  echo "==> Removing /swapfile"
  run swapoff /swapfile 2>/dev/null || true
  run rm -f /swapfile
  run sed -i '\#^/swapfile #d' /etc/fstab
fi

if [[ "$PURGE_PACKAGES" -eq 1 ]]; then
  echo "==> Removing postgresql, redis-server, nodejs"
  export DEBIAN_FRONTEND=noninteractive
  run apt-get remove --purge -y postgresql postgresql-contrib redis-server nodejs
  run apt-get autoremove -y
fi

if [[ "$REMOVE_APP_DIR" -eq 1 ]]; then
  echo "==> Removing ${APP_DIR}"
  # Can't rm -rf the directory this script is currently executing from —
  # schedule it for just after this process exits instead.
  if [[ "$DRY_RUN" -eq 1 ]]; then
    echo "    [dry-run] rm -rf ${APP_DIR}"
  else
    ( sleep 1; rm -rf "$APP_DIR" ) &
    disown
  fi
fi

echo ""
echo "=================================================================="
if [[ "$DRY_RUN" -eq 1 ]]; then
  echo " Dry run complete — nothing was changed."
else
  echo " Uninstall complete."
  [[ -d "$BACKUP_DIR" ]] && echo " Backup kept at: ${BACKUP_DIR}"
  if [[ "$REMOVE_APP_DIR" -ne 1 ]]; then
    echo " ${APP_DIR} was left in place — remove it yourself if you're done with it."
  fi
fi
echo "=================================================================="
