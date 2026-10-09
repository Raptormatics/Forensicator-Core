#!/usr/bin/env bash
#
# Forensicator Core — privileged update installer.
#
# This is the ONLY script the forensicator service account may run as root
# (see the sudoers drop-in provision.sh installs) — the Admin UI's "Install
# Update" button invokes it via `sudo`, since the app's own service account
# is deliberately locked down (nologin, no shell) and can't stop services,
# replace its own code, or run migrations itself.
#
# Usage (as root):
#   forensicator-update.sh --package /path/to/Forensicator-Core-X.Y.Z.fpk [--allow-downgrade]
#   forensicator-update.sh --overlay /path/to/Forensicator-Enterprise-Overlay-X.Y.Z.fpk [--allow-downgrade]
#   forensicator-update.sh --rollback <backup-id>
#
# --overlay applies the Enterprise overlay — a separate, signed package
# (own Ed25519 keypair, deploy/overlay-public-key.pem, distinct from this
# instance's own update key). First use turns a running Core install into
# Enterprise in place; every later use is just a newer overlay version on
# the SAME Core install — this is a perpetual, versioned delta on top of
# whichever Core release is currently installed, not a one-time event.
# Two version numbers exist independently from here on: Core's own
# (package.json, exactly as before — the overlay never touches it
# directly) and the overlay's own (CONFIG_DIR/enterprise-delta.json).
#
# Every overlay manifest declares requiresCoreVersion — the minimum Core
# version it was built against. Applying one refuses outright if the
# installed Core version is older, with a clear "install the pending Core
# update first" message: this is the ordering guarantee between the two
# channels. Core itself never knows the overlay exists and never refuses
# on its account, in either direction — if that ever needs to change
# (a Core release genuinely incompatible with an old overlay), that's a
# release-discipline problem for whoever cuts that Core release, not
# something this script enforces today.
#
# Because a regular --package install fully replaces every file Core
# ships — including the handful the overlay also replaces, like
# sidebar.tsx — installing a Core update on an already-overlaid instance
# would otherwise silently strip the Pro UI back out from under a Pro
# database. So --package replays whichever overlay is currently applied
# (CONFIG_DIR/current-enterprise-delta.fpk, cached from its last
# successful apply) immediately after extracting the new Core release —
# see apply_delta_files() and the end of do_install().
#
# The overlay also never ships or overwrites package.json outright (that
# would stomp Core's own version field and anything else Core's build
# added since the overlay was last built) — instead it ships
# enterprise.deps.json, a small { dependencies, devDependencies }
# fragment merged into whatever package.json currently exists, every
# time the overlay is applied or replayed. See merge_overlay_deps().
#
# Writes live progress to BACKUPS_DIR/.current-progress.json (polled by the
# Admin UI) and a permanent result to <backup-dir>/result.json.

set -euo pipefail

APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG_DIR="/etc/forensicator"
ENV_FILE="${CONFIG_DIR}/forensicator.env"
PUBLIC_KEY="${APP_DIR}/deploy/update-public-key.pem"
OVERLAY_PUBLIC_KEY="${APP_DIR}/deploy/overlay-public-key.pem"
LIC_FILE="${CONFIG_DIR}/enterprise.lic"
DELTA_STATE_FILE="${CONFIG_DIR}/enterprise-delta.json"
DELTA_CACHE_FPK="${CONFIG_DIR}/current-enterprise-delta.fpk"
BACKUPS_DIR="${APP_DIR}/backups"
PROGRESS_FILE="${BACKUPS_DIR}/.current-progress.json"

if [[ $EUID -ne 0 ]]; then
  echo "Must be run as root." >&2
  exit 1
fi
if [[ ! -f "$ENV_FILE" ]]; then
  echo "Missing ${ENV_FILE} — this doesn't look like a provisioned instance." >&2
  exit 1
fi

# shellcheck disable=SC1090
source "$ENV_FILE"
SERVICE_USER="${SERVICE_USER:-forensicator}"
PORT="${PORT:-3000}"

mkdir -p "$BACKUPS_DIR"

MODE=""
PACKAGE_PATH=""
ROLLBACK_ID=""
ALLOW_DOWNGRADE=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --package)    MODE="install"; PACKAGE_PATH="$2"; shift 2 ;;
    --overlay)    MODE="overlay"; PACKAGE_PATH="$2"; shift 2 ;;
    --rollback)   MODE="rollback"; ROLLBACK_ID="$2"; shift 2 ;;
    --allow-downgrade) ALLOW_DOWNGRADE=1; shift ;;
    *) echo "Unknown argument: $1" >&2; exit 1 ;;
  esac
done
if [[ -z "$MODE" ]]; then
  echo "Usage: $0 --package <file.fpk> [--allow-downgrade] | --overlay <file.fpk> | --rollback <backup-id>" >&2
  exit 1
fi

# Writes the current stage to PROGRESS_FILE for the Admin UI to poll live.
# Includes this script's own PID so the Admin UI can tell a genuinely
# abandoned update (process gone, e.g. killed/crashed/rebooted mid-install)
# apart from one that's still actually running — see currentProgress() in
# src/lib/updates/paths.ts.
set_progress() {
  echo "==> [$1] $2"
  PROGRESS_FILE="$PROGRESS_FILE" STAGE="$1" MSG="$2" PID="$$" node -e '
    const fs = require("fs");
    fs.writeFileSync(process.env.PROGRESS_FILE, JSON.stringify({
      stage: process.env.STAGE, message: process.env.MSG, updatedAt: new Date().toISOString(),
      pid: Number(process.env.PID),
    }, null, 2));
  ' 2>/dev/null || true
}

# The progress file's only job is to signal "an update is actively running
# right now" (it gates new installs — see currentProgress()). Once a run
# reaches any terminal state, the permanent record lives in result.json;
# the progress file must be removed so the Admin UI doesn't stay stuck
# showing that last stage forever.
clear_progress() {
  rm -f "$PROGRESS_FILE"
}

services_present() {
  systemctl list-unit-files "$1" --no-legend 2>/dev/null | grep -q "$1"
}

stop_services() {
  systemctl stop forensicator.service || true
  if services_present forensicator-workers.service; then
    systemctl stop forensicator-workers.service || true
  fi
}

start_services() {
  systemctl start forensicator.service || true
  if services_present forensicator-workers.service; then
    systemctl start forensicator-workers.service || true
  fi
}

health_check() {
  # Up to 2 minutes for `next start` + DB connection to come up after a build.
  for _ in $(seq 1 60); do
    if curl -sf "http://127.0.0.1:${PORT}/api/health" >/dev/null 2>&1; then
      return 0
    fi
    sleep 2
  done
  return 1
}

installed_version() {
  node -p "require('${APP_DIR}/package.json').version"
}

# True (exit 0) if $1 >= $2, as major.minor.patch. Lexicographic compare —
# same algorithm as src/lib/updates/version.ts's isNewerVersion, kept in
# sync so the Admin UI's own checks and this script never disagree. A
# naive component-wise "every part >=" check is WRONG here — it would
# call 1.1.9 >= 1.2.0 false for the wrong reason (true call: 1.2.0 is
# newer) and 1.2.0 >= 1.1.9 would need care with the patch digit alone.
# Used for: the regular downgrade check, the overlay's own downgrade
# check against the currently-applied delta version, and the overlay's
# requiresCoreVersion gate against the installed Core version.
version_gte() {
  node -e "
    const [a, b] = [process.argv[1], process.argv[2]].map(v => v.split('.').map(Number));
    const len = Math.max(a.length, b.length);
    for (let i = 0; i < len; i++) {
      const na = a[i] ?? 0, nb = b[i] ?? 0;
      if (na !== nb) process.exit(na > nb ? 0 : 1);
    }
    process.exit(0);
  " "$1" "$2"
}

# Current overlay/delta version, or empty string if none has ever been
# applied. Distinct from Core's own version (installed_version(), always
# package.json) — these are two independent numbers from the moment the
# overlay is first applied.
installed_delta_version() {
  if [[ -f "$DELTA_STATE_FILE" ]]; then
    node -p "require('${DELTA_STATE_FILE}').version" 2>/dev/null || true
  fi
}

# DEPLOYMENT_MODE as currently baked into forensicator.env (defaults to
# "appliance", matching Core's own historical default) — used to rebuild
# with the matching NEXT_PUBLIC_DEPLOYMENT_MODE below, since that value is
# inlined into the client bundle at build time, not read at runtime.
current_deployment_mode() {
  local mode
  mode="$(grep -m1 '^DEPLOYMENT_MODE=' "$ENV_FILE" 2>/dev/null | cut -d'"' -f2)"
  echo "${mode:-appliance}"
}

# Merges enterprise.deps.json (shipped by the overlay, extracted alongside
# everything else) into package.json's dependencies/devDependencies. The
# overlay never ships a package.json of its own — see the header comment
# for why — so this is the only way it can add a Pro-only npm dependency.
# Idempotent: safe to rerun on every apply or replay.
merge_overlay_deps() {
  local deps_file="${APP_DIR}/enterprise.deps.json"
  if [[ ! -f "$deps_file" ]]; then
    return 0
  fi
  DEPS_FILE="$deps_file" PKG_FILE="${APP_DIR}/package.json" node -e '
    const fs = require("fs");
    const pkg = JSON.parse(fs.readFileSync(process.env.PKG_FILE, "utf8"));
    const extra = JSON.parse(fs.readFileSync(process.env.DEPS_FILE, "utf8"));
    pkg.dependencies = { ...pkg.dependencies, ...(extra.dependencies ?? {}) };
    pkg.devDependencies = { ...pkg.devDependencies, ...(extra.devDependencies ?? {}) };
    fs.writeFileSync(process.env.PKG_FILE, JSON.stringify(pkg, null, 2) + "\n");
  '
}

# Extracts an already-verified overlay package's release.tar.gz over
# APP_DIR and merges its dependency fragment in — the file-level half of
# applying the overlay, shared between do_overlay() (a new version) and
# do_install()'s post-Core-update replay (the SAME version, reapplied).
# Does not touch services, migrations, or the delta state file — callers
# handle those, since replay needs a subset of what a fresh apply needs.
apply_delta_files() {
  local release_tarball="$1"
  tar -C "$APP_DIR" -xzf "$release_tarball"
  merge_overlay_deps
  chown -R "${SERVICE_USER}:${SERVICE_USER}" "$APP_DIR"
}

# Backs up DB + app dir + config into $BACKUPS_DIR/<id>/, writes
# backup-manifest.json. Echoes the backup id.
create_backup() {
  local reason="$1" to_version="$2"
  local id from_version
  id="$(date -u +%Y%m%dT%H%M%SZ)"
  from_version="$(installed_version)"
  local dir="${BACKUPS_DIR}/${id}"
  mkdir -p "$dir"

  set_progress "backup" "Backing up database"
  pg_dump "$DATABASE_URL" | gzip > "${dir}/db.sql.gz"

  set_progress "backup" "Backing up application files"
  tar -C "$APP_DIR" \
    --exclude=node_modules --exclude=.next --exclude=reports-output --exclude=backups \
    -czf "${dir}/app-snapshot.tar.gz" .

  cp "$ENV_FILE" "${dir}/forensicator.env.bak"

  BACKUP_ID="$id" REASON="$reason" FROM_VERSION="$from_version" TO_VERSION="$to_version" \
    MANIFEST_PATH="${dir}/backup-manifest.json" \
    node -e '
      const fs = require("fs");
      fs.writeFileSync(process.env.MANIFEST_PATH, JSON.stringify({
        id: process.env.BACKUP_ID, reason: process.env.REASON,
        fromVersion: process.env.FROM_VERSION, toVersion: process.env.TO_VERSION,
        createdAt: new Date().toISOString(),
      }, null, 2));
    '

  echo "$id"
}

restore_backup() {
  local id="$1" dir="${BACKUPS_DIR}/${1}"
  if [[ ! -d "$dir" ]]; then
    echo "No such backup: $id" >&2
    return 1
  fi

  set_progress "restore" "Stopping services"
  stop_services

  set_progress "restore" "Restoring application files"
  # Clear tracked app content (not node_modules/.next/reports-output/backups,
  # which the snapshot deliberately excluded and which either regenerate or
  # must survive a restore) before re-extracting the snapshot over it.
  find "$APP_DIR" -mindepth 1 -maxdepth 1 \
    ! -name node_modules ! -name .next ! -name reports-output ! -name backups \
    -exec rm -rf {} +
  tar -C "$APP_DIR" -xzf "${dir}/app-snapshot.tar.gz"

  set_progress "restore" "Restoring database"
  gunzip -c "${dir}/db.sql.gz" | psql "$DATABASE_URL" >/dev/null

  set_progress "restore" "Restoring configuration"
  cp "${dir}/forensicator.env.bak" "$ENV_FILE"

  chown -R "${SERVICE_USER}:${SERVICE_USER}" "$APP_DIR" "$CONFIG_DIR"

  set_progress "restore" "Starting services"
  start_services
}

verify_package() {
  local pkg="$1" work="$2" public_key="${3:-$PUBLIC_KEY}"
  set_progress "verify" "Extracting package"
  tar -xzf "$pkg" -C "$work"
  for f in manifest.json release.tar.gz release.tar.gz.sig; do
    if [[ ! -f "${work}/${f}" ]]; then
      echo "Malformed package: missing ${f}" >&2
      return 1
    fi
  done

  set_progress "verify" "Verifying signature"
  WORK_DIR="$work" PUBLIC_KEY="$public_key" node -e '
    const fs = require("fs");
    const crypto = require("crypto");
    const publicKey = crypto.createPublicKey(fs.readFileSync(process.env.PUBLIC_KEY, "utf8"));
    const tarball = fs.readFileSync(`${process.env.WORK_DIR}/release.tar.gz`);
    const signature = Buffer.from(fs.readFileSync(`${process.env.WORK_DIR}/release.tar.gz.sig`, "utf8").trim(), "base64");
    const ok = crypto.verify(null, tarball, publicKey, signature);
    if (!ok) { console.error("Signature verification FAILED — refusing to install."); process.exit(1); }
    console.log("Signature OK.");
  '

  set_progress "verify" "Verifying checksum"
  local expectedSha actualSha
  expectedSha="$(node -p "require('${work}/manifest.json').sha256")"
  actualSha="$(sha256sum "${work}/release.tar.gz" | awk '{print $1}')"
  if [[ "$expectedSha" != "$actualSha" ]]; then
    echo "Checksum mismatch (manifest says ${expectedSha}, got ${actualSha})." >&2
    return 1
  fi
}

do_install() {
  local pkg="$PACKAGE_PATH"
  if [[ ! -f "$pkg" ]]; then
    echo "Package not found: $pkg" >&2
    exit 1
  fi

  local work
  work="$(mktemp -d)"
  trap 'rm -rf "$work"' EXIT

  verify_package "$pkg" "$work"

  local new_version current_version
  new_version="$(node -p "require('${work}/manifest.json').version")"
  current_version="$(installed_version)"

  if [[ "$ALLOW_DOWNGRADE" -ne 1 ]] && version_gte "$current_version" "$new_version"; then
    echo "Refusing downgrade/no-op: installed=${current_version} package=${new_version}. Pass --allow-downgrade to override." >&2
    exit 1
  fi

  local backup_id
  backup_id="$(create_backup "pre-update" "$new_version")"
  echo "Backup created: ${backup_id}"

  # From here on, any failure triggers an automatic rollback to this backup.
  local install_failed=0
  {
    set_progress "install" "Stopping services"
    stop_services

    set_progress "install" "Installing new release (v${new_version})"
    tar -C "$APP_DIR" -xzf "${work}/release.tar.gz"
    cp "$PUBLIC_KEY" "${APP_DIR}/deploy/update-public-key.pem" 2>/dev/null || true
    chown -R "${SERVICE_USER}:${SERVICE_USER}" "$APP_DIR"

    set_progress "install" "Installing dependencies and building"
    # NEXT_PUBLIC_DEPLOYMENT_MODE is inlined into the client bundle at
    # build time, not read from forensicator.env at runtime — without
    # this, every Core update would silently bake in "undefined" here
    # instead of whatever this instance was actually provisioned as,
    # even though server-side isAppliance() (reading DEPLOYMENT_MODE
    # itself, at request time) stays correct regardless. See
    # provision.sh's own version of this same export for the original
    # fix this mirrors.
    runuser -u "$SERVICE_USER" -- bash -lc "cd '${APP_DIR}' && npm ci && NEXT_PUBLIC_DEPLOYMENT_MODE='$(current_deployment_mode)' npm run build"

    set_progress "install" "Running database migrations"
    runuser -u "$SERVICE_USER" -- bash -lc "cd '${APP_DIR}' && npx prisma migrate deploy"

    # The Core release just extracted above fully replaced every file it
    # ships, including the handful the overlay also replaces (sidebar.tsx
    # etc.) — if an overlay is currently applied, replay it now so those
    # files, the merged dependency fragment, and any Pro migrations all
    # come back, instead of silently reverting to Core's plain versions.
    # Re-verifies the cached package's signature again rather than
    # trusting that it's unmodified since it was cached.
    if [[ -f "$DELTA_CACHE_FPK" ]]; then
      set_progress "install" "Re-applying the Enterprise overlay (v$(installed_delta_version))"
      local replay_work
      replay_work="$(mktemp -d)"
      verify_package "$DELTA_CACHE_FPK" "$replay_work" "$OVERLAY_PUBLIC_KEY"
      apply_delta_files "${replay_work}/release.tar.gz"
      rm -rf "$replay_work"

      # The build above (this function's own "Installing dependencies and
      # building" step) ran BEFORE this replay ever extracted the overlay's
      # files back on top — it only reflects the fresh Core release. Same
      # reasoning as do_overlay()'s own rebuild: without this, every Core
      # update would silently revert an overlaid instance's UI/routes back
      # to plain Core, even though delta-state still reports the overlay
      # as applied.
      set_progress "install" "Rebuilding with the Enterprise overlay included"
      runuser -u "$SERVICE_USER" -- bash -lc "cd '${APP_DIR}' && npm ci && NEXT_PUBLIC_DEPLOYMENT_MODE='$(current_deployment_mode)' npm run build"

      set_progress "install" "Running Enterprise overlay migrations"
      runuser -u "$SERVICE_USER" -- bash -lc "cd '${APP_DIR}' && npx prisma migrate deploy"
    fi

    set_progress "install" "Restarting services"
    start_services

    set_progress "install" "Waiting for the app to come back healthy"
    if ! health_check; then
      echo "Health check failed after install." >&2
      install_failed=1
    fi
  } || install_failed=1

  if [[ "$install_failed" -eq 1 ]]; then
    set_progress "rollback" "Install failed — automatically rolling back to ${backup_id}"
    restore_backup "$backup_id"
    if health_check; then
      set_progress "failed" "Update to v${new_version} failed and was rolled back to v${current_version}."
      write_result false "$new_version" "$current_version" "$backup_id" true "Install failed; automatically rolled back."
      clear_progress
      exit 1
    else
      set_progress "failed" "Update failed AND automatic rollback did not come back healthy — manual intervention required."
      write_result false "$new_version" "$current_version" "$backup_id" false "Install failed; automatic rollback also failed to come back healthy."
      clear_progress
      exit 1
    fi
  fi

  set_progress "complete" "Updated to v${new_version}."
  write_result true "$new_version" "$current_version" "$backup_id" false ""
  clear_progress
}

do_overlay() {
  local pkg="$PACKAGE_PATH"
  if [[ ! -f "$pkg" ]]; then
    echo "Package not found: $pkg" >&2
    exit 1
  fi

  local work
  work="$(mktemp -d)"
  trap 'rm -rf "$work"' EXIT

  verify_package "$pkg" "$work" "$OVERLAY_PUBLIC_KEY"

  local overlay_version current_version current_delta_version requires_core_version
  overlay_version="$(node -p "require('${work}/manifest.json').version")"
  current_version="$(installed_version)"
  current_delta_version="$(installed_delta_version)"
  requires_core_version="$(node -p "require('${work}/manifest.json').requiresCoreVersion")"
  local first_apply=1
  if [[ -n "$current_delta_version" ]]; then first_apply=0; fi

  # The ordering guarantee: this overlay version was built against a
  # specific Core baseline, and may rely on schema/columns/files that
  # baseline introduced. Checked here, authoritatively — the Admin UI
  # shows the same comparison for the user's benefit before they ever
  # click Install, but this is the actual trust boundary.
  if ! version_gte "$current_version" "$requires_core_version"; then
    echo "This Enterprise update requires Core v${requires_core_version} or later (installed: v${current_version}) — install the pending Core update first." >&2
    exit 1
  fi

  if [[ "$first_apply" -eq 0 && "$ALLOW_DOWNGRADE" -ne 1 ]] && version_gte "$current_delta_version" "$overlay_version"; then
    echo "Refusing downgrade/no-op: installed overlay=${current_delta_version} package=${overlay_version}. Pass --allow-downgrade to override." >&2
    exit 1
  fi

  local backup_id
  backup_id="$(create_backup "pre-overlay" "$overlay_version")"
  echo "Backup created: ${backup_id}"

  local install_failed=0
  {
    set_progress "overlay" "Stopping services"
    stop_services

    set_progress "overlay" "Applying Enterprise overlay (v${overlay_version})"
    apply_delta_files "${work}/release.tar.gz"

    # `next start` only ever serves whatever .next/ already held from the
    # last build — the files apply_delta_files() just extracted (new
    # pages, the Enterprise sidebar, new API routes, any new deps
    # merge_overlay_deps() just added to package.json) are completely
    # inert on disk until this runs. Without it, the overlay registers as
    # "applied" in delta-state but the UI/routes stay exactly what they
    # were before — nothing changes until an unrelated future Core update
    # finally triggers do_install()'s own rebuild.
    set_progress "overlay" "Rebuilding with the Enterprise overlay included"
    runuser -u "$SERVICE_USER" -- bash -lc "cd '${APP_DIR}' && npm ci && NEXT_PUBLIC_DEPLOYMENT_MODE='$(current_deployment_mode)' npm run build"

    # Core's own provision.sh never installs tshark or sets up a
    # Volatility3 venv — it has no PCAP/RAM Analysis to need them. The
    # overlay just added those features' application code and database
    # models above, but the underlying system tools still don't exist on
    # this machine unless this step adds them — without it, PCAP/RAM
    # Analysis would be visibly present in the UI and silently broken at
    # the first actual upload. Shipped as part of the overlay's own file
    # tree (apply_delta_files above just extracted it) rather than
    # inlined here, so deploy/packer/build.sh in the overlay repo can
    # call the exact same script when baking a fresh appliance image —
    # one source of truth, not two copies that can drift apart.
    set_progress "overlay" "Installing PCAP/RAM Analysis system dependencies"
    APP_DIR="$APP_DIR" SERVICE_USER="$SERVICE_USER" bash "${APP_DIR}/deploy/install-system-deps.sh"

    set_progress "overlay" "Running database migrations"
    runuser -u "$SERVICE_USER" -- bash -lc "cd '${APP_DIR}' && npx prisma migrate deploy"

    if [[ "$first_apply" -eq 1 ]]; then
      # Carries the already-activated license (Settings -> Enterprise,
      # gated on this exact file — see src/lib/license/activation.ts)
      # over into Enterprise's new LicenseStatus table, which exists for
      # the first time as of the migration just above. Enterprise's own
      # guard.ts re-verifies it itself from here on; this is a one-time
      # handoff, not a copy of the verification logic — and only makes
      # sense on the FIRST apply, never a later overlay version update.
      if [[ -f "$LIC_FILE" ]]; then
        set_progress "overlay" "Carrying over the activated Enterprise license"
        LIC_FILE="$LIC_FILE" runuser -u "$SERVICE_USER" -- bash -lc "cd '${APP_DIR}' && node -e '
          const fs = require(\"fs\");
          const { PrismaClient } = require(\"@prisma/client\");
          const prisma = new PrismaClient();
          const licContent = fs.readFileSync(process.env.LIC_FILE, \"utf8\");
          prisma.licenseStatus.upsert({
            where: { id: \"singleton\" },
            update: { licContent },
            create: { id: \"singleton\", licContent },
          }).then(() => prisma.\$disconnect()).catch((e) => { console.error(e); process.exit(1); });
        '"
      else
        echo "No activated license file found at ${LIC_FILE} — Enterprise will start unlicensed; activate under Settings -> License." >&2
      fi
    fi

    # Edited before the restart below (not after) so the services that
    # restart already pick it up — env vars are read once at process
    # startup, not hot-reloaded. Safe even if this whole block later
    # fails: restore_backup() below reverts this file from the backup
    # taken moments ago, same as every other file touched here. Core's
    # own channel stays live and independently useful even after this —
    # see do_install()'s replay step — so this only ever adds the
    # Enterprise channel on top, never removes Core's.
    if [[ "$first_apply" -eq 1 ]]; then
      set_progress "overlay" "Adding the Enterprise update channel"
      grep -v '^UPDATE_SERVER_URL=' "$ENV_FILE" > "${ENV_FILE}.tmp" || true
      echo 'UPDATE_SERVER_URL="https://updates.forensicator.io"' >> "${ENV_FILE}.tmp"
      mv "${ENV_FILE}.tmp" "$ENV_FILE"
      chmod 600 "$ENV_FILE"
    fi

    set_progress "overlay" "Restarting services"
    start_services

    set_progress "overlay" "Waiting for the app to come back healthy"
    if ! health_check; then
      echo "Health check failed after applying the overlay." >&2
      install_failed=1
    fi
  } || install_failed=1

  if [[ "$install_failed" -eq 1 ]]; then
    set_progress "rollback" "Overlay apply failed — automatically rolling back to ${backup_id}"
    restore_backup "$backup_id"
    if health_check; then
      set_progress "failed" "Enterprise overlay failed and was rolled back to v${current_version}."
      write_result false "$overlay_version" "$current_version" "$backup_id" true "Overlay apply failed; automatically rolled back."
      clear_progress
      exit 1
    else
      set_progress "failed" "Overlay apply failed AND automatic rollback did not come back healthy — manual intervention required."
      write_result false "$overlay_version" "$current_version" "$backup_id" false "Overlay apply failed; automatic rollback also failed to come back healthy."
      clear_progress
      exit 1
    fi
  fi

  # Only written on confirmed success — a failed-and-rolled-back attempt
  # must leave the previous state (or no state, on a first attempt)
  # exactly as it was.
  VERSION="$overlay_version" REQUIRES_CORE="$requires_core_version" STATE_PATH="$DELTA_STATE_FILE" node -e '
    const fs = require("fs");
    fs.writeFileSync(process.env.STATE_PATH, JSON.stringify({
      version: process.env.VERSION,
      requiresCoreVersion: process.env.REQUIRES_CORE,
      appliedAt: new Date().toISOString(),
    }, null, 2));
  '
  cp "$pkg" "$DELTA_CACHE_FPK"
  chmod 600 "$DELTA_STATE_FILE" "$DELTA_CACHE_FPK"

  set_progress "complete" "Enterprise overlay applied (v${overlay_version})."
  write_result true "$overlay_version" "$current_version" "$backup_id" false ""
  clear_progress
}

write_result() {
  local success="$1" to_version="$2" from_version="$3" backup_id="$4" rolled_back="$5" error="$6"
  local dir="${BACKUPS_DIR}/${backup_id}"
  SUCCESS="$success" TO_VERSION="$to_version" FROM_VERSION="$from_version" BACKUP_ID="$backup_id" \
    ROLLED_BACK="$rolled_back" ERROR="$error" RESULT_PATH="${dir}/result.json" \
    node -e '
      const fs = require("fs");
      fs.writeFileSync(process.env.RESULT_PATH, JSON.stringify({
        success: process.env.SUCCESS === "true",
        toVersion: process.env.TO_VERSION,
        fromVersion: process.env.FROM_VERSION,
        backupId: process.env.BACKUP_ID,
        rolledBack: process.env.ROLLED_BACK === "true",
        error: process.env.ERROR || null,
        completedAt: new Date().toISOString(),
      }, null, 2));
    '
}

do_rollback() {
  local dir="${BACKUPS_DIR}/${ROLLBACK_ID}"
  if [[ ! -d "$dir" ]]; then
    echo "No such backup: $ROLLBACK_ID" >&2
    exit 1
  fi
  local to_version current_version
  to_version="$(node -p "require('${dir}/backup-manifest.json').fromVersion")"
  current_version="$(installed_version)"

  restore_backup "$ROLLBACK_ID"

  if health_check; then
    set_progress "complete" "Rolled back to v${to_version}."
    write_result true "$to_version" "$current_version" "$ROLLBACK_ID" true ""
    clear_progress
  else
    set_progress "failed" "Rollback completed but the app did not come back healthy — manual intervention required."
    write_result false "$to_version" "$current_version" "$ROLLBACK_ID" true "App unhealthy after rollback."
    clear_progress
    exit 1
  fi
}

case "$MODE" in
  install)  do_install ;;
  overlay)  do_overlay ;;
  rollback) do_rollback ;;
esac
