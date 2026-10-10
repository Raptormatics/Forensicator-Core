#!/usr/bin/env bash
#
# Forensicator Core — fresh-OS provisioning script.
#
# Run ONCE on a clean Debian/Ubuntu machine to install everything needed to
# run the app: system packages, Node.js, the built application, and systemd
# units. This script requires network access (apt + npm registry).
#
# Two distinct ways this gets run, and they need genuinely different
# endings — not just a flag tweak:
#
#   Bare metal / VM, run by hand (the default — IMAGE_BUILD unset):
#     Someone already logged into their own machine, running this
#     directly (the documented git-clone quickstart). deploy/setup.sh
#     runs automatically at the end: generates secrets, migrates, seeds
#     the org, starts services — all synchronously, right now, in this
#     same shell. No separate OS account, no console takeover, nothing
#     deferred to a later boot.
#
#   Building a shared golden image (IMAGE_BUILD=1 — the Enterprise
#   overlay's Packer template sets this):
#     An unknown FUTURE user will clone this image and boot it fresh,
#     with only console access and no OS login of their own yet.
#     Secrets can't be generated now — baking them into the image would
#     mean every clone shares the same DATABASE_URL password and
#     NEXTAUTH_SECRET. deploy/first-boot.sh handles that case instead,
#     at the real first boot of each individual clone, which is also
#     where it creates a fresh OS admin account and shows credentials
#     on the console — none of which makes sense for the bare-metal
#     case above, where the person running this already has their own
#     login.
#
# Usage (as root):
#   ORG_NAME="Acme Corp" ORG_SLUG=acme ./deploy/provision.sh
#
# Env vars (all optional):
#   ORG_NAME           seeded organization name (default: "Default Organization")
#   ORG_SLUG           seeded organization slug (default: "default")
#   PUBLIC_URL         externally reachable URL, used as NEXTAUTH_URL (default: http://localhost:3000)
#   APP_PORT           port next start binds to (default: 3000)
#   SERVICE_USER       system user the app runs as (default: forensicator)
#   IMAGE_BUILD        "1" if building a shared image for later cloning (default: unset — see above)
#   UPDATE_SERVER_URL  update server "Check for Updates" queries (default:
#                      https://updates.forensicator.io/core — same public URL for every
#                      install, not a secret). Set to an empty string to disable the
#                      feature entirely (e.g. air-gapped installs); offline/CLI installs
#                      of a signed .fpk package work regardless of this setting.

set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "Must be run as root (sudo ./deploy/provision.sh)" >&2
  exit 1
fi

APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PUBLIC_URL="${PUBLIC_URL:-http://localhost:3000}"
APP_PORT="${APP_PORT:-3000}"
SERVICE_USER="${SERVICE_USER:-forensicator}"
IMAGE_BUILD="${IMAGE_BUILD:-0}"
UPDATE_SERVER_URL="${UPDATE_SERVER_URL-https://updates.forensicator.io/core}"
CONFIG_DIR="/etc/forensicator"
ENV_FILE="${CONFIG_DIR}/forensicator.env"

echo "==> Provisioning Forensicator Core at ${APP_DIR}"

echo "==> Ensuring adequate swap (next build can spike memory well past a small VM's RAM)"
if [[ "$(swapon --show=SIZE --noheadings 2>/dev/null | wc -l)" -eq 0 ]]; then
  fallocate -l 4G /swapfile 2>/dev/null || dd if=/dev/zero of=/swapfile bs=1M count=4096
  chmod 600 /swapfile
  mkswap /swapfile
  swapon /swapfile
  grep -q '^/swapfile' /etc/fstab || echo '/swapfile none swap sw 0 0' >> /etc/fstab
  echo "    added 4G swapfile"
else
  echo "    swap already present, leaving as-is"
fi

echo "==> Installing system packages"
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y ca-certificates curl gnupg build-essential postgresql postgresql-contrib redis-server sudo

echo "==> Installing Node.js 26.x (current LTS)"
if ! command -v node >/dev/null || [[ "$(node -v)" != v26.* ]]; then
  curl -fsSL https://deb.nodesource.com/setup_26.x | bash -
  apt-get install -y nodejs
fi
# The NodeSource package bundles whatever npm shipped with that Node
# build at release time, which drifts behind as patch releases land —
# pull the latest npm release compatible with the installed Node major
# right now rather than letting it go stale from day one.
npm install -g npm@latest
# Quiets npm's own "new major version available" nag on every npm
# invocation from here on (migrations, seeding, future updates/overlay
# applies) — written to npm's global config so it applies regardless of
# which user runs npm, not just root.
npm config set update-notifier false --location=global
echo "    node $(node -v), npm $(npm -v)"

echo "==> Creating service user '${SERVICE_USER}'"
if ! id "$SERVICE_USER" >/dev/null 2>&1; then
  useradd --system --create-home --shell /usr/sbin/nologin "$SERVICE_USER"
fi

if [[ "$IMAGE_BUILD" == "1" ]]; then
  # A separate, real (sudo, login-shell) OS account for actually managing
  # the box — deliberately NOT the same account as SERVICE_USER above,
  # which stays locked down (nologin) since it only ever needs to run the
  # app. Created with no password here (locked, unusable) —
  # first-boot.sh generates and sets the actual per-instance password at
  # the real first boot of each clone, so a shared base image never
  # carries a shared credential. Skipped entirely for a direct bare-metal
  # install (the default) — whoever ran `sudo` to get here already has
  # their own OS login; a second generated account would just be an
  # unused credential sitting around.
  echo "==> Creating OS admin account 'forensicator-admin' (password set on first boot)"
  if ! id forensicator-admin >/dev/null 2>&1; then
    useradd --create-home --shell /bin/bash --groups sudo forensicator-admin
  fi
fi

echo "==> Enabling PostgreSQL and Redis"
systemctl enable --now postgresql
systemctl enable --now redis-server

echo "==> Installing dependencies and building the app"
cd "$APP_DIR"
npm ci
npm run prisma:generate
# NEXT_PUBLIC_* vars are inlined into the client bundle at build time, not
# read from the env file at runtime — must be exported before `npm run
# build`. See the Enterprise overlay's own provision.sh for the real bug
# this guards against (a client-side gate silently reading undefined).
export NEXT_PUBLIC_DEPLOYMENT_MODE="appliance"
npm run build

echo "==> Writing baked (non-secret) config to ${ENV_FILE}"
mkdir -p "$CONFIG_DIR"
chmod 700 "$CONFIG_DIR"
cat > "$ENV_FILE" <<EOF
NODE_ENV="production"
PORT="${APP_PORT}"
DEPLOYMENT_MODE="appliance"
NEXT_PUBLIC_DEPLOYMENT_MODE="appliance"
NEXTAUTH_URL="${PUBLIC_URL}"
UPLOAD_DEFAULT_USER_EMAIL="analyst@forensicator.local"
REPORTS_DIR="${APP_DIR}/reports-output"
EOF
# Quoted — this file gets `source`d later (first-boot.sh), and ORG_NAME
# commonly contains spaces (e.g. "Default Organization", "Acme Corp").
# Unquoted, bash parses that as an assignment followed by a bogus command.
{
  echo "ORG_NAME=\"${ORG_NAME:-Default Organization}\""
  echo "ORG_SLUG=\"${ORG_SLUG:-default}\""
} >> "$ENV_FILE"
if [[ -n "$UPDATE_SERVER_URL" ]]; then
  # Where "Check for Updates" looks, same for every install, not a secret.
  # Empty means that feature just shows "not configured"; offline .fpk
  # installs work either way.
  echo "UPDATE_SERVER_URL=\"${UPDATE_SERVER_URL}\"" >> "$ENV_FILE"
fi
chmod 600 "$ENV_FILE"
chown -R "${SERVICE_USER}:${SERVICE_USER}" "$APP_DIR" "$CONFIG_DIR"

echo "==> Installing systemd units"
sed "s#{{APP_DIR}}#${APP_DIR}#g; s#{{SERVICE_USER}}#${SERVICE_USER}#g" \
  "${APP_DIR}/deploy/systemd/forensicator.service" > /etc/systemd/system/forensicator.service
sed "s#{{APP_DIR}}#${APP_DIR}#g; s#{{SERVICE_USER}}#${SERVICE_USER}#g" \
  "${APP_DIR}/deploy/systemd/forensicator-workers.service" > /etc/systemd/system/forensicator-workers.service

if [[ "$IMAGE_BUILD" == "1" ]]; then
  # forensicator-firstboot.service takes exclusive ownership of tty1 (see
  # FIRSTBOOT_STDIO below) to reliably show the generated credentials on
  # whatever console you're watching — disabled here so it can't race to
  # grab tty1 first; first-boot.sh explicitly starts it back up once done.
  systemctl disable getty@tty1.service 2>/dev/null || true

  # Deliberately NOT TTYReset=/TTYVHangup=yes — those are for kicking an
  # existing session off a tty before taking it over, which doesn't apply
  # here (getty@tty1 is already disabled, above, so nothing else is ever
  # attached to tty1 in the first place) and were the direct cause of a
  # real, reproducible bug in the Enterprise overlay this was split from:
  # restarting this unit killed its own process instantly with signal=HUP,
  # because TTYVHangup's hangup-before-exec step was hanging up the very
  # tty this same unit had just taken over moments before. Minimal config
  # only.
  FIRSTBOOT_STDIO='StandardInput=tty\nStandardOutput=tty\nStandardError=tty\nTTYPath=/dev/tty1'
  sed "s#{{APP_DIR}}#${APP_DIR}#g; s#{{SERVICE_USER}}#${SERVICE_USER}#g; s#{{FIRSTBOOT_STDIO}}#${FIRSTBOOT_STDIO}#" \
    "${APP_DIR}/deploy/systemd/forensicator-firstboot.service" > /etc/systemd/system/forensicator-firstboot.service
  systemctl daemon-reload
  systemctl enable forensicator-firstboot.service
  systemctl enable forensicator.service
  systemctl enable forensicator-workers.service
else
  # No forensicator-firstboot.service at all in this mode — deploy/setup.sh
  # (called directly, below) does its job synchronously instead. Strip the
  # dependency from the two real services so starting them doesn't pull in
  # a unit that was never installed — a surgical edit, not a wholesale
  # rewrite, so "After=... network.target" keeps that ordering.
  sed -i -e 's/^After=forensicator-firstboot\.service /After=/' \
         -e '/^Requires=forensicator-firstboot\.service$/d' \
    /etc/systemd/system/forensicator.service /etc/systemd/system/forensicator-workers.service
  systemctl daemon-reload
  systemctl enable forensicator.service
  systemctl enable forensicator-workers.service
fi

echo "==> Installing update CLI and scoped sudoers rule"
chmod +x "${APP_DIR}/deploy/forensicator-update.sh"
sed "s#{{APP_DIR}}#${APP_DIR}#g" "${APP_DIR}/deploy/forensicator-cli.sh" > /usr/local/bin/forensicator
chmod +x /usr/local/bin/forensicator
# The app's own service account is deliberately locked down (nologin, no
# shell) — this is the one narrow exception, letting the Admin UI trigger
# the update installer (which needs root to stop services, replace app
# files, and run migrations) without giving that account broader sudo.
cat > /etc/sudoers.d/forensicator-update <<SUDOERS
${SERVICE_USER} ALL=(root) NOPASSWD: ${APP_DIR}/deploy/forensicator-update.sh *
SUDOERS
chmod 440 /etc/sudoers.d/forensicator-update
visudo -cf /etc/sudoers.d/forensicator-update

echo "==> Installing Ollama control script and scoped sudoers rule"
chmod +x "${APP_DIR}/deploy/forensicator-ollama-ctl.sh"
# Same rationale as the update rule above — lets Settings > AI Analysis
# install/start/stop a local Ollama service without broadening the app's
# own sudo access beyond these two specific, audited scripts.
cat > /etc/sudoers.d/forensicator-ollama <<SUDOERS
${SERVICE_USER} ALL=(root) NOPASSWD: ${APP_DIR}/deploy/forensicator-ollama-ctl.sh *
SUDOERS
chmod 440 /etc/sudoers.d/forensicator-ollama
visudo -cf /etc/sudoers.d/forensicator-ollama

echo ""
echo "==> Provisioning complete."
echo ""

if [[ "$IMAGE_BUILD" == "1" ]]; then
  cat <<'EOF'
Image build — nothing further happens now. forensicator-firstboot.service
is enabled and will run automatically on each clone's real first boot,
generating that instance's own secrets and OS admin credentials
(written to /etc/forensicator/initial-credentials.txt) before
forensicator/forensicator-workers start.
EOF
else
  chmod +x "${APP_DIR}/deploy/setup.sh"
  "${APP_DIR}/deploy/setup.sh"
fi
