#!/usr/bin/env bash
#
# Forensicator Core — first-boot instance setup.
#
# Runs once per machine instance (guarded by a marker file), NOT once per
# disk image. Forensicator Core always runs in appliance mode — single
# organization, seeded here — unlike the Enterprise overlay, which also
# supports a multi-tenant SaaS mode; there's no mode branching in this
# script at all because there's only one mode to support.
#
# Invoked by forensicator-firstboot.service, before the web/workers units.
# No network access required — everything here is local (DB, secrets, migrations).
#
# Also sets the password for the OS admin account (forensicator-admin,
# created but locked by provision.sh) and shows it before this instance is
# usable at all. There is otherwise no way in whatsoever: no SSH key ships
# by default, and no OS account has a usable password until this script
# sets one.
#
# No web app user is seeded here — none exists at all until someone
# completes the mandatory /setup wizard on first visit (see
# src/app/setup/page.tsx), which is what creates the actual admin
# account. That's the whole point: every install doesn't end up with the
# same admin@forensicator.local login.
#
# This unit owns tty1 outright (see forensicator-firstboot.service's
# FIRSTBOOT_STDIO — provision.sh disables getty@tty1.service so nothing
# else is contending for it) and blocks on a keypress before handing tty1
# back to a real login prompt, so the credentials are guaranteed to still
# be on screen when someone looks.

set -euo pipefail

CONFIG_DIR="/etc/forensicator"
ENV_FILE="${CONFIG_DIR}/forensicator.env"
MARKER="${CONFIG_DIR}/.provisioned"
CREDS_FILE="${CONFIG_DIR}/initial-credentials.txt"
APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [[ -f "$MARKER" ]]; then
  echo "==> Already provisioned on $(cat "$MARKER") — skipping."
  exit 0
fi

if [[ ! -f "$ENV_FILE" ]]; then
  echo "Missing ${ENV_FILE} — run deploy/provision.sh first." >&2
  exit 1
fi

# Alnum only, no ambiguous characters (0/O, 1/l/I) — a long base64 string
# is genuinely hard to type correctly on a console with no copy/paste,
# especially masked (invisible) password input. 14 chars from this ~57
# character alphabet is still solidly strong (~82 bits of entropy).
gen_pw() {
  # `head -c N /dev/urandom | tr -dc ...` (even with `|| true` tacked on)
  # still prints "tr: write error: Broken pipe" to stderr on real hardware
  # — `|| true` only swallows the exit code, not tr's own error text, which
  # still lands on the console since this unit's StandardError targets it.
  # Structured this way instead: `head -c 64 /dev/urandom` reads a fixed,
  # finite amount and exits on its own — tr then consumes that to a clean
  # natural EOF, with nothing downstream ever cutting it off mid-write, so
  # there's no SIGPIPE at all, not just one that's suppressed. The loop
  # guards the (extremely unlikely) case where filtering 64 random bytes
  # down to this ~57-character alphabet yields fewer than 14 usable chars.
  local pw=""
  while [[ ${#pw} -lt 14 ]]; do
    pw+="$(head -c 64 /dev/urandom | tr -dc 'A-HJ-NP-Za-km-z2-9')"
  done
  printf '%s' "${pw:0:14}"
}

echo "==> Generating per-instance secrets"
DB_NAME="forensicator"
DB_USER="forensicator"
DB_PASSWORD="$(openssl rand -base64 24 | tr -d '=+/')"
NEXTAUTH_SECRET="$(openssl rand -base64 32)"
OS_ADMIN_PASSWORD="$(gen_pw)"

echo "==> Creating PostgreSQL role and database"
sudo -u postgres psql -v ON_ERROR_STOP=1 <<SQL
DO \$\$
BEGIN
  IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = '${DB_USER}') THEN
    CREATE ROLE ${DB_USER} LOGIN PASSWORD '${DB_PASSWORD}';
  ELSE
    ALTER ROLE ${DB_USER} WITH PASSWORD '${DB_PASSWORD}';
  END IF;
END
\$\$;
SQL
if ! sudo -u postgres psql -tAc "SELECT 1 FROM pg_database WHERE datname='${DB_NAME}'" | grep -q 1; then
  sudo -u postgres createdb -O "$DB_USER" "$DB_NAME"
fi

echo "==> Appending secrets to ${ENV_FILE}"
# Quoted — this file gets `source`d, and DATABASE_URL's "&" is a shell
# metacharacter (backgrounding) if left unquoted, silently truncating the
# value at that point instead of erroring loudly.
{
  echo "DATABASE_URL=\"postgresql://${DB_USER}:${DB_PASSWORD}@localhost:5432/${DB_NAME}?schema=public&sslmode=disable\""
  echo "NEXTAUTH_SECRET=\"${NEXTAUTH_SECRET}\""
} >> "$ENV_FILE"
chmod 600 "$ENV_FILE"

# Load the now-complete env file for the one-off commands below.
set -a
# shellcheck disable=SC1090
source "$ENV_FILE"
set +a

LAN_URL_HINT="http://<ip-address>:${PORT:-3000}"

echo "==> Running database migrations"
cd "$APP_DIR"
npm run prisma:deploy

echo "==> Seeding organization"
npx tsx scripts/seed-org.ts

echo "==> Setting OS admin account password"
# This unit owns tty1 (see the FIRSTBOOT_STDIO note at the top of this
# file), so it's safe to prompt here — letting whoever's at the console
# set a password they already know beats transcribing a generated one
# under masked (invisible) input.
echo ""
echo "Generated OS admin password: ${OS_ADMIN_PASSWORD}"
echo "Press ENTER to keep it, or type your own password now (input hidden):"
read -r -s CUSTOM_OS_PASSWORD || true
echo ""
if [[ -n "$CUSTOM_OS_PASSWORD" ]]; then
  echo "Confirm password:"
  read -r -s CUSTOM_OS_PASSWORD_CONFIRM || true
  echo ""
  if [[ "$CUSTOM_OS_PASSWORD" == "$CUSTOM_OS_PASSWORD_CONFIRM" ]]; then
    OS_ADMIN_PASSWORD="$CUSTOM_OS_PASSWORD"
  else
    echo "Passwords didn't match — keeping the generated one above."
  fi
fi
echo "forensicator-admin:${OS_ADMIN_PASSWORD}" | chpasswd

cat > "$CREDS_FILE" <<EOF
Forensicator Core — initial credentials
Generated: $(date -u +%Y-%m-%dT%H:%M:%SZ)

  Web app:
    Configured URL:  ${NEXTAUTH_URL:-not configured}
    Or from another machine: ${LAN_URL_HINT} (replace <ip-address> with this machine's actual IP)
    No admin account exists yet — visiting either URL above will prompt
    you to create one. There is no default login.

  OS console / SSH login (sudo):
    User:     forensicator-admin
    Password: ${OS_ADMIN_PASSWORD}

Change the OS password immediately, then delete this file
(${CREDS_FILE}).
EOF
chmod 600 "$CREDS_FILE"

date -u +%Y-%m-%dT%H:%M:%SZ > "$MARKER"

BANNER="
================================================================
  FORENSICATOR CORE - FIRST BOOT COMPLETE
================================================================

  The OS admin password below is either what was just generated or
  whatever you just set — nothing here is a shared or default value.

  WEB APP SETUP
    URL      : ${NEXTAUTH_URL:-not configured} (or ${LAN_URL_HINT} from another machine,
               replacing <ip-address> with this machine's actual IP)
    No admin account exists yet — visiting either URL creates one.

  OS ADMIN LOGIN (sudo)
    Username : forensicator-admin
    Password : ${OS_ADMIN_PASSWORD}

  Also saved to: ${CREDS_FILE}
  (readable once logged in as forensicator-admin)

  CHANGE THE OS PASSWORD IMMEDIATELY.
================================================================
"

# Deliberately a fixed sleep here, NOT a second blocking read. The
# password prompt above (a single read) has been repeatedly confirmed,
# via direct QEMU console testing (screenshots + monitor-injected
# keypresses), to respond correctly to Enter. A second read placed here
# — tried both as `read -p` and as a plain `read` matching the first
# prompt's exact working structure — consistently did NOT respond to a
# real keypress on either a real hypervisor console or in scripted
# testing, for reasons that didn't resolve even when isolated from the
# rest of this script. Rather than ship a confirm step that can leave an
# install permanently stuck with no console and no login (getty already
# disabled, service never reaches the point of re-enabling it), a
# generous fixed pause achieves the actual goal — give someone at the
# console time to read the credentials before tty1 is handed back — with
# a mechanism that can't hang indefinitely.
echo "$BANNER"
echo "Continuing in 60 seconds..."
sleep 60
# --no-block is load-bearing: `systemctl start` normally waits for the
# started unit's job to finish, but agetty can't actually acquire
# /dev/tty1 until THIS process (still holding it open via TTYPath)
# exits — a synchronous start here deadlocks forever, since neither
# side can proceed. Queue it and move on; it starts the instant this
# script exits and releases the tty.
systemctl start --no-block getty@tty1.service
systemctl disable forensicator-firstboot.service
