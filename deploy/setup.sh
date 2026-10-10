#!/usr/bin/env bash
#
# Forensicator Core — bare-metal first-run setup.
#
# Generates per-instance secrets, creates the database, runs migrations,
# seeds the single organization, and starts services — run automatically
# by provision.sh once it finishes, for anyone running provision.sh
# directly on their own already-accessible machine (the documented
# "git clone + sudo ./deploy/provision.sh" quickstart).
#
# NOT used when building a shared golden image (IMAGE_BUILD=1, e.g. via
# the Enterprise overlay's Packer template) — there, secrets must never
# be generated until the actual first real boot of a CLONED instance,
# or every clone of the image would share the same DATABASE_URL
# password and NEXTAUTH_SECRET. That case uses deploy/first-boot.sh
# instead, triggered by forensicator-firstboot.service at real first
# boot — a different script because it also has to handle a genuinely
# different scenario: an unknown future user with only console access,
# no OS login of their own yet. If you're reading this because you're
# already logged into the machine you just ran provision.sh on, this
# script (not first-boot.sh) is the one that just ran for you.
#
# Safe to re-run — every step here is idempotent (upsert-based org seed,
# a role/database creation guarded by existence checks, repeatable
# migrations).

set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "Must be run as root (sudo ./deploy/setup.sh)" >&2
  exit 1
fi

APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG_DIR="/etc/forensicator"
ENV_FILE="${CONFIG_DIR}/forensicator.env"
SERVICE_USER="${SERVICE_USER:-forensicator}"

if [[ ! -f "$ENV_FILE" ]]; then
  echo "Missing ${ENV_FILE} — run deploy/provision.sh first." >&2
  exit 1
fi

if grep -q '^DATABASE_URL=' "$ENV_FILE" 2>/dev/null; then
  echo "==> Secrets already generated — skipping straight to migrate/start."
else
  echo "==> Generating per-instance secrets"
  DB_NAME="forensicator"
  DB_USER="forensicator"
  DB_PASSWORD="$(openssl rand -base64 24 | tr -d '=+/')"
  NEXTAUTH_SECRET="$(openssl rand -base64 32)"

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

  echo "==> Writing secrets to ${ENV_FILE}"
  # Quoted — this file gets `source`d below, and DATABASE_URL's "&" is a
  # shell metacharacter (backgrounding) if left unquoted.
  {
    echo "DATABASE_URL=\"postgresql://${DB_USER}:${DB_PASSWORD}@localhost:5432/${DB_NAME}?schema=public&sslmode=disable\""
    echo "NEXTAUTH_SECRET=\"${NEXTAUTH_SECRET}\""
  } >> "$ENV_FILE"
  chmod 600 "$ENV_FILE"
  chown "${SERVICE_USER}:${SERVICE_USER}" "$ENV_FILE"
fi

set -a
# shellcheck disable=SC1090
source "$ENV_FILE"
set +a

echo "==> Running database migrations"
runuser -u "$SERVICE_USER" -- bash -lc "cd '${APP_DIR}' && npm run prisma:deploy"

echo "==> Seeding organization (${ORG_NAME:-Default Organization})"
runuser -u "$SERVICE_USER" -- bash -lc "cd '${APP_DIR}' && npx tsx scripts/seed-org.ts"

echo "==> Starting services"
systemctl start forensicator.service forensicator-workers.service

cat <<EOF

==> Setup complete.

Visit ${NEXTAUTH_URL:-http://localhost:3000} to create your admin account —
there is no default login.
EOF
