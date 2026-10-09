#!/bin/sh
#
# Docker-only equivalent of deploy/first-boot.sh's app-level steps
# (migrate, seed the one organization) plus actually starting the
# process — there's no separate systemd unit to hand off to here, and no
# OS-admin-account/credentials-file step at all: Docker Desktop's own
# host boundary is what's being trusted instead, not an SSH login on this
# container, so that whole piece of first-boot.sh doesn't apply.
#
# Runs on every container start, not once — prisma migrate deploy and
# the org seed (an upsert keyed on slug) are both safe to repeat.

set -eu

echo "==> Running database migrations (retrying until Postgres is reachable)"
until npx prisma migrate deploy; do
  echo "    Postgres not ready yet, retrying in 2s..."
  sleep 2
done

case "${1:-web}" in
  web)
    echo "==> Seeding organization (${ORG_NAME:-Default Organization})"
    npx tsx scripts/seed-org.ts
    echo "==> Starting web"
    exec node_modules/.bin/next start -p "${PORT:-3000}"
    ;;
  workers)
    echo "==> Starting workers"
    exec npx tsx src/lib/jobs/worker.ts
    ;;
  *)
    echo "Unknown command: $1 (expected 'web' or 'workers')" >&2
    exit 1
    ;;
esac
