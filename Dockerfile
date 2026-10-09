# Forensicator Core — container image.
#
# Only needed for the Docker/docker-compose path (see README.md and
# docker-compose.yml) — a from-scratch Linux box should use
# deploy/provision.sh + deploy/first-boot.sh directly instead, which also
# sets up systemd units, the update mechanism's sudoers rule, etc. Docker
# is specifically for "I don't want to provision a whole machine" —
# Windows and macOS users via Docker Desktop, or anyone who'd rather run
# this alongside other containerized services.
#
# Multi-stage: deps are installed once and reused by the build stage.
# The runtime image does still carry devDependencies and the TypeScript
# source tree (unlike a typical Next.js image) — worker.ts and
# seed-org.ts run via `tsx` at container start rather than being compiled
# into .next, so they need the real source present at runtime, not just
# build time.

FROM node:20-slim AS deps
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci

FROM node:20-slim AS builder
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY . .
# NEXT_PUBLIC_* vars are inlined into the client bundle at build time, not
# read at runtime — same reasoning as deploy/provision.sh's own build step.
ENV NEXT_PUBLIC_DEPLOYMENT_MODE=appliance
# `prisma generate` parses the schema's datasource block, which requires
# DATABASE_URL to just be *present* — it never connects at generate time.
# The real one is supplied at container run time by docker-compose.yml;
# this placeholder only has to satisfy that parse step.
ENV DATABASE_URL="postgresql://user:pass@localhost:5432/db"
RUN npx prisma generate
RUN npm run build

FROM node:20-slim AS runner
WORKDIR /app
ENV NODE_ENV=production
RUN groupadd --system forensicator && useradd --system --gid forensicator --create-home forensicator

COPY --from=builder /app/public ./public
COPY --from=builder /app/.next ./.next
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/package.json ./package.json
COPY --from=builder /app/next.config.mjs ./next.config.mjs
COPY --from=builder /app/tsconfig.json ./tsconfig.json
# worker.ts and seed-org.ts run via `tsx` at container start, not compiled
# into .next — unlike the web app itself, they need the real source tree
# (and tsconfig.json above, for tsx to resolve @/* path aliases) present
# at runtime, not just build time.
COPY --from=builder /app/src ./src
COPY --from=builder /app/scripts ./scripts
COPY docker-entrypoint.sh ./docker-entrypoint.sh
RUN chmod +x ./docker-entrypoint.sh && mkdir -p reports-output && chown -R forensicator:forensicator /app

USER forensicator
EXPOSE 3000
ENTRYPOINT ["./docker-entrypoint.sh"]
# Overridden by docker-compose.yml's "workers" service to run the worker
# process instead — same split as the two systemd units
# (forensicator.service / forensicator-workers.service), for the same
# reason: one can restart without affecting the other.
CMD ["web"]
