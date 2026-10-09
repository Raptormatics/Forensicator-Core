-- findings.tags predates this repo's migration history the same way
-- investigations.collection_request_id did (see 20260816090000's fix) —
-- it exists on databases that grew organically during development, but no
-- tracked migration ever created it, so a from-scratch `migrate deploy`
-- (e.g. a fresh install on a new server) never gets the column, and
-- prisma.finding.createMany() then fails on every investigation upload
-- with "The column `tags` does not exist in the current database."

ALTER TABLE "findings" ADD COLUMN IF NOT EXISTS "tags" TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[];
