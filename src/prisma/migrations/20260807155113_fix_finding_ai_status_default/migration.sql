-- Fix Finding.aiStatus default: "pending" was indistinguishable from
-- "genuinely queued right now", causing every never-analyzed finding to
-- show a permanent false "Queued for analysis..." in the UI. Align with
-- Investigation.aiStatus's existing "not_queued" convention.
ALTER TABLE "findings" ALTER COLUMN "ai_status" SET DEFAULT 'not_queued';

-- Backfill: every current "pending" row is a never-analyzed finding, not a
-- stuck job — confirmed via the Redis queue (0 jobs in "forensicator-ai"
-- wait/active/failed) and DB counts (0 "processing" rows exist). Safe to
-- reset in bulk.
UPDATE "findings" SET "ai_status" = 'not_queued' WHERE "ai_status" = 'pending';
