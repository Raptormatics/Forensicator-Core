-- Case closure record: who closed a case, when, and with what disposition
-- and summary; and the latest reopen with its reason.
ALTER TABLE "cases" ADD COLUMN "closed_at" TIMESTAMP(3),
ADD COLUMN "closed_by_id" UUID,
ADD COLUMN "closure_disposition" TEXT,
ADD COLUMN "closure_summary" TEXT,
ADD COLUMN "reopened_at" TIMESTAMP(3),
ADD COLUMN "reopened_by_id" UUID,
ADD COLUMN "reopen_reason" TEXT;

-- Cases already closed before this record existed: best available close
-- time is their last update.
UPDATE "cases" SET "closed_at" = "updated_at" WHERE "status" = 'closed';
