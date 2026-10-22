-- Archive: closed cases, and investigations/uploads that belong to no case.
ALTER TABLE "cases" ADD COLUMN "archived_at" TIMESTAMP(3), ADD COLUMN "archived_by_id" UUID;
ALTER TABLE "investigations" ADD COLUMN "archived_at" TIMESTAMP(3), ADD COLUMN "archived_by_id" UUID;
ALTER TABLE "log_uploads" ADD COLUMN "archived_at" TIMESTAMP(3), ADD COLUMN "archived_by_id" UUID;
ALTER TABLE "pcap_uploads" ADD COLUMN "archived_at" TIMESTAMP(3), ADD COLUMN "archived_by_id" UUID;
ALTER TABLE "ram_uploads" ADD COLUMN "archived_at" TIMESTAMP(3), ADD COLUMN "archived_by_id" UUID;
ALTER TABLE "windows_artifact_uploads" ADD COLUMN "archived_at" TIMESTAMP(3), ADD COLUMN "archived_by_id" UUID;

CREATE INDEX "cases_archived_at_idx" ON "cases"("archived_at");
CREATE INDEX "investigations_archived_at_idx" ON "investigations"("archived_at");
