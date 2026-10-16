-- AlterTable
ALTER TABLE "windows_artifact_files" ADD COLUMN     "log1_storage_path" TEXT,
ADD COLUMN     "log2_storage_path" TEXT;

-- CreateTable
CREATE TABLE "timeline_activity_entries" (
    "id" UUID NOT NULL,
    "file_id" UUID NOT NULL,
    "profile_name" TEXT,
    "start_time" TIMESTAMP(3),
    "activity_kind" TEXT NOT NULL,
    "app_display_name" TEXT,
    "description" TEXT,
    "package_identifier" TEXT,
    "active_duration_seconds" INTEGER,
    "reporting_app" TEXT,
    "details" JSONB NOT NULL,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "timeline_activity_entries_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "timeline_activity_entries_file_id_idx" ON "timeline_activity_entries"("file_id");

-- AddForeignKey
ALTER TABLE "timeline_activity_entries" ADD CONSTRAINT "timeline_activity_entries_file_id_fkey" FOREIGN KEY ("file_id") REFERENCES "windows_artifact_files"("id") ON DELETE CASCADE ON UPDATE CASCADE;

