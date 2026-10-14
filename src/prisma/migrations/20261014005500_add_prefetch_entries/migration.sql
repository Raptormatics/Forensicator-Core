-- AlterTable
ALTER TABLE "system_settings" ADD COLUMN     "prefetch_python_path" TEXT;

-- CreateTable
CREATE TABLE "prefetch_entries" (
    "id" UUID NOT NULL,
    "file_id" UUID NOT NULL,
    "executable_name" TEXT NOT NULL,
    "run_count" INTEGER,
    "last_run_times" TIMESTAMP(3)[],
    "first_run_time" TIMESTAMP(3),
    "volume_serials" TEXT[],
    "referenced_files" TEXT[],
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "prefetch_entries_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "prefetch_entries_file_id_idx" ON "prefetch_entries"("file_id");

-- CreateIndex
CREATE INDEX "prefetch_entries_executable_name_idx" ON "prefetch_entries"("executable_name");

-- AddForeignKey
ALTER TABLE "prefetch_entries" ADD CONSTRAINT "prefetch_entries_file_id_fkey" FOREIGN KEY ("file_id") REFERENCES "windows_artifact_files"("id") ON DELETE CASCADE ON UPDATE CASCADE;

