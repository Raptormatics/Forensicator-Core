-- AlterTable
ALTER TABLE "system_settings" ADD COLUMN     "win_artifacts_system_python_path" TEXT;

-- AlterTable
ALTER TABLE "windows_artifact_files" ADD COLUMN     "journal_metadata_text" TEXT;

-- AlterTable
ALTER TABLE "windows_artifact_uploads" ADD COLUMN     "srum_extensions_map" JSONB;

-- CreateTable
CREATE TABLE "mft_entries" (
    "id" UUID NOT NULL,
    "file_id" UUID NOT NULL,
    "mft_entry_number" INTEGER NOT NULL,
    "sequence_number" INTEGER,
    "name" TEXT NOT NULL,
    "path" TEXT,
    "parent_entry_number" INTEGER,
    "is_allocated" BOOLEAN NOT NULL,
    "is_directory" BOOLEAN NOT NULL,
    "creation_time" TIMESTAMP(3),
    "modification_time" TIMESTAMP(3),
    "access_time" TIMESTAMP(3),
    "entry_modification_time" TIMESTAMP(3),
    "file_size" BIGINT,
    "has_alternate_data_streams" BOOLEAN NOT NULL DEFAULT false,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "mft_entries_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "usn_jrnl_entries" (
    "id" UUID NOT NULL,
    "file_id" UUID NOT NULL,
    "usn" BIGINT NOT NULL,
    "file_reference_number" TEXT,
    "parent_file_reference_number" TEXT,
    "timestamp" TIMESTAMP(3),
    "reason" TEXT[],
    "file_name" TEXT,
    "file_attributes" INTEGER,
    "source_info" INTEGER,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "usn_jrnl_entries_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "srum_entries" (
    "id" UUID NOT NULL,
    "file_id" UUID NOT NULL,
    "table_name" TEXT NOT NULL,
    "provider_label" TEXT,
    "timestamp" TIMESTAMP(3),
    "app_id" TEXT,
    "user_sid" TEXT,
    "details" JSONB NOT NULL,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "srum_entries_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "mft_entries_file_id_idx" ON "mft_entries"("file_id");

-- CreateIndex
CREATE INDEX "mft_entries_mft_entry_number_idx" ON "mft_entries"("mft_entry_number");

-- CreateIndex
CREATE INDEX "mft_entries_path_idx" ON "mft_entries"("path");

-- CreateIndex
CREATE INDEX "usn_jrnl_entries_file_id_idx" ON "usn_jrnl_entries"("file_id");

-- CreateIndex
CREATE INDEX "usn_jrnl_entries_usn_idx" ON "usn_jrnl_entries"("usn");

-- CreateIndex
CREATE INDEX "usn_jrnl_entries_file_name_idx" ON "usn_jrnl_entries"("file_name");

-- CreateIndex
CREATE INDEX "srum_entries_file_id_idx" ON "srum_entries"("file_id");

-- CreateIndex
CREATE INDEX "srum_entries_table_name_idx" ON "srum_entries"("table_name");

-- CreateIndex
CREATE INDEX "srum_entries_app_id_idx" ON "srum_entries"("app_id");

-- AddForeignKey
ALTER TABLE "mft_entries" ADD CONSTRAINT "mft_entries_file_id_fkey" FOREIGN KEY ("file_id") REFERENCES "windows_artifact_files"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "usn_jrnl_entries" ADD CONSTRAINT "usn_jrnl_entries_file_id_fkey" FOREIGN KEY ("file_id") REFERENCES "windows_artifact_files"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "srum_entries" ADD CONSTRAINT "srum_entries_file_id_fkey" FOREIGN KEY ("file_id") REFERENCES "windows_artifact_files"("id") ON DELETE CASCADE ON UPDATE CASCADE;

