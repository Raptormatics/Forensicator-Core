-- AlterTable
ALTER TABLE "windows_artifact_uploads" ADD COLUMN     "collection_manifest" JSONB;

-- AlterTable
ALTER TABLE "windows_artifact_files" ADD COLUMN     "integrity_status" TEXT,
ADD COLUMN     "manifest_sha256" TEXT,
ADD COLUMN     "provenance" TEXT;

-- CreateTable
CREATE TABLE "registry_plugin_entries" (
    "id" UUID NOT NULL,
    "file_id" UUID NOT NULL,
    "plugin" TEXT NOT NULL,
    "key_path" TEXT,
    "timestamp" TIMESTAMP(3),
    "summary" TEXT NOT NULL,
    "details" JSONB NOT NULL,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "registry_plugin_entries_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "registry_plugin_entries_file_id_idx" ON "registry_plugin_entries"("file_id");

-- CreateIndex
CREATE INDEX "registry_plugin_entries_plugin_idx" ON "registry_plugin_entries"("plugin");

-- AddForeignKey
ALTER TABLE "registry_plugin_entries" ADD CONSTRAINT "registry_plugin_entries_file_id_fkey" FOREIGN KEY ("file_id") REFERENCES "windows_artifact_files"("id") ON DELETE CASCADE ON UPDATE CASCADE;

