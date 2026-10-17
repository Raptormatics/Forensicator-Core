-- AlterTable
ALTER TABLE "system_settings" ADD COLUMN     "win_artifacts_chunk_size_bytes" INTEGER;

-- AlterTable
-- Int (~2.1GB max) overflowed once chunked uploads made it possible for
-- $MFT (etc.) to actually reach this far instead of failing earlier.
ALTER TABLE "windows_artifact_files" ALTER COLUMN "file_size" TYPE BIGINT;

-- CreateTable
CREATE TABLE "windows_artifact_staged_files" (
    "id" UUID NOT NULL,
    "filename" TEXT NOT NULL,
    "total_bytes" BIGINT NOT NULL,
    "received_bytes" BIGINT NOT NULL DEFAULT 0,
    "storage_path" TEXT NOT NULL,
    "status" TEXT NOT NULL DEFAULT 'uploading',
    "uploaded_by_id" UUID NOT NULL,
    "expires_at" TIMESTAMP(3) NOT NULL,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "windows_artifact_staged_files_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "windows_artifact_staged_files_uploaded_by_id_idx" ON "windows_artifact_staged_files"("uploaded_by_id");

-- CreateIndex
CREATE INDEX "windows_artifact_staged_files_status_idx" ON "windows_artifact_staged_files"("status");

-- CreateIndex
CREATE INDEX "windows_artifact_staged_files_expires_at_idx" ON "windows_artifact_staged_files"("expires_at");

-- AddForeignKey
ALTER TABLE "windows_artifact_staged_files" ADD CONSTRAINT "windows_artifact_staged_files_uploaded_by_id_fkey" FOREIGN KEY ("uploaded_by_id") REFERENCES "users"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
