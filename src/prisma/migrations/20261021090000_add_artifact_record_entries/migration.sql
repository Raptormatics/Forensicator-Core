-- CreateTable
CREATE TABLE "artifact_record_entries" (
    "id" UUID NOT NULL,
    "file_id" UUID NOT NULL,
    "kind" TEXT NOT NULL,
    "title" TEXT NOT NULL,
    "timestamp" TIMESTAMP(3),
    "path" TEXT,
    "user_name" TEXT,
    "process" TEXT,
    "url" TEXT,
    "ip" TEXT,
    "sha256" TEXT,
    "sha1" TEXT,
    "md5" TEXT,
    "details" JSONB NOT NULL,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "artifact_record_entries_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "artifact_record_entries_file_id_idx" ON "artifact_record_entries"("file_id");

-- CreateIndex
CREATE INDEX "artifact_record_entries_kind_idx" ON "artifact_record_entries"("kind");

-- CreateIndex
CREATE INDEX "artifact_record_entries_sha256_idx" ON "artifact_record_entries"("sha256");

-- AddForeignKey
ALTER TABLE "artifact_record_entries" ADD CONSTRAINT "artifact_record_entries_file_id_fkey" FOREIGN KEY ("file_id") REFERENCES "windows_artifact_files"("id") ON DELETE CASCADE ON UPDATE CASCADE;

