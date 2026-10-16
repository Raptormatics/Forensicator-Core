-- CreateTable
CREATE TABLE "wer_report_entries" (
    "id" UUID NOT NULL,
    "file_id" UUID NOT NULL,
    "source_file_name" TEXT NOT NULL,
    "event_type" TEXT,
    "event_time" TIMESTAMP(3),
    "report_guid" TEXT,
    "app_name" TEXT,
    "app_version" TEXT,
    "app_timestamp" TEXT,
    "fault_module_name" TEXT,
    "fault_module_version" TEXT,
    "fault_module_timestamp" TEXT,
    "exception_code" TEXT,
    "exception_offset" TEXT,
    "sig_fields" JSONB NOT NULL,
    "raw_fields" JSONB NOT NULL,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "wer_report_entries_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "wer_dump_entries" (
    "id" UUID NOT NULL,
    "file_id" UUID NOT NULL,
    "source_file_name" TEXT NOT NULL,
    "exception_code" TEXT,
    "exception_address" TEXT,
    "faulting_thread_id" INTEGER,
    "process_id" INTEGER,
    "process_create_time" TIMESTAMP(3),
    "os_version" TEXT,
    "cpu_architecture" TEXT,
    "module_list" JSONB NOT NULL,
    "misc_info" JSONB NOT NULL,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "wer_dump_entries_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "recycle_bin_entries" (
    "id" UUID NOT NULL,
    "file_id" UUID NOT NULL,
    "sid" TEXT NOT NULL,
    "source_file_name" TEXT NOT NULL,
    "format_version" INTEGER NOT NULL,
    "original_path" TEXT NOT NULL,
    "deleted_time" TIMESTAMP(3),
    "file_size_bytes" BIGINT,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "recycle_bin_entries_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "notification_entries" (
    "id" UUID NOT NULL,
    "file_id" UUID NOT NULL,
    "profile_name" TEXT,
    "arrival_time" TIMESTAMP(3),
    "expiry_time" TIMESTAMP(3),
    "notif_type" TEXT,
    "tag" TEXT,
    "group_name" TEXT,
    "handler_id" TEXT,
    "handler_label" TEXT,
    "payload" TEXT,
    "details" JSONB NOT NULL,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "notification_entries_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "search_index_entries" (
    "id" UUID NOT NULL,
    "file_id" UUID NOT NULL,
    "table_name" TEXT NOT NULL,
    "record_index" INTEGER NOT NULL,
    "details" JSONB NOT NULL,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "search_index_entries_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "defender_quarantine_entries" (
    "id" UUID NOT NULL,
    "file_id" UUID NOT NULL,
    "source_file_name" TEXT NOT NULL,
    "entry_id_hex" TEXT,
    "scan_id_hex" TEXT,
    "threat_id" TEXT,
    "detection_name" TEXT,
    "timestamp" TIMESTAMP(3),
    "resources" JSONB NOT NULL,
    "raw_fields" JSONB NOT NULL,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "defender_quarantine_entries_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "defender_quarantine_payloads" (
    "id" UUID NOT NULL,
    "file_id" UUID NOT NULL,
    "source_file_name" TEXT NOT NULL,
    "magic_valid" BOOLEAN NOT NULL,
    "sha256" TEXT,
    "decrypted_size_bytes" BIGINT,
    "decrypted_storage_path" TEXT,
    "file_type_sniff" TEXT,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "defender_quarantine_payloads_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "bits_job_entries" (
    "id" UUID NOT NULL,
    "file_id" UUID NOT NULL,
    "job_id" TEXT,
    "name" TEXT,
    "desc" TEXT,
    "cmd" TEXT,
    "sid" TEXT,
    "job_type" TEXT,
    "priority" TEXT,
    "state" TEXT,
    "ctime" TIMESTAMP(3),
    "mtime" TIMESTAMP(3),
    "dest_fn" TEXT,
    "src_fn" TEXT,
    "tmp_fn" TEXT,
    "download_size_bytes" BIGINT,
    "transfer_size_bytes" BIGINT,
    "is_carved" BOOLEAN NOT NULL DEFAULT false,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "bits_job_entries_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "wer_report_entries_file_id_idx" ON "wer_report_entries"("file_id");

-- CreateIndex
CREATE INDEX "wer_dump_entries_file_id_idx" ON "wer_dump_entries"("file_id");

-- CreateIndex
CREATE INDEX "recycle_bin_entries_file_id_idx" ON "recycle_bin_entries"("file_id");

-- CreateIndex
CREATE INDEX "recycle_bin_entries_sid_idx" ON "recycle_bin_entries"("sid");

-- CreateIndex
CREATE INDEX "notification_entries_file_id_idx" ON "notification_entries"("file_id");

-- CreateIndex
CREATE INDEX "search_index_entries_file_id_idx" ON "search_index_entries"("file_id");

-- CreateIndex
CREATE INDEX "search_index_entries_table_name_idx" ON "search_index_entries"("table_name");

-- CreateIndex
CREATE INDEX "defender_quarantine_entries_file_id_idx" ON "defender_quarantine_entries"("file_id");

-- CreateIndex
CREATE INDEX "defender_quarantine_payloads_file_id_idx" ON "defender_quarantine_payloads"("file_id");

-- CreateIndex
CREATE INDEX "defender_quarantine_payloads_sha256_idx" ON "defender_quarantine_payloads"("sha256");

-- CreateIndex
CREATE INDEX "bits_job_entries_file_id_idx" ON "bits_job_entries"("file_id");

-- CreateIndex
CREATE INDEX "bits_job_entries_job_id_idx" ON "bits_job_entries"("job_id");

-- AddForeignKey
ALTER TABLE "wer_report_entries" ADD CONSTRAINT "wer_report_entries_file_id_fkey" FOREIGN KEY ("file_id") REFERENCES "windows_artifact_files"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "wer_dump_entries" ADD CONSTRAINT "wer_dump_entries_file_id_fkey" FOREIGN KEY ("file_id") REFERENCES "windows_artifact_files"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "recycle_bin_entries" ADD CONSTRAINT "recycle_bin_entries_file_id_fkey" FOREIGN KEY ("file_id") REFERENCES "windows_artifact_files"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "notification_entries" ADD CONSTRAINT "notification_entries_file_id_fkey" FOREIGN KEY ("file_id") REFERENCES "windows_artifact_files"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "search_index_entries" ADD CONSTRAINT "search_index_entries_file_id_fkey" FOREIGN KEY ("file_id") REFERENCES "windows_artifact_files"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "defender_quarantine_entries" ADD CONSTRAINT "defender_quarantine_entries_file_id_fkey" FOREIGN KEY ("file_id") REFERENCES "windows_artifact_files"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "defender_quarantine_payloads" ADD CONSTRAINT "defender_quarantine_payloads_file_id_fkey" FOREIGN KEY ("file_id") REFERENCES "windows_artifact_files"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "bits_job_entries" ADD CONSTRAINT "bits_job_entries_file_id_fkey" FOREIGN KEY ("file_id") REFERENCES "windows_artifact_files"("id") ON DELETE CASCADE ON UPDATE CASCADE;

