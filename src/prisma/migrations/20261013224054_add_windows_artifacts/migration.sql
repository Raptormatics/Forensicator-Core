-- AlterTable
ALTER TABLE "system_settings" ADD COLUMN     "win_artifacts_dir" TEXT,
ADD COLUMN     "win_artifacts_python_path" TEXT;

-- CreateTable
CREATE TABLE "windows_artifact_uploads" (
    "id" UUID NOT NULL,
    "hostname" TEXT,
    "notes" TEXT,
    "finding_count" INTEGER NOT NULL DEFAULT 0,
    "uploaded_by_id" UUID NOT NULL,
    "organization_id" UUID,
    "case_id" UUID,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "windows_artifact_uploads_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "windows_artifact_files" (
    "id" UUID NOT NULL,
    "upload_id" UUID NOT NULL,
    "role" TEXT NOT NULL,
    "filename" TEXT NOT NULL,
    "file_size" INTEGER NOT NULL,
    "sha256" TEXT NOT NULL,
    "status" TEXT NOT NULL DEFAULT 'queued',
    "storage_path" TEXT,
    "job_id" TEXT,
    "error_message" TEXT,
    "finding_count" INTEGER NOT NULL DEFAULT 0,
    "profile_name" TEXT,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "parsed_at" TIMESTAMP(3),

    CONSTRAINT "windows_artifact_files_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "shimcache_entries" (
    "id" UUID NOT NULL,
    "file_id" UUID NOT NULL,
    "path" TEXT NOT NULL,
    "last_modified" TIMESTAMP(3),
    "execution_flag" BOOLEAN,
    "order" INTEGER NOT NULL,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "shimcache_entries_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "amcache_entries" (
    "id" UUID NOT NULL,
    "file_id" UUID NOT NULL,
    "path" TEXT NOT NULL,
    "sha1" TEXT,
    "file_size_bytes" BIGINT,
    "publisher" TEXT,
    "first_seen" TIMESTAMP(3),
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "amcache_entries_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "userassist_entries" (
    "id" UUID NOT NULL,
    "file_id" UUID NOT NULL,
    "program_path" TEXT NOT NULL,
    "run_count" INTEGER,
    "last_executed" TIMESTAMP(3),
    "focus_count" INTEGER,
    "focus_time_ms" INTEGER,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "userassist_entries_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "bam_entries" (
    "id" UUID NOT NULL,
    "file_id" UUID NOT NULL,
    "sid" TEXT NOT NULL,
    "path" TEXT NOT NULL,
    "last_executed" TIMESTAMP(3),
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "bam_entries_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "autorun_entries" (
    "id" UUID NOT NULL,
    "file_id" UUID NOT NULL,
    "hive_source" TEXT NOT NULL,
    "key_path" TEXT NOT NULL,
    "value_name" TEXT,
    "value_data" TEXT NOT NULL,
    "category" TEXT NOT NULL,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "autorun_entries_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "windows_artifact_findings" (
    "id" UUID NOT NULL,
    "file_id" UUID NOT NULL,
    "rule_id" UUID,
    "title" TEXT NOT NULL,
    "description" TEXT,
    "severity" TEXT NOT NULL,
    "match_count" INTEGER NOT NULL DEFAULT 1,
    "first_seen" TIMESTAMP(3),
    "last_seen" TIMESTAMP(3),
    "matched_field" TEXT,
    "matched_value" TEXT,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "windows_artifact_findings_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "windows_artifact_rules" (
    "id" UUID NOT NULL,
    "name" TEXT NOT NULL,
    "description" TEXT,
    "severity" TEXT NOT NULL DEFAULT 'medium',
    "enabled" BOOLEAN NOT NULL DEFAULT true,
    "is_builtin" BOOLEAN NOT NULL DEFAULT false,
    "logic" TEXT NOT NULL DEFAULT 'AND',
    "conditions" JSONB NOT NULL,
    "tags" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "created_by_id" UUID,
    "organization_id" UUID,
    "hit_count" INTEGER NOT NULL DEFAULT 0,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "windows_artifact_rules_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "windows_artifact_uploads_uploaded_by_id_idx" ON "windows_artifact_uploads"("uploaded_by_id");

-- CreateIndex
CREATE INDEX "windows_artifact_uploads_organization_id_idx" ON "windows_artifact_uploads"("organization_id");

-- CreateIndex
CREATE INDEX "windows_artifact_uploads_case_id_idx" ON "windows_artifact_uploads"("case_id");

-- CreateIndex
CREATE INDEX "windows_artifact_uploads_created_at_idx" ON "windows_artifact_uploads"("created_at");

-- CreateIndex
CREATE INDEX "windows_artifact_files_upload_id_idx" ON "windows_artifact_files"("upload_id");

-- CreateIndex
CREATE INDEX "windows_artifact_files_role_idx" ON "windows_artifact_files"("role");

-- CreateIndex
CREATE INDEX "windows_artifact_files_status_idx" ON "windows_artifact_files"("status");

-- CreateIndex
CREATE INDEX "shimcache_entries_file_id_idx" ON "shimcache_entries"("file_id");

-- CreateIndex
CREATE INDEX "shimcache_entries_path_idx" ON "shimcache_entries"("path");

-- CreateIndex
CREATE INDEX "amcache_entries_file_id_idx" ON "amcache_entries"("file_id");

-- CreateIndex
CREATE INDEX "amcache_entries_sha1_idx" ON "amcache_entries"("sha1");

-- CreateIndex
CREATE INDEX "amcache_entries_path_idx" ON "amcache_entries"("path");

-- CreateIndex
CREATE INDEX "userassist_entries_file_id_idx" ON "userassist_entries"("file_id");

-- CreateIndex
CREATE INDEX "userassist_entries_program_path_idx" ON "userassist_entries"("program_path");

-- CreateIndex
CREATE INDEX "bam_entries_file_id_idx" ON "bam_entries"("file_id");

-- CreateIndex
CREATE INDEX "bam_entries_path_idx" ON "bam_entries"("path");

-- CreateIndex
CREATE INDEX "autorun_entries_file_id_idx" ON "autorun_entries"("file_id");

-- CreateIndex
CREATE INDEX "autorun_entries_category_idx" ON "autorun_entries"("category");

-- CreateIndex
CREATE INDEX "windows_artifact_findings_file_id_idx" ON "windows_artifact_findings"("file_id");

-- CreateIndex
CREATE INDEX "windows_artifact_findings_rule_id_idx" ON "windows_artifact_findings"("rule_id");

-- CreateIndex
CREATE INDEX "windows_artifact_findings_severity_idx" ON "windows_artifact_findings"("severity");

-- CreateIndex
CREATE INDEX "windows_artifact_rules_organization_id_idx" ON "windows_artifact_rules"("organization_id");

-- CreateIndex
CREATE INDEX "windows_artifact_rules_enabled_idx" ON "windows_artifact_rules"("enabled");

-- CreateIndex
CREATE INDEX "windows_artifact_rules_severity_idx" ON "windows_artifact_rules"("severity");

-- CreateIndex
CREATE INDEX "windows_artifact_rules_is_builtin_idx" ON "windows_artifact_rules"("is_builtin");

-- AddForeignKey
ALTER TABLE "windows_artifact_uploads" ADD CONSTRAINT "windows_artifact_uploads_uploaded_by_id_fkey" FOREIGN KEY ("uploaded_by_id") REFERENCES "users"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "windows_artifact_uploads" ADD CONSTRAINT "windows_artifact_uploads_organization_id_fkey" FOREIGN KEY ("organization_id") REFERENCES "organizations"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "windows_artifact_uploads" ADD CONSTRAINT "windows_artifact_uploads_case_id_fkey" FOREIGN KEY ("case_id") REFERENCES "cases"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "windows_artifact_files" ADD CONSTRAINT "windows_artifact_files_upload_id_fkey" FOREIGN KEY ("upload_id") REFERENCES "windows_artifact_uploads"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "shimcache_entries" ADD CONSTRAINT "shimcache_entries_file_id_fkey" FOREIGN KEY ("file_id") REFERENCES "windows_artifact_files"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "amcache_entries" ADD CONSTRAINT "amcache_entries_file_id_fkey" FOREIGN KEY ("file_id") REFERENCES "windows_artifact_files"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "userassist_entries" ADD CONSTRAINT "userassist_entries_file_id_fkey" FOREIGN KEY ("file_id") REFERENCES "windows_artifact_files"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "bam_entries" ADD CONSTRAINT "bam_entries_file_id_fkey" FOREIGN KEY ("file_id") REFERENCES "windows_artifact_files"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "autorun_entries" ADD CONSTRAINT "autorun_entries_file_id_fkey" FOREIGN KEY ("file_id") REFERENCES "windows_artifact_files"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "windows_artifact_findings" ADD CONSTRAINT "windows_artifact_findings_file_id_fkey" FOREIGN KEY ("file_id") REFERENCES "windows_artifact_files"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "windows_artifact_findings" ADD CONSTRAINT "windows_artifact_findings_rule_id_fkey" FOREIGN KEY ("rule_id") REFERENCES "windows_artifact_rules"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "windows_artifact_rules" ADD CONSTRAINT "windows_artifact_rules_created_by_id_fkey" FOREIGN KEY ("created_by_id") REFERENCES "users"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "windows_artifact_rules" ADD CONSTRAINT "windows_artifact_rules_organization_id_fkey" FOREIGN KEY ("organization_id") REFERENCES "organizations"("id") ON DELETE SET NULL ON UPDATE CASCADE;

