-- AlterTable
ALTER TABLE "investigations" ALTER COLUMN "archive_sha256" SET DATA TYPE TEXT;

-- CreateTable
CREATE TABLE "ioc_records" (
    "id" UUID NOT NULL,
    "value" TEXT NOT NULL,
    "type" TEXT NOT NULL,
    "first_seen" TIMESTAMP(3),
    "last_seen" TIMESTAMP(3),
    "reputation" INTEGER,
    "confidence" INTEGER,
    "malware_family" TEXT,
    "threat_type" TEXT,
    "enriched_at" TIMESTAMP(3),
    "enrich_job_id" TEXT,
    "provider_results" JSONB,
    "blocklisted" BOOLEAN NOT NULL DEFAULT false,
    "blocklisted_at" TIMESTAMP(3),
    "blocklisted_by_id" UUID,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "ioc_records_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ioc_enrichments" (
    "id" UUID NOT NULL,
    "ioc_id" UUID NOT NULL,
    "provider" TEXT NOT NULL,
    "status" TEXT NOT NULL DEFAULT 'pending',
    "response" JSONB,
    "enriched_at" TIMESTAMP(3),
    "error_msg" TEXT,

    CONSTRAINT "ioc_enrichments_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "correlations" (
    "id" UUID NOT NULL,
    "case_id" UUID,
    "correlation_type" TEXT NOT NULL,
    "value" TEXT NOT NULL,
    "confidence" INTEGER NOT NULL DEFAULT 50,
    "hosts" TEXT[],
    "investigation_ids" TEXT[],
    "evidence_ids" TEXT[],
    "metadata" JSONB,
    "job_id" TEXT,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "correlations_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "correlation_whitelist" (
    "id" UUID NOT NULL,
    "correlation_type" TEXT NOT NULL,
    "value" TEXT NOT NULL,
    "note" TEXT,
    "created_by_id" UUID NOT NULL,
    "organization_id" UUID,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "correlation_whitelist_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "org_threat_intel_providers" (
    "id" UUID NOT NULL,
    "organization_id" UUID NOT NULL,
    "provider" TEXT NOT NULL,
    "encrypted_api_key" TEXT,
    "key_last4" TEXT,
    "enabled" BOOLEAN NOT NULL DEFAULT true,
    "last_used_at" TIMESTAMP(3),
    "last_error" TEXT,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "org_threat_intel_providers_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "urlhaus_feed_entries" (
    "id" UUID NOT NULL,
    "urlhaus_id" TEXT NOT NULL,
    "url" TEXT NOT NULL,
    "url_status" TEXT,
    "threat" TEXT,
    "tags" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "reporter" TEXT,
    "date_added" TIMESTAMP(3),
    "urlhaus_link" TEXT,
    "synced_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "urlhaus_feed_entries_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "log_uploads" (
    "id" UUID NOT NULL,
    "filename" TEXT NOT NULL,
    "source_type" TEXT NOT NULL,
    "status" TEXT NOT NULL DEFAULT 'pending',
    "event_count" INTEGER NOT NULL DEFAULT 0,
    "finding_count" INTEGER NOT NULL DEFAULT 0,
    "hostname" TEXT,
    "asset_name" TEXT,
    "ip_address" TEXT,
    "notes" TEXT,
    "error_message" TEXT,
    "uploaded_by_id" UUID NOT NULL,
    "organization_id" UUID,
    "case_id" UUID,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "log_uploads_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "log_events" (
    "id" UUID NOT NULL,
    "upload_id" UUID NOT NULL,
    "line_number" INTEGER NOT NULL,
    "timestamp" TIMESTAMP(3),
    "source_app" TEXT NOT NULL,
    "event_type" TEXT,
    "src_ip" TEXT,
    "dst_ip" TEXT,
    "src_port" INTEGER,
    "dst_port" INTEGER,
    "username" TEXT,
    "domain" TEXT,
    "process" TEXT,
    "command_line" TEXT,
    "file_path" TEXT,
    "file_name" TEXT,
    "hash_md5" TEXT,
    "hash_sha1" TEXT,
    "hash_sha256" TEXT,
    "url" TEXT,
    "http_method" TEXT,
    "status_code" INTEGER,
    "user_agent" TEXT,
    "message" TEXT,
    "raw" TEXT NOT NULL,
    "normalized" JSONB NOT NULL,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "log_events_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "log_findings" (
    "id" UUID NOT NULL,
    "upload_id" UUID NOT NULL,
    "rule_id" UUID,
    "title" TEXT NOT NULL,
    "description" TEXT,
    "severity" TEXT NOT NULL,
    "event_count" INTEGER NOT NULL DEFAULT 1,
    "first_seen" TIMESTAMP(3),
    "last_seen" TIMESTAMP(3),
    "matched_field" TEXT,
    "matched_value" TEXT,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "log_findings_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "log_iocs" (
    "id" UUID NOT NULL,
    "upload_id" UUID NOT NULL,
    "type" TEXT NOT NULL,
    "value" TEXT NOT NULL,
    "count" INTEGER NOT NULL DEFAULT 1,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "log_iocs_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "log_analysis_rules" (
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

    CONSTRAINT "log_analysis_rules_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "log_decoders" (
    "id" UUID NOT NULL,
    "name" TEXT NOT NULL,
    "title" TEXT,
    "description" TEXT,
    "yaml_content" TEXT NOT NULL,
    "enabled" BOOLEAN NOT NULL DEFAULT true,
    "is_builtin" BOOLEAN NOT NULL DEFAULT false,
    "version" INTEGER NOT NULL DEFAULT 1,
    "created_by_id" UUID,
    "organization_id" UUID,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "log_decoders_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "ioc_records_value_key" ON "ioc_records"("value");

-- CreateIndex
CREATE INDEX "ioc_records_type_idx" ON "ioc_records"("type");

-- CreateIndex
CREATE INDEX "ioc_records_reputation_idx" ON "ioc_records"("reputation");

-- CreateIndex
CREATE INDEX "ioc_records_enriched_at_idx" ON "ioc_records"("enriched_at");

-- CreateIndex
CREATE INDEX "ioc_records_blocklisted_idx" ON "ioc_records"("blocklisted");

-- CreateIndex
CREATE INDEX "ioc_enrichments_ioc_id_idx" ON "ioc_enrichments"("ioc_id");

-- CreateIndex
CREATE INDEX "ioc_enrichments_provider_status_idx" ON "ioc_enrichments"("provider", "status");

-- CreateIndex
CREATE UNIQUE INDEX "ioc_enrichments_ioc_id_provider_key" ON "ioc_enrichments"("ioc_id", "provider");

-- CreateIndex
CREATE INDEX "correlations_case_id_idx" ON "correlations"("case_id");

-- CreateIndex
CREATE INDEX "correlations_correlation_type_idx" ON "correlations"("correlation_type");

-- CreateIndex
CREATE INDEX "correlations_confidence_idx" ON "correlations"("confidence");

-- CreateIndex
CREATE INDEX "correlations_created_at_idx" ON "correlations"("created_at");

-- CreateIndex
CREATE INDEX "correlation_whitelist_correlation_type_value_idx" ON "correlation_whitelist"("correlation_type", "value");

-- CreateIndex
CREATE UNIQUE INDEX "correlation_whitelist_correlation_type_value_organization_i_key" ON "correlation_whitelist"("correlation_type", "value", "organization_id");

-- CreateIndex
CREATE INDEX "org_threat_intel_providers_organization_id_idx" ON "org_threat_intel_providers"("organization_id");

-- CreateIndex
CREATE UNIQUE INDEX "org_threat_intel_providers_organization_id_provider_key" ON "org_threat_intel_providers"("organization_id", "provider");

-- CreateIndex
CREATE UNIQUE INDEX "urlhaus_feed_entries_urlhaus_id_key" ON "urlhaus_feed_entries"("urlhaus_id");

-- CreateIndex
CREATE INDEX "urlhaus_feed_entries_url_idx" ON "urlhaus_feed_entries" USING HASH ("url");

-- CreateIndex
CREATE INDEX "log_uploads_uploaded_by_id_idx" ON "log_uploads"("uploaded_by_id");

-- CreateIndex
CREATE INDEX "log_uploads_organization_id_idx" ON "log_uploads"("organization_id");

-- CreateIndex
CREATE INDEX "log_uploads_status_idx" ON "log_uploads"("status");

-- CreateIndex
CREATE INDEX "log_uploads_case_id_idx" ON "log_uploads"("case_id");

-- CreateIndex
CREATE INDEX "log_uploads_created_at_idx" ON "log_uploads"("created_at");

-- CreateIndex
CREATE INDEX "log_events_upload_id_idx" ON "log_events"("upload_id");

-- CreateIndex
CREATE INDEX "log_events_upload_id_timestamp_idx" ON "log_events"("upload_id", "timestamp");

-- CreateIndex
CREATE INDEX "log_events_src_ip_idx" ON "log_events"("src_ip");

-- CreateIndex
CREATE INDEX "log_events_username_idx" ON "log_events"("username");

-- CreateIndex
CREATE INDEX "log_events_process_idx" ON "log_events"("process");

-- CreateIndex
CREATE INDEX "log_findings_upload_id_idx" ON "log_findings"("upload_id");

-- CreateIndex
CREATE INDEX "log_findings_rule_id_idx" ON "log_findings"("rule_id");

-- CreateIndex
CREATE INDEX "log_findings_severity_idx" ON "log_findings"("severity");

-- CreateIndex
CREATE INDEX "log_iocs_upload_id_idx" ON "log_iocs"("upload_id");

-- CreateIndex
CREATE INDEX "log_iocs_type_idx" ON "log_iocs"("type");

-- CreateIndex
CREATE INDEX "log_iocs_value_idx" ON "log_iocs"("value");

-- CreateIndex
CREATE UNIQUE INDEX "log_iocs_upload_id_type_value_key" ON "log_iocs"("upload_id", "type", "value");

-- CreateIndex
CREATE INDEX "log_analysis_rules_organization_id_idx" ON "log_analysis_rules"("organization_id");

-- CreateIndex
CREATE INDEX "log_analysis_rules_enabled_idx" ON "log_analysis_rules"("enabled");

-- CreateIndex
CREATE INDEX "log_analysis_rules_severity_idx" ON "log_analysis_rules"("severity");

-- CreateIndex
CREATE INDEX "log_analysis_rules_is_builtin_idx" ON "log_analysis_rules"("is_builtin");

-- CreateIndex
CREATE UNIQUE INDEX "log_decoders_name_key" ON "log_decoders"("name");

-- CreateIndex
CREATE INDEX "log_decoders_enabled_idx" ON "log_decoders"("enabled");

-- CreateIndex
CREATE INDEX "log_decoders_is_builtin_idx" ON "log_decoders"("is_builtin");

-- CreateIndex
CREATE INDEX "log_decoders_organization_id_idx" ON "log_decoders"("organization_id");

-- AddForeignKey
ALTER TABLE "ioc_records" ADD CONSTRAINT "ioc_records_blocklisted_by_id_fkey" FOREIGN KEY ("blocklisted_by_id") REFERENCES "users"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ioc_enrichments" ADD CONSTRAINT "ioc_enrichments_ioc_id_fkey" FOREIGN KEY ("ioc_id") REFERENCES "ioc_records"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "correlations" ADD CONSTRAINT "correlations_case_id_fkey" FOREIGN KEY ("case_id") REFERENCES "cases"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "correlation_whitelist" ADD CONSTRAINT "correlation_whitelist_created_by_id_fkey" FOREIGN KEY ("created_by_id") REFERENCES "users"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "correlation_whitelist" ADD CONSTRAINT "correlation_whitelist_organization_id_fkey" FOREIGN KEY ("organization_id") REFERENCES "organizations"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "org_threat_intel_providers" ADD CONSTRAINT "org_threat_intel_providers_organization_id_fkey" FOREIGN KEY ("organization_id") REFERENCES "organizations"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "log_uploads" ADD CONSTRAINT "log_uploads_uploaded_by_id_fkey" FOREIGN KEY ("uploaded_by_id") REFERENCES "users"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "log_uploads" ADD CONSTRAINT "log_uploads_organization_id_fkey" FOREIGN KEY ("organization_id") REFERENCES "organizations"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "log_uploads" ADD CONSTRAINT "log_uploads_case_id_fkey" FOREIGN KEY ("case_id") REFERENCES "cases"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "log_events" ADD CONSTRAINT "log_events_upload_id_fkey" FOREIGN KEY ("upload_id") REFERENCES "log_uploads"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "log_findings" ADD CONSTRAINT "log_findings_upload_id_fkey" FOREIGN KEY ("upload_id") REFERENCES "log_uploads"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "log_findings" ADD CONSTRAINT "log_findings_rule_id_fkey" FOREIGN KEY ("rule_id") REFERENCES "log_analysis_rules"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "log_iocs" ADD CONSTRAINT "log_iocs_upload_id_fkey" FOREIGN KEY ("upload_id") REFERENCES "log_uploads"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "log_analysis_rules" ADD CONSTRAINT "log_analysis_rules_created_by_id_fkey" FOREIGN KEY ("created_by_id") REFERENCES "users"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "log_analysis_rules" ADD CONSTRAINT "log_analysis_rules_organization_id_fkey" FOREIGN KEY ("organization_id") REFERENCES "organizations"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "log_decoders" ADD CONSTRAINT "log_decoders_created_by_id_fkey" FOREIGN KEY ("created_by_id") REFERENCES "users"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "log_decoders" ADD CONSTRAINT "log_decoders_organization_id_fkey" FOREIGN KEY ("organization_id") REFERENCES "organizations"("id") ON DELETE SET NULL ON UPDATE CASCADE;
