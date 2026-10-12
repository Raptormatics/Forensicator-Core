-- AlterTable
ALTER TABLE "system_settings" ADD COLUMN     "pcap_dir" TEXT,
ADD COLUMN     "ram_chunk_size_bytes" INTEGER,
ADD COLUMN     "ram_dir" TEXT,
ADD COLUMN     "tshark_path" TEXT,
ADD COLUMN     "volatility_path" TEXT,
ADD COLUMN     "volatility_symbols_dir" TEXT;

-- CreateTable
CREATE TABLE "pcap_uploads" (
    "id" UUID NOT NULL,
    "filename" TEXT NOT NULL,
    "file_size" INTEGER NOT NULL,
    "sha256" TEXT NOT NULL,
    "status" TEXT NOT NULL DEFAULT 'queued',
    "storage_path" TEXT,
    "job_id" TEXT,
    "error_message" TEXT,
    "capture_start" TIMESTAMP(3),
    "capture_end" TIMESTAMP(3),
    "link_type" TEXT,
    "packet_count" INTEGER NOT NULL DEFAULT 0,
    "byte_count" BIGINT NOT NULL DEFAULT 0,
    "conversation_count" INTEGER NOT NULL DEFAULT 0,
    "dns_query_count" INTEGER NOT NULL DEFAULT 0,
    "finding_count" INTEGER NOT NULL DEFAULT 0,
    "ioc_count" INTEGER NOT NULL DEFAULT 0,
    "hostname" TEXT,
    "asset_name" TEXT,
    "ip_address" TEXT,
    "notes" TEXT,
    "uploaded_by_id" UUID NOT NULL,
    "organization_id" UUID,
    "case_id" UUID,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "pcap_uploads_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "pcap_conversations" (
    "id" UUID NOT NULL,
    "upload_id" UUID NOT NULL,
    "protocol" TEXT NOT NULL,
    "addr_a" TEXT NOT NULL,
    "port_a" INTEGER,
    "addr_b" TEXT NOT NULL,
    "port_b" INTEGER,
    "packets_a_to_b" INTEGER NOT NULL DEFAULT 0,
    "packets_b_to_a" INTEGER NOT NULL DEFAULT 0,
    "bytes_a_to_b" BIGINT NOT NULL DEFAULT 0,
    "bytes_b_to_a" BIGINT NOT NULL DEFAULT 0,
    "first_seen" TIMESTAMP(3),
    "last_seen" TIMESTAMP(3),
    "tls_sni" TEXT,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "pcap_conversations_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "pcap_dns_queries" (
    "id" UUID NOT NULL,
    "upload_id" UUID NOT NULL,
    "query_name" TEXT NOT NULL,
    "query_type" TEXT,
    "response_ips" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "count" INTEGER NOT NULL DEFAULT 1,
    "first_seen" TIMESTAMP(3),
    "last_seen" TIMESTAMP(3),
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "pcap_dns_queries_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "pcap_findings" (
    "id" UUID NOT NULL,
    "upload_id" UUID NOT NULL,
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

    CONSTRAINT "pcap_findings_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "pcap_iocs" (
    "id" UUID NOT NULL,
    "upload_id" UUID NOT NULL,
    "type" TEXT NOT NULL,
    "value" TEXT NOT NULL,
    "count" INTEGER NOT NULL DEFAULT 1,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "pcap_iocs_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "pcap_analysis_rules" (
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

    CONSTRAINT "pcap_analysis_rules_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ram_uploads" (
    "id" UUID NOT NULL,
    "filename" TEXT NOT NULL,
    "file_size" BIGINT NOT NULL,
    "sha256" TEXT NOT NULL,
    "status" TEXT NOT NULL DEFAULT 'queued',
    "storage_path" TEXT,
    "job_id" TEXT,
    "error_message" TEXT,
    "os_type" TEXT NOT NULL DEFAULT 'windows',
    "os_build" TEXT,
    "os_arch" TEXT,
    "plugin_status" JSONB,
    "process_count" INTEGER NOT NULL DEFAULT 0,
    "connection_count" INTEGER NOT NULL DEFAULT 0,
    "finding_count" INTEGER NOT NULL DEFAULT 0,
    "ioc_count" INTEGER NOT NULL DEFAULT 0,
    "hostname" TEXT,
    "asset_name" TEXT,
    "ip_address" TEXT,
    "notes" TEXT,
    "uploaded_by_id" UUID NOT NULL,
    "organization_id" UUID,
    "case_id" UUID,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "ram_uploads_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ram_upload_sessions" (
    "id" UUID NOT NULL,
    "filename" TEXT NOT NULL,
    "total_bytes" BIGINT NOT NULL,
    "received_bytes" BIGINT NOT NULL DEFAULT 0,
    "os_type" TEXT NOT NULL,
    "hostname" TEXT,
    "asset_name" TEXT,
    "ip_address" TEXT,
    "notes" TEXT,
    "storage_path" TEXT NOT NULL,
    "status" TEXT NOT NULL DEFAULT 'uploading',
    "uploaded_by_id" UUID NOT NULL,
    "organization_id" UUID,
    "case_id" UUID,
    "expires_at" TIMESTAMP(3) NOT NULL,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "ram_upload_sessions_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ram_processes" (
    "id" UUID NOT NULL,
    "upload_id" UUID NOT NULL,
    "pid" INTEGER NOT NULL,
    "ppid" INTEGER,
    "name" TEXT NOT NULL,
    "path" TEXT,
    "command_line" TEXT,
    "create_time" TIMESTAMP(3),
    "exit_time" TIMESTAMP(3),
    "session_id" INTEGER,
    "threads" INTEGER,
    "handles" INTEGER,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "ram_processes_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ram_network_connections" (
    "id" UUID NOT NULL,
    "upload_id" UUID NOT NULL,
    "protocol" TEXT,
    "local_addr" TEXT,
    "local_port" INTEGER,
    "foreign_addr" TEXT,
    "foreign_port" INTEGER,
    "state" TEXT,
    "pid" INTEGER,
    "process_name" TEXT,
    "created" TIMESTAMP(3),
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "ram_network_connections_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ram_findings" (
    "id" UUID NOT NULL,
    "upload_id" UUID NOT NULL,
    "rule_id" UUID,
    "yara_rule_id" UUID,
    "title" TEXT NOT NULL,
    "description" TEXT,
    "severity" TEXT NOT NULL,
    "match_count" INTEGER NOT NULL DEFAULT 1,
    "first_seen" TIMESTAMP(3),
    "last_seen" TIMESTAMP(3),
    "matched_field" TEXT,
    "matched_value" TEXT,
    "pid" INTEGER,
    "process_name" TEXT,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "ram_findings_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ram_finding_matches" (
    "id" UUID NOT NULL,
    "finding_id" UUID NOT NULL,
    "pid" INTEGER,
    "process_name" TEXT,
    "matched_field" TEXT,
    "matched_value" TEXT,

    CONSTRAINT "ram_finding_matches_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ram_iocs" (
    "id" UUID NOT NULL,
    "upload_id" UUID NOT NULL,
    "type" TEXT NOT NULL,
    "value" TEXT NOT NULL,
    "count" INTEGER NOT NULL DEFAULT 1,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "ram_iocs_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ram_malfind_regions" (
    "id" UUID NOT NULL,
    "finding_id" UUID NOT NULL,
    "tag" TEXT,
    "protection" TEXT,
    "start_address" TEXT,
    "end_address" TEXT,
    "commit_charge" INTEGER,
    "private_memory" INTEGER,
    "path" TEXT,
    "preview_hex" TEXT,

    CONSTRAINT "ram_malfind_regions_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ram_symbol_tables" (
    "id" UUID NOT NULL,
    "os_type" TEXT NOT NULL,
    "filename" TEXT NOT NULL,
    "description" TEXT,
    "storage_path" TEXT NOT NULL,
    "file_size" INTEGER NOT NULL,
    "uploaded_by_id" UUID NOT NULL,
    "organization_id" UUID,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "ram_symbol_tables_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ram_analysis_rules" (
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

    CONSTRAINT "ram_analysis_rules_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ram_yara_rules" (
    "id" UUID NOT NULL,
    "name" TEXT NOT NULL,
    "description" TEXT,
    "severity" TEXT NOT NULL DEFAULT 'medium',
    "enabled" BOOLEAN NOT NULL DEFAULT true,
    "is_builtin" BOOLEAN NOT NULL DEFAULT false,
    "yara_source" TEXT NOT NULL,
    "tags" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "created_by_id" UUID,
    "organization_id" UUID,
    "hit_count" INTEGER NOT NULL DEFAULT 0,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "ram_yara_rules_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "pcap_uploads_uploaded_by_id_idx" ON "pcap_uploads"("uploaded_by_id");

-- CreateIndex
CREATE INDEX "pcap_uploads_organization_id_idx" ON "pcap_uploads"("organization_id");

-- CreateIndex
CREATE INDEX "pcap_uploads_status_idx" ON "pcap_uploads"("status");

-- CreateIndex
CREATE INDEX "pcap_uploads_case_id_idx" ON "pcap_uploads"("case_id");

-- CreateIndex
CREATE INDEX "pcap_uploads_created_at_idx" ON "pcap_uploads"("created_at");

-- CreateIndex
CREATE INDEX "pcap_conversations_upload_id_idx" ON "pcap_conversations"("upload_id");

-- CreateIndex
CREATE INDEX "pcap_conversations_addr_a_idx" ON "pcap_conversations"("addr_a");

-- CreateIndex
CREATE INDEX "pcap_conversations_addr_b_idx" ON "pcap_conversations"("addr_b");

-- CreateIndex
CREATE UNIQUE INDEX "pcap_conversations_upload_id_protocol_addr_a_port_a_addr_b__key" ON "pcap_conversations"("upload_id", "protocol", "addr_a", "port_a", "addr_b", "port_b");

-- CreateIndex
CREATE INDEX "pcap_dns_queries_upload_id_idx" ON "pcap_dns_queries"("upload_id");

-- CreateIndex
CREATE INDEX "pcap_dns_queries_query_name_idx" ON "pcap_dns_queries"("query_name");

-- CreateIndex
CREATE UNIQUE INDEX "pcap_dns_queries_upload_id_query_name_key" ON "pcap_dns_queries"("upload_id", "query_name");

-- CreateIndex
CREATE INDEX "pcap_findings_upload_id_idx" ON "pcap_findings"("upload_id");

-- CreateIndex
CREATE INDEX "pcap_findings_rule_id_idx" ON "pcap_findings"("rule_id");

-- CreateIndex
CREATE INDEX "pcap_findings_severity_idx" ON "pcap_findings"("severity");

-- CreateIndex
CREATE INDEX "pcap_iocs_upload_id_idx" ON "pcap_iocs"("upload_id");

-- CreateIndex
CREATE INDEX "pcap_iocs_type_idx" ON "pcap_iocs"("type");

-- CreateIndex
CREATE INDEX "pcap_iocs_value_idx" ON "pcap_iocs"("value");

-- CreateIndex
CREATE UNIQUE INDEX "pcap_iocs_upload_id_type_value_key" ON "pcap_iocs"("upload_id", "type", "value");

-- CreateIndex
CREATE INDEX "pcap_analysis_rules_organization_id_idx" ON "pcap_analysis_rules"("organization_id");

-- CreateIndex
CREATE INDEX "pcap_analysis_rules_enabled_idx" ON "pcap_analysis_rules"("enabled");

-- CreateIndex
CREATE INDEX "pcap_analysis_rules_severity_idx" ON "pcap_analysis_rules"("severity");

-- CreateIndex
CREATE INDEX "pcap_analysis_rules_is_builtin_idx" ON "pcap_analysis_rules"("is_builtin");

-- CreateIndex
CREATE INDEX "ram_uploads_uploaded_by_id_idx" ON "ram_uploads"("uploaded_by_id");

-- CreateIndex
CREATE INDEX "ram_uploads_organization_id_idx" ON "ram_uploads"("organization_id");

-- CreateIndex
CREATE INDEX "ram_uploads_status_idx" ON "ram_uploads"("status");

-- CreateIndex
CREATE INDEX "ram_uploads_case_id_idx" ON "ram_uploads"("case_id");

-- CreateIndex
CREATE INDEX "ram_uploads_created_at_idx" ON "ram_uploads"("created_at");

-- CreateIndex
CREATE INDEX "ram_upload_sessions_uploaded_by_id_idx" ON "ram_upload_sessions"("uploaded_by_id");

-- CreateIndex
CREATE INDEX "ram_upload_sessions_organization_id_idx" ON "ram_upload_sessions"("organization_id");

-- CreateIndex
CREATE INDEX "ram_upload_sessions_case_id_idx" ON "ram_upload_sessions"("case_id");

-- CreateIndex
CREATE INDEX "ram_upload_sessions_status_idx" ON "ram_upload_sessions"("status");

-- CreateIndex
CREATE INDEX "ram_upload_sessions_expires_at_idx" ON "ram_upload_sessions"("expires_at");

-- CreateIndex
CREATE INDEX "ram_processes_upload_id_idx" ON "ram_processes"("upload_id");

-- CreateIndex
CREATE INDEX "ram_processes_pid_idx" ON "ram_processes"("pid");

-- CreateIndex
CREATE INDEX "ram_network_connections_upload_id_idx" ON "ram_network_connections"("upload_id");

-- CreateIndex
CREATE INDEX "ram_network_connections_foreign_addr_idx" ON "ram_network_connections"("foreign_addr");

-- CreateIndex
CREATE INDEX "ram_findings_upload_id_idx" ON "ram_findings"("upload_id");

-- CreateIndex
CREATE INDEX "ram_findings_rule_id_idx" ON "ram_findings"("rule_id");

-- CreateIndex
CREATE INDEX "ram_findings_yara_rule_id_idx" ON "ram_findings"("yara_rule_id");

-- CreateIndex
CREATE INDEX "ram_findings_severity_idx" ON "ram_findings"("severity");

-- CreateIndex
CREATE INDEX "ram_findings_pid_idx" ON "ram_findings"("pid");

-- CreateIndex
CREATE INDEX "ram_finding_matches_finding_id_idx" ON "ram_finding_matches"("finding_id");

-- CreateIndex
CREATE INDEX "ram_iocs_upload_id_idx" ON "ram_iocs"("upload_id");

-- CreateIndex
CREATE INDEX "ram_iocs_type_idx" ON "ram_iocs"("type");

-- CreateIndex
CREATE INDEX "ram_iocs_value_idx" ON "ram_iocs"("value");

-- CreateIndex
CREATE UNIQUE INDEX "ram_iocs_upload_id_type_value_key" ON "ram_iocs"("upload_id", "type", "value");

-- CreateIndex
CREATE INDEX "ram_malfind_regions_finding_id_idx" ON "ram_malfind_regions"("finding_id");

-- CreateIndex
CREATE INDEX "ram_symbol_tables_os_type_idx" ON "ram_symbol_tables"("os_type");

-- CreateIndex
CREATE INDEX "ram_symbol_tables_organization_id_idx" ON "ram_symbol_tables"("organization_id");

-- CreateIndex
CREATE INDEX "ram_analysis_rules_organization_id_idx" ON "ram_analysis_rules"("organization_id");

-- CreateIndex
CREATE INDEX "ram_analysis_rules_enabled_idx" ON "ram_analysis_rules"("enabled");

-- CreateIndex
CREATE INDEX "ram_analysis_rules_severity_idx" ON "ram_analysis_rules"("severity");

-- CreateIndex
CREATE INDEX "ram_analysis_rules_is_builtin_idx" ON "ram_analysis_rules"("is_builtin");

-- CreateIndex
CREATE INDEX "ram_yara_rules_organization_id_idx" ON "ram_yara_rules"("organization_id");

-- CreateIndex
CREATE INDEX "ram_yara_rules_enabled_idx" ON "ram_yara_rules"("enabled");

-- CreateIndex
CREATE INDEX "ram_yara_rules_is_builtin_idx" ON "ram_yara_rules"("is_builtin");

-- AddForeignKey
ALTER TABLE "pcap_uploads" ADD CONSTRAINT "pcap_uploads_uploaded_by_id_fkey" FOREIGN KEY ("uploaded_by_id") REFERENCES "users"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "pcap_uploads" ADD CONSTRAINT "pcap_uploads_organization_id_fkey" FOREIGN KEY ("organization_id") REFERENCES "organizations"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "pcap_uploads" ADD CONSTRAINT "pcap_uploads_case_id_fkey" FOREIGN KEY ("case_id") REFERENCES "cases"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "pcap_conversations" ADD CONSTRAINT "pcap_conversations_upload_id_fkey" FOREIGN KEY ("upload_id") REFERENCES "pcap_uploads"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "pcap_dns_queries" ADD CONSTRAINT "pcap_dns_queries_upload_id_fkey" FOREIGN KEY ("upload_id") REFERENCES "pcap_uploads"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "pcap_findings" ADD CONSTRAINT "pcap_findings_upload_id_fkey" FOREIGN KEY ("upload_id") REFERENCES "pcap_uploads"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "pcap_findings" ADD CONSTRAINT "pcap_findings_rule_id_fkey" FOREIGN KEY ("rule_id") REFERENCES "pcap_analysis_rules"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "pcap_iocs" ADD CONSTRAINT "pcap_iocs_upload_id_fkey" FOREIGN KEY ("upload_id") REFERENCES "pcap_uploads"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "pcap_analysis_rules" ADD CONSTRAINT "pcap_analysis_rules_created_by_id_fkey" FOREIGN KEY ("created_by_id") REFERENCES "users"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "pcap_analysis_rules" ADD CONSTRAINT "pcap_analysis_rules_organization_id_fkey" FOREIGN KEY ("organization_id") REFERENCES "organizations"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ram_uploads" ADD CONSTRAINT "ram_uploads_uploaded_by_id_fkey" FOREIGN KEY ("uploaded_by_id") REFERENCES "users"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ram_uploads" ADD CONSTRAINT "ram_uploads_organization_id_fkey" FOREIGN KEY ("organization_id") REFERENCES "organizations"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ram_uploads" ADD CONSTRAINT "ram_uploads_case_id_fkey" FOREIGN KEY ("case_id") REFERENCES "cases"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ram_upload_sessions" ADD CONSTRAINT "ram_upload_sessions_uploaded_by_id_fkey" FOREIGN KEY ("uploaded_by_id") REFERENCES "users"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ram_upload_sessions" ADD CONSTRAINT "ram_upload_sessions_organization_id_fkey" FOREIGN KEY ("organization_id") REFERENCES "organizations"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ram_upload_sessions" ADD CONSTRAINT "ram_upload_sessions_case_id_fkey" FOREIGN KEY ("case_id") REFERENCES "cases"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ram_processes" ADD CONSTRAINT "ram_processes_upload_id_fkey" FOREIGN KEY ("upload_id") REFERENCES "ram_uploads"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ram_network_connections" ADD CONSTRAINT "ram_network_connections_upload_id_fkey" FOREIGN KEY ("upload_id") REFERENCES "ram_uploads"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ram_findings" ADD CONSTRAINT "ram_findings_upload_id_fkey" FOREIGN KEY ("upload_id") REFERENCES "ram_uploads"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ram_findings" ADD CONSTRAINT "ram_findings_rule_id_fkey" FOREIGN KEY ("rule_id") REFERENCES "ram_analysis_rules"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ram_findings" ADD CONSTRAINT "ram_findings_yara_rule_id_fkey" FOREIGN KEY ("yara_rule_id") REFERENCES "ram_yara_rules"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ram_finding_matches" ADD CONSTRAINT "ram_finding_matches_finding_id_fkey" FOREIGN KEY ("finding_id") REFERENCES "ram_findings"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ram_iocs" ADD CONSTRAINT "ram_iocs_upload_id_fkey" FOREIGN KEY ("upload_id") REFERENCES "ram_uploads"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ram_malfind_regions" ADD CONSTRAINT "ram_malfind_regions_finding_id_fkey" FOREIGN KEY ("finding_id") REFERENCES "ram_findings"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ram_symbol_tables" ADD CONSTRAINT "ram_symbol_tables_uploaded_by_id_fkey" FOREIGN KEY ("uploaded_by_id") REFERENCES "users"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ram_symbol_tables" ADD CONSTRAINT "ram_symbol_tables_organization_id_fkey" FOREIGN KEY ("organization_id") REFERENCES "organizations"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ram_analysis_rules" ADD CONSTRAINT "ram_analysis_rules_created_by_id_fkey" FOREIGN KEY ("created_by_id") REFERENCES "users"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ram_analysis_rules" ADD CONSTRAINT "ram_analysis_rules_organization_id_fkey" FOREIGN KEY ("organization_id") REFERENCES "organizations"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ram_yara_rules" ADD CONSTRAINT "ram_yara_rules_created_by_id_fkey" FOREIGN KEY ("created_by_id") REFERENCES "users"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ram_yara_rules" ADD CONSTRAINT "ram_yara_rules_organization_id_fkey" FOREIGN KEY ("organization_id") REFERENCES "organizations"("id") ON DELETE SET NULL ON UPDATE CASCADE;

