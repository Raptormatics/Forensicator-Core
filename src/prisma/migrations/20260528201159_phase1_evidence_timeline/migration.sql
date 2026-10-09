-- CreateTable
CREATE TABLE "evidence" (
    "id" UUID NOT NULL,
    "investigation_id" UUID NOT NULL,
    "finding_id" UUID NOT NULL,
    "type" TEXT NOT NULL,
    "source" TEXT,
    "timestamp" TIMESTAMP(3),
    "hostname" TEXT,
    "username" TEXT,
    "raw" JSONB NOT NULL,
    "searchable_text" TEXT,
    "hash" TEXT,
    "ip" TEXT,
    "domain" TEXT,
    "url" TEXT,
    "process_name" TEXT,
    "command_line" TEXT,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "evidence_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "timeline_events" (
    "id" UUID NOT NULL,
    "investigation_id" UUID NOT NULL,
    "finding_id" UUID,
    "timestamp" TIMESTAMP(3) NOT NULL,
    "title" TEXT NOT NULL,
    "description" TEXT,
    "category" TEXT NOT NULL,
    "severity" TEXT NOT NULL DEFAULT 'informational',
    "source_type" TEXT NOT NULL,
    "evidence_id" UUID,
    "metadata" JSONB,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "timeline_events_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "evidence_investigation_id_idx" ON "evidence"("investigation_id");

-- CreateIndex
CREATE INDEX "evidence_finding_id_idx" ON "evidence"("finding_id");

-- CreateIndex
CREATE INDEX "evidence_timestamp_idx" ON "evidence"("timestamp");

-- CreateIndex
CREATE INDEX "evidence_type_idx" ON "evidence"("type");

-- CreateIndex
CREATE INDEX "evidence_hostname_idx" ON "evidence"("hostname");

-- CreateIndex
CREATE INDEX "evidence_username_idx" ON "evidence"("username");

-- CreateIndex
CREATE INDEX "evidence_hash_idx" ON "evidence"("hash");

-- CreateIndex
CREATE INDEX "evidence_ip_idx" ON "evidence"("ip");

-- CreateIndex
CREATE INDEX "evidence_domain_idx" ON "evidence"("domain");

-- CreateIndex
CREATE INDEX "evidence_url_idx" ON "evidence"("url");

-- CreateIndex
CREATE INDEX "evidence_process_name_idx" ON "evidence"("process_name");

-- CreateIndex
CREATE INDEX "timeline_events_investigation_id_timestamp_idx" ON "timeline_events"("investigation_id", "timestamp");

-- CreateIndex
CREATE INDEX "timeline_events_investigation_id_category_idx" ON "timeline_events"("investigation_id", "category");

-- CreateIndex
CREATE INDEX "timeline_events_investigation_id_severity_idx" ON "timeline_events"("investigation_id", "severity");

-- AddForeignKey
ALTER TABLE "evidence" ADD CONSTRAINT "evidence_investigation_id_fkey" FOREIGN KEY ("investigation_id") REFERENCES "investigations"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "evidence" ADD CONSTRAINT "evidence_finding_id_fkey" FOREIGN KEY ("finding_id") REFERENCES "findings"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "timeline_events" ADD CONSTRAINT "timeline_events_investigation_id_fkey" FOREIGN KEY ("investigation_id") REFERENCES "investigations"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "timeline_events" ADD CONSTRAINT "timeline_events_finding_id_fkey" FOREIGN KEY ("finding_id") REFERENCES "findings"("id") ON DELETE SET NULL ON UPDATE CASCADE;
