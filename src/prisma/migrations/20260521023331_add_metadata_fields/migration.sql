-- CreateTable
CREATE TABLE "users" (
    "id" UUID NOT NULL,
    "email" TEXT NOT NULL,
    "name" TEXT,
    "role" TEXT NOT NULL DEFAULT 'analyst',
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "users_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "investigations" (
    "id" UUID NOT NULL,
    "title" TEXT NOT NULL,
    "description" TEXT,
    "hostname" TEXT,
    "status" TEXT NOT NULL DEFAULT 'uploaded',
    "metadata" JSONB NOT NULL DEFAULT '{}',
    "ai_status" TEXT NOT NULL DEFAULT 'not_queued',
    "ai_summary" TEXT,
    "ai_confidence" DOUBLE PRECISION,
    "finding_count" INTEGER NOT NULL DEFAULT 0,
    "uploaded_by_id" UUID NOT NULL,
    "investigation_source_id" TEXT,
    "username" TEXT,
    "os_info" JSONB,
    "tags" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "detection_stats" JSONB,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "investigations_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "findings" (
    "id" UUID NOT NULL,
    "investigation_id" UUID NOT NULL,
    "finding_id" TEXT NOT NULL,
    "finding_type" TEXT NOT NULL,
    "category" TEXT NOT NULL,
    "severity" TEXT NOT NULL,
    "host_name" TEXT,
    "risk_score" INTEGER,
    "evidence_count" INTEGER NOT NULL DEFAULT 0,
    "data" JSONB NOT NULL,
    "search_text" TEXT NOT NULL DEFAULT '',
    "ai_status" TEXT NOT NULL DEFAULT 'pending',
    "ai_summary" TEXT,
    "ai_confidence" DOUBLE PRECISION,
    "ai_model" TEXT,
    "ai_enriched_at" TIMESTAMP(3),
    "source_path" TEXT,
    "source_category" TEXT,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "findings_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "users_email_key" ON "users"("email");

-- CreateIndex
CREATE INDEX "investigations_uploaded_by_id_idx" ON "investigations"("uploaded_by_id");

-- CreateIndex
CREATE INDEX "investigations_hostname_idx" ON "investigations"("hostname");

-- CreateIndex
CREATE INDEX "investigations_created_at_idx" ON "investigations"("created_at");

-- CreateIndex
CREATE INDEX "findings_investigation_id_idx" ON "findings"("investigation_id");

-- CreateIndex
CREATE INDEX "findings_investigation_id_severity_idx" ON "findings"("investigation_id", "severity");

-- CreateIndex
CREATE INDEX "findings_investigation_id_category_idx" ON "findings"("investigation_id", "category");

-- CreateIndex
CREATE INDEX "findings_investigation_id_finding_type_idx" ON "findings"("investigation_id", "finding_type");

-- CreateIndex
CREATE INDEX "findings_investigation_id_source_category_idx" ON "findings"("investigation_id", "source_category");

-- CreateIndex
CREATE INDEX "findings_host_name_idx" ON "findings"("host_name");

-- CreateIndex
CREATE UNIQUE INDEX "findings_investigation_id_finding_id_key" ON "findings"("investigation_id", "finding_id");

-- AddForeignKey
ALTER TABLE "investigations" ADD CONSTRAINT "investigations_uploaded_by_id_fkey" FOREIGN KEY ("uploaded_by_id") REFERENCES "users"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "findings" ADD CONSTRAINT "findings_investigation_id_fkey" FOREIGN KEY ("investigation_id") REFERENCES "investigations"("id") ON DELETE CASCADE ON UPDATE CASCADE;
