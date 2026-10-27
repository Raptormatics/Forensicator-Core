-- CreateTable
CREATE TABLE "sigma_rules" (
    "id" UUID NOT NULL,
    "sigma_id" TEXT NOT NULL,
    "title" TEXT NOT NULL,
    "description" TEXT,
    "status" TEXT,
    "level" TEXT NOT NULL,
    "author" TEXT,
    "tags" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "references" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "false_positives" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "product" TEXT,
    "category" TEXT,
    "service" TEXT,
    "path" TEXT,
    "yaml" TEXT NOT NULL,
    "compiled" JSONB,
    "supported" BOOLEAN NOT NULL DEFAULT true,
    "covered" BOOLEAN NOT NULL DEFAULT true,
    "unsupported_reason" TEXT,
    "enabled" BOOLEAN NOT NULL DEFAULT true,
    "source" TEXT NOT NULL DEFAULT 'sigmahq',
    "hit_count" INTEGER NOT NULL DEFAULT 0,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "sigma_rules_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "sigma_library_state" (
    "id" TEXT NOT NULL DEFAULT 'sigmahq',
    "package" TEXT NOT NULL DEFAULT 'core+',
    "release_tag" TEXT,
    "synced_at" TIMESTAMP(3),
    "rule_count" INTEGER NOT NULL DEFAULT 0,
    "supported_count" INTEGER NOT NULL DEFAULT 0,
    "covered_count" INTEGER NOT NULL DEFAULT 0,
    "last_error" TEXT,
    "updated_at" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "sigma_library_state_pkey" PRIMARY KEY ("id")
);

-- AlterTable
ALTER TABLE "log_findings" ADD COLUMN "sigma_rule_id" UUID,
ADD COLUMN "details" JSONB;

-- CreateIndex
CREATE UNIQUE INDEX "sigma_rules_sigma_id_key" ON "sigma_rules"("sigma_id");

-- CreateIndex
CREATE INDEX "sigma_rules_level_idx" ON "sigma_rules"("level");

-- CreateIndex
CREATE INDEX "sigma_rules_enabled_idx" ON "sigma_rules"("enabled");

-- CreateIndex
CREATE INDEX "sigma_rules_product_category_service_idx" ON "sigma_rules"("product", "category", "service");

-- CreateIndex
CREATE INDEX "log_findings_sigma_rule_id_idx" ON "log_findings"("sigma_rule_id");

-- AddForeignKey
ALTER TABLE "log_findings" ADD CONSTRAINT "log_findings_sigma_rule_id_fkey" FOREIGN KEY ("sigma_rule_id") REFERENCES "sigma_rules"("id") ON DELETE SET NULL ON UPDATE CASCADE;
