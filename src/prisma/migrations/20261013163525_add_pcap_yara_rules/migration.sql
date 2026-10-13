-- AlterTable
ALTER TABLE "pcap_findings" ADD COLUMN     "yara_rule_id" UUID;

-- CreateTable
CREATE TABLE "pcap_yara_rules" (
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

    CONSTRAINT "pcap_yara_rules_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "pcap_yara_rules_organization_id_idx" ON "pcap_yara_rules"("organization_id");

-- CreateIndex
CREATE INDEX "pcap_yara_rules_enabled_idx" ON "pcap_yara_rules"("enabled");

-- CreateIndex
CREATE INDEX "pcap_yara_rules_is_builtin_idx" ON "pcap_yara_rules"("is_builtin");

-- CreateIndex
CREATE INDEX "pcap_findings_yara_rule_id_idx" ON "pcap_findings"("yara_rule_id");

-- AddForeignKey
ALTER TABLE "pcap_findings" ADD CONSTRAINT "pcap_findings_yara_rule_id_fkey" FOREIGN KEY ("yara_rule_id") REFERENCES "pcap_yara_rules"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "pcap_yara_rules" ADD CONSTRAINT "pcap_yara_rules_created_by_id_fkey" FOREIGN KEY ("created_by_id") REFERENCES "users"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "pcap_yara_rules" ADD CONSTRAINT "pcap_yara_rules_organization_id_fkey" FOREIGN KEY ("organization_id") REFERENCES "organizations"("id") ON DELETE SET NULL ON UPDATE CASCADE;

