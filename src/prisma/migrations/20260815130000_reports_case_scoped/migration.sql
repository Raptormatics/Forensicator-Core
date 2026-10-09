-- AlterTable
ALTER TABLE "reports" ADD COLUMN     "case_id" UUID,
ALTER COLUMN "investigation_id" DROP NOT NULL;

-- CreateIndex
CREATE INDEX "reports_case_id_idx" ON "reports"("case_id");

-- AddForeignKey
ALTER TABLE "reports" ADD CONSTRAINT "reports_case_id_fkey" FOREIGN KEY ("case_id") REFERENCES "cases"("id") ON DELETE CASCADE ON UPDATE CASCADE;
