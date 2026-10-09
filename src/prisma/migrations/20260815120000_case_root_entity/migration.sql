-- AlterTable
ALTER TABLE "cases" ADD COLUMN     "case_seq" SERIAL NOT NULL;

-- CreateIndex
CREATE UNIQUE INDEX "cases_case_seq_key" ON "cases"("case_seq");
