-- CreateTable
CREATE TABLE "imported_iocs" (
    "id" UUID NOT NULL,
    "case_id" UUID NOT NULL,
    "value" TEXT NOT NULL,
    "type" TEXT NOT NULL,
    "created_by_id" UUID NOT NULL,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "imported_iocs_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "imported_iocs_case_id_idx" ON "imported_iocs"("case_id");

-- CreateIndex
CREATE UNIQUE INDEX "imported_iocs_case_id_value_key" ON "imported_iocs"("case_id", "value");

-- AddForeignKey
ALTER TABLE "imported_iocs" ADD CONSTRAINT "imported_iocs_case_id_fkey" FOREIGN KEY ("case_id") REFERENCES "cases"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "imported_iocs" ADD CONSTRAINT "imported_iocs_created_by_id_fkey" FOREIGN KEY ("created_by_id") REFERENCES "users"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

