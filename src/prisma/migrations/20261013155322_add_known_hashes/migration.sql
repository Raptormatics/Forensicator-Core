-- CreateTable
CREATE TABLE "known_hashes" (
    "id" UUID NOT NULL,
    "hash" TEXT NOT NULL,
    "source" TEXT NOT NULL DEFAULT 'custom',
    "note" TEXT,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "known_hashes_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "case_known_hashes" (
    "id" UUID NOT NULL,
    "case_id" UUID NOT NULL,
    "known_hash_id" UUID NOT NULL,
    "created_by_id" UUID NOT NULL,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "case_known_hashes_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "known_hashes_hash_key" ON "known_hashes"("hash");

-- CreateIndex
CREATE INDEX "known_hashes_source_idx" ON "known_hashes"("source");

-- CreateIndex
CREATE INDEX "case_known_hashes_case_id_idx" ON "case_known_hashes"("case_id");

-- CreateIndex
CREATE UNIQUE INDEX "case_known_hashes_case_id_known_hash_id_key" ON "case_known_hashes"("case_id", "known_hash_id");

-- AddForeignKey
ALTER TABLE "case_known_hashes" ADD CONSTRAINT "case_known_hashes_case_id_fkey" FOREIGN KEY ("case_id") REFERENCES "cases"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "case_known_hashes" ADD CONSTRAINT "case_known_hashes_known_hash_id_fkey" FOREIGN KEY ("known_hash_id") REFERENCES "known_hashes"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "case_known_hashes" ADD CONSTRAINT "case_known_hashes_created_by_id_fkey" FOREIGN KEY ("created_by_id") REFERENCES "users"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

