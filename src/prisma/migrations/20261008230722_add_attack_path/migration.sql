-- CreateTable
CREATE TABLE "attack_paths" (
    "id" UUID NOT NULL,
    "investigation_id" UUID NOT NULL,
    "job_id" TEXT,
    "status" TEXT NOT NULL DEFAULT 'pending',
    "stages" JSONB NOT NULL,
    "summary" TEXT,
    "generated_at" TIMESTAMP(3),
    "error_message" TEXT,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "attack_paths_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "attack_paths_investigation_id_idx" ON "attack_paths"("investigation_id");

-- CreateIndex
CREATE INDEX "attack_paths_status_idx" ON "attack_paths"("status");

-- AddForeignKey
ALTER TABLE "attack_paths" ADD CONSTRAINT "attack_paths_investigation_id_fkey" FOREIGN KEY ("investigation_id") REFERENCES "investigations"("id") ON DELETE CASCADE ON UPDATE CASCADE;
