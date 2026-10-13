-- AlterTable
ALTER TABLE "cases" ADD COLUMN     "incident_type" TEXT;

-- CreateTable
CREATE TABLE "playbooks" (
    "id" UUID NOT NULL,
    "name" TEXT NOT NULL,
    "incident_type" TEXT NOT NULL,
    "description" TEXT,
    "is_builtin" BOOLEAN NOT NULL DEFAULT true,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "playbooks_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "playbook_tasks" (
    "id" UUID NOT NULL,
    "playbook_id" UUID NOT NULL,
    "title" TEXT NOT NULL,
    "notes" TEXT,
    "priority" TEXT NOT NULL DEFAULT 'medium',
    "order" INTEGER NOT NULL DEFAULT 0,

    CONSTRAINT "playbook_tasks_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "playbooks_incident_type_key" ON "playbooks"("incident_type");

-- CreateIndex
CREATE INDEX "playbook_tasks_playbook_id_idx" ON "playbook_tasks"("playbook_id");

-- AddForeignKey
ALTER TABLE "playbook_tasks" ADD CONSTRAINT "playbook_tasks_playbook_id_fkey" FOREIGN KEY ("playbook_id") REFERENCES "playbooks"("id") ON DELETE CASCADE ON UPDATE CASCADE;

