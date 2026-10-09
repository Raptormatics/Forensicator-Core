-- AlterTable
ALTER TABLE "system_settings"
  ADD COLUMN "ai_enabled" BOOLEAN NOT NULL DEFAULT false,
  ADD COLUMN "ollama_managed" BOOLEAN NOT NULL DEFAULT false;
