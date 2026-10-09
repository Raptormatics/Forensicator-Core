-- AlterTable
ALTER TABLE "system_settings"
  ADD COLUMN "ollama_host" TEXT NOT NULL DEFAULT 'http://localhost:11434',
  ADD COLUMN "ollama_model" TEXT NOT NULL DEFAULT 'mistral:7b-instruct';
