-- Rename Ollama-specific columns to generic AI columns (multi-provider support)
ALTER TABLE "system_settings" RENAME COLUMN "ollama_host" TO "ai_host";
ALTER TABLE "system_settings" RENAME COLUMN "ollama_model" TO "ai_model";

-- AlterTable
ALTER TABLE "system_settings"
  ADD COLUMN "ai_provider" TEXT NOT NULL DEFAULT 'ollama',
  ADD COLUMN "ai_api_key_encrypted" TEXT,
  ADD COLUMN "ai_api_key_last4" TEXT;
