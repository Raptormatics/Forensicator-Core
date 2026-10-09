-- ─────────────────────────────────────────────────────────────────────────────
-- Migration: 20260705000004_investigation_archive_sha256
-- Adds archive_sha256 — SHA-256 of the raw uploaded collector ZIP, computed
-- at upload time so investigators can verify it against the hash the
-- collector reported at collection time. Purely additive.
-- ─────────────────────────────────────────────────────────────────────────────

ALTER TABLE "investigations" ADD COLUMN IF NOT EXISTS "archive_sha256" VARCHAR(64);
CREATE INDEX IF NOT EXISTS "investigations_archive_sha256_idx" ON "investigations" ("archive_sha256");
