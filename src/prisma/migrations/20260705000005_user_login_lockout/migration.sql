-- ─────────────────────────────────────────────────────────────────────────────
-- Migration: 20260705000005_user_login_lockout
-- Adds brute-force lockout tracking to users — purely additive.
-- ─────────────────────────────────────────────────────────────────────────────

ALTER TABLE "users" ADD COLUMN IF NOT EXISTS "failed_login_attempts" INTEGER NOT NULL DEFAULT 0;
ALTER TABLE "users" ADD COLUMN IF NOT EXISTS "locked_until" TIMESTAMP(3);
