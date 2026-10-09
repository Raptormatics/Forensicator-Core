-- HostProfile triage fields for the Host Profiles page revamp: primary
-- user, last known IP, and analyst-tracked (not live/EDR) containment status.

ALTER TABLE "host_profiles" ADD COLUMN     "isolation_note" TEXT,
ADD COLUMN     "isolation_status" TEXT NOT NULL DEFAULT 'active',
ADD COLUMN     "isolation_updated_at" TIMESTAMP(3),
ADD COLUMN     "isolation_updated_by_id" UUID,
ADD COLUMN     "last_known_ip" TEXT,
ADD COLUMN     "primary_user" TEXT;

CREATE INDEX "host_profiles_isolation_status_idx" ON "host_profiles"("isolation_status");

ALTER TABLE "host_profiles" ADD CONSTRAINT "host_profiles_isolation_updated_by_id_fkey" FOREIGN KEY ("isolation_updated_by_id") REFERENCES "users"("id") ON DELETE SET NULL ON UPDATE CASCADE;
