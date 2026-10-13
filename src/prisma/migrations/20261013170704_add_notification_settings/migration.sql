-- AlterTable
ALTER TABLE "system_settings" ADD COLUMN     "critical_finding_alerts_enabled" BOOLEAN NOT NULL DEFAULT false,
ADD COLUMN     "notification_email" TEXT,
ADD COLUMN     "smtp_from_address" TEXT,
ADD COLUMN     "smtp_host" TEXT,
ADD COLUMN     "smtp_password_encrypted" TEXT,
ADD COLUMN     "smtp_password_last4" TEXT,
ADD COLUMN     "smtp_port" INTEGER,
ADD COLUMN     "smtp_secure" BOOLEAN NOT NULL DEFAULT false,
ADD COLUMN     "smtp_user" TEXT;

