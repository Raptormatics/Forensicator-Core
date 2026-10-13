-- DropIndex
DROP INDEX "organization_members_role_idx";

-- AlterTable
ALTER TABLE "organization_members" DROP COLUMN "role";

-- AlterTable
ALTER TABLE "users" DROP COLUMN "role";

