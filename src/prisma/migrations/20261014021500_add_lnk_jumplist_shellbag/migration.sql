-- CreateTable
CREATE TABLE "lnk_entries" (
    "id" UUID NOT NULL,
    "file_id" UUID NOT NULL,
    "target_path" TEXT,
    "arguments" TEXT,
    "working_directory" TEXT,
    "icon_location" TEXT,
    "creation_time" TIMESTAMP(3),
    "access_time" TIMESTAMP(3),
    "modification_time" TIMESTAMP(3),
    "file_size" INTEGER,
    "drive_serial_number" TEXT,
    "drive_type" TEXT,
    "volume_label" TEXT,
    "net_name" TEXT,
    "device_name" TEXT,
    "machine_id" TEXT,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "lnk_entries_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "jump_list_entries" (
    "id" UUID NOT NULL,
    "file_id" UUID NOT NULL,
    "source" TEXT NOT NULL,
    "app_id" TEXT,
    "target_path" TEXT,
    "arguments" TEXT,
    "working_directory" TEXT,
    "last_accessed" TIMESTAMP(3),
    "access_rank" INTEGER,
    "pinned" BOOLEAN,
    "machine_name" TEXT,
    "stream_number" TEXT,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "jump_list_entries_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "shellbag_entries" (
    "id" UUID NOT NULL,
    "file_id" UUID NOT NULL,
    "path" TEXT NOT NULL,
    "node_name" TEXT NOT NULL,
    "node_slot" TEXT NOT NULL,
    "depth" INTEGER NOT NULL,
    "item_type" TEXT,
    "creation_time" TIMESTAMP(3),
    "access_time" TIMESTAMP(3),
    "last_modified" TIMESTAMP(3),
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "shellbag_entries_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "lnk_entries_file_id_idx" ON "lnk_entries"("file_id");

-- CreateIndex
CREATE INDEX "lnk_entries_target_path_idx" ON "lnk_entries"("target_path");

-- CreateIndex
CREATE INDEX "jump_list_entries_file_id_idx" ON "jump_list_entries"("file_id");

-- CreateIndex
CREATE INDEX "jump_list_entries_target_path_idx" ON "jump_list_entries"("target_path");

-- CreateIndex
CREATE INDEX "shellbag_entries_file_id_idx" ON "shellbag_entries"("file_id");

-- CreateIndex
CREATE INDEX "shellbag_entries_path_idx" ON "shellbag_entries"("path");

-- AddForeignKey
ALTER TABLE "lnk_entries" ADD CONSTRAINT "lnk_entries_file_id_fkey" FOREIGN KEY ("file_id") REFERENCES "windows_artifact_files"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "jump_list_entries" ADD CONSTRAINT "jump_list_entries_file_id_fkey" FOREIGN KEY ("file_id") REFERENCES "windows_artifact_files"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "shellbag_entries" ADD CONSTRAINT "shellbag_entries_file_id_fkey" FOREIGN KEY ("file_id") REFERENCES "windows_artifact_files"("id") ON DELETE CASCADE ON UPDATE CASCADE;

