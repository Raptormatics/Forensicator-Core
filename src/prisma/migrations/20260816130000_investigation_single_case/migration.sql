-- Case <-> Investigation is a direct one-to-many on Core (there is no
-- case_investigations many-to-many join table here at all — that table,
-- and the migration that collapses it down to this same direct column,
-- only ever existed in the Enterprise lineage this schema split was cut
-- from; Core goes straight to the direct FK).

ALTER TABLE "investigations" ADD COLUMN "case_id" UUID;

CREATE INDEX "investigations_case_id_idx" ON "investigations"("case_id");
ALTER TABLE "investigations" ADD CONSTRAINT "investigations_case_id_fkey" FOREIGN KEY ("case_id") REFERENCES "cases"("id") ON DELETE SET NULL ON UPDATE CASCADE;
