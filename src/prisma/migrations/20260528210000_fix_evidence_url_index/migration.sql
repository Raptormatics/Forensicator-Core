-- Drop the plain btree indexes on long-text columns that exceed PostgreSQL's
-- btree maximum key size (~2704 bytes for btree v4).
DROP INDEX IF EXISTS "evidence_url_idx";
DROP INDEX IF EXISTS "evidence_domain_idx";

-- Replace with MD5 functional indexes so any-length values can be indexed.
CREATE INDEX "evidence_url_md5_idx"    ON "evidence"(md5("url"));
CREATE INDEX "evidence_domain_md5_idx" ON "evidence"(md5("domain"));
