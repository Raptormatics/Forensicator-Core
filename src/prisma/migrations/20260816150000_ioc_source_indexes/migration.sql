-- Indexes on the core "evidence" table — kept even though their original
-- motivation (the Enterprise IOC Intelligence page's "Source" lookup) is a
-- Pro feature, since they're genuinely useful on evidence.domain/url
-- lookups generally and don't reference or depend on anything Pro-only.
-- The matching log_iocs/pcap_iocs/ram_iocs indexes from the original
-- migration are NOT included here — those tables don't exist in Core.

CREATE INDEX "evidence_domain_idx" ON "evidence"("domain");
-- Plain btree fails: some existing URL values exceed the 2704-byte row limit.
-- Hash index only supports equality, which is all this column is ever
-- queried with (IN-lists for IOC-style lookups).
CREATE INDEX "evidence_url_idx" ON "evidence" USING HASH ("url");
