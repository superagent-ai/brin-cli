-- Add unique constraint on package_cves to prevent duplicates
ALTER TABLE package_cves ADD CONSTRAINT package_cves_unique UNIQUE (package_id, cve_id);
