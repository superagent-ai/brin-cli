-- Add unique constraint on package_cves to prevent duplicates
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'package_cves_unique'
    ) THEN
        ALTER TABLE package_cves ADD CONSTRAINT package_cves_unique UNIQUE (package_id, cve_id);
    END IF;
END $$;
