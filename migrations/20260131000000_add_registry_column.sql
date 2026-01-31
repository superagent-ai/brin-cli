-- Add registry column with default 'npm'
ALTER TABLE packages ADD COLUMN IF NOT EXISTS registry VARCHAR(50) NOT NULL DEFAULT 'npm';

-- Drop existing unique constraint and recreate with registry
ALTER TABLE packages DROP CONSTRAINT IF EXISTS packages_name_version_key;
ALTER TABLE packages ADD CONSTRAINT packages_name_version_registry_key UNIQUE (name, version, registry);

-- Add index for registry queries
CREATE INDEX IF NOT EXISTS idx_packages_registry ON packages(registry);
