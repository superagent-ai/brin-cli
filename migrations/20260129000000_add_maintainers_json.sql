-- Add maintainers JSONB column to store full maintainer data
ALTER TABLE packages ADD COLUMN IF NOT EXISTS maintainers JSONB;
