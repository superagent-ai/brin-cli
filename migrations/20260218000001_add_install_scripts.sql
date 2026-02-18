-- Add install_scripts JSONB column to packages table
ALTER TABLE packages ADD COLUMN IF NOT EXISTS install_scripts JSONB NOT NULL DEFAULT '{}';
