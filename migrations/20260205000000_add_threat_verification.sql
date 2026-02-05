-- Add verification status column to agentic_threats
-- Three states: pending (default), in_progress, verified
-- Only verified threats affect risk_level and are shown to CLI users

ALTER TABLE agentic_threats 
ADD COLUMN verification_status VARCHAR(20) NOT NULL DEFAULT 'pending';

-- Add constraint for valid values
ALTER TABLE agentic_threats
ADD CONSTRAINT chk_verification_status 
CHECK (verification_status IN ('pending', 'in_progress', 'verified'));

-- Index for filtering by status
CREATE INDEX idx_agentic_threats_status ON agentic_threats(verification_status);
