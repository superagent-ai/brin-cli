-- Add 'dismissed' status for threats reviewed and determined to be false positives
-- Four states: pending (default), in_progress, verified, dismissed
-- Dismissed threats are kept for audit trail but not shown to CLI users

ALTER TABLE agentic_threats
DROP CONSTRAINT IF EXISTS chk_verification_status;

ALTER TABLE agentic_threats
ADD CONSTRAINT chk_verification_status 
CHECK (verification_status IN ('pending', 'in_progress', 'verified', 'dismissed'));
