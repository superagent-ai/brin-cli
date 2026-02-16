-- Initial database schema for brin

-- Packages table
CREATE TABLE IF NOT EXISTS packages (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    version VARCHAR(100) NOT NULL,
    
    -- Risk assessment
    risk_level VARCHAR(20) NOT NULL,  -- 'clean', 'warning', 'critical'
    risk_reasons JSONB DEFAULT '[]',
    
    -- Trust signals
    trust_score SMALLINT,
    publisher_verified BOOLEAN,
    weekly_downloads BIGINT,
    maintainer_count INTEGER,
    last_publish TIMESTAMPTZ,
    
    -- Capabilities
    capabilities JSONB NOT NULL DEFAULT '{}',
    
    -- Generated manifest
    skill_md TEXT,
    
    -- Metadata
    scanned_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    scan_version VARCHAR(20),
    
    UNIQUE(name, version)
);

-- CVEs linked to packages
CREATE TABLE IF NOT EXISTS package_cves (
    id SERIAL PRIMARY KEY,
    package_id INTEGER REFERENCES packages(id) ON DELETE CASCADE,
    cve_id VARCHAR(50) NOT NULL,
    severity VARCHAR(20),
    description TEXT,
    fixed_in VARCHAR(100),
    published_at TIMESTAMPTZ
);

-- Agentic threats detected
CREATE TABLE IF NOT EXISTS agentic_threats (
    id SERIAL PRIMARY KEY,
    package_id INTEGER REFERENCES packages(id) ON DELETE CASCADE,
    threat_type VARCHAR(50) NOT NULL,
    confidence REAL NOT NULL,
    location VARCHAR(255),
    snippet TEXT,
    detected_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_packages_name ON packages(name);
CREATE INDEX IF NOT EXISTS idx_packages_risk ON packages(risk_level);
CREATE INDEX IF NOT EXISTS idx_packages_scanned ON packages(scanned_at);
CREATE INDEX IF NOT EXISTS idx_package_cves_package ON package_cves(package_id);
CREATE INDEX IF NOT EXISTS idx_agentic_threats_package ON agentic_threats(package_id);
