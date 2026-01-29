//! Database connection and operations

use crate::models::*;
use anyhow::Result;
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;

/// Database connection wrapper
#[derive(Clone)]
pub struct Database {
    pool: PgPool,
}

impl Database {
    /// Create a new database connection
    pub async fn new(database_url: &str) -> Result<Self> {
        let pool = PgPoolOptions::new()
            .max_connections(10)
            .connect(database_url)
            .await?;

        Ok(Self { pool })
    }

    /// Get the underlying pool
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// Run migrations
    pub async fn migrate(&self) -> Result<()> {
        sqlx::migrate!("../../migrations").run(&self.pool).await?;
        Ok(())
    }

    /// Get the latest scan for a package (any version)
    pub async fn get_latest_scan(&self, name: &str) -> Result<Option<Package>> {
        let package = sqlx::query_as::<_, Package>(
            r#"
            SELECT * FROM packages 
            WHERE name = $1 
            ORDER BY scanned_at DESC 
            LIMIT 1
            "#,
        )
        .bind(name)
        .fetch_optional(&self.pool)
        .await?;

        Ok(package)
    }

    /// Get a specific package version scan
    pub async fn get_scan(&self, name: &str, version: &str) -> Result<Option<Package>> {
        let package = sqlx::query_as::<_, Package>(
            r#"
            SELECT * FROM packages 
            WHERE name = $1 AND version = $2
            "#,
        )
        .bind(name)
        .bind(version)
        .fetch_optional(&self.pool)
        .await?;

        Ok(package)
    }

    /// Get CVEs for a package
    pub async fn get_package_cves(&self, package_id: i32) -> Result<Vec<PackageCve>> {
        let cves = sqlx::query_as::<_, PackageCve>(
            r#"
            SELECT * FROM package_cves 
            WHERE package_id = $1
            "#,
        )
        .bind(package_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(cves)
    }

    /// Get agentic threats for a package
    pub async fn get_package_threats(&self, package_id: i32) -> Result<Vec<AgenticThreat>> {
        let threats = sqlx::query_as::<_, AgenticThreat>(
            r#"
            SELECT * FROM agentic_threats 
            WHERE package_id = $1
            "#,
        )
        .bind(package_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(threats)
    }

    /// Insert or update a package scan
    pub async fn upsert_package(&self, package: &NewPackage) -> Result<i32> {
        let row = sqlx::query_scalar::<_, i32>(
            r#"
            INSERT INTO packages (name, version, risk_level, risk_reasons, trust_score, 
                publisher_verified, weekly_downloads, maintainer_count, last_publish, 
                capabilities, skill_md, scan_version)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
            ON CONFLICT (name, version) DO UPDATE SET
                risk_level = EXCLUDED.risk_level,
                risk_reasons = EXCLUDED.risk_reasons,
                trust_score = EXCLUDED.trust_score,
                publisher_verified = EXCLUDED.publisher_verified,
                weekly_downloads = EXCLUDED.weekly_downloads,
                maintainer_count = EXCLUDED.maintainer_count,
                last_publish = EXCLUDED.last_publish,
                capabilities = EXCLUDED.capabilities,
                skill_md = EXCLUDED.skill_md,
                scan_version = EXCLUDED.scan_version,
                scanned_at = NOW()
            RETURNING id
            "#,
        )
        .bind(&package.name)
        .bind(&package.version)
        .bind(package.risk_level)
        .bind(&package.risk_reasons)
        .bind(package.trust_score)
        .bind(package.publisher_verified)
        .bind(package.weekly_downloads)
        .bind(package.maintainer_count)
        .bind(package.last_publish)
        .bind(&package.capabilities)
        .bind(&package.skill_md)
        .bind(&package.scan_version)
        .fetch_one(&self.pool)
        .await?;

        Ok(row)
    }

    /// Insert a CVE for a package
    pub async fn insert_cve(&self, cve: &NewPackageCve) -> Result<i32> {
        let id = sqlx::query_scalar::<_, i32>(
            r#"
            INSERT INTO package_cves (package_id, cve_id, severity, description, fixed_in, published_at)
            VALUES ($1, $2, $3, $4, $5, $6)
            RETURNING id
            "#,
        )
        .bind(cve.package_id)
        .bind(&cve.cve_id)
        .bind(&cve.severity)
        .bind(&cve.description)
        .bind(&cve.fixed_in)
        .bind(cve.published_at)
        .fetch_one(&self.pool)
        .await?;

        Ok(id)
    }

    /// Insert an agentic threat
    pub async fn insert_threat(&self, threat: &NewAgenticThreat) -> Result<i32> {
        let id = sqlx::query_scalar::<_, i32>(
            r#"
            INSERT INTO agentic_threats (package_id, threat_type, confidence, location, snippet)
            VALUES ($1, $2, $3, $4, $5)
            RETURNING id
            "#,
        )
        .bind(threat.package_id)
        .bind(threat.threat_type)
        .bind(threat.confidence)
        .bind(&threat.location)
        .bind(&threat.snippet)
        .fetch_one(&self.pool)
        .await?;

        Ok(id)
    }

    /// Delete old CVEs for a package (before re-scanning)
    pub async fn delete_package_cves(&self, package_id: i32) -> Result<()> {
        sqlx::query("DELETE FROM package_cves WHERE package_id = $1")
            .bind(package_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Delete old threats for a package (before re-scanning)
    pub async fn delete_package_threats(&self, package_id: i32) -> Result<()> {
        sqlx::query("DELETE FROM agentic_threats WHERE package_id = $1")
            .bind(package_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Bulk lookup packages
    pub async fn bulk_lookup(&self, packages: &[PackageVersionPair]) -> Result<Vec<Package>> {
        // Build query with multiple conditions
        let mut results = Vec::new();
        for pkg in packages {
            if let Some(package) = self.get_scan(&pkg.name, &pkg.version).await? {
                results.push(package);
            }
        }
        Ok(results)
    }

    /// Check if a package (any version) exists in the database
    pub async fn package_exists(&self, name: &str) -> Result<bool> {
        let exists: bool =
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM packages WHERE name = $1)")
                .bind(name)
                .fetch_one(&self.pool)
                .await?;

        Ok(exists)
    }

    /// Get all unique package names in the database (for caching)
    pub async fn get_all_package_names(&self) -> Result<Vec<String>> {
        let names: Vec<String> = sqlx::query_scalar("SELECT DISTINCT name FROM packages")
            .fetch_all(&self.pool)
            .await?;

        Ok(names)
    }
}

/// New package for insertion
#[derive(Debug, Clone)]
pub struct NewPackage {
    pub name: String,
    pub version: String,
    pub risk_level: RiskLevel,
    pub risk_reasons: serde_json::Value,
    pub trust_score: Option<i16>,
    pub publisher_verified: Option<bool>,
    pub weekly_downloads: Option<i64>,
    pub maintainer_count: Option<i32>,
    pub last_publish: Option<chrono::DateTime<chrono::Utc>>,
    pub capabilities: serde_json::Value,
    pub skill_md: Option<String>,
    pub scan_version: Option<String>,
}

/// New CVE for insertion
#[derive(Debug, Clone)]
pub struct NewPackageCve {
    pub package_id: i32,
    pub cve_id: String,
    pub severity: Option<String>,
    pub description: Option<String>,
    pub fixed_in: Option<String>,
    pub published_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// New agentic threat for insertion
#[derive(Debug, Clone)]
pub struct NewAgenticThreat {
    pub package_id: i32,
    pub threat_type: ThreatType,
    pub confidence: f32,
    pub location: Option<String>,
    pub snippet: Option<String>,
}
