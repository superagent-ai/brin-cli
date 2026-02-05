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

    /// Get the latest scan for a package (any version), optionally filtered by registry
    pub async fn get_latest_scan(
        &self,
        name: &str,
        registry: Option<Registry>,
    ) -> Result<Option<Package>> {
        let package = match registry {
            Some(reg) => {
                sqlx::query_as::<_, Package>(
                    r#"
                    SELECT * FROM packages 
                    WHERE name = $1 AND registry = $2
                    ORDER BY scanned_at DESC 
                    LIMIT 1
                    "#,
                )
                .bind(name)
                .bind(reg)
                .fetch_optional(&self.pool)
                .await?
            }
            None => {
                sqlx::query_as::<_, Package>(
                    r#"
                    SELECT * FROM packages 
                    WHERE name = $1 
                    ORDER BY scanned_at DESC 
                    LIMIT 1
                    "#,
                )
                .bind(name)
                .fetch_optional(&self.pool)
                .await?
            }
        };

        Ok(package)
    }

    /// Get a specific package version scan, optionally filtered by registry
    pub async fn get_scan(
        &self,
        name: &str,
        version: &str,
        registry: Option<Registry>,
    ) -> Result<Option<Package>> {
        let package = match registry {
            Some(reg) => {
                sqlx::query_as::<_, Package>(
                    r#"
                    SELECT * FROM packages 
                    WHERE name = $1 AND version = $2 AND registry = $3
                    "#,
                )
                .bind(name)
                .bind(version)
                .bind(reg)
                .fetch_optional(&self.pool)
                .await?
            }
            None => {
                sqlx::query_as::<_, Package>(
                    r#"
                    SELECT * FROM packages 
                    WHERE name = $1 AND version = $2
                    "#,
                )
                .bind(name)
                .bind(version)
                .fetch_optional(&self.pool)
                .await?
            }
        };

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

    /// Get verified agentic threats for a package (only verified threats are returned)
    pub async fn get_package_threats(&self, package_id: i32) -> Result<Vec<AgenticThreat>> {
        let threats = sqlx::query_as::<_, AgenticThreat>(
            r#"
            SELECT * FROM agentic_threats 
            WHERE package_id = $1 AND verification_status = 'verified'
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
            INSERT INTO packages (name, version, registry, risk_level, risk_reasons, trust_score, 
                publisher_verified, weekly_downloads, maintainer_count, maintainers, last_publish, 
                capabilities, skill_md, scan_version)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
            ON CONFLICT (name, version, registry) DO UPDATE SET
                risk_level = EXCLUDED.risk_level,
                risk_reasons = EXCLUDED.risk_reasons,
                trust_score = EXCLUDED.trust_score,
                publisher_verified = EXCLUDED.publisher_verified,
                weekly_downloads = EXCLUDED.weekly_downloads,
                maintainer_count = EXCLUDED.maintainer_count,
                maintainers = EXCLUDED.maintainers,
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
        .bind(package.registry)
        .bind(package.risk_level)
        .bind(&package.risk_reasons)
        .bind(package.trust_score)
        .bind(package.publisher_verified)
        .bind(package.weekly_downloads)
        .bind(package.maintainer_count)
        .bind(&package.maintainers)
        .bind(package.last_publish)
        .bind(&package.capabilities)
        .bind(&package.skill_md)
        .bind(&package.scan_version)
        .fetch_one(&self.pool)
        .await?;

        Ok(row)
    }

    /// Insert a CVE for a package (upsert to avoid duplicates)
    pub async fn insert_cve(&self, cve: &NewPackageCve) -> Result<i32> {
        let id = sqlx::query_scalar::<_, i32>(
            r#"
            INSERT INTO package_cves (package_id, cve_id, severity, description, fixed_in, published_at)
            VALUES ($1, $2, $3, $4, $5, $6)
            ON CONFLICT (package_id, cve_id) DO UPDATE SET
                severity = EXCLUDED.severity,
                description = EXCLUDED.description,
                fixed_in = EXCLUDED.fixed_in,
                published_at = EXCLUDED.published_at
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
            if let Some(package) = self.get_scan(&pkg.name, &pkg.version, pkg.registry).await? {
                results.push(package);
            }
        }
        Ok(results)
    }

    /// Check if a package (any version) exists in the database, optionally filtered by registry
    pub async fn package_exists(&self, name: &str, registry: Option<Registry>) -> Result<bool> {
        let exists: bool = match registry {
            Some(reg) => {
                sqlx::query_scalar(
                    "SELECT EXISTS(SELECT 1 FROM packages WHERE name = $1 AND registry = $2)",
                )
                .bind(name)
                .bind(reg)
                .fetch_one(&self.pool)
                .await?
            }
            None => {
                sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM packages WHERE name = $1)")
                    .bind(name)
                    .fetch_one(&self.pool)
                    .await?
            }
        };

        Ok(exists)
    }

    /// Get all unique package names in the database (for caching)
    pub async fn get_all_package_names(&self) -> Result<Vec<String>> {
        let names: Vec<String> = sqlx::query_scalar("SELECT DISTINCT name FROM packages")
            .fetch_all(&self.pool)
            .await?;

        Ok(names)
    }

    /// Get all unique package names for a specific registry
    pub async fn get_package_names_by_registry(
        &self,
        registry: crate::models::Registry,
    ) -> Result<Vec<String>> {
        let registry_str = registry.to_string().to_lowercase();
        let names: Vec<String> =
            sqlx::query_scalar("SELECT DISTINCT name FROM packages WHERE registry = $1")
                .bind(&registry_str)
                .fetch_all(&self.pool)
                .await?;

        Ok(names)
    }

    /// Get the latest version of each unique package (for watcher sweep)
    pub async fn get_all_packages_latest_version(&self) -> Result<Vec<PackageBasicInfo>> {
        let packages: Vec<PackageBasicInfo> = sqlx::query_as(
            r#"
            SELECT DISTINCT ON (name, registry) name, version, registry
            FROM packages
            ORDER BY name, registry, scanned_at DESC
            "#,
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(packages)
    }

    /// Get all packages from the database
    pub async fn get_all_packages(&self) -> Result<Vec<Package>> {
        let packages: Vec<Package> = sqlx::query_as(
            r#"
            SELECT id, name, version, registry, risk_level, risk_reasons, trust_score,
                   publisher_verified, weekly_downloads, maintainer_count,
                   last_publish, capabilities, skill_md, scanned_at, scan_version
            FROM packages
            ORDER BY name, version
            "#,
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(packages)
    }

    /// Get packages with pagination and CVE/threat counts (optimized for list views)
    pub async fn get_packages_paginated(
        &self,
        limit: i64,
        offset: i64,
        registry: Option<Registry>,
        risk_level: Option<RiskLevel>,
    ) -> Result<(Vec<PackageWithCounts>, i64)> {
        let registry_str = registry.map(|r| r.to_string());
        let risk_level_str = risk_level.map(|r| r.to_string());

        let packages: Vec<PackageWithCounts> = sqlx::query_as(
            r#"
            SELECT 
                p.id, p.name, p.version, p.registry, p.risk_level, p.trust_score,
                p.publisher_verified, p.weekly_downloads, p.capabilities, p.scanned_at,
                COALESCE((SELECT COUNT(*) FROM package_cves WHERE package_id = p.id), 0) as cve_count,
                COALESCE((SELECT COUNT(*) FROM agentic_threats WHERE package_id = p.id AND verification_status = 'verified'), 0) as threat_count
            FROM packages p
            WHERE ($3::text IS NULL OR p.registry = $3)
              AND ($4::text IS NULL OR p.risk_level = $4)
            ORDER BY p.weekly_downloads DESC NULLS LAST, p.name ASC
            LIMIT $1 OFFSET $2
            "#,
        )
        .bind(limit)
        .bind(offset)
        .bind(&registry_str)
        .bind(&risk_level_str)
        .fetch_all(&self.pool)
        .await?;

        let total: (i64,) = sqlx::query_as(
            r#"
            SELECT COUNT(*) FROM packages
            WHERE ($1::text IS NULL OR registry = $1)
              AND ($2::text IS NULL OR risk_level = $2)
            "#,
        )
        .bind(&registry_str)
        .bind(&risk_level_str)
        .fetch_one(&self.pool)
        .await?;

        Ok((packages, total.0))
    }

    /// Search packages by name with pagination and CVE/threat counts
    /// Results are ranked by relevance: exact match > starts with > contains
    pub async fn search_packages(
        &self,
        query: &str,
        limit: i64,
        offset: i64,
        registry: Option<Registry>,
        risk_level: Option<RiskLevel>,
    ) -> Result<(Vec<PackageWithCounts>, i64)> {
        let pattern = format!("%{}%", query);
        let registry_str = registry.map(|r| r.to_string());
        let risk_level_str = risk_level.map(|r| r.to_string());

        let packages: Vec<PackageWithCounts> = sqlx::query_as(
            r#"
            SELECT 
                p.id, p.name, p.version, p.registry, p.risk_level, p.trust_score,
                p.publisher_verified, p.weekly_downloads, p.capabilities, p.scanned_at,
                COALESCE((SELECT COUNT(*) FROM package_cves WHERE package_id = p.id), 0) as cve_count,
                COALESCE((SELECT COUNT(*) FROM agentic_threats WHERE package_id = p.id AND verification_status = 'verified'), 0) as threat_count
            FROM packages p
            WHERE p.name ILIKE $1
              AND ($5::text IS NULL OR p.registry = $5)
              AND ($6::text IS NULL OR p.risk_level = $6)
            ORDER BY 
                CASE 
                    WHEN LOWER(p.name) = LOWER($2) THEN 0
                    WHEN LOWER(p.name) LIKE LOWER($2) || '%' THEN 1
                    ELSE 2
                END,
                p.weekly_downloads DESC NULLS LAST,
                p.name ASC
            LIMIT $3 OFFSET $4
            "#,
        )
        .bind(&pattern)
        .bind(query)
        .bind(limit)
        .bind(offset)
        .bind(&registry_str)
        .bind(&risk_level_str)
        .fetch_all(&self.pool)
        .await?;

        let total: (i64,) = sqlx::query_as(
            r#"
            SELECT COUNT(*) FROM packages
            WHERE name ILIKE $1
              AND ($2::text IS NULL OR registry = $2)
              AND ($3::text IS NULL OR risk_level = $3)
            "#,
        )
        .bind(&pattern)
        .bind(&registry_str)
        .bind(&risk_level_str)
        .fetch_one(&self.pool)
        .await?;

        Ok((packages, total.0))
    }

    /// Get packages with pagination, latest version only per (name, registry)
    pub async fn get_packages_paginated_latest(
        &self,
        limit: i64,
        offset: i64,
        registry: Option<Registry>,
        risk_level: Option<RiskLevel>,
    ) -> Result<(Vec<PackageWithCounts>, i64)> {
        let registry_str = registry.map(|r| r.to_string());
        let risk_level_str = risk_level.map(|r| r.to_string());

        let packages: Vec<PackageWithCounts> = sqlx::query_as(
            r#"
            WITH latest AS (
                SELECT DISTINCT ON (name, registry) *
                FROM packages
                WHERE ($3::text IS NULL OR registry = $3)
                  AND ($4::text IS NULL OR risk_level = $4)
                ORDER BY name, registry, scanned_at DESC
            )
            SELECT 
                p.id, p.name, p.version, p.registry, p.risk_level, p.trust_score,
                p.publisher_verified, p.weekly_downloads, p.capabilities, p.scanned_at,
                COALESCE((SELECT COUNT(*) FROM package_cves WHERE package_id = p.id), 0) as cve_count,
                COALESCE((SELECT COUNT(*) FROM agentic_threats WHERE package_id = p.id AND verification_status = 'verified'), 0) as threat_count
            FROM latest p
            ORDER BY p.weekly_downloads DESC NULLS LAST, p.name ASC
            LIMIT $1 OFFSET $2
            "#,
        )
        .bind(limit)
        .bind(offset)
        .bind(&registry_str)
        .bind(&risk_level_str)
        .fetch_all(&self.pool)
        .await?;

        let total: (i64,) = sqlx::query_as(
            r#"
            SELECT COUNT(*) FROM (
                SELECT DISTINCT name, registry FROM packages
                WHERE ($1::text IS NULL OR registry = $1)
                  AND ($2::text IS NULL OR risk_level = $2)
            ) t
            "#,
        )
        .bind(&registry_str)
        .bind(&risk_level_str)
        .fetch_one(&self.pool)
        .await?;

        Ok((packages, total.0))
    }

    /// Search packages by name, latest version only per (name, registry)
    pub async fn search_packages_latest(
        &self,
        query: &str,
        limit: i64,
        offset: i64,
        registry: Option<Registry>,
        risk_level: Option<RiskLevel>,
    ) -> Result<(Vec<PackageWithCounts>, i64)> {
        let pattern = format!("%{}%", query);
        let registry_str = registry.map(|r| r.to_string());
        let risk_level_str = risk_level.map(|r| r.to_string());

        let packages: Vec<PackageWithCounts> = sqlx::query_as(
            r#"
            WITH latest AS (
                SELECT DISTINCT ON (name, registry) *
                FROM packages
                WHERE name ILIKE $1
                  AND ($5::text IS NULL OR registry = $5)
                  AND ($6::text IS NULL OR risk_level = $6)
                ORDER BY name, registry, scanned_at DESC
            )
            SELECT 
                p.id, p.name, p.version, p.registry, p.risk_level, p.trust_score,
                p.publisher_verified, p.weekly_downloads, p.capabilities, p.scanned_at,
                COALESCE((SELECT COUNT(*) FROM package_cves WHERE package_id = p.id), 0) as cve_count,
                COALESCE((SELECT COUNT(*) FROM agentic_threats WHERE package_id = p.id AND verification_status = 'verified'), 0) as threat_count
            FROM latest p
            ORDER BY 
                CASE 
                    WHEN LOWER(p.name) = LOWER($2) THEN 0
                    WHEN LOWER(p.name) LIKE LOWER($2) || '%' THEN 1
                    ELSE 2
                END,
                p.weekly_downloads DESC NULLS LAST,
                p.name ASC
            LIMIT $3 OFFSET $4
            "#,
        )
        .bind(&pattern)
        .bind(query)
        .bind(limit)
        .bind(offset)
        .bind(&registry_str)
        .bind(&risk_level_str)
        .fetch_all(&self.pool)
        .await?;

        let total: (i64,) = sqlx::query_as(
            r#"
            SELECT COUNT(*) FROM (
                SELECT DISTINCT name, registry FROM packages
                WHERE name ILIKE $1
                  AND ($2::text IS NULL OR registry = $2)
                  AND ($3::text IS NULL OR risk_level = $3)
            ) t
            "#,
        )
        .bind(&pattern)
        .bind(&registry_str)
        .bind(&risk_level_str)
        .fetch_one(&self.pool)
        .await?;

        Ok((packages, total.0))
    }
}

/// Package with CVE/threat counts for list views
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct PackageWithCounts {
    pub id: i32,
    pub name: String,
    pub version: String,
    pub registry: Registry,
    pub risk_level: RiskLevel,
    pub trust_score: Option<i16>,
    pub publisher_verified: Option<bool>,
    pub weekly_downloads: Option<i64>,
    pub capabilities: serde_json::Value,
    pub scanned_at: chrono::DateTime<chrono::Utc>,
    pub cve_count: i64,
    pub threat_count: i64,
}

/// New package for insertion
#[derive(Debug, Clone)]
pub struct NewPackage {
    pub name: String,
    pub version: String,
    pub registry: Registry,
    pub risk_level: RiskLevel,
    pub risk_reasons: serde_json::Value,
    pub trust_score: Option<i16>,
    pub publisher_verified: Option<bool>,
    pub weekly_downloads: Option<i64>,
    pub maintainer_count: Option<i32>,
    pub maintainers: Option<serde_json::Value>,
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
