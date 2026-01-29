//! Redis-based scan queue

use crate::models::{ScanJob, ScanPriority};
use anyhow::Result;
use deadpool_redis::{Config, Pool, Runtime};
use redis::AsyncCommands;

const QUEUE_KEY_PREFIX: &str = "sus:scan:queue:";
const JOB_KEY_PREFIX: &str = "sus:scan:job:";

/// Redis-backed priority scan queue
#[derive(Clone)]
pub struct ScanQueue {
    pool: Pool,
}

impl ScanQueue {
    /// Create a new scan queue
    pub async fn new(redis_url: &str) -> Result<Self> {
        let cfg = Config::from_url(redis_url);
        let pool = cfg.create_pool(Some(Runtime::Tokio1))?;

        // Test connection
        let mut conn = pool.get().await?;
        let _: () = redis::cmd("PING").query_async(&mut conn).await?;

        Ok(Self { pool })
    }

    /// Push a job to the queue
    pub async fn push(&self, job: ScanJob) -> Result<()> {
        let mut conn = self.pool.get().await?;

        // Store job data
        let job_key = format!("{}{}", JOB_KEY_PREFIX, job.id);
        let job_json = serde_json::to_string(&job)?;
        let _: () = conn.set(&job_key, &job_json).await?;

        // Add to priority queue (sorted set with priority as score)
        let queue_key = self.queue_key_for_priority(job.priority);
        let score = job.requested_at.timestamp_millis() as f64;
        let _: () = conn.zadd(&queue_key, job.id.to_string(), score).await?;

        tracing::debug!(
            job_id = %job.id,
            package = %job.package,
            priority = ?job.priority,
            "Pushed job to queue"
        );

        Ok(())
    }

    /// Push a high-priority job (user-requested)
    pub async fn push_priority(&self, job: ScanJob) -> Result<uuid::Uuid> {
        let id = job.id;
        self.push(job).await?;
        Ok(id)
    }

    /// Pop the highest priority job
    pub async fn pop(&self) -> Result<Option<ScanJob>> {
        let mut conn = self.pool.get().await?;

        // Try each priority level from highest to lowest
        for priority in [
            ScanPriority::Immediate,
            ScanPriority::High,
            ScanPriority::Medium,
            ScanPriority::Low,
        ] {
            let queue_key = self.queue_key_for_priority(priority);

            // Pop from sorted set (ZPOPMIN returns lowest score first, which is oldest)
            let result: Option<(String, f64)> =
                conn.zpopmin(&queue_key, 1)
                    .await
                    .ok()
                    .and_then(|v: Vec<(String, f64)>| {
                        if v.is_empty() {
                            None
                        } else {
                            Some(v.into_iter().next().unwrap())
                        }
                    });

            if let Some((job_id, _)) = result {
                // Fetch job data
                let job_key = format!("{}{}", JOB_KEY_PREFIX, job_id);
                let job_json: Option<String> = conn.get(&job_key).await?;

                if let Some(json) = job_json {
                    // Delete job data
                    let _: () = conn.del(&job_key).await?;

                    let job: ScanJob = serde_json::from_str(&json)?;
                    tracing::debug!(
                        job_id = %job.id,
                        package = %job.package,
                        priority = ?job.priority,
                        "Popped job from queue"
                    );
                    return Ok(Some(job));
                }
            }
        }

        Ok(None)
    }

    /// Get queue length for a priority
    pub async fn len(&self, priority: ScanPriority) -> Result<usize> {
        let mut conn = self.pool.get().await?;
        let queue_key = self.queue_key_for_priority(priority);
        let len: usize = conn.zcard(&queue_key).await?;
        Ok(len)
    }

    /// Get total queue length across all priorities
    pub async fn total_len(&self) -> Result<usize> {
        let mut total = 0;
        for priority in [
            ScanPriority::Immediate,
            ScanPriority::High,
            ScanPriority::Medium,
            ScanPriority::Low,
        ] {
            total += self.len(priority).await?;
        }
        Ok(total)
    }

    fn queue_key_for_priority(&self, priority: ScanPriority) -> String {
        format!("{}{:?}", QUEUE_KEY_PREFIX, priority)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore] // Requires Redis
    async fn test_queue_push_pop() {
        let queue = ScanQueue::new("redis://localhost:6379").await.unwrap();

        let job = ScanJob::new(
            "test-package".to_string(),
            Some("1.0.0".to_string()),
            ScanPriority::High,
        );
        let job_id = job.id;

        queue.push(job).await.unwrap();

        let popped = queue.pop().await.unwrap();
        assert!(popped.is_some());
        assert_eq!(popped.unwrap().id, job_id);
    }
}
