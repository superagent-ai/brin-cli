# Deployment Guide

## Prerequisites

1. Authenticate with Google Cloud:
```bash
gcloud auth login
gcloud config set project superagent-410019
```

2. Configure Docker for Artifact Registry:
```bash
gcloud auth configure-docker us-central1-docker.pkg.dev
```

3. Load production environment variables:
```bash
set -a; source .env.production; set +a
```

---

## Build & Deploy All Services

### Worker (scans packages for threats)

```bash
# Build
docker build --platform linux/amd64 -f Dockerfile.worker -t us-central1-docker.pkg.dev/superagent-410019/brin/worker:latest .

# Push
docker push us-central1-docker.pkg.dev/superagent-410019/brin/worker:latest

# Deploy
set -a; source .env.production; set +a

gcloud run deploy brin-worker \
  --image us-central1-docker.pkg.dev/superagent-410019/brin/worker:latest \
  --region us-central1 \
  --platform managed \
  --allow-unauthenticated \
  --min-instances 1 \
  --set-env-vars "DATABASE_URL=$DATABASE_URL,REDIS_URL=$REDIS_URL,AWS_BEARER_TOKEN_BEDROCK=$AWS_BEARER_TOKEN_BEDROCK,AWS_REGION=$AWS_REGION,GITHUB_TOKEN=$GITHUB_TOKEN,RUST_LOG=info"
```

### API (serves package data)

```bash
# Build
docker build --platform linux/amd64 -f Dockerfile.api -t us-central1-docker.pkg.dev/superagent-410019/brin/api:latest .

# Push
docker push us-central1-docker.pkg.dev/superagent-410019/brin/api:latest

# Deploy
set -a; source .env.production; set +a

gcloud run deploy brin-api \
  --image us-central1-docker.pkg.dev/superagent-410019/brin/api:latest \
  --region us-central1 \
  --platform managed \
  --allow-unauthenticated \
  --set-env-vars "DATABASE_URL=$DATABASE_URL,REDIS_URL=$REDIS_URL,RUST_LOG=info"
```

### CVE Service (enriches packages with CVE data)

```bash
# Build
docker build --platform linux/amd64 -f Dockerfile.cve -t us-central1-docker.pkg.dev/superagent-410019/brin/cve:latest .

# Push
docker push us-central1-docker.pkg.dev/superagent-410019/brin/cve:latest

# Deploy
set -a; source .env.production; set +a

gcloud run deploy brin-cve \
  --image us-central1-docker.pkg.dev/superagent-410019/brin/cve:latest \
  --region us-central1 \
  --platform managed \
  --allow-unauthenticated \
  --min-instances 1 \
  --set-env-vars "DATABASE_URL=$DATABASE_URL,GITHUB_TOKEN=$GITHUB_TOKEN,NVD_API_KEY=$NVD_API_KEY,CVE_POLL_INTERVAL_MINS=15,RUST_LOG=info"
```

### Watcher (monitors npm for updates to tracked packages)

```bash
# Build
docker build --platform linux/amd64 -f Dockerfile.watcher -t us-central1-docker.pkg.dev/superagent-410019/brin/watcher:latest .

# Push
docker push us-central1-docker.pkg.dev/superagent-410019/brin/watcher:latest

# Deploy
set -a; source .env.production; set +a

gcloud run deploy brin-watcher \
  --image us-central1-docker.pkg.dev/superagent-410019/brin/watcher:latest \
  --region us-central1 \
  --platform managed \
  --allow-unauthenticated \
  --min-instances 1 \
  --set-env-vars "DATABASE_URL=$DATABASE_URL,REDIS_URL=$REDIS_URL,POLL_INTERVAL_SECS=30,CHANGES_LIMIT=200,RUST_LOG=info"
```

---

## Database Migrations

Run migrations against production database:

```bash
docker run --rm postgres:16-alpine psql "$DATABASE_URL" -f migrations/YYYYMMDD_migration_name.sql
```

Or inline:

```bash
docker run --rm postgres:16-alpine psql "$DATABASE_URL" -c "ALTER TABLE packages ADD COLUMN IF NOT EXISTS maintainers JSONB;"
```

---

## Seeding

Seed the database with top npm packages:

```bash
set -a; source .env.production; set +a

# Seed with N packages
cargo run --package seed -- --count 100

# Include AI/agent ecosystem packages (langchain, openai, ai, etc.)
cargo run --package seed -- --count 100 --include-ai

# Include packages with known CVEs
cargo run --package seed -- --count 100 --include-cves

# Incremental seeding: skip first N packages, then take next M
# Example: already seeded top 1000, now seed packages 1001-3000
cargo run --package seed -- --offset 1000 --count 2000 --include-ai
```

---

## Monitoring

### Check service logs

```bash
gcloud run services logs read brin-worker --region us-central1 --limit 50
gcloud run services logs read brin-api --region us-central1 --limit 50
gcloud run services logs read brin-cve --region us-central1 --limit 50
gcloud run services logs read brin-watcher --region us-central1 --limit 50
```

### Check Redis queue

```bash
set -a; source .env.production; set +a
docker run --rm redis:7-alpine redis-cli -u "$REDIS_URL" KEYS '*'
```

### Query production database

```bash
docker run --rm postgres:16-alpine psql "$DATABASE_URL" -c "SELECT name, version, risk_level FROM packages ORDER BY scanned_at DESC LIMIT 10;"
```

---

## Troubleshooting

### Clear Redis queue

```bash
set -a; source .env.production; set +a
docker run --rm redis:7-alpine redis-cli -u "$REDIS_URL" FLUSHDB
```

### Check service status

```bash
gcloud run services list --region us-central1
```

### Delete a service

```bash
gcloud run services delete brin-watcher --region us-central1
```
