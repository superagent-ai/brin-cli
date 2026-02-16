#!/bin/bash
set -e

# =============================================================================
# brin Cloud Run Deployment Script
# =============================================================================

PROJECT_ID="superagent-410019"
REGION="us-central1"
REPO="brin"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log() { echo -e "${GREEN}[brin]${NC} $1" >&2; }
warn() { echo -e "${YELLOW}[brin]${NC} $1" >&2; }
error() { echo -e "${RED}[brin]${NC} $1" >&2; exit 1; }

# =============================================================================
# Load Environment Variables
# =============================================================================

ENV_FILE=".env.production"
if [ -f "$ENV_FILE" ]; then
    log "Loading environment variables from $ENV_FILE..."
    set -a
    source "$ENV_FILE"
    set +a
else
    warn "No $ENV_FILE found. Using environment variables."
fi

# =============================================================================
# Prerequisites Check
# =============================================================================

log "Checking prerequisites..."

if ! command -v gcloud &> /dev/null; then
    error "gcloud CLI not found. Install from https://cloud.google.com/sdk"
fi

# Set project
gcloud config set project $PROJECT_ID

# Enable required APIs
log "Enabling required APIs..."
gcloud services enable \
    cloudbuild.googleapis.com \
    run.googleapis.com \
    artifactregistry.googleapis.com \
    secretmanager.googleapis.com \
    --quiet

# Create Artifact Registry repository if it doesn't exist
log "Setting up Artifact Registry..."
gcloud artifacts repositories describe $REPO --location=$REGION 2>/dev/null || \
    gcloud artifacts repositories create $REPO \
        --repository-format=docker \
        --location=$REGION \
        --description="brin container images"

# Configure Docker auth
gcloud auth configure-docker ${REGION}-docker.pkg.dev --quiet

# =============================================================================
# Environment Variables Check
# =============================================================================

log "Checking environment variables..."

if [ -z "$DATABASE_URL" ]; then
    warn "DATABASE_URL not set. You'll need to set this in Cloud Run."
    warn "Example: postgres://user:pass@host:5432/brin"
fi

if [ -z "$REDIS_URL" ]; then
    warn "REDIS_URL not set. You'll need to set this in Cloud Run."
    warn "Example: redis://host:6379"
fi

# =============================================================================
# Build and Push Images
# =============================================================================

IMAGE_BASE="${REGION}-docker.pkg.dev/${PROJECT_ID}/${REPO}"
TAG=$(git rev-parse --short HEAD 2>/dev/null || echo "latest")

build_and_push() {
    local service=$1
    local dockerfile=$2
    local image="${IMAGE_BASE}/${service}:${TAG}"
    
    log "Building ${service} for linux/amd64..."
    docker build --platform linux/amd64 -t $image -f $dockerfile . >&2
    
    log "Pushing ${service}..."
    docker push $image >&2
    
    echo $image
}

log "Building and pushing images (this may take a few minutes)..."

API_IMAGE=$(build_and_push "api" "Dockerfile.api")
WORKER_IMAGE=$(build_and_push "worker" "Dockerfile.worker")
WATCHER_IMAGE=$(build_and_push "watcher" "Dockerfile.watcher")
CVE_IMAGE=$(build_and_push "cve" "Dockerfile.cve")

# =============================================================================
# Deploy to Cloud Run
# =============================================================================

# Create temp YAML file for env vars (handles special characters properly)
ENV_YAML=$(mktemp)
trap "rm -f $ENV_YAML" EXIT

echo "# Generated env vars" > "$ENV_YAML"
var_count=0
if [ -f "$ENV_FILE" ]; then
    while IFS= read -r line || [ -n "$line" ]; do
        # Skip empty lines and comments
        [[ -z "$line" || "$line" =~ ^[[:space:]]*# ]] && continue
        
        # Extract key and value
        key="${line%%=*}"
        value="${line#*=}"
        
        # Skip if value is empty
        [ -z "$value" ] && continue
        
        # Write to YAML (quote value to handle special chars)
        echo "${key}: \"${value}\"" >> "$ENV_YAML"
        ((var_count++))
    done < "$ENV_FILE"
    log "Loaded $var_count environment variables from $ENV_FILE"
fi

# Deploy API (public, serves HTTP traffic)
# min-instances=1 to avoid cold starts for better UX
log "Deploying API..."
gcloud run deploy brin-api \
    --image $API_IMAGE \
    --region $REGION \
    --platform managed \
    --allow-unauthenticated \
    --port 3000 \
    --memory 512Mi \
    --cpu 1 \
    --min-instances 1 \
    --max-instances 10 \
    --env-vars-file "$ENV_YAML" \
    --quiet

# Deploy Worker (internal, processes scan jobs)
# Note: --no-cpu-throttling requires minimum 512Mi memory
log "Deploying Worker..."
gcloud run deploy brin-worker \
    --image $WORKER_IMAGE \
    --region $REGION \
    --platform managed \
    --no-allow-unauthenticated \
    --memory 1Gi \
    --cpu 2 \
    --min-instances 0 \
    --max-instances 5 \
    --env-vars-file "$ENV_YAML" \
    --no-cpu-throttling \
    --quiet

# Deploy Watcher (internal, monitors npm registry)
# Note: --no-cpu-throttling requires minimum 512Mi memory
log "Deploying Watcher..."
gcloud run deploy brin-watcher \
    --image $WATCHER_IMAGE \
    --region $REGION \
    --platform managed \
    --no-allow-unauthenticated \
    --memory 512Mi \
    --cpu 1 \
    --min-instances 0 \
    --max-instances 1 \
    --env-vars-file "$ENV_YAML" \
    --no-cpu-throttling \
    --quiet

# Deploy CVE Enricher (internal, fetches CVE data)
# Note: --no-cpu-throttling requires minimum 512Mi memory
log "Deploying CVE Enricher..."
gcloud run deploy brin-cve \
    --image $CVE_IMAGE \
    --region $REGION \
    --platform managed \
    --no-allow-unauthenticated \
    --memory 512Mi \
    --cpu 1 \
    --min-instances 0 \
    --max-instances 1 \
    --env-vars-file "$ENV_YAML" \
    --no-cpu-throttling \
    --quiet

# =============================================================================
# Get Service URLs
# =============================================================================

log "Deployment complete!"
echo ""
echo "======================================"
echo "Service URLs:"
echo "======================================"

API_URL=$(gcloud run services describe brin-api --region $REGION --format 'value(status.url)')
echo "API:     $API_URL"
echo ""
echo "Test with:"
echo "  curl ${API_URL}/health"
echo ""

# =============================================================================
# Important Notes
# =============================================================================

warn "IMPORTANT: Make sure to set these environment variables in Cloud Run Console:"
echo "  - DATABASE_URL: Your PostgreSQL connection string"
echo "  - REDIS_URL: Your Redis connection string"
echo "  - ANTHROPIC_API_KEY: For agentic threat analysis (optional)"
echo ""
echo "You can set them with:"
echo "  gcloud run services update brin-api --region $REGION --set-env-vars DATABASE_URL=...,REDIS_URL=..."
echo ""
