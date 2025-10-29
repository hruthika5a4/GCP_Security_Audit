#!/bin/bash
# ======================================================
# 🚀 Auto-Deploy Script: GCP Security Audit Cloud Function + Cloud Scheduler
# ======================================================

set -e

# --- CONFIGURATION ---
PROJECT_ID=$(gcloud config get-value project 2>/dev/null)
REGION="asia-south1"
FUNCTION_NAME="security_audit_001"
ENTRY_POINT="security_audit"
RUNTIME="python312"
SCHEDULER_JOB_NAME="auto-audit-trigger"

echo "-----------------------------------------"
echo "🔹 Starting Security Audit Cloud Function Setup"
echo "-----------------------------------------"

# --- Step 1: Verify Project ---
if [[ -z "$PROJECT_ID" ]]; then
  echo "❌ No active project configured."
  echo "➡️  Run: gcloud config set project <PROJECT_ID>"
  exit 1
fi
echo "✅ Using Project: $PROJECT_ID"

# --- Step 2: Enable Required APIs ---
echo "🔄 Enabling necessary APIs..."
gcloud services enable \
  cloudfunctions.googleapis.com \
  cloudscheduler.googleapis.com \
  cloudbuild.googleapis.com \
  artifactregistry.googleapis.com \
  iam.googleapis.com

# --- Step 3: Deploy Cloud Function ---
echo "🚀 Deploying Cloud Function: $FUNCTION_NAME ..."
gcloud functions deploy $FUNCTION_NAME \
  --runtime $RUNTIME \
  --trigger-http \
  --allow-unauthenticated \
  --region=$REGION \
  --entry-point=$ENTRY_POINT

# --- Step 4: Fetch Function URL ---
echo "🌐 Fetching function URL..."
FUNCTION_URL=$(gcloud functions describe $FUNCTION_NAME \
  --region $REGION \
  --format 'value(httpsTrigger.url)')

if [[ -z "$FUNCTION_URL" ]]; then
  echo "❌ Error: Unable to fetch Cloud Function URL."
  exit 1
fi

echo "✅ Cloud Function URL: $FUNCTION_URL"

# --- Step 5: Create or Update Cloud Scheduler Job ---
echo "⏰ Setting up Cloud Scheduler job: $SCHEDULER_JOB_NAME ..."

if gcloud scheduler jobs describe $SCHEDULER_JOB_NAME --location=$REGION >/dev/null 2>&1; then
  echo "🔄 Job exists. Updating..."
  gcloud scheduler jobs update http $SCHEDULER_JOB_NAME \
    --schedule="*/2 * * * *" \
    --time-zone="Asia/Kolkata" \
    --uri="$FUNCTION_URL" \
    --http-method=GET \
    --location=$REGION \
    --description="Triggers Security Audit Function every 2 minutes"
else
  echo "🆕 Creating new job..."
  gcloud scheduler jobs create http $SCHEDULER_JOB_NAME \
    --schedule="*/2 * * * *" \
    --time-zone="Asia/Kolkata" \
    --uri="$FUNCTION_URL" \
    --http-method=GET \
    --location=$REGION \
    --description="Triggers Security Audit Function every 2 minutes"
fi

echo "✅ Cloud Scheduler setup complete!"
