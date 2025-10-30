#!/bin/bash
# ======================================================
# 🚀 Auto-Deploy Script: GCP Security Audit Cloud Function + Cloud Scheduler
# ======================================================

set -e

# --- CONFIGURATION ---
PROJECT_ID=$(gcloud config get-value project 2>/dev/null)
REGION="asia-south1"
FUNCTION_NAME="security_audit_005"
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
  --region=$REGION \
  --format='value(serviceConfig.uri)')

if [[ -z "$FUNCTION_URL" ]]; then
  echo "❌ Error: Unable to fetch Cloud Function URL."
  exit 1
fi

echo "✅ Cloud Function URL: $FUNCTION_URL"

echo ""
echo "⏰ Cloud Scheduler Setup"
echo "-----------------------------------------"
echo "Choose schedule type:"
echo " 1) Every N minutes"
echo " 2) Every N hours"
echo " 3) Daily at specific hour"
echo " 4) Weekly on a specific day and time"
echo " 5) Monthly on specific date and time"
read -p "Select option (1-5): " opt

case "$opt" in
  1)
    read -p "Run every N minutes (e.g., 5): " num
    CRON_SCHEDULE="*/$num * * * *"
    ;;

  2)
    read -p "Run every N hours (e.g., 3): " num
    CRON_SCHEDULE="0 */$num * * *"
    ;;

  3)
    read -p "Enter hour of day (0–23): " hour
    read -p "Enter minute (0–59) [default 0]: " min
    min=${min:-0}
    CRON_SCHEDULE="$min $hour * * *"
    ;;

  4)
    echo "Enter day of week:"
    echo " 0=Sunday, 1=Mon ... 6=Sat"
    read -p "Select day (0-6): " dow
    read -p "Enter hour (0–23): " hour
    read -p "Enter minute (0–59) [default 0]: " min
    min=${min:-0}
    CRON_SCHEDULE="$min $hour * * $dow"
    ;;

  5)
    read -p "Enter date of month (1–31): " dom
    read -p "Enter hour (0–23): " hour
    read -p "Enter minute (0–59) [default 0]: " min
    min=${min:-0}
    CRON_SCHEDULE="$min $hour $dom * *"
    ;;

  *)
    echo "❌ Invalid choice. Using default: every 2 minutes"
    CRON_SCHEDULE="*/2 * * * *"
    ;;
esac

echo "✅ Using Cron Schedule: $CRON_SCHEDULE"
echo ""

# --- Step 5: Create or Update Cloud Scheduler Job ---
# --- Step 5: Create or Update Cloud Scheduler Job ---
echo "⏰ Setting up Cloud Scheduler job: $SCHEDULER_JOB_NAME ..."

if gcloud scheduler jobs describe $SCHEDULER_JOB_NAME --location=$REGION >/dev/null 2>&1; then
  echo "🔄 Job exists. Updating..."
  gcloud scheduler jobs update http $SCHEDULER_JOB_NAME \
    --schedule="$CRON_SCHEDULE" \
    --time-zone="Asia/Kolkata" \
    --uri="$FUNCTION_URL" \
    --http-method=GET \
    --location=$REGION \
    --description="Triggers Security Audit Function"
else
  echo "🆕 Creating new job..."
  gcloud scheduler jobs create http $SCHEDULER_JOB_NAME \
    --schedule="$CRON_SCHEDULE" \
    --time-zone="Asia/Kolkata" \
    --uri="$FUNCTION_URL" \
    --http-method=GET \
    --location=$REGION \
    --description="Triggers Security Audit Function"
fi

echo "✅ Cloud Scheduler setup complete!"



# --- Step 6: Force Run Scheduler Job ---
echo "🚀 Triggering the Cloud Scheduler job immediately..."
gcloud scheduler jobs run $SCHEDULER_JOB_NAME --location=$REGION

echo "✅ Cloud Scheduler job executed successfully!"
