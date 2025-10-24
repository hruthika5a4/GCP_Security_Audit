#!/bin/bash
# ======================================================
# 🚀 Auto-Deploy Script: GCP Security Audit Cloud Function
# ======================================================

set -e

# --- CONFIGURATION ---
PROJECT_ID=$(gcloud config get-value project 2>/dev/null)
REGION="asia-south1"
FUNCTION_NAME="security_audit_2"
ENTRY_POINT="GCP_Security_Audit"
RUNTIME="python311"

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
  cloudbuild.googleapis.com \
  artifactregistry.googleapis.com \
  iam.googleapis.com

# --- Step 3: Install Dependencies ---
if [[ -f requirements.txt ]]; then
  echo "📦 Installing dependencies..."
  pip install -r requirements.txt -t lib/
fi

# --- Step 4: Deploy Function ---
echo "🚀 Deploying Cloud Function..."
gcloud functions deploy security_audit_122 \
  --runtime python312 \
  --trigger-http \
  --allow-unauthenticated \
  --region=asia-south1 \
  --entry-point=security_audit


# --- Step 5: Get Function URL ---
URL=$(gcloud functions describe $FUNCTION_NAME --region=$REGION --format='value(httpsTrigger.url)')
echo "✅ Deployment Complete!"
echo "🌐 Function URL: $URL"
echo "-----------------------------------------"
