#!/usr/bin/env bash
# Generate GuardDuty sample findings, wait for Firehose to flush, then query them in Athena.
set -euo pipefail
DET=$(aws guardduty list-detectors --query 'DetectorIds[0]' --output text)
aws guardduty create-sample-findings --detector-id "$DET"
echo "Waiting 3 minutes for EventBridge -> Firehose (60s buffer) -> S3 Parquet ..."
sleep 180
QID=$(aws athena start-query-execution --work-group findings-lake \
  --query-string "SELECT source, severity_label, type FROM security_findings.findings ORDER BY severity_rank DESC LIMIT 10" \
  --query QueryExecutionId --output text)
sleep 8
aws athena get-query-results --query-execution-id "$QID" --output table
