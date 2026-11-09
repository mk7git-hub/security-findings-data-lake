# Design decisions: Security Findings Data Lake

### 1. EventBridge → Firehose instead of Lambda writing to S3
- **Why:** Firehose handles batching, retries, compression, Parquet conversion and error output; less code to own.

### 2. Firehose's built-in Parquet conversion with a Glue schema
- **Alternative:** a Lambda with pyarrow or AWS SDK for pandas.
- **Why:** no heavy dependency layer; schema lives in the Glue table.
- **Constraint:** one JSON object per record, which is why multi-finding events go to the error prefix.

### 3. Lambda transform to one schema
- **Why:** GuardDuty and Security Hub differ (numeric vs label severity, different resource shapes). One schema makes cross-source queries simple.

### 4. Partition by source and day, with partition projection
- **Why:** queries filter by date and source, so Athena reads only those folders. Projection computes partitions from the path template, so no Glue crawler or `MSCK REPAIR`.

### 5. Parquet with Snappy
- **Why:** columnar plus compressed means Athena scans far less data than JSON; cost is per TB scanned.

### 6. Athena workgroup with enforced settings and a 1 GB per-query cap
- **Why:** results encrypted to a fixed location, and a runaway query cannot run up a bill.

### 7. Lifecycle: findings 400 days, Athena results 7 days
- **Why:** a year plus margin for audits; query results are disposable.

### 8. Customer-managed KMS key for bucket, logs and Firehose
- **Why:** key access is auditable and revocable; one key keeps the lab simple (production might separate keys by data class).
