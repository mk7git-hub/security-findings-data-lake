terraform {
  required_version = ">= 1.6"
  required_providers {
    aws     = { source = "hashicorp/aws", version = "~> 5.70" }
    archive = { source = "hashicorp/archive", version = "~> 2.6" }
  }
}

provider "aws" {
  region = var.region
  default_tags {
    tags = { Project = "security-findings-data-lake", ManagedBy = "terraform", Owner = var.owner }
  }
}

data "aws_caller_identity" "me" {}
data "aws_region" "current" {}

locals {
  name    = "findings-lake"
  account = data.aws_caller_identity.me.account_id
  region  = data.aws_region.current.name
}

resource "aws_kms_key" "lake" {
  description         = "${local.name} encryption"
  enable_key_rotation = true
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Sid = "Root", Effect = "Allow", Principal = { AWS = "arn:aws:iam::${local.account}:root" }, Action = "kms:*", Resource = "*" },
      { Sid = "Logs", Effect = "Allow", Principal = { Service = "logs.${local.region}.amazonaws.com" },
      Action = ["kms:Encrypt*", "kms:Decrypt*", "kms:GenerateDataKey*", "kms:Describe*"], Resource = "*" }
    ]
  })
  #checkov:skip=CKV_AWS_109:Standard key policy root statement
  #checkov:skip=CKV_AWS_111:Standard key policy root statement
  #checkov:skip=CKV_AWS_356:Key policies use Resource "*" (the key itself)
}

# ---------- Storage ----------
resource "aws_s3_bucket" "lake" {
  bucket        = "${local.name}-${local.account}"
  force_destroy = true
  #checkov:skip=CKV_AWS_144:Cross-region replication not needed for a lab
  #checkov:skip=CKV_AWS_18:Access logging would add a second bucket; CloudTrail data events cover access
  #checkov:skip=CKV2_AWS_62:No event notifications needed
}

resource "aws_s3_bucket" "athena" {
  bucket        = "${local.name}-athena-results-${local.account}"
  force_destroy = true
  #checkov:skip=CKV_AWS_144:Query results are disposable
  #checkov:skip=CKV_AWS_18:Query results are disposable
  #checkov:skip=CKV2_AWS_62:No event notifications needed
}

resource "aws_s3_bucket_versioning" "v" {
  for_each = { lake = aws_s3_bucket.lake.id, athena = aws_s3_bucket.athena.id }
  bucket   = each.value
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "e" {
  for_each = { lake = aws_s3_bucket.lake.id, athena = aws_s3_bucket.athena.id }
  bucket   = each.value
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.lake.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "b" {
  for_each                = { lake = aws_s3_bucket.lake.id, athena = aws_s3_bucket.athena.id }
  bucket                  = each.value
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "l" {
  for_each = { lake = { id = aws_s3_bucket.lake.id, days = 400 }, athena = { id = aws_s3_bucket.athena.id, days = 7 } }
  bucket   = each.value.id
  rule {
    id     = "expire"
    status = "Enabled"
    filter {}
    expiration { days = each.value.days }
    noncurrent_version_expiration { noncurrent_days = 7 }
    abort_incomplete_multipart_upload { days_after_initiation = 1 }
  }
}

# ---------- Catalog ----------
resource "aws_glue_catalog_database" "db" {
  name = "security_findings"
}

resource "aws_glue_catalog_table" "findings" {
  name          = "findings"
  database_name = aws_glue_catalog_database.db.name
  table_type    = "EXTERNAL_TABLE"
  parameters = {
    "classification"            = "parquet"
    "projection.enabled"        = "true"
    "projection.source.type"    = "enum"
    "projection.source.values"  = "guardduty,securityhub"
    "projection.dt.type"        = "date"
    "projection.dt.format"      = "yyyy-MM-dd"
    "projection.dt.range"       = "2026-01-01,NOW"
    "storage.location.template" = "s3://${aws_s3_bucket.lake.bucket}/findings/source=$${source}/dt=$${dt}/"
  }

  partition_keys {
    name = "source"
    type = "string"
  }
  partition_keys {
    name = "dt"
    type = "string"
  }

  storage_descriptor {
    location      = "s3://${aws_s3_bucket.lake.bucket}/findings/"
    input_format  = "org.apache.hadoop.hive.ql.io.parquet.MapredParquetInputFormat"
    output_format = "org.apache.hadoop.hive.ql.io.parquet.MapredParquetOutputFormat"
    ser_de_info {
      serialization_library = "org.apache.hadoop.hive.ql.io.parquet.serde.ParquetHiveSerDe"
    }
    dynamic "columns" {
      for_each = [
        ["finding_id", "string"], ["account_id", "string"], ["region", "string"], ["type", "string"],
        ["title", "string"], ["severity_label", "string"], ["severity_rank", "int"], ["resource_type", "string"],
        ["resource_id", "string"], ["control_id", "string"], ["compliance_status", "string"],
        ["workflow_status", "string"], ["first_seen", "string"], ["last_seen", "string"]
      ]
      content {
        name = columns.value[0]
        type = columns.value[1]
      }
    }
  }
}

# ---------- Transform Lambda ----------
data "archive_file" "zip" {
  type        = "zip"
  source_file = "${path.module}/../src/transform.py"
  output_path = "${path.module}/build/transform.zip"
}

resource "aws_iam_role" "fn" {
  name = "${local.name}-transform"
  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Principal = { Service = "lambda.amazonaws.com" }, Action = "sts:AssumeRole" }]
  })
}

resource "aws_cloudwatch_log_group" "fn" {
  name              = "/aws/lambda/${local.name}-transform"
  retention_in_days = 365
  kms_key_id        = aws_kms_key.lake.arn
}

resource "aws_iam_role_policy" "fn" {
  name = "logs"
  role = aws_iam_role.fn.id
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = ["logs:CreateLogStream", "logs:PutLogEvents"], Resource = "${aws_cloudwatch_log_group.fn.arn}:*" }]
  })
}

resource "aws_lambda_function" "transform" {
  function_name                  = "${local.name}-transform"
  role                           = aws_iam_role.fn.arn
  runtime                        = "python3.12"
  handler                        = "transform.handler"
  filename                       = data.archive_file.zip.output_path
  source_code_hash               = data.archive_file.zip.output_base64sha256
  timeout                        = 60
  memory_size                    = 256
  reserved_concurrent_executions = var.reserved_concurrency
  #checkov:skip=CKV_AWS_115:New accounts have a 10-concurrency limit and AWS keeps 10 unreserved; set var.reserved_concurrency once the limit is raised
  kms_key_arn = aws_kms_key.lake.arn
  tracing_config { mode = "PassThrough" }
  #checkov:skip=CKV_AWS_117:Pure transform, no network access needed
  #checkov:skip=CKV_AWS_116:Firehose retries and writes failures to the error prefix; a DLQ would duplicate that
  #checkov:skip=CKV_AWS_272:Code signing out of scope for a lab
  #checkov:skip=CKV_AWS_50:X-Ray not needed for a pure transform
  #checkov:skip=CKV_AWS_173:Environment has no variables to encrypt
  depends_on = [aws_cloudwatch_log_group.fn]
}

# ---------- Firehose ----------
resource "aws_iam_role" "firehose" {
  name = "${local.name}-firehose"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow", Principal = { Service = "firehose.amazonaws.com" }, Action = "sts:AssumeRole",
    Condition = { StringEquals = { "sts:ExternalId" = local.account } } }]
  })
}

resource "aws_iam_role_policy" "firehose" {
  name = "deliver"
  role = aws_iam_role.firehose.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Effect = "Allow", Action = ["s3:PutObject", "s3:GetBucketLocation", "s3:ListBucket", "s3:AbortMultipartUpload", "s3:ListBucketMultipartUploads"],
      Resource = [aws_s3_bucket.lake.arn, "${aws_s3_bucket.lake.arn}/*"] },
      { Effect = "Allow", Action = ["kms:GenerateDataKey", "kms:Decrypt"], Resource = aws_kms_key.lake.arn },
      { Effect = "Allow", Action = ["lambda:InvokeFunction", "lambda:GetFunctionConfiguration"], Resource = "${aws_lambda_function.transform.arn}*" },
      { Effect = "Allow", Action = ["glue:GetTable", "glue:GetTableVersion", "glue:GetTableVersions"],
        Resource = ["arn:aws:glue:${local.region}:${local.account}:catalog", "arn:aws:glue:${local.region}:${local.account}:database/${aws_glue_catalog_database.db.name}",
      "arn:aws:glue:${local.region}:${local.account}:table/${aws_glue_catalog_database.db.name}/${aws_glue_catalog_table.findings.name}"] },
      { Effect = "Allow", Action = ["logs:PutLogEvents"], Resource = "${aws_cloudwatch_log_group.firehose.arn}:*" }
    ]
  })
}

resource "aws_cloudwatch_log_group" "firehose" {
  name              = "/aws/kinesisfirehose/${local.name}"
  retention_in_days = 365
  kms_key_id        = aws_kms_key.lake.arn
}

resource "aws_cloudwatch_log_stream" "firehose" {
  name           = "delivery"
  log_group_name = aws_cloudwatch_log_group.firehose.name
}

resource "aws_kinesis_firehose_delivery_stream" "findings" {
  name        = local.name
  destination = "extended_s3"

  server_side_encryption {
    enabled  = true
    key_type = "CUSTOMER_MANAGED_CMK"
    key_arn  = aws_kms_key.lake.arn
  }

  extended_s3_configuration {
    role_arn            = aws_iam_role.firehose.arn
    bucket_arn          = aws_s3_bucket.lake.arn
    kms_key_arn         = aws_kms_key.lake.arn
    buffering_size      = 64
    buffering_interval  = 60
    prefix              = "findings/source=!{partitionKeyFromLambda:source}/dt=!{timestamp:yyyy-MM-dd}/"
    error_output_prefix = "errors/!{firehose:error-output-type}/dt=!{timestamp:yyyy-MM-dd}/"

    dynamic_partitioning_configuration { enabled = true }

    processing_configuration {
      enabled = true
      processors {
        type = "Lambda"
        parameters {
          parameter_name  = "LambdaArn"
          parameter_value = "${aws_lambda_function.transform.arn}:$LATEST"
        }
      }
    }

    data_format_conversion_configuration {
      input_format_configuration {
        deserializer {
          open_x_json_ser_de {}
        }
      }
      output_format_configuration {
        serializer {
          parquet_ser_de { compression = "SNAPPY" }
        }
      }
      schema_configuration {
        database_name = aws_glue_catalog_database.db.name
        table_name    = aws_glue_catalog_table.findings.name
        role_arn      = aws_iam_role.firehose.arn
      }
    }

    cloudwatch_logging_options {
      enabled         = true
      log_group_name  = aws_cloudwatch_log_group.firehose.name
      log_stream_name = aws_cloudwatch_log_stream.firehose.name
    }
  }
}

# ---------- EventBridge -> Firehose ----------
resource "aws_cloudwatch_event_rule" "findings" {
  name        = "${local.name}-findings"
  description = "All GuardDuty and Security Hub findings"
  event_pattern = jsonencode({
    source      = ["aws.guardduty", "aws.securityhub"]
    detail-type = ["GuardDuty Finding", "Security Hub Findings - Imported"]
  })
}

resource "aws_iam_role" "events" {
  name = "${local.name}-events"
  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Principal = { Service = "events.amazonaws.com" }, Action = "sts:AssumeRole" }]
  })
}

resource "aws_iam_role_policy" "events" {
  name = "put"
  role = aws_iam_role.events.id
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = ["firehose:PutRecord", "firehose:PutRecordBatch"], Resource = aws_kinesis_firehose_delivery_stream.findings.arn }]
  })
}

resource "aws_cloudwatch_event_target" "firehose" {
  rule     = aws_cloudwatch_event_rule.findings.name
  arn      = aws_kinesis_firehose_delivery_stream.findings.arn
  role_arn = aws_iam_role.events.arn
}

# ---------- Athena ----------
resource "aws_athena_workgroup" "wg" {
  name          = local.name
  force_destroy = true
  configuration {
    enforce_workgroup_configuration    = true
    publish_cloudwatch_metrics_enabled = true
    bytes_scanned_cutoff_per_query     = 1073741824 # 1 GB cap per query keeps cost near zero
    result_configuration {
      output_location = "s3://${aws_s3_bucket.athena.bucket}/results/"
      encryption_configuration {
        encryption_option = "SSE_KMS"
        kms_key_arn       = aws_kms_key.lake.arn
      }
    }
  }
}

resource "aws_athena_named_query" "q" {
  for_each  = fileset("${path.module}/../queries", "*.sql")
  name      = trimsuffix(each.value, ".sql")
  workgroup = aws_athena_workgroup.wg.id
  database  = aws_glue_catalog_database.db.name
  query     = file("${path.module}/../queries/${each.value}")
}
