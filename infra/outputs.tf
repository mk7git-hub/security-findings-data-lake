output "lake_bucket" { value = aws_s3_bucket.lake.bucket }
output "athena_workgroup" { value = aws_athena_workgroup.wg.name }
output "firehose_stream" { value = aws_kinesis_firehose_delivery_stream.findings.name }
