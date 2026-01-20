# =============================================================================
# CloudGuard - AWS Security Compliance Scanner
# Terraform Outputs
# =============================================================================

# -----------------------------------------------------------------------------
# Lambda Function ARNs
# -----------------------------------------------------------------------------
output "orchestrator_lambda_arn" {
  description = "ARN of the orchestrator Lambda function"
  value       = aws_lambda_function.orchestrator.arn
}

output "check_s3_lambda_arn" {
  description = "ARN of the S3 check Lambda function"
  value       = aws_lambda_function.check_s3.arn
}

output "check_iam_lambda_arn" {
  description = "ARN of the IAM check Lambda function"
  value       = aws_lambda_function.check_iam.arn
}

output "check_ec2_lambda_arn" {
  description = "ARN of the EC2 check Lambda function"
  value       = aws_lambda_function.check_ec2.arn
}

output "check_vpc_lambda_arn" {
  description = "ARN of the VPC check Lambda function"
  value       = aws_lambda_function.check_vpc.arn
}

output "check_cloudtrail_lambda_arn" {
  description = "ARN of the CloudTrail check Lambda function"
  value       = aws_lambda_function.check_cloudtrail.arn
}

output "report_generator_lambda_arn" {
  description = "ARN of the report generator Lambda function"
  value       = aws_lambda_function.report_generator.arn
}

# -----------------------------------------------------------------------------
# DynamoDB Tables
# -----------------------------------------------------------------------------
output "findings_table_name" {
  description = "Name of the DynamoDB findings table"
  value       = aws_dynamodb_table.findings.name
}

output "findings_table_arn" {
  description = "ARN of the DynamoDB findings table"
  value       = aws_dynamodb_table.findings.arn
}

output "scan_history_table_name" {
  description = "Name of the DynamoDB scan history table"
  value       = aws_dynamodb_table.scan_history.name
}

# -----------------------------------------------------------------------------
# S3 Buckets
# -----------------------------------------------------------------------------
output "reports_bucket_name" {
  description = "Name of the S3 bucket for compliance reports"
  value       = aws_s3_bucket.reports.id
}

output "reports_bucket_arn" {
  description = "ARN of the S3 bucket for compliance reports"
  value       = aws_s3_bucket.reports.arn
}

output "lambda_code_bucket_name" {
  description = "Name of the S3 bucket for Lambda code"
  value       = aws_s3_bucket.lambda_code.id
}

# -----------------------------------------------------------------------------
# SNS Topics
# -----------------------------------------------------------------------------
output "alerts_topic_arn" {
  description = "ARN of the SNS topic for critical alerts"
  value       = aws_sns_topic.alerts.arn
}

output "daily_summary_topic_arn" {
  description = "ARN of the SNS topic for daily summaries"
  value       = aws_sns_topic.daily_summary.arn
}

# -----------------------------------------------------------------------------
# EventBridge
# -----------------------------------------------------------------------------
output "daily_scan_rule_arn" {
  description = "ARN of the EventBridge rule for daily scans"
  value       = aws_cloudwatch_event_rule.daily_scan.arn
}

# -----------------------------------------------------------------------------
# IAM Roles
# -----------------------------------------------------------------------------
output "scanner_role_arn" {
  description = "ARN of the scanner Lambda execution role"
  value       = aws_iam_role.scanner_lambda_role.arn
}

output "report_generator_role_arn" {
  description = "ARN of the report generator Lambda execution role"
  value       = aws_iam_role.report_generator_role.arn
}

# -----------------------------------------------------------------------------
# Useful Information
# -----------------------------------------------------------------------------
output "reports_url" {
  description = "Base URL for accessing compliance reports"
  value       = "https://${aws_s3_bucket.reports.id}.s3.${local.region}.amazonaws.com/reports/"
}

output "scan_schedule" {
  description = "Schedule expression for daily scans"
  value       = var.schedule_expression
}
