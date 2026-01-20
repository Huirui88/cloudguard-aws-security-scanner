# =============================================================================
# CloudGuard - AWS Security Compliance Scanner
# Lambda Functions
# =============================================================================

# -----------------------------------------------------------------------------
# Package Lambda Functions
# -----------------------------------------------------------------------------

# Orchestrator Lambda Package
data "archive_file" "orchestrator" {
  type        = "zip"
  source_dir  = "${path.module}/../src/orchestrator"
  output_path = "${path.module}/.terraform/tmp/orchestrator.zip"
}

# S3 Security Check Lambda Package
data "archive_file" "check_s3" {
  type        = "zip"
  source_dir  = "${path.module}/../src/checks/s3"
  output_path = "${path.module}/.terraform/tmp/check_s3.zip"
}

# IAM Security Check Lambda Package
data "archive_file" "check_iam" {
  type        = "zip"
  source_dir  = "${path.module}/../src/checks/iam"
  output_path = "${path.module}/.terraform/tmp/check_iam.zip"
}

# EC2 Security Check Lambda Package
data "archive_file" "check_ec2" {
  type        = "zip"
  source_dir  = "${path.module}/../src/checks/ec2"
  output_path = "${path.module}/.terraform/tmp/check_ec2.zip"
}

# VPC Security Check Lambda Package
data "archive_file" "check_vpc" {
  type        = "zip"
  source_dir  = "${path.module}/../src/checks/vpc"
  output_path = "${path.module}/.terraform/tmp/check_vpc.zip"
}

# CloudTrail Check Lambda Package
data "archive_file" "check_cloudtrail" {
  type        = "zip"
  source_dir  = "${path.module}/../src/checks/cloudtrail"
  output_path = "${path.module}/.terraform/tmp/check_cloudtrail.zip"
}

# Report Generator Lambda Package
data "archive_file" "report_generator" {
  type        = "zip"
  source_dir  = "${path.module}/../src/report_generator"
  output_path = "${path.module}/.terraform/tmp/report_generator.zip"
}

# -----------------------------------------------------------------------------
# Lambda Functions
# -----------------------------------------------------------------------------

# Orchestrator Lambda
resource "aws_lambda_function" "orchestrator" {
  function_name = "${local.name_prefix}-orchestrator-${local.random_suffix}"
  description   = "Orchestrates security compliance scans"
  role          = aws_iam_role.scanner_lambda_role.arn
  handler       = "lambda_function.lambda_handler"
  runtime       = "python3.12"
  timeout       = var.lambda_timeout_orchestrator
  memory_size   = var.lambda_memory_orchestrator

  filename         = data.archive_file.orchestrator.output_path
  source_code_hash = data.archive_file.orchestrator.output_base64sha256

  environment {
    variables = {
      FINDINGS_TABLE     = aws_dynamodb_table.findings.name
      SCAN_HISTORY_TABLE = aws_dynamodb_table.scan_history.name
      CHECK_S3_FUNCTION  = aws_lambda_function.check_s3.function_name
      CHECK_IAM_FUNCTION = aws_lambda_function.check_iam.function_name
      CHECK_EC2_FUNCTION = aws_lambda_function.check_ec2.function_name
      CHECK_VPC_FUNCTION = aws_lambda_function.check_vpc.function_name
      CHECK_CLOUDTRAIL_FUNCTION = aws_lambda_function.check_cloudtrail.function_name
      REPORT_FUNCTION    = aws_lambda_function.report_generator.function_name
    }
  }

  tags = {
    Name = "${local.name_prefix}-orchestrator"
  }
}

# S3 Security Check Lambda
resource "aws_lambda_function" "check_s3" {
  function_name = "${local.name_prefix}-check-s3-${local.random_suffix}"
  description   = "Scans S3 buckets for security compliance"
  role          = aws_iam_role.scanner_lambda_role.arn
  handler       = "lambda_function.lambda_handler"
  runtime       = "python3.12"
  timeout       = var.lambda_timeout_checks
  memory_size   = var.lambda_memory_checks

  filename         = data.archive_file.check_s3.output_path
  source_code_hash = data.archive_file.check_s3.output_base64sha256

  environment {
    variables = {
      FINDINGS_TABLE = aws_dynamodb_table.findings.name
    }
  }

  tags = {
    Name = "${local.name_prefix}-check-s3"
  }
}

# IAM Security Check Lambda
resource "aws_lambda_function" "check_iam" {
  function_name = "${local.name_prefix}-check-iam-${local.random_suffix}"
  description   = "Scans IAM configuration for security compliance"
  role          = aws_iam_role.scanner_lambda_role.arn
  handler       = "lambda_function.lambda_handler"
  runtime       = "python3.12"
  timeout       = var.lambda_timeout_checks
  memory_size   = var.lambda_memory_checks

  filename         = data.archive_file.check_iam.output_path
  source_code_hash = data.archive_file.check_iam.output_base64sha256

  environment {
    variables = {
      FINDINGS_TABLE = aws_dynamodb_table.findings.name
    }
  }

  tags = {
    Name = "${local.name_prefix}-check-iam"
  }
}

# EC2 Security Check Lambda
resource "aws_lambda_function" "check_ec2" {
  function_name = "${local.name_prefix}-check-ec2-${local.random_suffix}"
  description   = "Scans EC2 instances and security groups for compliance"
  role          = aws_iam_role.scanner_lambda_role.arn
  handler       = "lambda_function.lambda_handler"
  runtime       = "python3.12"
  timeout       = var.lambda_timeout_checks
  memory_size   = var.lambda_memory_checks

  filename         = data.archive_file.check_ec2.output_path
  source_code_hash = data.archive_file.check_ec2.output_base64sha256

  environment {
    variables = {
      FINDINGS_TABLE = aws_dynamodb_table.findings.name
    }
  }

  tags = {
    Name = "${local.name_prefix}-check-ec2"
  }
}

# VPC Security Check Lambda
resource "aws_lambda_function" "check_vpc" {
  function_name = "${local.name_prefix}-check-vpc-${local.random_suffix}"
  description   = "Scans VPC configuration for security compliance"
  role          = aws_iam_role.scanner_lambda_role.arn
  handler       = "lambda_function.lambda_handler"
  runtime       = "python3.12"
  timeout       = var.lambda_timeout_checks
  memory_size   = var.lambda_memory_checks

  filename         = data.archive_file.check_vpc.output_path
  source_code_hash = data.archive_file.check_vpc.output_base64sha256

  environment {
    variables = {
      FINDINGS_TABLE = aws_dynamodb_table.findings.name
    }
  }

  tags = {
    Name = "${local.name_prefix}-check-vpc"
  }
}

# CloudTrail Check Lambda
resource "aws_lambda_function" "check_cloudtrail" {
  function_name = "${local.name_prefix}-check-cloudtrail-${local.random_suffix}"
  description   = "Scans CloudTrail configuration for compliance"
  role          = aws_iam_role.scanner_lambda_role.arn
  handler       = "lambda_function.lambda_handler"
  runtime       = "python3.12"
  timeout       = var.lambda_timeout_checks
  memory_size   = var.lambda_memory_checks

  filename         = data.archive_file.check_cloudtrail.output_path
  source_code_hash = data.archive_file.check_cloudtrail.output_base64sha256

  environment {
    variables = {
      FINDINGS_TABLE = aws_dynamodb_table.findings.name
    }
  }

  tags = {
    Name = "${local.name_prefix}-check-cloudtrail"
  }
}

# Report Generator Lambda
resource "aws_lambda_function" "report_generator" {
  function_name = "${local.name_prefix}-report-generator-${local.random_suffix}"
  description   = "Generates compliance reports and sends notifications"
  role          = aws_iam_role.report_generator_role.arn
  handler       = "lambda_function.lambda_handler"
  runtime       = "python3.12"
  timeout       = var.lambda_timeout_report
  memory_size   = var.lambda_memory_report

  filename         = data.archive_file.report_generator.output_path
  source_code_hash = data.archive_file.report_generator.output_base64sha256

  environment {
    variables = {
      FINDINGS_TABLE  = aws_dynamodb_table.findings.name
      REPORT_BUCKET   = aws_s3_bucket.reports.id
      SNS_TOPIC_ARN   = aws_sns_topic.alerts.arn
      SUMMARY_TOPIC_ARN = aws_sns_topic.daily_summary.arn
    }
  }

  tags = {
    Name = "${local.name_prefix}-report-generator"
  }
}

# -----------------------------------------------------------------------------
# CloudWatch Log Groups
# -----------------------------------------------------------------------------

resource "aws_cloudwatch_log_group" "orchestrator" {
  name              = "/aws/lambda/${aws_lambda_function.orchestrator.function_name}"
  retention_in_days = 30
}

resource "aws_cloudwatch_log_group" "check_s3" {
  name              = "/aws/lambda/${aws_lambda_function.check_s3.function_name}"
  retention_in_days = 30
}

resource "aws_cloudwatch_log_group" "check_iam" {
  name              = "/aws/lambda/${aws_lambda_function.check_iam.function_name}"
  retention_in_days = 30
}

resource "aws_cloudwatch_log_group" "check_ec2" {
  name              = "/aws/lambda/${aws_lambda_function.check_ec2.function_name}"
  retention_in_days = 30
}

resource "aws_cloudwatch_log_group" "check_vpc" {
  name              = "/aws/lambda/${aws_lambda_function.check_vpc.function_name}"
  retention_in_days = 30
}

resource "aws_cloudwatch_log_group" "check_cloudtrail" {
  name              = "/aws/lambda/${aws_lambda_function.check_cloudtrail.function_name}"
  retention_in_days = 30
}

resource "aws_cloudwatch_log_group" "report_generator" {
  name              = "/aws/lambda/${aws_lambda_function.report_generator.function_name}"
  retention_in_days = 30
}
