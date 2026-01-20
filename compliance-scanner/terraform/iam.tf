# =============================================================================
# CloudGuard - AWS Security Compliance Scanner
# IAM Roles and Policies
# =============================================================================

# -----------------------------------------------------------------------------
# Lambda Execution Role - Scanner
# -----------------------------------------------------------------------------
resource "aws_iam_role" "scanner_lambda_role" {
  name = "${local.name_prefix}-scanner-role-${local.random_suffix}"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })
}

# CloudWatch Logs Policy
resource "aws_iam_role_policy" "scanner_logs" {
  name = "${local.name_prefix}-scanner-logs"
  role = aws_iam_role.scanner_lambda_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "arn:aws:logs:${local.region}:${local.account_id}:log-group:/aws/lambda/${local.name_prefix}-*"
      }
    ]
  })
}

# DynamoDB Policy
resource "aws_iam_role_policy" "scanner_dynamodb" {
  name = "${local.name_prefix}-scanner-dynamodb"
  role = aws_iam_role.scanner_lambda_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "dynamodb:PutItem",
          "dynamodb:GetItem",
          "dynamodb:UpdateItem",
          "dynamodb:Query",
          "dynamodb:Scan"
        ]
        Resource = [
          aws_dynamodb_table.findings.arn,
          aws_dynamodb_table.scan_history.arn
        ]
      }
    ]
  })
}

# Lambda Invoke Policy (for orchestrator)
resource "aws_iam_role_policy" "scanner_lambda_invoke" {
  name = "${local.name_prefix}-scanner-invoke"
  role = aws_iam_role.scanner_lambda_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "lambda:InvokeFunction"
        ]
        Resource = "arn:aws:lambda:${local.region}:${local.account_id}:function:${local.name_prefix}-*"
      }
    ]
  })
}

# S3 Read Policy (for security checks)
resource "aws_iam_role_policy" "scanner_s3_read" {
  name = "${local.name_prefix}-scanner-s3-read"
  role = aws_iam_role.scanner_lambda_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:ListAllMyBuckets",
          "s3:GetBucketLocation",
          "s3:GetBucketPolicy",
          "s3:GetBucketPolicyStatus",
          "s3:GetBucketPublicAccessBlock",
          "s3:GetBucketVersioning",
          "s3:GetBucketLogging",
          "s3:GetBucketEncryption",
          "s3:GetBucketAcl",
          "s3:GetAccountPublicAccessBlock"
        ]
        Resource = "*"
      }
    ]
  })
}

# IAM Read Policy (for security checks)
resource "aws_iam_role_policy" "scanner_iam_read" {
  name = "${local.name_prefix}-scanner-iam-read"
  role = aws_iam_role.scanner_lambda_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "iam:GetAccountPasswordPolicy",
          "iam:GetAccountSummary",
          "iam:ListUsers",
          "iam:ListAccessKeys",
          "iam:GetAccessKeyLastUsed",
          "iam:ListUserPolicies",
          "iam:ListAttachedUserPolicies",
          "iam:ListMFADevices",
          "iam:ListPolicies",
          "iam:GetPolicy",
          "iam:GetPolicyVersion",
          "iam:ListRoles",
          "iam:GetRole",
          "iam:ListRolePolicies",
          "iam:ListAttachedRolePolicies",
          "iam:GetCredentialReport",
          "iam:GenerateCredentialReport"
        ]
        Resource = "*"
      }
    ]
  })
}

# EC2 Read Policy (for security checks)
resource "aws_iam_role_policy" "scanner_ec2_read" {
  name = "${local.name_prefix}-scanner-ec2-read"
  role = aws_iam_role.scanner_lambda_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "ec2:DescribeInstances",
          "ec2:DescribeSecurityGroups",
          "ec2:DescribeVolumes",
          "ec2:DescribeImages",
          "ec2:DescribeVpcs",
          "ec2:DescribeSubnets",
          "ec2:DescribeRouteTables",
          "ec2:DescribeFlowLogs",
          "ec2:DescribeNetworkAcls",
          "ec2:DescribeVpcPeeringConnections"
        ]
        Resource = "*"
      }
    ]
  })
}

# CloudTrail Read Policy (for security checks)
resource "aws_iam_role_policy" "scanner_cloudtrail_read" {
  name = "${local.name_prefix}-scanner-cloudtrail-read"
  role = aws_iam_role.scanner_lambda_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "cloudtrail:DescribeTrails",
          "cloudtrail:GetTrailStatus",
          "cloudtrail:GetEventSelectors"
        ]
        Resource = "*"
      }
    ]
  })
}

# -----------------------------------------------------------------------------
# Lambda Execution Role - Report Generator
# -----------------------------------------------------------------------------
resource "aws_iam_role" "report_generator_role" {
  name = "${local.name_prefix}-report-role-${local.random_suffix}"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })
}

# CloudWatch Logs Policy for Report Generator
resource "aws_iam_role_policy" "report_logs" {
  name = "${local.name_prefix}-report-logs"
  role = aws_iam_role.report_generator_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "arn:aws:logs:${local.region}:${local.account_id}:log-group:/aws/lambda/${local.name_prefix}-*"
      }
    ]
  })
}

# DynamoDB Read Policy for Report Generator
resource "aws_iam_role_policy" "report_dynamodb" {
  name = "${local.name_prefix}-report-dynamodb"
  role = aws_iam_role.report_generator_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "dynamodb:GetItem",
          "dynamodb:Query",
          "dynamodb:Scan"
        ]
        Resource = [
          aws_dynamodb_table.findings.arn,
          aws_dynamodb_table.scan_history.arn
        ]
      }
    ]
  })
}

# S3 Write Policy for Report Generator
resource "aws_iam_role_policy" "report_s3_write" {
  name = "${local.name_prefix}-report-s3-write"
  role = aws_iam_role.report_generator_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:PutObject",
          "s3:GetObject"
        ]
        Resource = "${aws_s3_bucket.reports.arn}/*"
      }
    ]
  })
}

# SNS Publish Policy for Report Generator
resource "aws_iam_role_policy" "report_sns" {
  name = "${local.name_prefix}-report-sns"
  role = aws_iam_role.report_generator_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "sns:Publish"
        ]
        Resource = aws_sns_topic.alerts.arn
      }
    ]
  })
}
