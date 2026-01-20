# =============================================================================
# CloudGuard - AWS Security Compliance Scanner
# SNS Topics and Subscriptions
# =============================================================================

# -----------------------------------------------------------------------------
# Critical Findings Alert Topic
# -----------------------------------------------------------------------------
resource "aws_sns_topic" "alerts" {
  name = "${local.name_prefix}-alerts-${local.random_suffix}"

  tags = {
    Name = "${local.name_prefix}-alerts"
  }
}

# SNS Topic Policy
resource "aws_sns_topic_policy" "alerts" {
  arn = aws_sns_topic.alerts.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowLambdaPublish"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
        Action   = "sns:Publish"
        Resource = aws_sns_topic.alerts.arn
        Condition = {
          ArnLike = {
            "aws:SourceArn" = "arn:aws:lambda:${local.region}:${local.account_id}:function:${local.name_prefix}-*"
          }
        }
      }
    ]
  })
}

# Email subscription (if email is provided)
resource "aws_sns_topic_subscription" "email" {
  count     = var.alert_email != "" ? 1 : 0
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# -----------------------------------------------------------------------------
# Daily Summary Topic
# -----------------------------------------------------------------------------
resource "aws_sns_topic" "daily_summary" {
  name = "${local.name_prefix}-daily-summary-${local.random_suffix}"

  tags = {
    Name = "${local.name_prefix}-daily-summary"
  }
}

# Daily summary email subscription (if email is provided)
resource "aws_sns_topic_subscription" "daily_summary_email" {
  count     = var.alert_email != "" ? 1 : 0
  topic_arn = aws_sns_topic.daily_summary.arn
  protocol  = "email"
  endpoint  = var.alert_email
}
