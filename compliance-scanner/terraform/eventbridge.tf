# =============================================================================
# CloudGuard - AWS Security Compliance Scanner
# EventBridge Rules
# =============================================================================

# -----------------------------------------------------------------------------
# Daily Scan Schedule
# -----------------------------------------------------------------------------
resource "aws_cloudwatch_event_rule" "daily_scan" {
  name                = "${local.name_prefix}-daily-scan-${local.random_suffix}"
  description         = "Triggers daily security compliance scan at 2 AM UTC"
  schedule_expression = var.schedule_expression

  tags = {
    Name = "${local.name_prefix}-daily-scan"
  }
}

# Target for daily scan - Lambda Orchestrator
resource "aws_cloudwatch_event_target" "daily_scan" {
  rule      = aws_cloudwatch_event_rule.daily_scan.name
  target_id = "TriggerComplianceScan"
  arn       = aws_lambda_function.orchestrator.arn

  input = jsonencode({
    source    = "scheduled"
    timestamp = "$.time"
  })
}

# Permission for EventBridge to invoke Lambda
resource "aws_lambda_permission" "eventbridge" {
  statement_id  = "AllowEventBridgeInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.orchestrator.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.daily_scan.arn
}
