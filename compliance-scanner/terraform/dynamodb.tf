# =============================================================================
# CloudGuard - AWS Security Compliance Scanner
# DynamoDB Tables
# =============================================================================

# -----------------------------------------------------------------------------
# Findings Table - Stores all security findings
# -----------------------------------------------------------------------------
resource "aws_dynamodb_table" "findings" {
  name         = "${local.name_prefix}-findings-${local.random_suffix}"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "finding_id"

  attribute {
    name = "finding_id"
    type = "S"
  }

  attribute {
    name = "check_type"
    type = "S"
  }

  attribute {
    name = "severity"
    type = "S"
  }

  attribute {
    name = "status"
    type = "S"
  }

  attribute {
    name = "scan_date"
    type = "S"
  }

  # Global Secondary Index for querying by check type
  global_secondary_index {
    name            = "check_type-index"
    hash_key        = "check_type"
    range_key       = "scan_date"
    projection_type = "ALL"
  }

  # Global Secondary Index for querying by severity
  global_secondary_index {
    name            = "severity-index"
    hash_key        = "severity"
    range_key       = "scan_date"
    projection_type = "ALL"
  }

  # Global Secondary Index for querying by status
  global_secondary_index {
    name            = "status-index"
    hash_key        = "status"
    range_key       = "scan_date"
    projection_type = "ALL"
  }

  # TTL for automatic cleanup of old findings
  ttl {
    attribute_name = "ttl"
    enabled        = true
  }

  point_in_time_recovery {
    enabled = true
  }

  tags = {
    Name = "${local.name_prefix}-findings"
  }
}

# -----------------------------------------------------------------------------
# Scan History Table - Tracks scan execution history
# -----------------------------------------------------------------------------
resource "aws_dynamodb_table" "scan_history" {
  name         = "${local.name_prefix}-scan-history-${local.random_suffix}"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "scan_id"

  attribute {
    name = "scan_id"
    type = "S"
  }

  attribute {
    name = "scan_date"
    type = "S"
  }

  # Global Secondary Index for querying by date
  global_secondary_index {
    name            = "scan_date-index"
    hash_key        = "scan_date"
    projection_type = "ALL"
  }

  # TTL for automatic cleanup of old scan records
  ttl {
    attribute_name = "ttl"
    enabled        = true
  }

  point_in_time_recovery {
    enabled = true
  }

  tags = {
    Name = "${local.name_prefix}-scan-history"
  }
}
