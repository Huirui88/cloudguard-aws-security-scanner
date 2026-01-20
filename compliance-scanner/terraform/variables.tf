# =============================================================================
# CloudGuard - AWS Security Compliance Scanner
# Terraform Variables
# =============================================================================

variable "aws_region" {
  description = "AWS region for deployment"
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Environment name (dev, staging, prod)"
  type        = string
  default     = "dev"
}

variable "schedule_expression" {
  description = "CloudWatch Events schedule expression for daily scans"
  type        = string
  default     = "cron(0 2 * * ? *)" # Daily at 2 AM UTC
}

variable "alert_email" {
  description = "Email address for security alerts"
  type        = string
  default     = ""
}

variable "enable_sns_notifications" {
  description = "Enable SNS notifications for critical findings"
  type        = bool
  default     = true
}

variable "findings_retention_days" {
  description = "Number of days to retain findings in DynamoDB"
  type        = number
  default     = 90
}

variable "lambda_memory_orchestrator" {
  description = "Memory allocation for orchestrator Lambda (MB)"
  type        = number
  default     = 256
}

variable "lambda_memory_checks" {
  description = "Memory allocation for check Lambdas (MB)"
  type        = number
  default     = 512
}

variable "lambda_memory_report" {
  description = "Memory allocation for report generator Lambda (MB)"
  type        = number
  default     = 512
}

variable "lambda_timeout_orchestrator" {
  description = "Timeout for orchestrator Lambda (seconds)"
  type        = number
  default     = 300
}

variable "lambda_timeout_checks" {
  description = "Timeout for check Lambdas (seconds)"
  type        = number
  default     = 600
}

variable "lambda_timeout_report" {
  description = "Timeout for report generator Lambda (seconds)"
  type        = number
  default     = 300
}

variable "enable_vpc_checks" {
  description = "Enable VPC security checks"
  type        = bool
  default     = true
}

variable "enable_cloudtrail_checks" {
  description = "Enable CloudTrail security checks"
  type        = bool
  default     = true
}
