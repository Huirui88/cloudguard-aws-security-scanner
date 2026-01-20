# =============================================================================
# CloudGuard - AWS Security Compliance Scanner
# Main Terraform Configuration
# =============================================================================

terraform {
  required_version = ">= 1.0.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.0"
    }
  }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = "CloudGuard"
      Environment = var.environment
      ManagedBy   = "Terraform"
    }
  }
}

# Generate random suffix for globally unique resource names
resource "random_string" "suffix" {
  length  = 8
  special = false
  upper   = false
}

# Data source for current AWS account
data "aws_caller_identity" "current" {}

# Data source for current AWS region
data "aws_region" "current" {}

# Local variables
locals {
  account_id    = data.aws_caller_identity.current.account_id
  region        = data.aws_region.current.name
  name_prefix   = "compliance-scanner"
  random_suffix = random_string.suffix.result

  common_tags = {
    Project     = "CloudGuard"
    Environment = var.environment
  }
}
