# =============================================================================
# CloudGuard - AWS Security Compliance Scanner
# S3 Buckets
# =============================================================================

# -----------------------------------------------------------------------------
# Reports Bucket - Stores generated compliance reports
# -----------------------------------------------------------------------------
resource "aws_s3_bucket" "reports" {
  bucket = "${local.name_prefix}-reports-${local.random_suffix}"

  tags = {
    Name = "${local.name_prefix}-reports"
  }
}

# Enable versioning for reports bucket
resource "aws_s3_bucket_versioning" "reports" {
  bucket = aws_s3_bucket.reports.id
  versioning_configuration {
    status = "Enabled"
  }
}

# Enable server-side encryption for reports bucket
resource "aws_s3_bucket_server_side_encryption_configuration" "reports" {
  bucket = aws_s3_bucket.reports.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# Block public access for reports bucket
resource "aws_s3_bucket_public_access_block" "reports" {
  bucket = aws_s3_bucket.reports.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Lifecycle rules for reports bucket
resource "aws_s3_bucket_lifecycle_configuration" "reports" {
  bucket = aws_s3_bucket.reports.id

  rule {
    id     = "archive-old-reports"
    status = "Enabled"
    
    filter {}

    transition {
      days          = 30
      storage_class = "STANDARD_IA"
    }

    transition {
      days          = 90
      storage_class = "GLACIER"
    }

    expiration {
      days = 365
    }
  }
}

# -----------------------------------------------------------------------------
# Lambda Code Bucket - Stores Lambda deployment packages
# -----------------------------------------------------------------------------
resource "aws_s3_bucket" "lambda_code" {
  bucket = "${local.name_prefix}-lambda-code-${local.random_suffix}"

  tags = {
    Name = "${local.name_prefix}-lambda-code"
  }
}

# Enable versioning for lambda code bucket
resource "aws_s3_bucket_versioning" "lambda_code" {
  bucket = aws_s3_bucket.lambda_code.id
  versioning_configuration {
    status = "Enabled"
  }
}

# Enable server-side encryption for lambda code bucket
resource "aws_s3_bucket_server_side_encryption_configuration" "lambda_code" {
  bucket = aws_s3_bucket.lambda_code.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# Block public access for lambda code bucket
resource "aws_s3_bucket_public_access_block" "lambda_code" {
  bucket = aws_s3_bucket.lambda_code.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
