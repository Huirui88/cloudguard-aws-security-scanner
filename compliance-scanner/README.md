# CloudGuard - AWS Security Compliance Scanner

🛡️ **Automated security compliance scanning for AWS infrastructure**

CloudGuard continuously monitors your AWS infrastructure for security misconfigurations and compliance violations, helping you detect security issues before they become breaches.

## 🎯 Features

- **Automated Daily Scans**: Scheduled security checks run automatically at 2 AM UTC
- **Comprehensive Coverage**: Scans S3, IAM, EC2, VPC, and CloudTrail configurations
- **CIS Benchmark Aligned**: Checks mapped to CIS AWS Foundations Benchmark controls
- **Beautiful Reports**: HTML and JSON reports with severity-based categorization
- **Real-time Alerts**: SNS notifications for critical findings
- **Serverless Architecture**: Cost-effective, scalable Lambda-based design

## 📋 Security Checks

### S3 Security
- ✅ Public access blocked
- ✅ Encryption enabled (AES256 or KMS)
- ✅ Versioning enabled
- ✅ Access logging enabled
- ✅ Bucket policies reviewed (no wildcards)

### IAM Security
- ✅ Root account MFA enabled
- ✅ No access keys for root account
- ✅ Password policy enforced
- ✅ Unused credentials (>90 days)
- ✅ Users with admin privileges
- ✅ Policies with wildcard permissions

### EC2 Security
- ✅ Security groups with 0.0.0.0/0 on risky ports
- ✅ EBS volumes encrypted
- ✅ IMDSv2 required
- ✅ Public AMIs
- ✅ Unused security groups

### VPC Security
- ✅ VPC flow logs enabled
- ✅ Default security group locked down
- ✅ Network ACLs reviewed
- ✅ VPC peering connections

### CloudTrail
- ✅ CloudTrail enabled in all regions
- ✅ Log file validation enabled
- ✅ Logs encrypted with KMS
- ✅ S3 bucket logging enabled

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    EventBridge                          │
│              (Daily at 2 AM UTC)                        │
└────────────────────┬────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────┐
│            Lambda: Scanner Orchestrator                 │
└────────────────────┬────────────────────────────────────┘
                     │
     ┌───────────────┼───────────────┐
     ▼               ▼               ▼
┌─────────┐   ┌─────────┐   ┌─────────┐
│   S3    │   │   IAM   │   │   EC2   │  ... more checks
│  Check  │   │  Check  │   │  Check  │
└────┬────┘   └────┬────┘   └────┬────┘
     │             │             │
     └─────────────┼─────────────┘
                   ▼
┌─────────────────────────────────────────────────────────┐
│              DynamoDB: Findings Table                   │
└────────────────────┬────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────┐
│            Lambda: Report Generator                     │
└────────────────────┬────────────────────────────────────┘
                     │
     ┌───────────────┼───────────────┐
     ▼               ▼               ▼
┌─────────┐   ┌─────────┐   ┌─────────┐
│   S3    │   │   SNS   │   │  Email  │
│ Reports │   │ Alerts  │   │         │
└─────────┘   └─────────┘   └─────────┘
```

## 📁 Project Structure

```
compliance-scanner/
├── README.md
├── terraform/
│   ├── main.tf           # Main Terraform configuration
│   ├── variables.tf      # Input variables
│   ├── outputs.tf        # Output values
│   ├── lambda.tf         # Lambda function definitions
│   ├── dynamodb.tf       # DynamoDB tables
│   ├── s3.tf             # S3 buckets
│   ├── iam.tf            # IAM roles and policies
│   ├── eventbridge.tf    # EventBridge rules
│   └── sns.tf            # SNS topics
├── src/
│   ├── orchestrator/
│   │   └── lambda_function.py
│   ├── checks/
│   │   ├── s3/lambda_function.py
│   │   ├── iam/lambda_function.py
│   │   ├── ec2/lambda_function.py
│   │   ├── vpc/lambda_function.py
│   │   └── cloudtrail/lambda_function.py
│   ├── report_generator/
│   │   └── lambda_function.py
│   └── shared/
│       └── utils.py
├── tests/
└── docs/
```

## 🚀 Deployment

### Prerequisites

- AWS CLI configured with appropriate credentials
- Terraform >= 1.0.0
- Python 3.12

### Quick Start

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd compliance-scanner
   ```

2. **Configure variables**
   
   Create a `terraform.tfvars` file:
   ```hcl
   aws_region   = "us-east-1"
   environment  = "prod"
   alert_email  = "security@yourcompany.com"
   ```

3. **Deploy with Terraform**
   ```bash
   cd terraform
   terraform init
   terraform plan
   terraform apply
   ```

4. **Verify deployment**
   ```bash
   # Check Lambda functions
   aws lambda list-functions --query "Functions[?contains(FunctionName, 'compliance-scanner')]"
   
   # Check DynamoDB tables
   aws dynamodb list-tables --query "TableNames[?contains(@, 'compliance-scanner')]"
   ```

### Configuration Options

| Variable | Description | Default |
|----------|-------------|---------|
| `aws_region` | AWS region for deployment | `us-east-1` |
| `environment` | Environment name | `dev` |
| `schedule_expression` | Cron schedule for scans | `cron(0 2 * * ? *)` |
| `alert_email` | Email for alerts | `""` |
| `enable_sns_notifications` | Enable SNS alerts | `true` |

## 🔧 Manual Scan

To trigger a manual scan:

```bash
aws lambda invoke \
  --function-name compliance-scanner-orchestrator-<suffix> \
  --payload '{"source": "manual"}' \
  response.json
```

## 📊 Viewing Reports

Reports are stored in S3:
- HTML Report: `s3://compliance-scanner-reports-<suffix>/reports/YYYY-MM-DD/compliance-report.html`
- JSON Report: `s3://compliance-scanner-reports-<suffix>/reports/YYYY-MM-DD/compliance-report.json`

## 💰 Cost Estimate

Monthly costs (assuming daily scans):
- Lambda executions: ~$0.50
- DynamoDB: ~$2.00
- S3 storage: ~$0.50
- SNS: ~$0.10
- **Total: ~$3.10/month**

## 🔐 IAM Permissions

The scanner requires read-only access to:
- S3 (bucket policies, encryption, versioning)
- IAM (users, policies, password policy)
- EC2 (instances, security groups, volumes)
- VPC (flow logs, network ACLs)
- CloudTrail (trail configuration)

See `terraform/iam.tf` for complete IAM policies.

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

## 📝 License

MIT License - See LICENSE file for details.

## 🙏 Acknowledgments

- CIS AWS Foundations Benchmark for security control guidance
- AWS Well-Architected Framework for architecture best practices
