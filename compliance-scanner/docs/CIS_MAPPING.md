# CIS AWS Foundations Benchmark Mapping

This document maps CloudGuard security checks to the CIS AWS Foundations Benchmark v1.5.0.

## 1. Identity and Access Management

| CIS Control | Description | CloudGuard Check |
|-------------|-------------|------------------|
| 1.4 | Ensure no root account access keys exist | `check_root_access_keys` |
| 1.5 | Ensure MFA is enabled for the root account | `check_root_mfa` |
| 1.8 | Ensure IAM password policy requires minimum length of 14 | `check_password_policy` |
| 1.10 | Ensure IAM password policy prevents password reuse | `check_password_policy` |
| 1.11 | Ensure IAM password policy expires passwords within 90 days | `check_password_policy` |
| 1.3 | Ensure credentials unused for 90 days or greater are disabled | `check_unused_credentials` |
| 1.16 | Ensure IAM policies that allow full "*:*" administrative privileges are not attached | `check_admin_privileges` |
| 1.22 | Ensure IAM policies are attached only to groups or roles | `check_wildcard_policies` |

## 2. Storage

| CIS Control | Description | CloudGuard Check |
|-------------|-------------|------------------|
| 2.1.1 | Ensure S3 Bucket Policy is set to deny HTTP requests | `check_bucket_encryption` |
| 2.1.3 | Ensure MFA Delete is enabled on S3 buckets | `check_bucket_versioning` |
| 2.1.4 | Ensure all data in Amazon S3 has been discovered, classified and secured | `check_bucket_logging` |
| 2.1.5 | Ensure S3 bucket access logging is enabled on CloudTrail S3 bucket | `check_public_access_block` |
| 2.2.1 | Ensure EBS volume encryption is enabled | `check_ebs_encryption` |

## 3. Logging

| CIS Control | Description | CloudGuard Check |
|-------------|-------------|------------------|
| 3.1 | Ensure CloudTrail is enabled in all regions | `check_cloudtrail_enabled`, `check_multi_region_trail` |
| 3.2 | Ensure CloudTrail log file validation is enabled | `check_log_file_validation` |
| 3.6 | Ensure S3 bucket access logging is enabled on CloudTrail S3 bucket | `check_cloudtrail_bucket_logging` |
| 3.7 | Ensure CloudTrail logs are encrypted at rest using KMS CMKs | `check_cloudtrail_encryption` |
| 3.9 | Ensure VPC flow logging is enabled in all VPCs | `check_vpc_flow_logs` |

## 4. Monitoring

| CIS Control | Description | CloudGuard Check |
|-------------|-------------|------------------|
| 4.x | CloudWatch Alarms | *Future Implementation* |

## 5. Networking

| CIS Control | Description | CloudGuard Check |
|-------------|-------------|------------------|
| 5.1 | Ensure no Network ACLs allow ingress from 0.0.0.0/0 to remote server administration ports | `check_network_acls`, `check_public_instances` |
| 5.2 | Ensure no security groups allow ingress from 0.0.0.0/0 to remote server administration ports | `check_security_groups` |
| 5.3 | Ensure the default security group of every VPC restricts all traffic | `check_default_security_groups`, `check_unused_security_groups` |
| 5.4 | Ensure routing tables for VPC peering are "least access" | `check_public_amis` |
| 5.5 | Ensure VPC peering connections have appropriate tags | `check_vpc_peering` |
| 5.6 | Ensure EC2 instances use Instance Metadata Service Version 2 (IMDSv2) | `check_imdsv2` |

## Severity Mapping

CloudGuard maps findings to severity levels based on potential impact:

| Severity | Description | Examples |
|----------|-------------|----------|
| **CRITICAL** | Immediate security risk, requires urgent action | Root MFA disabled, S3 public access, SSH open to internet |
| **HIGH** | Significant security risk, should be addressed quickly | Unencrypted EBS, wildcard IAM policies |
| **MEDIUM** | Moderate risk, should be addressed in normal workflow | Missing VPC flow logs, IMDSv2 not required |
| **LOW** | Low risk or informational | Unused security groups, missing S3 logging |

## Compliance Frameworks

CloudGuard checks support multiple compliance frameworks:

- **CIS AWS Foundations Benchmark** v1.5.0
- **AWS Well-Architected Framework** - Security Pillar
- **PCI DSS** - Relevant controls
- **HIPAA** - Technical safeguards
- **SOC 2** - Common criteria

## Adding Custom Checks

To add custom security checks aligned with CIS controls:

1. Create a new check function in the appropriate Lambda
2. Map the check to the CIS control ID
3. Set appropriate severity based on impact
4. Include remediation guidance
5. Update this mapping document

## References

- [CIS AWS Foundations Benchmark](https://www.cisecurity.org/benchmark/amazon_web_services)
- [AWS Security Best Practices](https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/)
- [AWS Config Managed Rules](https://docs.aws.amazon.com/config/latest/developerguide/managed-rules-by-aws-config.html)
