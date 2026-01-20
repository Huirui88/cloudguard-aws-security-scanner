"""
CloudGuard - S3 Security Check
Scans all S3 buckets for security compliance issues
"""

import boto3
import json
import os
from datetime import datetime, timezone
from botocore.exceptions import ClientError

s3_client = boto3.client('s3')
dynamodb = boto3.resource('dynamodb')

FINDINGS_TABLE = os.environ.get('FINDINGS_TABLE', 'compliance-scanner-findings')


def lambda_handler(event, context):
    """
    Scans S3 buckets for security compliance
    """
    scan_id = event.get('scan_id', f"manual-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}")
    findings = []
    
    print(f"Starting S3 security scan: {scan_id}")
    
    # Get all S3 buckets
    try:
        buckets = s3_client.list_buckets()['Buckets']
        print(f"Found {len(buckets)} buckets to scan")
    except Exception as e:
        print(f"Error listing buckets: {str(e)}")
        return {'statusCode': 500, 'error': str(e)}
    
    for bucket in buckets:
        bucket_name = bucket['Name']
        print(f"Scanning bucket: {bucket_name}")
        
        # Check 1: Public Access Block
        findings.extend(check_public_access_block(bucket_name, scan_id))
        
        # Check 2: Encryption
        findings.extend(check_bucket_encryption(bucket_name, scan_id))
        
        # Check 3: Versioning
        findings.extend(check_bucket_versioning(bucket_name, scan_id))
        
        # Check 4: Logging
        findings.extend(check_bucket_logging(bucket_name, scan_id))
        
        # Check 5: Bucket Policy
        findings.extend(check_bucket_policy(bucket_name, scan_id))
    
    # Store findings in DynamoDB
    findings_table = dynamodb.Table(FINDINGS_TABLE)
    stored_count = 0
    
    for finding in findings:
        try:
            findings_table.put_item(Item=finding)
            stored_count += 1
        except Exception as e:
            print(f"Error storing finding: {str(e)}")
    
    print(f"S3 scan complete. Found {len(findings)} issues, stored {stored_count}")
    
    return {
        'statusCode': 200,
        'body': json.dumps({
            'scan_id': scan_id,
            'findings_count': len(findings),
            'buckets_scanned': len(buckets)
        })
    }


def create_finding(bucket_name, scan_id, severity, title, description, remediation, cis_control):
    """Helper function to create a standardized finding"""
    now = datetime.now(timezone.utc).isoformat()
    return {
        'finding_id': f"s3-{title.lower().replace(' ', '-')[:30]}-{bucket_name[:20]}-{scan_id}",
        'scan_date': now,
        'check_type': 'S3_SECURITY',
        'resource_id': f"arn:aws:s3:::{bucket_name}",
        'resource_name': bucket_name,
        'severity': severity,
        'title': title,
        'description': description,
        'remediation': remediation,
        'cis_control': cis_control,
        'status': 'OPEN',
        'first_detected': now,
        'last_seen': now
    }


def check_public_access_block(bucket_name, scan_id):
    """Check if public access block is enabled"""
    findings = []
    
    try:
        response = s3_client.get_public_access_block(Bucket=bucket_name)
        config = response['PublicAccessBlockConfiguration']
        
        # Check if all settings are True
        if not all([
            config.get('BlockPublicAcls', False),
            config.get('IgnorePublicAcls', False),
            config.get('BlockPublicPolicy', False),
            config.get('RestrictPublicBuckets', False)
        ]):
            findings.append(create_finding(
                bucket_name=bucket_name,
                scan_id=scan_id,
                severity='CRITICAL',
                title='S3 Public Access Block Not Fully Enabled',
                description=f"Bucket '{bucket_name}' does not have all public access block settings enabled",
                remediation='Enable all public access block settings: BlockPublicAcls, IgnorePublicAcls, BlockPublicPolicy, RestrictPublicBuckets',
                cis_control='2.1.5'
            ))
            
    except ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchPublicAccessBlockConfiguration':
            # No public access block configured at all - CRITICAL
            findings.append(create_finding(
                bucket_name=bucket_name,
                scan_id=scan_id,
                severity='CRITICAL',
                title='S3 Public Access Block Not Configured',
                description=f"Bucket '{bucket_name}' has no public access block configuration",
                remediation='Configure public access block settings for the bucket',
                cis_control='2.1.5'
            ))
        else:
            print(f"Error checking public access block for {bucket_name}: {str(e)}")
    except Exception as e:
        print(f"Error checking public access block for {bucket_name}: {str(e)}")
    
    return findings


def check_bucket_encryption(bucket_name, scan_id):
    """Check if bucket has encryption enabled"""
    findings = []
    
    try:
        s3_client.get_bucket_encryption(Bucket=bucket_name)
        # If we get here, encryption is configured
        
    except ClientError as e:
        if e.response['Error']['Code'] == 'ServerSideEncryptionConfigurationNotFoundError':
            # No encryption configured - HIGH severity
            findings.append(create_finding(
                bucket_name=bucket_name,
                scan_id=scan_id,
                severity='HIGH',
                title='S3 Bucket Encryption Not Enabled',
                description=f"Bucket '{bucket_name}' does not have default encryption enabled",
                remediation='Enable default encryption (AES256 or KMS) for the bucket',
                cis_control='2.1.1'
            ))
        else:
            print(f"Error checking encryption for {bucket_name}: {str(e)}")
    except Exception as e:
        print(f"Error checking encryption for {bucket_name}: {str(e)}")
    
    return findings


def check_bucket_versioning(bucket_name, scan_id):
    """Check if bucket has versioning enabled"""
    findings = []
    
    try:
        response = s3_client.get_bucket_versioning(Bucket=bucket_name)
        status = response.get('Status', 'Disabled')
        
        if status != 'Enabled':
            findings.append(create_finding(
                bucket_name=bucket_name,
                scan_id=scan_id,
                severity='MEDIUM',
                title='S3 Bucket Versioning Not Enabled',
                description=f"Bucket '{bucket_name}' does not have versioning enabled",
                remediation='Enable versioning to protect against accidental deletion',
                cis_control='2.1.3'
            ))
            
    except Exception as e:
        print(f"Error checking versioning for {bucket_name}: {str(e)}")
    
    return findings


def check_bucket_logging(bucket_name, scan_id):
    """Check if bucket has access logging enabled"""
    findings = []
    
    try:
        response = s3_client.get_bucket_logging(Bucket=bucket_name)
        
        if 'LoggingEnabled' not in response:
            findings.append(create_finding(
                bucket_name=bucket_name,
                scan_id=scan_id,
                severity='LOW',
                title='S3 Bucket Access Logging Not Enabled',
                description=f"Bucket '{bucket_name}' does not have access logging enabled",
                remediation='Enable S3 access logging for audit trail',
                cis_control='2.1.4'
            ))
            
    except Exception as e:
        print(f"Error checking logging for {bucket_name}: {str(e)}")
    
    return findings


def check_bucket_policy(bucket_name, scan_id):
    """Check bucket policy for overly permissive access"""
    findings = []
    
    try:
        response = s3_client.get_bucket_policy(Bucket=bucket_name)
        policy = json.loads(response['Policy'])
        
        # Check for wildcard principals or actions
        for statement in policy.get('Statement', []):
            principal = statement.get('Principal', {})
            effect = statement.get('Effect', 'Deny')
            
            # Only check Allow statements
            if effect != 'Allow':
                continue
            
            # Check for wildcard principal
            if principal == '*' or (isinstance(principal, dict) and principal.get('AWS') == '*'):
                # Check if there are conditions that might restrict access
                conditions = statement.get('Condition', {})
                if not conditions:
                    findings.append(create_finding(
                        bucket_name=bucket_name,
                        scan_id=scan_id,
                        severity='HIGH',
                        title='S3 Bucket Policy Allows Wildcard Principal',
                        description=f"Bucket '{bucket_name}' has a policy with Principal: '*' without restrictive conditions",
                        remediation='Restrict bucket policy to specific principals or add conditions',
                        cis_control='2.1.5'
                    ))
                    break
                    
    except ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchBucketPolicy':
            # No policy is fine
            pass
        else:
            print(f"Error checking policy for {bucket_name}: {str(e)}")
    except Exception as e:
        print(f"Error checking policy for {bucket_name}: {str(e)}")
    
    return findings
