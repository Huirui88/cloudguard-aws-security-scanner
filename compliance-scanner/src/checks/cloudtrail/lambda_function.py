"""
CloudGuard - CloudTrail Security Check
Scans CloudTrail configuration for security compliance issues
"""

import boto3
import json
import os
from datetime import datetime, timezone
from botocore.exceptions import ClientError

cloudtrail_client = boto3.client('cloudtrail')
dynamodb = boto3.resource('dynamodb')

FINDINGS_TABLE = os.environ.get('FINDINGS_TABLE', 'compliance-scanner-findings')


def lambda_handler(event, context):
    """
    Scans CloudTrail configuration for security compliance
    """
    scan_id = event.get('scan_id', f"manual-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}")
    findings = []
    
    print(f"Starting CloudTrail security scan: {scan_id}")
    
    # Check 1: CloudTrail enabled
    findings.extend(check_cloudtrail_enabled(scan_id))
    
    # Check 2: Multi-region trail
    findings.extend(check_multi_region_trail(scan_id))
    
    # Check 3: Log file validation
    findings.extend(check_log_file_validation(scan_id))
    
    # Check 4: CloudTrail encryption
    findings.extend(check_cloudtrail_encryption(scan_id))
    
    # Check 5: S3 bucket logging for CloudTrail bucket
    findings.extend(check_cloudtrail_bucket_logging(scan_id))
    
    # Store findings in DynamoDB
    findings_table = dynamodb.Table(FINDINGS_TABLE)
    stored_count = 0
    
    for finding in findings:
        try:
            findings_table.put_item(Item=finding)
            stored_count += 1
        except Exception as e:
            print(f"Error storing finding: {str(e)}")
    
    print(f"CloudTrail scan complete. Found {len(findings)} issues, stored {stored_count}")
    
    return {
        'statusCode': 200,
        'body': json.dumps({
            'scan_id': scan_id,
            'findings_count': len(findings)
        })
    }


def create_finding(resource_name, scan_id, severity, title, description, remediation, cis_control, resource_id=None):
    """Helper function to create a standardized finding"""
    now = datetime.now(timezone.utc).isoformat()
    return {
        'finding_id': f"cloudtrail-{title.lower().replace(' ', '-')[:30]}-{resource_name[:20]}-{scan_id}",
        'scan_date': now,
        'check_type': 'CLOUDTRAIL',
        'resource_id': resource_id or resource_name,
        'resource_name': resource_name,
        'severity': severity,
        'title': title,
        'description': description,
        'remediation': remediation,
        'cis_control': cis_control,
        'status': 'OPEN',
        'first_detected': now,
        'last_seen': now
    }


def get_trails():
    """Get all CloudTrail trails"""
    try:
        response = cloudtrail_client.describe_trails()
        return response.get('trailList', [])
    except Exception as e:
        print(f"Error getting trails: {str(e)}")
        return []


def check_cloudtrail_enabled(scan_id):
    """Check if CloudTrail is enabled"""
    findings = []
    
    try:
        trails = get_trails()
        
        if not trails:
            findings.append(create_finding(
                resource_name='account',
                scan_id=scan_id,
                severity='CRITICAL',
                title='CloudTrail Not Enabled',
                description='No CloudTrail trails are configured for this account',
                remediation='Enable CloudTrail with a multi-region trail to log all API activity',
                cis_control='3.1',
                resource_id='arn:aws:cloudtrail:::trail/*'
            ))
            return findings
        
        # Check if any trail is logging
        any_logging = False
        for trail in trails:
            trail_arn = trail.get('TrailARN', '')
            try:
                status = cloudtrail_client.get_trail_status(Name=trail_arn)
                if status.get('IsLogging', False):
                    any_logging = True
                    break
            except Exception as e:
                print(f"Error getting trail status for {trail_arn}: {str(e)}")
        
        if not any_logging:
            findings.append(create_finding(
                resource_name='account',
                scan_id=scan_id,
                severity='CRITICAL',
                title='CloudTrail Not Logging',
                description='CloudTrail trails exist but none are actively logging',
                remediation='Start logging on at least one CloudTrail trail',
                cis_control='3.1',
                resource_id='arn:aws:cloudtrail:::trail/*'
            ))
            
    except Exception as e:
        print(f"Error checking CloudTrail enabled: {str(e)}")
    
    return findings


def check_multi_region_trail(scan_id):
    """Check for multi-region trail"""
    findings = []
    
    try:
        trails = get_trails()
        has_multi_region = False
        
        for trail in trails:
            if trail.get('IsMultiRegionTrail', False):
                has_multi_region = True
                break
        
        if trails and not has_multi_region:
            findings.append(create_finding(
                resource_name='account',
                scan_id=scan_id,
                severity='HIGH',
                title='No Multi-Region CloudTrail Trail',
                description='No CloudTrail trail is configured to log events from all regions',
                remediation='Create or update a CloudTrail trail to be multi-region',
                cis_control='3.1',
                resource_id='arn:aws:cloudtrail:::trail/*'
            ))
            
    except Exception as e:
        print(f"Error checking multi-region trail: {str(e)}")
    
    return findings


def check_log_file_validation(scan_id):
    """Check if log file validation is enabled"""
    findings = []
    
    try:
        trails = get_trails()
        
        for trail in trails:
            trail_name = trail.get('Name', 'unknown')
            trail_arn = trail.get('TrailARN', '')
            
            if not trail.get('LogFileValidationEnabled', False):
                findings.append(create_finding(
                    resource_name=trail_name,
                    scan_id=scan_id,
                    severity='MEDIUM',
                    title='CloudTrail Log File Validation Not Enabled',
                    description=f"CloudTrail trail '{trail_name}' does not have log file validation enabled",
                    remediation='Enable log file validation to detect tampering of log files',
                    cis_control='3.2',
                    resource_id=trail_arn
                ))
                
    except Exception as e:
        print(f"Error checking log file validation: {str(e)}")
    
    return findings


def check_cloudtrail_encryption(scan_id):
    """Check if CloudTrail logs are encrypted"""
    findings = []
    
    try:
        trails = get_trails()
        
        for trail in trails:
            trail_name = trail.get('Name', 'unknown')
            trail_arn = trail.get('TrailARN', '')
            kms_key = trail.get('KmsKeyId')
            
            if not kms_key:
                findings.append(create_finding(
                    resource_name=trail_name,
                    scan_id=scan_id,
                    severity='MEDIUM',
                    title='CloudTrail Logs Not Encrypted with KMS',
                    description=f"CloudTrail trail '{trail_name}' logs are not encrypted with a KMS key",
                    remediation='Configure CloudTrail to encrypt logs using a KMS CMK',
                    cis_control='3.7',
                    resource_id=trail_arn
                ))
                
    except Exception as e:
        print(f"Error checking CloudTrail encryption: {str(e)}")
    
    return findings


def check_cloudtrail_bucket_logging(scan_id):
    """Check if S3 bucket logging is enabled for CloudTrail bucket"""
    findings = []
    s3_client = boto3.client('s3')
    
    try:
        trails = get_trails()
        checked_buckets = set()
        
        for trail in trails:
            trail_name = trail.get('Name', 'unknown')
            bucket_name = trail.get('S3BucketName')
            
            if not bucket_name or bucket_name in checked_buckets:
                continue
            
            checked_buckets.add(bucket_name)
            
            try:
                response = s3_client.get_bucket_logging(Bucket=bucket_name)
                
                if 'LoggingEnabled' not in response:
                    findings.append(create_finding(
                        resource_name=bucket_name,
                        scan_id=scan_id,
                        severity='LOW',
                        title='CloudTrail S3 Bucket Access Logging Not Enabled',
                        description=f"S3 bucket '{bucket_name}' used by CloudTrail '{trail_name}' does not have access logging enabled",
                        remediation='Enable S3 access logging on the CloudTrail destination bucket',
                        cis_control='3.6',
                        resource_id=f"arn:aws:s3:::{bucket_name}"
                    ))
                    
            except ClientError as e:
                if e.response['Error']['Code'] == 'NoSuchBucket':
                    findings.append(create_finding(
                        resource_name=bucket_name,
                        scan_id=scan_id,
                        severity='HIGH',
                        title='CloudTrail S3 Bucket Does Not Exist',
                        description=f"S3 bucket '{bucket_name}' configured for CloudTrail '{trail_name}' does not exist",
                        remediation='Create the S3 bucket or update CloudTrail configuration',
                        cis_control='3.1',
                        resource_id=f"arn:aws:s3:::{bucket_name}"
                    ))
                else:
                    print(f"Error checking bucket logging for {bucket_name}: {str(e)}")
                    
    except Exception as e:
        print(f"Error checking CloudTrail bucket logging: {str(e)}")
    
    return findings
