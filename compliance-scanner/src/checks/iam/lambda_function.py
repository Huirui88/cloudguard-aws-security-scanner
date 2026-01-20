"""
CloudGuard - IAM Security Check
Scans IAM configuration for security compliance issues
"""

import boto3
import json
import os
from datetime import datetime, timezone, timedelta
from botocore.exceptions import ClientError
import time

iam_client = boto3.client('iam')
dynamodb = boto3.resource('dynamodb')

FINDINGS_TABLE = os.environ.get('FINDINGS_TABLE', 'compliance-scanner-findings')


def lambda_handler(event, context):
    """
    Scans IAM configuration for security compliance
    """
    scan_id = event.get('scan_id', f"manual-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}")
    findings = []
    
    print(f"Starting IAM security scan: {scan_id}")
    
    # Check 1: Root account MFA
    findings.extend(check_root_mfa(scan_id))
    
    # Check 2: Root account access keys
    findings.extend(check_root_access_keys(scan_id))
    
    # Check 3: Password policy
    findings.extend(check_password_policy(scan_id))
    
    # Check 4: Unused credentials
    findings.extend(check_unused_credentials(scan_id))
    
    # Check 5: Users with admin privileges
    findings.extend(check_admin_privileges(scan_id))
    
    # Check 6: Policies with wildcard permissions
    findings.extend(check_wildcard_policies(scan_id))
    
    # Store findings in DynamoDB
    findings_table = dynamodb.Table(FINDINGS_TABLE)
    stored_count = 0
    
    for finding in findings:
        try:
            findings_table.put_item(Item=finding)
            stored_count += 1
        except Exception as e:
            print(f"Error storing finding: {str(e)}")
    
    print(f"IAM scan complete. Found {len(findings)} issues, stored {stored_count}")
    
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
        'finding_id': f"iam-{title.lower().replace(' ', '-')[:30]}-{resource_name[:20]}-{scan_id}",
        'scan_date': now,
        'check_type': 'IAM_SECURITY',
        'resource_id': resource_id or f"arn:aws:iam:::user/{resource_name}",
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


def check_root_mfa(scan_id):
    """Check if root account has MFA enabled"""
    findings = []
    
    try:
        response = iam_client.get_account_summary()
        summary = response['SummaryMap']
        
        if summary.get('AccountMFAEnabled', 0) != 1:
            findings.append(create_finding(
                resource_name='root',
                scan_id=scan_id,
                severity='CRITICAL',
                title='Root Account MFA Not Enabled',
                description='The AWS root account does not have MFA enabled',
                remediation='Enable MFA for the root account using a hardware MFA device or virtual MFA',
                cis_control='1.5',
                resource_id='arn:aws:iam:::root'
            ))
            
    except Exception as e:
        print(f"Error checking root MFA: {str(e)}")
    
    return findings


def check_root_access_keys(scan_id):
    """Check if root account has access keys"""
    findings = []
    
    try:
        # Generate credential report
        try:
            iam_client.generate_credential_report()
            time.sleep(2)  # Wait for report generation
        except ClientError as e:
            if 'ReportInProgress' not in str(e):
                raise
        
        response = iam_client.get_credential_report()
        report = response['Content'].decode('utf-8')
        
        # Parse CSV report
        lines = report.split('\n')
        headers = lines[0].split(',')
        
        for line in lines[1:]:
            if not line:
                continue
            values = line.split(',')
            user_data = dict(zip(headers, values))
            
            if user_data.get('user') == '<root_account>':
                if user_data.get('access_key_1_active', 'false').lower() == 'true' or \
                   user_data.get('access_key_2_active', 'false').lower() == 'true':
                    findings.append(create_finding(
                        resource_name='root',
                        scan_id=scan_id,
                        severity='CRITICAL',
                        title='Root Account Has Active Access Keys',
                        description='The AWS root account has active access keys, which is a security risk',
                        remediation='Delete all access keys for the root account and use IAM users instead',
                        cis_control='1.4',
                        resource_id='arn:aws:iam:::root'
                    ))
                break
                
    except Exception as e:
        print(f"Error checking root access keys: {str(e)}")
    
    return findings


def check_password_policy(scan_id):
    """Check if password policy meets requirements"""
    findings = []
    
    try:
        response = iam_client.get_account_password_policy()
        policy = response['PasswordPolicy']
        
        # Check minimum length
        if policy.get('MinimumPasswordLength', 0) < 14:
            findings.append(create_finding(
                resource_name='password-policy',
                scan_id=scan_id,
                severity='MEDIUM',
                title='Password Policy Minimum Length Too Short',
                description=f"Password policy minimum length is {policy.get('MinimumPasswordLength', 0)}, should be at least 14",
                remediation='Update password policy to require minimum 14 character passwords',
                cis_control='1.8',
                resource_id='arn:aws:iam:::account-password-policy'
            ))
        
        # Check password reuse prevention
        if policy.get('PasswordReusePrevention', 0) < 24:
            findings.append(create_finding(
                resource_name='password-policy',
                scan_id=scan_id,
                severity='LOW',
                title='Password Reuse Prevention Not Configured',
                description='Password policy does not prevent reuse of last 24 passwords',
                remediation='Update password policy to prevent reuse of last 24 passwords',
                cis_control='1.10',
                resource_id='arn:aws:iam:::account-password-policy'
            ))
        
        # Check password expiration
        if not policy.get('MaxPasswordAge'):
            findings.append(create_finding(
                resource_name='password-policy',
                scan_id=scan_id,
                severity='LOW',
                title='Password Expiration Not Configured',
                description='Password policy does not enforce password expiration',
                remediation='Update password policy to require password rotation every 90 days or less',
                cis_control='1.11',
                resource_id='arn:aws:iam:::account-password-policy'
            ))
            
    except ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchEntity':
            findings.append(create_finding(
                resource_name='password-policy',
                scan_id=scan_id,
                severity='HIGH',
                title='No Password Policy Configured',
                description='No custom password policy is configured for this account',
                remediation='Create a password policy that enforces complexity requirements',
                cis_control='1.5-1.11',
                resource_id='arn:aws:iam:::account-password-policy'
            ))
        else:
            print(f"Error checking password policy: {str(e)}")
    except Exception as e:
        print(f"Error checking password policy: {str(e)}")
    
    return findings


def check_unused_credentials(scan_id):
    """Check for unused credentials (>90 days)"""
    findings = []
    threshold_days = 90
    threshold_date = datetime.now(timezone.utc) - timedelta(days=threshold_days)
    
    try:
        # Generate credential report
        try:
            iam_client.generate_credential_report()
            time.sleep(2)
        except ClientError as e:
            if 'ReportInProgress' not in str(e):
                raise
        
        response = iam_client.get_credential_report()
        report = response['Content'].decode('utf-8')
        
        lines = report.split('\n')
        headers = lines[0].split(',')
        
        for line in lines[1:]:
            if not line:
                continue
            values = line.split(',')
            user_data = dict(zip(headers, values))
            
            username = user_data.get('user', 'unknown')
            if username == '<root_account>':
                continue
            
            # Check password last used
            password_last_used = user_data.get('password_last_used', 'N/A')
            if password_last_used not in ['N/A', 'no_information', 'not_supported']:
                try:
                    last_used = datetime.fromisoformat(password_last_used.replace('Z', '+00:00'))
                    if last_used < threshold_date:
                        findings.append(create_finding(
                            resource_name=username,
                            scan_id=scan_id,
                            severity='MEDIUM',
                            title='Unused IAM User Password',
                            description=f"User '{username}' has not used their password in over {threshold_days} days",
                            remediation='Disable or delete unused IAM user credentials',
                            cis_control='1.3',
                            resource_id=f"arn:aws:iam:::user/{username}"
                        ))
                except (ValueError, AttributeError):
                    pass
            
            # Check access key 1
            key1_active = user_data.get('access_key_1_active', 'false').lower() == 'true'
            key1_last_used = user_data.get('access_key_1_last_used_date', 'N/A')
            
            if key1_active and key1_last_used not in ['N/A', 'no_information']:
                try:
                    last_used = datetime.fromisoformat(key1_last_used.replace('Z', '+00:00'))
                    if last_used < threshold_date:
                        findings.append(create_finding(
                            resource_name=username,
                            scan_id=scan_id,
                            severity='MEDIUM',
                            title='Unused IAM Access Key',
                            description=f"User '{username}' has an access key not used in over {threshold_days} days",
                            remediation='Rotate or delete unused access keys',
                            cis_control='1.3',
                            resource_id=f"arn:aws:iam:::user/{username}/accesskey/1"
                        ))
                except (ValueError, AttributeError):
                    pass
                    
    except Exception as e:
        print(f"Error checking unused credentials: {str(e)}")
    
    return findings


def check_admin_privileges(scan_id):
    """Check for users with administrative privileges"""
    findings = []
    admin_policies = ['AdministratorAccess', 'PowerUserAccess']
    
    try:
        paginator = iam_client.get_paginator('list_users')
        
        for page in paginator.paginate():
            for user in page['Users']:
                username = user['UserName']
                has_admin = False
                
                # Check attached policies
                try:
                    attached = iam_client.list_attached_user_policies(UserName=username)
                    for policy in attached['AttachedPolicies']:
                        if policy['PolicyName'] in admin_policies:
                            has_admin = True
                            break
                except Exception as e:
                    print(f"Error checking attached policies for {username}: {str(e)}")
                
                # Check inline policies for admin-like permissions
                if not has_admin:
                    try:
                        inline = iam_client.list_user_policies(UserName=username)
                        for policy_name in inline['PolicyNames']:
                            policy_doc = iam_client.get_user_policy(
                                UserName=username,
                                PolicyName=policy_name
                            )
                            doc = policy_doc['PolicyDocument']
                            if has_admin_permissions(doc):
                                has_admin = True
                                break
                    except Exception as e:
                        print(f"Error checking inline policies for {username}: {str(e)}")
                
                if has_admin:
                    findings.append(create_finding(
                        resource_name=username,
                        scan_id=scan_id,
                        severity='HIGH',
                        title='IAM User Has Administrative Privileges',
                        description=f"User '{username}' has administrative access to the AWS account",
                        remediation='Review if administrative access is required. Consider using more restrictive policies.',
                        cis_control='1.16',
                        resource_id=f"arn:aws:iam:::user/{username}"
                    ))
                    
    except Exception as e:
        print(f"Error checking admin privileges: {str(e)}")
    
    return findings


def has_admin_permissions(policy_document):
    """Check if a policy document grants admin-like permissions"""
    statements = policy_document.get('Statement', [])
    
    for statement in statements:
        if statement.get('Effect') != 'Allow':
            continue
            
        actions = statement.get('Action', [])
        resources = statement.get('Resource', [])
        
        if isinstance(actions, str):
            actions = [actions]
        if isinstance(resources, str):
            resources = [resources]
        
        # Check for * actions on * resources
        if '*' in actions and '*' in resources:
            return True
    
    return False


def check_wildcard_policies(scan_id):
    """Check for policies with wildcard permissions"""
    findings = []
    
    try:
        paginator = iam_client.get_paginator('list_policies')
        
        for page in paginator.paginate(Scope='Local'):  # Only customer managed policies
            for policy in page['Policies']:
                policy_name = policy['PolicyName']
                policy_arn = policy['Arn']
                
                try:
                    # Get the default version of the policy
                    version_id = policy['DefaultVersionId']
                    policy_version = iam_client.get_policy_version(
                        PolicyArn=policy_arn,
                        VersionId=version_id
                    )
                    
                    doc = policy_version['PolicyVersion']['Document']
                    if has_dangerous_wildcards(doc):
                        findings.append(create_finding(
                            resource_name=policy_name,
                            scan_id=scan_id,
                            severity='HIGH',
                            title='IAM Policy Has Dangerous Wildcard Permissions',
                            description=f"Policy '{policy_name}' contains wildcard (*) permissions that may be overly permissive",
                            remediation='Review and restrict wildcard permissions to specific actions and resources',
                            cis_control='1.22',
                            resource_id=policy_arn
                        ))
                        
                except Exception as e:
                    print(f"Error checking policy {policy_name}: {str(e)}")
                    
    except Exception as e:
        print(f"Error checking wildcard policies: {str(e)}")
    
    return findings


def has_dangerous_wildcards(policy_document):
    """Check if a policy has dangerous wildcard permissions"""
    statements = policy_document.get('Statement', [])
    dangerous_action_patterns = ['iam:*', 's3:*', 'ec2:*', 'rds:*', 'lambda:*']
    
    for statement in statements:
        if statement.get('Effect') != 'Allow':
            continue
            
        actions = statement.get('Action', [])
        resources = statement.get('Resource', [])
        
        if isinstance(actions, str):
            actions = [actions]
        if isinstance(resources, str):
            resources = [resources]
        
        # Check for dangerous patterns
        if '*' in resources:
            for action in actions:
                if action == '*' or action in dangerous_action_patterns:
                    return True
    
    return False
