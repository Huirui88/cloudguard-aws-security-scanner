"""
CloudGuard - Scanner Orchestrator
Coordinates all security compliance checks
"""

import boto3
import json
import os
from datetime import datetime, timezone
import time

lambda_client = boto3.client('lambda')
dynamodb = boto3.resource('dynamodb')

# Environment variables
FINDINGS_TABLE = os.environ.get('FINDINGS_TABLE', 'compliance-scanner-findings')
SCAN_HISTORY_TABLE = os.environ.get('SCAN_HISTORY_TABLE', 'compliance-scanner-scan-history')
CHECK_S3_FUNCTION = os.environ.get('CHECK_S3_FUNCTION')
CHECK_IAM_FUNCTION = os.environ.get('CHECK_IAM_FUNCTION')
CHECK_EC2_FUNCTION = os.environ.get('CHECK_EC2_FUNCTION')
CHECK_VPC_FUNCTION = os.environ.get('CHECK_VPC_FUNCTION')
CHECK_CLOUDTRAIL_FUNCTION = os.environ.get('CHECK_CLOUDTRAIL_FUNCTION')
REPORT_FUNCTION = os.environ.get('REPORT_FUNCTION')


def lambda_handler(event, context):
    """
    Orchestrates security compliance scans across all check functions
    """
    scan_id = f"scan-{datetime.now(timezone.utc).strftime('%Y-%m-%d-%H-%M-%S')}"
    scan_start = datetime.now(timezone.utc)
    
    print(f"Starting compliance scan: {scan_id}")
    
    # List of check functions to invoke
    check_functions = [
        ('S3_SECURITY', CHECK_S3_FUNCTION),
        ('IAM_SECURITY', CHECK_IAM_FUNCTION),
        ('EC2_SECURITY', CHECK_EC2_FUNCTION),
        ('VPC_SECURITY', CHECK_VPC_FUNCTION),
        ('CLOUDTRAIL', CHECK_CLOUDTRAIL_FUNCTION),
    ]
    
    results = []
    checks_performed = []
    
    # Invoke each check function asynchronously
    for check_type, function_name in check_functions:
        if not function_name:
            print(f"Skipping {check_type} - function not configured")
            continue
            
        try:
            response = lambda_client.invoke(
                FunctionName=function_name,
                InvocationType='Event',  # Async invocation
                Payload=json.dumps({
                    'scan_id': scan_id,
                    'timestamp': datetime.now(timezone.utc).isoformat(),
                    'check_type': check_type
                })
            )
            
            results.append({
                'function': function_name,
                'check_type': check_type,
                'status': 'invoked',
                'status_code': response['StatusCode']
            })
            checks_performed.append(check_type)
            print(f"Invoked {check_type} check: {function_name}")
            
        except Exception as e:
            print(f"Error invoking {function_name}: {str(e)}")
            results.append({
                'function': function_name,
                'check_type': check_type,
                'status': 'failed',
                'error': str(e)
            })
    
    # Record scan history
    try:
        scan_history_table = dynamodb.Table(SCAN_HISTORY_TABLE)
        scan_history_table.put_item(Item={
            'scan_id': scan_id,
            'scan_date': scan_start.isoformat(),
            'status': 'IN_PROGRESS',
            'checks_performed': checks_performed,
            'invocation_results': results
        })
    except Exception as e:
        print(f"Error recording scan history: {str(e)}")
    
    # Schedule report generation after a delay to allow checks to complete
    # In production, use Step Functions for proper orchestration
    if REPORT_FUNCTION:
        try:
            # Use a slight delay for async checks to complete
            # In production, use Step Functions or callbacks
            lambda_client.invoke(
                FunctionName=REPORT_FUNCTION,
                InvocationType='Event',
                Payload=json.dumps({
                    'scan_id': scan_id,
                    'delay_seconds': 120  # Wait 2 minutes for checks to complete
                })
            )
            print(f"Scheduled report generation for scan: {scan_id}")
        except Exception as e:
            print(f"Error scheduling report generation: {str(e)}")
    
    return {
        'statusCode': 200,
        'body': json.dumps({
            'scan_id': scan_id,
            'checks_triggered': len([r for r in results if r['status'] == 'invoked']),
            'checks_failed': len([r for r in results if r['status'] == 'failed']),
            'results': results
        })
    }
