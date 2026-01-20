"""
CloudGuard - Shared Utilities
Common functions used across Lambda functions
"""

import json
from datetime import datetime, timezone
from decimal import Decimal


class DecimalEncoder(json.JSONEncoder):
    """Custom JSON encoder for Decimal types from DynamoDB"""
    def default(self, obj):
        if isinstance(obj, Decimal):
            return int(obj) if obj % 1 == 0 else float(obj)
        return super().default(obj)


def get_current_timestamp():
    """Get current UTC timestamp in ISO format"""
    return datetime.now(timezone.utc).isoformat()


def create_finding(
    resource_name: str,
    scan_id: str,
    check_type: str,
    severity: str,
    title: str,
    description: str,
    remediation: str,
    cis_control: str,
    resource_id: str = None
) -> dict:
    """
    Create a standardized security finding
    
    Args:
        resource_name: Human-readable name of the resource
        scan_id: ID of the current scan
        check_type: Category of check (S3_SECURITY, IAM_SECURITY, etc.)
        severity: CRITICAL, HIGH, MEDIUM, or LOW
        title: Short title of the finding
        description: Detailed description of the issue
        remediation: Steps to remediate the finding
        cis_control: CIS benchmark control reference
        resource_id: ARN or ID of the resource (optional)
    
    Returns:
        dict: Finding object ready for DynamoDB
    """
    now = get_current_timestamp()
    
    # Create a safe finding ID
    safe_title = title.lower().replace(' ', '-')[:30]
    safe_resource = resource_name[:20].replace('/', '-').replace(':', '-')
    
    return {
        'finding_id': f"{check_type.lower()}-{safe_title}-{safe_resource}-{scan_id}",
        'scan_date': now,
        'check_type': check_type,
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


def severity_priority(severity: str) -> int:
    """Get numeric priority for severity (lower = more severe)"""
    priorities = {
        'CRITICAL': 1,
        'HIGH': 2,
        'MEDIUM': 3,
        'LOW': 4
    }
    return priorities.get(severity, 5)


def format_finding_summary(findings: list) -> dict:
    """
    Summarize a list of findings by severity
    
    Args:
        findings: List of finding dictionaries
    
    Returns:
        dict: Summary with counts by severity
    """
    summary = {
        'CRITICAL': 0,
        'HIGH': 0,
        'MEDIUM': 0,
        'LOW': 0,
        'total': 0
    }
    
    for finding in findings:
        severity = finding.get('severity', 'LOW')
        if severity in summary:
            summary[severity] += 1
        summary['total'] += 1
    
    return summary


def sanitize_for_dynamodb(item: dict) -> dict:
    """
    Sanitize a dictionary for DynamoDB storage
    Removes empty strings and None values
    
    Args:
        item: Dictionary to sanitize
    
    Returns:
        dict: Sanitized dictionary
    """
    return {k: v for k, v in item.items() if v is not None and v != ''}


def batch_items(items: list, batch_size: int = 25) -> list:
    """
    Split a list into batches for DynamoDB batch writes
    
    Args:
        items: List of items to batch
        batch_size: Maximum items per batch (default 25 for DynamoDB)
    
    Returns:
        list: List of batches
    """
    return [items[i:i + batch_size] for i in range(0, len(items), batch_size)]
