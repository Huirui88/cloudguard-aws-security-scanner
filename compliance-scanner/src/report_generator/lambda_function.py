"""
CloudGuard - Report Generator
Generates HTML and JSON compliance reports from scan findings
"""

import boto3
import json
import os
from datetime import datetime, timezone
from decimal import Decimal

dynamodb = boto3.resource('dynamodb')
s3_client = boto3.client('s3')
sns_client = boto3.client('sns')

FINDINGS_TABLE = os.environ.get('FINDINGS_TABLE', 'compliance-scanner-findings')
REPORT_BUCKET = os.environ.get('REPORT_BUCKET', 'compliance-reports-bucket')
SNS_TOPIC_ARN = os.environ.get('SNS_TOPIC_ARN', '')
SUMMARY_TOPIC_ARN = os.environ.get('SUMMARY_TOPIC_ARN', '')


class DecimalEncoder(json.JSONEncoder):
    """Custom JSON encoder for Decimal types"""
    def default(self, obj):
        if isinstance(obj, Decimal):
            return int(obj) if obj % 1 == 0 else float(obj)
        return super().default(obj)


def lambda_handler(event, context):
    """
    Generates compliance reports from findings
    """
    scan_id = event.get('scan_id', f"manual-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}")
    
    print(f"Generating report for scan: {scan_id}")
    
    # Query all findings with status=OPEN
    findings_table = dynamodb.Table(FINDINGS_TABLE)
    
    try:
        response = findings_table.scan(
            FilterExpression='#status = :status',
            ExpressionAttributeNames={'#status': 'status'},
            ExpressionAttributeValues={':status': 'OPEN'}
        )
        findings = response.get('Items', [])
        
        # Handle pagination
        while 'LastEvaluatedKey' in response:
            response = findings_table.scan(
                FilterExpression='#status = :status',
                ExpressionAttributeNames={'#status': 'status'},
                ExpressionAttributeValues={':status': 'OPEN'},
                ExclusiveStartKey=response['LastEvaluatedKey']
            )
            findings.extend(response.get('Items', []))
            
    except Exception as e:
        print(f"Error querying findings: {str(e)}")
        return {'statusCode': 500, 'error': str(e)}
    
    print(f"Found {len(findings)} open findings")
    
    # Group findings by severity
    summary = {
        'CRITICAL': [],
        'HIGH': [],
        'MEDIUM': [],
        'LOW': []
    }
    
    for finding in findings:
        severity = finding.get('severity', 'LOW')
        if severity in summary:
            summary[severity].append(finding)
    
    # Generate reports
    timestamp = datetime.now(timezone.utc).strftime('%Y-%m-%d')
    
    # Generate HTML report
    html_report = generate_html_report(summary, scan_id)
    
    # Generate JSON report
    json_report = json.dumps({
        'scan_id': scan_id,
        'scan_date': datetime.now(timezone.utc).isoformat(),
        'summary': {
            'critical': len(summary['CRITICAL']),
            'high': len(summary['HIGH']),
            'medium': len(summary['MEDIUM']),
            'low': len(summary['LOW']),
            'total': len(findings)
        },
        'findings': findings
    }, indent=2, cls=DecimalEncoder)
    
    # Upload reports to S3
    try:
        s3_client.put_object(
            Bucket=REPORT_BUCKET,
            Key=f"reports/{timestamp}/compliance-report.html",
            Body=html_report,
            ContentType='text/html'
        )
        
        s3_client.put_object(
            Bucket=REPORT_BUCKET,
            Key=f"reports/{timestamp}/compliance-report.json",
            Body=json_report,
            ContentType='application/json'
        )
        
        print(f"Reports uploaded to s3://{REPORT_BUCKET}/reports/{timestamp}/")
        
    except Exception as e:
        print(f"Error uploading reports: {str(e)}")
    
    # Send SNS notification if critical findings
    if len(summary['CRITICAL']) > 0 and SNS_TOPIC_ARN:
        try:
            sns_client.publish(
                TopicArn=SNS_TOPIC_ARN,
                Subject=f"🚨 {len(summary['CRITICAL'])} Critical Security Findings Detected",
                Message=format_critical_alert(summary, scan_id, timestamp)
            )
            print("Critical findings alert sent")
        except Exception as e:
            print(f"Error sending SNS notification: {str(e)}")
    
    # Send daily summary
    if SUMMARY_TOPIC_ARN:
        try:
            sns_client.publish(
                TopicArn=SUMMARY_TOPIC_ARN,
                Subject=f"📊 Daily Security Compliance Summary - {timestamp}",
                Message=format_daily_summary(summary, scan_id, timestamp)
            )
            print("Daily summary sent")
        except Exception as e:
            print(f"Error sending daily summary: {str(e)}")
    
    report_url = f"https://{REPORT_BUCKET}.s3.amazonaws.com/reports/{timestamp}/compliance-report.html"
    
    return {
        'statusCode': 200,
        'body': json.dumps({
            'scan_id': scan_id,
            'findings_count': len(findings),
            'report_url': report_url,
            'summary': {
                'critical': len(summary['CRITICAL']),
                'high': len(summary['HIGH']),
                'medium': len(summary['MEDIUM']),
                'low': len(summary['LOW'])
            }
        })
    }


def format_critical_alert(summary, scan_id, timestamp):
    """Format critical findings alert message"""
    message = f"""
⚠️ SECURITY ALERT: Critical findings detected!

Scan ID: {scan_id}
Date: {timestamp}

📊 SUMMARY:
━━━━━━━━━━━━━━━━━━━━━━━━━━
🔴 Critical: {len(summary['CRITICAL'])}
🟠 High: {len(summary['HIGH'])}
🟡 Medium: {len(summary['MEDIUM'])}
🟢 Low: {len(summary['LOW'])}
━━━━━━━━━━━━━━━━━━━━━━━━━━

🚨 CRITICAL FINDINGS:
"""
    
    for finding in summary['CRITICAL'][:10]:  # Limit to first 10
        message += f"""
• {finding.get('title', 'Unknown')}
  Resource: {finding.get('resource_name', 'Unknown')}
  Description: {finding.get('description', 'No description')}
  Remediation: {finding.get('remediation', 'No remediation provided')}
"""
    
    if len(summary['CRITICAL']) > 10:
        message += f"\n... and {len(summary['CRITICAL']) - 10} more critical findings\n"
    
    message += f"\nPlease review and remediate these findings immediately."
    
    return message


def format_daily_summary(summary, scan_id, timestamp):
    """Format daily summary message"""
    total = sum(len(findings) for findings in summary.values())
    
    message = f"""
📊 Daily Security Compliance Report

Scan ID: {scan_id}
Date: {timestamp}

━━━━━━━━━━━━━━━━━━━━━━━━━━
FINDINGS SUMMARY
━━━━━━━━━━━━━━━━━━━━━━━━━━
🔴 Critical: {len(summary['CRITICAL'])}
🟠 High: {len(summary['HIGH'])}
🟡 Medium: {len(summary['MEDIUM'])}
🟢 Low: {len(summary['LOW'])}
━━━━━━━━━━━━━━━━━━━━━━━━━━
📈 Total: {total}
━━━━━━━━━━━━━━━━━━━━━━━━━━

"""
    
    if len(summary['CRITICAL']) > 0:
        message += "🚨 CRITICAL ISSUES REQUIRING IMMEDIATE ATTENTION:\n"
        for finding in summary['CRITICAL'][:5]:
            message += f"  • {finding.get('title', 'Unknown')} - {finding.get('resource_name', 'Unknown')}\n"
        if len(summary['CRITICAL']) > 5:
            message += f"  ... and {len(summary['CRITICAL']) - 5} more\n"
        message += "\n"
    
    if len(summary['HIGH']) > 0:
        message += "⚠️ HIGH PRIORITY ISSUES:\n"
        for finding in summary['HIGH'][:5]:
            message += f"  • {finding.get('title', 'Unknown')} - {finding.get('resource_name', 'Unknown')}\n"
        if len(summary['HIGH']) > 5:
            message += f"  ... and {len(summary['HIGH']) - 5} more\n"
        message += "\n"
    
    message += "Please review the full report for details and remediation steps."
    
    return message


def generate_html_report(summary, scan_id):
    """Generates HTML compliance report"""
    total_findings = sum(len(findings) for findings in summary.values())
    timestamp = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')
    
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Compliance Report - {scan_id}</title>
    <style>
        :root {{
            --critical-color: #dc3545;
            --high-color: #fd7e14;
            --medium-color: #ffc107;
            --low-color: #28a745;
            --bg-color: #f8f9fa;
            --card-bg: #ffffff;
            --text-color: #212529;
            --border-color: #dee2e6;
        }}
        
        * {{
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }}
        
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background-color: var(--bg-color);
            color: var(--text-color);
            line-height: 1.6;
            padding: 20px;
        }}
        
        .container {{
            max-width: 1200px;
            margin: 0 auto;
        }}
        
        header {{
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            color: white;
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 30px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
        }}
        
        header h1 {{
            font-size: 2rem;
            margin-bottom: 10px;
            display: flex;
            align-items: center;
            gap: 10px;
        }}
        
        .meta {{
            display: flex;
            gap: 30px;
            font-size: 0.9rem;
            opacity: 0.9;
        }}
        
        .summary-cards {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        
        .card {{
            background: var(--card-bg);
            border-radius: 10px;
            padding: 20px;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.05);
            border-left: 4px solid;
            transition: transform 0.2s;
        }}
        
        .card:hover {{
            transform: translateY(-2px);
        }}
        
        .card.critical {{ border-left-color: var(--critical-color); }}
        .card.high {{ border-left-color: var(--high-color); }}
        .card.medium {{ border-left-color: var(--medium-color); }}
        .card.low {{ border-left-color: var(--low-color); }}
        
        .card h3 {{
            font-size: 0.9rem;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-bottom: 5px;
        }}
        
        .card .count {{
            font-size: 2.5rem;
            font-weight: bold;
        }}
        
        .card.critical .count {{ color: var(--critical-color); }}
        .card.high .count {{ color: var(--high-color); }}
        .card.medium .count {{ color: var(--medium-color); }}
        .card.low .count {{ color: var(--low-color); }}
        
        .findings-section {{
            margin-bottom: 30px;
        }}
        
        .findings-section h2 {{
            font-size: 1.3rem;
            padding: 15px 20px;
            border-radius: 8px;
            margin-bottom: 15px;
            display: flex;
            align-items: center;
            gap: 10px;
        }}
        
        .findings-section.critical h2 {{ background: #fce4e4; color: var(--critical-color); }}
        .findings-section.high h2 {{ background: #fff3e0; color: var(--high-color); }}
        .findings-section.medium h2 {{ background: #fff8e1; color: #856404; }}
        .findings-section.low h2 {{ background: #e8f5e9; color: #155724; }}
        
        .finding {{
            background: var(--card-bg);
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 15px;
            box-shadow: 0 1px 3px rgba(0, 0, 0, 0.05);
            border: 1px solid var(--border-color);
        }}
        
        .finding h3 {{
            font-size: 1.1rem;
            margin-bottom: 15px;
            color: #1a1a2e;
        }}
        
        .finding-details {{
            display: grid;
            gap: 10px;
        }}
        
        .finding-details p {{
            margin: 0;
            padding: 8px 12px;
            background: var(--bg-color);
            border-radius: 4px;
            font-size: 0.9rem;
        }}
        
        .finding-details strong {{
            color: #495057;
            margin-right: 8px;
        }}
        
        .cis-badge {{
            display: inline-block;
            background: #e9ecef;
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 0.8rem;
            font-weight: 500;
        }}
        
        footer {{
            text-align: center;
            padding: 20px;
            color: #6c757d;
            font-size: 0.9rem;
        }}
        
        @media (max-width: 768px) {{
            .meta {{
                flex-direction: column;
                gap: 5px;
            }}
            
            header h1 {{
                font-size: 1.5rem;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🛡️ Security Compliance Report</h1>
            <div class="meta">
                <span><strong>Scan ID:</strong> {scan_id}</span>
                <span><strong>Generated:</strong> {timestamp}</span>
                <span><strong>Total Findings:</strong> {total_findings}</span>
            </div>
        </header>
        
        <div class="summary-cards">
            <div class="card critical">
                <h3>Critical</h3>
                <div class="count">{len(summary['CRITICAL'])}</div>
            </div>
            <div class="card high">
                <h3>High</h3>
                <div class="count">{len(summary['HIGH'])}</div>
            </div>
            <div class="card medium">
                <h3>Medium</h3>
                <div class="count">{len(summary['MEDIUM'])}</div>
            </div>
            <div class="card low">
                <h3>Low</h3>
                <div class="count">{len(summary['LOW'])}</div>
            </div>
        </div>
"""
    
    # Add findings for each severity
    severity_icons = {
        'CRITICAL': '🔴',
        'HIGH': '🟠',
        'MEDIUM': '🟡',
        'LOW': '🟢'
    }
    
    for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
        if summary[severity]:
            html += f"""
        <div class="findings-section {severity.lower()}">
            <h2>{severity_icons[severity]} {severity} Findings ({len(summary[severity])})</h2>
"""
            for finding in summary[severity]:
                html += f"""
            <div class="finding">
                <h3>{finding.get('title', 'Unknown Finding')}</h3>
                <div class="finding-details">
                    <p><strong>Resource:</strong> {finding.get('resource_name', 'Unknown')}</p>
                    <p><strong>Description:</strong> {finding.get('description', 'No description available')}</p>
                    <p><strong>Remediation:</strong> {finding.get('remediation', 'No remediation provided')}</p>
                    <p><strong>CIS Control:</strong> <span class="cis-badge">{finding.get('cis_control', 'N/A')}</span></p>
                    <p><strong>First Detected:</strong> {finding.get('first_detected', 'Unknown')}</p>
                </div>
            </div>
"""
            html += "        </div>\n"
    
    html += """
        <footer>
            <p>Generated by CloudGuard - AWS Security Compliance Scanner</p>
            <p>Powered by Anthropic Claude</p>
        </footer>
    </div>
</body>
</html>
"""
    return html
