"""
CloudGuard - VPC Security Check
Scans VPC configuration for security compliance issues
"""

import boto3
import json
import os
from datetime import datetime, timezone
from botocore.exceptions import ClientError

ec2_client = boto3.client('ec2')
dynamodb = boto3.resource('dynamodb')

FINDINGS_TABLE = os.environ.get('FINDINGS_TABLE', 'compliance-scanner-findings')


def lambda_handler(event, context):
    """
    Scans VPC configuration for security compliance
    """
    scan_id = event.get('scan_id', f"manual-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}")
    findings = []
    
    print(f"Starting VPC security scan: {scan_id}")
    
    # Check 1: VPC Flow Logs
    findings.extend(check_vpc_flow_logs(scan_id))
    
    # Check 2: Default Security Group
    findings.extend(check_default_security_groups(scan_id))
    
    # Check 3: Network ACLs
    findings.extend(check_network_acls(scan_id))
    
    # Check 4: VPC Peering Connections
    findings.extend(check_vpc_peering(scan_id))
    
    # Store findings in DynamoDB
    findings_table = dynamodb.Table(FINDINGS_TABLE)
    stored_count = 0
    
    for finding in findings:
        try:
            findings_table.put_item(Item=finding)
            stored_count += 1
        except Exception as e:
            print(f"Error storing finding: {str(e)}")
    
    print(f"VPC scan complete. Found {len(findings)} issues, stored {stored_count}")
    
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
        'finding_id': f"vpc-{title.lower().replace(' ', '-')[:30]}-{resource_name[:20]}-{scan_id}",
        'scan_date': now,
        'check_type': 'VPC_SECURITY',
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


def check_vpc_flow_logs(scan_id):
    """Check if VPC flow logs are enabled"""
    findings = []
    
    try:
        # Get all VPCs
        vpcs = ec2_client.describe_vpcs()
        
        # Get all flow logs
        flow_logs = ec2_client.describe_flow_logs()
        vpcs_with_flow_logs = set()
        
        for fl in flow_logs['FlowLogs']:
            if fl['ResourceType'] == 'VPC':
                vpcs_with_flow_logs.add(fl['ResourceId'])
        
        # Check each VPC
        for vpc in vpcs['Vpcs']:
            vpc_id = vpc['VpcId']
            
            # Get VPC name from tags
            vpc_name = vpc_id
            for tag in vpc.get('Tags', []):
                if tag['Key'] == 'Name':
                    vpc_name = tag['Value']
                    break
            
            if vpc_id not in vpcs_with_flow_logs:
                findings.append(create_finding(
                    resource_name=vpc_name,
                    scan_id=scan_id,
                    severity='MEDIUM',
                    title='VPC Flow Logs Not Enabled',
                    description=f"VPC '{vpc_name}' ({vpc_id}) does not have flow logs enabled",
                    remediation='Enable VPC flow logs for network traffic monitoring and security analysis',
                    cis_control='3.9',
                    resource_id=vpc_id
                ))
                
    except Exception as e:
        print(f"Error checking VPC flow logs: {str(e)}")
    
    return findings


def check_default_security_groups(scan_id):
    """Check if default security groups have rules"""
    findings = []
    
    try:
        paginator = ec2_client.get_paginator('describe_security_groups')
        
        for page in paginator.paginate(Filters=[{'Name': 'group-name', 'Values': ['default']}]):
            for sg in page['SecurityGroups']:
                sg_id = sg['GroupId']
                vpc_id = sg.get('VpcId', 'unknown')
                
                # Check if default SG has any ingress rules (other than self-referencing)
                has_risky_ingress = False
                for rule in sg.get('IpPermissions', []):
                    # Check for non-self-referencing rules
                    for ip_range in rule.get('IpRanges', []):
                        has_risky_ingress = True
                        break
                    for ip_range in rule.get('Ipv6Ranges', []):
                        has_risky_ingress = True
                        break
                    if has_risky_ingress:
                        break
                
                # Check egress rules
                has_risky_egress = False
                for rule in sg.get('IpPermissionsEgress', []):
                    for ip_range in rule.get('IpRanges', []):
                        if ip_range.get('CidrIp') == '0.0.0.0/0':
                            has_risky_egress = True
                            break
                    if has_risky_egress:
                        break
                
                if has_risky_ingress or has_risky_egress:
                    findings.append(create_finding(
                        resource_name=f"default-sg-{vpc_id}",
                        scan_id=scan_id,
                        severity='MEDIUM',
                        title='Default Security Group Has Rules',
                        description=f"Default security group ({sg_id}) in VPC {vpc_id} has ingress or egress rules configured",
                        remediation='Remove all inbound and outbound rules from default security groups',
                        cis_control='5.3',
                        resource_id=sg_id
                    ))
                    
    except Exception as e:
        print(f"Error checking default security groups: {str(e)}")
    
    return findings


def check_network_acls(scan_id):
    """Check Network ACLs for overly permissive rules"""
    findings = []
    
    try:
        paginator = ec2_client.get_paginator('describe_network_acls')
        
        for page in paginator.paginate():
            for nacl in page['NetworkAcls']:
                nacl_id = nacl['NetworkAclId']
                vpc_id = nacl.get('VpcId', 'unknown')
                
                # Get NACL name from tags
                nacl_name = nacl_id
                for tag in nacl.get('Tags', []):
                    if tag['Key'] == 'Name':
                        nacl_name = tag['Value']
                        break
                
                # Check entries
                for entry in nacl.get('Entries', []):
                    # Skip egress rules and deny rules
                    if entry.get('Egress', False) or entry.get('RuleAction') != 'allow':
                        continue
                    
                    cidr = entry.get('CidrBlock', '')
                    ipv6_cidr = entry.get('Ipv6CidrBlock', '')
                    
                    # Check for 0.0.0.0/0 or ::/0 allowing all traffic
                    if cidr == '0.0.0.0/0' or ipv6_cidr == '::/0':
                        protocol = entry.get('Protocol', '-1')
                        port_range = entry.get('PortRange', {})
                        
                        # -1 means all protocols
                        if protocol == '-1':
                            findings.append(create_finding(
                                resource_name=nacl_name,
                                scan_id=scan_id,
                                severity='HIGH',
                                title='Network ACL Allows All Traffic from Internet',
                                description=f"Network ACL '{nacl_name}' ({nacl_id}) allows all inbound traffic from 0.0.0.0/0",
                                remediation='Restrict Network ACL rules to specific ports and protocols',
                                cis_control='5.1',
                                resource_id=nacl_id
                            ))
                            break  # Only report once per NACL
                            
    except Exception as e:
        print(f"Error checking Network ACLs: {str(e)}")
    
    return findings


def check_vpc_peering(scan_id):
    """Check VPC peering connections for security review"""
    findings = []
    
    try:
        response = ec2_client.describe_vpc_peering_connections(
            Filters=[{'Name': 'status-code', 'Values': ['active']}]
        )
        
        for peering in response['VpcPeeringConnections']:
            peering_id = peering['VpcPeeringConnectionId']
            
            requester_vpc = peering.get('RequesterVpcInfo', {})
            accepter_vpc = peering.get('AccepterVpcInfo', {})
            
            requester_owner = requester_vpc.get('OwnerId', 'unknown')
            accepter_owner = accepter_vpc.get('OwnerId', 'unknown')
            
            # Check for cross-account peering
            if requester_owner != accepter_owner:
                findings.append(create_finding(
                    resource_name=peering_id,
                    scan_id=scan_id,
                    severity='LOW',
                    title='Cross-Account VPC Peering Connection',
                    description=f"VPC peering connection '{peering_id}' connects VPCs in different AWS accounts ({requester_owner} <-> {accepter_owner})",
                    remediation='Review cross-account VPC peering connections to ensure they are authorized',
                    cis_control='5.5',
                    resource_id=peering_id
                ))
            
            # Check peering options for DNS resolution
            requester_options = peering.get('RequesterVpcInfo', {}).get('PeeringOptions', {})
            accepter_options = peering.get('AccepterVpcInfo', {}).get('PeeringOptions', {})
            
            if requester_options.get('AllowDnsResolutionFromRemoteVpc') or \
               accepter_options.get('AllowDnsResolutionFromRemoteVpc'):
                findings.append(create_finding(
                    resource_name=peering_id,
                    scan_id=scan_id,
                    severity='LOW',
                    title='VPC Peering Allows DNS Resolution',
                    description=f"VPC peering connection '{peering_id}' allows DNS resolution from remote VPC",
                    remediation='Review if DNS resolution across VPC peering is required',
                    cis_control='5.5',
                    resource_id=peering_id
                ))
                
    except Exception as e:
        print(f"Error checking VPC peering: {str(e)}")
    
    return findings
