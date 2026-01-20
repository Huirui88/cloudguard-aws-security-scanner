"""
CloudGuard - EC2 Security Check
Scans EC2 instances and security groups for security compliance issues
"""

import boto3
import json
import os
from datetime import datetime, timezone
from botocore.exceptions import ClientError

ec2_client = boto3.client('ec2')
dynamodb = boto3.resource('dynamodb')

FINDINGS_TABLE = os.environ.get('FINDINGS_TABLE', 'compliance-scanner-findings')

# Risky ports that should not be open to the world
RISKY_PORTS = {
    22: 'SSH',
    3389: 'RDP',
    3306: 'MySQL',
    5432: 'PostgreSQL',
    1433: 'MSSQL',
    27017: 'MongoDB',
    6379: 'Redis',
    11211: 'Memcached',
    9200: 'Elasticsearch',
    5601: 'Kibana',
    23: 'Telnet',
    21: 'FTP',
    445: 'SMB',
    135: 'RPC'
}


def lambda_handler(event, context):
    """
    Scans EC2 instances and security groups for security compliance
    """
    scan_id = event.get('scan_id', f"manual-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}")
    findings = []
    
    print(f"Starting EC2 security scan: {scan_id}")
    
    # Check 1: Security groups with risky open ports
    findings.extend(check_security_groups(scan_id))
    
    # Check 2: Unencrypted EBS volumes
    findings.extend(check_ebs_encryption(scan_id))
    
    # Check 3: IMDSv2 not enabled
    findings.extend(check_imdsv2(scan_id))
    
    # Check 4: Public AMIs
    findings.extend(check_public_amis(scan_id))
    
    # Check 5: Instances in public subnets
    findings.extend(check_public_instances(scan_id))
    
    # Check 6: Unused security groups
    findings.extend(check_unused_security_groups(scan_id))
    
    # Store findings in DynamoDB
    findings_table = dynamodb.Table(FINDINGS_TABLE)
    stored_count = 0
    
    for finding in findings:
        try:
            findings_table.put_item(Item=finding)
            stored_count += 1
        except Exception as e:
            print(f"Error storing finding: {str(e)}")
    
    print(f"EC2 scan complete. Found {len(findings)} issues, stored {stored_count}")
    
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
        'finding_id': f"ec2-{title.lower().replace(' ', '-')[:30]}-{resource_name[:20]}-{scan_id}",
        'scan_date': now,
        'check_type': 'EC2_SECURITY',
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


def check_security_groups(scan_id):
    """Check security groups for risky open ports"""
    findings = []
    
    try:
        paginator = ec2_client.get_paginator('describe_security_groups')
        
        for page in paginator.paginate():
            for sg in page['SecurityGroups']:
                sg_id = sg['GroupId']
                sg_name = sg.get('GroupName', sg_id)
                
                for rule in sg.get('IpPermissions', []):
                    from_port = rule.get('FromPort', 0)
                    to_port = rule.get('ToPort', 65535)
                    
                    # Check for 0.0.0.0/0 or ::/0
                    for ip_range in rule.get('IpRanges', []):
                        if ip_range.get('CidrIp') == '0.0.0.0/0':
                            finding = check_risky_port_range(sg_id, sg_name, from_port, to_port, scan_id, 'IPv4')
                            if finding:
                                findings.append(finding)
                    
                    for ip_range in rule.get('Ipv6Ranges', []):
                        if ip_range.get('CidrIpv6') == '::/0':
                            finding = check_risky_port_range(sg_id, sg_name, from_port, to_port, scan_id, 'IPv6')
                            if finding:
                                findings.append(finding)
                                
    except Exception as e:
        print(f"Error checking security groups: {str(e)}")
    
    return findings


def check_risky_port_range(sg_id, sg_name, from_port, to_port, scan_id, ip_version):
    """Check if a port range includes risky ports"""
    for port, service in RISKY_PORTS.items():
        if from_port <= port <= to_port:
            severity = 'CRITICAL' if port in [22, 3389, 3306, 5432] else 'HIGH'
            return create_finding(
                resource_name=sg_name,
                scan_id=scan_id,
                severity=severity,
                title=f'Security Group Allows {service} from Internet',
                description=f"Security group '{sg_name}' ({sg_id}) allows {service} (port {port}) from 0.0.0.0/0 ({ip_version})",
                remediation=f'Restrict {service} access to specific IP ranges or use a bastion host/VPN',
                cis_control='5.2',
                resource_id=sg_id
            )
    return None


def check_ebs_encryption(scan_id):
    """Check for unencrypted EBS volumes"""
    findings = []
    
    try:
        paginator = ec2_client.get_paginator('describe_volumes')
        
        for page in paginator.paginate():
            for volume in page['Volumes']:
                volume_id = volume['VolumeId']
                
                if not volume.get('Encrypted', False):
                    # Get attached instance info
                    attachments = volume.get('Attachments', [])
                    instance_info = ''
                    if attachments:
                        instance_id = attachments[0].get('InstanceId', 'unknown')
                        instance_info = f" (attached to {instance_id})"
                    
                    findings.append(create_finding(
                        resource_name=volume_id,
                        scan_id=scan_id,
                        severity='HIGH',
                        title='EBS Volume Not Encrypted',
                        description=f"EBS volume '{volume_id}'{instance_info} is not encrypted",
                        remediation='Create an encrypted snapshot and replace the volume, or enable default EBS encryption',
                        cis_control='2.2.1',
                        resource_id=volume_id
                    ))
                    
    except Exception as e:
        print(f"Error checking EBS encryption: {str(e)}")
    
    return findings


def check_imdsv2(scan_id):
    """Check if instances are using IMDSv2"""
    findings = []
    
    try:
        paginator = ec2_client.get_paginator('describe_instances')
        
        for page in paginator.paginate(Filters=[{'Name': 'instance-state-name', 'Values': ['running']}]):
            for reservation in page['Reservations']:
                for instance in reservation['Instances']:
                    instance_id = instance['InstanceId']
                    
                    # Get instance name from tags
                    instance_name = instance_id
                    for tag in instance.get('Tags', []):
                        if tag['Key'] == 'Name':
                            instance_name = tag['Value']
                            break
                    
                    # Check metadata options
                    metadata_options = instance.get('MetadataOptions', {})
                    http_tokens = metadata_options.get('HttpTokens', 'optional')
                    
                    if http_tokens != 'required':
                        findings.append(create_finding(
                            resource_name=instance_name,
                            scan_id=scan_id,
                            severity='MEDIUM',
                            title='IMDSv2 Not Required',
                            description=f"Instance '{instance_name}' ({instance_id}) does not require IMDSv2",
                            remediation='Modify instance metadata options to require IMDSv2 (HttpTokens=required)',
                            cis_control='5.6',
                            resource_id=instance_id
                        ))
                        
    except Exception as e:
        print(f"Error checking IMDSv2: {str(e)}")
    
    return findings


def check_public_amis(scan_id):
    """Check for publicly shared AMIs owned by the account"""
    findings = []
    
    try:
        # Get account ID
        sts = boto3.client('sts')
        account_id = sts.get_caller_identity()['Account']
        
        # List AMIs owned by this account
        response = ec2_client.describe_images(Owners=['self'])
        
        for image in response['Images']:
            image_id = image['ImageId']
            image_name = image.get('Name', image_id)
            
            if image.get('Public', False):
                findings.append(create_finding(
                    resource_name=image_name,
                    scan_id=scan_id,
                    severity='HIGH',
                    title='AMI Is Publicly Accessible',
                    description=f"AMI '{image_name}' ({image_id}) is publicly accessible",
                    remediation='Modify AMI permissions to remove public access',
                    cis_control='5.4',
                    resource_id=image_id
                ))
                
    except Exception as e:
        print(f"Error checking public AMIs: {str(e)}")
    
    return findings


def check_public_instances(scan_id):
    """Check for instances with public IP addresses in public subnets"""
    findings = []
    
    try:
        # Get all public subnets (subnets with route to IGW)
        public_subnet_ids = set()
        
        route_tables = ec2_client.describe_route_tables()
        for rt in route_tables['RouteTables']:
            has_igw = False
            for route in rt.get('Routes', []):
                if route.get('GatewayId', '').startswith('igw-'):
                    has_igw = True
                    break
            
            if has_igw:
                for assoc in rt.get('Associations', []):
                    subnet_id = assoc.get('SubnetId')
                    if subnet_id:
                        public_subnet_ids.add(subnet_id)
        
        # Check instances
        paginator = ec2_client.get_paginator('describe_instances')
        
        for page in paginator.paginate(Filters=[{'Name': 'instance-state-name', 'Values': ['running']}]):
            for reservation in page['Reservations']:
                for instance in reservation['Instances']:
                    instance_id = instance['InstanceId']
                    public_ip = instance.get('PublicIpAddress')
                    subnet_id = instance.get('SubnetId')
                    
                    # Get instance name
                    instance_name = instance_id
                    for tag in instance.get('Tags', []):
                        if tag['Key'] == 'Name':
                            instance_name = tag['Value']
                            break
                    
                    if public_ip and subnet_id in public_subnet_ids:
                        findings.append(create_finding(
                            resource_name=instance_name,
                            scan_id=scan_id,
                            severity='MEDIUM',
                            title='Instance Has Public IP in Public Subnet',
                            description=f"Instance '{instance_name}' ({instance_id}) has public IP {public_ip} in a public subnet",
                            remediation='Consider using a private subnet with NAT Gateway, or ensure proper security group rules',
                            cis_control='5.1',
                            resource_id=instance_id
                        ))
                        
    except Exception as e:
        print(f"Error checking public instances: {str(e)}")
    
    return findings


def check_unused_security_groups(scan_id):
    """Check for unused security groups"""
    findings = []
    
    try:
        # Get all security groups
        all_sgs = {}
        paginator = ec2_client.get_paginator('describe_security_groups')
        for page in paginator.paginate():
            for sg in page['SecurityGroups']:
                # Skip default security groups
                if sg['GroupName'] != 'default':
                    all_sgs[sg['GroupId']] = sg['GroupName']
        
        # Get security groups in use by instances
        used_sgs = set()
        instance_paginator = ec2_client.get_paginator('describe_instances')
        for page in instance_paginator.paginate():
            for reservation in page['Reservations']:
                for instance in reservation['Instances']:
                    for sg in instance.get('SecurityGroups', []):
                        used_sgs.add(sg['GroupId'])
        
        # Get security groups in use by network interfaces
        eni_paginator = ec2_client.get_paginator('describe_network_interfaces')
        for page in eni_paginator.paginate():
            for eni in page['NetworkInterfaces']:
                for sg in eni.get('Groups', []):
                    used_sgs.add(sg['GroupId'])
        
        # Find unused security groups
        unused_sgs = set(all_sgs.keys()) - used_sgs
        
        for sg_id in unused_sgs:
            sg_name = all_sgs.get(sg_id, sg_id)
            findings.append(create_finding(
                resource_name=sg_name,
                scan_id=scan_id,
                severity='LOW',
                title='Unused Security Group',
                description=f"Security group '{sg_name}' ({sg_id}) is not attached to any resources",
                remediation='Review and delete unused security groups to reduce attack surface',
                cis_control='5.3',
                resource_id=sg_id
            ))
            
    except Exception as e:
        print(f"Error checking unused security groups: {str(e)}")
    
    return findings
