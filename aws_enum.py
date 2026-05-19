import boto3

def get_current_user():
    sts = boto3.client('sts')
    identity = sts.get_caller_identity()
    print("Account:", identity['Account'])
    print("User ARN:", identity['Arn'])

get_current_user()

def list_user_policies(username):
    iam = boto3.client('iam')
    try:
        policies = iam.list_attached_user_policies(UserName=username)
        for policy in policies['AttachedPolicies']:
            print("Policy:", policy['PolicyName'])
    except iam.exceptions.ClientError as e:
        print("Access denied:", e.operation_name)

list_user_policies('test-readonly')

def list_security_groups():
    """Lists security groups and their inbound rules."""
    ec2 = boto3.client('ec2', region_name='eu-north-1')
    try:
        sgs = ec2.describe_security_groups()
        for sg in sgs['SecurityGroups']:
            print(f"\nSecurity Group: {sg['GroupName']} ({sg['GroupId']})")
            for rule in sg['IpPermissions']:
                protocol = rule.get('IpProtocol', 'all')
                from_port = rule.get('FromPort', 'all')
                for ip_range in rule.get('IpRanges', []):
                    cidr = ip_range.get('CidrIp', 'unknown')
                    print(f"  Inbound: {protocol} port {from_port} from {cidr}")
    except Exception as e:
        print("Access denied:", str(e))

list_security_groups()

def list_nacls():
    """Lists Network ACLs and their inbound rules."""
    ec2 = boto3.client('ec2', region_name='eu-north-1')
    try:
        nacls = ec2.describe_network_acls()
        for nacl in nacls['NetworkAcls']:
            print(f"\nNACL: {nacl['NetworkAclId']} (Default: {nacl['IsDefault']})")
            inbound = [r for r in nacl['Entries'] if not r['Egress']]
            inbound.sort(key=lambda x: x['RuleNumber'])
            for rule in inbound:
                protocol = rule.get('Protocol', 'all')
                action = rule.get('RuleAction', 'unknown')
                cidr = rule.get('CidrBlock', 'unknown')
                rule_num = rule.get('RuleNumber', '?')
                print(f"  Rule {rule_num}: {action} {cidr} protocol {protocol}")
    except Exception as e:
        print("Error:", str(e))

list_nacls()
