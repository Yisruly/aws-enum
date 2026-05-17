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
