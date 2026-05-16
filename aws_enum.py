import boto3

# AWS Enumeration Tool
# Used during cloud pentests to identify the current identity
# and enumerate attached permissions after obtaining credentials.

def get_current_user():
    """Identifies the current AWS identity using STS."""
    sts = boto3.client('sts')
    identity = sts.get_caller_identity()
    print("Account:", identity['Account'])
    print("User ARN:", identity['Arn'])

def list_user_policies(username):
    """Lists all managed policies attached to a given IAM user."""
    iam = boto3.client('iam')
    try:
        policies = iam.list_attached_user_policies(UserName=username)
        for policy in policies['AttachedPolicies']:
            print("Policy:", policy['PolicyName'])
    except iam.exceptions.ClientError as e:
        print("Access denied:", e.operation_name)

def list_s3_buckets():
    """Lists all S3 buckets visible to the current identity."""
    s3 = boto3.client('s3')
    try:
        buckets = s3.list_buckets()
        for bucket in buckets['Buckets']:
            print("Bucket:", bucket['Name'])
    except Exception as e:
        print("Access denied:", str(e))

get_current_user()
print("---")
list_user_policies('admin-israel')
print("---")
list_s3_buckets()
