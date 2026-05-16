# aws-enum


A lightweight AWS enumeration script for use during cloud penetration tests.


## What it does


- Identifies the current AWS identity (account ID and ARN)
- Lists managed policies attached to a specified IAM user
- Lists all S3 buckets visible to the current identity


## Requirements


- Python 3
- boto3 ('pip3 install boto3')
- AWS credentials configured ('aws configure')


## Usage


'''bash
python3 aws_enum.py
'''


## Purpose 


Built as part of a cloud security learning path focused on AWS penetration testing and cloud security enginnering. 
