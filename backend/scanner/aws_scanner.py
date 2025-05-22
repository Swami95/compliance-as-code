import boto3
from .policy_engine import load_policies, evaluate

def scan_aws_account(credentials):
    session = boto3.Session(
        aws_access_key_id=credentials["access_key"],
        aws_secret_access_key=credentials["secret_key"]
    )
    iam = session.client("iam")
    s3 = session.client("s3")

    # Sample: get IAM users and attached policies
    users = iam.list_users()["Users"]
    for user in users:
        policies = iam.list_attached_user_policies(UserName=user["UserName"])
        user["policies"] = policies["AttachedPolicies"]

    s3_buckets = s3.list_buckets()["Buckets"]

resources = {
    "s3_buckets": [
        {"Name": "bucket-1", "ACL": "private"},
        {"Name": "bucket-2", "ACL": "public"}  # mocked ACL
    ],
    "iam_users": [
        {"UserName": "alice", "mfa_enabled": True},
        {"UserName": "bob", "mfa_enabled": False}
    ],
    "security_groups": [
        {
            "GroupId": "sg-001",
            "IpPermissions": [
                {
                    "FromPort": 22,
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}]
                }
            ]
        }
    ],
    "rds_instances": [
        {"DBInstanceIdentifier": "db-prod", "StorageEncrypted": False}
    ],
    "cloudtrail_enabled": False
}


    policies = load_policies("scanner/rules/soc2.yaml")
    violations = evaluate(resources, policies)
    return {"violations": violations}
