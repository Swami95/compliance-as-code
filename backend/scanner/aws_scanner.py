import boto3
from .policy_engine import load_policies, evaluate

def scan_aws_account(credentials: dict):
    session = boto3.Session(
        aws_access_key_id=credentials["access_key"],
        aws_secret_access_key=credentials["secret_key"],
        region_name=credentials.get("region", "us-east-1")
    )

    s3 = session.client("s3")
    iam = session.client("iam")
    ec2 = session.client("ec2")
    rds = session.client("rds")
    ct = session.client("cloudtrail")

    # 1. S3 Buckets
    s3_buckets = []
    for bucket in s3.list_buckets()["Buckets"]:
        name = bucket["Name"]
        acl = s3.get_bucket_acl(Bucket=name)
        grants = [g["Grantee"].get("URI", "") for g in acl["Grants"]]
        is_public = any("AllUsers" in g or "AuthenticatedUsers" in g for g in grants)
        s3_buckets.append({"Name": name, "ACL": "public" if is_public else "private"})

    # 2. IAM Users & MFA
    iam_users = []
    for user in iam.list_users()["Users"]:
        mfa_devices = iam.list_mfa_devices(UserName=user["UserName"])
        iam_users.append({
            "UserName": user["UserName"],
            "mfa_enabled": len(mfa_devices["MFADevices"]) > 0
        })

    # 3. EC2 Security Groups
    sgs = ec2.describe_security_groups()["SecurityGroups"]

    # 4. RDS Encryption Check
    rds_instances = []
    for db in rds.describe_db_instances()["DBInstances"]:
        rds_instances.append({
            "DBInstanceIdentifier": db["DBInstanceIdentifier"],
            "StorageEncrypted": db["StorageEncrypted"]
        })

    # 5. CloudTrail
    trails = ct.describe_trails()["trailList"]
    cloudtrail_enabled = any(t.get("IsMultiRegionTrail", False) for t in trails)

    resources = {
        "s3_buckets": s3_buckets,
        "iam_users": iam_users,
        "security_groups": sgs,
        "rds_instances": rds_instances,
        "cloudtrail_enabled": cloudtrail_enabled
    }

    policies = load_policies("scanner/rules/hipaa.yaml")
    return evaluate(resources, policies)
