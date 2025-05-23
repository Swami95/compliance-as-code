import boto3
from scanner.policy_engine import load_policies, evaluate


def scan_aws_account(credentials: dict = None):
    if credentials:
        session = boto3.Session(
            aws_access_key_id=credentials.get("aws_access_key_id"),
            aws_secret_access_key=credentials.get("aws_secret_access_key"),
            aws_session_token=credentials.get("aws_session_token"),
            region_name="ap-south-1"
        )
    else:
        session = boto3.Session(profile_name="personal_aws", region_name="ap-south-1")

    s3 = session.client("s3")
    iam = session.client("iam")
    ec2 = session.client("ec2")
    rds = session.client("rds")
    ct = session.client("cloudtrail")

    # 1. S3 Buckets
    s3_buckets = []
    for bucket in s3.list_buckets().get("Buckets", []):
        name = bucket["Name"]
        acl = s3.get_bucket_acl(Bucket=name)
        grants = [g["Grantee"].get("URI", "") for g in acl["Grants"]]
        is_public = any("AllUsers" in g or "AuthenticatedUsers" in g for g in grants)
        s3_buckets.append({"Name": name, "ACL": "public" if is_public else "private"})

    # 2. IAM Users, MFA, Admin Access
    iam_users = []
    for user in iam.list_users().get("Users", []):
        username = user["UserName"]

        # MFA check
        mfa_devices = iam.list_mfa_devices(UserName=username)
        mfa_enabled = len(mfa_devices.get("MFADevices", [])) > 0

        # Attached managed policies
        attached_policies = iam.list_attached_user_policies(UserName=username).get("AttachedPolicies", [])

        # Inline user policies
        inline_policy_names = iam.list_user_policies(UserName=username).get("PolicyNames", [])
        inline_policies = []
        for pname in inline_policy_names:
            policy_doc = iam.get_user_policy(UserName=username, PolicyName=pname)["PolicyDocument"]
            inline_policies.append(policy_doc)

        # Groups and their policies
        groups = iam.list_groups_for_user(UserName=username).get("Groups", [])
        group_policies = []
        for group in groups:
            gname = group["GroupName"]

            # Group managed policies
            group_attached = iam.list_attached_group_policies(GroupName=gname).get("AttachedPolicies", [])

            # Group inline policies
            inline_names = iam.list_group_policies(GroupName=gname).get("PolicyNames", [])
            group_inline = []
            for pname in inline_names:
                group_policy = iam.get_group_policy(GroupName=gname, PolicyName=pname)["PolicyDocument"]
                group_inline.append(group_policy)

            group_policies.append({
                "GroupName": gname,
                "AttachedPolicies": group_attached,
                "InlinePolicies": group_inline
            })

        iam_users.append({
            "UserName": username,
            "mfa_enabled": mfa_enabled,
            "AttachedPolicies": attached_policies,
            "InlinePolicies": inline_policies,
            "Groups": group_policies
        })

    # 3. EC2 Security Groups
    sgs = ec2.describe_security_groups().get("SecurityGroups", [])

    # 4. RDS Encryption Check
    rds_instances = []
    for db in rds.describe_db_instances().get("DBInstances", []):
        rds_instances.append({
            "DBInstanceIdentifier": db["DBInstanceIdentifier"],
            "StorageEncrypted": db.get("StorageEncrypted", False)
        })

    # 5. CloudTrail
    trails = ct.describe_trails().get("trailList", [])
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


if __name__ == "__main__":
    print("Starting AWS compliance scan...")

    violations = scan_aws_account({})  # Pass credentials dict if needed

    if not violations:
        print("✅ No compliance violations found!")
    else:
        print(f"❌ Found {len(violations)} violations:")
        for v in violations:
            print(f"[{v['severity'].upper()}] {v['id']}: {v['resource']} — {v['description']}")
