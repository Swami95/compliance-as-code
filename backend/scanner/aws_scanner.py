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
        "iam_users": users,
        "s3_buckets": s3_buckets,
    }

    policies = load_policies("scanner/rules/soc2.yaml")
    violations = evaluate(resources, policies)
    return {"violations": violations}
