import yaml

def load_policies(file_path):
    with open(file_path, "r") as f:
        return yaml.safe_load(f)

def evaluate(resources: dict, policies: list) -> list:
    violations = []

    for rule in policies:
        detect = rule.get("detect", {})
        rule_type = detect.get("type")

        if rule_type == "bucket_acl":
            for bucket in resources.get("s3_buckets", []):
                if bucket.get("ACL", "") == "public":  # replace with real check
                    violations.append(build_violation(rule, bucket["Name"]))

        elif rule_type == "mfa_check":
            for user in resources.get("iam_users", []):
                if not user.get("mfa_enabled", False):
                    violations.append(build_violation(rule, user["UserName"]))

        elif rule_type == "security_group_check":
            port = detect.get("port")
            cidr = detect.get("cidr")
            for sg in resources.get("security_groups", []):
                for permission in sg.get("IpPermissions", []):
                    if permission.get("FromPort") == port:
                        for ip_range in permission.get("IpRanges", []):
                            if ip_range.get("CidrIp") == cidr:
                                violations.append(build_violation(rule, sg["GroupId"]))

        elif rule_type == "encryption_check":
            field = detect.get("resource_field")
            match = detect.get("match")
            for db in resources.get("rds_instances", []):
                if db.get(field) == match:
                    violations.append(build_violation(rule, db["DBInstanceIdentifier"]))

        elif rule_type == "cloudtrail_check":
            # if CloudTrail not enabled
            if not resources.get("cloudtrail_enabled", True):
                violations.append(build_violation(rule, "global"))

    return violations

def build_violation(rule, resource_id):
    return {
        "id": rule["id"],
        "resource": resource_id,
        "framework": rule.get("framework", ""),
        "severity": rule["severity"],
        "description": rule["description"],
        "recommendation": rule["remediation"]
    }
