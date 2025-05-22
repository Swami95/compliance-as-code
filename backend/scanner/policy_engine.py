import yaml

def load_policies(file_path):
    with open(file_path, "r") as f:
        return yaml.safe_load(f)

def evaluate(resources, policies):
    violations = []
    for rule in policies:
        if rule["id"] == "SOC2-IAM-001":
            for user in resources["iam_users"]:
                for policy in user.get("policies", []):
                    if policy["PolicyName"] == "AdministratorAccess":
                        violations.append({
                            "id": rule["id"],
                            "resource": user["UserName"],
                            "description": rule["description"],
                            "recommendation": rule["remediation"]
                        })
    return violations
