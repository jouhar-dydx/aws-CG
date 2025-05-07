from datetime import datetime, timezone, timedelta
import boto3
from botocore.exceptions import ClientError
import csv
import json
import dateutil.parser

# ----------------------------
# Helper Functions
# ----------------------------

def calculate_age(created_date):
    now = datetime.now(timezone.utc)
    if isinstance(created_date, str):
        try:
            created_date = dateutil.parser.parse(created_date)
        except Exception as e:
            print(f" Failed to parse date: {created_date}. Error: {e}")
            return -1
    if isinstance(created_date, datetime):
        return (now - created_date.replace(tzinfo=timezone.utc)).days
    else:
        return -1


def is_old_entity(last_used):
    if not last_used:
        return True
    if isinstance(last_used, str):
        last_used = dateutil.parser.parse(last_used)
    threshold = datetime.now(timezone.utc) - timedelta(days=90)
    return last_used < threshold


def save_to_json(data, filename="reports/iam_audit_report.json"):
    try:
        with open(filename, "w") as f:
            json.dump(data, f, indent=4, default=str)
        print(f"\n Report saved to '{filename}'")
    except Exception as e:
        print(f" Failed to save JSON file: {e}")


def save_to_csv(data, filename="reports/iam_audit_report.csv"):
    try:
        fieldnames = ["type", "name", "arn", "created", "age_days", "mfa_enabled", "unused", "inline_policies", "risky_policy"]
        with open(filename, "w", newline='') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for item in data:
                writer.writerow(item)
        print(f" Report saved to '{filename}'")
    except Exception as e:
        print(f" Failed to save CSV file: {e}")


def check_risky_policy(policy_document):
    """Detect overly broad permissions"""
    risky_statements = []
    for statement in policy_document.get("Statement", []):
        if statement.get("Effect") == "Allow":
            actions = statement.get("Action", [])
            resources = statement.get("Resource", "")
            if isinstance(actions, str):
                actions = [actions]
            if "*" in actions or ("*" in resources and "sts:GetFederationToken" not in actions):
                risky_statements.append(statement)
    return len(risky_statements) > 0


def get_managed_policy_details(iam_client, policy_arn):
    try:
        policy = iam_client.get_policy(PolicyArn=policy_arn)
        policy_version = iam_client.get_policy_version(
            PolicyArn=policy_arn,
            VersionId=policy['Policy']['DefaultVersionId']
        )
        return policy_version['PolicyVersion']['Document']
    except ClientError as e:
        print(f" Error fetching managed policy {policy_arn}: {e}")
        return {}


def analyze_policies(iam_client, user_name=None, role_name=None):
    resource_type = "user" if user_name else "role"
    name = user_name or role_name
    try:
        attached_policies = []
        inline_policies = []

        if user_name:
            attached_policies = iam_client.list_attached_user_policies(UserName=user_name)['AttachedPolicies']
            inline_policies = iam_client.list_user_policies(UserName=user_name)['PolicyNames']
        else:
            attached_policies = iam_client.list_attached_role_policies(RoleName=role_name)['AttachedPolicies']
            inline_policies = iam_client.list_role_policies(RoleName=role_name)['PolicyNames']

        risky_policies = []

        # Analyze attached policies
        for policy in attached_policies:
            policy_doc = get_managed_policy_details(iam_client, policy['PolicyArn'])
            if check_risky_policy(policy_doc):
                risky_policies.append({
                    "type": "attached",
                    "name": policy['PolicyName'],
                    "arn": policy['PolicyArn'],
                    "risk_reason": "Broad permissions found (e.g., *:*)"
                })

        # Analyze inline policies
        for policy_name in inline_policies:
            if user_name:
                policy_doc = iam_client.get_user_policy(UserName=user_name, PolicyName=policy_name)['PolicyDocument']
            else:
                policy_doc = iam_client.get_role_policy(RoleName=role_name, PolicyName=policy_name)['PolicyDocument']
            if check_risky_policy(policy_doc):
                risky_policies.append({
                    "type": "inline",
                    "name": policy_name,
                    "document": policy_doc,
                    "risk_reason": "Broad permissions found (e.g., *:*)"
                })

        return {
            "risky_policies": risky_policies,
            "inline_count": len(inline_policies),
            "attached_count": len(attached_policies)
        }

    except ClientError as e:
        print(f" Error analyzing policies for {resource_type} '{name}': {e}")
        return {"risky_policies": [], "inline_count": 0, "attached_count": 0}


# ----------------------------
# Scanner Functions
# ----------------------------

def scan_iam():
    iam_client = boto3.client('iam')

    print("\n Running Enhanced IAM Audit Scanner...\n")

    report_data = {
        "timestamp": str(datetime.now()),
        "users": [],
        "roles": [],
        "groups": [],
        "policies": []
    }

    csv_data = []

    # IAM Users
    try:
        users = iam_client.list_users()['Users']
        print(" IAM Users:")
        for user in users:
            mfa_devices = iam_client.list_mfa_devices(UserName=user['UserName'])['MFADevices']
            login_profile = None
            try:
                login_profile = iam_client.get_login_profile(UserName=user['UserName'])
            except ClientError:
                pass

            last_used = user.get('PasswordLastUsed')
            unused = is_old_entity(last_used)

            policy_analysis = analyze_policies(iam_client, user_name=user['UserName'])

            entry = {
                "username": user['UserName'],
                "arn": user['Arn'],
                "created": str(user['CreateDate']),
                "age_days": calculate_age(user['CreateDate']),
                "mfa_enabled": bool(mfa_devices),
                "login_profile": bool(login_profile),
                "unused": unused,
                "inline_policies": policy_analysis['inline_count'],
                "risky_policies": policy_analysis['risky_policies']
            }
            report_data["users"].append(entry)

            csv_data.append({
                "type": "user",
                "name": entry["username"],
                "arn": entry["arn"],
                "created": entry["created"],
                "age_days": entry["age_days"],
                "mfa_enabled": entry["mfa_enabled"],
                "unused": entry["unused"],
                "inline_policies": entry["inline_policies"],
                "risky_policy": len(entry["risky_policies"]) > 0
            })

            status = ""
            if not entry["mfa_enabled"]:
                status += "MFA,"
            if entry["unused"]:
                status += "Unused,"
            if entry["inline_policies"] > 0:
                status += "Inline,"
            if len(entry["risky_policies"]) > 0:
                status += "Risky"

            print(f" - {user['UserName']} (Age: {entry['age_days']} days)", end="")
            if status:
                print(f" | Issues: {status[:-1]}")
            else:
                print()

    except ClientError as e:
        print(f" Error listing IAM users: {e}")

    # IAM Roles
    try:
        roles = iam_client.list_roles()['Roles']
        print("\n IAM Roles:")
        for role in roles:
            last_used = role.get('RoleLastUsed', {}).get('LastUsedDate')
            unused = is_old_entity(last_used)

            policy_analysis = analyze_policies(iam_client, role_name=role['RoleName'])

            entry = {
                "rolename": role['RoleName'],
                "arn": role['Arn'],
                "created": str(role['CreateDate']),
                "age_days": calculate_age(role['CreateDate']),
                "unused": unused,
                "inline_policies": policy_analysis['inline_count'],
                "risky_policies": policy_analysis['risky_policies']
            }
            report_data["roles"].append(entry)

            csv_data.append({
                "type": "role",
                "name": entry["rolename"],
                "arn": entry["arn"],
                "created": entry["created"],
                "age_days": entry["age_days"],
                "mfa_enabled": False,
                "unused": entry["unused"],
                "inline_policies": entry["inline_policies"],
                "risky_policy": len(entry["risky_policies"]) > 0
            })

            status = ""
            if entry["unused"]:
                status += "Unused,"
            if entry["inline_policies"] > 0:
                status += "Inline,"
            if len(entry["risky_policies"]) > 0:
                status += "Risky"

            print(f" - {role['RoleName']} (Age: {entry['age_days']} days)", end="")
            if status:
                print(f" | Issues: {status[:-1]}")
            else:
                print()

    except ClientError as e:
        print(f" Error listing IAM roles: {e}")

    # Save reports
    save_to_json(report_data)
    save_to_csv(csv_data)

    # Calculate IAM Health Score
    total_entities = len(report_data["users"]) + len(report_data["roles"])
    if total_entities == 0:
        print("\n IAM Health Score: N/A")
        print("No IAM users or roles found to analyze.")
        return

    safe_entities = 0
    mfa_missing = 0
    unused_entities = []
    inline_policies_list = []
    risky_policies_details = []

    for user in report_data["users"]:
        if user["mfa_enabled"]:
            safe_entities += 1
        else:
            mfa_missing += 1
        if not user["unused"]:
            safe_entities += 1
        else:
            unused_entities.append(f"User: {user['username']} (created {user['age_days']} days ago)")
        if user["inline_policies"] == 0:
            safe_entities += 1
        else:
            inline_policies_list.append(f"User: {user['username']} has {user['inline_policies']} inline policies")
        if len(user["risky_policies"]) == 0:
            safe_entities += 1
        else:
            for policy in user["risky_policies"]:
                policy_type = "attached" if policy["type"] == "attached" else "inline"
                risk_desc = policy["risk_reason"]
                risky_policies_details.append(
                    f"[User: {user['username']}]"
                    f"\n  🔹 {policy_type.capitalize()} Policy: {policy['name']}"
                    f"\n     Reason: {risk_desc}"
                )

    for role in report_data["roles"]:
        if not role["unused"]:
            safe_entities += 1
        else:
            unused_entities.append(f"Role: {role['rolename']} (created {role['age_days']} days ago)")
        if role["inline_policies"] == 0:
            safe_entities += 1
        else:
            inline_policies_list.append(f"Role: {role['rolename']} has {role['inline_policies']} inline policies")
        if len(role["risky_policies"]) == 0:
            safe_entities += 1
        else:
            for policy in role["risky_policies"]:
                policy_type = "attached" if policy["type"] == "attached" else "inline"
                risk_desc = policy["risk_reason"]
                risky_policies_details.append(
                    f"[Role: {role['rolename']}]"
                    f"\n  🔹 {policy_type.capitalize()} Policy: {policy['name']}"
                    f"\n     Reason: {risk_desc}"
                )

    max_score = total_entities * 4  # Each entity can contribute up to 4 points
    health_score = round((safe_entities / max_score) * 100, 2)

    print(f"\n IAM Health Score: {health_score}/100")

    if health_score >= 80:
        print(" Excellent — Your IAM configuration follows best practices.")
    elif health_score >= 60:
        print(" Good, but some improvements possible.")
    elif health_score >= 20:
        print(" Significant security risks detected.")
    else:
        print(" Critical IAM misconfigurations found.")

    print("\n Detailed Breakdown:")

    # --- Unused Entities ---
    print("\n Unused Entities (not active in last 90 days):")
    if unused_entities:
        for item in unused_entities:
            print(f" - {item}")
    else:
        print("   None found.")

    # --- Inline Policies ---
    print("\n Inline Policies (harder to manage):")
    if inline_policies_list:
        for item in inline_policies_list:
            print(f" - {item}")
    else:
        print("   None found.")

    # --- Risky Policies ---
    print("\n Risky Policies (broad permissions):")
    if risky_policies_details:
        for item in risky_policies_details:
            print(item)
    else:
        print("   None found.")

    print("\n IAM Scan Complete.")