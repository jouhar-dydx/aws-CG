# modules/lambda_scanner.py

from datetime import datetime, timezone, timedelta
import boto3
import csv
import json
import os
import dateutil.parser

# ----------------------------
# Helper Functions
# ----------------------------

def calculate_age(created_date):
    now = datetime.now(timezone.utc)
    if isinstance(created_state := created_date, str):
        created_state = dateutil.parser.parse(created_state)
    return (now - created_state.replace(tzinfo=timezone.utc)).days


def is_old_entity(last_seen):
    """Check if function has been unused in last N days"""
    if not last_seen:
        return True
    if isinstance(last_seen, int):
        last_seen = datetime.fromtimestamp(last_seen / 1000, tz=timezone.utc)
    elif isinstance(last_seen, str):
        last_seen = dateutil.parser.parse(last_seen)

    threshold = datetime.now(timezone.utc) - timedelta(days=15)
    return last_seen < threshold


def save_to_json(data, filename="reports/lambda_functions_report.json"):
    try:
        os.makedirs("reports", exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        new_filename = f"reports/lambda_functions_report_{timestamp}.json"
        with open(new_filename, "w") as f:
            json.dump(data, f, indent=4, default=str)
        print(f"JSON report saved to '{new_filename}'")
    except Exception as e:
        print(f"Failed to save JSON file: {e}")


def save_to_csv(data, filename="reports/lambda_functions_report.csv"):
    try:
        os.makedirs("reports", exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        new_filename = f"reports/lambda_functions_report_{timestamp}.csv"

        fieldnames = [
            "function_name", "arn", "runtime", "handler", "role_arn",
            "state", "last_modified", "age_days", "code_size_mb",
            "public_access", "attached_to_api_gateway", "attached_to_events",
            "risky_policy", "tags", "description", "vpc_config", "layers",
            "environment", "tracing_config", "invocation_count", "unused"
        ]
        with open(new_filename, "w", newline='') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for item in data:
                writer.writerow(item)
        print(f"CSV report saved to '{new_filename}'")
    except Exception as e:
        print(f"Failed to save CSV file: {e}")

# ----------------------------
# Main Lambda Scanning Function
# ----------------------------

def scan_lambda():
    session = boto3.Session()

    print("\nRunning Enhanced AWS Lambda Scanner...\n")

    # Validate AWS Credentials
    try:
        sts = session.client("sts")
        identity = sts.get_caller_identity()
        print(f"Authenticated as: {identity['Arn']}")
    except Exception as e:
        print(f"AWS credentials error: {e}")
        exit(1)

    valid_regions = get_valid_regions()
    all_functions = []

    # Scan Lambda Functions
    print("Scanning Lambda Functions Across Regions...")

    for region in valid_regions:
        lambda_client = session.client("lambda", region_name=region)

        try:
            paginator = lambda_client.get_paginator("list_functions")
            page_iterator = paginator.paginate()

            for page in page_iterator:
                functions = page.get("Functions", [])
                if not functions:
                    continue  # Skip regions with no Lambdas

                for function in functions:
                    name = function["FunctionName"]
                    arn = function["FunctionArn"]
                    runtime = function.get("Runtime")
                    handler = function.get("Handler")
                    role_arn = function.get("Role", "N/A")
                    state = function.get("State", "Unknown")
                    last_modified = function.get("LastModified")
                    age_days = calculate_age(function.get("LastModified"))
                    code_size = function.get("CodeSize", 0) / (1024 * 1024)  # MB
                    description = function.get("Description", "")
                    vpc_config = function.get("VpcConfig", {})
                    layers = [layer["Arn"] for layer in function.get("Layers", [])]
                    tracing_config = function.get("TracingConfig", {}).get("Mode", "Off")
                    environment = function.get("Environment", {})
                    tags = {}
                    try:
                        tags = lambda_client.list_tags(Resource=arn).get("Tags", {})
                    except Exception:
                        pass

                    # Check policy for public access
                    risky_policy = False
                    public_access = False
                    try:
                        policy = lambda_client.get_policy(FunctionName=name)
                        policy_doc = json.loads(policy["Policy"])
                        risky_policy = check_risky_policy(policy_doc)
                        public_access = any(stmt.get("Principal") == "*" for stmt in policy_doc.get("Statement", []))
                    except Exception:
                        pass

                    # Get last invocation from CloudWatch
                    logs_client = session.client("logs", region_name=region)
                    log_group = f"/aws/lambda/{name}"
                    last_invocation = None
                    try:
                        response = logs_client.describe_log_streams(logGroupName=log_group)
                        sorted_streams = sorted(response["logStreams"], key=lambda x: x.get("lastEventTimestamp", 0), reverse=True)
                        if sorted_streams and "lastEventTimestamp" in sorted_streams[0]:
                            last_invocation = sorted_streams[0]["lastEventTimestamp"]
                    except Exception:
                        pass

                    # Check EventBridge triggers
                    events_client = session.client("events", region_name=region)
                    attached_to_events = False
                    try:
                        rules = events_client.list_rules(NamePrefix=name)
                        if rules.get("Rules"):
                            rule_name = rules["Rules"][0]["Name"]
                            targets = events_client.list_targets_by_rule(Rule=rule_name)["Targets"]
                            attached_to_events = len(targets) > 0
                    except Exception:
                        pass

                    # API Gateway trigger check
                    apigw_attached = False
                    if attached_to_events:
                        for target in events_client.list_targets_by_rule(Rule=rule_name).get("Targets", []):
                            if "apigateway" in target.get("Arn", ""):
                                apigw_attached = True

                    unused = is_old_entity(last_invocation)

                    function_data = {
                        "function_name": name,
                        "arn": arn,
                        "runtime": runtime,
                        "handler": handler,
                        "role_arn": role_arn,
                        "state": state,
                        "last_modified": str(last_modified),
                        "age_days": age_days,
                        "code_size_mb": round(code_size, 2),
                        "public_access": public_access,
                        "attached_to_api_gateway": apigw_attached,
                        "attached_to_events": attached_to_events,
                        "risky_policy": risky_policy,
                        "tags": tags,
                        "description": description,
                        "vpc_config": vpc_config,
                        "layers": layers,
                        "environment": environment,
                        "tracing_config": tracing_config,
                        "last_invocation": str(last_invocation) if last_invocation else None,
                        "unused": unused,
                        "region": region
                    }

                    all_functions.append(function_data)

                    # Print detailed function summary
                    print(f"\nLambda Function: {name} ({runtime})")
                    print(f"ARN: {arn}")
                    print(f"Handler: {function_data['handler']}")
                    print(f"State: {function_data['state']}")
                    print(f"Role ARN: {function_data['role_arn']}")
                    print(f"Region: {function_data['region']}")
                    print(f"Public Access: {'Yes' if function_data['public_access'] else 'No'}")
                    print(f"Risky Policy: {'Yes' if function_data['risky_policy'] else 'No'}")
                    print(f"Attached to API Gateway: {'Yes' if function_data['attached_to_api_gateway'] else 'No'}")
                    print(f"Attached to Events: {'Yes' if function_data['attached_to_events'] else 'No'}")
                    print(f"Memory Size: {function.get('MemorySize', 'N/A')} MB")
                    print(f"Timeout: {function.get('Timeout', 'N/A')} sec")
                    print(f"Tracing Mode: {function_data['tracing_config']}")
                    print(f"VPC Config: {function_data['vpc_config']}")
                    print(f"Environment: {function_data['environment']}")
                    print(f"Layers: {len(function_data['layers'])} layer(s)")
                    print(f"Last Invocation: {function_data['last_invocation'] or 'Never'}")
                    print(f"Unused (>15 days): {'Yes' if function_data['unused'] else 'No'}")
                    print(f"Tags: {function_data['tags'] or 'None'}")

        except Exception as e:
            pass  # Silently skip inaccessible regions

    # Generate Report
    report_data = {
        "timestamp": str(datetime.now()),
        "functions": all_functions
    }

    save_to_json(report_data)
    save_to_csv(all_functions)

    # Summary
    total = len(all_functions)
    running = sum(1 for f in all_functions if f["state"] == "Active")
    public_funcs = sum(1 for f in all_functions if f["public_access"])
    unused_funcs = sum(1 for f in all_functions if f["unused"])
    no_tags = sum(1 for f in all_functions if not f["tags"])

    print("\nLambda Health Summary:")
    print(f"Total Functions: {total}")
    print(f"Publicly Accessible: {public_funcs}")
    print(f"Unused (>15 days): {unused_funcs}")
    print(f"Missing Tags: {no_tags}")

    # Health Score
    max_score = total * 100
    deductions = (
        public_funcs * 25 +
        unused_funcs * 30 +
        no_tags * 10
    )

    final_score = max(0, max_score - deductions)
    health_percentage = round(final_score / max_score * 100, 2) if max_score > 0 else 100

    print(f"\nFinal Lambda Health Score: {health_percentage}/100")
    if health_percentage >= 80:
        print("Excellent — Few or no risks")
    elif health_percentage >= 60:
        print("Good, but some cleanup needed")
    elif health_percentage >= 20:
        print("Moderate risk — several unused/public Lambdas")
    else:
        print("Critical — Most Lambdas are unused or exposed!")

    print("Lambda Scan Complete.")
    return report_data


# ----------------------------
# Helper Logic
# ----------------------------

def get_valid_regions():
    session = boto3.Session()
    ec2_client = session.client("ec2", region_name="us-east-1")

    valid_regions = []
    try:
        response = ec2_client.describe_regions()
        for region in response.get("Regions", []):
            valid_regions.append(region["RegionName"])
    except Exception:
        print("Unable to describe AWS regions. Using fallback list...")
        valid_regions = ['us-east-1', 'us-west-2', 'ap-south-1']

    if not valid_regions:
        print("No accessible regions found. Check AWS credentials or IAM permissions.")
        exit(1)

    return valid_regions


def check_risky_policy(policy_document):
    """Detect overly broad permissions in resource policies"""
    if not policy_document:
        return False
    for statement in policy_document.get("Statement", []):
        if statement.get("Effect") == "Allow" and statement.get("Principal") == "*":
            return True
    return False

# ----------------------------
# Run It!
# ----------------------------

if __name__ == "__main__":
    scan_lambda()