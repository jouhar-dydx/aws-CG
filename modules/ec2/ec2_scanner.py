from datetime import datetime, timezone
import boto3
import csv
import json
from botocore.exceptions import ClientError, NoCredentialsError
import dateutil.parser
import os

# ----------------------------
# Helper Functions
# ----------------------------

def calculate_age(created_date):
    now = datetime.now(timezone.utc)
    if isinstance(created_date, str):
        created_date = dateutil.parser.parse(created_date)
    return (now - created_date.replace(tzinfo=timezone.utc)).days


def get_instance_name(instance):
    """Extract 'Name' tag from instance"""
    for tag in instance.get("Tags", []):
        if tag["Key"] == "Name":
            return tag["Value"]
    return "N/A"


def is_public_sg(security_groups, ec2_client):
    """Check if SG allows public SSH access"""
    try:
        sg_info = ec2_client.describe_security_groups(GroupIds=[sg['GroupId'] for sg in security_groups])
        for group in sg_info["SecurityGroups"]:
            for rule in group.get("IpPermissions", []):
                for ip_range in rule.get("IpRanges", []):
                    if ip_range.get("CidrIp") == "0.0.0.0/0" and rule.get("FromPort") == 22:
                        return True
        return False
    except Exception as e:
        print(f"Error fetching security group info: {e}")
        return False


def get_valid_regions():
    session = boto3.Session()
    valid_regions = []
    try:
        ec2 = session.client('ec2', region_name='us-east-1')
        response = ec2.describe_regions()
        available_regions = [region['RegionName'] for region in response['Regions']]
    except ClientError as e:
        print(f"Failed to list AWS regions: {e}")
        exit(1)

    for region in available_regions:
        try:
            ec2 = session.client("ec2", region_name=region)
            ec2.describe_instances(MaxResults=5)
            valid_regions.append(region)
        except ClientError:
            # Skip inaccessible regions without printing errors
            pass

    if not valid_regions:
        print("No accessible EC2-enabled regions found.")
        print("Please check:")
        print(" - AWS credentials (`aws configure`)")
        print(" - IAM permissions (needs DescribeInstances)")
        print(" - Account region enablement")
        exit(1)

    return valid_regions


# ----------------------------
# Main EC2 Scanning Function
# ----------------------------

def scan_ec2():
    session = boto3.Session()

    print("\nRunning Enhanced EC2 Instance Scanner...\n")

    # Validate AWS Credentials First
    try:
        sts = boto3.client("sts")
        identity = sts.get_caller_identity()
        print(f"Authenticated as: {identity['Arn']}")
    except NoCredentialsError:
        print("AWS credentials not found. Run `aws configure`")
        exit(1)
    except ClientError as e:
        print(f"Unable to validate AWS credentials: {e}")
        exit(1)

    valid_regions = get_valid_regions()
    all_instances = []

    # Scan Instances
    for region in valid_regions:
        ec2_client = session.client("ec2", region_name=region)
        has_instances_in_region = False

        try:
            paginator = ec2_client.get_paginator("describe_instances")
            page_iterator = paginator.paginate(MaxResults=100)

            for page in page_iterator:
                for reservation in page.get("Reservations", []):
                    for instance in reservation.get("Instances", []):

                        name = get_instance_name(instance)
                        launch_time = instance.get("LaunchTime")
                        public_ip = instance.get("PublicIpAddress", "None")
                        private_ip = instance.get("PrivateIpAddress", "None")
                        sg_list = instance.get("SecurityGroups", [])
                        vpc_id = instance.get("VpcId", "None")
                        subnet_id = instance.get("SubnetId", "None")
                        key_name = instance.get("KeyName", "None")
                        state = instance.get("State", {}).get("Name", "unknown")
                        iam_role = instance.get("IamInstanceProfile", {}).get("Arn", "None")
                        tags = instance.get("Tags", [])

                        is_public_ssh = is_public_sg(sg_list, ec2_client)

                        instance_data = {
                            "instance_id": instance.get("InstanceId"),
                            "name": name,
                            "state": state,
                            "type": instance.get("InstanceType"),
                            "public_ip": public_ip,
                            "private_ip": private_ip,
                            "region": region,
                            "vpc_id": vpc_id,
                            "subnet_id": subnet_id,
                            "security_groups": [sg["GroupName"] for sg in sg_list],
                            "key_name": key_name,
                            "launch_time": str(launch_time),
                            "age_days": calculate_age(launch_time),
                            "platform": instance.get("PlatformDetails", "Linux/UNIX"),
                            "tags": tags,
                            "iam_role": iam_role,
                            "public_ssh_exposed": is_public_ssh
                        }

                        all_instances.append(instance_data)
                        has_instances_in_region = True

        except ClientError as e:
            # Skip inaccessible regions
            continue

        # Print region only if it had instances
        if has_instances_in_region:
            print(f"\nScanning EC2 Instances in Region: {region}")
            for inst in all_instances:
                if inst["region"] == region:
                    print(f"Instance ID: {inst['instance_id']}")
                    print(f"   Name Tag: {inst['name']}")
                    print(f"   State: {inst['state'].capitalize()}")
                    print(f"   Type: {inst['type']}")
                    print(f"   Public IP: {inst['public_ip']}")
                    print(f"   Private IP: {inst['private_ip']}")
                    print(f"   VPC ID: {inst['vpc_id']}")
                    print(f"   Subnet: {inst['subnet_id']}")
                    print(f"   Key Pair: {inst['key_name']}")
                    print(f"   Age: {inst['age_days']} days")
                    print(f"   Platform: {inst['platform']}")
                    print(f"   IAM Role: {inst['iam_role']}")
                    print(f"   Tags: {inst['tags'] or 'None'}")

                    issues = []
                    if inst["public_ssh_exposed"]:
                        issues.append("Public SSH Access Detected")
                    if inst["public_ip"] != "None":
                        issues.append("Publicly Accessible")
                    if not inst["iam_role"]:
                        issues.append("No IAM Role Attached")
                    if len(inst["tags"]) == 0:
                        issues.append("Missing Tags")
                    elif not any(tag["Key"] == "Owner" for tag in inst["tags"]):
                        issues.append("Missing Owner Tag")

                    if issues:
                        print("   Issues:")
                        for issue in issues:
                            print(f"     - {issue}")

    # Generate Reports
    report_data = {
        "timestamp": str(datetime.now()),
        "instances": all_instances
    }

    save_to_json(report_data)
    save_to_csv(all_instances)

    # Summary
    total_instances = len(all_instances)
    running_instances = sum(1 for inst in all_instances if inst["state"] == "running")
    public_ssh_count = sum(1 for inst in all_instances if inst["public_ssh_exposed"])
    missing_owner_tag_count = sum(1 for inst in all_instances if inst["tags"] and not any(tag["Key"] == "Owner" for tag in inst["tags"]))
    no_iam_role_count = sum(1 for inst in all_instances if inst["iam_role"] == "None")

    print("\nEC2 Health Summary:")
    print(f"Total Instances: {total_instances}")
    print(f"Running Instances: {running_instances}")
    print(f"Instances with Public SSH Access: {public_ssh_count}")
    print(f"Instances Missing Owner Tag: {missing_owner_tag_count}")
    print(f"Instances Without IAM Role: {no_iam_role_count}")

    # Health Score Calculation
    max_score = total_instances * 100
    deductions = (
        public_ssh_count * 20 +
        missing_owner_tag_count * 15 +
        no_iam_role_count * 10
    )

    final_score = max(0, max_score - deductions)
    health_percentage = round(final_score / max_score * 100, 2) if max_score > 0 else 100

    print(f"\nFinal EC2 Health Score: {health_percentage}/100")
    if health_percentage >= 80:
        print("Excellent — Few risks detected")
    elif health_percentage >= 60:
        print("Good, but some improvements possible")
    elif health_percentage >= 40:
        print("Moderate risk found")
    else:
        print("High risk detected")

    print("\nEC2 Scan Complete.")
    return report_data


# ----------------------------
# Report Generation
# ----------------------------

def save_to_json(data, filename="reports/ec2_instances_report.json"):
    try:
        os.makedirs("reports", exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        new_filename = f"reports/ec2_instances_report_{timestamp}.json"
        with open(new_filename, "w") as f:
            json.dump(data, f, indent=4, default=str)
        print(f"JSON report saved to '{new_filename}'")
    except Exception as e:
        print(f"Failed to save JSON file: {e}")


def save_to_csv(instances, filename="reports/ec2_instances_report.csv"):
    try:
        os.makedirs("reports", exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        new_filename = f"reports/ec2_instances_report_{timestamp}.csv"

        fieldnames = [
            "instance_id",
            "name",
            "state",
            "type",
            "public_ip",
            "private_ip",
            "region",
            "vpc_id",
            "subnet_id",
            "key_name",
            "age_days",
            "platform",
            "iam_role",
            "public_ssh_exposed"
        ]

        with open(new_filename, "w", newline='') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for item in instances:
                row = {k: v for k, v in item.items() if k in fieldnames}
                writer.writerow(row)

        print(f"Instance report saved to '{new_filename}'")

    except Exception as e:
        print(f"Failed to save CSV files: {e}")


# ----------------------------
# Run It!
# ----------------------------

if __name__ == "__main__":
    scan_ec2()