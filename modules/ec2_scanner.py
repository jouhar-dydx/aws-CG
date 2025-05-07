# modules/ec2_scanner.py

from datetime import datetime, timezone
import boto3
import csv
import json
from botocore.exceptions import ClientError, NoCredentialsError
import dateutil.parser

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
        print(f"❌ Error fetching security group info: {e}")
        return False


def get_valid_regions():
    session = boto3.Session()
    valid_regions = []

    print("\n🌐 Detecting Enabled & Accessible Regions...\n")

    # Get all available regions
    ec2 = session.client('ec2', region_name='us-east-1')
    try:
        response = ec2.describe_regions()
        available_regions = [region['RegionName'] for region in response['Regions']]
    except ClientError as e:
        print(f"❌ Failed to list AWS regions: {e}")
        exit(1)

    for region in available_regions:
        try:
            ec2 = session.client("ec2", region_name=region)

            # Use MaxResults >= 5 to avoid InvalidParameterValue
            instances = ec2.describe_instances(MaxResults=5)
            valid_regions.append(region)
            print(f"✅ Region '{region}' is accessible")
        except ClientError as e:
            error_code = e.response['Error'].get('Code', 'Unknown')
            error_msg = e.response['Error'].get('Message', 'No message')

            if error_code == 'AuthFailure':
                print(f"🚫 Region '{region}': Authentication failed (check AWS keys)")
            elif error_code == 'UnrecognizedClientException':
                print(f"🚫 Region '{region}': Unauthenticated access (check credentials)")
            else:
                print(f"⚠️ Region '{region}': {error_code} ({error_msg})")

    if not valid_regions:
        print("\n❌ No accessible EC2-enabled regions found.")
        print("➡️  Please check:")
        print("   - AWS credentials (`aws configure`)")
        print("   - IAM permissions (needs DescribeInstances)")
        print("   - Account region enablement")
        exit(1)

    return valid_regions


# ----------------------------
# Main EC2 Scanning Function
# ----------------------------

def scan_ec2():
    print("\n🔍 Running Enhanced EC2 Instance & Elastic IP Scanner...\n")

    # Validate AWS Credentials First
    try:
        sts = boto3.client("sts")
        identity = sts.get_caller_identity()
        print(f"👤 Authenticated as: {identity['Arn']}")
    except NoCredentialsError:
        print("❌ AWS credentials not found. Run `aws configure`")
        exit(1)
    except ClientError as e:
        print(f"❌ Unable to validate AWS credentials: {e}")
        exit(1)

    # Get Valid Regions
    valid_regions = get_valid_regions()

    all_instances = []
    all_eips = []

    # Scan Instances
    for region in valid_regions:
        print(f"\n📍 Scanning EC2 Instances in Region: {region}")
        ec2_client = boto3.client("ec2", region_name=region)

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

                        # Print detailed instance info
                        print(f"\n🖥️ Instance ID: {instance_data['instance_id']}")
                        print(f"   Name Tag: {instance_data['name']}")
                        print(f"   State: {instance_data['state'].capitalize()}")
                        print(f"   Type: {instance_data['type']}")
                        print(f"   Public IP: {instance_data['public_ip']}")
                        print(f"   Private IP: {instance_data['private_ip']}")
                        print(f"   VPC ID: {instance_data['vpc_id']}")
                        print(f"   Subnet: {instance_data['subnet_id']}")
                        print(f"   Key Pair: {instance_data['key_name']}")
                        print(f"   Age: {instance_data['age_days']} days")
                        print(f"   Platform: {instance_data['platform']}")
                        print(f"   IAM Role: {instance_data['iam_role']}")
                        print(f"   Tags: {instance_data['tags'] or 'None'}")

                        issues = []
                        if is_public_ssh:
                            issues.append("🔓 Public SSH Access Detected")
                        if public_ip != "None":
                            issues.append("🌐 Publicly Accessible")
                        if not instance_data["iam_role"]:
                            issues.append("⚠️ No IAM Role Attached")
                        if len(tags) == 0:
                            issues.append("🏷️ Missing Tags")
                        elif not any(tag['Key'] == 'Owner' for tag in tags):
                            issues.append("👤 Missing Owner Tag")

                        if issues:
                            print("   🔍 Issues:")
                            for issue in issues:
                                print(f"     - {issue}")

        except ClientError as e:
            print(f"❌ Failed to describe instances in {region}: {e}")

    # Scan Elastic IPs
    print("\n🔁 Scanning Elastic IPs...")
    for region in valid_regions:
        print(f"📍 Region: {region}")
        ec2_client = boto3.client("ec2", region_name=region)

        try:
            response = ec2_client.describe_addresses()
            for eip in response.get("Addresses", []):
                instance_id = eip.get("InstanceId", "Unattached")
                public_ip = eip.get("PublicIp", "Unknown")
                allocation_id = eip.get("AllocationId", "N/A")

                eip_data = {
                    "public_ip": public_ip,
                    "allocation_id": allocation_id,
                    "instance_id": instance_id,
                    "region": region,
                    "orphaned": instance_id == "Unattached"
                }
                all_eips.append(eip_data)

                if eip_data["orphaned"]:
                    print(f"   🚩 Orphaned EIP: {public_ip} (not attached to any instance)")
                else:
                    print(f"   📍 EIP: {public_ip} → Instance: {instance_id}")

        except ClientError as e:
            print(f"❌ Failed to describe EIPs in {region}: {e}")

    # Generate Reports
    report_data = {
        "timestamp": str(datetime.now()),
        "instances": all_instances,
        "elastic_ips": all_eips
    }

    save_to_json(report_data)
    save_to_csv(all_instances, all_eips)

    # Summary
    total_instances = len(all_instances)
    running_instances = sum(1 for inst in all_instances if inst["state"] == "running")
    public_ssh_count = sum(1 for inst in all_instances if inst["public_ssh_exposed"])
    orphaned_eip_count = sum(1 for eip in all_eips if eip["orphaned"])

    print("\n📊 EC2 Health Summary:")
    print(f"Total Instances: {total_instances}")
    print(f"Running Instances: {running_instances}")
    print(f"Elastic IPs: {len(all_eips)}")
    print(f"Orphaned Elastic IPs: {orphaned_eip_count}")
    print(f"Instances with Public SSH Access: {public_ssh_count}")

    print("\n✅ EC2 Scan Complete.")
    return report_data


# ----------------------------
# Report Generation
# ----------------------------

def save_to_json(data, filename="reports/ec2_instances_report.json"):
    try:
        with open(filename, "w") as f:
            json.dump(data, f, indent=4, default=str)
        print(f"✅ JSON report saved to '{filename}'")
    except Exception as e:
        print(f"❌ Failed to save JSON file: {e}")


def save_to_csv(instances, eips, filename="reports/ec2_instances_report.csv"):
    try:
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

        with open(filename, "w", newline='') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for item in instances:
                row = {k: v for k, v in item.items() if k in fieldnames}
                writer.writerow(row)

        print(f"✅ Instance report saved to '{filename}'")

        eip_filename = "reports/ec2_elastic_ips_report.csv"
        eip_fieldnames = ["public_ip", "allocation_id", "instance_id", "region", "orphaned"]
        with open(eip_filename, "w", newline='') as f:
            writer = csv.DictWriter(f, fieldnames=eip_fieldnames)
            writer.writeheader()
            for item in eips:
                writer.writerow(item)

        print(f"✅ EIP report saved to '{eip_filename}'")

    except Exception as e:
        print(f"❌ Failed to save CSV files: {e}")


# ----------------------------
# Run It!
# ----------------------------

if __name__ == "__main__":
    scan_ec2()