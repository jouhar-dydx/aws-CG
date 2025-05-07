# modules/elastic_ip_scanner.py

from datetime import datetime, timezone
import boto3
import csv
import json
from botocore.exceptions import ClientError, NoCredentialsError
import dateutil.parser

# ----------------------------
# Helper Functions
# ----------------------------

def save_to_json(data, filename="reports/ec2_elastic_ips_report.json"):
    try:
        with open(filename, "w") as f:
            json.dump(data, f, indent=4, default=str)
        # print(f" JSON report saved to '{filename}'")
    except Exception as e:
        print(f" Failed to save JSON file: {e}")


def save_to_csv(data, filename="reports/ec2_elastic_ips_report.csv"):
    try:
        fieldnames = [
            "public_ip",
            "allocation_id",
            "association_id",
            "instance_id",
            "network_interface",
            "region",
            "orphaned"
        ]
        with open(filename, "w", newline='') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for item in data:
                writer.writerow(item)
        # print(f" CSV report saved to '{filename}'")
    except Exception as e:
        print(f" Failed to save CSV file: {e}")


def get_valid_regions():
    session = boto3.Session()
    ec2_client = session.client("ec2", region_name="us-east-1")

    valid_regions = []
    try:
        response = ec2_client.describe_regions()
        for region in response.get("Regions", []):
            region_name = region["RegionName"]
            try:
                # Test access by listing instances
                ec2 = session.client("ec2", region_name=region_name)
                ec2.describe_instances(MaxResults=5)  # Test access
                valid_regions.append(region_name)
            except ClientError as e:
                # Suppress error messages for cleaner run
                pass
    except ClientError as e:
        print(f" Unable to describe AWS regions: {e}")
        exit(1)

    if not valid_regions:
        print(" No accessible regions found. Check AWS credentials or IAM permissions.")
        exit(1)

    return valid_regions


# ----------------------------
# Main Elastic IP Scanning Function
# ----------------------------

def scan_elastic_ips():
    session = boto3.Session()

    print("\n Running Enhanced Elastic IP Scanner...\n")

    # Validate AWS Credentials
    try:
        sts = session.client("sts")
        identity = sts.get_caller_identity()
        print(f" Authenticated as: {identity['Arn']}")
    except NoCredentialsError:
        print(" AWS credentials not found. Run 'aws configure'")
        exit(1)
    except ClientError as e:
        print(f" Unable to validate AWS credentials: {e}")
        exit(1)

    valid_regions = get_valid_regions()
    all_eips = []

    # Scan Elastic IPs
    print("\n Scanning Elastic IPs Across Regions...")
    for region in valid_regions:
        ec2_client = session.client("ec2", region_name=region)

        try:
            response = ec2_client.describe_addresses()
            for eip in response.get("Addresses", []):
                instance_id = eip.get("InstanceId", "Unattached")
                public_ip = eip.get("PublicIp", "Unknown")
                allocation_id = eip.get("AllocationId", "N/A")
                association_id = eip.get("AssociationId", "N/A")
                network_interface = eip.get("NetworkInterfaceId", "None")

                eip_data = {
                    "public_ip": public_ip,
                    "allocation_id": allocation_id,
                    "association_id": association_id,
                    "instance_id": instance_id,
                    "network_interface": network_interface,
                    "region": region,
                    "orphaned": instance_id == "Unattached"
                }

                all_eips.append(eip_data)

                if eip_data["orphaned"]:
                    print(f" Orphaned EIP: {public_ip} (not attached to any instance)")
                else:
                    print(f" EIP: {public_ip} → Instance: {instance_id}")

        except ClientError as e:
            # Optionally log region errors silently
            pass

    # Generate Report
    report_data = {
        "timestamp": str(datetime.now()),
        "elastic_ips": all_eips
    }

    save_to_json(report_data)
    save_to_csv(all_eips)

    # Summary
    total_eips = len(all_eips)
    orphaned_eip_count = sum(1 for eip in all_eips if eip["orphaned"])

    print("\n Elastic IP Health Summary:")
    print(f"Total Elastic IPs: {total_eips}")
    print(f"Orphaned / Unattached: {orphaned_eip_count}")

    # Health Score
    max_score = total_eips * 100
    deductions = orphaned_eip_count * 50

    final_score = max(0, max_score - deductions)
    health_percentage = round(final_score / max_score * 100, 2) if max_score > 0 else 100

    print(f"\n Final Elastic IP Health Score: {health_percentage}/100")
    if health_percentage >= 80:
        print(" Excellent — no orphaned IPs")
    elif health_percentage >= 60:
        print(" Good, but some cleanup needed")
    elif health_percentage >= 20:
        print(" Moderate risk — several unused IPs")
    else:
        print(" Critical — Most IPs are orphaned!")

    print("\n Elastic IP Scan Complete.")
    return report_data


# ----------------------------
# Run It!
# ----------------------------

if __name__ == "__main__":
    scan_elastic_ips()