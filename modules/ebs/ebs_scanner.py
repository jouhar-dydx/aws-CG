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


def get_valid_regions():
    session = boto3.Session()
    ec2_client = session.client("ec2", region_name="us-east-1")

    valid_regions = []
    try:
        response = ec2_client.describe_regions()
        for region in response.get("Regions", []):
            region_name = region["RegionName"]
            valid_regions.append(region_name)
    except ClientError as e:
        print(f" Unable to describe AWS regions: {e}")
        exit(1)

    if not valid_regions:
        print(" No accessible regions found. Check AWS credentials or IAM permissions.")
        exit(1)

    return valid_regions


def save_to_json(data, filename="reports/ebs_volumes_report.json"):
    try:
        with open(filename, "w") as f:
            json.dump(data, f, indent=4, default=str)
    except Exception as e:
        print(f" Failed to save JSON file: {e}")


def save_to_csv(data, filename="reports/ebs_volumes_report.csv"):
    try:
        fieldnames = ["volume_id", "created", "age_days", "type", "size_gb", "attached_instance", "state", "region", "tags", "orphaned"]
        with open(filename, "w", newline='') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for item in data:
                writer.writerow(item)
        print(f" CSV report saved to '{filename}'")
    except Exception as e:
        print(f" Failed to save CSV file: {e}")

# ----------------------------
# Main EBS Volume Scanning Function
# ----------------------------

def scan_ebs_volumes():
    session = boto3.Session()

    print("\n Running Enhanced EBS Volume Scanner...\n")

    # Validate AWS Credentials
    try:
        sts = session.client("sts")
        identity = sts.get_caller_identity()
        print(f"👤 Authenticated as: {identity['Arn']}")
    except NoCredentialsError:
        print(" AWS credentials not found. Run 'aws configure'")
        exit(1)
    except ClientError as e:
        print(f" Unable to validate AWS credentials: {e}")
        exit(1)

    valid_regions = get_valid_regions()
    all_volumes = []

    # Scan Volumes
    print("\n Scanning EBS Volumes Across Regions...")

    for region in valid_regions:
        ec2_client = session.client("ec2", region_name=region)

        try:
            paginator = ec2_client.get_paginator("describe_volumes")
            page_iterator = paginator.paginate()

            region_has_volumes = False
            for page in page_iterator:
                for vol in page.get("Volumes", []):
                    region_has_volumes = True  # Mark region as having volumes
                    volume_id = vol["VolumeId"]
                    state = vol["State"]
                    size = vol["Size"]
                    volume_type = vol["VolumeType"]
                    created = str(vol["CreateTime"])
                    age_days = calculate_age(vol["CreateTime"])
                    tags = vol.get("Tags", [])
                    attached = len(vol.get("Attachments", [])) > 0
                    attached_instance = vol["Attachments"][0]["InstanceId"] if attached else "None"

                    volume_data = {
                        "volume_id": volume_id,
                        "created": created,
                        "age_days": age_days,
                        "type": volume_type,
                        "size_gb": size,
                        "attached_instance": attached_instance,
                        "state": state,
                        "region": region,
                        "tags": tags,
                        "orphaned": not attached
                    }

                    all_volumes.append(volume_data)

            # Only show region if it has volumes
            if region_has_volumes:
                print(f"\n Region: {region} ({len(page.get('Volumes', []))} volumes)")
                for vol in all_volumes:
                    if vol["region"] == region:
                        status_line = " Orphaned" if vol["orphaned"] else " In Use"
                        instance_info = f"→ Instance: {vol['attached_instance']}" if not vol["orphaned"] else ""

                        print(f" - {status_line}: {vol['volume_id']} | Size: {vol['size_gb']} GB | Type: {vol['type']} {instance_info}")

        except ClientError as e:
            print(f" Failed to describe EBS volumes in {region}: {e}")

    # Generate Report
    report_data = {
        "timestamp": str(datetime.now()),
        "volumes": all_volumes
    }

    save_to_json(report_data)
    save_to_csv(all_volumes)

    # Summary
    total_volumes = len(all_volumes)
    orphaned_volumes = sum(1 for v in all_volumes if v["orphaned"])

    print("\n EBS Volume Health Summary:")
    print(f"Total Volumes: {total_volumes}")
    print(f" Orphaned / Unused Volumes: {orphaned_volumes}")

    # Health Score
    max_score = total_volumes * 100
    deductions = orphaned_volumes * 70
    final_score = max(0, max_score - deductions)
    health_percentage = round(final_score / max_score * 100, 2) if max_score > 0 else 100

    print(f"\n Final EBS Health Score: {health_percentage}/100")
    if health_percentage >= 80:
        print(" Excellent — no orphaned volumes")
    elif health_percentage >= 60:
        print(" Good, but some cleanup needed")
    elif health_percentage >= 20:
        print(" Moderate risk — several unused volumes")
    else:
        print(" Critical — Most volumes are orphaned!")

    print("\n EBS Scan Complete.")
    return report_data


# ----------------------------
# Run It!
# ----------------------------

if __name__ == "__main__":
    scan_ebs_volumes()