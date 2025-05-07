# modules/s3_scanner.py

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


def save_to_json(data, filename="reports/s3_buckets_report.json"):
    try:
        with open(filename, "w") as f:
            json.dump(data, f, indent=4, default=str)
        print(f"✅ JSON report saved to '{filename}'")
    except Exception as e:
        print(f"❌ Failed to save JSON file: {e}")


def save_to_csv(data, filename="reports/s3_buckets_report.csv"):
    try:
        fieldnames = ["bucket_name", "created", "age_days", "region", "public_access", "encryption_enabled", "versioning_enabled", "tags"]
        with open(filename, "w", newline='') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for item in data:
                row = {k: v for k, v in item.items() if k in fieldnames}
                writer.writerow(row)
        print(f"✅ CSV report saved to '{filename}'")
    except Exception as e:
        print(f"❌ Failed to save CSV file: {e}")


def check_overly_permissive_policy(policy_document):
    """Detect overly broad IAM policies on S3 bucket"""
    for statement in policy_document.get("Statement", []):
        if statement.get("Effect") == "Allow":
            principal = statement.get("Principal")
            action = statement.get("Action")
            resource = statement.get("Resource")

            if principal == "*" or principal == {"AWS": "*"}:
                if "s3:GetObject" in action or action == "s3:*" or action == "*":
                    return True
    return False


# ----------------------------
# Main S3 Scanning Function
# ----------------------------

def scan_s3():
    session = boto3.Session()

    print("\n🔍 Running Enhanced S3 Bucket Scanner...\n")

    # Validate AWS Credentials
    try:
        sts = session.client("sts")
        identity = sts.get_caller_identity()
        print(f"👤 Authenticated as: {identity['Arn']}")
    except NoCredentialsError:
        print("❌ AWS credentials not found. Run 'aws configure'")
        exit(1)
    except ClientError as e:
        print(f"❌ Unable to validate AWS credentials: {e}")
        exit(1)

    s3_client = session.client("s3")

    all_buckets = []

    try:
        response = s3_client.list_buckets()
        buckets = response.get("Buckets", [])
    except ClientError as e:
        print(f"❌ Error listing S3 buckets: {e}")
        exit(1)

    print(f"📦 Found {len(buckets)} S3 buckets.\n")

    for bucket in buckets:
        bucket_name = bucket["Name"]

        try:
            location = s3_client.get_bucket_location(Bucket=bucket_name)
            region = location.get("LocationConstraint", "us-east-1")
            if region is None:
                region = "us-east-1"
        except ClientError as e:
            region = "unknown"
            print(f"⚠️ Could not fetch region for '{bucket_name}': {e}")

        try:
            public_access_block = s3_client.get_public_access_block(Bucket=bucket_name)
            public_access = any([
                public_access_block["PublicAccessBlockConfiguration"].get("BlockPublicAcls"),
                public_access_block["PublicAccessBlockConfiguration"].get("BlockPublicPolicy"),
                public_access_block["PublicAccessBlockConfiguration"].get("BlockPublicAccess"),
                public_access_block["PublicAccessBlockConfiguration"].get("RestrictPublicBuckets")
            ])
            public_access = not public_access  # If all blocks are enabled → not public
        except ClientError as e:
            public_access = True  # Assume risky if we can't get config
            print(f"⚠️ Could not fetch public access block for '{bucket_name}': {e}")

        try:
            encryption = s3_client.get_bucket_encryption(Bucket=bucket_name)
            encryption_enabled = True
            rules = encryption.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])
            for rule in rules:
                if rule.get("ApplyServerSideEncryptionByDefault", {}).get("SSEAlgorithm") != "AES256":
                    encryption_enabled = False
        except ClientError:
            encryption_enabled = False

        try:
            versioning = s3_client.get_bucket_versioning(Bucket=bucket_name)
            versioning_enabled = versioning.get("Status") == "Enabled"
        except ClientError as e:
            versioning_enabled = False
            print(f"⚠️ Could not fetch versioning for '{bucket_name}': {e}")

        try:
            tagging = s3_client.get_bucket_tagging(Bucket=bucket_name)
            tags = tagging.get("TagSet", [])
        except ClientError:
            tags = []

        # Check bucket policy for overly broad permissions
        try:
            policy = s3_client.get_bucket_policy(Bucket=bucket_name)
            policy_doc = json.loads(policy["Policy"])
            has_risky_policy = check_overly_permissive_policy(policy_doc)
        except ClientError:
            has_risky_policy = False

        bucket_data = {
            "bucket_name": bucket_name,
            "created": str(bucket["CreationDate"]),
            "age_days": calculate_age(bucket["CreationDate"]),
            "region": region,
            "public_access": public_access,
            "encryption_enabled": encryption_enabled,
            "versioning_enabled": versioning_enabled,
            "tags": tags,
            "has_risky_policy": has_risky_policy
        }

        all_buckets.append(bucket_data)

        # Print summary per bucket
        print(f"🧾 Bucket: {bucket_data['bucket_name']} ({bucket_data['region']})")
        print(f"   Created: {bucket_data['created']} | Age: {bucket_data['age_days']} days")
        print(f"   Public Access: {'❌ Yes' if bucket_data['public_access'] else '✅ No'}")
        print(f"   Encryption: {'✅ Enabled' if bucket_data['encryption_enabled'] else '❌ Disabled'}")
        print(f"   Versioning: {'✅ Enabled' if bucket_data['versioning_enabled'] else '❌ Disabled'}")
        print(f"   Risky Policy: {'🚩 Yes' if bucket_data['has_risky_policy'] else '✅ No'}")
        print(f"   Tags: {bucket_data['tags'] or 'None'}")

        issues = []
        if bucket_data["public_access"]:
            issues.append("🔓 Publicly Accessible")
        if not bucket_data["encryption_enabled"]:
            issues.append("🔒 Missing Encryption")
        if not bucket_data["versioning_enabled"]:
            issues.append("🔄 Versioning Disabled")
        if not bucket_data["tags"]:
            issues.append("🏷️ No Tags Found")
        elif not any(tag["Key"] == "Owner" for tag in bucket_data["tags"]):
            issues.append("👤 Missing Owner Tag")
        if bucket_data["has_risky_policy"]:
            issues.append("🧼 Overly Permissive Bucket Policy")

        if issues:
            print("   🔍 Issues:")
            for issue in issues:
                print(f"     - {issue}")

    # Generate Report
    report_data = {
        "timestamp": str(datetime.now()),
        "buckets": all_buckets
    }

    save_to_json(report_data)
    save_to_csv(all_buckets)

    # Summary
    total_buckets = len(all_buckets)
    public_buckets = sum(1 for b in all_buckets if b["public_access"])
    no_encryption = sum(1 for b in all_buckets if not b["encryption_enabled"])
    no_versioning = sum(1 for b in all_buckets if not b["versioning_enabled"])
    no_tags = sum(1 for b in all_buckets if not b["tags"])
    risky_policies = sum(1 for b in all_buckets if b["has_risky_policy"])

    print("\n📊 S3 Health Summary:")
    print(f"Total Buckets: {total_buckets}")
    print(f"Publicly Accessible: {public_buckets}")
    print(f"Missing Encryption: {no_encryption}")
    print(f"Versioning Disabled: {no_versioning}")
    print(f"Missing Tags: {no_tags}")
    print(f"Overly Permissive Policies: {risky_policies}")

    # Calculate Health Score
    max_score = total_buckets * 100
    deductions = (
        public_buckets * 20 +
        no_encryption * 15 +
        no_versioning * 10 +
        no_tags * 5 +
        risky_policies * 25
    )

    final_score = max(0, max_score - deductions)
    health_percentage = round(final_score / max_score * 100, 2) if max_score > 0 else 100

    print(f"\n📈 Final S3 Health Score: {health_percentage}/100")
    if health_percentage >= 80:
        print("✅ Excellent — All buckets appear secure.")
    elif health_percentage >= 60:
        print("⚠️ Good, but some improvements possible.")
    elif health_percentage >= 20:
        print("🚩 Moderate risk detected.")
    else:
        print("🚨 Critical misconfigurations found.")

    print("\n✅ S3 Scan Complete.")
    return report_data


# ----------------------------
# Run It!
# ----------------------------

if __name__ == "__main__":
    scan_s3()