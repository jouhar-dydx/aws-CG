# modules/utils.py
import json
from datetime import datetime, timezone
import dateutil.parser

def load_aws_services(filename="aws_available_services.json"):
    try:
        with open(filename, "r") as f:
            return json.load(f)["services"]
    except FileNotFoundError:
        print("❌ File not found:", filename)
        return []
    except Exception as e:
        print("❌ Error loading services:", e)
        return []

def calculate_age(created_date):
    now = datetime.now(timezone.utc)

    if isinstance(created_date, str):
        try:
            created_date = dateutil.parser.parse(created_date)
        except Exception as e:
            print(f"❌ Failed to parse date: {created_date}. Error: {e}")
            return -1

    if isinstance(created_date, datetime):
        return (now - created_date.replace(tzinfo=timezone.utc)).days
    else:
        print("❌ Invalid date provided")
        return -1

def save_to_json(data, filename="reports/iam_audit_report.json"):
    try:
        with open(filename, "w") as f:
            json.dump(data, f, indent=4, default=str)
        print(f"\n✅ Report saved to '{filename}'")
    except Exception as e:
        print(f"❌ Failed to save JSON file: {e}")

def save_to_csv(data, filename="reports/iam_audit_report.csv"):
    try:
        fieldnames = ["type", "name", "arn", "created", "age_days", "risky"]
        with open(filename, "w", newline='') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for item in data:
                writer.writerow(item)
        print(f"✅ Report saved to '{filename}'")
    except Exception as e:
        print(f"❌ Failed to save CSV file: {e}")