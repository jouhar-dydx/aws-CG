# main.py
from modules.iam_scanner import scan_iam
from modules.utils import load_aws_services
from modules.elastic_ip_scanner import scan_elastic_ips
from modules.s3_scanner import scan_s3
from modules.ebs_scanner import scan_ebs_volumes
from modules.ec2_scanner import scan_ec2

def main():
    print("🚀 Welcome to AWS DevOps Copilot v1.0")
    print("--------------------------------------\n")

    print("📦 Loading AWS Services...")
    services = load_aws_services()
    print(f"✅ Loaded {len(services)} AWS services.\n")

    print("🔍 Starting IAM Security Scan...")
    scan_iam()
    scan_elastic_ips()
    scan_s3()
    scan_ebs_volumes()
    scan_ec2()

if __name__ == "__main__":
    main()