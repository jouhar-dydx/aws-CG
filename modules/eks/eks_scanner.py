# modules/eks_scanner.py

from datetime import datetime, timezone
import boto3
import csv
import json
import os
from botocore.exceptions import ClientError
from kubernetes import client as k8s_client
from kubernetes.client.rest import ApiException

# Local imports (relative to project root)
try:
    from ai.predict_root_cause import predict_root_cause
except ImportError:
    print("AI module 'ai/predict_root_cause' not found. Running without root cause prediction.")
    predict_root_cause = lambda x: {"predicted_cause": "Unknown", "confidence": 0}

# ----------------------------
# Helper Functions
# ----------------------------

def calculate_age(created_date):
    now = datetime.now(timezone.utc)
    if isinstance(created_date, str):
        created_date = created_date.replace(" ", "T")
    return (now - datetime.fromisoformat(created_date)).days


def save_to_json(data, filename="reports/eks_clusters_report.json"):
    try:
        os.makedirs("reports", exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        new_filename = f"reports/eks_clusters_report_{timestamp}.json"
        with open(new_filename, "w") as f:
            json.dump(data, f, indent=4, default=str)
        print(f"JSON report saved to '{new_filename}'")
    except Exception as e:
        print(f"Failed to save JSON file: {e}")


def save_to_csv(data, filename="reports/eks_clusters_report.csv"):
    try:
        os.makedirs("reports", exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        new_filename = f"reports/eks_clusters_report_{timestamp}.csv"

        fieldnames = [
            "cluster_name",
            "version",
            "region",
            "vpc_id",
            "public_access",
            "iam_role",
            "node_groups_count",
            "fargate_profiles_count",
            "age_days",
            "tags",
            "total_pods",
            "pending_pods",
            "crashloop_pods",
            "image_pull_errors",
            "nodes_not_ready",
            "issues"
        ]

        with open(new_filename, "w", newline='') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for item in data:
                item["issues"] = "; ".join(item.get("issues", []))
                row = {k: v for k, v in item.items() if k in fieldnames}
                writer.writerow(row)

        print(f"Instance report saved to '{new_filename}'")

    except Exception as e:
        print(f"Failed to save CSV files: {e}")

# ----------------------------
# Scan EKS Clusters using Boto3
# ----------------------------

def scan_eks_clusters(session):
    eks_client = session.client("eks")
    valid_regions = []

    print("\nDetecting Enabled & Accessible Regions...\n")

    # Get all regions where EKS can be accessed
    ec2 = session.client('ec2', region_name='us-east-1')
    try:
        response = ec2.describe_regions()
        available_regions = [region['RegionName'] for region in response['Regions']]
    except ClientError as e:
        print(f"Failed to list AWS regions: {e}")
        exit(1)

    for region in available_regions:
        try:
            eks = session.client("eks", region_name=region)
            eks.list_clusters(maxResults=1)
            valid_regions.append(region)
            print(f"Region '{region}' is accessible")
        except ClientError:
            pass  # Silently skip inaccessible regions

    if not valid_regions:
        print("No accessible EKS-enabled regions found.")
        exit(1)

    all_clusters = []

    for region in valid_regions:
        eks = session.client("eks", region_name=region)

        print(f"\nScanning EKS Clusters in Region: {region}")
        try:
            response = eks.list_clusters()
            cluster_names = response.get("clusters", [])
            if not cluster_names:
                print(f"   ➖ No EKS clusters found in this region.")
                continue

            for cluster_name in cluster_names:
                try:
                    cluster_info = eks.describe_cluster(name=cluster_name)
                    cluster = cluster_info["cluster"]
                    name = cluster["name"]
                    version = cluster["version"]
                    vpc_id = cluster.get("resourcesVpcConfig", {}).get("vpc")
                    public_access = cluster.get("resourcesVpcConfig", {}).get("publicAccess")
                    iam_role = cluster.get("roleArn")
                    created_at = cluster["createdAt"]
                    age_days = calculate_age(str(created_at))
                    tags = cluster.get("tags", {})

                    eks_data = {
                        "cluster_name": name,
                        "version": version,
                        "region": region,
                        "vpc_id": vpc_id,
                        "public_access": public_access,
                        "iam_role": iam_role,
                        "node_groups_count": 0,
                        "fargate_profiles_count": 0,
                        "age_days": age_days,
                        "tags": tags,
                        "total_pods": 0,
                        "pending_pods": 0,
                        "crashloop_pods": 0,
                        "image_pull_errors": 0,
                        "nodes_not_ready": 0,
                        "issues": []
                    }

                    all_clusters.append(eks_data)

                except ClientError as ce:
                    print(f" Failed to describe cluster {cluster_name}: {ce}")

        except ClientError as e:
            print(f" Failed to list clusters in {region}: {e}")

    return all_clusters, valid_regions


# ----------------------------
# Connect to Kubernetes API
# ----------------------------

def connect_k8s_from_session_manager(session, region, cluster_name):
    """Use boto3 credentials to access K8s API without kubeconfig"""
    eks = session.client("eks", region_name=region)
    try:
        resp = eks.describe_cluster(name=cluster_name)
        endpoint = resp["cluster"]["endpoint"]
        cert_data = resp["cluster"]["certificateAuthority"]["data"]

        configuration = k8s_client.Configuration()
        configuration.host = endpoint
        configuration.verify_ssl = True
        configuration.ssl_ca_cert = cert_data

        api_client = k8s_client.ApiClient(configuration)
        return api_client
    except Exception as e:
        print(f" Unable to authenticate to Kubernetes API: {e}")
        return None


# ----------------------------
# Scan Kubernetes Resources
# ----------------------------

def scan_k8s_resources(session, cluster_data):
    results = []

    for cluster in cluster_data:
        print(f"\nConnecting to Cluster: {cluster['cluster_name']} ({cluster['region']})")
        api_client = connect_k8s_from_session_manager(session, cluster["region"], cluster["cluster_name"])
        if not api_client:
            cluster["kube_api_error"] = "Authentication failed"
            results.append(cluster)
            continue

        core_v1 = k8s_client.CoreV1Api(api_client)

        issues = []

        # Scan Pods
        try:
            ret = core_v1.list_pod_for_all_namespaces(watch=False)
            crashloop_pods = 0
            pending_pods = 0
            image_pull_errors = 0

            for p in ret.items:
                if p.status.phase == "Pending":
                    pending_pods += 1
                elif p.status.container_statuses:
                    statuses = p.status.container_statuses
                    for c in statuses:
                        if c.state and c.state.waiting:
                            reason = c.state.waiting.reason
                            if reason == "CrashLoopBackOff":
                                crashloop_pods += 1
                            elif reason == "ImagePullBackOff":
                                image_pull_errors += 1

            cluster["total_pods"] = len(ret.items)
            cluster["pending_pods"] = pending_pods
            cluster["crashloop_pods"] = crashloop_pods
            cluster["image_pull_errors"] = image_pull_errors

            if crashloop_pods > 0:
                issues.append(f"{crashloop_pods} pods in CrashLoopBackOff")
            if pending_pods > 0:
                issues.append(f"{pending_pods} pods stuck in Pending")
            if image_pull_errors > 0:
                issues.append(f"{image_pull_errors} ImagePullBackOff errors")

        except ApiException as pe:
            issues.append(f"Pod listing failed: {pe.reason}")
            print(f" Pod scanning error: {pe.reason}")

        # Scan Nodes
        try:
            nodes = core_v1.list_node(watch=False)
            not_ready_nodes = sum(
                1 for n in nodes.items
                if not any(c.type == 'Ready' and c.status == 'True' for c in n.status.conditions)
            )
            cluster["nodes_not_ready"] = not_ready_nodes
            if not_ready_nodes > 0:
                issues.append(f"{not_ready_nodes} worker nodes not Ready")

        except ApiException as ne:
            issues.append(f"Node scanning failed: {ne.reason}")
            print(f" Node scanning error: {ne.reason}")

        # Scan Events for Warnings
        try:
            events = core_v1.list_event_for_all_namespaces(limit=50)
            relevant_events = []
            for ev in events.items:
                if ev.type == "Warning":
                    relevant_events.append({
                        "reason": ev.reason,
                        "message": ev.message,
                        "type": ev.type,
                        "timestamp": str(ev.last_timestamp)
                    })

            cluster["events"] = relevant_events
            if relevant_events:
                issues.append("Recent Warning Events Found")

                # Predict root cause
                sample_message = "\n".join([ev["message"] for ev in relevant_events[:3]])
                prediction = predict_root_cause(sample_message)
                predicted_cause = prediction.get("predicted_cause", "Unknown")
                confidence = prediction.get("confidence", 0)

                issues[-1] += f" | AI: Possible cause → {predicted_cause} ({confidence}% confidence)"

        except ApiException as ee:
            print(f" Event scanning error: {ee.reason}")

        # Update cluster metadata
        cluster["issues"] = issues
        results.append(cluster)

    return results


# ----------------------------
# Main EKS Scanning Function
# ----------------------------

def scan_eks():
    session = boto3.Session()

    print("\nRunning Enhanced EKS Health & Configuration Scanner\n")

    # Validate AWS Credentials First
    try:
        sts = session.client("sts")
        identity = sts.get_caller_identity()
        print(f"Authenticated as: {identity['Arn']}")
    except Exception as e:
        print(f" Unable to validate AWS credentials: {e}")
        exit(1)

    # Step 1: Scan EKS Clusters via AWS API
    eks_clusters, valid_regions = scan_eks_clusters(session)

    # Step 2: Scan Kubernetes Resources via K8s API
    print("\nAnalyzing Kubernetes Resources...\n")
    full_clusters = scan_k8s_resources(session, eks_clusters)

    # Generate Report
    report_data = {
        "timestamp": str(datetime.now()),
        "clusters": full_clusters
    }

    save_to_json(report_data)
    save_to_csv(full_clusters)

    print("\nEKS Health Summary:")
    total_clusters = len(full_clusters)
    crashloop_pods = sum(c.get("crashloop_pods", 0) for c in full_clusters)
    pending_pods = sum(c.get("pending_pods", 0) for c in full_clusters)
    image_pull_errors = sum(c.get("image_pull_errors", 0) for c in full_clusters)
    not_ready_nodes = sum(c.get("nodes_not_ready", 0) for c in full_clusters)

    print(f"Total Clusters: {total_clusters}")
    print(f"Pods in CrashLoopBackOff: {crashloop_pods}")
    print(f"Pods in Pending: {pending_pods}")
    print(f"Image Pull Errors: {image_pull_errors}")
    print(f"Worker Nodes Not Ready: {not_ready_nodes}")

    print("\n EKS Scan Complete.")
    return report_data


# ----------------------------
# Run It!
# ----------------------------

if __name__ == "__main__":
    scan_eks()