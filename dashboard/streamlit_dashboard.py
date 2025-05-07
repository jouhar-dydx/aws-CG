# dashboard/streamlit_dashboard.py

import streamlit as st
import pandas as pd
import os
import json
from datetime import datetime

st.set_page_config(page_title="AWS DevOps Copilot", layout="wide")
st.title("🖥️ AWS EC2 & IAM DevOps Copilot Dashboard")

# Load JSON report
report_file = "reports/ec2_instances_report.json"

if not os.path.exists(report_file):
    st.warning("⚠️ No EC2 report found. Please run the scanner first.")
else:
    with open(report_file, "r") as f:
        report = json.load(f)

    instances = report.get("instances", [])
    eips = report.get("elastic_ips", [])

    df_instances = pd.DataFrame(instances)
    df_eips = pd.DataFrame(eips)

    # Show summary metrics
    st.header("📊 Resource Health Summary")

    col1, col2, col3 = st.columns(3)
    col1.metric("Total EC2 Instances", len(df_instances))
    col2.metric("Running Instances", len(df_instances[df_instances["state"] == "running"]))
    
    orphaned_eip_count = 0
    if not df_eips.empty and 'orphaned' in df_eips.columns:
        orphaned_eip_count = len(df_eips[df_eips['orphaned'] == True])
    col3.metric("Orphaned Elastic IPs", orphaned_eip_count)

    # Instance Details Table
    st.subheader("🖥️ EC2 Instances")
    if not df_instances.empty:
        instance_columns = [
            "instance_id", "name", "state", "type", "public_ip",
            "private_ip", "region", "vpc_id", "key_name", "age_days",
            "platform", "iam_role", "public_ssh_exposed"
        ]
        filtered_df = df_instances[instance_columns]
        st.dataframe(filtered_df)
    else:
        st.info("No EC2 instance data found.")

    # EIP Details Table
    st.subheader("📍 Elastic IPs")
    if not df_eips.empty:
        st.dataframe(df_eips)
    else:
        st.info("No Elastic IP data found.")

    # Tag Suggestions (optional — add if implemented in scanner)
    st.sidebar.header("🏷️ Auto Tag Suggestions")
    tag_suggestions_found = False

    for idx, inst in enumerate(df_instances.to_dict(orient='records')):
        auto_tags = inst.get("auto_tag_suggestion", {})
        if auto_tags:
            st.sidebar.warning(f"{inst['instance_id']} → {auto_tags}")
            tag_suggestions_found = True

    if not tag_suggestions_found:
        st.sidebar.info("All instances are properly tagged.")

    # Last Scan Info
    st.sidebar.header("🕒 Last Scan Time")
    st.sidebar.info(report.get("timestamp", "Unknown"))

    # Download buttons
    st.sidebar.header("⬇️ Download Reports")

    @st.cache_data
    def convert_df_to_csv(df):
        return df.to_csv(index=False).encode('utf-8')

    if not df_instances.empty:
        csv_instances = convert_df_to_csv(df_instances)
        st.sidebar.download_button(
            label="Download Instance Report",
            data=csv_instances,
            file_name="ec2_instances_report.csv",
            mime="text/csv"
        )

    if not df_eips.empty:
        csv_eips = convert_df_to_csv(df_eips)
        st.sidebar.download_button(
            label="Download EIP Report",
            data=csv_eips,
            file_name="ec2_elastic_ips_report.csv",
            mime="text/csv"
        )