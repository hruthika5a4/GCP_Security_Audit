# ----------------- main.py -----------------
from flask import make_response
from datetime import datetime
from google.auth import default
from audit_checks import (
    check_compute_public_ips,
    check_sql_public_ips,
    check_gke_clusters,
    check_owner_service_accounts,
    check_public_buckets,
    check_load_balancers,
    check_firewall_vulnerabilities,
    check_vpc_flow_logs,
    check_cloud_nat_logs,
    check_ip_forwarding
)
from report_excel import create_excel_report
from report_email import send_audit_email


# ----------------- Recommendation Logic -----------------
def get_recommendation(category, row):
    """Generate recommendation text based on category"""
    category = category.lower()
    text = "No issues found."

    if "compute" in category:
        text = "Avoid assigning external/public IPs to VMs unless absolutely required."
    elif "sql" in category:
        text = "Use private IP for Cloud SQL and restrict public access."
    elif "gke" in category:
        text = "Restrict public endpoint access and enable authorized networks."
    elif "iam" in category:
        text = "Avoid using 'Owner' role; follow least privilege principle."
    elif "bucket" in category:
        text = "Remove public access; apply uniform bucket-level access."
    elif "load balancer" in category:
        text = "Restrict frontend access to trusted IP ranges or use Cloud Armor."
    elif "firewall" in category:
        text = "Restrict 0.0.0.0/0 source ranges and avoid open SSH/RDP ports."
    elif "vpc" in category or "logging" in category:
        text = "Enable VPC flow and firewall logging for better network visibility."
    elif "cloud nat" in category:
        text = "Enable Cloud NAT logging for audit and troubleshooting."
    elif "ip forwarding" in category:
        text = "Disable IP forwarding unless VM acts as NAT/router."
    return text


# ----------------- Main Audit Function -----------------
def security_audit(request):
    creds, project = default()

    # ----------------- Run All Checks -----------------
    vm_data = check_compute_public_ips()
    sql_data = check_sql_public_ips()
    gke_data = check_gke_clusters()
    owner_data = check_owner_service_accounts()
    bucket_data = check_public_buckets()
    lb_data = check_load_balancers()
    firewall_data = check_firewall_vulnerabilities()
    vpc_flow_data = check_vpc_flow_logs()
    nat_data = check_cloud_nat_logs()
    ip_forward_data = check_ip_forwarding()

    # ----------------- Excel Report -----------------
    excel_path = create_excel_report(
        project, vm_data, sql_data, gke_data, owner_data,
        bucket_data, firewall_data, vpc_flow_data, nat_data,
        lb_data, ip_forward_data
    )

    status = send_audit_email(project, excel_path, "pradeepsinghania906@gmail.com")

    # ----------------- HTML UI -----------------
    html = f"""
    <html>
    <head>
        <title>GCP Security Audit Dashboard</title>
        <script src="https://cdn.tailwindcss.com"></script>
        <style>
            th, td {{
                padding: 8px 10px;
                text-align: left;
                border-bottom: 1px solid #e5e7eb;
            }}
            table {{
                width: 100%;
                border-collapse: collapse;
                margin-top: 0.5rem;
            }}
            thead {{
                background-color: #f1f5f9;
                color: #1e3a8a;
                font-weight: 600;
            }}
            .print-btn {{
                background-color: #2563eb;
                color: white;
                padding: 8px 16px;
                border-radius: 6px;
                font-size: 14px;
                margin-bottom: 10px;
            }}
            .print-btn:hover {{
                background-color: #1d4ed8;
            }}
        </style>
    </head>
    <body class="bg-gray-50 text-gray-900">
        <div class="max-w-7xl mx-auto mt-10 p-6 bg-white shadow-lg rounded-lg">
            <div class="flex justify-between items-center mb-4">
                <h1 class="text-3xl font-bold text-blue-700">GCP Security Audit Dashboard</h1>
                <button class="print-btn" onclick="window.print()">Print Report</button>
            </div>
            <p class="text-gray-600 mb-6">
                Project: <b>{project}</b> | Time: {datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")}
            </p>
    """

    # ----------------- Display Sections -----------------
    sections = [
        ("Compute Engine", vm_data, ["Instance Name", "Zone", "External IP"]),
        ("Cloud SQL", sql_data, ["Instance Name", "Public IP"]),
        ("GKE Clusters", gke_data, ["Cluster Name", "Endpoint"]),
        ("IAM Owners", owner_data, ["Account", "Role"]),
        ("Buckets", bucket_data, ["Bucket Name", "Access Level", "Entity"]),
        ("Load Balancers", lb_data, ["LB Name", "Scheme", "IP", "Target", "SSL Policy", "Cloud Armor"]),
        ("Firewall Rules", firewall_data, ["Rule Name", "Port/Protocol", "Source Ranges", "Status", "Reason"]),
        ("VPC Flow Logs", vpc_flow_data, ["Subnet", "Region", "Flow Enabled", "Sample Rate", "Status", "Reason"]),
        ("Cloud NAT Logs", nat_data, ["NAT Name", "Router", "Logging Enabled", "Status", "Reason"]),
        ("IP Forwarding", ip_forward_data, ["Instance", "Can IP Forward", "Status", "Reason"]),
    ]

    # ----------------- Build Tables -----------------
    for category, data, headers in sections:
        html += f"""
        <div class='border border-gray-200 rounded-lg p-4 mb-6'>
            <h2 class='text-xl font-semibold text-blue-600 mb-2'>{category}</h2>
        """
        if data:
            html += "<div class='overflow-x-auto'><table class='min-w-full text-sm text-gray-800'><thead><tr>"
            for h in headers:
                html += f"<th>{h}</th>"
            html += "<th>Recommendation</th></tr></thead><tbody>"

            for row in data:
                html += "<tr class='hover:bg-gray-50'>"
                for cell in row:
                    html += f"<td>{str(cell)}</td>"
                rec = get_recommendation(category, row)
                html += f"<td>{rec}</td></tr>"
            html += "</tbody></table></div>"
        else:
            html += "<p class='text-green-600 font-medium'>✅ No issues found.</p>"
        html += "</div>"

    html += f"""
        <p class="text-center text-green-700 font-semibold mt-6">{status}</p>
        </div>
    </body>
    </html>
    """

    response = make_response(html)
    response.headers['Content-Type'] = 'text/html'
    return response
