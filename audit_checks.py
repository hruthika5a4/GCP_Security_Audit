from flask import make_response
from audit_checks import *
from report_excel import create_excel_report
from report_email import send_audit_email
from datetime import datetime


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
    elif "firewall" in category or "logging" in category:
        text = "Enable firewall and VPC flow logging for better visibility."
    elif "network" in category:
        text = "Restrict open ports (SSH/RDP) and apply IP-based filtering."
    elif "ip forwarding" in category:
        text = "Disable IP forwarding unless the VM is a NAT/router."
    return text


def security_audit(request):
    creds, project = default()

    # ----------------- Run checks -----------------
    vm_data = check_compute_public_ips()
    sql_data = check_sql_public_ips()
    gke_data = check_gke_clusters()
    owner_data = check_owner_service_accounts()
    bucket_data = check_public_buckets()
    lb_data = check_load_balancers()
    cis_results = audit_cis()

    networking_data, logging_data, org_data, ip_forwarding = [], [], [], []

    # CIS checks formatting
    for ssh in cis_results.get("ssh_firewall", []):
        networking_data.append(["SSH Firewall", ssh[0], f"Logging Enabled: {ssh[1]}"])
    for rdp in cis_results.get("rdp_firewall", []):
        networking_data.append(["RDP Firewall", rdp[0], f"Logging Enabled: {rdp[1]}"])
    for fw in cis_results.get("firewall_logs", []):
        logging_data.append(["Firewall Rule", fw[0], f"Logging Enabled: {fw[1]}"])
    for vpc in cis_results.get("vpc_flow_logs", []):
        logging_data.append(["VPC Flow Logs", vpc[0], f"Flow Enabled: {vpc[1]}, Sample Rate: {vpc[2]}"])
    for nat in cis_results.get("cloud_nat_logs", []):
        logging_data.append(["Cloud NAT", nat[0], f"Router: {nat[1]}, Logging Enabled: {nat[2]}"])

    # ✅ Fixed: IP Forwarding formatting
    for ipf in cis_results.get("ip_forwarding", []):
        if isinstance(ipf, list) and len(ipf) == 3:
            instance_name = ipf[0]
            can_ip_forward = ipf[1]
            status = ipf[2] if len(ipf) > 2 else ""
            ip_forwarding.append(["Compute Instance", instance_name, str(can_ip_forward)])
        elif isinstance(ipf, list) and len(ipf) == 2:
            ip_forwarding.append(["Compute Instance", ipf[0], str(ipf[1]), ""])
        else:
            ip_forwarding.append(["Compute Instance", str(ipf), "", ""])

    # ----------------- Excel + Email -----------------
    excel_path = create_excel_report(
        project, vm_data, sql_data, gke_data, owner_data,
        bucket_data, networking_data, logging_data, org_data,
        lb_data, ip_forwarding
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

    sections = [
        ("Compute Engine", vm_data, ["Instance Name", "Zone", "External IP"]),
        ("Cloud SQL", sql_data, ["Instance Name", "Public IP"]),
        ("GKE Clusters", gke_data, ["Cluster Name", "Endpoint"]),
        ("IAM Owners", owner_data, ["Account", "Role"]),
        ("Buckets", bucket_data, ["Bucket Name", "Access Level", "Entity"]),
        ("Load Balancers", lb_data, ["LB Name", "Type"]),
        ("Logging Checks", logging_data, ["Resource", "Details", "Logging Enabled Status"]),
        ("Networking Checks", networking_data, ["Resource", "Rule", "Status"]),
        ("IP Forwarding", ip_forwarding, ["Type", "Instance Name", "canIpForward Status"]),
    ]

    # ----------------- Build tables -----------------
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
            html += "<p class='text-green-600 font-medium'>No issues found.</p>"
        html += "</div>"

    html += f"""
        <p class="text-center text-green-700 font-semibold mt-6">
            {status}
        </p>
        </div>
    </body>
    </html>
    """

    response = make_response(html)
    response.headers['Content-Type'] = 'text/html'
    return response
