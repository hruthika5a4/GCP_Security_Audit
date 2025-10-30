from flask import make_response
from audit_checks import (
    check_compute_public_ips,
    check_sql_public_ips,
    check_gke_clusters,
    check_owner_service_accounts,
    check_public_buckets,
    check_firewall_rules,
    check_load_balancers_audit,
    check_cloud_functions_and_run  # ✅ NEW
)
from report_excel import create_excel_report
from report_email import send_audit_email
from datetime import datetime
from google.auth import default


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
    elif "service accounts with owner role" in category:
        text = "Avoid using 'Owner' role; follow least privilege principle."
    elif "bucket" in category:
        text = "Remove public access; apply uniform bucket-level access."
    elif "firewall" in category:
        text = "Avoid using 0.0.0.0/0 in firewall rules; restrict to trusted IP ranges."
    elif "load balancer" in category:
        text = "Ensure HTTPS redirection, valid SSL certificates, and strong Cloud Armor policies."
    elif "cloud function" in category or "cloud run" in category:
        text = "Restrict unauthenticated invocations and use ingress controls for internal-only access."

    return text


def security_audit(request):
    creds, project = default()

    # ----------------- Run all security checks -----------------
    vm_data = check_compute_public_ips()
    sql_data = check_sql_public_ips()
    gke_data = check_gke_clusters()
    owner_data = check_owner_service_accounts()
    bucket_data = check_public_buckets()
    fw_data = check_firewall_rules()
    lb_data = check_load_balancers_audit()
    cf_data = check_cloud_functions_and_run()  # ✅ Cloud Functions + Cloud Run check

    # ----------------- Excel + Email -----------------
    excel_path = create_excel_report(
        project,
        vm_data,
        sql_data,
        gke_data,
        owner_data,
        bucket_data,
        fw_data,
        lb_data,
        cf_data  # ✅ Include new audit data
    )
    status = send_audit_email(project, excel_path, "hruthika.sa@cloudambassadors.com")

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

    # ----------------- Sections for HTML -----------------
    sections = [
        ("Compute Engine", vm_data, ["Instance Name", "Zone", "External IP"]),
        ("Cloud SQL", sql_data, ["Instance Name", "Public IP"]),
        ("GKE Clusters", gke_data, ["Cluster Name", "Endpoint"]),
        ("Service Accounts with Owner Role", owner_data, ["Account", "Role"]),
        ("Buckets", bucket_data, ["Bucket Name", "Access Level", "Entity"]),
        ("Firewall Rules", fw_data, ["Rule Name", "Direction", "Protocols", "Source Ranges", "Network", "Priority", "Disabled"]),
        ("Load Balancers", lb_data, [
            "LB Name", "Scheme", "IP", "SSL Policy",
            "SSL Cert Status", "HTTPS Redirect", "Cloud Armor Policy",
            "Armor Rule Strength", "Internal Exposure"
        ]),
        ("Cloud Functions & Cloud Run", cf_data, [
            "Resource Type", "Name", "Region", "Runtime", "Trigger Type",
            "URL", "Ingress Setting", "Auth Level", "Service Account",
            "Unauthenticated Access", "Exposure Risk"
        ])
    ]

    # ----------------- Build tables dynamically -----------------
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
                if isinstance(row, dict):
                    for val in row.values():
                        html += f"<td>{str(val)}</td>"
                else:
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


