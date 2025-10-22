from flask import make_response
from audit_checks import *
from report_excel import create_excel_report
from report_email import send_audit_email
from datetime import datetime

def security_audit(request):
    creds, project = default()

    # ----------------- Existing resource checks -----------------
    vm_data = check_compute_public_ips()
    sql_data = check_sql_public_ips()
    gke_data = check_gke_clusters()
    owner_data = check_owner_service_accounts()
    bucket_data = check_public_buckets()
    lb_data = check_load_balancers()

    # ----------------- CIS Checks -----------------
    cis_results = audit_cis()  # Returns a dict with all CIS checks

    # Format CIS results for Excel
    networking_data = []  # You can use SSH/RDP/firewall logs here
    logging_data = []     # Cloud NAT / VPC flow logs
    org_data = []         # Placeholder for Org policies (if any)
    ip_forwarding =[]
    # Example formatting:
    # SSH Firewall
    for ssh in cis_results.get("ssh_firewall", []):
        networking_data.append(["SSH Firewall", ssh[0], "Logging Enabled: " + str(ssh[1]), ssh[2]])

    # RDP Firewall
    for rdp in cis_results.get("rdp_firewall", []):
        networking_data.append(["RDP Firewall", rdp[0], "Logging Enabled: " + str(rdp[1]), rdp[2]])

    # All Firewall Logs
    for fw in cis_results.get("firewall_logs", []):
        logging_data.append(["Firewall Rule", fw[0], "Logging Enabled: " + str(fw[1]), fw[2]])

    # VPC Flow Logs
    for vpc in cis_results.get("vpc_flow_logs", []):
        logging_data.append(["VPC Flow Logs", vpc[0], f"Flow Enabled: {vpc[1]}, Sample Rate: {vpc[2]}", vpc[3]])

    # Cloud NAT Logs
    for nat in cis_results.get("cloud_nat_logs", []):
        logging_data.append(["Cloud NAT", nat[0], f"Router: {nat[1]}, Logging Enabled: {nat[2]}", nat[3]])
    # ----------------- IP Forwarding Logs -----------------
    for ipf in cis_results.get("ip_forwarding", []):
        # Check if this is an instance result or an error string
        if isinstance(ipf, list) and len(ipf) == 3:
            ip_forwarding.append(["Compute Instance", ipf[0], "canIpForward: " + str(ipf[1]), ipf[2]])
        else:
            # Error message
            ip_forwarding.append(["Compute Instance", str(ipf), "", "ERROR"])

    # ----------------- Create Excel -----------------
    excel_path = create_excel_report(
        project,
        vm_data, sql_data, gke_data, owner_data, bucket_data,
        networking_data, logging_data, org_data,
        lb_data, ip_forwarding
    )

    # ----------------- Send Email -----------------
    status = send_audit_email(project, excel_path, "hruthika.sa258@gmail.com")

    
    # --- Build Beautiful HTML Dashboard ---
    html = f"""
    <html>
    <head>
        <title>GCP Security Audit Dashboard</title>
        <meta charset="UTF-8">
        <script src="https://cdn.tailwindcss.com"></script>
        <style>
            body {{
                background-color: #f8fafc;
                font-family: 'Inter', sans-serif;
            }}
            .section-card {{
                transition: transform 0.2s ease, box-shadow 0.2s ease;
            }}
            .section-card:hover {{
                transform: translateY(-4px);
                box-shadow: 0 4px 14px rgba(0,0,0,0.1);
            }}
            table {{
                width: 100%;
                border-collapse: collapse;
                margin-top: 1rem;
            }}
            th, td {{
                padding: 0.6rem;
                text-align: left;
                border-bottom: 1px solid #e5e7eb;
            }}
            th {{
                background-color: #eff6ff;
                color: #1d4ed8;
                font-weight: 600;
            }}
        </style>
    </head>
    <body class="min-h-screen flex flex-col items-center">
        <div class="w-full max-w-6xl mt-10 mb-10 bg-white shadow-lg rounded-2xl p-8">
            <h1 class="text-4xl font-extrabold text-center text-blue-700 mb-2">
                🔒 GCP Security Audit Dashboard
            </h1>
            <p class="text-center text-gray-500 mb-8">
                Project: <span class="font-semibold text-gray-700">{project}</span> |
                Time: <span class="text-gray-600">{datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")}</span>
            </p>
    """

    # ---- Data Sections ----
    sections = [
        ("Compute Engine", vm_data),
        ("Cloud SQL", sql_data),
        ("GKE Clusters", gke_data),
        ("IAM Owners", owner_data),
        ("Buckets", bucket_data),
        ("Load Balancers", lb_data),
        ("Organization Policies", org_data),
        ("Logging Data", logging_data),
        ("Networking Data", networking_data),
        ("IP Forwarding", ip_forwarding)
    ]

    for category, data in sections:
        html += f"""
        <div class="section-card border border-gray-200 rounded-xl p-6 mb-6">
            <h2 class="text-2xl font-semibold text-blue-600 mb-3">{category}</h2>
        """
        if data:
            html += """
            <div class="overflow-x-auto">
                <table class="table-auto text-sm text-gray-700">
                    <thead>
                        <tr>
            """
            # Determine column count dynamically
            col_count = len(data[0]) if len(data) > 0 else 0
            for i in range(col_count):
                html += f"<th>Column {i+1}</th>"
            html += "</tr></thead><tbody>"

            for row in data:
                html += "<tr>"
                for cell in row:
                    html += f"<td>{str(cell)}</td>"
                html += "</tr>"

            html += "</tbody></table></div>"
        else:
            html += "<p class='text-green-600 font-medium'>✅ No issues found.</p>"
        html += "</div>"

    html += f"""
        <div class="mt-10 text-center">
            <p class="text-green-700 text-lg font-semibold">✅ {status}</p>
        </div>
    </div>

    <footer class="text-center text-gray-400 text-sm py-4">
        © {datetime.utcnow().year} Security Audit | Built with ❤️ and Python
    </footer>

    </body>
    </html>
    """


    response = make_response(html)
    response.headers['Content-Type'] = 'text/html'
    return response

