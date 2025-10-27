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

    # --- Build HTML dashboard ---
    html = f"""
    <html>
    <head>
        <title>🔒 GCP Security Audit Dashboard</title>
        <script src="https://cdn.tailwindcss.com"></script>
    </head>
    <body class="bg-gray-50 text-gray-900">
        <div class="max-w-5xl mx-auto mt-10 p-6 bg-white shadow-lg rounded-lg">
            <h1 class="text-3xl font-bold text-center text-blue-700 mb-4">
                🔒 GCP Security Audit Dashboard
            </h1>
            <p class="text-center text-gray-600 mb-6">
                Project: {project} | Time: {datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")}
            </p>
    """

    sections = [
        ("Compute Engine", vm_data),
        ("Cloud SQL", sql_data),
        ("GKE Clusters", gke_data),
        ("IAM Owners", owner_data),
        ("Buckets", bucket_data),
        ("LB", lb_data),
        ("org_data",org_data),
        ("logging_data",logging_data),
        ("networking_data",networking_data),
        ("ip_forwarding",ip_forwarding)
    ]

    for category, data in sections:
        html += f"""
        <div class='border border-gray-200 rounded-lg p-4 mb-4'>
            <h2 class='text-xl font-semibold text-blue-600 mb-2'>{category}</h2>
        """
        if data:
            html += "<ul class='list-disc pl-6 text-gray-700'>"
            for row in data:
                html += f"<li>{' | '.join(map(str, row))}</li>"
            html += "</ul>"
        else:
            html += "<p class='text-green-600'>✅ No issues found.</p>"
        html += "</div>"

    html += f"""
        <p class="text-center text-green-700 font-semibold mt-6">
            ✅ {status}
        </p>
        </div>
    </body>
    </html>
    """

    response = make_response(html)
    response.headers['Content-Type'] = 'text/html'
    return response
