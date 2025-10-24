from openpyxl import Workbook
from openpyxl.styles import Font, PatternFill, Alignment
from openpyxl.utils import get_column_letter
from datetime import datetime

# ------------------ Helper: Auto fit columns ------------------
def auto_fit_columns(ws):
    for column_cells in ws.columns:
        max_length = 0
        column_letter = get_column_letter(column_cells[0].column)
        for cell in column_cells:
            try:
                cell_length = len(str(cell.value))
                if cell_length > max_length:
                    max_length = cell_length
            except:
                pass
        ws.column_dimensions[column_letter].width = max_length + 2


# ------------------ Helper: Add sheet ------------------
def add_sheet(wb, name, headers, data):
    ws = wb.create_sheet(name)
    ws.append(headers)

    # Header styling
    for c in ws[1]:
        c.font = Font(bold=True, color="FFFFFF")
        c.fill = PatternFill("solid", fgColor="4F81BD")
        c.alignment = Alignment(horizontal="center", vertical="center")

    if data:
        for d in data:
            if isinstance(d, dict):  # flatten dict rows (for LB)
                ws.append(list(d.values()))
            else:
                ws.append(d)
    else:
        ws.append(["✅ No issues found."])

    ws.freeze_panes = "A2"
    auto_fit_columns(ws)


# ------------------ Individual Sheet Creators ------------------
def add_vm_sheet(wb, vm_data):
    headers = ["Instance", "Zone", "Public IP"]
    add_sheet(wb, "VMs", headers, vm_data)


def add_sql_sheet(wb, sql_data):
    headers = ["Instance", "Public IP"]
    add_sheet(wb, "SQL", headers, sql_data)


def add_gke_sheet(wb, gke_data):
    headers = ["Cluster", "Endpoint", "Private Nodes"]
    add_sheet(wb, "GKE", headers, gke_data)


def add_owner_sheet(wb, owner_data):
    headers = ["Member", "Role"]
    add_sheet(wb, "Owners", headers, owner_data)


def add_bucket_sheet(wb, bucket_data):
    headers = ["Bucket", "Role", "Member"]
    add_sheet(wb, "Buckets", headers, bucket_data)


def add_networking_sheet(wb, networking_data):
    headers = ["Resource", "Issue", "Region", "Severity"]
    add_sheet(wb, "Networking", headers, networking_data)


def add_logging_sheet(wb, logging_data):
    headers = ["Feature", "Status"]
    add_sheet(wb, "Logging", headers, logging_data)


def add_orgpolicy_sheet(wb, org_data):
    headers = ["Policy", "Status"]
    add_sheet(wb, "OrgPolicy", headers, org_data)


def add_lb_sheet(wb, lb_data):
    headers = [
        "LB Name", "Scope", "LB Type", "Target Type", "IP", "Protocol", "Port Range",
        "SSL Policy", "SSL Profile", "Min TLS", "SSL Recommendation", "TLS Recommendation",
        "Backend Services (Logging / Cloud Run)", "Recommendation"
    ]

    ws = wb.create_sheet("LoadBalancers")
    ws.append(headers)

    for c in ws[1]:
        c.font = Font(bold=True, color="FFFFFF")
        c.fill = PatternFill("solid", fgColor="4F81BD")
        c.alignment = Alignment(horizontal="center", vertical="center")

    if lb_data:
        for d in lb_data:
            row = [
                d.get('name'),
                d.get('scope'),
                d.get('lb_type'),
                d.get('target_type'),
                d.get('ip'),
                d.get('ip_protocol'),
                d.get('port_range'),
                d.get('ssl_policy'),
                d.get('ssl_profile'),
                d.get('ssl_min_tls'),
                d.get('ssl_recommendation'),
                d.get('tls_recommendation'),
                "; ".join([f"{b['backend_service']} (logging: {b.get('logging_enabled')}, CloudRun: {b.get('cloud_run_service', '-')})"
                           for b in d.get('backend_services', [])]),
                d.get('recommendation')
            ]
            ws.append(row)
    else:
        ws.append(["✅ No issues found."])

    ws.freeze_panes = "A2"
    auto_fit_columns(ws)


def add_ip_forwarding_sheet(wb, ip_forwarding):
    headers = ["Compute Instance", "canIpForward", "Status"]
    add_sheet(wb, "IPForwarding", headers, ip_forwarding)


# ------------------ Main Function ------------------
def create_excel_report(project, vm_data, sql_data, gke_data, owner_data, bucket_data,
                        networking_data, logging_data, org_data, ip_forwarding=None, lb_data=None):
    wb = Workbook()
    summary = wb.active
    summary.title = "Summary"
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Summary Sheet
    summary.append([
        "Project ID", "Audit Time", "VMs", "SQL", "GKE", "Owners", 
        "Buckets", "Load Balancers", "IP Forwarding Issues"
    ])
    summary.append([
        project, now, len(vm_data), len(sql_data), len(gke_data),
        len(owner_data), len(bucket_data),
        len(lb_data) if lb_data else 0,
        len(ip_forwarding) if ip_forwarding else 0
    ])

    for cell in summary[1]:
        cell.font = Font(bold=True, color="FFFFFF")
        cell.fill = PatternFill("solid", fgColor="4F81BD")
        cell.alignment = Alignment(horizontal="center", vertical="center")

    auto_fit_columns(summary)

    # Add each resource sheet
    add_vm_sheet(wb, vm_data)
    add_sql_sheet(wb, sql_data)
    add_gke_sheet(wb, gke_data)
    add_owner_sheet(wb, owner_data)
    add_bucket_sheet(wb, bucket_data)
    add_networking_sheet(wb, networking_data)
    add_logging_sheet(wb, logging_data)
    add_orgpolicy_sheet(wb, org_data)

    if lb_data:
        add_lb_sheet(wb, lb_data)
    if ip_forwarding:
        add_ip_forwarding_sheet(wb, ip_forwarding)

    # Save file
    path = f"/tmp/{project}_security_audit.xlsx"
    wb.save(path)
    return path
