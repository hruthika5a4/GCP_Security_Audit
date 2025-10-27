from openpyxl import Workbook
from openpyxl.styles import Font, PatternFill, Alignment
from datetime import datetime
from openpyxl.utils import get_column_letter

# After adding data to a worksheet, call this helper:
def auto_fit_columns(ws):
    for column_cells in ws.columns:
        max_length = 0
        column = column_cells[0].column  # Get column index
        column_letter = get_column_letter(column)
        for cell in column_cells:
            try:
                cell_length = len(str(cell.value))
                if cell_length > max_length:
                    max_length = cell_length
            except:
                pass
        adjusted_width = (max_length + 2)
        ws.column_dimensions[column_letter].width = adjusted_width

def create_excel_report(project, vm_data, sql_data, gke_data, owner_data, bucket_data,
                        networking_data, logging_data, org_data, ip_forwarding=None, lb_data=None):
    wb = Workbook()
    summary = wb.active
    summary.title = "Summary"
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Summary sheet
    summary.append(["Project ID", "Audit Time", "VMs", "SQL", "GKE", "Owners", "Buckets", "Load Balancers"])
    summary.append([
        project, now, len(vm_data), len(sql_data), len(gke_data), len(owner_data), 
        len(bucket_data), len(lb_data) if lb_data else 0
    ])

    for cell in summary[1]:
        cell.font = Font(bold=True, color="FFFFFF")
        cell.fill = PatternFill("solid", fgColor="4F81BD")
        cell.alignment = Alignment(horizontal="center", vertical="center")

    # Helper to create a sheet
    def add_sheet(name, headers, data):
        ws = wb.create_sheet(name)
        ws.append(headers)
        for c in ws[1]:
            c.font = Font(bold=True, color="FFFFFF")
            c.fill = PatternFill("solid", fgColor="4F81BD")
            c.alignment = Alignment(horizontal="center", vertical="center")
        if data:
            for d in data:
                ws.append(d)
        else:
            ws.append(["✅ No issues found."])
        ws.freeze_panes = "A2"
        # At the end of add_sheet:
        auto_fit_columns(ws)

    # Add existing sheets
    add_sheet("VMs", ["Instance", "Zone", "Public IP"], vm_data)
    add_sheet("SQL", ["Instance", "Public IP"], sql_data)
    add_sheet("GKE", ["Cluster", "Endpoint", "Private Nodes"], gke_data)
    add_sheet("Owners", ["Member", "Role"], owner_data)
    add_sheet("Buckets", ["Bucket", "Role", "Member"], bucket_data)



    # Add Load Balancers sheet
    if lb_data:
        lb_headers = [
            "LB Name", "Scope", "LB Type", "Target Type", "IP", "Protocol", "Port Range",
            "SSL Policy", "SSL Profile", "Min TLS", "SSL Recommendation", "TLS Recommendation",
            "Backend Services (Logging / Cloud Run)", "Recommendation"
        ]
        add_sheet("LoadBalancers", lb_headers, lb_data)


    path = f"/tmp/{project}_security_audit.xlsx"
    wb.save(path)
    return path

