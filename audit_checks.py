# ==========================
# audit_checks.py
# ==========================

import logging
from googleapiclient import discovery
from google.auth import default
import traceback

logging.basicConfig(level=logging.INFO)

# ----------------- Credentials -----------------
creds, project = default()

# ----------------- Helper to safely execute requests -----------------
def safe_execute(request, default_result=None):
    try:
        return request.execute()
    except Exception as e:
        logging.error(f"API call failed: {e}\n{traceback.format_exc()}")
        return default_result

# ----------------- 1. Compute Engine Public IPs -----------------
def check_compute_public_ips():
    compute = discovery.build('compute', 'v1', credentials=creds)
    vm_data = []
    try:
        req = compute.instances().aggregatedList(project=project)
        while req is not None:
            res = safe_execute(req, {'items': {}})
            for zone, scoped_list in res.get('items', {}).items():
                for instance in scoped_list.get('instances', []):
                    name = instance.get('name', 'N/A')
                    for nic in instance.get('networkInterfaces', []):
                        for ac in nic.get('accessConfigs', []):
                            if 'natIP' in ac:
                                vm_data.append([name, zone, ac['natIP']])
            req = compute.instances().aggregatedList_next(req, res)
    except Exception as e:
        logging.error(f"check_compute_public_ips failed: {e}")
    return vm_data

# ----------------- 2. Cloud SQL Public IPs -----------------
def check_sql_public_ips():
    sqladmin = discovery.build('sqladmin', 'v1beta4', credentials=creds)
    sql_data = []
    try:
        res = safe_execute(sqladmin.instances().list(project=project), {'items': []})
        for instance in res.get('items', []):
            for ip in instance.get('ipAddresses', []):
                if ip.get('type') == 'PRIMARY':
                    sql_data.append([instance.get('name', 'N/A'), ip.get('ipAddress', 'N/A')])
    except Exception as e:
        logging.error(f"check_sql_public_ips failed: {e}")
    return sql_data

# ----------------- 3. GKE Clusters -----------------
def check_gke_clusters():
    container = discovery.build('container', 'v1', credentials=creds)
    gke_data = []
    try:
        res = safe_execute(container.projects().locations().clusters().list(
            parent=f"projects/{project}/locations/-"), {'clusters': []})
        for cluster in res.get('clusters', []):
            endpoint = cluster.get('endpoint', '')
            private_nodes = cluster.get('privateClusterConfig', {}).get('enablePrivateNodes', False)
            if endpoint and not private_nodes:
                gke_data.append([cluster.get('name', 'N/A'), endpoint])
    except Exception as e:
        logging.error(f"check_gke_clusters failed: {e}")
    return gke_data

# ----------------- 4. IAM Owner Service Accounts -----------------
def check_owner_service_accounts():
    crm = discovery.build('cloudresourcemanager', 'v1', credentials=creds)
    owner_data = []
    try:
        policy = safe_execute(crm.projects().getIamPolicy(resource=project, body={}), {'bindings': []})
        for binding in policy.get('bindings', []):
            if binding.get('role') == 'roles/owner':
                for member in binding.get('members', []):
                    if member.startswith("serviceAccount:"):
                        owner_data.append([member, binding.get('role', 'N/A')])
    except Exception as e:
        logging.error(f"check_owner_service_accounts failed: {e}")
    return owner_data

# ----------------- 5. Public Buckets -----------------
def check_public_buckets():
    storage = discovery.build('storage', 'v1', credentials=creds)
    bucket_data = []
    try:
        res = safe_execute(storage.buckets().list(project=project), {'items': []})
        for bucket in res.get('items', []):
            try:
                iam = safe_execute(storage.buckets().getIamPolicy(bucket=bucket['name']), {'bindings': []})
                for b in iam.get('bindings', []):
                    for m in b.get('members', []):
                        if 'allUsers' in m or 'allAuthenticatedUsers' in m:
                            bucket_data.append([bucket['name'], b.get('role', 'N/A'), m])
            except Exception as e:
                logging.warning(f"Bucket {bucket['name']} IAM fetch failed: {e}")
    except Exception as e:
        logging.error(f"check_public_buckets failed: {e}")
    return bucket_data

# ----------------- 6. Load Balancers -----------------
def check_load_balancers():
    compute = discovery.build('compute', 'v1', credentials=creds)
    lb_data = []
    try:
        req = compute.forwardingRules().aggregatedList(project=project)
        while req is not None:
            res = safe_execute(req, {'items': {}})
            for region, scoped_list in res.get('items', {}).items():
                for rule in scoped_list.get('forwardingRules', []):
                    lb_data.append({
                        'name': rule.get('name', ''),
                        'scheme': rule.get('loadBalancingScheme', ''),
                        'ip': rule.get('IPAddress', ''),
                        'target': rule.get('target', ''),
                        'ssl_policy': 'N/A',
                        'cloud_armor_policy': 'N/A'
                    })
            req = compute.forwardingRules().aggregatedList_next(req, res)
    except Exception as e:
        logging.error(f"check_load_balancers failed: {e}")
    return lb_data

# ----------------- 7. Firewall Rules -----------------
def check_firewall_vulnerabilities():
    compute = discovery.build('compute', 'v1', credentials=creds)
    firewall_data = []
    try:
        req = compute.firewalls().list(project=project)
        while req is not None:
            res = safe_execute(req, {'items': []})
            for fw in res.get('items', []):
                name = fw.get('name', 'N/A')
                direction = fw.get('direction', 'INGRESS')
                allowed = fw.get('allowed', [])
                source_ranges = fw.get('sourceRanges', [])
                for rule in allowed:
                    ports = rule.get('ports', ['all'])
                    proto = rule.get('IPProtocol', 'all')
                    if '0.0.0.0/0' in source_ranges and direction == 'INGRESS':
                        if '22' in ports:
                            firewall_data.append([name, "SSH (22)", source_ranges, "VIOLATION", "Public SSH access"])
                        elif '3389' in ports:
                            firewall_data.append([name, "RDP (3389)", source_ranges, "VIOLATION", "Public RDP access"])
                        else:
                            firewall_data.append([name, f"{proto}:{ports}", source_ranges, "VIOLATION", "Public access allowed"])
                    else:
                        firewall_data.append([name, f"{proto}:{ports}", source_ranges, "PASS", "No public access"])
            req = compute.firewalls().list_next(req, res)
    except Exception as e:
        logging.error(f"check_firewall_vulnerabilities failed: {e}")
    return firewall_data

# ----------------- 8. VPC Flow Logs -----------------
def check_vpc_flow_logs():
    compute = discovery.build('compute', 'v1', credentials=creds)
    vpc_flow_data = []
    try:
        regions = safe_execute(compute.regions().list(project=project), {'items': []}).get('items', [])
        for region in regions:
            region_name = region['name']
            req = compute.subnetworks().list(project=project, region=region_name)
            while req is not None:
                res = safe_execute(req, {'items': []})
                for subnet in res.get('items', []):
                    flow_enabled = subnet.get('enableFlowLogs', False)
                    sample_rate = subnet.get('logConfig', {}).get('flowSampling', 0)
                    status = "PASS" if flow_enabled else "VIOLATION"
                    reason = "Flow logs enabled" if flow_enabled else "Flow logs disabled"
                    vpc_flow_data.append([subnet['name'], region_name, flow_enabled, sample_rate, status, reason])
                req = compute.subnetworks().list_next(req, res)
    except Exception as e:
        logging.error(f"check_vpc_flow_logs failed: {e}")
    return vpc_flow_data

# ----------------- 9. Cloud NAT Logs -----------------
def check_cloud_nat_logs():
    compute = discovery.build('compute', 'v1', credentials=creds)
    nat_data = []
    try:
        regions = safe_execute(compute.regions().list(project=project), {'items': []}).get('items', [])
        for region in regions:
            region_name = region['name']
            req = compute.routers().list(project=project, region=region_name)
            while req is not None:
                res = safe_execute(req, {'items': []})
                for router in res.get('items', []):
                    router_name = router.get('name', 'N/A')
                    for nat in router.get('nats', []):
                        nat_name = nat.get('name', 'N/A')
                        log_enabled = nat.get('logConfig', {}).get('enable', False)
                        status = "PASS" if log_enabled else "VIOLATION"
                        reason = "Logging enabled" if log_enabled else "Logging disabled"
                        nat_data.append([nat_name, router_name, log_enabled, status, reason])
                req = compute.routers().list_next(req, res)
    except Exception as e:
        logging.error(f"check_cloud_nat_logs failed: {e}")
    return nat_data

# ----------------- 10. IP Forwarding -----------------
def check_ip_forwarding():
    compute = discovery.build('compute', 'v1', credentials=creds)
    ip_forward_data = []
    try:
        req = compute.instances().aggregatedList(project=project)
        while req is not None:
            res = safe_execute(req, {'items': {}})
            for zone, scoped_list in res.get('items', {}).items():
                for instance in scoped_list.get('instances', []):
                    name = instance.get('name', 'N/A')
                    can_forward = instance.get('canIpForward', False)
                    status = "VIOLATION" if can_forward else "PASS"
                    reason = "IP forwarding enabled (risk of spoofing)" if can_forward else "Safe"
                    ip_forward_data.append([name, can_forward, status, reason])
            req = compute.instances().aggregatedList_next(req, res)
    except Exception as e:
        logging.error(f"check_ip_forwarding failed: {e}")
    return ip_forward_data
