from googleapiclient import discovery
from google.auth import default

# ----------------- Credentials -----------------
creds, project = default()

# ----------------- Existing GCP Checks -----------------
def check_compute_public_ips():
    compute = discovery.build('compute', 'v1', credentials=creds)
    vm_data = []
    req = compute.instances().aggregatedList(project=project)
    while req is not None:
        res = req.execute()
        for zone, scoped_list in res.get('items', {}).items():
            for instance in scoped_list.get('instances', []):
                name = instance['name']
                for nic in instance.get('networkInterfaces', []):
                    for ac in nic.get('accessConfigs', []):
                        if 'natIP' in ac:
                            vm_data.append([name, zone, ac['natIP']])
        req = compute.instances().aggregatedList_next(req, res)
    return vm_data


def check_sql_public_ips():
    sqladmin = discovery.build('sqladmin', 'v1beta4', credentials=creds)
    sql_data = []
    req = sqladmin.instances().list(project=project)
    res = req.execute()
    for instance in res.get('items', []):
        for ip in instance.get('ipAddresses', []):
            if ip.get('type') == 'PRIMARY':
                sql_data.append([instance['name'], ip.get('ipAddress', 'N/A')])
    return sql_data


def check_gke_clusters():
    container = discovery.build('container', 'v1', credentials=creds)
    gke_data = []
    req = container.projects().locations().clusters().list(parent=f"projects/{project}/locations/-")
    res = req.execute()
    for cluster in res.get('clusters', []):
        endpoint = cluster.get('endpoint', '')
        private_nodes = cluster.get('privateClusterConfig', {}).get('enablePrivateNodes', False)
        if endpoint and not private_nodes:
            gke_data.append([cluster['name'], endpoint])
    return gke_data


def check_owner_service_accounts():
    crm = discovery.build('cloudresourcemanager', 'v1', credentials=creds)
    owner_data = []
    policy = crm.projects().getIamPolicy(resource=project, body={}).execute()
    for binding in policy.get('bindings', []):
        if binding.get('role') == 'roles/owner':
            for member in binding.get('members', []):
                if member.startswith("serviceAccount:"):
                    owner_data.append([member, binding['role']])
    return owner_data


def check_public_buckets():
    storage = discovery.build('storage', 'v1', credentials=creds)
    bucket_data = []
    req = storage.buckets().list(project=project).execute()
    for bucket in req.get('items', []):
        try:
            iam = storage.buckets().getIamPolicy(bucket=bucket['name']).execute()
            for b in iam.get('bindings', []):
                for m in b.get('members', []):
                    if 'allUsers' in m or 'allAuthenticatedUsers' in m:
                        bucket_data.append([bucket['name'], b['role'], m])
        except Exception:
            continue
    return bucket_data


def check_load_balancers():
    compute = discovery.build('compute', 'v1', credentials=creds)
    lb_data = []

    # Fetch all forwarding rules
    req = compute.forwardingRules().aggregatedList(project=project)
    while req is not None:
        res = req.execute()
        for region, scoped_list in res.get('items', {}).items():
            for rule in scoped_list.get('forwardingRules', []):
                lb_name = rule.get('name', '')
                target = rule.get('target', '') or rule.get('backendService', '') or rule.get('targetPool', '')
                
                # Initialize TLS and Cloud Armor defaults
                ssl_policy = 'N/A'
                cloud_armor_policy = 'N/A'

                # Check if target is HTTPS proxy to get SSL/TLS policy
                if 'targetHttpsProxies' in target or target.endswith('httpsProxies'):
                    try:
                        target_name = target.split('/')[-1]
                        proxy = compute.targetHttpsProxies().get(project=project, targetHttpsProxy=target_name).execute()
                        ssl_policy = proxy.get('sslPolicy', 'None')
                        cloud_armor_policy = proxy.get('securityPolicy', 'None')
                    except Exception:
                        ssl_policy = 'Error'
                        cloud_armor_policy = 'Error'

                # Check if target is HTTP proxy to get Cloud Armor
                elif 'targetHttpProxies' in target or target.endswith('httpProxies'):
                    try:
                        target_name = target.split('/')[-1]
                        proxy = compute.targetHttpProxies().get(project=project, targetHttpProxy=target_name).execute()
                        cloud_armor_policy = proxy.get('securityPolicy', 'None')
                    except Exception:
                        cloud_armor_policy = 'Error'

                lb_data.append({
                    'name': lb_name,
                    'scheme': rule.get('loadBalancingScheme', ''),
                    'ip': rule.get('IPAddress', ''),
                    'target': target,
                    'ssl_policy': ssl_policy,
                    'cloud_armor_policy': cloud_armor_policy
                })
        req = compute.forwardingRules().aggregatedList_next(req, res)
    return lb_data


from googleapiclient import discovery
from google.auth import default

# ----------------- Credentials -----------------
creds, project = default()

# ----------------- 1. Firewall Vulnerabilities -----------------
def check_firewall_vulnerabilities():
    compute = discovery.build('compute', 'v1', credentials=creds)
    firewall_data = []
    try:
        req = compute.firewalls().list(project=project)
        while req is not None:
            res = req.execute()
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
        firewall_data.append(["Error", str(e), "VIOLATION", "Firewall check failed"])
    return firewall_data


# ----------------- 2. VPC Flow Logs -----------------
def check_vpc_flow_logs():
    compute = discovery.build('compute', 'v1', credentials=creds)
    vpc_flow_data = []
    try:
        regions = compute.regions().list(project=project).execute().get('items', [])
        for region in regions:
            region_name = region['name']
            req = compute.subnetworks().list(project=project, region=region_name)
            while req is not None:
                res = req.execute()
                for subnet in res.get('items', []):
                    flow_enabled = subnet.get('enableFlowLogs', False)
                    sample_rate = subnet.get('logConfig', {}).get('flowSampling', 0)
                    status = "PASS" if flow_enabled else "VIOLATION"
                    reason = "Flow logs enabled" if flow_enabled else "Flow logs disabled"
                    vpc_flow_data.append([subnet['name'], region_name, flow_enabled, sample_rate, status, reason])
                req = compute.subnetworks().list_next(req, res)
    except Exception as e:
        vpc_flow_data.append(["Error", str(e), "VIOLATION", "VPC flow log check failed"])
    return vpc_flow_data


# ----------------- 3. Cloud NAT Logs -----------------
def check_cloud_nat_logs():
    compute = discovery.build('compute', 'v1', credentials=creds)
    nat_data = []
    try:
        regions = compute.regions().list(project=project).execute().get('items', [])
        for region in regions:
            region_name = region['name']
            req = compute.routers().list(project=project, region=region_name)
            while req is not None:
                res = req.execute()
                for router in res.get('items', []):
                    router_name = router['name']
                    for nat in router.get('nats', []):
                        nat_name = nat.get('name', 'unknown')
                        log_enabled = nat.get('logConfig', {}).get('enable', False)
                        status = "PASS" if log_enabled else "VIOLATION"
                        reason = "Logging enabled" if log_enabled else "Logging disabled"
                        nat_data.append([nat_name, router_name, log_enabled, status, reason])
                req = compute.routers().list_next(req, res)
    except Exception as e:
        nat_data.append(["Error", str(e), "VIOLATION", "Cloud NAT log check failed"])
    return nat_data


# ----------------- 4. IP Forwarding -----------------
def check_ip_forwarding():
    compute = discovery.build('compute', 'v1', credentials=creds)
    ip_forward_data = []
    try:
        req = compute.instances().aggregatedList(project=project)
        while req is not None:
            res = req.execute()
            for zone, scoped_list in res.get('items', {}).items():
                for instance in scoped_list.get('instances', []):
                    name = instance['name']
                    can_forward = instance.get('canIpForward', False)
                    status = "VIOLATION" if can_forward else "PASS"
                    reason = "IP forwarding enabled (risk of spoofing)" if can_forward else "Safe"
                    ip_forward_data.append([name, can_forward, status, reason])
            req = compute.instances().aggregatedList_next(req, res)
    except Exception as e:
        ip_forward_data.append(["Error", str(e), "VIOLATION", "IP forwarding check failed"])
    return ip_forward_data




