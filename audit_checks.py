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
            gke_data.append([cluster['name'], endpoint, str(private_nodes)])
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


# ----------------- CIS Audit Checks -----------------
from googleapiclient import discovery

# ----------------- CIS Audit Checks -----------------
def audit_cis(project, creds):
    compute = discovery.build('compute', 'v1', credentials=creds)
    results = {
        "ssh_firewall": [],
        "rdp_firewall": [],
        "firewall_logs": [],
        "vpc_flow_logs": [],
        "cloud_nat_logs": [],
        "ip_forwarding": []
    }

    # ----------------- Firewall Rule Security Checks -----------------
    try:
        req = compute.firewalls().list(project=project)
        while req is not None:
            res = req.execute()
            for fw in res.get('items', []):
                name = fw.get('name')
                direction = fw.get('direction', 'INGRESS')
                source_ranges = fw.get('sourceRanges', [])
                allowed = fw.get('allowed', [])
                log_enabled = fw.get('logConfig', {}).get('enable', False)

                # Check SSH / RDP open to public
                for rule in allowed:
                    ports = rule.get('ports', [])
                    ip_protocol = rule.get('IPProtocol', '')

                    if direction == 'INGRESS':
                        # SSH Check
                        if ip_protocol in ['tcp', 'all'] and '22' in ports and '0.0.0.0/0' in source_ranges:
                            results['ssh_firewall'].append([
                                name, '22/tcp', ','.join(source_ranges),
                                'VIOLATION', 'SSH open to public internet.'
                            ])
                        # RDP Check
                        if ip_protocol in ['tcp', 'all'] and '3389' in ports and '0.0.0.0/0' in source_ranges:
                            results['rdp_firewall'].append([
                                name, '3389/tcp', ','.join(source_ranges),
                                'VIOLATION', 'RDP open to public internet.'
                            ])

                # Logging Enabled?
                log_status = "PASS" if log_enabled else "VIOLATION"
                results['firewall_logs'].append([
                    name, log_enabled, log_status,
                    "Firewall logging enabled" if log_enabled else "Logging disabled"
                ])

            req = compute.firewalls().list_next(previous_request=req, previous_response=res)

    except Exception as e:
        results['firewall_logs'].append(["Error fetching firewall rules", str(e)])

    # ----------------- VPC Flow Logs Check -----------------
    try:
        regions = compute.regions().list(project=project).execute().get('items', [])
        for region in regions:
            region_name = region['name']
            req = compute.subnetworks().list(project=project, region=region_name)
            while req is not None:
                res = req.execute()
                for subnet in res.get('items', []):
                    name = subnet['name']
                    flow_enabled = subnet.get('enableFlowLogs', False)
                    sampling = subnet.get('logConfig', {}).get('flowSampling', 0)
                    aggregation = subnet.get('logConfig', {}).get('aggregationInterval', 'interval-5-sec')

                    status = "PASS" if flow_enabled and sampling >= 0.1 else "VIOLATION"
                    recommendation = "Enable VPC Flow Logs with >=0.1 sampling rate" if not flow_enabled else "Compliant"

                    results['vpc_flow_logs'].append([
                        name, region_name, flow_enabled, sampling, aggregation, status, recommendation
                    ])
                req = compute.subnetworks().list_next(previous_request=req, previous_response=res)

    except Exception as e:
        results['vpc_flow_logs'].append(["Error checking VPC Flow Logs", str(e)])

    # ----------------- Cloud NAT Logging Check -----------------
    try:
        for region in regions:
            region_name = region['name']
            req = compute.routers().list(project=project, region=region_name)
            while req is not None:
                res = req.execute()
                for router in res.get('items', []):
                    router_name = router['name']
                    try:
                        nat_list = compute.routers().listNat(
                            project=project, region=region_name, router=router_name
                        ).execute()

                        for nat in nat_list.get('items', []):
                            nat_name = nat['name']
                            log_enabled = nat.get('logConfig', {}).get('enable', False)
                            status = "PASS" if log_enabled else "VIOLATION"
                            recommendation = "Enable NAT logging" if not log_enabled else "Compliant"

                            results['cloud_nat_logs'].append([
                                nat_name, router_name, region_name, log_enabled, status, recommendation
                            ])
                    except Exception:
                        continue
                req = compute.routers().list_next(previous_request=req, previous_response=res)

    except Exception as e:
        results['cloud_nat_logs'].append(["Error checking NAT logs", str(e)])

    # ----------------- IP Forwarding (CIS 4.6.1) -----------------
    try:
        req = compute.instances().aggregatedList(project=project)
        while req is not None:
            res = req.execute()
            for zone, scoped_list in res.get('items', {}).items():
                for instance in scoped_list.get('instances', []):
                    name = instance['name']
                    can_forward = instance.get('canIpForward', False)
                    status = "VIOLATION" if can_forward else "PASS"
                    recommendation = (
                        "Disable IP forwarding unless required by architecture"
                        if can_forward else "Compliant"
                    )
                    results['ip_forwarding'].append([name, can_forward, status, recommendation])
            req = compute.instances().aggregatedList_next(req, res)

    except Exception as e:
        results['ip_forwarding'].append(["IP Forwarding check failed", str(e)])

    return results


