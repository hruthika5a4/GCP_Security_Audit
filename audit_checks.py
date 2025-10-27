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


# ----------------- CIS Audit Checks -----------------
# ----------------- CIS Audit Checks -----------------
def audit_cis():
    results = {
        "ssh_firewall": [],
        "rdp_firewall": [],
        "vpc_flow_logs": [],
        "firewall_logs": [],
        "cloud_nat_logs": [],
        "ip_forwarding": []  # <-- added CIS 4.6.1 results
    }

    try:
        compute = discovery.build('compute', 'v1', credentials=creds)

        # ----------------- Firewall Rules -----------------
        try:
            request = compute.firewalls().list(project=project)
            while request is not None:
                try:
                    response = request.execute()
                except Exception as e:
                    results['firewall_logs'].append([f"Error fetching firewall: {str(e)}"])
                    break
                for fw in response.get('items', []):
                    fw_name = fw['name']
                    log_enabled = fw.get('logConfig', {}).get('enable', False)
                    if fw_name == 'default-allow-ssh':
                        results['ssh_firewall'].append([fw_name, log_enabled, 'PASS' if log_enabled else 'VIOLATION'])
                    if fw_name == 'default-allow-rdp':
                        results['rdp_firewall'].append([fw_name, log_enabled, 'PASS' if log_enabled else 'VIOLATION'])
                    results['firewall_logs'].append([fw_name, log_enabled, 'PASS' if log_enabled else 'VIOLATION'])
                request = compute.firewalls().list_next(previous_request=request, previous_response=response)
        except Exception as e:
            results['firewall_logs'].append([f"Firewall error: {str(e)}"])

        # ----------------- VPC Flow Logs -----------------
        try:
            regions = compute.regions().list(project=project).execute().get('items', [])
            for region in regions[:3]:  # <-- limit to first 3 regions for testing
                region_name = region['name']
                request = compute.subnetworks().list(project=project, region=region_name)
                while request is not None:
                    try:
                        response = request.execute()
                    except Exception as e:
                        results['vpc_flow_logs'].append([f"Error fetching subnets: {str(e)}"])
                        break
                    for subnet in response.get('items', []):
                        flow_enabled = subnet.get('enableFlowLogs', False)
                        sample_rate = subnet.get('logConfig', {}).get('flowSampling', 0)
                        status = "PASS" if flow_enabled and sample_rate >= 0.1 else "VIOLATION"
                        results['vpc_flow_logs'].append([subnet['name'], flow_enabled, sample_rate, status])
                    request = compute.subnetworks().list_next(previous_request=request, previous_response=response)
        except Exception as e:
            results['vpc_flow_logs'].append([f"VPC error: {str(e)}"])

        # ----------------- Cloud NAT Logs -----------------
        try:
            for region in regions[:3]:  # limit regions
                region_name = region['name']
                request = compute.routers().list(project=project, region=region_name)
                while request is not None:
                    try:
                        response = request.execute()
                    except Exception as e:
                        results['cloud_nat_logs'].append([f"Error fetching routers: {str(e)}"])
                        break
                    for router in response.get('items', []):
                        router_name = router['name']
                        try:
                            nat_request = compute.routers().listNat(project=project, region=region_name, router=router_name)
                            nat_response = nat_request.execute()
                            for nat in nat_response.get('items', []):
                                nat_name = nat['name']
                                log_enabled = nat.get('logConfig', {}).get('enable', False)
                                results['cloud_nat_logs'].append([nat_name, router_name])
                        except Exception:
                            continue
                    request = compute.routers().list_next(previous_request=request, previous_response=response)
        except Exception as e:
            results['cloud_nat_logs'].append([f"NAT error: {str(e)}"])

        # ----------------- IP Forwarding (CIS 4.6.1) -----------------
        try:
            req = compute.instances().aggregatedList(project=project)
            while req is not None:
                res = req.execute()
                for zone, scoped_list in res.get('items', {}).items():
                    for instance in scoped_list.get('instances', []):
                        name = instance['name']
                        can_forward = instance.get('canIpForward', False)
                        # status = 'VIOLATION' if can_forward else 'PASS'
                        results['ip_forwarding'].append([name, can_forward])
                req = compute.instances().aggregatedList_next(req, res)
        except Exception as e:
            results['ip_forwarding'].append([f"IP Forwarding check failed: {str(e)}"])

    except Exception as e:
        results['firewall_logs'].append([f"CIS audit failed: {str(e)}"])

    return results
