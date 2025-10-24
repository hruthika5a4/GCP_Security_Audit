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


def audit_cis():
    results = {
        "firewall_vulnerabilities": [],
        "vpc_flow_logs": [],
        "cloud_nat_logs": [],
        "ip_forwarding": []
    }

    try:
        compute = discovery.build('compute', 'v1', credentials=creds)

        # ----------------- Firewall Rule Vulnerabilities -----------------
        try:
            request = compute.firewalls().list(project=project)
            while request is not None:
                response = request.execute()
                for fw in response.get('items', []):
                    fw_name = fw.get('name', 'unknown')
                    direction = fw.get('direction', 'INGRESS')
                    log_enabled = fw.get('logConfig', {}).get('enable', False)
                    allowed = fw.get('allowed', [])
                    source_ranges = fw.get('sourceRanges', [])

                    for rule in allowed:
                        ports = rule.get('ports', ['all'])
                        protocol = rule.get('IPProtocol', 'all')

                        # ---- Check vulnerabilities ----
                        if '0.0.0.0/0' in source_ranges and direction == 'INGRESS':
                            if protocol in ['tcp', 'udp', 'all']:
                                results["firewall_vulnerabilities"].append([
                                    fw_name,
                                    f"{protocol.upper()} ports: {','.join(ports)}",
                                    source_ranges,
                                    "VIOLATION",
                                    "Unrestricted public access (0.0.0.0/0)"
                                ])
                            if '22' in ports:
                                results["firewall_vulnerabilities"].append([
                                    fw_name,
                                    "SSH (TCP/22)",
                                    source_ranges,
                                    "VIOLATION",
                                    "Public SSH access is open"
                                ])
                            if '3389' in ports:
                                results["firewall_vulnerabilities"].append([
                                    fw_name,
                                    "RDP (TCP/3389)",
                                    source_ranges,
                                    "VIOLATION",
                                    "Public RDP access is open"
                                ])
                        else:
                            results["firewall_vulnerabilities"].append([
                                fw_name,
                                f"{protocol.upper()} ports: {','.join(ports)}",
                                source_ranges,
                                "PASS",
                                "No public access detected"
                            ])
                request = compute.firewalls().list_next(previous_request=request, previous_response=response)
        except Exception as e:
            results['firewall_vulnerabilities'].append(["Error", str(e), "VIOLATION", "Firewall check failed"])

        # ----------------- VPC Flow Logs -----------------
        try:
            regions = compute.regions().list(project=project).execute().get('items', [])
            for region in regions:
                region_name = region['name']
                req = compute.subnetworks().list(project=project, region=region_name)
                while req is not None:
                    response = req.execute()
                    for subnet in response.get('items', []):
                        flow_enabled = subnet.get('enableFlowLogs', False)
                        sample_rate = subnet.get('logConfig', {}).get('flowSampling', 0)
                        status = "PASS" if flow_enabled else "VIOLATION"
                        reason = "Flow logs disabled" if not flow_enabled else "Flow logs enabled"
                        results['vpc_flow_logs'].append([subnet['name'], region_name, flow_enabled, sample_rate, status, reason])
                    req = compute.subnetworks().list_next(previous_request=req, previous_response=response)
        except Exception as e:
            results['vpc_flow_logs'].append(["Error", str(e), "VIOLATION", "VPC Flow log check failed"])

        # ----------------- Cloud NAT Logs -----------------
        try:
            for region in regions:
                region_name = region['name']
                req = compute.routers().list(project=project, region=region_name)
                while req is not None:
                    response = req.execute()
                    for router in response.get('items', []):
                        router_name = router['name']
                        try:
                            nat_req = compute.routers().getNatMappingInfo(project=project, region=region_name, router=router_name)
                            nat_response = nat_req.execute()
                            for nat_info in nat_response.get('result', []):
                                nat_name = nat_info.get('name', 'unknown')
                                log_enabled = nat_info.get('logConfig', {}).get('enable', False)
                                status = "PASS" if log_enabled else "VIOLATION"
                                reason = "Logging disabled" if not log_enabled else "Logging enabled"
                                results['cloud_nat_logs'].append([nat_name, router_name, log_enabled, status, reason])
                        except Exception:
                            continue
                    req = compute.routers().list_next(previous_request=req, previous_response=response)
        except Exception as e:
            results['cloud_nat_logs'].append(["Error", str(e), "VIOLATION", "NAT log check failed"])

        # ----------------- IP Forwarding -----------------
        try:
            req = compute.instances().aggregatedList(project=project)
            while req is not None:
                res = req.execute()
                for zone, scoped_list in res.get('items', {}).items():
                    for instance in scoped_list.get('instances', []):
                        name = instance['name']
                        can_forward = instance.get('canIpForward', False)
                        status = "VIOLATION" if can_forward else "PASS"
                        reason = "IP forwarding enabled (may allow spoofing)" if can_forward else "Safe"
                        results['ip_forwarding'].append([name, can_forward, status, reason])
                req = compute.instances().aggregatedList_next(req, res)
        except Exception as e:
            results['ip_forwarding'].append(["Error", str(e), "VIOLATION", "IP forwarding check failed"])

    except Exception as e:
        results['firewall_vulnerabilities'].append(["CIS audit failed", str(e), "VIOLATION", "Script execution error"])

    return results


