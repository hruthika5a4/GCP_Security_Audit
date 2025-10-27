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


# ----------------- Firewall Rules Check -----------------

def check_firewall_rules():
    creds, project = default()
    compute = discovery.build('compute', 'v1', credentials=creds)
    firewall_data = []

    try:
        request = compute.firewalls().list(project=project)
        while request is not None:
            response = request.execute()

            for rule in response.get('items', []):
                name = rule.get('name')
                direction = rule.get('direction')
                allowed = rule.get('allowed', [])
                source_ranges = rule.get('sourceRanges', [])
                network = rule.get('network', '')
                priority = rule.get('priority', '')
                disabled = rule.get('disabled', False)

                # Skip default / GCP-managed firewall rules
                if name.startswith("default-") or "gke-" in name:
                    continue

                # Check if open to the internet
                if any(src == "0.0.0.0/0" for src in source_ranges):
                    firewall_data.append([
                        name,
                        direction,
                        [a.get('IPProtocol') for a in allowed],
                        source_ranges,
                        network.split('/')[-1],  # extract network name
                        priority,
                        disabled
                    ])

            request = compute.firewalls().list_next(previous_request=request, previous_response=response)
    except Exception as e:
        firewall_data.append([f"Error fetching firewall rules: {str(e)}"])

    return firewall_data


