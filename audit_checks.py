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


from googleapiclient import discovery
from google.auth import default

def check_load_balancers_audit():
    creds, project = default()
    compute = discovery.build('compute', 'v1', credentials=creds)
    lb_data = []

    req = compute.forwardingRules().aggregatedList(project=project)
    while req is not None:
        res = req.execute()
        for region, scoped_list in res.get('items', {}).items():
            for rule in scoped_list.get('forwardingRules', []):
                lb_name = rule.get('name', '')
                target = rule.get('target', '') or rule.get('backendService', '') or rule.get('targetPool', '')
                scheme = rule.get('loadBalancingScheme', '')
                ip = rule.get('IPAddress', '')

                # Default values
                ssl_policy = 'N/A'
                cloud_armor_policy = 'N/A'
                ssl_cert_status = 'N/A'
                https_redirect = 'N/A'
                armor_rule_strength = 'N/A'
                internal_exposure = 'N/A'

                # ---------------- HTTPS Proxy ----------------
                if 'targetHttpsProxies' in target or target.endswith('httpsProxies'):
                    try:
                        target_name = target.split('/')[-1]
                        proxy = compute.targetHttpsProxies().get(project=project, targetHttpsProxy=target_name).execute()

                        ssl_policy = proxy.get('sslPolicy', 'None')
                        cloud_armor_policy = proxy.get('securityPolicy', 'None')

                        # 1️⃣ SSL Certificate Check
                        cert_urls = proxy.get('sslCertificates', [])
                        if cert_urls:
                            ssl_cert_status = []
                            for cert_url in cert_urls:
                                cert_name = cert_url.split('/')[-1]
                                cert = compute.sslCertificates().get(project=project, sslCertificate=cert_name).execute()
                                exp = cert.get('expireTime', 'Unknown')
                                ssl_cert_status.append(f"Valid till: {exp}")
                            ssl_cert_status = ', '.join(ssl_cert_status)
                        else:
                            ssl_cert_status = 'No SSL Certificates attached'

                        # 3️⃣ Cloud Armor Rule Strength
                        if cloud_armor_policy not in ['None', 'N/A']:
                            armor_name = cloud_armor_policy.split('/')[-1]
                            policy = compute.securityPolicies().get(project=project, securityPolicy=armor_name).execute()
                            rules = policy.get('rules', [])
                            if not rules:
                                armor_rule_strength = 'Weak - No rules found'
                            else:
                                armor_rule_strength = f"Strong - {len(rules)} rules"
                        else:
                            armor_rule_strength = 'No Cloud Armor policy'

                    except Exception as e:
                        ssl_cert_status = f"Error: {str(e)}"

                # ---------------- HTTP Proxy ----------------
                elif 'targetHttpProxies' in target or target.endswith('httpProxies'):
                    try:
                        target_name = target.split('/')[-1]
                        proxy = compute.targetHttpProxies().get(project=project, targetHttpProxy=target_name).execute()
                        cloud_armor_policy = proxy.get('securityPolicy', 'None')

                        # 2️⃣ Check if HTTP is redirected to HTTPS
                        # Usually via URL maps that contain redirect actions
                        url_map_url = proxy.get('urlMap', '')
                        if url_map_url:
                            url_map_name = url_map_url.split('/')[-1]
                            url_map = compute.urlMaps().get(project=project, urlMap=url_map_name).execute()
                            has_redirect = any('redirectAction' in path_matcher.get('defaultRouteAction', {})
                                               for path_matcher in url_map.get('pathMatchers', []))
                            https_redirect = 'Yes' if has_redirect else 'No'
                        else:
                            https_redirect = 'No URL map found'

                        # Cloud Armor policy check (similar to HTTPS)
                        if cloud_armor_policy not in ['None', 'N/A']:
                            armor_name = cloud_armor_policy.split('/')[-1]
                            policy = compute.securityPolicies().get(project=project, securityPolicy=armor_name).execute()
                            rules = policy.get('rules', [])
                            armor_rule_strength = f"Strong - {len(rules)} rules" if rules else "Weak - No rules"
                        else:
                            armor_rule_strength = 'No Cloud Armor policy'

                    except Exception as e:
                        https_redirect = f"Error: {str(e)}"

                # ---------------- External Exposure Check ----------------
                if scheme == 'EXTERNAL':
                    # Check if backend is an internal resource (like internal backend service or instance group)
                    internal_exposure = 'Potential Risk' if any(x in target for x in ['backendServices', 'instanceGroups']) else 'OK'

                lb_data.append({
                    'name': lb_name,
                    'scheme': scheme,
                    'ip': ip,
                    'ssl_policy': ssl_policy,
                    'ssl_cert_status': ssl_cert_status,
                    'https_redirect': https_redirect,
                    'cloud_armor_policy': cloud_armor_policy,
                    'armor_rule_strength': armor_rule_strength,
                    'internal_exposure': internal_exposure
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

# --------------------------------- check_cloud_functions_and_run ---------------------------------------------------
def check_cloud_functions_and_run():
    from googleapiclient import discovery
    from google.auth import default

    creds, project = default()
    functions_service = discovery.build('cloudfunctions', 'v1', credentials=creds)
    run_service = discovery.build('run', 'v1', credentials=creds)

    audit_data = []

    # -------------------- Cloud Functions --------------------
    try:
        req = functions_service.projects().locations().functions().list(
            parent=f"projects/{project}/locations/-"
        )
        res = req.execute()

        for fn in res.get('functions', []):
            name = fn.get('name', '').split('/')[-1]
            region = fn.get('name', '').split('/')[3] if len(fn.get('name', '').split('/')) > 3 else 'global'
            runtime = fn.get('runtime', 'N/A')
            trigger_type = 'HTTP' if 'httpsTrigger' in fn else 'Event'
            url = fn.get('httpsTrigger', {}).get('url', 'N/A')
            ingress = fn.get('ingressSettings', 'N/A')
            auth = fn.get('httpsTrigger', {}).get('securityLevel', 'N/A')
            service_account = fn.get('serviceAccountEmail', 'N/A')

            unauthenticated = 'Yes' if auth == 'SECURE_OPTIONAL' else 'No'
            exposure_risk = (
                'High' if ingress == 'ALLOW_ALL' or unauthenticated == 'Yes'
                else 'Medium' if ingress == 'ALLOW_INTERNAL_AND_GCLB'
                else 'Low'
            )

            recommendation = "Restrict unauthenticated invocations and apply ingress controls for internal-only access."

            audit_data.append([
                "Cloud Function",
                name,
                region,
                runtime,
                trigger_type,
                url,
                ingress,
                auth,
                service_account,
                unauthenticated,
                exposure_risk,
                recommendation
            ])
    except Exception as e:
        audit_data.append([
            "Cloud Function",
            f"Error fetching: {str(e)}",
            "", "", "", "", "", "", "", "", "",
            "Restrict unauthenticated invocations and apply ingress controls for internal-only access."
        ])

    # -------------------- Cloud Run --------------------
    try:
        req = run_service.projects().locations().services().list(
            parent=f"projects/{project}/locations/-"
        )
        res = req.execute()

        for service in res.get('items', []):
            metadata = service.get('metadata', {})
            spec = service.get('spec', {})
            template_spec = spec.get('template', {}).get('spec', {})

            name = metadata.get('name', 'N/A')
            region = metadata.get('labels', {}).get('cloud.googleapis.com/location', 'global')
            url = service.get('status', {}).get('url', 'N/A')
            annotations = metadata.get('annotations', {})
            ingress = annotations.get('run.googleapis.com/ingress', 'N/A')
            service_account = template_spec.get('serviceAccountName', 'N/A')

            # IAM Policy check for auth
            try:
                resource_name = f"projects/{project}/locations/{region}/services/{name}"
                policy = run_service.projects().locations().services().getIamPolicy(
                    resource=resource_name
                ).execute()

                members = [m for b in policy.get('bindings', []) for m in b.get('members', [])]
                unauthenticated = any('allUsers' in m for m in members)
                authenticated = any('allAuthenticatedUsers' in m for m in members)

                auth_level = (
                    "Unauthenticated" if unauthenticated else
                    "Authenticated (All Authenticated Users)" if authenticated else
                    "Authenticated (Restricted)"
                )
            except Exception:
                unauthenticated = False
                auth_level = "Unknown"

            exposure_risk = (
                'High' if ingress == 'all' or unauthenticated else
                'Medium' if ingress == 'internal-and-cloud-load-balancing' else
                'Low'
            )

            audit_data.append([
                "Cloud Run",
                name,
                region,
                "N/A",
                "HTTP",
                url,
                ingress,
                auth_level,
                service_account,
                "Yes" if unauthenticated else "No",
                exposure_risk
            ])
    except Exception as e:
        audit_data.append([
            "Cloud Run",
            f"Error fetching: {str(e)}",
            "", "", "", "", "", "", "", "", "",
            "Restrict unauthenticated invocations and use ingress controls for internal-only access."
        ])

    return audit_data

