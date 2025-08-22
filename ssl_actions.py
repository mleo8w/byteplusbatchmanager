import json
import time
from flask import jsonify
from auth import make_api_request
from datetime import datetime

# --- CONFIGURATION ---
try:
    with open('config.json') as f:
        credentials = json.load(f)
except FileNotFoundError:
    print("FATAL ERROR: config.json not found.")
    credentials = {}

API_SERVICE_CERT = 'certificate_service'
API_SERVICE_CDN = 'cdn'
API_SERVICE_DNS = 'dns'
API_SERVICE_LIVE = 'live' # New service for MediaLive

# =================================================================
# SSL WORKFLOW FUNCTIONS
# =================================================================

def create_ssl_orders(data):
    domains = data.get('domains', [])
    cert_type = data.get('cert_type', 'lets_encrypt_standard_dv')
    results = []
    for domain in domains:
        payload = {
            "plan": cert_type,
            "tag": "GSA",
            "order_organization": credentials.get("organization_details"),
            "ssl": {
                "common_name": domain,
                "order_validation_type": "dns_txt",
                "san": [domain],
                "certificate": {"csr": "", "private_key": "", "key_type": "rsa"}
            }
        }
        query = {'Action': 'CertificateAddFreeInstance', 'Version': '2021-06-01'}
        success, result = make_api_request(credentials, 'POST', query, json.dumps(payload), API_SERVICE_CERT)
        results.append({"domain": domain, "success": success, "response": result})
        time.sleep(0.1)
    return jsonify(results)

def get_dns_info(data):
    cert_ids = data.get('cert_ids', [])
    results = []
    if not cert_ids:
        return jsonify({"status": "error", "message": "Please provide Certificate IDs."})
        
    for cert_id in cert_ids:
        query = {'Action': 'CertificateGetDcvParam', 'Version': '2021-06-01', 'instance_id': cert_id}
        success, result = make_api_request(credentials, 'GET', query, '', API_SERVICE_CERT)
        results.append({"cert_id": cert_id, "success": success, "response": result})
        time.sleep(0.1)
    return jsonify(results)

def check_cert_status_and_binding(data):
    cert_ids = data.get('cert_ids', [])
    results = []
    if not cert_ids:
        return jsonify({"status": "error", "message": "Please provide Certificate IDs."})

    for cert_id in cert_ids:
        status_query = {'Action': 'CertificateGetInstance', 'Version': '2021-06-01', 'instance_id': cert_id}
        status_success, status_result = make_api_request(credentials, 'GET', status_query, '', API_SERVICE_CERT)
        
        binding_query = {'Action': 'ListCdnCertInfo', 'Version': '2021-03-01'}
        binding_payload = {"CertId": cert_id}
        binding_success, binding_result = make_api_request(credentials, 'POST', binding_query, json.dumps(binding_payload), API_SERVICE_CDN)

        binding_info = "Not Found"
        if binding_success and binding_result.get("Result", {}).get("CertInfo") and len(binding_result["Result"]["CertInfo"]) > 0:
            binding_info = binding_result["Result"]["CertInfo"][0].get("Domain", "Not Found")

        results.append({
            "cert_id": cert_id, 
            "success": status_success, 
            "status_response": status_result,
            "binding_info": binding_info
        })
        time.sleep(0.1)
    return jsonify(results)

def pull_expiring_certs():
    query = {'Action': 'ListCdnCertInfo', 'Version': '2021-03-01'}
    payload = {"Status": "expiring_soon"}
    success, result = make_api_request(credentials, 'POST', query, json.dumps(payload), API_SERVICE_CDN)
    if success:
        cert_info = result.get("Result", {}).get("CertInfo") or []
        key_items = [
            {
                "Domain": cert.get("ConfiguredDomain"),
                "CertId": cert.get("CertId"),
                "ExpireTime": cert.get("ExpireTime")
            }
            for cert in cert_info
        ]
        return jsonify({"status": "success", "raw_response": result, "key_items": key_items})
    else:
        return jsonify({"status": "error", "message": result}), 500

def replace_cert_orders(data):
    return create_ssl_orders(data)

def bind_certs_to_domains(data):
    cert_ids = data.get('cert_ids', [])
    domains = data.get('domains', [])
    results = []
    if not cert_ids or not domains or len(cert_ids) != len(domains):
        return jsonify({"status": "error", "message": "Please provide a matching number of Certificate IDs and Domains."})

    for i in range(len(cert_ids)):
        cert_id = cert_ids[i]
        domain = domains[i]
        
        payload = {"CertId": cert_id, "Domain": domain}
        query = {'Action': 'BatchDeployCert', 'Version': '2021-03-01'}
        success, result = make_api_request(credentials, 'POST', query, json.dumps(payload), API_SERVICE_CDN)
        results.append({"cert_id": cert_id, "domain": domain, "success": success, "response": result})
        time.sleep(0.1)
    return jsonify(results)

def push_dns():
    # 1. Fetch all certificates and filter for those needing delegation
    cert_query = {'Action': 'CertificateGetInstance', 'Version': '2021-06-01'}
    cert_success, cert_result = make_api_request(credentials, 'GET', cert_query, '', API_SERVICE_CERT)

    if not cert_success or not cert_result.get("Result") or not cert_result["Result"].get("content"):
        return jsonify({"status": "error", "message": f"Failed to get certificate list: {cert_result}"})

    certs_to_delegate = [cert for cert in cert_result["Result"]["content"] if cert.get("managed_task_id") == ""]
    
    if not certs_to_delegate:
        return jsonify({"status": "info", "message": "No certificates found that require DNS delegation."})

    results = []
    successful_cert_ids = []
    for cert in certs_to_delegate:
        cert_id = cert.get("id")
        domain_name = cert.get("common_name")

        # 2. Create Delegated CNAME records
        delegate_query = {'Action': 'CreateDelegatedCnameRecords', 'Version': '2021-06-01'}
        delegate_payload = {"instance_id": cert_id}
        delegate_success, delegate_result = make_api_request(credentials, 'POST', delegate_query, json.dumps(delegate_payload), API_SERVICE_CERT)

        if not delegate_success or not delegate_result.get("Result") or not delegate_result["Result"].get("cnameRecords"):
            results.append({"domain": domain_name, "status": "Failed to create CNAME records", "error": delegate_result})
            continue

        cname_record = delegate_result["Result"]["cnameRecords"][0]
        cname_host = cname_record.get("host")
        cname_value = cname_record.get("value")
        root_domain = '.'.join(domain_name.split('.')[-2:])

        # 3. Find the Zone ID
        zones_query = {'Action': 'ListZones', 'Version': '2018-08-01', 'ZoneName': root_domain}
        zone_success, zone_result = make_api_request(credentials, 'GET', zones_query, '', API_SERVICE_DNS)
        
        if not zone_success or not zone_result.get("Result") or not zone_result["Result"].get("Zones"):
            results.append({"domain": domain_name, "status": f"Failed to find Zone ID for {root_domain}", "error": zone_result})
            continue
            
        zone_id = zone_result["Result"]["Zones"][0].get("ZID")

        # 4. Create the DNS Record
        create_record_query = {'Action': 'CreateRecord', 'Version': '2018-08-01'}
        create_record_payload = {
            "Host": cname_host.replace(f".{root_domain}", ''),
            "Line": "default", "TTL": 600, "Type": "CNAME",
            "Value": cname_value, "Weight": 1, "ZID": zone_id
        }
        create_success, create_result = make_api_request(credentials, 'POST', create_record_query, json.dumps(create_record_payload), API_SERVICE_DNS)
        
        if create_success:
            results.append({"domain": domain_name, "status": "DNS Record Created Successfully"})
            successful_cert_ids.append(cert_id)
        else:
            results.append({"domain": domain_name, "status": "Failed to create DNS record", "error": create_result})

    return jsonify({"status": "success", "results": results, "successful_cert_ids": successful_cert_ids})

def check_and_create_hosting_task(data):
    cert_ids = data.get('cert_ids', [])
    results = []
    if not cert_ids:
        return jsonify({"status": "error", "message": "Please provide Certificate IDs."})

    for cert_id in cert_ids:
        # 1. Check Delegated CNAME Records
        check_query = {'Action': 'CheckDelegatedCnameRecords', 'Version': '2021-06-01', 'instance_id': cert_id}
        check_success, check_result = make_api_request(credentials, 'GET', check_query, '', API_SERVICE_CERT)

        if not check_success or not check_result.get("Result"):
            results.append({"cert_id": cert_id, "status": f"DNS Check Failed: {check_result}"})
            continue

        if check_result["Result"].get("check_result") is True:
            # 2. Create Managed Task
            create_query = {'Action': 'CreateMangedTask', 'Version': '2021-06-01'}
            create_payload = {
                "binding_services": ["CDN"], "instance_id": cert_id,
                "renew_period": 30, "tag": "GSAxxX9CU"
            }
            create_success, create_result = make_api_request(credentials, 'POST', create_query, json.dumps(create_payload), API_SERVICE_CERT)

            if create_success:
                results.append({"cert_id": cert_id, "status": "Hosting Task Created Successfully"})
            else:
                results.append({"cert_id": cert_id, "status": f"Hosting Task Failed: {create_result}"})
        else:
            results.append({"cert_id": cert_id, "status": "DNS Check Failed (Result: false)"})
            
    return jsonify(results)

def pull_and_push_medialive_cert(data):
    cert_ids = data.get('cert_ids', [])
    if not cert_ids:
        return jsonify({"status": "error", "message": "Please provide Certificate IDs."})

    results = []
    for cert_id in cert_ids:
        # 1. Pull Cert Info
        cert_query = {'Action': 'CertificateGetInstance', 'Version': '2021-06-01', 'instance_id': cert_id}
        cert_success, cert_result = make_api_request(credentials, 'GET', cert_query, '', API_SERVICE_CERT)

        if not cert_success or not cert_result.get("Result") or not cert_result["Result"].get("content"):
            results.append({"cert_id": cert_id, "success": False, "response": f"Failed to get cert info: {cert_result}"})
            continue

        cert_content = cert_result["Result"]["content"][0]
        
        # Initialize keys as None
        pub_key = None
        pri_key = None

        # Safely navigate the nested JSON structure
        if "ssl" in cert_content and isinstance(cert_content["ssl"], dict):
            if "certificate" in cert_content["ssl"] and isinstance(cert_content["ssl"]["certificate"], dict):
                cert_data = cert_content["ssl"]["certificate"]
                pri_key = cert_data.get("private_key")
                chain_list = cert_data.get("chain", [])
                if chain_list:
                    pub_key = "\n".join(chain_list)

        if not pub_key or not pri_key:
            results.append({"cert_id": cert_id, "success": False, "response": "Public or Private key not found in certificate instance."})
            continue
            
        # 2. Push Cert to MediaLive
        live_payload = {
            "UseWay": "https",
            "Rsa": {
                "PubKey": pub_key,
                "PriKey": pri_key
            }
        }
        live_query = {'Action': 'CreateCert', 'Version': '2023-01-01'}
        live_success, live_result = make_api_request(credentials, 'POST', live_query, json.dumps(live_payload), API_SERVICE_LIVE)
        
        results.append({
            "cert_id": cert_id,
            "success": live_success,
            "response": live_result
        })
        time.sleep(0.2)

    return jsonify({"status": "complete", "results": results})