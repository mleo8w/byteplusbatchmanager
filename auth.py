import hashlib
import hmac
import datetime
import requests
import json
from urllib.parse import quote_plus

API_HOST = 'open.byteplusapi.com'

def sha256(data):
    return hashlib.sha256(data.encode('utf-8')).hexdigest()

def hmac_sha256(key, msg, as_bytes=False):
    if isinstance(key, str):
        key = key.encode('utf-8')
    
    digest = hmac.new(key, msg.encode('utf-8'), hashlib.sha256)
    if as_bytes:
        return digest.digest()
    return digest.hexdigest()

def get_signature_key(key, date_stamp, region_name, service_name):
    k_date = hmac_sha256(key, date_stamp, as_bytes=True)
    k_region = hmac_sha256(k_date, region_name, as_bytes=True)
    k_service = hmac_sha256(k_region, service_name, as_bytes=True)
    k_signing = hmac_sha256(k_service, 'request', as_bytes=True)
    return k_signing

def get_signature_headers(credentials, host, method, path, query, payload, service):
    algorithm = 'HMAC-SHA256'
    request_type = 'request'
    
    now = datetime.datetime.utcnow()
    request_date = now.strftime('%Y%m%dT%H%M%SZ')
    date_stamp = now.strftime('%Y%m%d')
    
    payload_hash = sha256(payload or "")
    
    # [FIXED] Use the correct region based on the service being called
    region = 'byteplus-global' if service == 'waf' else credentials['region']
    
    sorted_query = sorted(query.items())
    canonical_query_string = '&'.join([f"{quote_plus(k)}={quote_plus(v)}" for k, v in sorted_query])
    
    canonical_headers = f"x-content-sha256:{payload_hash}\nx-date:{request_date}\n"
    signed_headers = 'x-content-sha256;x-date'
    
    canonical_request = f"{method}\n{path}\n{canonical_query_string}\n{canonical_headers}\n{signed_headers}\n{payload_hash}"
    
    credential_scope = f"{date_stamp}/{region}/{service}/{request_type}"
    string_to_sign = f"{algorithm}\n{request_date}\n{credential_scope}\n{sha256(canonical_request)}"
    
    signing_key = get_signature_key(credentials['secret_key'], date_stamp, region, service)
    signature = hmac.new(signing_key, string_to_sign.encode('utf-8'), hashlib.sha256).hexdigest()
    
    authorization_header = f"{algorithm} Credential={credentials['access_key']}/{credential_scope}, SignedHeaders={signed_headers}, Signature={signature}"
    
    headers = {
        'Authorization': authorization_header,
        'Content-Type': 'application/json',
        'X-Date': request_date,
        'X-Content-Sha256': payload_hash,
        'ServiceName': service,
        'Region': region
    }

    # [FIXED] Add the required language header for WAF requests
    if service == 'waf':
        headers['X-Top-Language'] = 'en'
        
    return headers

def make_api_request(credentials, method, query, payload, service):
    try:
        headers = get_signature_headers(credentials, API_HOST, method, '/', query, payload, service)
        query_string = '&'.join([f"{k}={v}" for k, v in query.items()])
        url = f"https://{API_HOST}/?{query_string}"
        
        response = requests.request(method, url, headers=headers, data=payload.encode('utf-8'))
        
        if response.status_code == 200:
            json_response = response.json()
            if "ResponseMetadata" in json_response and "Error" in json_response["ResponseMetadata"]:
                error = json_response["ResponseMetadata"]["Error"]
                return False, f"API Error: {error.get('Code')} - {error.get('Message')}"
            return True, json_response
        else:
            return False, f"HTTP Error {response.status_code}: {response.text}"
            
    except Exception as e:
        return False, str(e)
