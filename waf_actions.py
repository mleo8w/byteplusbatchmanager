import json
import time
from flask import jsonify
from auth import make_api_request

# --- CONFIGURATION ---
try:
    with open('config.json') as f:
        credentials = json.load(f)
    with open('ai_bot_library.json') as f:
        ai_bot_library = json.load(f)
except FileNotFoundError as e:
    print(f"FATAL ERROR: Configuration file not found - {e.filename}")
    credentials = {}
    ai_bot_library = {}

API_SERVICE_WAF = 'waf'
RATE_LIMIT_API_VERSION = '2020-12-09'
BOT_MANAGEMENT_API_VERSION = '2023-12-25'
VULN_API_VERSION = '2023-12-25'
CUSTOM_BOT_API_VERSION = '2023-12-25'


# =================================================================
# HELPER FUNCTION FOR CLEANING JSON
# =================================================================

def clean_and_parse_json(text):
    """A robust function to clean and parse a JSON string."""
    try:
        # Replace various non-standard quotes, escaped quotes, and remove newlines
        cleaned_text = text.strip().replace('""', '"').replace('“', '"').replace('”', '"').replace('\n', '')
        return json.loads(cleaned_text)
    except json.JSONDecodeError as e:
        print(f"JSON Parse Error: {e}")
        print(f"Original Text: {text}")
        return None

# =================================================================
# WAF WORKFLOW FUNCTIONS
# =================================================================

def add_domain_to_waf(data):
    domains = data.get('domains', [])
    results = []
    for i in range(0, len(domains), 20):
        batch = domains[i:i + 20]
        payload = { "Domains": batch, "TLSEnable": 1 }
        query = {'Action': 'CreateVolcWafServicesByBytePlusCDN', 'Version': '2020-12-09'}
        success, result = make_api_request(credentials, 'POST', query, json.dumps(payload), API_SERVICE_WAF)
        results.append({"batch_start_domain": batch[0], "success": success, "response": result})
    return jsonify(results)

def turn_waf_all(data):
    base_payload = {
        "WafEnable": 1, "BotRepeatEnable": 1, "BotDytokenEnable": 1, "AutoCCEnable": 1,
        "BotSequenceEnable": 1, "BotSequenceDefaultAction": 0, "BotFrequencyEnable": 1,
        "CcEnable": 1, "WhiteEnable": 1, "BlackIpEnable": 1, "BlackLctEnable": 1,
        "WafWhiteReqEnable": 1, "WhiteFieldEnable": 1, "CustomRspEnable": 1,
        "SystemBotEnable": 1, "CustomBotEnable": 1, "ApiEnable": 1,
        "TamperProofEnable": 1, "DlpEnable": 1
    }
    return update_waf_service_control(data, base_payload, 'Turn WAF All')

def turn_rl(data):
    base_payload = {"AutoCCEnable": 1, "CcEnable": 1}
    return update_waf_service_control(data, base_payload, 'Turn RL')

def turn_bot(data):
    base_payload = {
        "BotRepeatEnable": 1, "BotDytokenEnable": 1, "BotSequenceEnable": 1,
        "BotSequenceDefaultAction": 7, "BotFrequencyEnable": 1, "SystemBotEnable": 1,
        "CustomBotEnable": 1
    }
    return update_waf_service_control(data, base_payload, 'Turn Bot')

def update_waf_service_control(data, base_payload, alert_title):
    domains = data.get('domains', [])
    results = []
    for domain in domains:
        payload = {**base_payload, "Host": domain}
        query = {'Action': 'UpdateWafServiceControl', 'Version': BOT_MANAGEMENT_API_VERSION}
        success, result = make_api_request(credentials, 'POST', query, json.dumps(payload), API_SERVICE_WAF)
        results.append({"domain": domain, "success": success, "response": result})
        time.sleep(0.1)
    return jsonify(results)

def create_rate_limiting_rules(data):
    domains = data.get('domains', [])
    rules_text = data.get('rules', '')
    if not domains or not rules_text:
        return jsonify({"status": "error", "message": "Domains and a rule template are required."})

    results = []
    rule_template = clean_and_parse_json(rules_text)
    if rule_template is None:
        return jsonify({"status": "error", "message": "Invalid JSON format in the rules box."})

    if 'Id' in rule_template:
        del rule_template['Id']

    for domain in domains:
        payload = {**rule_template, "Host": domain}
        query = {'Action': 'CreateCCRule', 'Version': RATE_LIMIT_API_VERSION}
        success, result = make_api_request(credentials, 'POST', query, json.dumps(payload), API_SERVICE_WAF)
        results.append({"domain": domain, "rule_name": payload.get("Name"), "success": success, "response": result})
        time.sleep(0.1)
    return jsonify(results)

def list_rate_limiting_rules(data):
    domain = data.get('domains', [''])[0]
    if not domain:
        return jsonify({"status": "error", "message": "Please provide a domain to list rules for."})

    payload = {"Host": domain}
    query = {'Action': 'ListCCRule', 'Version': RATE_LIMIT_API_VERSION}
    success, result = make_api_request(credentials, 'POST', query, json.dumps(payload), API_SERVICE_WAF)

    if success and result.get("Result"):
        all_rules = []
        if isinstance(result["Result"], list):
            for group in result["Result"]:
                if group.get("RuleGroup"):
                    for sub_group in group["RuleGroup"]:
                        if sub_group.get("Rules"):
                            all_rules.extend(sub_group["Rules"])
        
        simplified_rules = []
        for rule in all_rules:
            simplified_rules.append({
                "Id": rule.get("Id"), "Name": rule.get("Name"), "Url": rule.get("Url"),
                "Field": rule.get("Field"), "SingleThreshold": rule.get("SingleThreshold"),
                "PathThreshold": rule.get("PathThreshold"), "CountTime": rule.get("CountTime"),
                "CCType": rule.get("CCType"), "RulePriority": rule.get("RulePriority"),
                "Enable": rule.get("Enable"), "EffectTime": rule.get("EffectTime"), "Host": rule.get("Host")
            })
        return jsonify({"status": "success", "rules": simplified_rules})
    else:
        return jsonify({"status": "error", "message": result}), 500

def update_rate_limiting_rules(data):
    domains = data.get('domains', [])
    rules_text = data.get('rules', '')
    if not domains or not rules_text:
        return jsonify({"status": "error", "message": "Domains and rules are required."})

    results = []
    try:
        rule = clean_and_parse_json(rules_text)
        if rule is None:
            raise ValueError("Invalid JSON format.")
    except (json.JSONDecodeError, ValueError) as e:
        return jsonify({"status": "error", "message": f"Invalid JSON format in the rules box: {e}"})

    for domain in domains:
        if "Id" not in rule:
            results.append({"domain": domain, "rule_name": rule.get("Name"), "success": False, "response": "Rule JSON must contain an 'Id' for updates."})
            continue
        
        payload = {**rule, "Host": domain}
        query = {'Action': 'UpdateCCRule', 'Version': RATE_LIMIT_API_VERSION}
        success, result = make_api_request(credentials, 'POST', query, json.dumps(payload), API_SERVICE_WAF)
        results.append({"domain": domain, "rule_name": rule.get("Name"), "success": success, "response": result})
        time.sleep(0.1)
    return jsonify(results)

def delete_rate_limiting_rules(data):
    domains = data.get('domains', [])
    rules_text = data.get('rules', '')
    if not domains or not rules_text:
        return jsonify({"status": "error", "message": "Domains and rules/IDs are required."})

    results = []
    rule_ids = []
    
    parsed_json = clean_and_parse_json(rules_text)
    if parsed_json:
        json_rules = parsed_json if isinstance(parsed_json, list) else [parsed_json]
        for rule in json_rules:
            if isinstance(rule, dict) and "Id" in rule:
                rule_ids.append(rule["Id"])
    else:
        for line in rules_text.strip().split('\n'):
            if line.strip().isdigit():
                rule_ids.append(int(line.strip()))

    if not rule_ids:
        return jsonify({"status": "error", "message": "Could not parse any Rule IDs from the text box."})

    for domain in domains:
        domain_results = []
        for rule_id in rule_ids:
            payload = {"Host": domain, "ID": rule_id}
            query = {'Action': 'DeleteCCRule', 'Version': RATE_LIMIT_API_VERSION}
            success, result = make_api_request(credentials, 'POST', query, json.dumps(payload), API_SERVICE_WAF)
            domain_results.append({"rule_id": rule_id, "success": success, "response": result})
            time.sleep(0.1)
        results.append({"domain": domain, "deletions": domain_results})
    return jsonify(results)


def list_managed_bot_rules(data):
    domain = data.get('domains', [''])[0]
    if not domain:
        return jsonify({"status": "error", "message": "Please provide at least one domain."})

    payload = {"Host": domain}
    query = {'Action': 'ListSystemBotConfig', 'Version': BOT_MANAGEMENT_API_VERSION}
    success, result = make_api_request(credentials, 'POST', query, json.dumps(payload), API_SERVICE_WAF)

    if success and result.get("Result", {}).get("Data"):
        all_rules = [r for r in result["Result"]["Data"] if r.get("BotType") != 'search_engine_bot']
        return jsonify({"status": "success", "data": all_rules})
    else:
        return jsonify({"status": "error", "message": result}), 500

def configure_managed_bot_rules(data):
    domains = data.get('domains', [])
    rules_from_ui = data.get('rules', [])
    if not domains or not rules_from_ui:
        return jsonify({"status": "error", "message": "Domain and rules are required."})

    overall_results = []
    for domain in domains:
        domain_update_results = []
        for ui_rule in rules_from_ui:
            payload = {
                "Host": domain,
                "BotType": ui_rule.get("name"),
                "Enable": ui_rule.get("enable"),
                "Action": ui_rule.get("action")
            }
            if 'time' in ui_rule:
                payload['VerificationExemptionTime'] = ui_rule.get('time')
            
            query = {'Action': 'UpdateSystemBotConfig', 'Version': BOT_MANAGEMENT_API_VERSION}
            success, result = make_api_request(credentials, 'POST', query, json.dumps(payload), API_SERVICE_WAF)
            domain_update_results.append({"bot_type": ui_rule.get("name"), "success": success, "response": result})
            time.sleep(0.2)
        
        overall_results.append({"domain": domain, "results": domain_update_results})

    return jsonify({"status": "complete", "overall_results": overall_results})

def list_seo_bot_rules(data):
    domain = data.get('domains', [''])[0]
    if not domain:
        return jsonify({"status": "error", "message": "Please provide at least one domain."})

    payload = {"Host": domain}
    query = {'Action': 'ListSystemBotConfig', 'Version': BOT_MANAGEMENT_API_VERSION}
    success, result = make_api_request(credentials, 'POST', query, json.dumps(payload), API_SERVICE_WAF)

    if success and result.get("Result", {}).get("Data"):
        seo_parent = next((r for r in result["Result"]["Data"] if r.get("BotType") == 'search_engine_bot'), None)
        seo_rules = seo_parent.get("SubRules", []) if seo_parent else []
        return jsonify({"status": "success", "data": seo_rules})
    else:
        return jsonify({"status": "error", "message": result}), 500

def configure_seo_bot_rules(data):
    domains = data.get('domains', [])
    rules_from_ui = data.get('rules', [])
    if not domains or not rules_from_ui:
        return jsonify({"status": "error", "message": "Domain and rules are required."})

    overall_results = []
    for domain in domains:
        list_payload = {"Host": domain}
        list_query = {'Action': 'ListSystemBotConfig', 'Version': BOT_MANAGEMENT_API_VERSION}
        success, current_config_res = make_api_request(credentials, 'POST', list_query, json.dumps(list_payload), API_SERVICE_WAF)

        if not success:
            overall_results.append({"domain": domain, "status": "error", "message": f"Could not fetch current config: {current_config_res}"})
            continue
        
        current_config = current_config_res.get("Result", {}).get("Data", [])
        seo_parent_rule = next((r for r in current_config if r.get("BotType") == 'search_engine_bot'), None)

        if not seo_parent_rule:
            overall_results.append({"domain": domain, "status": "error", "message": "Could not find parent SEO rule to update."})
            continue
        
        domain_update_results = []
        for ui_rule in rules_from_ui:
            # Create a fresh copy of the parent rule for each sub-rule update
            updated_seo_rule = json.loads(json.dumps(seo_parent_rule))
            
            sub_rule_to_update = next((sr for sr in updated_seo_rule.get("SubRules", []) if sr.get("Name") == ui_rule.get("name")), None)
            
            if sub_rule_to_update:
                sub_rule_to_update['Enable'] = ui_rule.get('enable')
                sub_rule_to_update['Action'] = ui_rule.get('action')
                if 'time' in ui_rule:
                    sub_rule_to_update['VerificationExemptionTime'] = ui_rule.get('time')

                # The API expects a list containing only the sub-rule being changed
                updated_seo_rule["SubRules"] = [sub_rule_to_update]

                update_payload = {**updated_seo_rule, "Host": domain}
                update_query = {'Action': 'UpdateSystemBotConfig', 'Version': BOT_MANAGEMENT_API_VERSION}
                success, result = make_api_request(credentials, 'POST', update_query, json.dumps(update_payload), API_SERVICE_WAF)
                domain_update_results.append({"sub_rule": ui_rule.get("name"), "success": success, "response": result})
                time.sleep(0.2)

        overall_results.append({"domain": domain, "results": domain_update_results})

    return jsonify({"status": "complete", "overall_results": overall_results})


def list_vulnerability_rules(data):
    domain = data.get('domains', [''])[0]
    if not domain:
        return jsonify({"status": "error", "message": "Please provide a domain to list rules for."})

    payload = {"Host": domain}
    query = {'Action': 'GetVulnerabilityConfig', 'Version': VULN_API_VERSION}
    success, result = make_api_request(credentials, 'POST', query, json.dumps(payload), API_SERVICE_WAF)

    if success and result.get("Result"):
        return jsonify({"status": "success", "data": result["Result"]})
    else:
        return jsonify({"status": "error", "message": result}), 500

def configure_vulnerability_rules(data):
    domains = data.get('domains', [])
    rules_config = data.get('rules', {})
    if not domains or not rules_config:
        return jsonify({"status": "error", "message": "Domains and rules are required."})

    results = []
    try:
        simplified_config = json.loads(rules_config)
    except (json.JSONDecodeError, TypeError):
        simplified_config = rules_config


    for domain in domains:
        get_query = {'Action': 'GetVulnerabilityConfig', 'Version': VULN_API_VERSION}
        get_payload = {"Host": domain}
        success, current_config_res = make_api_request(credentials, 'POST', get_query, json.dumps(get_payload), API_SERVICE_WAF)

        if not success:
            results.append({"domain": domain, "success": False, "response": f"Could not fetch current config: {current_config_res}"})
            continue

        full_config = current_config_res.get("Result", {})
        
        full_config['RuleMode'] = simplified_config.get('RuleMode', full_config.get('RuleMode'))
        full_config['Action'] = simplified_config.get('Action', full_config.get('Action'))
        if 'AdvanceConfig' in full_config and 'AutoTraversal' in full_config['AdvanceConfig']:
            full_config['AdvanceConfig']['AutoTraversal']['Enable'] = simplified_config.get('AutoTraversal', full_config['AdvanceConfig']['AutoTraversal']['Enable'])
        if 'AdvanceConfig' in full_config and 'FreqScan' in full_config['AdvanceConfig']:
            full_config['AdvanceConfig']['FreqScan']['Enable'] = simplified_config.get('FreqScan', full_config['AdvanceConfig']['FreqScan']['Enable'])
        full_config['Host'] = domain

        update_query = {'Action': 'UpdateVulnerabilityConfig', 'Version': VULN_API_VERSION}
        success, result = make_api_request(credentials, 'POST', update_query, json.dumps(full_config), API_SERVICE_WAF)
        results.append({"domain": domain, "success": success, "response": result})
        time.sleep(0.1)
        
    return jsonify(results)

def configure_ai_bot_rules(data):
    domains = data.get('domains', [])
    rules_from_ui = data.get('rules', [])
    if not domains or not rules_from_ui:
        return jsonify({"status": "error", "message": "Domain and rules are required."})

    overall_results = []
    for domain in domains:
        list_query = {'Action': 'ListCustomBotConfig', 'Version': CUSTOM_BOT_API_VERSION, 'Host': domain}
        list_success, list_result = make_api_request(credentials, 'GET', list_query, '', API_SERVICE_WAF)
        existing_rules = list_result.get("Result", {}).get("Rows", []) if list_success else []
        existing_rule_map = {rule.get("BotType"): rule.get("Id") for rule in existing_rules}

        domain_results = []
        for ui_rule in rules_from_ui:
            bot_name = ui_rule.get('name')
            bot_definition = ai_bot_library.get(bot_name)
            if not bot_definition:
                domain_results.append({"bot_name": bot_name, "success": False, "response": "Bot definition not found in library."})
                continue

            payload = {
                "Host": domain,
                "Action": ui_rule.get('action'),
                "Description": bot_definition.get("Description"),
                "Enable": ui_rule.get('enable'),
                "BotType": bot_name,
                "Advanced": 1,
                "Policy": 1,
                "Accurate": {
                    "Logic": 1,
                    "AccurateRules": [
                        {
                            "Property": 0,
                            "HttpObj": "request.header.ua",
                            "ObjType": 6,
                            "Opretar": 2,
                            "ValueString": content["Content"]
                        } for content in bot_definition.get("Conditions", [{}])[0].get("Detection", {}).get("Contents", [])
                    ]
                }
            }
            if 'time' in ui_rule:
                payload['VerificationExemptionTime'] = ui_rule.get('time')

            if bot_name in existing_rule_map:
                payload["Id"] = existing_rule_map[bot_name]
                query = {'Action': 'UpdateCustomBotConfig', 'Version': CUSTOM_BOT_API_VERSION}
            else:
                query = {'Action': 'CreateCustomBotConfig', 'Version': CUSTOM_BOT_API_VERSION}

            success, result = make_api_request(credentials, 'POST', query, json.dumps(payload), API_SERVICE_WAF)
            domain_results.append({"bot_name": bot_name, "success": success, "response": result})
            time.sleep(0.2)
        overall_results.append({"domain": domain, "results": domain_results})
    
    return jsonify({"status": "complete", "overall_results": overall_results})
