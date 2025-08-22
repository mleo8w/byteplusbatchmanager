from flask import Flask, request, jsonify
from flask_cors import CORS

# Import the new action modules
import ssl_actions
import waf_actions

app = Flask(__name__)
CORS(app)  # Allows your HTML file to talk to the Python server

# =================================================================
# SSL ENDPOINT - Acts as a router to the ssl_actions.py module
# =================================================================
@app.route('/ssl', methods=['POST'])
def handle_ssl():
    data = request.json
    action = data.get('action')

    if action == 'create_orders':
        return ssl_actions.create_ssl_orders(data)
    elif action == 'get_dns_info':
        return ssl_actions.get_dns_info(data)
    elif action == 'check_status':
        return ssl_actions.check_cert_status_and_binding(data)
    elif action == 'pull_expiring':
        return ssl_actions.pull_expiring_certs()
    elif action == 'replace_orders':
        return ssl_actions.replace_cert_orders(data)
    elif action == 'bind_certs':
        return ssl_actions.bind_certs_to_domains(data)
    elif action == 'push_dns':
        return ssl_actions.push_dns()
    elif action == 'create_hosting_task':
        return ssl_actions.check_and_create_hosting_task(data)
    elif action == 'pull_and_push_medialive_cert':
        return ssl_actions.pull_and_push_medialive_cert(data)
    else:
        return jsonify({"status": "error", "message": f"Unknown SSL action: {action}"}), 400

# =================================================================
# WAF ENDPOINT - Acts as a router to the waf_actions.py module
# =================================================================
@app.route('/waf', methods=['POST'])
def handle_waf():
    data = request.json
    action = data.get('action')

    if action == 'add_domain':
        return waf_actions.add_domain_to_waf(data)
    elif action == 'turn_waf_all':
        return waf_actions.turn_waf_all(data)
    elif action == 'turn_rl':
        return waf_actions.turn_rl(data)
    elif action == 'turn_bot':
        return waf_actions.turn_bot(data)
    elif action == 'list_rl_rules':
        return waf_actions.list_rate_limiting_rules(data)
    elif action == 'config_rl_rules':
        return waf_actions.create_rate_limiting_rules(data)
    elif action == 'update_rl_rules':
        return waf_actions.update_rate_limiting_rules(data)
    elif action == 'delete_rl_rules':
        return waf_actions.delete_rate_limiting_rules(data)
    elif action == 'list_managed_bot_rules':
        return waf_actions.list_managed_bot_rules(data)
    elif action == 'config_managed_bot_rules':
        return waf_actions.configure_managed_bot_rules(data)
    elif action == 'list_seo_bot_rules':
        return waf_actions.list_seo_bot_rules(data)
    elif action == 'config_seo_bot_rules':
        return waf_actions.configure_seo_bot_rules(data)
    elif action == 'list_vul_rules':
        return waf_actions.list_vulnerability_rules(data)
    elif action == 'config_vul_rules':
        return waf_actions.configure_vulnerability_rules(data)
    elif action == 'config_ai_bots':
        return waf_actions.configure_ai_bot_rules(data)
    else:
        return jsonify({"status": "error", "message": f"Unknown WAF action: {action}"}), 400

if __name__ == '__main__':
    print("Starting BytePlus Manager backend server...")
    print("Open your app.html file in a web browser to use the tool.")
    app.run(debug=False)
