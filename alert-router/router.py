import os, requests, json, re
from flask import Flask, request

app = Flask(__name__)

WEBHOOK_HIGH = os.environ.get("SLACK_WEBHOOK_HIGH")
WEBHOOK_MEDIUM = os.environ.get("SLACK_WEBHOOK_MEDIUM")
WEBHOOK_WARNINGS = os.environ.get("SLACK_WEBHOOK_WARNINGS")

def parse_fields(output):
    proc = re.search(r'proc(?:ess)?=([^\s|]+)', output)
    cmd = re.search(r'command=([^\s|]+(?:\s[^\s|]+)*)', output)
    f = re.search(r'file=([^\s|]+)', output)
    cn = re.search(r'container_name=([^\s|]+)', output)
    return {
        "proc": proc.group(1) if proc else "N/A",
        "cmd": cmd.group(1) if cmd else "N/A",
        "file": f.group(1) if f else "N/A",
        "container": cn.group(1) if cn else "Host"
    }

@app.route('/alert', methods=['POST'])
def receive_alert():
    data = request.json or {}
    output = data.get("output", "")
    rule = data.get("rule", "Unknown")
    priority = data.get("priority", "Notice").capitalize()
    source = data.get("source", "")

    if priority in ["Emergency", "Alert", "Critical"]:
        severity, webhook, color = "HIGH", WEBHOOK_HIGH, "#f5222d"
    elif priority in ["Error", "Warning"]:
        severity, webhook, color = "MEDIUM", WEBHOOK_MEDIUM, "#fa8c16"
    else:
        severity, webhook, color = "WARNING", WEBHOOK_WARNINGS, "#1890ff"

    print(f"[ROUTER] {priority} -> {severity} | {rule} | source={source or 'falco'}", flush=True)

    meta = parse_fields(output)
    slack_msg = {
        "attachments": [{
            "color": color,
            "blocks": [
                {"type": "header", "text": {"type": "plain_text", "text": f"Security Alert: {rule}"}},
                {"type": "section", "fields": [
                    {"type": "mrkdwn", "text": f"*Severity:*\n{severity} ({priority})"},
                    {"type": "mrkdwn", "text": f"*Container:*\n`{meta['container']}`"},
                    {"type": "mrkdwn", "text": f"*Process:*\n`{meta['proc']}`"},
                    {"type": "mrkdwn", "text": f"*Target:*\n`{meta['file']}`"}
                ]},
                {"type": "section", "text": {"type": "mrkdwn", "text": f"*Raw Log:*\n```{output[:2800]}```"}}
            ]
        }]
    }

    if webhook:
        try:
            r = requests.post(webhook, json=slack_msg, timeout=5)
            print(f"[ROUTER] Slack response: {r.status_code}", flush=True)
        except Exception as e:
            print(f"[ROUTER] Slack error: {e}", flush=True)
    else:
        print(f"[SIMULATED] No webhook for {severity}", flush=True)

    # Forward all Falco alerts to the UI
    try:
        requests.post("http://prototype-app:5000/ingest-log", json=data, timeout=2)
    except:
        pass

    return "ok", 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
