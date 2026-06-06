import os
import json
import requests
from flask import Flask, request

app = Flask(__name__)

WEBHOOKS = {
    "HIGH": os.environ.get("SLACK_WEBHOOK_HIGH", ""),
    "MEDIUM": os.environ.get("SLACK_WEBHOOK_MEDIUM", ""),
    "WARNINGS": os.environ.get("SLACK_WEBHOOK_WARNINGS", "")
}

def map_priority(priority_str):
    priority = priority_str.lower()
    if priority in ["emergency", "alert", "critical"]:
        return "HIGH"
    elif priority in ["error", "warning"]:
        return "MEDIUM"
    else:
        return "WARNINGS"

@app.route('/alert', methods=['POST'])
def receive_alert():
    data = request.json
    if not data:
        return "No JSON payload", 400

    priority = data.get("priority", "Notice")
    rule = data.get("rule", "Unknown Rule")
    output = data.get("output", "No details")
    time_str = data.get("time", "Unknown time")

    severity = map_priority(priority)
    webhook_url = WEBHOOKS.get(severity)

    slack_msg = {
        "blocks": [
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*🚨 Falco Security Alert: {rule}*"
                }
            },
            {
                "type": "section",
                "fields": [
                    {
                        "type": "mrkdwn",
                        "text": f"*Priority:*\n`{priority}`"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Time:*\n`{time_str}`"
                    }
                ]
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Details:*\n`{output}`"
                }
            }
        ]
    }

    print(f"\n[ALERT ROUTER] Routing {priority} alert to channel: {severity}")
    if webhook_url:
        try:
            resp = requests.post(webhook_url, json=slack_msg)
            print(f"Slack API Response: {resp.status_code}")
        except Exception as e:
            print(f"Failed to send to Slack: {e}")
    else:
        print(f"[SIMULATED - NO WEBHOOK CONFIGURED FOR {severity}]")
        print(json.dumps(slack_msg, indent=2))

    return "OK", 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
