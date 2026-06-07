import os, subprocess, queue, threading, json, datetime, csv, io
from flask import Flask, Response, request, stream_with_context, jsonify, send_file

try:
    import requests as req_lib
except ImportError:
    req_lib = None

app = Flask(__name__)
log_q = queue.Queue(maxsize=500)
log_history = []
all_logs = []
lock = threading.Lock()

def ts():
    return datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

def run_capture(cmd):
    """Run a command inside this container and capture output."""
    try:
        r = subprocess.run(cmd, shell=True, timeout=10, capture_output=True, text=True)
        out = r.stdout + r.stderr
        return {"output": out if out.strip() else "(no output)", "exit_code": r.returncode}
    except subprocess.TimeoutExpired:
        return {"output": "Error: Command timed out (10s)", "exit_code": -1}
    except Exception as e:
        return {"output": "Error: " + str(e), "exit_code": -1}

def push_to_ui(sev, rule, output, priority, tags=""):
    """Push an alert to the UI SSE stream. Used ONLY by /ingest-log (real Falco events)."""
    e = {"severity": sev, "rule": rule, "output": output,
         "priority": priority, "tags": tags, "time": ts()}
    with lock:
        log_history.append(e)
        if len(log_history) > 500:
            log_history.pop(0)
        all_logs.append(e)
        if len(all_logs) > 10000:
            all_logs.pop(0)
    try:
        log_q.put_nowait(e)
    except queue.Full:
        pass

# ── Falco ingest (ONLY source of real alerts) ────
@app.route('/ingest-log', methods=['POST'])
def ingest():
    """Receives real Falco alerts forwarded by alert-router."""
    d = request.json or {}
    p = d.get("priority", "Notice").lower()
    if p in ["emergency", "alert", "critical"]:
        sev = "HIGH"
    elif p in ["error", "warning"]:
        sev = "MEDIUM"
    else:
        sev = "WARNING"
    push_to_ui(sev, d.get("rule", "Unknown"), d.get("output", ""),
               d.get("priority", "Notice"), " ".join(d.get("tags", [])))
    return "ok", 200

# ── SSE stream for real-time UI ──────────────────
@app.route('/stream')
def stream():
    def gen():
        with lock:
            recent = list(log_history[-30:])
        for e in recent:
            yield "data: " + json.dumps(e) + "\n\n"
        while True:
            try:
                e = log_q.get(timeout=25)
                yield "data: " + json.dumps(e) + "\n\n"
            except queue.Empty:
                yield ": ping\n\n"
    return Response(stream_with_context(gen()), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

# ── Attack Simulator (runs REAL commands only) ───
# These run actual commands inside the container.
# Falco detects the syscalls via eBPF and fires alerts.
# No fake alerts are generated here.

@app.route('/trigger/spawn-shell', methods=['POST'])
def spawn_shell():
    return jsonify(run_capture("/bin/bash -c 'whoami && id && cat /etc/hostname'"))

@app.route('/trigger/write-binary', methods=['POST'])
def write_binary():
    return jsonify(run_capture("touch /usr/bin/evil-implant && rm -f /usr/bin/evil-implant"))

@app.route('/trigger/chmod-sensitive', methods=['POST'])
def chmod_sensitive():
    return jsonify(run_capture("chmod 644 /etc/passwd"))

@app.route('/trigger/nc-connect', methods=['POST'])
def nc_connect():
    return jsonify(run_capture("bash -c 'echo test | nc -w1 1.1.1.1 4444 2>&1 || true'"))

@app.route('/trigger/mkdir-bin', methods=['POST'])
def mkdir_bin():
    return jsonify(run_capture("mkdir -p /bin/evil-dir && rmdir /bin/evil-dir"))

@app.route('/trigger/overwrite-sudoers', methods=['POST'])
def overwrite_sudoers():
    return jsonify(run_capture("cat /etc/sudoers 2>&1 || echo 'sudoers not found'"))

@app.route('/trigger/read-shadow', methods=['POST'])
def read_shadow():
    return jsonify(run_capture("cat /etc/shadow"))

@app.route('/trigger/read-passwd', methods=['POST'])
def read_passwd():
    return jsonify(run_capture("cat /etc/passwd"))

@app.route('/trigger/pkgmgmt', methods=['POST'])
def pkgmgmt():
    return jsonify(run_capture("apt-get --version"))

@app.route('/trigger/cron-write', methods=['POST'])
def cron_write():
    return jsonify(run_capture("echo '* * * * * root id' > /tmp/evil_cron && cat /tmp/evil_cron && rm -f /tmp/evil_cron"))

@app.route('/trigger/ssh-keygen', methods=['POST'])
def ssh_keygen():
    return jsonify(run_capture("ssh-keygen -t rsa -N '' -f /tmp/testkey -q 2>&1; rm -f /tmp/testkey /tmp/testkey.pub"))

@app.route('/trigger/iptables', methods=['POST'])
def iptables():
    return jsonify(run_capture("iptables -L -n 2>&1 || echo 'iptables not available'"))

@app.route('/trigger/env-dump', methods=['POST'])
def env_dump():
    return jsonify(run_capture("env"))

@app.route('/trigger/list-proc', methods=['POST'])
def list_proc():
    return jsonify(run_capture("ps aux"))

@app.route('/trigger/read-hosts', methods=['POST'])
def read_hosts():
    return jsonify(run_capture("cat /etc/hosts"))

@app.route('/trigger/curl-external', methods=['POST'])
def curl_external():
    return jsonify(run_capture("curl -s --max-time 3 https://ifconfig.me || echo 'curl failed'"))

@app.route('/trigger/write-tmp', methods=['POST'])
def write_tmp():
    return jsonify(run_capture("echo '#!/bin/bash' > /tmp/payload.sh && chmod +x /tmp/payload.sh && ls -la /tmp/payload.sh && rm -f /tmp/payload.sh"))

@app.route('/trigger/net-scan', methods=['POST'])
def net_scan():
    return jsonify(run_capture("cat /proc/net/tcp"))

# ── Terminal — real execution, no fake alerts ─────
@app.route('/execute', methods=['POST'])
def execute():
    d = request.json or {}
    cmd = d.get("cmd", "").strip()
    if not cmd:
        return jsonify({"output": "No command provided", "exit_code": -1})
    return jsonify(run_capture(cmd))

# ── Log Archive API ───────────────────────────────
@app.route('/api/logs', methods=['GET'])
def get_logs():
    severity = request.args.get("severity", "")
    time_range = request.args.get("range", "")
    fmt = request.args.get("format", "json")

    with lock:
        filtered = list(all_logs)

    if severity:
        sevs = [s.strip().upper() for s in severity.split(",")]
        filtered = [l for l in filtered if l.get("severity") in sevs]

    if time_range:
        now = datetime.datetime.utcnow()
        hours = {"1h": 1, "6h": 6, "24h": 24}.get(time_range)
        if hours:
            cutoff = (now - datetime.timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%SZ")
            filtered = [l for l in filtered if l.get("time", "") >= cutoff]

    if fmt == "csv":
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["Time", "Severity", "Priority", "Rule", "Output", "Tags"])
        for r in filtered:
            w.writerow([r.get("time",""), r.get("severity",""), r.get("priority",""),
                        r.get("rule",""), r.get("output",""), r.get("tags","")])
        return Response(buf.getvalue(), mimetype="text/csv",
                        headers={"Content-Disposition": "attachment; filename=sentinel_logs.csv"})

    return jsonify({"total": len(filtered), "logs": filtered})

# ── Serve UI ──────────────────────────────────────
@app.route('/')
def home():
    return send_file('index.html')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, threaded=True)
