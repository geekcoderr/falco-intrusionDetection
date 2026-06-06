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

def run(cmd):
    try:
        subprocess.run(cmd, shell=True, timeout=5,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except:
        pass

def run_capture(cmd):
    try:
        r = subprocess.run(cmd, shell=True, timeout=10, capture_output=True, text=True)
        out = r.stdout + r.stderr
        return {"output": out if out.strip() else "(no output)", "exit_code": r.returncode}
    except subprocess.TimeoutExpired:
        return {"output": "Error: Command timed out (10s)", "exit_code": -1}
    except Exception as e:
        return {"output": "Error: " + str(e), "exit_code": -1}

def push_to_ui(sev, rule, output, priority, tags=""):
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

def trigger_alert(sev, rule, output, priority):
    push_to_ui(sev, rule, output, priority)
    if req_lib:
        try:
            req_lib.post("http://alert-router:8080/alert",
                         json={"priority": priority, "rule": rule,
                               "output": output, "source": "simulator"},
                         timeout=2)
        except:
            pass

@app.route('/ingest-log', methods=['POST'])
def ingest():
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

# ── HIGH ──────────────────────────────────────────
@app.route('/trigger/spawn-shell', methods=['POST'])
def spawn_shell():
    run("/bin/bash -c 'id'")
    trigger_alert("HIGH", "Terminal shell spawned in container",
                  ts() + ": Critical Terminal shell spawned | proc=bash command=/bin/bash container_name=prototype-app", "Critical")
    return "ok"

@app.route('/trigger/write-binary', methods=['POST'])
def write_binary():
    run("touch /usr/bin/evil-implant && rm -f /usr/bin/evil-implant")
    trigger_alert("HIGH", "Write below binary dir",
                  ts() + ": Critical Write below binary dir | file=/usr/bin/evil-implant proc=touch command=touch container_name=prototype-app", "Critical")
    return "ok"

@app.route('/trigger/chmod-sensitive', methods=['POST'])
def chmod_sensitive():
    run("chmod 644 /etc/passwd")
    trigger_alert("HIGH", "chmod on sensitive file",
                  ts() + ": Alert chmod on sensitive file | file=/etc/passwd proc=chmod command=chmod container_name=prototype-app", "Alert")
    return "ok"

@app.route('/trigger/nc-connect', methods=['POST'])
def nc_connect():
    run("nc -w1 -z 1.1.1.1 4444")
    trigger_alert("HIGH", "Outbound reverse shell connection attempt",
                  ts() + ": Emergency Reverse shell activity | proc=nc command=nc container_name=prototype-app", "Emergency")
    return "ok"

@app.route('/trigger/mkdir-bin', methods=['POST'])
def mkdir_bin():
    run("mkdir -p /bin/evil-dir && rmdir /bin/evil-dir")
    trigger_alert("HIGH", "Directory created in sensitive path",
                  ts() + ": Critical mkdir in /bin | file=/bin/evil-dir proc=mkdir command=mkdir container_name=prototype-app", "Critical")
    return "ok"

@app.route('/trigger/overwrite-sudoers', methods=['POST'])
def overwrite_sudoers():
    trigger_alert("HIGH", "Modify sudoers file",
                  ts() + ": Critical sudoers modification | file=/etc/sudoers proc=sh command=sh container_name=prototype-app", "Critical")
    return "ok"

# ── MEDIUM ────────────────────────────────────────
@app.route('/trigger/read-shadow', methods=['POST'])
def read_shadow():
    run("cat /etc/shadow")
    trigger_alert("MEDIUM", "Read sensitive file untrusted",
                  ts() + ": Warning Sensitive file opened | file=/etc/shadow proc=cat command=cat container_name=prototype-app", "Warning")
    return "ok"

@app.route('/trigger/read-passwd', methods=['POST'])
def read_passwd():
    run("cat /etc/passwd")
    trigger_alert("MEDIUM", "Read sensitive file untrusted",
                  ts() + ": Warning Sensitive file opened | file=/etc/passwd proc=cat command=cat container_name=prototype-app", "Warning")
    return "ok"

@app.route('/trigger/pkgmgmt', methods=['POST'])
def pkgmgmt():
    trigger_alert("MEDIUM", "Package management launched in container",
                  ts() + ": Warning Package mgmt launched | proc=apt-get command=apt-get container_name=prototype-app", "Warning")
    return "ok"

@app.route('/trigger/cron-write', methods=['POST'])
def cron_write():
    run("echo '* * * * * root id' > /tmp/evil_cron && rm -f /tmp/evil_cron")
    trigger_alert("MEDIUM", "Cron persistence mechanism detected",
                  ts() + ": Warning Write to cron | file=/etc/cron.d/evil proc=sh command=sh container_name=prototype-app", "Warning")
    return "ok"

@app.route('/trigger/ssh-keygen', methods=['POST'])
def ssh_keygen():
    run("ssh-keygen -t rsa -N '' -f /tmp/testkey -q && rm -f /tmp/testkey /tmp/testkey.pub")
    trigger_alert("MEDIUM", "SSH keypair generated inside container",
                  ts() + ": Warning Credential generation | proc=ssh-keygen command=ssh-keygen container_name=prototype-app", "Warning")
    return "ok"

@app.route('/trigger/iptables', methods=['POST'])
def iptables():
    run("iptables -L -n 2>/dev/null")
    trigger_alert("MEDIUM", "Firewall rule enumeration detected",
                  ts() + ": Warning iptables used | proc=iptables command=iptables container_name=prototype-app", "Warning")
    return "ok"

# ── WARNING ───────────────────────────────────────
@app.route('/trigger/env-dump', methods=['POST'])
def env_dump():
    run("env")
    trigger_alert("WARNING", "Sensitive environment variable access",
                  ts() + ": Notice ENV read | proc=env command=env container_name=prototype-app", "Notice")
    return "ok"

@app.route('/trigger/list-proc', methods=['POST'])
def list_proc():
    run("ps aux")
    trigger_alert("WARNING", "Process enumeration detected",
                  ts() + ": Notice Process listing | proc=ps command=ps container_name=prototype-app", "Notice")
    return "ok"

@app.route('/trigger/read-hosts', methods=['POST'])
def read_hosts():
    run("cat /etc/hosts")
    trigger_alert("WARNING", "Network configuration file read",
                  ts() + ": Notice /etc/hosts opened | file=/etc/hosts proc=cat command=cat container_name=prototype-app", "Notice")
    return "ok"

@app.route('/trigger/curl-external', methods=['POST'])
def curl_external():
    run("curl -s --max-time 3 https://ifconfig.me -o /dev/null")
    trigger_alert("WARNING", "Outbound data exfiltration attempt",
                  ts() + ": Notice Outbound connection | proc=curl command=curl container_name=prototype-app", "Notice")
    return "ok"

@app.route('/trigger/write-tmp', methods=['POST'])
def write_tmp():
    run("echo '#!/bin/bash' > /tmp/payload.sh && chmod +x /tmp/payload.sh && rm -f /tmp/payload.sh")
    trigger_alert("WARNING", "Executable payload dropped in /tmp",
                  ts() + ": Notice Executable in /tmp | file=/tmp/payload.sh proc=sh command=sh container_name=prototype-app", "Notice")
    return "ok"

@app.route('/trigger/net-scan', methods=['POST'])
def net_scan():
    run("cat /proc/net/tcp")
    trigger_alert("WARNING", "Internal network reconnaissance",
                  ts() + ": Notice Network table read | file=/proc/net/tcp proc=cat command=cat container_name=prototype-app", "Notice")
    return "ok"

# ── Terminal & Logs API ───────────────────────────
def check_and_trigger_command_alert(cmd):
    cmd_lower = cmd.lower()
    
    # Check High Severity alerts
    if "nc " in cmd_lower or "netcat" in cmd_lower or "bash -i" in cmd_lower or "sh -i" in cmd_lower:
        trigger_alert("HIGH", "Outbound reverse shell connection attempt",
                      ts() + f": Emergency Reverse shell activity | proc=nc command={cmd} container_name=prototype-app", "Emergency")
    elif "chmod" in cmd_lower and ("/etc/passwd" in cmd_lower or "/etc/shadow" in cmd_lower or "passwd" in cmd_lower or "shadow" in cmd_lower):
        trigger_alert("HIGH", "chmod on sensitive file",
                      ts() + f": Alert chmod on sensitive file | file=/etc/passwd proc=chmod command={cmd} container_name=prototype-app", "Alert")
    elif ("touch" in cmd_lower or "echo" in cmd_lower or "mv" in cmd_lower) and ("/usr/bin" in cmd_lower or "/bin" in cmd_lower or "/usr/sbin" in cmd_lower or "/sbin" in cmd_lower):
        trigger_alert("HIGH", "Write below binary dir",
                      ts() + f": Critical Write below binary dir | file=/usr/bin/evil-implant proc=touch command={cmd} container_name=prototype-app", "Critical")
    elif "mkdir" in cmd_lower and ("/bin" in cmd_lower or "/usr/bin" in cmd_lower or "/sbin" in cmd_lower or "/usr/sbin" in cmd_lower):
        trigger_alert("HIGH", "Directory created in sensitive path",
                      ts() + f": Critical mkdir in /bin | file=/bin/evil-dir proc=mkdir command={cmd} container_name=prototype-app", "Critical")
    elif "sudoers" in cmd_lower:
        trigger_alert("HIGH", "Modify sudoers file",
                      ts() + f": Critical sudoers modification | file=/etc/sudoers proc=sh command={cmd} container_name=prototype-app", "Critical")
    elif "/bin/bash" in cmd_lower or "/bin/sh" in cmd_lower or "spawn" in cmd_lower:
        trigger_alert("HIGH", "Terminal shell spawned in container",
                      ts() + f": Critical Terminal shell spawned | proc=bash command={cmd} container_name=prototype-app", "Critical")
                      
    # Check Medium Severity alerts
    elif "shadow" in cmd_lower:
        trigger_alert("MEDIUM", "Read sensitive file untrusted",
                      ts() + f": Warning Sensitive file opened | file=/etc/shadow proc=cat command={cmd} container_name=prototype-app", "Warning")
    elif "passwd" in cmd_lower:
        trigger_alert("MEDIUM", "Read sensitive file untrusted",
                      ts() + f": Warning Sensitive file opened | file=/etc/passwd proc=cat command={cmd} container_name=prototype-app", "Warning")
    elif "apt-get" in cmd_lower or "apt " in cmd_lower or "dpkg" in cmd_lower or "yum" in cmd_lower or "rpm" in cmd_lower:
        trigger_alert("MEDIUM", "Package management launched in container",
                      ts() + f": Warning Package mgmt launched | proc=apt command={cmd} container_name=prototype-app", "Warning")
    elif "cron" in cmd_lower or "/etc/cron" in cmd_lower:
        trigger_alert("MEDIUM", "Cron persistence mechanism detected",
                      ts() + f": Warning Write to cron | file=/etc/cron.d/evil proc=sh command={cmd} container_name=prototype-app", "Warning")
    elif "ssh-keygen" in cmd_lower:
        trigger_alert("MEDIUM", "SSH keypair generated inside container",
                      ts() + f": Warning Credential generation | proc=ssh-keygen command={cmd} container_name=prototype-app", "Warning")
    elif "iptables" in cmd_lower:
        trigger_alert("MEDIUM", "Firewall rule enumeration detected",
                      ts() + f": Warning iptables used | proc=iptables command={cmd} container_name=prototype-app", "Warning")
                      
    # Check Warnings
    elif "env" in cmd_lower:
        trigger_alert("WARNING", "Sensitive environment variable access",
                      ts() + f": Notice ENV read | proc=env command={cmd} container_name=prototype-app", "Notice")
    elif "ps " in cmd_lower or "top" in cmd_lower or "htop" in cmd_lower:
        trigger_alert("WARNING", "Process enumeration detected",
                      ts() + f": Notice Process listing | proc=ps command={cmd} container_name=prototype-app", "Notice")
    elif "hosts" in cmd_lower:
        trigger_alert("WARNING", "Network configuration file read",
                      ts() + f": Notice /etc/hosts opened | file=/etc/hosts proc=cat command={cmd} container_name=prototype-app", "Notice")
    elif "curl" in cmd_lower or "wget" in cmd_lower:
        trigger_alert("WARNING", "Outbound data exfiltration attempt",
                      ts() + f": Notice Outbound connection | proc=curl command={cmd} container_name=prototype-app", "Notice")
    elif "/tmp/" in cmd_lower:
        trigger_alert("WARNING", "Executable payload dropped in /tmp",
                      ts() + f": Notice Executable in /tmp | file=/tmp/payload.sh proc=sh command={cmd} container_name=prototype-app", "Notice")
    elif "tcp" in cmd_lower or "udp" in cmd_lower or "netstat" in cmd_lower or "ss" in cmd_lower:
        trigger_alert("WARNING", "Internal network reconnaissance",
                      ts() + f": Notice Network table read | file=/proc/net/tcp proc=cat command={cmd} container_name=prototype-app", "Notice")
    else:
        # Default benign execution log
        push_to_ui("WARNING", "Custom command executed",
                   ts() + f": Notice Custom command | proc=sh command={cmd} container_name=prototype-app", "Notice")

@app.route('/execute', methods=['POST'])
def execute():
    d = request.json or {}
    cmd = d.get("cmd", "").strip()
    if not cmd:
        return jsonify({"output": "No command provided", "exit_code": -1})
    result = run_capture(cmd)
    check_and_trigger_command_alert(cmd)
    return jsonify(result)

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
