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

def push_to_ui(sev, rule, output, priority, tags=""):
    """Push a real Falco alert to the UI SSE stream."""
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

# ── Falco ingest (ONLY source of alerts) ─────────
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
            recent = list(log_history[-50:])
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

# ── Stats API for dashboard graphs ───────────────
@app.route('/api/stats', methods=['GET'])
def get_stats():
    with lock:
        logs = list(all_logs)
    total = len(logs)
    high = sum(1 for l in logs if l.get("severity") == "HIGH")
    medium = sum(1 for l in logs if l.get("severity") == "MEDIUM")
    warning = sum(1 for l in logs if l.get("severity") == "WARNING")

    # Rule frequency
    rule_counts = {}
    for l in logs:
        r = l.get("rule", "Unknown")
        rule_counts[r] = rule_counts.get(r, 0) + 1
    top_rules = sorted(rule_counts.items(), key=lambda x: -x[1])[:10]

    # Timeline (last 24h, bucketed by hour)
    now = datetime.datetime.utcnow()
    timeline = {}
    for i in range(24):
        h = (now - datetime.timedelta(hours=i)).strftime("%Y-%m-%dT%H:00:00Z")
        timeline[h] = {"HIGH": 0, "MEDIUM": 0, "WARNING": 0}
    for l in logs:
        t = l.get("time", "")
        if len(t) >= 13:
            bucket = t[:13] + ":00:00Z"
            if bucket in timeline:
                sev = l.get("severity", "WARNING")
                timeline[bucket][sev] = timeline[bucket].get(sev, 0) + 1

    sorted_timeline = sorted(timeline.items())

    return jsonify({
        "total": total, "high": high, "medium": medium, "warning": warning,
        "top_rules": [{"rule": r, "count": c} for r, c in top_rules],
        "timeline": [{"time": t, **v} for t, v in sorted_timeline]
    })

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
                        headers={"Content-Disposition": "attachment; filename=falco_alerts.csv"})

    return jsonify({"total": len(filtered), "logs": filtered})

# ── Serve UI ──────────────────────────────────────
@app.route('/')
def home():
    return send_file('index.html')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, threaded=True)
