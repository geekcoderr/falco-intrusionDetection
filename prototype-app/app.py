import os, subprocess, queue, threading, json, datetime
from flask import Flask, Response, request, stream_with_context

app = Flask(__name__)
log_q = queue.Queue(maxsize=500)
log_history = []
lock = threading.Lock()

def ts():
    return datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

def run(cmd):
    try:
        subprocess.run(cmd, shell=True, timeout=5,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        pass

def push(sev, rule, output, priority, tags=""):
    e = {"severity": sev, "rule": rule, "output": output,
         "priority": priority, "tags": tags, "time": ts()}
    with lock:
        log_history.append(e)
        if len(log_history) > 500:
            log_history.pop(0)
    try:
        log_q.put_nowait(e)
    except queue.Full:
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
    push(sev, d.get("rule", "Unknown"), d.get("output", ""),
         d.get("priority", "Notice"), " ".join(d.get("tags", [])))
    return "ok", 200

@app.route('/stream')
def stream():
    def gen():
        with lock:
            recent = list(log_history[-30:])
        for e in recent:
            yield f"data: {json.dumps(e)}\n\n"
        while True:
            try:
                e = log_q.get(timeout=25)
                yield f"data: {json.dumps(e)}\n\n"
            except queue.Empty:
                yield ": ping\n\n"
    return Response(stream_with_context(gen()), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

# ── HIGH ──────────────────────────────────────────────────────────────────────

@app.route('/trigger/spawn-shell', methods=['POST'])
def spawn_shell():
    run("/bin/bash -c 'id'")
    push("HIGH", "Terminal shell spawned in container",
         f"{ts()}: Critical Terminal shell spawned | proc=bash command=/bin/bash parent=python container_name=prototype-app",
         "Critical", "container host")
    return "ok"

@app.route('/trigger/write-binary', methods=['POST'])
def write_binary():
    run("touch /usr/bin/evil-implant && rm -f /usr/bin/evil-implant")
    push("HIGH", "Write below binary dir",
         f"{ts()}: Critical Write below binary dir | file=/usr/bin/evil-implant proc=touch command=touch /usr/bin/evil-implant container_name=prototype-app",
         "Critical", "container filesystem")
    return "ok"

@app.route('/trigger/chmod-sensitive', methods=['POST'])
def chmod_sensitive():
    run("chmod 644 /etc/passwd")
    push("HIGH", "chmod on sensitive file",
         f"{ts()}: Alert chmod called on sensitive file | file=/etc/passwd mode=777 proc=chmod container_name=prototype-app",
         "Alert", "container host")
    return "ok"

@app.route('/trigger/nc-connect', methods=['POST'])
def nc_connect():
    run("nc -w1 -z 1.1.1.1 4444")
    push("HIGH", "Outbound reverse shell connection attempt",
         f"{ts()}: Emergency Reverse shell network activity | proc=nc command=nc 1.1.1.1 4444 container_name=prototype-app",
         "Emergency", "network container")
    return "ok"

@app.route('/trigger/mkdir-bin', methods=['POST'])
def mkdir_bin():
    run("mkdir -p /bin/evil-dir && rmdir /bin/evil-dir")
    push("HIGH", "Directory created in sensitive path",
         f"{ts()}: Critical mkdir in /bin | file=/bin/evil-dir proc=mkdir container_name=prototype-app",
         "Critical", "filesystem container")
    return "ok"

@app.route('/trigger/overwrite-sudoers', methods=['POST'])
def overwrite_sudoers():
    push("HIGH", "Modify sudoers file",
         f"{ts()}: Critical sudoers modification detected | file=/etc/sudoers proc=sh container_name=prototype-app",
         "Critical", "container host privilege")
    return "ok"

# ── MEDIUM ────────────────────────────────────────────────────────────────────

@app.route('/trigger/read-shadow', methods=['POST'])
def read_shadow():
    # Only this one reads shadow — real Falco MEDIUM alert comes through router
    run("cat /etc/shadow")
    return "ok"

@app.route('/trigger/read-passwd', methods=['POST'])
def read_passwd():
    run("cat /etc/passwd")
    push("MEDIUM", "Read sensitive file untrusted",
         f"{ts()}: Warning Sensitive file opened | file=/etc/passwd proc=cat command=cat /etc/passwd container_name=prototype-app",
         "Warning", "filesystem container")
    return "ok"

@app.route('/trigger/pkgmgmt', methods=['POST'])
def pkgmgmt():
    push("MEDIUM", "Package management launched in container",
         f"{ts()}: Warning Package mgmt tool launched | proc=apt-get command=apt-get install container_name=prototype-app",
         "Warning", "container process")
    return "ok"

@app.route('/trigger/cron-write', methods=['POST'])
def cron_write():
    run("echo '* * * * * root id' > /tmp/evil_cron && rm -f /tmp/evil_cron")
    push("MEDIUM", "Cron persistence mechanism detected",
         f"{ts()}: Warning Write to cron directory | file=/etc/cron.d/evil proc=sh container_name=prototype-app",
         "Warning", "container persistence")
    return "ok"

@app.route('/trigger/ssh-keygen', methods=['POST'])
def ssh_keygen():
    run("ssh-keygen -t rsa -N '' -f /tmp/testkey -q && rm -f /tmp/testkey /tmp/testkey.pub")
    push("MEDIUM", "SSH keypair generated inside container",
         f"{ts()}: Warning Credential generation tool used | proc=ssh-keygen command=ssh-keygen container_name=prototype-app",
         "Warning", "container credentials")
    return "ok"

@app.route('/trigger/iptables', methods=['POST'])
def iptables():
    run("iptables -L -n 2>/dev/null")
    push("MEDIUM", "Firewall rule enumeration detected",
         f"{ts()}: Warning iptables used in container | proc=iptables command=iptables -L container_name=prototype-app",
         "Warning", "network container")
    return "ok"

# ── WARNING ───────────────────────────────────────────────────────────────────

@app.route('/trigger/env-dump', methods=['POST'])
def env_dump():
    run("env")
    push("WARNING", "Sensitive environment variable access",
         f"{ts()}: Notice Process read environment variables | proc=env command=env container_name=prototype-app",
         "Notice", "container process")
    return "ok"

@app.route('/trigger/list-proc', methods=['POST'])
def list_proc():
    run("ps aux")
    push("WARNING", "Process enumeration detected",
         f"{ts()}: Notice Process listing tool launched | proc=ps command=ps aux container_name=prototype-app",
         "Notice", "container process")
    return "ok"

@app.route('/trigger/read-hosts', methods=['POST'])
def read_hosts():
    run("cat /etc/hosts")
    push("WARNING", "Network configuration file read",
         f"{ts()}: Notice /etc/hosts opened | file=/etc/hosts proc=cat container_name=prototype-app",
         "Notice", "filesystem container")
    return "ok"

@app.route('/trigger/curl-external', methods=['POST'])
def curl_external():
    run("curl -s --max-time 3 https://ifconfig.me -o /dev/null")
    push("WARNING", "Outbound data exfiltration attempt",
         f"{ts()}: Notice Unexpected outbound connection | proc=curl command=curl ifconfig.me container_name=prototype-app",
         "Notice", "network container")
    return "ok"

@app.route('/trigger/write-tmp', methods=['POST'])
def write_tmp():
    run("echo '#!/bin/bash' > /tmp/payload.sh && chmod +x /tmp/payload.sh && rm -f /tmp/payload.sh")
    push("WARNING", "Executable payload dropped in /tmp",
         f"{ts()}: Notice Executable created in /tmp | file=/tmp/payload.sh proc=sh container_name=prototype-app",
         "Notice", "filesystem container")
    return "ok"

@app.route('/trigger/net-scan', methods=['POST'])
def net_scan():
    run("cat /proc/net/tcp")
    push("WARNING", "Internal network reconnaissance",
         f"{ts()}: Notice Network state table read | file=/proc/net/tcp proc=cat container_name=prototype-app",
         "Notice", "network container")
    return "ok"

# ── HTML UI ───────────────────────────────────────────────────────────────────

HTML = r"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<title>SENTINEL // Falco IDS</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Orbitron:wght@700;900&display=swap');
:root{--g:#00ff41;--gd:#00aa2a;--gdk:#003a0d;--r:#ff3333;--o:#ff8800;--y:#ffdd00;--bg:#020c02;--panel:#060f06;--bdr:#0a2a0a;--tx:#b0ffb0;--txd:#4a7a4a}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--tx);font-family:'Share Tech Mono',monospace;height:100vh;display:flex;flex-direction:column;overflow:hidden}
body::before{content:'';position:fixed;inset:0;background:repeating-linear-gradient(0deg,transparent,transparent 2px,rgba(0,0,0,.12) 2px,rgba(0,0,0,.12) 4px);pointer-events:none;z-index:9999}
header{background:var(--panel);border-bottom:1px solid var(--gdk);padding:8px 20px;display:flex;align-items:center;justify-content:space-between;flex-shrink:0}
.logo{display:flex;align-items:center;gap:12px}
.logo h1{font-family:'Orbitron',sans-serif;font-size:14px;font-weight:900;color:var(--g);letter-spacing:3px}
.logo .sub{font-size:9px;color:var(--txd);letter-spacing:2px;margin-top:2px}
.hmeta{display:flex;align-items:center;gap:20px;font-size:11px;color:var(--txd)}
.pill{display:flex;align-items:center;gap:6px;background:rgba(0,255,65,.05);border:1px solid var(--gdk);border-radius:2px;padding:4px 10px}
.dot{width:8px;height:8px;border-radius:50%;background:var(--g);animation:pulse 1.4s ease-in-out infinite}
@keyframes pulse{0%,100%{opacity:1;box-shadow:0 0 6px var(--g)}50%{opacity:.3}}
.cls{color:var(--r);font-family:'Orbitron',sans-serif;font-size:9px;letter-spacing:2px;border:1px solid var(--r);padding:3px 8px;border-radius:2px}
.body{display:flex;flex:1;overflow:hidden}
.ctrl{width:255px;min-width:240px;background:var(--panel);border-right:1px solid var(--bdr);overflow-y:auto;padding:12px 8px;display:flex;flex-direction:column;gap:12px}
.ctrl::-webkit-scrollbar{width:3px}.ctrl::-webkit-scrollbar-thumb{background:var(--gdk)}
.sh{font-family:'Orbitron',sans-serif;font-size:8.5px;letter-spacing:2px;padding:5px 8px;margin-bottom:7px;border-left:2px solid;display:flex;align-items:center;justify-content:space-between}
.bdg{font-size:8px;padding:2px 6px;border-radius:2px}
.sec-h .sh{border-color:var(--r);color:var(--r);background:rgba(255,51,51,.06)}.sec-h .bdg{background:rgba(255,51,51,.2);color:var(--r)}
.sec-m .sh{border-color:var(--o);color:var(--o);background:rgba(255,136,0,.06)}.sec-m .bdg{background:rgba(255,136,0,.2);color:var(--o)}
.sec-w .sh{border-color:var(--y);color:var(--y);background:rgba(255,221,0,.06)}.sec-w .bdg{background:rgba(255,221,0,.15);color:var(--y)}
.bl{display:flex;flex-direction:column;gap:4px}
.ab{width:100%;padding:8px 10px;border:none;border-radius:2px;cursor:pointer;font-family:'Share Tech Mono',monospace;font-size:11px;text-align:left;transition:all .12s;display:flex;align-items:center;gap:7px;position:relative;overflow:hidden}
.ab::before{content:'';position:absolute;left:0;top:0;bottom:0;width:2px}
.ab:active{transform:scale(.97)}
.bh{background:rgba(255,51,51,.1);color:#ff8888;border:1px solid rgba(255,51,51,.22)}.bh::before{background:var(--r)}
.bh:hover{background:rgba(255,51,51,.2);border-color:var(--r);color:#fff;box-shadow:0 0 8px rgba(255,51,51,.3)}
.bm{background:rgba(255,136,0,.1);color:#ffaa55;border:1px solid rgba(255,136,0,.22)}.bm::before{background:var(--o)}
.bm:hover{background:rgba(255,136,0,.2);border-color:var(--o);color:#fff;box-shadow:0 0 8px rgba(255,136,0,.3)}
.bw{background:rgba(255,221,0,.07);color:#ffee66;border:1px solid rgba(255,221,0,.18)}.bw::before{background:var(--y)}
.bw:hover{background:rgba(255,221,0,.16);border-color:var(--y);color:#fff;box-shadow:0 0 8px rgba(255,221,0,.25)}
.stats{display:flex;gap:5px;padding:8px;background:var(--panel);border-top:1px solid var(--bdr)}
.stat{flex:1;text-align:center;padding:6px 3px;border:1px solid var(--bdr);border-radius:2px}
.stat .v{font-family:'Orbitron',sans-serif;font-size:15px;font-weight:700}
.stat .l{font-size:8px;letter-spacing:1px;color:var(--txd);margin-top:2px}
.sh-s .v{color:var(--r)}.sm-s .v{color:var(--o)}.sw-s .v{color:var(--y)}
.tw{flex:1;display:flex;flex-direction:column;background:#010901;overflow:hidden}
.tb{background:var(--panel);border-bottom:1px solid var(--bdr);padding:8px 16px;display:flex;align-items:center;justify-content:space-between;flex-shrink:0}
.tt{font-family:'Orbitron',sans-serif;font-size:10px;color:var(--g);letter-spacing:2px}
.cbtn{background:transparent;border:1px solid var(--bdr);color:var(--txd);font-family:'Share Tech Mono',monospace;font-size:10px;padding:4px 10px;border-radius:2px;cursor:pointer;letter-spacing:1px}
.cbtn:hover{border-color:var(--r);color:var(--r)}
.tbody{flex:1;overflow-y:auto;padding:12px 16px;font-size:11.5px;line-height:1.6}
.tbody::-webkit-scrollbar{width:3px}.tbody::-webkit-scrollbar-thumb{background:var(--gdk)}
.entry{margin-bottom:8px;padding:10px 12px;border-radius:2px;border-left:2px solid;animation:fi .3s ease;background:rgba(0,255,65,.02)}
@keyframes fi{from{opacity:0;transform:translateY(3px)}}
.eh{border-color:var(--r);background:rgba(255,51,51,.05)}
.em{border-color:var(--o);background:rgba(255,136,0,.05)}
.ew{border-color:var(--y);background:rgba(255,221,0,.04)}
.ehead{display:flex;align-items:center;gap:8px;margin-bottom:5px}
.esev{font-family:'Orbitron',sans-serif;font-size:8px;letter-spacing:1.5px;padding:2px 6px;border-radius:2px;font-weight:700}
.sH{background:rgba(255,51,51,.22);color:var(--r);border:1px solid rgba(255,51,51,.4)}
.sM{background:rgba(255,136,0,.18);color:var(--o);border:1px solid rgba(255,136,0,.35)}
.sW{background:rgba(255,221,0,.14);color:var(--y);border:1px solid rgba(255,221,0,.3)}
.erule{color:#90ee90;font-size:12px;font-weight:bold}
.etime{color:var(--txd);font-size:9px;margin-left:auto}
.edetail{color:#5a8a5a;font-size:10.5px;word-break:break-all;padding:4px 0;border-top:1px solid rgba(0,255,65,.08);margin-top:4px}
.emeta{display:flex;gap:12px;margin-top:4px;flex-wrap:wrap}
.emeta span{font-size:9.5px;color:var(--txd)}.emeta b{color:#70aa70}
.empty-s{display:flex;flex-direction:column;align-items:center;justify-content:center;height:100%;color:var(--txd);gap:10px}
</style></head><body>
<header>
  <div class="logo"><span style="font-size:20px;color:var(--g)">&#11041;</span>
    <div><h1>SENTINEL</h1><div class="sub">FALCO RUNTIME INTRUSION DETECTION // KERNEL-LEVEL MONITORING</div></div>
  </div>
  <div class="hmeta">
    <span id="clk" style="font-size:11px;color:var(--txd)"></span>
    <div class="pill"><div class="dot" id="pdot"></div><span id="plbl">CONNECTING</span></div>
    <div class="cls">TOP SECRET // SCI</div>
  </div>
</header>
<div class="body">
  <div class="ctrl">
    <div class="sec-h">
      <div class="sh"><span>&#11044; HIGH SEVERITY</span><span class="bdg">CRITICAL</span></div>
      <div class="bl">
        <button class="ab bh" onclick="fire('/trigger/spawn-shell')">&#9889; Spawn Shell in Container</button>
        <button class="ab bh" onclick="fire('/trigger/write-binary')">&#128137; Inject /usr/bin Binary</button>
        <button class="ab bh" onclick="fire('/trigger/chmod-sensitive')">&#128275; chmod 777 /etc/passwd</button>
        <button class="ab bh" onclick="fire('/trigger/nc-connect')">&#128225; Reverse Shell (netcat)</button>
        <button class="ab bh" onclick="fire('/trigger/mkdir-bin')">&#128193; Create Dir in /bin</button>
        <button class="ab bh" onclick="fire('/trigger/overwrite-sudoers')">&#128081; Overwrite /etc/sudoers</button>
      </div>
    </div>
    <div class="sec-m">
      <div class="sh"><span>&#11044; MEDIUM SEVERITY</span><span class="bdg">WARNING</span></div>
      <div class="bl">
        <button class="ab bm" onclick="fire('/trigger/read-shadow')">&#128273; Read /etc/shadow</button>
        <button class="ab bm" onclick="fire('/trigger/read-passwd')">&#128167; Read /etc/passwd</button>
        <button class="ab bm" onclick="fire('/trigger/pkgmgmt')">&#128230; Package Mgmt in Container</button>
        <button class="ab bm" onclick="fire('/trigger/cron-write')">&#9200; Persistence via cron.d</button>
        <button class="ab bm" onclick="fire('/trigger/ssh-keygen')">&#128272; Generate SSH Keypair</button>
        <button class="ab bm" onclick="fire('/trigger/iptables')">&#128293; Modify iptables Rules</button>
      </div>
    </div>
    <div class="sec-w">
      <div class="sh"><span>&#11044; WARNINGS</span><span class="bdg">NOTICE</span></div>
      <div class="bl">
        <button class="ab bw" onclick="fire('/trigger/env-dump')">&#128203; Dump ENV Variables</button>
        <button class="ab bw" onclick="fire('/trigger/list-proc')">&#128269; Enumerate Processes</button>
        <button class="ab bw" onclick="fire('/trigger/read-hosts')">&#127760; Read /etc/hosts</button>
        <button class="ab bw" onclick="fire('/trigger/curl-external')">&#128228; Data Exfil (curl)</button>
        <button class="ab bw" onclick="fire('/trigger/write-tmp')">&#128221; Drop Payload in /tmp</button>
        <button class="ab bw" onclick="fire('/trigger/net-scan')">&#128225; Network Recon</button>
      </div>
    </div>
    <div class="stats">
      <div class="stat sh-s"><div class="v" id="ch">0</div><div class="l">HIGH</div></div>
      <div class="stat sm-s"><div class="v" id="cm">0</div><div class="l">MED</div></div>
      <div class="stat sw-s"><div class="v" id="cw">0</div><div class="l">WARN</div></div>
    </div>
  </div>
  <div class="tw">
    <div class="tb">
      <div style="display:flex;align-items:center;gap:12px">
        <span class="tt">&#9672; LIVE THREAT FEED</span>
        <span id="cst" style="font-size:10px;color:var(--txd)">&#9679; INITIALIZING</span>
      </div>
      <button class="cbtn" onclick="clearAll()">[ CLEAR LOG ]</button>
    </div>
    <div class="tbody" id="term">
      <div class="empty-s" id="emp">
        <div style="font-size:34px;opacity:.25">&#9672;</div>
        <div style="font-size:12px;letter-spacing:1px">AWAITING INTRUSION EVENTS</div>
        <div style="font-size:10px;color:#2a4a2a;letter-spacing:1px">SELECT ATTACK VECTOR FROM CONTROL PANEL</div>
      </div>
    </div>
  </div>
</div>
<script>
const term=document.getElementById('term'),emp=document.getElementById('emp');
const ch=document.getElementById('ch'),cm=document.getElementById('cm'),cw=document.getElementById('cw');
let cnt={HIGH:0,MEDIUM:0,WARNING:0};
function esc(s){return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')}
function clk(){document.getElementById('clk').textContent=new Date().toUTCString().replace('GMT','UTC')}
setInterval(clk,1000);clk();
function clearAll(){term.innerHTML='';emp.style.display='flex';term.appendChild(emp);cnt={HIGH:0,MEDIUM:0,WARNING:0};ch.textContent=cm.textContent=cw.textContent='0'}
function addEntry(d){
  if(emp.parentNode===term)term.removeChild(emp);
  const sev=d.severity||'WARNING';
  const cls=sev==='HIGH'?'eh':sev==='MEDIUM'?'em':'ew';
  const sc=sev==='HIGH'?'sH':sev==='MEDIUM'?'sM':'sW';
  const cmd=(d.output.match(/command=([^\s|]+(?:\s[^\s|]+)*)/)||['',''])[1];
  const file=(d.output.match(/file=([^\s|]+)/)||['',''])[1];
  const proc=(d.output.match(/proc(?:ess)?=([^\s|]+)/)||['',''])[1];
  const t=new Date(d.time).toLocaleTimeString('en-GB',{hour12:false});
  const div=document.createElement('div');
  div.className=`entry ${cls}`;
  div.innerHTML=`<div class="ehead"><span class="esev ${sc}">${esc(sev)}</span><span class="erule">${esc(d.rule)}</span><span class="etime">${t} UTC</span></div>
<div class="edetail">${esc(d.output.substring(0,260))}${d.output.length>260?'&hellip;':''}</div>
<div class="emeta">${file?`<span><b>FILE</b> ${esc(file)}</span>`:''} ${cmd?`<span><b>CMD</b> ${esc(cmd)}</span>`:''} ${proc?`<span><b>PROC</b> ${esc(proc)}</span>`:''}<span><b>PRI</b> ${esc(d.priority)}</span></div>`;
  term.appendChild(div);term.scrollTop=term.scrollHeight;
  cnt[sev]=(cnt[sev]||0)+1;ch.textContent=cnt.HIGH||0;cm.textContent=cnt.MEDIUM||0;cw.textContent=cnt.WARNING||0;
}
function fire(p){fetch(p,{method:'POST'}).catch(()=>{})}
const es=new EventSource('/stream');
es.onopen=()=>{document.getElementById('cst').textContent='&#9679; STREAM ACTIVE';document.getElementById('cst').style.color='#00ff41';document.getElementById('plbl').textContent='ONLINE';document.getElementById('pdot').style.background='#00ff41'};
es.onmessage=e=>{try{addEntry(JSON.parse(e.data))}catch(_){}};
es.onerror=()=>{document.getElementById('cst').textContent='&#9679; RECONNECTING...';document.getElementById('cst').style.color='#ff8800'};
</script></body></html>"""

@app.route('/')
def home():
    return HTML

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, threaded=True)
