"""
SENTINEL BUSINESS - Dashboard Web
Centro di comando per PMI
"""
from flask import Flask, jsonify, request, render_template_string
import threading
import time
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

app = Flask(__name__)

DATA = {
    "stats": {"packets": 0, "devices": 0, "flows": 0, "threats": 0, "critical": 0, "high": 0, "medium": 0},
    "alerts": [],
    "devices": {},
    "chat": [],
    "office_devices": {},
    "status": "idle"
}

HTML = r"""<!DOCTYPE html>
<html lang="it">
<head>
<meta charset="utf-8">
<title>SENTINEL BUSINESS</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:#0a0e1a;color:#c8d6e5;font-family:'Segoe UI',system-ui,sans-serif;overflow-x:hidden}
.header{background:linear-gradient(135deg,#0a0e1a 0%,#1a1e3a 100%);padding:20px 30px;border-bottom:1px solid #1e2a4a;display:flex;justify-content:space-between;align-items:center}
.logo{font-size:1.5em;font-weight:700;color:#00d4ff}
.logo span{color:#ff4757;font-size:0.7em;margin-left:8px;padding:2px 8px;border:1px solid #ff4757;border-radius:4px}
.status{padding:6px 16px;border-radius:20px;font-size:0.85em;font-weight:600}
.status-active{background:#00d4ff22;color:#00d4ff;border:1px solid #00d4ff44}
.status-idle{background:#ffa50022;color:#ffa500;border:1px solid #ffa50044}
.main{display:grid;grid-template-columns:1fr 1fr;gap:20px;padding:20px 30px;max-width:1600px;margin:0 auto}
.full-width{grid-column:1/-1}
.cards{display:grid;grid-template-columns:repeat(4,1fr);gap:15px;grid-column:1/-1}
.card{background:#111827;border:1px solid #1e2a4a;border-radius:12px;padding:20px;text-align:center}
.card .value{font-size:2.2em;font-weight:700;color:#00d4ff}
.card .label{font-size:0.85em;color:#636e85;margin-top:4px}
.card.danger .value{color:#ff4757}
.card.warning .value{color:#ffa500}
.panel{background:#111827;border:1px solid #1e2a4a;border-radius:12px;padding:20px;max-height:500px;overflow-y:auto}
.panel h2{font-size:1.1em;color:#00d4ff;margin-bottom:15px;padding-bottom:8px;border-bottom:1px solid #1e2a4a}
.alert{padding:12px;margin:8px 0;border-radius:8px;border-left:4px solid}
.alert-CRITICO{background:#ff475711;border-color:#ff4757}
.alert-ALTO{background:#ffa50011;border-color:#ffa500}
.alert-MEDIO{background:#ffd32a11;border-color:#ffd32a}
.alert .sev{font-weight:700;font-size:0.8em;padding:2px 8px;border-radius:4px;display:inline-block;margin-bottom:6px}
.sev-CRITICO{background:#ff475733;color:#ff4757}
.sev-ALTO{background:#ffa50033;color:#ffa500}
.sev-MEDIO{background:#ffd32a33;color:#ffd32a}
.alert .type{font-weight:600;color:#fff;font-size:0.95em}
.alert .detail{font-size:0.82em;color:#8892a8;margin-top:4px}
.alert .malware{color:#ff4757;font-weight:600;font-size:0.82em}
.device-table{width:100%;border-collapse:collapse;font-size:0.85em}
.device-table th{text-align:left;color:#00d4ff;padding:8px;border-bottom:1px solid #1e2a4a}
.device-table td{padding:8px;border-bottom:1px solid #0d1117}
.device-table tr:hover{background:#1e2a4a33}
.threat-tag{font-size:0.75em;padding:1px 6px;border-radius:3px;background:#ff475733;color:#ff4757}
.safe-tag{font-size:0.75em;padding:1px 6px;border-radius:3px;background:#00d4ff22;color:#2ed573}
.chat-panel{display:flex;flex-direction:column;height:500px}
.chat-panel h2{flex-shrink:0}
.chat-messages{flex:1;overflow-y:auto;padding:10px 0}
.chat-msg{margin:6px 0;padding:8px 12px;border-radius:8px;font-size:0.85em;max-width:90%}
.msg-user{background:#00d4ff22;color:#00d4ff;margin-left:auto;text-align:right}
.msg-bot{background:#1e2a4a;color:#c8d6e5;white-space:pre-wrap}
.chat-input{display:flex;gap:8px;margin-top:10px;flex-shrink:0}
.chat-input input{flex:1;background:#0a0e1a;color:#c8d6e5;border:1px solid #1e2a4a;border-radius:8px;padding:10px 14px;font-size:0.9em;font-family:inherit}
.chat-input input:focus{outline:none;border-color:#00d4ff}
.chat-input button{background:#00d4ff;color:#0a0e1a;border:none;border-radius:8px;padding:10px 20px;font-weight:600;cursor:pointer;font-family:inherit}
.chat-input button:hover{background:#00b4d8}
.quick-btns{display:flex;gap:6px;flex-wrap:wrap;margin-bottom:10px;flex-shrink:0}
.qbtn{background:#1e2a4a;color:#8892a8;border:1px solid #2a3a5a;border-radius:6px;padding:6px 12px;cursor:pointer;font-size:0.78em;font-family:inherit}
.qbtn:hover{background:#00d4ff22;color:#00d4ff;border-color:#00d4ff44}
.nis2-bar{grid-column:1/-1;background:#111827;border:1px solid #1e2a4a;border-radius:12px;padding:15px 20px;display:flex;align-items:center;gap:20px}
.nis2-bar .nis2-label{color:#ffa500;font-weight:700;font-size:0.9em}
.nis2-bar .nis2-status{font-size:0.85em;color:#8892a8}
.nis2-bar .nis2-score{font-size:1.8em;font-weight:700;margin-left:auto}
.score-good{color:#2ed573}
.score-warn{color:#ffa500}
.score-bad{color:#ff4757}
</style>
</head>
<body>
<div class="header">
<div class="logo">SENTINEL BUSINESS <span>NIS2</span></div>
<div class="status status-idle" id="status">In attesa</div>
</div>

<div class="main">
<div class="cards">
<div class="card"><div class="value" id="c_pkt">0</div><div class="label">Pacchetti Analizzati</div></div>
<div class="card"><div class="value" id="c_dev">0</div><div class="label">Dispositivi in Rete</div></div>
<div class="card"><div class="value" id="c_flw">0</div><div class="label">Flussi di Rete</div></div>
<div class="card danger"><div class="value" id="c_thr">0</div><div class="label">Minacce Rilevate</div></div>
</div>

<div class="nis2-bar">
<div class="nis2-label">COMPLIANCE NIS2/GDPR</div>
<div class="nis2-status" id="nis2_text">Monitoraggio attivo. Report mensile disponibile.</div>
<div class="nis2-score score-good" id="nis2_score">--</div>
</div>

<div class="panel" id="alerts_panel">
<h2>Avvisi di Sicurezza</h2>
<div id="alerts_box">In attesa di dati...</div>
</div>

<div class="panel chat-panel">
<h2>Assistente AI</h2>
<div class="quick-btns">
<button class="qbtn" onclick="cmd('aiuto')">Aiuto</button>
<button class="qbtn" onclick="cmd('stato')">Stato Rete</button>
<button class="qbtn" onclick="cmd('minacce')">Minacce</button>
<button class="qbtn" onclick="cmd('dispositivi')">Dispositivi</button>
<button class="qbtn" onclick="cmd('report')">Report NIS2</button>
<button class="qbtn" onclick="cmd('scan')">Scansione</button>
</div>
<div class="chat-messages" id="chat"></div>
<form class="chat-input" id="cmdform">
<input type="text" id="inp" placeholder="Chiedi qualcosa... (es: analizza 192.168.1.11)" autocomplete="off">
<button type="submit">Invia</button>
</form>
</div>

<div class="panel full-width">
<h2>Mappa Dispositivi</h2>
<table class="device-table">
<thead><tr><th>IP</th><th>Nome</th><th>Tipo</th><th>Pacchetti</th><th>Bytes</th><th>Stato</th></tr></thead>
<tbody id="dev_table"></tbody>
</table>
</div>
</div>

<script>
document.getElementById('cmdform').addEventListener('submit',function(e){
    e.preventDefault();
    var inp=document.getElementById('inp');
    if(inp.value.trim()){cmd(inp.value.trim());inp.value='';}
});

function cmd(c){
    addChat(c,'msg-user');
    fetch('/api/command',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({command:c})})
    .then(function(r){return r.json()})
    .then(function(d){addChat(d.response,'msg-bot')})
    .catch(function(e){addChat('Errore di connessione','msg-bot')})
}

function addChat(text,cls){
    var chat=document.getElementById('chat');
    var div=document.createElement('div');
    div.className='chat-msg '+cls;
    div.textContent=text;
    chat.appendChild(div);
    chat.scrollTop=chat.scrollHeight;
}

function refresh(){
    fetch('/api/get_all')
    .then(function(r){return r.json()})
    .then(function(d){
        var s=d.stats;
        document.getElementById('c_pkt').textContent=s.packets||0;
        document.getElementById('c_dev').textContent=s.devices||0;
        document.getElementById('c_flw').textContent=s.flows||0;
        var thr=document.getElementById('c_thr');
        thr.textContent=s.threats||0;

        var st=document.getElementById('status');
        if(d.status==='running'){st.textContent='Monitoraggio Attivo';st.className='status status-active';}
        else if(d.status==='done'){st.textContent='Analisi Completata';st.className='status status-active';}

        var score=document.getElementById('nis2_score');
        var threats=s.threats||0;
        if(threats===0){score.textContent='A+';score.className='nis2-score score-good';}
        else if(threats<5){score.textContent='B';score.className='nis2-score score-warn';}
        else{score.textContent='F';score.className='nis2-score score-bad';}

        var ab=document.getElementById('alerts_box');
        if(!d.alerts||d.alerts.length===0){ab.innerHTML='<p style="color:#2ed573">Nessuna minaccia rilevata. Rete sicura.</p>';}
        else{
            var h='';
            for(var i=0;i<d.alerts.length;i++){
                var a=d.alerts[i];
                var sev=a.severity||'MEDIO';
                h+='<div class="alert alert-'+sev+'">';
                h+='<span class="sev sev-'+sev+'">'+sev+'</span> ';
                h+='<span class="type">'+a.type+'</span>';
                h+='<div class="detail">'+a.src+' &rarr; '+a.dst+':'+a.port+' | Confidenza: '+a.confidence+'%</div>';
                h+='<div class="detail">'+a.detail+'</div>';
                if(a.matched_malware){h+='<div class="malware">Malware: '+a.matched_malware+'</div>';}
                h+='</div>';
            }
            ab.innerHTML=h;
        }

        var dt=document.getElementById('dev_table');
        var dh='';
        var devs=d.devices||{};
        var office=d.office_devices||{};
        for(var ip in devs){
            var dev=devs[ip];
            var info=office[ip]||{};
            var name=info.name||'-';
            var type=info.type||'-';
            var has_threat=dev.threats&&dev.threats>0;
            var tag=has_threat?'<span class="threat-tag">'+dev.threats+' minacce</span>':'<span class="safe-tag">OK</span>';
            dh+='<tr><td>'+ip+'</td><td>'+name+'</td><td>'+type+'</td><td>'+(dev.packets||0)+'</td><td>'+(dev.bytes||0)+'</td><td>'+tag+'</td></tr>';
        }
        dt.innerHTML=dh;
    })
    .catch(function(e){})
}

setInterval(refresh,2000);
refresh();
addChat('Benvenuto in Sentinel Business. Sono il tuo assistente di sicurezza AI. Scrivi "aiuto" per i comandi disponibili.','msg-bot');
</script>
</body>
</html>"""


@app.route("/")
def index():
    return render_template_string(HTML)


@app.route("/api/get_all")
def api_get_all():
    return jsonify(DATA)


@app.route("/api/command", methods=["POST"])
def api_command():
    c = request.json.get("command", "")
    try:
        from agents.investigator import Investigator
        if not hasattr(api_command, "_inv"):
            api_command._inv = Investigator()
        api_command._inv.threats = DATA["alerts"]
        api_command._inv.devices = DATA["devices"]
        api_command._inv.office_map = DATA["office_devices"]
        api_command._inv.stats = DATA["stats"]
        resp = api_command._inv.process_command(c)
    except Exception as e:
        resp = "Errore: " + str(e)
    return jsonify({"ok": True, "response": resp})


@app.route("/api/update", methods=["POST"])
def api_update():
    d = request.json
    if "stats" in d:
        DATA["stats"].update(d["stats"])
    if "alerts" in d:
        DATA["alerts"] = d["alerts"]
    if "devices" in d:
        DATA["devices"] = d["devices"]
    if "office_devices" in d:
        DATA["office_devices"] = d["office_devices"]
    if "status" in d:
        DATA["status"] = d["status"]
    return jsonify({"ok": True})


def run_dashboard(port=8080):
    print(f"[DASHBOARD] http://localhost:{port}")
    app.run(host="0.0.0.0", port=port, debug=False, use_reloader=False)
