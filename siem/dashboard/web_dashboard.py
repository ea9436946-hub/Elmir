import logging
from datetime import datetime
from threading import Thread

from flask import Flask, jsonify, render_template_string, request

try:
    from flask_socketio import SocketIO
    HAS_SOCKETIO = True
except ImportError:
    HAS_SOCKETIO = False

try:
    from prometheus_client import Counter, Gauge, generate_latest, CONTENT_TYPE_LATEST
    HAS_PROMETHEUS = True
    _events_total = Counter("elmir_events_total", "Total events processed", ["severity"])
    _alerts_total = Counter("elmir_alerts_total", "Total alerts fired", ["severity"])
    _open_alerts = Gauge("elmir_open_alerts", "Currently open (unacknowledged) alerts")
except ImportError:
    HAS_PROMETHEUS = False

logger = logging.getLogger(__name__)

_HTML = """<!DOCTYPE html>
<html lang="de">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Elmir SIEM</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Segoe UI',sans-serif;background:#0a0e1a;color:#c9d1d9;min-height:100vh}
header{background:#0d1421;border-bottom:1px solid #1e3a5f;padding:14px 24px;display:flex;align-items:center;gap:12px}
header h1{font-size:1.25rem;color:#00b4d8;letter-spacing:.5px}
.live-dot{width:9px;height:9px;border-radius:50%;background:#22c55e;animation:pulse 2s infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.3}}
.hdr-right{margin-left:auto;display:flex;align-items:center;gap:14px;font-size:.8rem;color:#64748b}
main{padding:20px 24px;max-width:1500px;margin:0 auto}
.stats{display:grid;grid-template-columns:repeat(5,1fr);gap:14px;margin-bottom:22px}
.sc{background:#0d1421;border:1px solid #1e3a5f;border-radius:10px;padding:18px 20px}
.sc .val{font-size:2rem;font-weight:700}
.sc .lbl{font-size:.75rem;color:#64748b;margin-top:3px;text-transform:uppercase;letter-spacing:.5px}
.c-blue{color:#00b4d8}.c-red{color:#ef4444}.c-yellow{color:#f59e0b}.c-green{color:#22c55e}.c-gray{color:#64748b}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:18px;margin-bottom:18px}
.grid3{display:grid;grid-template-columns:2fr 1fr;gap:18px;margin-bottom:18px}
.panel{background:#0d1421;border:1px solid #1e3a5f;border-radius:10px;overflow:hidden}
.ph{padding:12px 16px;font-size:.85rem;font-weight:600;border-bottom:1px solid #1e3a5f;display:flex;justify-content:space-between;align-items:center;color:#94a3b8}
.ph .controls{display:flex;gap:8px;align-items:center}
input[type=text]{background:#060d1a;border:1px solid #1e3a5f;color:#c9d1d9;padding:4px 10px;border-radius:6px;font-size:.78rem;width:160px}
select{background:#060d1a;border:1px solid #1e3a5f;color:#c9d1d9;padding:4px 8px;border-radius:6px;font-size:.78rem}
table{width:100%;border-collapse:collapse;font-size:.8rem}
th{text-align:left;padding:8px 12px;color:#475569;font-weight:500;background:#080f1c;border-bottom:1px solid #1e3a5f;font-size:.72rem;text-transform:uppercase}
td{padding:9px 12px;border-bottom:1px solid #0f1c2e;max-width:220px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
tr:hover td{background:#0f1c2e}
.sev{display:inline-block;padding:2px 8px;border-radius:12px;font-size:.7rem;font-weight:700}
.sev-CRITICAL{background:#7f1d1d;color:#fca5a5}
.sev-HIGH{background:#78350f;color:#fcd34d}
.sev-MEDIUM,.sev-WARNING,.sev-ERROR{background:#1e3a5f;color:#7dd3fc}
.sev-INFO,.sev-LOW{background:#14532d;color:#86efac}
.empty{padding:28px;text-align:center;color:#334155;font-size:.85rem}
.ack{background:none;border:1px solid #1e3a5f;color:#475569;padding:2px 7px;border-radius:4px;cursor:pointer;font-size:.72rem}
.ack:hover{border-color:#00b4d8;color:#00b4d8}
.new-row{animation:flash .6s ease}
@keyframes flash{0%{background:#1e3a5f}100%{background:transparent}}
/* Chart */
.chart{padding:14px 16px}
.bar-wrap{display:flex;align-items:flex-end;gap:3px;height:80px}
.bar{flex:1;min-width:4px;background:#1e4976;border-radius:2px 2px 0 0;transition:height .3s;cursor:default;position:relative}
.bar:hover::after{content:attr(data-tip);position:absolute;bottom:105%;left:50%;transform:translateX(-50%);background:#1e3a5f;color:#c9d1d9;padding:3px 7px;border-radius:4px;font-size:.7rem;white-space:nowrap;pointer-events:none}
.bar-labels{display:flex;justify-content:space-between;color:#334155;font-size:.65rem;margin-top:4px}
/* Top IPs */
.ip-row{display:flex;align-items:center;gap:10px;padding:7px 16px;border-bottom:1px solid #0f1c2e}
.ip-row:last-child{border-bottom:none}
.ip-name{font-size:.8rem;flex:1;font-family:monospace;color:#94a3b8}
.ip-bar{height:5px;background:#1e4976;border-radius:2px;min-width:4px}
.ip-cnt{font-size:.78rem;color:#475569;width:32px;text-align:right}
/* Alert feed */
.feed{max-height:260px;overflow-y:auto}
.feed-item{padding:9px 14px;border-bottom:1px solid #0f1c2e;display:flex;gap:10px;align-items:flex-start}
.feed-item:last-child{border-bottom:none}
.feed-time{font-size:.72rem;color:#334155;white-space:nowrap;margin-top:2px}
.feed-body{flex:1;font-size:.8rem}
.feed-desc{color:#94a3b8;margin-top:2px;font-size:.75rem}
@media(max-width:1100px){.stats{grid-template-columns:repeat(3,1fr)}.grid,.grid3{grid-template-columns:1fr}}
</style>
</head>
<body>
<header>
  <div class="live-dot" id="dot"></div>
  <h1>&#x1F6E1; Elmir SIEM</h1>
  <div class="hdr-right">
    <span id="conn-status">Verbinde...</span>
    <span id="last-upd"></span>
  </div>
</header>
<main>
  <div class="stats">
    <div class="sc"><div class="val c-blue" id="s-events">—</div><div class="lbl">Events gesamt</div></div>
    <div class="sc"><div class="val c-red"  id="s-alerts">—</div><div class="lbl">Alerts gesamt</div></div>
    <div class="sc"><div class="val c-yellow" id="s-open">—</div><div class="lbl">Offen</div></div>
    <div class="sc"><div class="val c-red" id="s-critical">—</div><div class="lbl">Kritisch</div></div>
    <div class="sc"><div class="val c-green" id="s-hour">—</div><div class="lbl">Events/Stunde</div></div>
  </div>

  <div class="grid3">
    <div class="panel">
      <div class="ph">Ereignisverlauf (24h)</div>
      <div class="chart">
        <div class="bar-wrap" id="chart-bars"></div>
        <div class="bar-labels"><span id="chart-from"></span><span>jetzt</span></div>
      </div>
    </div>
    <div class="panel">
      <div class="ph">Top Quell-IPs</div>
      <div id="top-ips"><div class="empty">Keine Daten</div></div>
    </div>
  </div>

  <div class="panel" style="margin-bottom:18px">
    <div class="ph">Live Alert-Feed
      <span id="alert-badge" style="background:#ef4444;color:#fff;font-size:.7rem;padding:1px 8px;border-radius:10px;display:none">NEU</span>
    </div>
    <div class="feed" id="alert-feed"><div class="empty">Keine Alerts</div></div>
  </div>

  <div class="panel">
    <div class="ph">Events
      <div class="controls">
        <input type="text" id="search" placeholder="Suche..." oninput="loadEvents()">
        <select id="sev-filter" onchange="loadEvents()">
          <option value="">Alle</option>
          <option value="CRITICAL">Kritisch</option>
          <option value="HIGH">Hoch</option>
          <option value="MEDIUM">Mittel</option>
          <option value="INFO">Info</option>
        </select>
        <span style="cursor:pointer;color:#00b4d8" onclick="loadEvents()">↻</span>
      </div>
    </div>
    <div id="events-body"><div class="empty">Lade...</div></div>
    <div style="padding:8px 14px;display:flex;gap:8px;align-items:center;border-top:1px solid #1e3a5f">
      <button class="ack" onclick="prevPage()">← Zurück</button>
      <span id="page-info" style="font-size:.78rem;color:#475569"></span>
      <button class="ack" onclick="nextPage()">Weiter →</button>
    </div>
  </div>
</main>

<script>
let page=1,totalPages=1;
const sevOrder={CRITICAL:0,HIGH:1,MEDIUM:2,WARNING:2,ERROR:2,INFO:3,LOW:3};

function sevBadge(s){return`<span class="sev sev-${s||'INFO'}">${s||'INFO'}</span>`}
function fmt(ts){return ts?ts.slice(0,19).replace('T',' '):'-'}
function td(v,cls=''){return`<td class="${cls}" title="${v||''}">${v||'—'}</td>`}

async function loadStats(){
  const d=await fetch('/api/stats').then(r=>r.json()).catch(()=>null);
  if(!d)return;
  document.getElementById('s-events').textContent=d.total_events.toLocaleString();
  document.getElementById('s-alerts').textContent=d.total_alerts.toLocaleString();
  document.getElementById('s-open').textContent=d.open_alerts.toLocaleString();
  document.getElementById('s-critical').textContent=(d.severity_counts['CRITICAL']||0).toLocaleString();
  document.getElementById('last-upd').textContent='Stand: '+new Date().toLocaleTimeString('de-DE');
}

async function loadTimeline(){
  const d=await fetch('/api/v2/stats').then(r=>r.json()).catch(()=>null);
  if(!d||!d.timeline)return;
  const tl=d.timeline;
  const max=Math.max(1,...tl.map(x=>x.count));
  const bars=document.getElementById('chart-bars');
  bars.innerHTML=tl.map(x=>{
    const h=Math.max(4,Math.round((x.count/max)*76));
    return`<div class="bar" style="height:${h}px" data-tip="${x.hour?.slice(11,16)||'?'}: ${x.count} Events"></div>`;
  }).join('');
  if(tl.length){
    document.getElementById('chart-from').textContent=tl[0].hour?.slice(11,16)||'';
    const last=d.events_last_hour||0;
    document.getElementById('s-hour').textContent=last.toLocaleString();
  }
  // Top IPs
  if(d.top_ips&&d.top_ips.length){
    const maxc=d.top_ips[0].count||1;
    document.getElementById('top-ips').innerHTML=d.top_ips.map(x=>`
      <div class="ip-row">
        <div class="ip-name">${x.ip}</div>
        <div class="ip-bar" style="width:${Math.round((x.count/maxc)*120)}px"></div>
        <div class="ip-cnt">${x.count}</div>
      </div>`).join('');
  }
}

async function loadAlertFeed(){
  const d=await fetch('/api/alerts?limit=20').then(r=>r.json()).catch(()=>[]);
  const feed=document.getElementById('alert-feed');
  if(!d.length){feed.innerHTML='<div class="empty">Keine Alerts</div>';return;}
  feed.innerHTML=d.map(a=>`
    <div class="feed-item">
      <div class="feed-time">${fmt(a.timestamp)}</div>
      <div class="feed-body">
        ${sevBadge(a.severity)} <strong>${a.rule_name||'—'}</strong>
        ${a.source_ip?`<span style="color:#475569;font-size:.75rem;margin-left:6px">${a.source_ip}</span>`:''}
        <div class="feed-desc">${a.description||''}</div>
      </div>
      <button class="ack" onclick="ack(${a.id})">ACK</button>
    </div>`).join('');
}

async function loadEvents(){
  const search=document.getElementById('search').value;
  const sev=document.getElementById('sev-filter').value;
  const params=new URLSearchParams({page,limit:50});
  if(search)params.set('search',search);
  if(sev)params.set('severity',sev);
  const d=await fetch('/api/v2/events?'+params).then(r=>r.json()).catch(()=>null);
  if(!d){document.getElementById('events-body').innerHTML='<div class="empty">Fehler</div>';return;}
  totalPages=d.pages||1;
  document.getElementById('page-info').textContent=`Seite ${d.page} / ${totalPages} (${d.total} Events)`;
  if(!d.items.length){document.getElementById('events-body').innerHTML='<div class="empty">Keine Events</div>';return;}
  document.getElementById('events-body').innerHTML=
    '<table><tr><th>Zeit</th><th>Typ</th><th>Schwere</th><th>Quelle</th><th>Benutzer</th><th>Nachricht</th></tr>'+
    d.items.map(e=>`<tr>
      ${td(fmt(e.timestamp))}
      ${td(e.event_type)}
      <td>${sevBadge(e.severity)}</td>
      ${td(e.source_ip)}
      ${td(e.username)}
      ${td(e.message)}
    </tr>`).join('')+'</table>';
}

async function ack(id){
  await fetch('/api/alerts/'+id+'/ack',{method:'POST'});
  loadAlertFeed();loadStats();
}

function prevPage(){if(page>1){page--;loadEvents();}}
function nextPage(){if(page<totalPages){page++;loadEvents();}}

// WebSocket (optional)
if(typeof io!=='undefined'){
  const socket=io();
  socket.on('connect',()=>{
    document.getElementById('dot').style.background='#22c55e';
    document.getElementById('conn-status').textContent='Live (WebSocket)';
  });
  socket.on('disconnect',()=>{
    document.getElementById('dot').style.background='#ef4444';
    document.getElementById('conn-status').textContent='Getrennt';
  });
  socket.on('new_alert',alert=>{
    document.getElementById('alert-badge').style.display='';
    setTimeout(()=>document.getElementById('alert-badge').style.display='none',5000);
    loadAlertFeed();loadStats();
  });
} else {
  document.getElementById('conn-status').textContent='Polling (15s)';
}

async function refresh(){
  await Promise.all([loadStats(),loadTimeline(),loadAlertFeed(),loadEvents()]);
}
refresh();
setInterval(refresh,15000);
</script>
</body>
</html>"""


class WebDashboard:
    def __init__(self, config: dict, event_store):
        self.host = config.get("host", "0.0.0.0")
        self.port = config.get("port", 8080)
        self.event_store = event_store
        self.app = Flask(__name__)
        self.socketio = SocketIO(self.app, cors_allowed_origins="*", async_mode="gevent") if HAS_SOCKETIO else None
        self._register_routes()

    def push_alert(self, alert: dict):
        if self.socketio:
            self.socketio.emit("new_alert", alert)

    def _register_routes(self):
        es = self.event_store
        app = self.app

        @app.route("/")
        def index():
            return render_template_string(_HTML)

        @app.route("/api/stats")
        def api_stats():
            return jsonify(es.get_stats())

        @app.route("/api/v2/stats")
        def api_v2_stats():
            stats = es.get_stats()
            timeline = es.get_timeline(hours=24)
            top_ips = es.get_top_ips(limit=10)
            events_last_hour = sum(b["count"] for b in timeline[-1:])
            return jsonify({
                **stats,
                "timeline": timeline,
                "top_ips": top_ips,
                "events_last_hour": events_last_hour,
                "generated_at": datetime.utcnow().isoformat(),
            })

        @app.route("/api/events")
        def api_events():
            limit = min(int(request.args.get("limit", 100)), 500)
            severity = request.args.get("severity")
            return jsonify(es.get_recent_events(limit=limit, severity=severity))

        @app.route("/api/v2/events")
        def api_v2_events():
            page = max(1, int(request.args.get("page", 1)))
            limit = min(int(request.args.get("limit", 50)), 200)
            severity = request.args.get("severity") or None
            ip = request.args.get("ip") or None
            search = request.args.get("search") or None
            return jsonify(es.get_events_paginated(page=page, limit=limit,
                                                    severity=severity, ip=ip, search=search))

        @app.route("/api/alerts")
        def api_alerts():
            limit = min(int(request.args.get("limit", 50)), 200)
            return jsonify(es.get_recent_alerts(limit=limit))

        @app.route("/api/alerts/<int:alert_id>/ack", methods=["POST"])
        def api_ack(alert_id):
            es.acknowledge_alert(alert_id)
            return jsonify({"ok": True})

        if HAS_PROMETHEUS:
            @app.route("/metrics")
            def metrics():
                from flask import Response
                return Response(generate_latest(), mimetype=CONTENT_TYPE_LATEST)

    def record_event(self, event: dict):
        if HAS_PROMETHEUS:
            _events_total.labels(severity=event.get("severity", "INFO")).inc()

    def record_alert(self, alert: dict):
        if HAS_PROMETHEUS:
            _alerts_total.labels(severity=alert.get("severity", "INFO")).inc()

    def start(self):
        if self.socketio:
            t = Thread(
                target=self.socketio.run,
                kwargs={"app": self.app, "host": self.host, "port": self.port,
                        "debug": False, "use_reloader": False, "log_output": False},
                daemon=True, name="dashboard",
            )
        else:
            t = Thread(
                target=self.app.run,
                kwargs={"host": self.host, "port": self.port,
                        "debug": False, "use_reloader": False},
                daemon=True, name="dashboard",
            )
        t.start()
        logger.info("Dashboard: http://%s:%d  |  Metrics: http://%s:%d/metrics",
                    self.host, self.port, self.host, self.port)
