import logging
from threading import Thread
from flask import Flask, jsonify, render_template_string, request, abort

logger = logging.getLogger(__name__)

_HTML = """<!DOCTYPE html>
<html lang="de">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Elmir SIEM Dashboard</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: 'Segoe UI', sans-serif; background: #0d1117; color: #c9d1d9; min-height: 100vh; }
    header { background: #161b22; border-bottom: 1px solid #30363d; padding: 16px 24px;
             display: flex; align-items: center; gap: 12px; }
    header h1 { font-size: 1.3rem; color: #58a6ff; }
    .badge { background: #238636; color: #fff; font-size: 0.7rem; padding: 2px 8px;
             border-radius: 12px; font-weight: 600; }
    main { padding: 24px; max-width: 1400px; margin: 0 auto; }
    .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 16px; margin-bottom: 28px; }
    .stat-card { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 20px; text-align: center; }
    .stat-card .value { font-size: 2rem; font-weight: 700; color: #58a6ff; }
    .stat-card .label { font-size: 0.8rem; color: #8b949e; margin-top: 4px; }
    .grid2 { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }
    @media (max-width: 900px) { .grid2 { grid-template-columns: 1fr; } }
    .panel { background: #161b22; border: 1px solid #30363d; border-radius: 8px; overflow: hidden; }
    .panel-header { padding: 14px 18px; font-weight: 600; font-size: 0.95rem;
                    border-bottom: 1px solid #30363d; display: flex; justify-content: space-between; align-items: center; }
    .panel-header .refresh { font-size: 0.75rem; color: #8b949e; cursor: pointer; }
    table { width: 100%; border-collapse: collapse; font-size: 0.82rem; }
    th { text-align: left; padding: 10px 14px; color: #8b949e; font-weight: 500;
         background: #0d1117; border-bottom: 1px solid #30363d; }
    td { padding: 10px 14px; border-bottom: 1px solid #21262d; max-width: 280px;
         overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    tr:last-child td { border-bottom: none; }
    tr:hover td { background: #1c2128; }
    .sev { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 0.75rem; font-weight: 600; }
    .sev-INFO     { background: #1f6feb22; color: #58a6ff; border: 1px solid #1f6feb44; }
    .sev-WARNING  { background: #9e6a0322; color: #d29922; border: 1px solid #9e6a0344; }
    .sev-ERROR    { background: #da363322; color: #f85149; border: 1px solid #da363344; }
    .sev-HIGH     { background: #da363322; color: #f85149; border: 1px solid #da363344; }
    .sev-CRITICAL { background: #b71c1c44; color: #ff6b6b; border: 1px solid #b71c1c88; }
    .empty { padding: 32px; text-align: center; color: #8b949e; font-size: 0.85rem; }
    .ack-btn { background: none; border: 1px solid #30363d; color: #8b949e; padding: 3px 8px;
               border-radius: 4px; cursor: pointer; font-size: 0.75rem; }
    .ack-btn:hover { border-color: #58a6ff; color: #58a6ff; }
    footer { text-align: center; color: #30363d; font-size: 0.75rem; padding: 24px; }
  </style>
</head>
<body>
  <header>
    <h1>&#x1F6E1; Elmir SIEM</h1>
    <span class="badge">LIVE</span>
    <span style="margin-left:auto;color:#8b949e;font-size:0.8rem" id="last-update"></span>
  </header>
  <main>
    <div class="stats" id="stats-grid">
      <div class="stat-card"><div class="value" id="s-events">-</div><div class="label">Total Events</div></div>
      <div class="stat-card"><div class="value" id="s-alerts">-</div><div class="label">Total Alerts</div></div>
      <div class="stat-card"><div class="value" id="s-open" style="color:#f85149">-</div><div class="label">Open Alerts</div></div>
      <div class="stat-card"><div class="value" id="s-warn" style="color:#d29922">-</div><div class="label">Warnings</div></div>
      <div class="stat-card"><div class="value" id="s-err" style="color:#f85149">-</div><div class="label">Errors</div></div>
    </div>
    <div class="grid2">
      <div class="panel">
        <div class="panel-header">Recent Alerts <span class="refresh" onclick="loadAlerts()">&#x21BB; Refresh</span></div>
        <div id="alerts-body"><div class="empty">Loading…</div></div>
      </div>
      <div class="panel">
        <div class="panel-header">Recent Events <span class="refresh" onclick="loadEvents()">&#x21BB; Refresh</span></div>
        <div id="events-body"><div class="empty">Loading…</div></div>
      </div>
    </div>
  </main>
  <footer>Elmir SIEM &mdash; Security Information &amp; Event Management</footer>
<script>
function sev(s){return `<span class="sev sev-${s}">${s}</span>`}
function td(v){return `<td title="${v||''}">${v||'-'}</td>`}

async function loadStats(){
  const r = await fetch('/api/stats'); const d = await r.json();
  document.getElementById('s-events').textContent = d.total_events.toLocaleString();
  document.getElementById('s-alerts').textContent = d.total_alerts.toLocaleString();
  document.getElementById('s-open').textContent   = d.open_alerts.toLocaleString();
  document.getElementById('s-warn').textContent   = (d.severity_counts['WARNING']||0).toLocaleString();
  document.getElementById('s-err').textContent    = (d.severity_counts['ERROR']||0).toLocaleString();
  document.getElementById('last-update').textContent = 'Updated ' + new Date().toLocaleTimeString();
}

async function loadAlerts(){
  const r = await fetch('/api/alerts'); const d = await r.json();
  if(!d.length){document.getElementById('alerts-body').innerHTML='<div class="empty">No alerts yet</div>';return;}
  let h='<table><tr><th>Time</th><th>Severity</th><th>Rule</th><th>Source IP</th><th></th></tr>';
  d.forEach(a=>{
    h+=`<tr>${td(a.timestamp?.slice(0,19))}
        <td>${sev(a.severity)}</td>
        ${td(a.rule_name)}${td(a.source_ip)}
        <td><button class="ack-btn" onclick="ack(${a.id})">ACK</button></td></tr>`;
  });
  document.getElementById('alerts-body').innerHTML=h+'</table>';
}

async function loadEvents(){
  const r = await fetch('/api/events'); const d = await r.json();
  if(!d.length){document.getElementById('events-body').innerHTML='<div class="empty">No events yet</div>';return;}
  let h='<table><tr><th>Time</th><th>Sev</th><th>Type</th><th>Source IP</th><th>Message</th></tr>';
  d.forEach(e=>{
    h+=`<tr>${td(e.timestamp?.slice(0,19))}<td>${sev(e.severity||'INFO')}</td>
        ${td(e.event_type)}${td(e.source_ip)}${td(e.message)}</tr>`;
  });
  document.getElementById('events-body').innerHTML=h+'</table>';
}

async function ack(id){
  await fetch('/api/alerts/'+id+'/ack', {method:'POST'});
  loadAlerts(); loadStats();
}

function refresh(){ loadStats(); loadAlerts(); loadEvents(); }
refresh();
setInterval(refresh, 15000);
</script>
</body>
</html>"""


class WebDashboard:
    def __init__(self, config: dict, event_store):
        self.host = config.get("host", "0.0.0.0")
        self.port = config.get("port", 8080)
        self.event_store = event_store
        self.app = Flask(__name__)
        self._register_routes()

    def _register_routes(self):
        es = self.event_store
        app = self.app

        @app.route("/")
        def index():
            return render_template_string(_HTML)

        @app.route("/api/stats")
        def api_stats():
            return jsonify(es.get_stats())

        @app.route("/api/events")
        def api_events():
            limit = min(int(request.args.get("limit", 100)), 500)
            return jsonify(es.get_recent_events(limit=limit))

        @app.route("/api/alerts")
        def api_alerts():
            limit = min(int(request.args.get("limit", 50)), 200)
            return jsonify(es.get_recent_alerts(limit=limit))

        @app.route("/api/alerts/<int:alert_id>/ack", methods=["POST"])
        def api_ack(alert_id):
            es.acknowledge_alert(alert_id)
            return jsonify({"ok": True})

    def start(self):
        t = Thread(
            target=self.app.run,
            kwargs={"host": self.host, "port": self.port, "debug": False, "use_reloader": False},
            daemon=True,
            name="dashboard",
        )
        t.start()
        logger.info("Dashboard available at http://%s:%d", self.host, self.port)
