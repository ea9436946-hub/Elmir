import json
import logging
import os
import platform
import subprocess
from datetime import datetime
from threading import Thread

from flask import Flask, jsonify, render_template_string, request, Response

try:
    from flask_socketio import SocketIO
    HAS_SOCKETIO = True
except ImportError:
    HAS_SOCKETIO = False

try:
    from prometheus_client import Counter, Gauge, generate_latest, CONTENT_TYPE_LATEST
    HAS_PROMETHEUS = True
    _events_total = Counter("elmir_events_total", "Total events", ["severity"])
    _alerts_total = Counter("elmir_alerts_total", "Total alerts", ["severity"])
    _open_alerts  = Gauge("elmir_open_alerts", "Open alerts")
except ImportError:
    HAS_PROMETHEUS = False

logger = logging.getLogger(__name__)


def _sysinfo() -> dict:
    info = {}
    try:
        with open("/proc/meminfo") as f:
            mem = {l.split(":")[0].strip(): int(l.split(":")[1].strip().split()[0])
                   for l in f if ":" in l}
        total = mem.get("MemTotal", 0)
        avail = mem.get("MemAvailable", 0)
        used  = total - avail
        info["ram"] = {"total_mb": total//1024, "used_mb": used//1024,
                       "free_mb": avail//1024, "pct": round(used/total*100, 1) if total else 0}
    except Exception:
        info["ram"] = {}
    try:
        with open("/proc/loadavg") as f:
            la = f.read().split()
        info["load"] = {"1m": float(la[0]), "5m": float(la[1]), "15m": float(la[2])}
    except Exception:
        info["load"] = {}
    try:
        import shutil
        disk = shutil.disk_usage("/")
        info["disk"] = {"total_gb": round(disk.total/1e9, 1),
                        "used_gb":  round(disk.used/1e9, 1),
                        "free_gb":  round(disk.free/1e9, 1),
                        "pct":      round(disk.used/disk.total*100, 1)}
    except Exception:
        info["disk"] = {}
    try:
        with open("/proc/stat") as f:
            line = f.readline()
        vals = list(map(int, line.split()[1:]))
        idle = vals[3]
        total = sum(vals)
        info["cpu"] = {"cores": os.cpu_count() or 1,
                       "model": platform.processor() or "unknown",
                       "idle_pct": round(idle/total*100, 1) if total else 0}
    except Exception:
        info["cpu"] = {}
    try:
        with open("/proc/net/if_inet6", "r") as _: pass
        r = subprocess.check_output(["ip", "-s", "link"], text=True, timeout=3)
        info["network_raw"] = r[:500]
    except Exception:
        info["network_raw"] = ""
    try:
        with open("/proc/uptime") as f:
            up = float(f.read().split()[0])
        d, rem = divmod(int(up), 86400)
        h, rem = divmod(rem, 3600)
        m = rem // 60
        info["uptime"] = f"{d}d {h}h {m}m"
    except Exception:
        info["uptime"] = "?"
    info["hostname"] = platform.node()
    info["os"] = platform.platform()
    return info


_HTML = r"""<!DOCTYPE html>
<html lang="de">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Elmir SIEM</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
:root{--bg:#080d18;--card:#0c1526;--border:#1a3050;--text:#c9d1d9;--muted:#475569;--blue:#38bdf8;--green:#22c55e;--red:#ef4444;--yellow:#f59e0b;--purple:#a78bfa}
body{font-family:'Segoe UI',sans-serif;background:var(--bg);color:var(--text);min-height:100vh}
/* HEADER */
header{background:#080f1e;border-bottom:1px solid var(--border);padding:12px 24px;display:flex;align-items:center;gap:12px;position:sticky;top:0;z-index:100}
header h1{font-size:1.2rem;color:var(--blue);font-weight:700;letter-spacing:.5px}
.dot{width:9px;height:9px;border-radius:50%;background:var(--green);animation:pulse 2s infinite;flex-shrink:0}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.25}}
.hdr-r{margin-left:auto;display:flex;gap:16px;align-items:center;font-size:.78rem;color:var(--muted)}
/* LAYOUT */
main{padding:18px 22px;max-width:1600px;margin:0 auto}
/* STAT CARDS */
.stats{display:grid;grid-template-columns:repeat(6,1fr);gap:12px;margin-bottom:18px}
.sc{background:var(--card);border:1px solid var(--border);border-radius:10px;padding:16px 18px}
.sc .v{font-size:1.9rem;font-weight:800}
.sc .l{font-size:.7rem;color:var(--muted);text-transform:uppercase;letter-spacing:.5px;margin-top:3px}
.cb{color:var(--blue)}.cr{color:var(--red)}.cy{color:var(--yellow)}.cg{color:var(--green)}.cp{color:var(--purple)}.cm{color:#64748b}
/* PANELS */
.panel{background:var(--card);border:1px solid var(--border);border-radius:10px;overflow:hidden}
.ph{padding:11px 16px;font-size:.82rem;font-weight:600;color:#94a3b8;border-bottom:1px solid var(--border);display:flex;justify-content:space-between;align-items:center}
/* GRID LAYOUTS */
.row{display:grid;gap:14px;margin-bottom:14px}
.r3{grid-template-columns:1.6fr 1fr 1fr}
.r2{grid-template-columns:2fr 1fr}
.r2b{grid-template-columns:1fr 1fr}
/* WORLD MAP */
#worldmap{width:100%;display:block;background:#060d1a;border-radius:0 0 8px 8px}
.map-dot{cursor:pointer;transition:r .2s}
.map-dot:hover{r:7}
.map-tooltip{position:fixed;background:#1a3050;color:#c9d1d9;padding:5px 10px;border-radius:6px;font-size:.75rem;pointer-events:none;z-index:999;display:none;border:1px solid var(--border)}
/* ALERTS FEED */
.feed{max-height:240px;overflow-y:auto}
.fi{padding:9px 14px;border-bottom:1px solid #0f1c2e;display:flex;gap:10px;align-items:flex-start}
.fi:last-child{border-bottom:none}
.fi-time{font-size:.7rem;color:var(--muted);white-space:nowrap;padding-top:2px;min-width:56px}
.fi-body{flex:1;font-size:.8rem;line-height:1.4}
.fi-desc{color:#7f8ea3;font-size:.73rem;margin-top:2px}
/* TABLE */
table{width:100%;border-collapse:collapse;font-size:.78rem}
th{text-align:left;padding:8px 12px;color:var(--muted);font-weight:500;background:#06101d;border-bottom:1px solid var(--border);font-size:.7rem;text-transform:uppercase}
td{padding:8px 12px;border-bottom:1px solid #0d1a2a;max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
tr:hover td{background:#0d1a2a}
/* BADGES */
.sev{display:inline-block;padding:1px 7px;border-radius:10px;font-size:.68rem;font-weight:700}
.sev-CRITICAL{background:#7f1d1d;color:#fca5a5}
.sev-HIGH{background:#78350f;color:#fcd34d}
.sev-MEDIUM,.sev-WARNING,.sev-ERROR{background:#1e3a5f;color:#7dd3fc}
.sev-INFO,.sev-LOW,.sev-syslog{background:#1a2e1a;color:#86efac}
.empty{padding:24px;text-align:center;color:var(--muted);font-size:.82rem}
/* SYSTEM INFO */
.si-grid{display:grid;grid-template-columns:1fr 1fr;gap:0}
.si-row{padding:9px 14px;border-bottom:1px solid #0d1a2a;display:flex;flex-direction:column;gap:3px}
.si-row:nth-child(odd){border-right:1px solid #0d1a2a}
.si-label{font-size:.68rem;color:var(--muted);text-transform:uppercase}
.si-val{font-size:.88rem;font-weight:600}
.bar-bg{height:5px;background:#1a2e1a;border-radius:3px;margin-top:4px;overflow:hidden}
.bar-fg{height:100%;border-radius:3px;transition:width .6s}
/* CHART */
.chart-wrap{padding:12px 16px 8px}
.bars{display:flex;align-items:flex-end;gap:2px;height:70px}
.b{flex:1;min-width:3px;border-radius:2px 2px 0 0;background:#1e4976;position:relative;cursor:default;transition:background .2s}
.b:hover{background:var(--blue)}
.b:hover::after{content:attr(data-tip);position:absolute;bottom:110%;left:50%;transform:translateX(-50%);background:#1a3050;color:var(--text);padding:3px 8px;border-radius:4px;font-size:.68rem;white-space:nowrap;pointer-events:none;border:1px solid var(--border)}
.chart-labels{display:flex;justify-content:space-between;font-size:.62rem;color:#2a4060;margin-top:4px}
/* TOP IPs */
.ip-row{display:flex;align-items:center;gap:8px;padding:7px 14px;border-bottom:1px solid #0d1a2a}
.ip-row:last-child{border-bottom:none}
.ip-n{font-family:monospace;font-size:.78rem;color:#94a3b8;flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis}
.ip-bar{height:4px;background:#1e4976;border-radius:2px}
.ip-c{font-size:.74rem;color:var(--muted);min-width:28px;text-align:right}
/* PAGINATION */
.pagi{padding:8px 14px;display:flex;gap:8px;align-items:center;border-top:1px solid var(--border)}
.btn{background:none;border:1px solid var(--border);color:var(--muted);padding:3px 10px;border-radius:5px;cursor:pointer;font-size:.75rem}
.btn:hover{border-color:var(--blue);color:var(--blue)}
input[type=text]{background:#06101d;border:1px solid var(--border);color:var(--text);padding:4px 10px;border-radius:6px;font-size:.75rem;width:150px}
select{background:#06101d;border:1px solid var(--border);color:var(--text);padding:4px 8px;border-radius:6px;font-size:.75rem}
.controls{display:flex;gap:7px;align-items:center}
.new-flash{animation:flash .8s ease}
@keyframes flash{0%{background:#1a3050}100%{background:transparent}}
@media(max-width:1200px){.stats{grid-template-columns:repeat(3,1fr)}.r3,.r2,.r2b{grid-template-columns:1fr}}
</style>
</head>
<body>
<div class="map-tooltip" id="tip"></div>
<header>
  <div class="dot" id="dot"></div>
  <h1>&#x1F6E1; Elmir SIEM</h1>
  <div class="hdr-r">
    <span id="conn-st">Verbinde...</span>
    <span id="ts">—</span>
  </div>
</header>
<main>

<!-- STAT CARDS -->
<div class="stats">
  <div class="sc"><div class="v cb" id="s-ev">—</div><div class="l">Events gesamt</div></div>
  <div class="sc"><div class="v cr" id="s-al">—</div><div class="l">Alerts gesamt</div></div>
  <div class="sc"><div class="v cy" id="s-op">—</div><div class="l">Offen</div></div>
  <div class="sc"><div class="v cr" id="s-cr">—</div><div class="l">Kritisch</div></div>
  <div class="sc"><div class="v cg" id="s-hr">—</div><div class="l">Events/Stunde</div></div>
  <div class="sc"><div class="v cm" id="s-ip">—</div><div class="l">Quell-IPs</div></div>
</div>

<!-- ROW 1: Weltkarte + System Info -->
<div class="row r2" style="margin-bottom:14px">
  <div class="panel">
    <div class="ph">&#x1F30D; Angriffs-Weltkarte <span id="map-count" style="color:var(--muted);font-weight:400"></span></div>
    <svg id="worldmap" viewBox="0 0 900 440" xmlns="http://www.w3.org/2000/svg">
      <!-- Simplified continents -->
      <!-- North America -->
      <path d="M60,60 L200,55 L230,100 L220,180 L190,200 L160,210 L130,250 L100,260 L80,230 L60,180 Z" fill="#0d1f35" stroke="#1a3050" stroke-width=".8"/>
      <!-- South America -->
      <path d="M140,265 L200,260 L230,290 L240,360 L220,410 L190,430 L160,420 L140,390 L130,340 L125,290 Z" fill="#0d1f35" stroke="#1a3050" stroke-width=".8"/>
      <!-- Europe -->
      <path d="M380,50 L460,45 L480,70 L470,110 L440,120 L410,115 L385,100 L375,75 Z" fill="#0d1f35" stroke="#1a3050" stroke-width=".8"/>
      <!-- Africa -->
      <path d="M390,130 L460,125 L490,160 L500,230 L490,310 L460,350 L420,360 L390,340 L370,290 L365,210 L375,160 Z" fill="#0d1f35" stroke="#1a3050" stroke-width=".8"/>
      <!-- Asia -->
      <path d="M470,40 L700,35 L740,70 L760,120 L730,160 L680,180 L620,175 L570,160 L520,150 L480,120 L465,80 Z" fill="#0d1f35" stroke="#1a3050" stroke-width=".8"/>
      <!-- Russia/North Asia -->
      <path d="M470,35 L750,30 L780,60 L770,100 L730,110 L700,100 L650,90 L600,80 L550,70 L500,65 L470,55 Z" fill="#0d1f35" stroke="#1a3050" stroke-width=".8"/>
      <!-- Australia -->
      <path d="M680,280 L780,275 L800,310 L800,360 L770,390 L720,395 L680,375 L660,340 L660,300 Z" fill="#0d1f35" stroke="#1a3050" stroke-width=".8"/>
      <!-- Grid lines -->
      <line x1="0" y1="220" x2="900" y2="220" stroke="#0f1c2e" stroke-width=".5"/>
      <line x1="450" y1="0" x2="450" y2="440" stroke="#0f1c2e" stroke-width=".5"/>
      <!-- Attack dots will be added by JS -->
      <g id="map-dots"></g>
    </svg>
  </div>

  <div class="panel">
    <div class="ph">&#x1F4BB; System-Info</div>
    <div class="si-grid" id="sysinfo-grid">
      <div class="si-row"><div class="si-label">Hostname</div><div class="si-val" id="si-host">—</div></div>
      <div class="si-row"><div class="si-label">Uptime</div><div class="si-val" id="si-up">—</div></div>
      <div class="si-row" style="grid-column:1/-1">
        <div class="si-label">RAM</div>
        <div class="si-val" id="si-ram">—</div>
        <div class="bar-bg"><div class="bar-fg" id="si-ram-bar" style="background:var(--blue);width:0%"></div></div>
      </div>
      <div class="si-row" style="grid-column:1/-1">
        <div class="si-label">Disk (/)</div>
        <div class="si-val" id="si-disk">—</div>
        <div class="bar-bg"><div class="bar-fg" id="si-disk-bar" style="background:var(--purple);width:0%"></div></div>
      </div>
      <div class="si-row"><div class="si-label">CPU Kerne</div><div class="si-val" id="si-cpu">—</div></div>
      <div class="si-row"><div class="si-label">Load (1m)</div><div class="si-val" id="si-load">—</div></div>
      <div class="si-row" style="grid-column:1/-1"><div class="si-label">OS</div><div class="si-val" id="si-os" style="font-size:.72rem;font-weight:400;color:#7f8ea3;white-space:nowrap;overflow:hidden;text-overflow:ellipsis">—</div></div>
    </div>
  </div>
</div>

<!-- ROW 2: Chart + Alert Feed -->
<div class="row r2b" style="margin-bottom:14px">
  <div class="panel">
    <div class="ph">&#x1F4CA; Ereignisverlauf 24h</div>
    <div class="chart-wrap">
      <div class="bars" id="bars"></div>
      <div class="chart-labels"><span id="cl-from"></span><span>jetzt</span></div>
    </div>
  </div>
  <div class="panel">
    <div class="ph">&#x1F514; Top Quell-IPs
      <span id="al-badge" style="background:var(--red);color:#fff;font-size:.65rem;padding:1px 7px;border-radius:10px;display:none">NEU</span>
    </div>
    <div id="top-ips"><div class="empty">Keine Daten</div></div>
  </div>
</div>

<!-- ROW 3: Live Alerts -->
<div class="panel" style="margin-bottom:14px">
  <div class="ph">&#x26A0; Live Alert-Feed</div>
  <div class="feed" id="feed"><div class="empty">Keine Alerts</div></div>
</div>

<!-- ROW 4: Events Table -->
<div class="panel">
  <div class="ph">&#x1F50D; Events
    <div class="controls">
      <input type="text" id="q" placeholder="Suche..." oninput="debSearch()">
      <select id="sf" onchange="goPage(1)">
        <option value="">Alle</option>
        <option value="CRITICAL">Kritisch</option>
        <option value="HIGH">Hoch</option>
        <option value="MEDIUM">Mittel</option>
        <option value="WARNING">Warning</option>
        <option value="INFO">Info</option>
      </select>
      <span class="btn" onclick="goPage(page)">↻</span>
    </div>
  </div>
  <div id="ev-body"><div class="empty">Lade...</div></div>
  <div class="pagi">
    <button class="btn" onclick="goPage(page-1)">← Zurück</button>
    <span id="pi" style="font-size:.75rem;color:var(--muted)"></span>
    <button class="btn" onclick="goPage(page+1)">Weiter →</button>
  </div>
</div>

</main>
<script>
// ── state ──────────────────────────────────────────────────────────────────
let page=1, totalPages=1, searchTimer=null;
const geoCache={};

// ── helpers ────────────────────────────────────────────────────────────────
const sev=s=>`<span class="sev sev-${s||'INFO'}">${s||'INFO'}</span>`;
const fmt=t=>t?(t.slice(0,10)+' '+t.slice(11,19)):'-';
const td=(v,t='')=>`<td title="${v||''}" ${t?`style="${t}"`:''} >${v||'—'}</td>`;

// ── geo lookup (ip-api.com, free, no key) ─────────────────────────────────
async function geoIP(ip){
  if(!ip||ip.startsWith('127.')||ip.startsWith('192.')||ip.startsWith('10.')||ip==='::1') return null;
  if(geoCache[ip]) return geoCache[ip];
  try{
    const r=await fetch(`http://ip-api.com/json/${ip}?fields=lat,lon,country,city,status`,{signal:AbortSignal.timeout(3000)});
    const d=await r.json();
    if(d.status==='success'){geoCache[ip]=d;return d;}
  }catch(e){}
  geoCache[ip]=null; return null;
}

// ── world map (equirectangular projection) ────────────────────────────────
function latLonToXY(lat,lon){
  // SVG viewBox 0 0 900 440
  const x=(lon+180)/360*900;
  const y=(90-lat)/180*440;
  return[x,y];
}

const SEV_COLORS={CRITICAL:'#ef4444',HIGH:'#f59e0b',MEDIUM:'#38bdf8',INFO:'#22c55e',LOW:'#22c55e'};

async function plotIP(ip, sev){
  const g=await geoIP(ip);
  if(!g) return;
  const[x,y]=latLonToXY(g.lat,g.lon);
  const color=SEV_COLORS[sev]||'#94a3b8';
  const dots=document.getElementById('map-dots');
  const circle=document.createElementNS('http://www.w3.org/2000/svg','circle');
  circle.setAttribute('cx',x.toFixed(1));
  circle.setAttribute('cy',y.toFixed(1));
  circle.setAttribute('r','5');
  circle.setAttribute('fill',color);
  circle.setAttribute('fill-opacity','0.8');
  circle.setAttribute('stroke','#fff');
  circle.setAttribute('stroke-width','0.8');
  circle.setAttribute('class','map-dot');
  circle.setAttribute('data-ip',ip);
  circle.setAttribute('data-loc',`${g.city||''}, ${g.country||''}`);
  // Pulse ring
  const ring=document.createElementNS('http://www.w3.org/2000/svg','circle');
  ring.setAttribute('cx',x.toFixed(1));
  ring.setAttribute('cy',y.toFixed(1));
  ring.setAttribute('r','5');
  ring.setAttribute('fill','none');
  ring.setAttribute('stroke',color);
  ring.setAttribute('stroke-width','1.5');
  ring.setAttribute('opacity','0');
  const anim=document.createElementNS('http://www.w3.org/2000/svg','animate');
  anim.setAttribute('attributeName','r'); anim.setAttribute('from','5'); anim.setAttribute('to','18');
  anim.setAttribute('dur','2s'); anim.setAttribute('repeatCount','indefinite');
  const anim2=document.createElementNS('http://www.w3.org/2000/svg','animate');
  anim2.setAttribute('attributeName','opacity'); anim2.setAttribute('from','0.6'); anim2.setAttribute('to','0');
  anim2.setAttribute('dur','2s'); anim2.setAttribute('repeatCount','indefinite');
  ring.appendChild(anim); ring.appendChild(anim2);
  dots.appendChild(ring); dots.appendChild(circle);
  // Tooltip
  const tip=document.getElementById('tip');
  circle.addEventListener('mouseenter',e=>{
    tip.textContent=`${ip} — ${g.city||'?'}, ${g.country||'?'}`;
    tip.style.display='block';
  });
  circle.addEventListener('mousemove',e=>{
    tip.style.left=(e.clientX+12)+'px'; tip.style.top=(e.clientY-28)+'px';
  });
  circle.addEventListener('mouseleave',()=>tip.style.display='none');
}

async function updateMap(topIPs){
  // Clear existing dots
  document.getElementById('map-dots').innerHTML='';
  let count=0;
  for(const {ip,sev:s} of topIPs){
    await plotIP(ip,s);
    count++;
  }
  document.getElementById('map-count').textContent=count?`(${count} IPs)`:'';
}

// ── stats ─────────────────────────────────────────────────────────────────
async function loadStats(){
  const d=await fetch('/api/v2/stats').then(r=>r.json()).catch(()=>null);
  if(!d) return;
  document.getElementById('s-ev').textContent=d.total_events?.toLocaleString()||'0';
  document.getElementById('s-al').textContent=d.total_alerts?.toLocaleString()||'0';
  document.getElementById('s-op').textContent=d.open_alerts?.toLocaleString()||'0';
  document.getElementById('s-cr').textContent=(d.severity_counts?.CRITICAL||0).toLocaleString();
  document.getElementById('s-hr').textContent=(d.events_last_hour||0).toLocaleString();
  document.getElementById('s-ip').textContent=(d.top_ips?.length||0).toLocaleString();
  document.getElementById('ts').textContent='Stand: '+new Date().toLocaleTimeString('de-DE');

  // Chart
  const tl=d.timeline||[];
  const max=Math.max(1,...tl.map(x=>x.count));
  document.getElementById('bars').innerHTML=tl.map(x=>{
    const h=Math.max(3,Math.round((x.count/max)*66));
    const col=x.count>max*.7?'#ef4444':x.count>max*.4?'#f59e0b':'#1e4976';
    return`<div class="b" style="height:${h}px;background:${col}" data-tip="${(x.hour||'').slice(11,16)}: ${x.count}"></div>`;
  }).join('');
  if(tl[0]) document.getElementById('cl-from').textContent=(tl[0].hour||'').slice(11,16);

  // Top IPs list
  const ips=d.top_ips||[];
  const maxc=ips[0]?.count||1;
  document.getElementById('top-ips').innerHTML=ips.length?ips.map(x=>`
    <div class="ip-row">
      <div class="ip-n">${x.ip}</div>
      <div class="ip-bar" style="width:${Math.round((x.count/maxc)*100)}px"></div>
      <div class="ip-c">${x.count}</div>
    </div>`).join(''):'<div class="empty">Keine Daten</div>';

  // Map
  const mapIPs=ips.slice(0,20).map(x=>({ip:x.ip,sev:'HIGH'}));
  updateMap(mapIPs);
}

// ── sysinfo ───────────────────────────────────────────────────────────────
async function loadSysinfo(){
  const d=await fetch('/api/sysinfo').then(r=>r.json()).catch(()=>null);
  if(!d) return;
  document.getElementById('si-host').textContent=d.hostname||'?';
  document.getElementById('si-up').textContent=d.uptime||'?';
  document.getElementById('si-os').textContent=d.os||'?';
  if(d.ram?.total_mb){
    document.getElementById('si-ram').textContent=
      `${d.ram.used_mb?.toLocaleString()} / ${d.ram.total_mb?.toLocaleString()} MB (${d.ram.pct}%)`;
    document.getElementById('si-ram-bar').style.width=d.ram.pct+'%';
    document.getElementById('si-ram-bar').style.background=d.ram.pct>85?'var(--red)':d.ram.pct>65?'var(--yellow)':'var(--blue)';
  }
  if(d.disk?.total_gb){
    document.getElementById('si-disk').textContent=
      `${d.disk.used_gb} / ${d.disk.total_gb} GB (${d.disk.pct}%)`;
    document.getElementById('si-disk-bar').style.width=d.disk.pct+'%';
    document.getElementById('si-disk-bar').style.background=d.disk.pct>85?'var(--red)':d.disk.pct>65?'var(--yellow)':'var(--purple)';
  }
  if(d.cpu) document.getElementById('si-cpu').textContent=`${d.cpu.cores} Kern(e)`;
  if(d.load) document.getElementById('si-load').textContent=`${d.load['1m']} / ${d.load['5m']} / ${d.load['15m']}`;
}

// ── alert feed ────────────────────────────────────────────────────────────
async function loadFeed(){
  const d=await fetch('/api/alerts?limit=25').then(r=>r.json()).catch(()=>[]);
  const feed=document.getElementById('feed');
  if(!d.length){feed.innerHTML='<div class="empty">Keine Alerts</div>';return;}
  feed.innerHTML=d.map(a=>`
    <div class="fi">
      <div class="fi-time">${(a.timestamp||'').slice(11,19)}</div>
      <div class="fi-body">
        ${sev(a.severity)} <strong style="font-size:.8rem">${a.rule_name||'—'}</strong>
        ${a.source_ip?`<code style="font-size:.7rem;color:#64748b;margin-left:6px">${a.source_ip}</code>`:''}
        <div class="fi-desc">${(a.description||'').slice(0,120)}</div>
      </div>
      <button class="btn" onclick="ack(${a.id})" style="font-size:.68rem;padding:2px 7px">ACK</button>
    </div>`).join('');

  // Also plot alert IPs on map
  const alertIPs=d.filter(a=>a.source_ip).map(a=>({ip:a.source_ip,sev:a.severity}));
  if(alertIPs.length) updateMap(alertIPs.slice(0,15));
}

// ── events table ──────────────────────────────────────────────────────────
async function loadEvents(){
  const q=document.getElementById('q').value;
  const sf=document.getElementById('sf').value;
  const params=new URLSearchParams({page,limit:50});
  if(q) params.set('search',q);
  if(sf) params.set('severity',sf);
  const d=await fetch('/api/v2/events?'+params).then(r=>r.json()).catch(()=>null);
  if(!d){document.getElementById('ev-body').innerHTML='<div class="empty">Fehler</div>';return;}
  totalPages=d.pages||1;
  document.getElementById('pi').textContent=`Seite ${d.page} / ${totalPages} (${d.total?.toLocaleString()} Events)`;
  if(!d.items?.length){document.getElementById('ev-body').innerHTML='<div class="empty">Keine Events</div>';return;}
  document.getElementById('ev-body').innerHTML=
    '<table><tr><th>Zeit</th><th>Typ</th><th>Schwere</th><th>Quelle IP</th><th>Benutzer</th><th>Nachricht</th></tr>'+
    d.items.map(e=>`<tr>
      ${td(fmt(e.timestamp))}
      ${td(e.event_type)}
      <td>${sev(e.severity)}</td>
      ${td(e.source_ip)}
      ${td(e.username)}
      ${td(e.message)}
    </tr>`).join('')+'</table>';
}

async function ack(id){
  await fetch('/api/alerts/'+id+'/ack',{method:'POST'});
  loadFeed(); loadStats();
}

function goPage(p){
  if(p<1||p>totalPages) return;
  page=p; loadEvents();
}
function debSearch(){
  clearTimeout(searchTimer);
  searchTimer=setTimeout(()=>{page=1;loadEvents();},350);
}

// ── WebSocket ─────────────────────────────────────────────────────────────
if(typeof io!=='undefined'){
  const sock=io();
  sock.on('connect',()=>{
    document.getElementById('dot').style.background='var(--green)';
    document.getElementById('conn-st').textContent='Live (WebSocket)';
  });
  sock.on('disconnect',()=>{
    document.getElementById('dot').style.background='var(--red)';
    document.getElementById('conn-st').textContent='Getrennt';
  });
  sock.on('new_alert',a=>{
    const b=document.getElementById('al-badge');
    b.style.display='';
    setTimeout(()=>b.style.display='none',4000);
    loadFeed(); loadStats();
    if(a.source_ip) plotIP(a.source_ip, a.severity);
  });
} else {
  document.getElementById('conn-st').textContent='Polling (15s)';
}

// ── init + refresh ────────────────────────────────────────────────────────
async function refresh(){
  await Promise.all([loadStats(), loadFeed(), loadSysinfo()]);
  loadEvents();
}
refresh();
setInterval(refresh, 15000);
</script>
</body>
</html>"""


class WebDashboard:
    def __init__(self, config: dict, event_store):
        self.host = config.get("host", "0.0.0.0")
        self.port = config.get("port", 8081)
        self.event_store = event_store
        self.app = Flask(__name__)
        self.socketio = SocketIO(self.app, cors_allowed_origins="*", async_mode="gevent") if HAS_SOCKETIO else None
        self._register_routes()

    def push_alert(self, alert: dict):
        if self.socketio:
            self.socketio.emit("new_alert", alert)

    def record_event(self, event: dict):
        if HAS_PROMETHEUS:
            _events_total.labels(severity=event.get("severity", "INFO")).inc()

    def record_alert(self, alert: dict):
        if HAS_PROMETHEUS:
            _alerts_total.labels(severity=alert.get("severity", "INFO")).inc()

    def _register_routes(self):
        es = self.event_store
        app = self.app

        @app.route("/")
        def index():
            return render_template_string(_HTML)

        @app.route("/api/sysinfo")
        def api_sysinfo():
            return jsonify(_sysinfo())

        @app.route("/api/stats")
        def api_stats():
            return jsonify(es.get_stats())

        @app.route("/api/v2/stats")
        def api_v2_stats():
            stats = es.get_stats()
            timeline = es.get_timeline(hours=24)
            top_ips = es.get_top_ips(limit=15)
            events_last_hour = sum(b["count"] for b in timeline[-1:])
            return jsonify({**stats, "timeline": timeline, "top_ips": top_ips,
                            "events_last_hour": events_last_hour,
                            "generated_at": datetime.utcnow().isoformat()})

        @app.route("/api/events")
        def api_events():
            limit = min(int(request.args.get("limit", 100)), 500)
            sev = request.args.get("severity")
            return jsonify(es.get_recent_events(limit=limit, severity=sev))

        @app.route("/api/v2/events")
        def api_v2_events():
            p = max(1, int(request.args.get("page", 1)))
            lim = min(int(request.args.get("limit", 50)), 200)
            return jsonify(es.get_events_paginated(
                page=p, limit=lim,
                severity=request.args.get("severity") or None,
                ip=request.args.get("ip") or None,
                search=request.args.get("search") or None,
            ))

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
                return Response(generate_latest(), mimetype=CONTENT_TYPE_LATEST)

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
        logger.info("Dashboard: http://%s:%d  |  Metrics: /metrics", self.host, self.port)
