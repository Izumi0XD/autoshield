"""
AutoShield AI — Fusion Console v2
Full rewrite: cinematic ops-center aesthetic, all 6 modules wired in.
Run: streamlit run dashboard.py
"""

import streamlit as st
import time
import json
import base64
import os
import requests
import pandas as pd
from datetime import datetime
from collections import Counter, deque

from scapy_engine import AutoShieldEngine
from auto_block import BlockManager
from cve_lookup import get_cve_card, _fallback_cves
from certin_feed import (
    fetch_certin_advisories,
    match_attack_to_certin,
    get_certin_summary,
)
from attack_map import build_attack_map, get_geo_stats, geolocate_ip
from threat_score import get_threat_engine
from alert_system import fire_alert, alert_config_status
from report_generator import generate_report, REPORTLAB_OK
from auth import require_auth, current_user, logout
from api_layer import AutoShieldAPIServer
from ui_shell import inject_shell_styles, render_top_nav

EVENT_STREAM_FILE = os.getenv(
    "AUTOSHIELD_EVENT_STREAM", "/tmp/autoshield_event_stream.jsonl"
)

# ─── Page config ──────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="AutoShield AI",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

require_auth()

inject_shell_styles()

# ─── CSS ──────────────────────────────────────────────────────────────────────
st.markdown(
    """
<style>
@import url('https://fonts.googleapis.com/css2?family=Space+Mono:wght@400;700&family=DM+Sans:wght@300;400;500;600;700;800&display=swap');
:root{
  --bg0:#0B0F14;--bg1:#0A0E13;--bg2:#11161C;--bg3:#151C25;
  --bd:#1C2535;--bd2:#24344B;
  --blue:#00C8FF;--green:#00FF9C;--red:#FF4D4D;--orange:#FF8B5B;--yellow:#FFC857;
  --purple:#6A5CFF;--teal:#00d4b8;
  --muted:#8B949E;--muted2:#4A6080;--text:#E7EEF9;--text2:#CDD8EB;
  --font:'DM Sans',-apple-system,sans-serif;--mono:'Space Mono',monospace;
  --radius:12px;
}
.stApp{background:var(--bg0)!important;font-family:var(--font)!important;color:var(--text)!important;}
.stApp::before{content:'';position:fixed;inset:0;
  background:radial-gradient(ellipse 600px 400px at 8% 6%,rgba(0,200,255,.025),transparent),
  radial-gradient(ellipse 500px 350px at 85% 8%,rgba(106,92,255,.02),transparent);
  pointer-events:none;z-index:0;}
.stApp>header{display:none!important;}
[data-testid="stSidebar"]{background:var(--bg1)!important;border-right:1px solid var(--bd)!important;}
[data-testid="stSidebar"] *{color:var(--text)!important;}
section[data-testid="stSidebarContent"]{padding:0!important;}
.block-container{padding:0.5rem 1.1rem 1.8rem!important;max-width:1300px!important;margin:0 auto!important;
  animation:fadein .3s cubic-bezier(.22,1,.36,1);}
div[data-testid="stHorizontalBlock"]{gap:12px!important;}
.element-container{margin:0!important;}
hr{border-color:var(--bd)!important;margin:12px 0!important;}

/* Metrics */
div[data-testid="stMetric"]{background:var(--bg2)!important;border:1px solid var(--bd)!important;
  border-radius:var(--radius)!important;padding:14px 16px!important;
  box-shadow:0 4px 16px rgba(0,0,0,.18);transition:all .25s cubic-bezier(.22,1,.36,1);}
div[data-testid="stMetric"]:hover{border-color:var(--bd2)!important;transform:translateY(-2px);
  box-shadow:0 8px 28px rgba(0,0,0,.28);}
div[data-testid="stMetric"] label{color:var(--muted)!important;font-size:11px!important;
  font-family:var(--mono)!important;letter-spacing:.06em!important;text-transform:uppercase!important;}
div[data-testid="stMetric"] [data-testid="stMetricValue"]{color:var(--text)!important;
  font-family:var(--mono)!important;font-weight:700!important;}

/* Buttons */
div[data-testid="stButton"]>button{width:100%;background:var(--bg2)!important;border:1px solid var(--bd2)!important;
  color:var(--text)!important;border-radius:var(--radius)!important;font-family:var(--font)!important;
  font-size:12px!important;font-weight:500!important;padding:8px 14px!important;
  transition:all .2s cubic-bezier(.22,1,.36,1)!important;}
div[data-testid="stButton"]>button:hover{background:var(--bg3)!important;border-color:rgba(0,200,255,.3)!important;
  transform:translateY(-1px)!important;box-shadow:0 6px 20px rgba(0,0,0,.25)!important;}
div[data-testid="stButton"]>button:active{transform:scale(.98)!important;}
div[data-testid="stButton"]>button[kind="primary"]{background:linear-gradient(135deg,var(--blue),var(--purple))!important;
  border:0!important;color:#fff!important;font-weight:600!important;
  box-shadow:0 4px 16px rgba(0,200,255,.15)!important;}
div[data-testid="stButton"]>button[kind="primary"]:hover{box-shadow:0 8px 28px rgba(0,200,255,.25)!important;}

/* Inputs */
div[data-testid="stSelectbox"]>div>div,div[data-testid="stTextInput"]>div>div>input{
  background:var(--bg2)!important;border:1px solid var(--bd)!important;color:var(--text)!important;
  border-radius:var(--radius)!important;font-size:12px!important;transition:all .2s!important;}
div[data-testid="stTextInput"]>div>div>input:focus{border-color:var(--blue)!important;
  box-shadow:0 0 0 1px rgba(0,200,255,.3),0 0 20px rgba(0,200,255,.08)!important;}
div[data-testid="stRadio"] label{font-size:12px!important;color:var(--text)!important;}

/* Tabs */
[data-testid="stTabs"] button{background:transparent!important;color:var(--muted)!important;
  font-family:var(--font)!important;font-size:12px!important;font-weight:500!important;
  border-bottom:2px solid transparent!important;border-radius:0!important;padding:10px 18px!important;
  letter-spacing:.03em;transition:all .2s!important;}
[data-testid="stTabs"] button:hover{color:var(--text2)!important;}
[data-testid="stTabs"] button[aria-selected="true"]{color:var(--blue)!important;border-bottom-color:var(--blue)!important;}
[data-testid="stTabs"]{border-bottom:1px solid var(--bd)!important;}

/* Code & Expanders */
.stCode,code{background:var(--bg1)!important;color:var(--green)!important;
  font-family:var(--mono)!important;font-size:11px!important;border:1px solid var(--bd)!important;
  border-radius:8px!important;}
[data-testid="stExpander"]{background:var(--bg2)!important;border:1px solid var(--bd)!important;border-radius:8px!important;}
[data-testid="stExpander"] summary{color:var(--text2)!important;font-size:12px!important;}

/* Sidebar sections */
.sb-sec{padding:14px 14px 6px;font-size:10px;font-weight:600;letter-spacing:.12em;color:var(--muted2);
  text-transform:uppercase;font-family:var(--mono);}

/* Glass cards */
.glass-card{background:rgba(17,22,28,.92);border:1px solid var(--bd);border-radius:var(--radius);
  padding:14px;backdrop-filter:blur(8px);-webkit-backdrop-filter:blur(8px);
  box-shadow:0 8px 24px rgba(2,8,20,.28);animation:fadein .3s cubic-bezier(.22,1,.36,1);}
.neon-pill{display:inline-block;padding:3px 10px;border-radius:999px;border:1px solid rgba(0,200,255,.25);
  background:rgba(0,200,255,.06);color:#8DD9FF;font-size:10px;font-family:var(--mono);}
.skeleton{position:relative;overflow:hidden;background:var(--bg2);border:1px solid var(--bd);
  border-radius:8px;height:16px;margin:8px 0;}
.skeleton::after{content:'';position:absolute;inset:0;transform:translateX(-100%);
  background:linear-gradient(90deg,transparent,rgba(255,255,255,.04),transparent);animation:sh 1.8s ease infinite;}

/* Table cards */
.table-card{background:var(--bg2);border:1px solid var(--bd);border-radius:14px;padding:14px 16px;}
.log-row{display:grid;grid-template-columns:80px 140px 95px 95px 120px 1fr;gap:10px;
  padding:8px 12px;border-radius:8px;border:1px solid transparent;transition:all .18s ease;}
.log-row:hover{background:rgba(0,200,255,.03);border-color:var(--bd);}

/* Scrollbars */
::-webkit-scrollbar{width:4px;height:4px;}
::-webkit-scrollbar-track{background:var(--bg1);}
::-webkit-scrollbar-thumb{background:var(--bd2);border-radius:2px;}
::-webkit-scrollbar-thumb:hover{background:var(--muted2);}

/* Animations */
@keyframes pulse-r{0%,100%{opacity:1}50%{opacity:.3}}
@keyframes pulse-g{0%,100%{opacity:1}50%{opacity:.5}}
@keyframes fadein{from{opacity:0;transform:translateY(4px)}to{opacity:1;transform:none}}
@keyframes sh{100%{transform:translateX(100%)}}
</style>""",
    unsafe_allow_html=True,
)


# ─── Session state ─────────────────────────────────────────────────────────────
def _init():
    d = st.session_state
    if "engine" not in d:
        d.engine = AutoShieldEngine()
    if "blocker" not in d:
        d.blocker = BlockManager()
    if "ts_engine" not in d:
        d.ts_engine = get_threat_engine()
    if "log" not in d:
        d.log = []
    if "last" not in d:
        d.last = None
    if "cve_sel" not in d:
        d.cve_sel = "SQLi"
    if "persona" not in d:
        d.persona = "Analyst"
    if "autopilot" not in d:
        d.autopilot = False
    if "sniff_mode" not in d:
        d.sniff_mode = False
    if "cli_mode" not in d:
        d.cli_mode = True
    if "pause_live" not in d:
        d.pause_live = False
    if "stream_offset" not in d:
        d.stream_offset = 0
    if "seen_stream_ids" not in d:
        d.seen_stream_ids = []
    if "stream_ingested" not in d:
        d.stream_ingested = 0
    if "last_stream_seen" not in d:
        d.last_stream_seen = 0.0
    if "map_cache_html" not in d:
        d.map_cache_html = ""
    if "map_cache_count" not in d:
        d.map_cache_count = 0
    if "map_cache_ts" not in d:
        d.map_cache_ts = 0.0
    if "notifications" not in d:
        d.notifications = []
    if "threat_trend" not in d:
        d.threat_trend = deque(maxlen=80)
    if "monitor_target" not in d:
        d.monitor_target = "https://example.com"
    if "monitor_history" not in d:
        d.monitor_history = {}
    if "monitor_last" not in d:
        d.monitor_last = {}
    if "monitor_interval" not in d:
        d.monitor_interval = 10
    if "monitor_checked_at" not in d:
        d.monitor_checked_at = 0.0
    if "firewall_country_block" not in d:
        d.firewall_country_block = set()
    if "firewall_rate_rules" not in d:
        d.firewall_rate_rules = [{"threshold": 6, "window": 60}]
    if "ip_hit_window" not in d:
        d.ip_hit_window = {}
    if "api_server" not in d:
        d.api_server = None
    if "api_running" not in d:
        d.api_running = False
    if "api_host" not in d:
        d.api_host = "127.0.0.1"
    if "api_port" not in d:
        d.api_port = 8787


_init()

engine = st.session_state.engine
blocker = st.session_state.blocker
ts_eng = st.session_state.ts_engine


def sync():
    st.session_state.log = engine.get_log()


def _push_notification(level, message):
    item = {
        "ts": datetime.now().strftime("%H:%M:%S"),
        "level": level,
        "message": message,
    }
    st.session_state.notifications.append(item)
    st.session_state.notifications = st.session_state.notifications[-80:]
    icon = {"CRITICAL": "🚨", "WARNING": "⚠️", "INFO": "ℹ️"}.get(level, "🔔")
    try:
        st.toast(f"[{level}] {message}", icon=icon)
    except Exception:
        pass


def _run_website_check(url):
    t0 = time.time()
    status = 0
    ok = False
    err = ""
    waf_hits = {"SQLi": 0, "XSS": 0, "LFI": 0}
    for ev in st.session_state.log[-120:]:
        at = ev.get("attack_type")
        if at in waf_hits:
            waf_hits[at] += 1

    try:
        resp = requests.get(url, timeout=4)
        status = resp.status_code
        ok = status < 500
    except Exception as ex:
        err = str(ex)

    latency = int((time.time() - t0) * 1000)
    history = st.session_state.monitor_history.get(url, [])
    history.append(latency)
    history = history[-50:]
    st.session_state.monitor_history[url] = history
    baseline = (
        (sum(history[:-1]) / max(len(history[:-1]), 1)) if len(history) > 1 else latency
    )
    anomaly = latency > max(900, int(baseline * 2.3)) or (
        status >= 500 if status else True
    )
    uptime = round(
        (sum(1 for v in history if v < 1500) / max(len(history), 1)) * 100,
        1,
    )
    data = {
        "url": url,
        "status": status,
        "latency_ms": latency,
        "uptime_pct": uptime,
        "anomaly": anomaly,
        "error": err,
        "waf": waf_hits,
        "checked_at": datetime.now().strftime("%H:%M:%S"),
    }
    st.session_state.monitor_last[url] = data
    return data


def _apply_runtime_firewall_rules(ev):
    ip = ev.get("src_ip", "0.0.0.0")
    country = geolocate_ip(ip).get("country", "Unknown")
    if country in st.session_state.firewall_country_block:
        rec = blocker.block_ip(
            ip,
            reason=f"Country block rule: {country}",
            severity=ev.get("severity", "HIGH"),
            attack_type=ev.get("attack_type", "Unknown"),
        )
        ev["action"] = "BLOCKED"
        ev["status"] = "MITIGATED"
        ev["block_record"] = rec

    now = time.time()
    hits = st.session_state.ip_hit_window.get(ip, [])
    hits.append(now)
    st.session_state.ip_hit_window[ip] = hits[-100:]

    for rule in st.session_state.firewall_rate_rules:
        win = int(rule.get("window", 60))
        thr = int(rule.get("threshold", 6))
        recent = [t for t in st.session_state.ip_hit_window[ip] if now - t <= win]
        st.session_state.ip_hit_window[ip] = recent
        if len(recent) >= thr:
            rec = blocker.block_ip(
                ip,
                reason=f"Runtime rate limit {thr}/{win}s",
                severity=ev.get("severity", "HIGH"),
                attack_type=ev.get("attack_type", "Unknown"),
            )
            ev["action"] = "BLOCKED"
            ev["status"] = "MITIGATED"
            ev["block_record"] = rec
            break


def _ingest_cli_stream(max_lines=150):
    if not st.session_state.cli_mode or not os.path.exists(EVENT_STREAM_FILE):
        st.session_state.stream_ingested = 0
        return 0

    ingested = 0
    seen = set(st.session_state.seen_stream_ids)
    start = int(st.session_state.stream_offset)
    try:
        with open(EVENT_STREAM_FILE, "r", encoding="utf-8") as f:
            f.seek(start)
            for _ in range(max_lines):
                line = f.readline()
                if not line:
                    break
                try:
                    raw = json.loads(line.strip() or "{}")
                except Exception:
                    continue
                eid = str(raw.get("event_id", ""))
                if eid and eid in seen:
                    continue
                at = raw.get("attack_type", "SQLi")
                ip = raw.get("src_ip", "192.168.1.100")
                ev = fire(at, ip)
                if ev and raw.get("payload"):
                    ev["payload_snip"] = raw.get("payload")
                if eid:
                    seen.add(eid)
                ingested += 1
            st.session_state.stream_offset = f.tell()
    except Exception:
        pass

    st.session_state.seen_stream_ids = list(seen)[-4000:]
    st.session_state.stream_ingested = ingested
    if ingested > 0:
        st.session_state.last_stream_seen = time.time()
    return ingested


def _cached_map_html(events):
    if not events:
        st.session_state.map_cache_html = ""
        st.session_state.map_cache_count = 0
        st.session_state.map_cache_ts = time.time()
        return ""

    now = time.time()
    needs_rebuild = (
        st.session_state.map_cache_html == ""
        or len(events) != st.session_state.map_cache_count
        or (now - st.session_state.map_cache_ts) > 12
    )
    if needs_rebuild:
        mp = build_attack_map(events, "/tmp/live_map.html")
        with open(mp, encoding="utf-8") as f:
            st.session_state.map_cache_html = f.read()
        st.session_state.map_cache_count = len(events)
        st.session_state.map_cache_ts = now
    return st.session_state.map_cache_html


def fire(atype, ip):
    ev = engine.simulate_attack(attack_type=atype, src_ip=ip)
    if ev:
        blocker.auto_respond(ev)
        _apply_runtime_firewall_rules(ev)
        engine.mark_blocked(ip)
        ts_eng.ingest(ev)
        st.session_state.last = ev
        st.session_state.cve_sel = atype
        top = ts_eng.get_top_threats(1)
        st.session_state.threat_trend.append(top[0]["threat_score"] if top else 0)
        if ev.get("severity") in ("CRITICAL", "HIGH"):
            fire_alert(ev)
            _push_notification(
                ev.get("severity", "WARNING"), f"{ev.get('attack_type')} from {ip}"
            )
        sync()
    return ev


def _recent_rps(events, seconds=10):
    if not events:
        return 0.0
    now = datetime.now()
    recent = 0
    for ev in events[-300:]:
        try:
            ts = datetime.fromisoformat(ev.get("timestamp", now.isoformat()))
        except Exception:
            ts = now
        if (now - ts).total_seconds() <= seconds:
            recent += 1
    return round(recent / max(seconds, 1), 2)


def _search_events(term):
    t = (term or "").strip().lower()
    if not t:
        return []
    out = []
    for ev in reversed(st.session_state.log[-500:]):
        hay = " ".join(
            [
                str(ev.get("src_ip", "")),
                str(ev.get("dst_ip", "")),
                str(ev.get("attack_type", "")),
                str(ev.get("payload_snip", "")),
                " ".join(ev.get("cve_hints", [])),
            ]
        ).lower()
        if t in hay:
            out.append(ev)
        if len(out) >= 12:
            break
    return out


def _health_summary(top_score, active_count, monitor_data):
    if monitor_data and (
        monitor_data.get("anomaly") or monitor_data.get("status", 0) >= 500
    ):
        return "DEGRADED", "#ff6b35"
    if top_score >= 80 or active_count >= 8:
        return "CRITICAL", "#ff3d57"
    if top_score >= 60 or active_count >= 4:
        return "ELEVATED", "#ffd60a"
    return "HEALTHY", "#00e676"


def _gauge_svg(score):
    color = (
        "#ff3d57"
        if score >= 80
        else "#ff6b35"
        if score >= 60
        else "#ffd60a"
        if score >= 40
        else "#00a8ff"
        if score >= 20
        else "#00e676"
    )
    angle = int((score / 100) * 283)
    return f"""
<svg width="160" height="160" viewBox="0 0 120 120" fill="none" xmlns="http://www.w3.org/2000/svg">
  <circle cx="60" cy="60" r="45" stroke="#1e2d45" stroke-width="10"/>
  <circle cx="60" cy="60" r="45" stroke="{color}" stroke-width="10" stroke-linecap="round"
          stroke-dasharray="{angle} 283" transform="rotate(-90 60 60)"/>
  <text x="60" y="58" text-anchor="middle" fill="#cdd8eb" font-size="20" font-family="Space Mono">{score}</text>
  <text x="60" y="74" text-anchor="middle" fill="#4a6080" font-size="9" font-family="Space Mono">THREAT SCORE</text>
</svg>"""


def _replay_rows(events, limit=24):
    rows = []
    for ev in events[-limit:]:
        rows.append(
            {
                "time": ev.get("timestamp", "")[-8:-3],
                "src_ip": ev.get("src_ip", "-"),
                "attack": ev.get("attack_type", "-"),
                "severity": ev.get("severity", "-"),
                "detect": "DETECTED",
                "response": ev.get("action", "PENDING"),
                "status": ev.get("status", "-"),
                "cve": (ev.get("cve_hints", ["-"]) or ["-"])[0],
            }
        )
    return rows


def _start_api_server_if_needed():
    if st.session_state.api_running and st.session_state.api_server is None:
        st.session_state.api_server = AutoShieldAPIServer(
            st.session_state.api_host,
            st.session_state.api_port,
            fire,
            lambda ip, reason: blocker.block_ip(
                ip, reason=reason, severity="HIGH", attack_type="API"
            ),
            lambda ip: ts_eng.get_profile(ip) if ip else ts_eng.get_top_threats(10),
        )
        st.session_state.api_server.start()


_start_api_server_if_needed()


# ─── HTML helpers ──────────────────────────────────────────────────────────────
def mc(val, lbl, col="#00a8ff", sub=None):
    s = (
        f'<div style="font-size:10px;color:#4a6080;font-family:Space Mono,monospace;margin-top:3px">{sub}</div>'
        if sub
        else ""
    )
    return f"""<div style="background:#0e1420;border:1px solid #1e2d45;border-radius:6px;padding:14px;text-align:center;animation:fadein .3s">
      <div style="font-size:10px;color:#4a6080;letter-spacing:.1em;text-transform:uppercase;font-family:Space Mono,monospace;margin-bottom:5px">{lbl}</div>
      <div style="font-size:26px;font-weight:700;color:{col};font-family:Space Mono,monospace;line-height:1">{val}</div>{s}</div>"""


def bar_card(score):
    col = (
        "#ff3d57"
        if score >= 80
        else "#ff6b35"
        if score >= 60
        else "#ffd60a"
        if score >= 40
        else "#00a8ff"
        if score >= 20
        else "#00e676"
    )
    lbl = (
        "CRITICAL"
        if score >= 80
        else "HIGH"
        if score >= 60
        else "MEDIUM"
        if score >= 40
        else "LOW"
        if score >= 20
        else "CLEAN"
    )
    return f"""<div style="background:#0e1420;border:1px solid {col}55;border-radius:6px;padding:14px;text-align:center;animation:fadein .3s">
      <div style="font-size:10px;color:#4a6080;letter-spacing:.1em;text-transform:uppercase;font-family:Space Mono,monospace;margin-bottom:5px">Top Threat Score</div>
      <div style="font-size:26px;font-weight:700;color:{col};font-family:Space Mono,monospace;line-height:1">{score}</div>
      <div style="font-size:9px;color:{col};font-family:Space Mono,monospace;margin:3px 0 8px">{lbl}</div>
      <div style="background:#131b2a;border-radius:2px;height:4px"><div style="background:{col};height:100%;width:{score}%;border-radius:2px;transition:width .5s"></div></div></div>"""


def threat_score_row(p, i):
    s = p["threat_score"]
    c = (
        "#ff3d57"
        if s >= 80
        else "#ff6b35"
        if s >= 60
        else "#ffd60a"
        if s >= 40
        else "#00a8ff"
    )
    rc = ["#ffd60a", "#8899b0", "#ff6b35"][i] if i < 3 else "#4a6080"
    t = "/".join(p["attack_types"])
    return f"""<div style="background:#0e1420;border:1px solid #1e2d45;border-radius:5px;padding:10px 12px;margin-bottom:7px">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:5px">
        <span style="font-size:10px;font-weight:700;color:{rc};font-family:Space Mono,monospace">#{i + 1}</span>
        <span style="font-size:11px;color:#cdd8eb;font-family:Space Mono,monospace;margin:0 8px;flex:1">{p["ip"]}</span>
        <span style="font-size:16px;font-weight:700;color:{c};font-family:Space Mono,monospace">{s}</span>
      </div>
      <div style="background:#131b2a;border-radius:2px;height:4px;overflow:hidden">
        <div style="background:{c};height:100%;width:{s}%;border-radius:2px"></div></div>
      <div style="display:flex;justify-content:space-between;margin-top:4px">
        <span style="font-size:9px;color:#4a6080;font-family:Space Mono,monospace">{t}</span>
        <span style="font-size:9px;color:{c};font-family:Space Mono,monospace">{p["threat_label"]}</span>
      </div></div>"""


# ─── Sidebar ───────────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown(
        """<div style="padding:18px 16px 14px;border-bottom:1px solid #1C2535">
      <div style="display:flex;align-items:center;gap:10px">
        <div style="width:32px;height:32px;border-radius:10px;background:linear-gradient(135deg,#00C8FF,#6A5CFF);
                    display:flex;align-items:center;justify-content:center;font-size:16px;flex-shrink:0">🛡️</div>
        <div>
          <div style="font-size:15px;font-weight:700;color:#E7EEF9;letter-spacing:-.02em">AutoShield AI</div>
          <div style="font-size:10px;color:#4A6080;letter-spacing:.08em;font-family:Space Mono,monospace;margin-top:1px">FUSION CONSOLE v2</div>
        </div>
      </div>
    </div>""",
        unsafe_allow_html=True,
    )

    user = current_user()
    st.markdown(
        f"""<div style="background:var(--bg2);border:1px solid var(--bd);border-radius:10px;padding:10px 12px;margin:10px 14px 4px">
      <div style="font-size:10px;color:var(--muted2);font-family:var(--mono);letter-spacing:.06em">SIGNED IN</div>
      <div style="font-size:12px;color:var(--blue);font-weight:600;margin-top:3px">{user.get("name", "Unknown")}</div>
      <div style="font-size:10px;color:var(--muted);font-family:var(--mono);margin-top:2px">{user.get("email", "")}</div>
    </div>""",
        unsafe_allow_html=True,
    )

    st.markdown('<div class="sb-sec">Website Setup</div>', unsafe_allow_html=True)
    st.page_link("pages/05_My_Websites.py", label="Add Website (Setup)", icon="🧩")

    if st.button("Logout", use_container_width=True):
        logout()
        st.switch_page("pages/00_Login.py")

    st.markdown('<div class="sb-sec">Control Panel</div>', unsafe_allow_html=True)
    st.page_link("dashboard.py", label="Fusion Dashboard", icon="🛡️")
    st.page_link("pages/01_Live_SOC.py", label="Live SOC", icon="⚡")
    st.page_link("pages/02_Attack_Geography.py", label="Attack Geography", icon="🌐")
    st.page_link(
        "pages/03_Threat_Intelligence.py", label="Threat Intelligence", icon="🧠"
    )
    st.page_link(
        "pages/04_Operations_Reports.py", label="Operations & Reports", icon="📦"
    )
    st.page_link("pages/05_My_Websites.py", label="My Websites", icon="🗂️")

    st.markdown('<div class="sb-sec">Mission Controls</div>', unsafe_allow_html=True)
    persona = st.selectbox(
        "Role",
        ["Analyst", "SOC Lead", "Executive"],
        key="p_sel",
        label_visibility="collapsed",
    )
    st.session_state.persona = persona
    focus = {
        "Analyst": "tactical triage + payload evidence",
        "SOC Lead": "team coordination + escalation",
        "Executive": "impact summary + compliance",
    }
    st.markdown(
        f"""<div style="background:#131b2a;border:1px solid #1e2d45;border-radius:4px;padding:8px 10px;margin:4px 0 8px">
      <div style="font-size:10px;color:#4a6080;font-family:Space Mono,monospace">ACTIVE PERSONA</div>
      <div style="font-size:11px;color:#00a8ff;font-family:DM Sans,sans-serif;font-weight:500">{persona} | {focus[persona]}</div>
    </div>""",
        unsafe_allow_html=True,
    )

    st.markdown('<div class="sb-sec">Simulate Attack</div>', unsafe_allow_html=True)
    atype_sel = st.selectbox(
        "Attack Type",
        ["SQLi", "XSS", "LFI", "CMDi"],
        key="a_sel",
        label_visibility="collapsed",
    )
    src_ip = st.text_input(
        "Source IP", value="192.168.1.100", label_visibility="collapsed"
    )
    if st.button("⚡ Launch Attack", type="primary", use_container_width=True):
        fire(atype_sel, src_ip)
        st.rerun()

    st.markdown('<div class="sb-sec">Engine Mode</div>', unsafe_allow_html=True)
    sniff_mode = st.toggle("Live sniff mode", value=st.session_state.sniff_mode)
    cli_mode = st.toggle("CLI stream ingest", value=st.session_state.cli_mode)
    if sniff_mode != st.session_state.sniff_mode:
        st.session_state.sniff_mode = sniff_mode
        try:
            if sniff_mode:
                engine.start()
            else:
                engine.stop()
        except Exception:
            st.session_state.sniff_mode = False
    if cli_mode != st.session_state.cli_mode:
        st.session_state.cli_mode = cli_mode
        st.rerun()
    if st.button("Reset Stream Offset", use_container_width=True):
        st.session_state.stream_offset = 0
        st.session_state.seen_stream_ids = []
        st.session_state.map_cache_html = ""
        st.session_state.map_cache_count = 0
        st.session_state.map_cache_ts = 0.0
        st.info("Stream cursor reset")
    if st.button("Clear All Logs", use_container_width=True):
        try:
            engine.stop()
        except Exception:
            pass
        st.session_state.sniff_mode = False
        engine.attack_log.clear()
        blocker.flush_all()
        st.session_state.log = []
        st.session_state.last = None
        st.session_state.stream_offset = 0
        st.session_state.seen_stream_ids = []
        st.session_state.map_cache_html = ""
        st.session_state.map_cache_count = 0
        st.session_state.map_cache_ts = 0.0
        if os.path.exists(EVENT_STREAM_FILE):
            try:
                os.remove(EVENT_STREAM_FILE)
            except Exception:
                pass
        st.rerun()

    st.markdown('<div class="sb-sec">Protected Server</div>', unsafe_allow_html=True)
    def_lat = st.text_input("Lat", value="28.6139", label_visibility="collapsed")
    def_lon = st.text_input("Lon", value="77.2090", label_visibility="collapsed")

    st.markdown(
        '<div class="sb-sec">Rapid Demo (all types)</div>', unsafe_allow_html=True
    )
    if st.button("🚀 Run Full Demo", use_container_width=True):
        for t, i in [
            ("SQLi", "10.0.0.11"),
            ("XSS", "10.0.0.12"),
            ("LFI", "10.0.0.13"),
            ("CMDi", "10.0.0.14"),
        ]:
            fire(t, i)
        st.rerun()

    st.markdown('<div class="sb-sec">Autopilot Demo</div>', unsafe_allow_html=True)
    c1, c2 = st.columns(2)
    with c1:
        if st.button("Start\nAutopilot", use_container_width=True):
            st.session_state.autopilot = True
    with c2:
        if st.button("Stop\nAutopilot", use_container_width=True):
            st.session_state.autopilot = False
    ap_delay = st.slider("", 1, 10, 3, label_visibility="collapsed")

    st.markdown('<div class="sb-sec">Alerts</div>', unsafe_allow_html=True)
    acfg = alert_config_status()
    wa_ok = acfg["whatsapp"]["configured"]
    em_ok = acfg["email"]["configured"]
    st.markdown(
        f"""<div style="background:#131b2a;border:1px solid #1e2d45;border-radius:4px;padding:8px 10px;font-size:11px;font-family:Space Mono,monospace">
      <div style="color:#4a6080">WhatsApp: <span style="color:{"#00e676" if wa_ok else "#4a6080"}">{"🟢 ON" if wa_ok else "⚫ off"}</span></div>
      <div style="color:#4a6080;margin-top:3px">Email: <span style="color:{"#00e676" if em_ok else "#4a6080"}">{"🟢 ON" if em_ok else "⚫ off"}</span></div>
    </div>""",
        unsafe_allow_html=True,
    )
    if st.button("Send Test Alert", use_container_width=True):
        ev0 = st.session_state.last or {
            "src_ip": "0.0.0.0",
            "attack_type": "SQLi",
            "severity": "CRITICAL",
            "action": "BLOCKED",
            "confidence": 75,
            "cve_hints": ["CVE-2023-23752"],
            "payload_snip": "test",
            "timestamp": datetime.now().isoformat(),
        }
        fire_alert(ev0, force=True)
        st.success("Alert fired!")

    st.markdown('<div class="sb-sec">Judge Mode</div>', unsafe_allow_html=True)
    j1, j2 = st.columns(2)
    with j1:
        if st.button("Start", key="js"):
            pass
    with j2:
        if st.button("Stop", key="jx"):
            pass
    if st.button("Run Detector Benchmark", use_container_width=True):
        for t in ["SQLi", "XSS", "LFI", "CMDi"]:
            for i in range(3):
                fire(t, f"10.1.{['SQLi', 'XSS', 'LFI', 'CMDi'].index(t)}.{i + 1}")
        st.rerun()

    st.markdown('<div class="sb-sec">Live Control</div>', unsafe_allow_html=True)
    pause = st.toggle("Pause live updates", value=st.session_state.pause_live)
    st.session_state.pause_live = pause

    st.markdown('<div class="sb-sec">API Layer</div>', unsafe_allow_html=True)
    st.session_state.api_host = st.text_input(
        "API Host", value=st.session_state.api_host, label_visibility="collapsed"
    )
    st.session_state.api_port = int(
        st.number_input(
            "API Port",
            min_value=1024,
            max_value=65535,
            value=int(st.session_state.api_port),
            label_visibility="collapsed",
        )
    )
    api_live = st.toggle("API server running", value=st.session_state.api_running)
    if api_live != st.session_state.api_running:
        st.session_state.api_running = api_live
        if not api_live and st.session_state.api_server:
            st.session_state.api_server.stop()
            st.session_state.api_server = None
        elif api_live:
            st.session_state.api_server = AutoShieldAPIServer(
                st.session_state.api_host,
                st.session_state.api_port,
                fire,
                lambda ip, reason: blocker.block_ip(
                    ip, reason=reason, severity="HIGH", attack_type="API"
                ),
                lambda ip: ts_eng.get_profile(ip) if ip else ts_eng.get_top_threats(10),
            )
            st.session_state.api_server.start()
        st.rerun()
    st.code(
        f"POST http://{st.session_state.api_host}:{st.session_state.api_port}/log-event\n"
        f"POST http://{st.session_state.api_host}:{st.session_state.api_port}/block-ip\n"
        f"GET  http://{st.session_state.api_host}:{st.session_state.api_port}/threat-score?ip=1.2.3.4",
        language="bash",
    )

# ─── Autopilot ─────────────────────────────────────────────────────────────────
_ingest_cli_stream()

if st.session_state.autopilot:
    import random

    fire(
        random.choice(["SQLi", "XSS", "LFI", "CMDi"]),
        f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}",
    )
    time.sleep(ap_delay)
    st.rerun()

# ─── Sync data ─────────────────────────────────────────────────────────────────
sync()
log = st.session_state.log
bips = blocker.get_blocked_list()
total = len(log)
blk = len([e for e in log if e.get("action") == "BLOCKED"])
sqli = len([e for e in log if e.get("attack_type") == "SQLi"])
xss = len([e for e in log if e.get("attack_type") == "XSS"])
lfi = len([e for e in log if e.get("attack_type") == "LFI"])
cmdi = len([e for e in log if e.get("attack_type") == "CMDi"])
profs = ts_eng.get_top_threats(1)
top_s = profs[0]["threat_score"] if profs else 0
active = any(e.get("status") != "MITIGATED" for e in log)
realtime_state = (
    "PAUSED"
    if st.session_state.pause_live
    else "ACTIVE"
    if (
        st.session_state.cli_mode
        or st.session_state.sniff_mode
        or st.session_state.autopilot
    )
    else "IDLE"
)

if (not st.session_state.monitor_last) or (
    time.time() - st.session_state.monitor_checked_at
    > st.session_state.monitor_interval
):
    _run_website_check(st.session_state.monitor_target)
    st.session_state.monitor_checked_at = time.time()

monitor_data = st.session_state.monitor_last.get(st.session_state.monitor_target, {})
req_ps = _recent_rps(log, 10)
active_threats = len([e for e in log[-60:] if e.get("status") != "MITIGATED"])
health_label, health_color = _health_summary(top_s, active_threats, monitor_data)

# ─── Header strip ──────────────────────────────────────────────────────────────
sc = "#ff3d57" if active else "#00e676"
st_txt = "UNDER ATTACK" if active else "ALL SYSTEMS SECURE"
dot = f'<span style="display:inline-block;width:8px;height:8px;border-radius:50%;background:{sc};margin-right:6px;animation:{"pulse-r" if active else "pulse-g"} 1s infinite"></span>'
now_s = datetime.now().strftime("%H:%M:%S")
notif_count = len(st.session_state.notifications)
recent_notifs = list(reversed(st.session_state.notifications[-6:]))
search_term = render_top_nav("dashboard") or st.session_state.get("global_search", "")
search_hits = _search_events(search_term) if search_term else []
provider = current_user().get("provider", "local").upper()

st.markdown(
    f"""
<div style="background:rgba(14,19,26,.86);border:1px solid #1e2d45;padding:10px 20px;
            display:flex;align-items:center;justify-content:space-between;
            margin:0 0 14px;border-radius:14px;backdrop-filter:blur(8px)">
  <div>
    <div style="font-size:16px;font-weight:700;color:#cdd8eb;font-family:DM Sans,sans-serif">AutoShield AI Fusion Console</div>
    <div style="font-size:10px;color:#4a6080;font-family:Space Mono,monospace;margin-top:1px">
      CVE/CERT-In intelligence · geo mapping · threat scoring · alerts · one-click incident reports
    </div>
  </div>
  <div style="display:flex;align-items:center;gap:20px">
    <div style="background:#111a28;border:1px solid #253550;border-radius:999px;padding:5px 10px;min-width:300px">
      <span style="font-size:10px;color:#4a6080;font-family:Space Mono,monospace">🔎 Search IP / domain / CVE in top bar below</span>
    </div>
    <div style="text-align:center">
      <div style="font-size:12px;color:#8dd9ff;font-family:Space Mono,monospace">🔔 {notif_count}</div>
      <div style="font-size:9px;color:#4a6080;font-family:Space Mono,monospace">ALERTS</div>
    </div>
    <div style="text-align:center">
      <div style="font-size:12px;font-weight:600;color:{sc};font-family:DM Sans,sans-serif">{dot}{st_txt}</div>
      <div style="font-size:10px;color:#4a6080;font-family:Space Mono,monospace;margin-top:2px">
        <span style="background:#0d2640;border:1px solid #00a8ff44;padding:1px 6px;border-radius:3px;color:#00a8ff;font-size:9px">LIVE STREAM ACTIVE</span>
        &nbsp;{len(bips)} blocked IPs · {total} alerts handled · Protected node: {def_lat}, {def_lon}
      </div>
    </div>
    <div style="text-align:right">
      <div style="font-size:16px;font-weight:700;color:#cdd8eb;font-family:Space Mono,monospace">{now_s}</div>
      <div style="font-size:9px;color:#4a6080;font-family:Space Mono,monospace">{current_user().get("name", "User")} · {provider}</div>
    </div>
  </div>
</div>
<div style="background:#101826;border:1px solid #1e2d45;border-radius:12px;padding:6px 14px;
            margin-bottom:12px;font-size:11px;color:#4a6080;font-family:Space Mono,monospace">
  Active persona: <span style="color:#00a8ff">{st.session_state.persona}</span>
  &nbsp;|&nbsp; Focus: <span style="color:#cdd8eb">{focus[st.session_state.persona]}</span>
  &nbsp;|&nbsp; Alerts: <span style="color:{"#00e676" if em_ok or wa_ok else "#4a6080"}">{"ACTIVE" if em_ok or wa_ok else "UNCONFIGURED"}</span>
</div>
""",
    unsafe_allow_html=True,
)

if search_term and search_hits:
    with st.expander(f"Search results ({len(search_hits)})", expanded=False):
        for ev in search_hits[:8]:
            st.markdown(
                f"<div class='glass-card'><span class='neon-pill'>{ev.get('attack_type')}</span> "
                f"<span style='color:#cdd8eb;font-family:Space Mono,monospace;font-size:11px;margin-left:8px'>{ev.get('src_ip')}</span> "
                f"<span style='color:#4a6080;font-family:Space Mono,monospace;font-size:10px;margin-left:8px'>{ev.get('cve_hints', [''])[0]}</span></div>",
                unsafe_allow_html=True,
            )

# ─── Metric row ────────────────────────────────────────────────────────────────
cols7 = st.columns(7)
cols7[0].markdown(
    mc(total, "Total Attacks", "#00a8ff", "session"), unsafe_allow_html=True
)
cols7[1].markdown(
    mc(blk, "Blocked", "#00e676", f"{int(blk / total * 100) if total else 0}% rate"),
    unsafe_allow_html=True,
)
cols7[2].markdown(mc(sqli, "SQLi", "#ff3d57"), unsafe_allow_html=True)
cols7[3].markdown(mc(xss, "XSS", "#ffd60a"), unsafe_allow_html=True)
cols7[4].markdown(mc(lfi, "LFI", "#b84dff"), unsafe_allow_html=True)
cols7[5].markdown(mc(cmdi, "CMDi", "#ff6b35"), unsafe_allow_html=True)
cols7[6].markdown(bar_card(top_s), unsafe_allow_html=True)

st.markdown("<div style='height:8px'></div>", unsafe_allow_html=True)

met1, met2, met3, met4 = st.columns(4)
met1.metric("Requests/sec", f"{req_ps}", delta=f"{round(req_ps * 0.12, 2)} trend")
met2.metric("Active threats", str(active_threats), delta=f"{len(log[-20:])} recent")
met3.metric("Blocked IPs", str(len(bips)), delta=f"{blk} actions")
met4.metric(
    "System health",
    health_label,
    delta="stable" if health_label == "HEALTHY" else "attention",
)

main_left, main_right = st.columns([7, 3], gap="medium")
with main_left:
    st.markdown(
        '<div class="table-card"><div style="font-size:12px;font-weight:700;color:#e7eef9;margin-bottom:8px">Traffic & Threat Trend</div>',
        unsafe_allow_html=True,
    )
    trend_data = list(st.session_state.threat_trend)
    if not trend_data and log:
        trend_data = [top_s for _ in range(min(len(log), 12))]
    if trend_data:
        tdf = pd.DataFrame(
            {"tick": list(range(len(trend_data))), "threat_score": trend_data}
        )
        st.line_chart(tdf, x="tick", y="threat_score", height=220)
    else:
        st.markdown(
            "<div class='skeleton'></div><div class='skeleton'></div><div class='skeleton'></div>",
            unsafe_allow_html=True,
        )
    st.markdown("</div>", unsafe_allow_html=True)

    st.markdown(
        '<div class="table-card" style="margin-top:10px"><div style="font-size:12px;font-weight:700;color:#e7eef9;margin-bottom:6px">Live Attack Feed</div>',
        unsafe_allow_html=True,
    )
    if log:
        for ev in reversed(log[-8:]):
            sev_color = {
                "CRITICAL": "#FF4D4D",
                "HIGH": "#FFC857",
                "MEDIUM": "#00C8FF",
                "LOW": "#00FF9C",
            }.get(ev.get("severity", "LOW"), "#8B949E")
            st.markdown(
                f"<div style='font-family:Space Mono,monospace;font-size:11px;padding:5px 0;border-bottom:1px dashed #1f2a3d'>"
                f"<span style='color:{sev_color}'>[{ev.get('severity', 'INFO')}]</span> "
                f"{ev.get('attack_type', '?')} from {ev.get('src_ip', '?')} "
                f"<span style='color:#8B949E'>→ {ev.get('action', 'PENDING')}</span></div>",
                unsafe_allow_html=True,
            )
    else:
        st.markdown(
            "<div class='skeleton'></div><div class='skeleton'></div>",
            unsafe_allow_html=True,
        )
    st.markdown("</div>", unsafe_allow_html=True)

with main_right:
    st.markdown(
        f"<div class='glass-card' style='text-align:center'>{_gauge_svg(top_s)}</div>",
        unsafe_allow_html=True,
    )
    st.markdown(
        f"""<div class='glass-card' style='margin-top:10px'>
      <div style='font-size:11px;color:#8B949E;font-family:Space Mono,monospace'>SYSTEM STATUS</div>
      <div style='font-size:22px;font-weight:800;color:{health_color};margin-top:4px'>{health_label}</div>
      <div style='font-size:11px;color:#8B949E'>Realtime: {realtime_state} · Alerts: {notif_count}</div>
    </div>""",
        unsafe_allow_html=True,
    )
    st.markdown(
        "<div class='glass-card' style='margin-top:10px'><div style='font-size:11px;color:#8B949E;font-family:Space Mono,monospace'>ALERTS PANEL</div>",
        unsafe_allow_html=True,
    )
    if recent_notifs:
        for nt in recent_notifs[:4]:
            col = {"CRITICAL": "#FF4D4D", "WARNING": "#FFC857", "INFO": "#00C8FF"}.get(
                nt.get("level", "INFO"), "#8B949E"
            )
            st.markdown(
                f"<div style='font-size:11px;padding:6px 0;border-bottom:1px dashed #233247'><span style='color:{col}'>{nt.get('level')}</span> · {nt.get('message')}</div>",
                unsafe_allow_html=True,
            )
    else:
        st.markdown(
            "<div class='skeleton'></div><div class='skeleton'></div>",
            unsafe_allow_html=True,
        )
    st.markdown("</div>", unsafe_allow_html=True)

st.markdown(
    '<div class="table-card" style="margin-top:10px"><div style="font-size:12px;font-weight:700;color:#e7eef9;margin-bottom:8px">Recent Event Table</div>',
    unsafe_allow_html=True,
)
if log:
    st.markdown(
        "<div class='log-row' style='color:#8B949E;font-size:10px;font-family:Space Mono,monospace'><div>Time</div><div>Source IP</div><div>Type</div><div>Severity</div><div>Action</div><div>CVE</div></div>",
        unsafe_allow_html=True,
    )
    for ev in reversed(log[-10:]):
        st.markdown(
            f"<div class='log-row'>"
            f"<div style='color:#8B949E;font-family:Space Mono,monospace;font-size:11px'>{ev.get('timestamp', '')[-8:-3]}</div>"
            f"<div style='color:#e7eef9;font-family:Space Mono,monospace;font-size:11px'>{ev.get('src_ip', '-')}</div>"
            f"<div style='color:#00C8FF;font-family:Space Mono,monospace;font-size:11px'>{ev.get('attack_type', '-')}</div>"
            f"<div style='color:#FFC857;font-family:Space Mono,monospace;font-size:11px'>{ev.get('severity', '-')}</div>"
            f"<div style='color:#00FF9C;font-family:Space Mono,monospace;font-size:11px'>{ev.get('action', '-')}</div>"
            f"<div style='color:#8B949E;font-family:Space Mono,monospace;font-size:11px'>{(ev.get('cve_hints', ['-']) or ['-'])[0]}</div>"
            f"</div>",
            unsafe_allow_html=True,
        )
else:
    st.markdown(
        "<div class='skeleton'></div><div class='skeleton'></div><div class='skeleton'></div>",
        unsafe_allow_html=True,
    )
st.markdown("</div>", unsafe_allow_html=True)

# ─── Tabs ──────────────────────────────────────────────────────────────────────
tabs = st.tabs(
    [
        "⚡ Command Center",
        "🌍 Website Monitoring",
        "🧱 Firewall Panel",
        "⏪ Attack Replay",
        "🔍 Threat Intel",
        "🌐 Global Attack Map",
        "📊 Threat Analytics",
        "📋 Response & Reports",
        "🛡️ Website Protection",
    ]
)

# ════════════ TAB 1 — COMMAND CENTER ════════════════════════════════
with tabs[0]:
    # Attack Lab bar
    st.markdown(
        '<div style="font-size:13px;font-weight:600;color:#cdd8eb;font-family:DM Sans,sans-serif;margin:6px 0 8px">✏ Attack Lab</div>',
        unsafe_allow_html=True,
    )
    lab = st.columns(4)
    for col, (at, c) in zip(
        lab,
        [
            ("SQLi", "#ff3d57"),
            ("XSS", "#ffd60a"),
            ("LFI", "#b84dff"),
            ("CMDi", "#ff6b35"),
        ],
    ):
        col.markdown(
            f'<div style="height:3px;background:{c}22;border-radius:2px;margin-bottom:4px"></div>',
            unsafe_allow_html=True,
        )
        if col.button(f"{at} Burst", key=f"lb_{at}", use_container_width=True):
            for i in range(3):
                fire(at, f"10.9.{['SQLi', 'XSS', 'LFI', 'CMDi'].index(at)}.{i + 1}")
            st.rerun()

    left_col, right_col = st.columns([3, 2], gap="medium")

    # LEFT: stream + log + blocked
    with left_col:
        stream_mode = "SIMULATION" if not sniff_mode else "LIVE SNIFF"
        st.markdown(
            f"""<div style="background:#0a0f1a;border:1px solid #1e2d45;border-radius:5px;padding:7px 12px;
                    font-size:11px;font-family:Space Mono,monospace;color:#4a6080;margin-bottom:10px">
          Stream status: <span style="color:#ffd60a">{stream_mode}</span> &nbsp;|&nbsp;
          CLI ingest: <span style="color:#00a8ff">{"ON" if cli_mode else "OFF"}</span> &nbsp;|&nbsp;
          Realtime: <span style="color:{"#00e676" if realtime_state == "ACTIVE" else "#ffd60a" if realtime_state == "PAUSED" else "#4a6080"}">{realtime_state}</span> &nbsp;|&nbsp;
          Processed events: <span style="color:#cdd8eb">{total}</span> &nbsp;|&nbsp;
          Stream cursor: <span style="color:#cdd8eb">{st.session_state.stream_offset}</span>
        </div>""",
            unsafe_allow_html=True,
        )

        # Recent event tags
        if log:
            tags = ""
            for ev in log[-6:]:
                c = {
                    "SQLi": "#ff3d57",
                    "XSS": "#ffd60a",
                    "LFI": "#b84dff",
                    "CMDi": "#ff6b35",
                }.get(ev.get("attack_type", ""), "#4a6080")
                tags += f'<span style="background:{c}22;color:{c};border:1px solid {c}55;padding:2px 8px;border-radius:3px;font-size:10px;font-family:Space Mono,monospace;margin-right:4px">{ev.get("attack_type")} · {ev.get("src_ip", "")}</span>'
            st.markdown(
                f'<div style="margin-bottom:10px"><div style="font-size:10px;color:#4a6080;font-family:Space Mono,monospace;margin-bottom:4px">RECENT LIVE EVENTS</div><div>{tags}</div></div>',
                unsafe_allow_html=True,
            )

        st.markdown(
            '<div style="font-size:13px;font-weight:600;color:#cdd8eb;font-family:DM Sans,sans-serif;margin-bottom:8px">📋 Live Attack Log</div>',
            unsafe_allow_html=True,
        )
        hdr = st.columns([1.2, 1.8, 1.1, 1.2, 1.2, 0.9])
        for col, lbl in zip(
            hdr, ["Time", "Source IP", "Type", "Severity", "Action", "Conf."]
        ):
            col.markdown(
                f"<div style='font-size:10px;color:#4a6080;font-family:Space Mono,monospace;padding-bottom:4px;border-bottom:1px solid #1e2d45'>{lbl}</div>",
                unsafe_allow_html=True,
            )

        if not log:
            st.markdown(
                '<div style="background:#0e1420;border:1px dashed #1e2d45;border-radius:6px;padding:32px;text-align:center;color:#4a6080;font-family:Space Mono,monospace;font-size:11px">🟢 NO ATTACKS DETECTED — Use sidebar to simulate</div>',
                unsafe_allow_html=True,
            )
        else:
            for ev in reversed(log[-20:]):
                r = st.columns([1.2, 1.8, 1.1, 1.2, 1.2, 0.9])
                tc = {
                    "SQLi": "#ff3d57",
                    "XSS": "#ffd60a",
                    "LFI": "#b84dff",
                    "CMDi": "#ff6b35",
                }.get(ev.get("attack_type", ""), "#cdd8eb")
                sc2 = {
                    "CRITICAL": "#ff3d57",
                    "HIGH": "#ff6b35",
                    "MEDIUM": "#ffd60a",
                    "LOW": "#00e676",
                }.get(ev.get("severity", ""), "#cdd8eb")
                ac = {
                    "BLOCKED": "#00e676",
                    "RATE_MONITORED": "#ffd60a",
                    "PENDING": "#4a6080",
                }.get(ev.get("action", ""), "#4a6080")
                cf = (
                    "#00e676"
                    if ev.get("confidence", 0) >= 75
                    else "#ffd60a"
                    if ev.get("confidence", 0) >= 50
                    else "#4a6080"
                )
                r[0].markdown(
                    f"<div style='font-size:11px;color:#4a6080;font-family:Space Mono,monospace;padding:5px 0'>{ev.get('timestamp', '')[-8:-3]}</div>",
                    unsafe_allow_html=True,
                )
                r[1].markdown(
                    f"<div style='font-size:11px;color:#cdd8eb;font-family:Space Mono,monospace;padding:5px 0'>{ev.get('src_ip', '-')}</div>",
                    unsafe_allow_html=True,
                )
                r[2].markdown(
                    f"<div style='font-size:11px;font-weight:700;color:{tc};font-family:Space Mono,monospace;padding:5px 0'>{ev.get('attack_type', '-')}</div>",
                    unsafe_allow_html=True,
                )
                r[3].markdown(
                    f"<div style='font-size:11px;color:{sc2};font-family:Space Mono,monospace;padding:5px 0'>{ev.get('severity', '-')}</div>",
                    unsafe_allow_html=True,
                )
                r[4].markdown(
                    f"<div style='font-size:11px;color:{ac};font-family:Space Mono,monospace;padding:5px 0'>{ev.get('action', 'PENDING')}</div>",
                    unsafe_allow_html=True,
                )
                r[5].markdown(
                    f"<div style='font-size:11px;color:{cf};font-family:Space Mono,monospace;padding:5px 0'>{ev.get('confidence', 0)}%</div>",
                    unsafe_allow_html=True,
                )

        st.markdown(
            '<div style="font-size:13px;font-weight:600;color:#cdd8eb;font-family:DM Sans,sans-serif;margin:14px 0 8px">🚫 Blocked IPs</div>',
            unsafe_allow_html=True,
        )
        if not bips:
            st.markdown(
                '<div style="font-size:11px;color:#4a6080;font-family:Space Mono,monospace">No IPs currently blocked.</div>',
                unsafe_allow_html=True,
            )
        else:
            for b in bips:
                bc = st.columns([1.8, 1.2, 2.2, 1.0])
                bc[0].markdown(
                    f"<div style='font-size:11px;color:#ff3d57;font-family:Space Mono,monospace;padding:4px 0'>{b['ip']}</div>",
                    unsafe_allow_html=True,
                )
                bc[1].markdown(
                    f"<div style='font-size:11px;color:#ffd60a;font-family:Space Mono,monospace;padding:4px 0'>{b['attack_type']}</div>",
                    unsafe_allow_html=True,
                )
                bc[2].markdown(
                    f"<div style='font-size:10px;color:#4a6080;font-family:Space Mono,monospace;padding:4px 0'>exp: {b.get('expires_at', '')[-8:-3]} · {b.get('method', '')}</div>",
                    unsafe_allow_html=True,
                )
                if bc[3].button("Unblock", key=f"ub_{b['ip']}"):
                    blocker.unblock_ip(b["ip"])
                    st.rerun()

    # RIGHT: CVE
    with right_col:
        st.markdown(
            '<div style="font-size:13px;font-weight:600;color:#cdd8eb;font-family:DM Sans,sans-serif;margin-bottom:10px">🔍 CVE Intelligence</div>',
            unsafe_allow_html=True,
        )
        cve_type = st.radio(
            "",
            ["SQLi", "XSS", "LFI", "CMDi"],
            horizontal=True,
            index=["SQLi", "XSS", "LFI", "CMDi"].index(st.session_state.cve_sel),
            key="cve_r",
            label_visibility="collapsed",
        )
        st.session_state.cve_sel = cve_type
        cve_d = get_cve_card(cve_type)
        top_cv = cve_d
        all_cv = cve_d.get("all_cves", [cve_d])
        score = top_cv.get("cvss_score", "N/A")
        sc_c = (
            "#ff3d57"
            if isinstance(score, (int, float)) and score >= 9
            else "#ff6b35"
            if isinstance(score, (int, float)) and score >= 7
            else "#00a8ff"
        )

        st.markdown(
            f"""<div style="background:#0e1420;border:1px solid {sc_c}55;border-left:3px solid {sc_c};border-radius:6px;padding:14px 16px;margin-bottom:10px">
          <div style="font-size:14px;font-weight:700;color:{sc_c};font-family:Space Mono,monospace">{top_cv.get("cve_id", "N/A")}</div>
          <div style="display:flex;align-items:center;gap:14px;margin-top:10px">
            <div><div style="font-size:30px;font-weight:700;color:{sc_c};font-family:Space Mono,monospace;line-height:1">{score}</div>
              <div style="font-size:9px;color:#4a6080;font-family:Space Mono,monospace">CVSS</div></div>
            <div><div style="background:{sc_c}22;color:{sc_c};border:1px solid {sc_c}55;padding:2px 8px;border-radius:3px;font-size:10px;font-weight:600;font-family:Space Mono,monospace">{top_cv.get("severity", "?")}</div>
              <div style="font-size:10px;color:#4a6080;font-family:Space Mono,monospace;margin-top:4px">Published: {top_cv.get("published", "N/A")}</div></div>
          </div>
          <div style="font-size:11px;color:#8899b0;margin-top:10px;line-height:1.5">{top_cv.get("description", "")[:220]}...</div>
          {"<a href='" + top_cv.get("reference", "") + "' target='_blank' style='font-size:10px;color:#00a8ff;font-family:Space Mono,monospace'>🔗 NVD Reference ↗</a>" if top_cv.get("reference") else ""}
        </div>""",
            unsafe_allow_html=True,
        )

        if (
            st.session_state.last
            and st.session_state.last.get("attack_type") == cve_type
        ):
            ev2 = st.session_state.last
            hint = ev2.get("cve_hints", ["?"])[0]
            st.markdown(
                f"""<div style="background:#1a0d00;border:1px solid #ff6b3566;border-radius:5px;padding:10px 12px;margin-bottom:10px">
              <div style="font-size:10px;font-weight:600;color:#ff6b35;font-family:Space Mono,monospace;margin-bottom:3px">⚠ ACTIVE THREAT MATCH</div>
              <div style="font-size:11px;color:#8899b0">Live attack from <span style="color:#ff3d57;font-weight:600">{ev2.get("src_ip")}</span> aligns with {hint}</div>
              <div style="font-size:10px;color:#4a6080;font-family:Space Mono,monospace;margin-top:3px">Confidence: {ev2.get("confidence", 0)}%</div>
            </div>""",
                unsafe_allow_html=True,
            )

        rel = [e for e in log if e.get("attack_type") == cve_type]
        if rel:
            rules = rel[-1].get("matched_rules", [])[:2]
            if rules:
                st.markdown(
                    '<div style="font-size:10px;color:#4a6080;font-family:Space Mono,monospace;margin-bottom:4px">MATCHED SIGNATURES</div>',
                    unsafe_allow_html=True,
                )
                for r2 in rules:
                    st.code(r2[:60], language=None)

        if len(all_cv) > 1:
            with st.expander(f"Show all {len(all_cv)} CVEs for {cve_type}"):
                for cv in all_cv[1:]:
                    s2 = cv.get("cvss_score", "N/A")
                    sc3 = (
                        "#ff3d57"
                        if isinstance(s2, (int, float)) and s2 >= 9
                        else "#ff6b35"
                        if isinstance(s2, (int, float)) and s2 >= 7
                        else "#00a8ff"
                    )
                    st.markdown(
                        f"""<div style="background:#0e1420;border:1px solid #1e2d45;border-radius:4px;padding:8px 10px;margin-bottom:5px">
                      <span style="color:{sc3};font-weight:700;font-family:Space Mono,monospace;font-size:11px">{cv.get("cve_id")}</span>
                      <span style="color:#ffd60a;font-size:10px;margin-left:8px;font-family:Space Mono,monospace">CVSS {s2}</span>
                      <div style="color:#8899b0;font-size:10px;margin-top:4px">{cv.get("description", "")[:100]}...</div>
                    </div>""",
                        unsafe_allow_html=True,
                    )

    # Payload Inspector
    st.markdown(
        '<div style="font-size:13px;font-weight:600;color:#cdd8eb;font-family:DM Sans,sans-serif;margin:14px 0 8px">🔬 Payload Inspector</div>',
        unsafe_allow_html=True,
    )
    if log:
        last_ev = log[-1]
        pi1, pi2 = st.columns([2, 1])
        with pi1:
            tc2 = {
                "SQLi": "#ff3d57",
                "XSS": "#ffd60a",
                "LFI": "#b84dff",
                "CMDi": "#ff6b35",
            }.get(last_ev.get("attack_type", ""), "#cdd8eb")
            st.markdown(
                f'<div style="font-size:11px;color:#4a6080;font-family:Space Mono,monospace;margin-bottom:4px">Last detected payload — <span style="color:{tc2};font-weight:700">{last_ev.get("attack_type", "-")}</span></div>',
                unsafe_allow_html=True,
            )
            st.code(last_ev.get("payload_snip", ""), language=None)
        with pi2:
            act = last_ev.get("action", "PENDING")
            ac2 = "#00e676" if act == "BLOCKED" else "#ffd60a"
            st.markdown(
                f"""<div style="background:#0e1420;border:1px solid {ac2}55;border-radius:6px;padding:12px">
              <div style="font-size:13px;font-weight:700;color:{ac2}">✅ {act}</div>
              <div style="font-size:10px;color:#8899b0;margin-top:6px;line-height:1.5">{last_ev.get("sanitization", "")}</div>
              <div style="font-size:10px;color:#8899b0;margin-top:6px;font-family:Space Mono,monospace">IP: <span style="color:#ff3d57">{last_ev.get("src_ip")}</span> → DROPPED</div>
            </div>""",
                unsafe_allow_html=True,
            )
    else:
        st.markdown(
            '<div style="font-size:11px;color:#4a6080;font-family:Space Mono,monospace">No payload data yet.</div>',
            unsafe_allow_html=True,
        )


# ════════════ TAB 2 — WEBSITE MONITORING ════════════════════════════
with tabs[1]:
    st.markdown(
        '<div style="font-size:13px;font-weight:600;color:#cdd8eb;font-family:DM Sans,sans-serif;margin-bottom:10px">🌍 Website Monitoring & WAF Signals</div>',
        unsafe_allow_html=True,
    )
    wm1, wm2 = st.columns([2.1, 1.2], gap="medium")
    with wm1:
        target = st.text_input("Target URL", value=st.session_state.monitor_target)
        cwm1, cwm2 = st.columns([1.4, 1])
        with cwm1:
            st.session_state.monitor_interval = st.slider(
                "Check interval (sec)", 5, 60, st.session_state.monitor_interval
            )
        with cwm2:
            if st.button("Run Health Check", use_container_width=True):
                st.session_state.monitor_target = target
                mon = _run_website_check(target)
                st.session_state.monitor_checked_at = time.time()
                if mon.get("anomaly"):
                    _push_notification(
                        "WARNING", f"Anomaly on {target}: {mon.get('latency_ms')} ms"
                    )

        mon = st.session_state.monitor_last.get(
            target
        ) or st.session_state.monitor_last.get(st.session_state.monitor_target, {})
        if mon:
            c1, c2, c3, c4 = st.columns(4)
            c1.metric("Status", str(mon.get("status", "N/A")))
            c2.metric("Latency", f"{mon.get('latency_ms', 0)} ms")
            c3.metric("Uptime", f"{mon.get('uptime_pct', 0)}%")
            c4.metric("Anomaly", "YES" if mon.get("anomaly") else "NO")
            hist = st.session_state.monitor_history.get(
                mon.get("url", st.session_state.monitor_target), []
            )
            if hist:
                hdf = pd.DataFrame({"probe": list(range(len(hist))), "latency": hist})
                st.area_chart(hdf, x="probe", y="latency", height=180)
        else:
            st.markdown(
                "<div class='skeleton'></div><div class='skeleton'></div><div class='skeleton'></div>",
                unsafe_allow_html=True,
            )

    with wm2:
        waf = monitor_data.get("waf", {"SQLi": 0, "XSS": 0, "LFI": 0})
        st.markdown(
            f"""<div class='glass-card'>
            <div style='font-size:11px;color:#4a6080;font-family:Space Mono,monospace;margin-bottom:8px'>BASIC WAF SIGNALS (LAST WINDOW)</div>
            <div style='display:flex;justify-content:space-between'><span>SQLi</span><span style='color:#ff3d57'>{waf.get("SQLi", 0)}</span></div>
            <div style='display:flex;justify-content:space-between'><span>XSS</span><span style='color:#ffd60a'>{waf.get("XSS", 0)}</span></div>
            <div style='display:flex;justify-content:space-between'><span>LFI</span><span style='color:#b84dff'>{waf.get("LFI", 0)}</span></div>
            <div style='font-size:10px;color:#4a6080;font-family:Space Mono,monospace;margin-top:8px'>Traffic anomaly detection compares live latency against rolling baseline.</div>
            </div>""",
            unsafe_allow_html=True,
        )


# ════════════ TAB 3 — FIREWALL PANEL ═════════════════════════════════
with tabs[2]:
    st.markdown(
        '<div style="font-size:13px;font-weight:600;color:#cdd8eb;font-family:DM Sans,sans-serif;margin-bottom:10px">🧱 Firewall Control Panel</div>',
        unsafe_allow_html=True,
    )
    fw1, fw2 = st.columns([1.5, 2], gap="medium")
    with fw1:
        ip_to_block = st.text_input("IP to block", value="203.0.113.25")
        block_reason = st.text_input("Reason", value="Manual SOC block")
        if st.button("Block IP", type="primary", use_container_width=True):
            blocker.block_ip(
                ip_to_block, reason=block_reason, severity="HIGH", attack_type="Manual"
            )
            _push_notification("INFO", f"Manually blocked {ip_to_block}")
            st.rerun()
        if st.button("Unblock IP", use_container_width=True):
            blocker.unblock_ip(ip_to_block)
            _push_notification("INFO", f"Unblocked {ip_to_block}")
            st.rerun()

        st.markdown("---")
        st.markdown("**Rate limiting rules**")
        th = st.number_input("Threshold", min_value=1, max_value=200, value=6)
        win = st.number_input("Window sec", min_value=5, max_value=600, value=60)
        if st.button("Add Rule", use_container_width=True):
            st.session_state.firewall_rate_rules.append(
                {"threshold": int(th), "window": int(win)}
            )

        st.markdown("**Country blocking**")
        country_opts = [
            "India",
            "China",
            "Russia",
            "United States",
            "Germany",
            "Brazil",
            "Netherlands",
        ]
        selected_countries = st.multiselect(
            "Blocked countries",
            country_opts,
            default=list(st.session_state.firewall_country_block),
        )
        st.session_state.firewall_country_block = set(selected_countries)

    with fw2:
        st.markdown(
            """<div class='glass-card'>
          <div style='font-size:11px;color:#4a6080;font-family:Space Mono,monospace'>ACTIVE RATE RULES</div>
        </div>""",
            unsafe_allow_html=True,
        )
        for idx, rr in enumerate(st.session_state.firewall_rate_rules):
            crr1, crr2, crr3 = st.columns([2, 2, 1])
            crr1.write(f"Rule {idx + 1}")
            crr2.write(f">= {rr['threshold']} hits / {rr['window']}s")
            if crr3.button("Delete", key=f"del_rate_{idx}"):
                st.session_state.firewall_rate_rules.pop(idx)
                st.rerun()

        st.markdown("---")
        st.markdown("**Blocked IP table**")
        if bips:
            bdf = pd.DataFrame(bips)[
                ["ip", "attack_type", "severity", "method", "expires_at"]
            ]
            st.dataframe(bdf, use_container_width=True, hide_index=True)
        else:
            st.markdown(
                "<div class='skeleton'></div><div class='skeleton'></div>",
                unsafe_allow_html=True,
            )


# ════════════ TAB 4 — ATTACK REPLAY ══════════════════════════════════
with tabs[3]:
    st.markdown(
        '<div style="font-size:13px;font-weight:600;color:#cdd8eb;font-family:DM Sans,sans-serif;margin-bottom:10px">⏪ Attack Replay Timeline</div>',
        unsafe_allow_html=True,
    )
    replay_speed = st.slider("Replay speed", 1, 5, 2)
    replay_rows = _replay_rows(log, limit=40)
    if replay_rows:
        if st.button("Run Replay", use_container_width=True):
            ph = st.empty()
            for r in replay_rows:
                ph.markdown(
                    f"<div class='glass-card'><span class='neon-pill'>{r['time']}</span> "
                    f"<span style='color:#cdd8eb;font-family:Space Mono,monospace'>{r['src_ip']}</span> "
                    f"<span style='color:#ff6b35;margin-left:8px'>{r['attack']}</span> "
                    f"<span style='color:#4a6080;margin-left:8px'>detect: {r['detect']} → response: {r['response']}</span></div>",
                    unsafe_allow_html=True,
                )
                time.sleep(max(0.15, 0.55 / replay_speed))
        rdf = pd.DataFrame(replay_rows)
        st.dataframe(rdf, use_container_width=True, hide_index=True)
    else:
        st.markdown(
            "<div class='skeleton'></div><div class='skeleton'></div><div class='skeleton'></div>",
            unsafe_allow_html=True,
        )


# ════════════ TAB 5 — THREAT INTEL ══════════════════════════════════
with tabs[4]:
    ti1, ti2 = st.columns([2, 1.2], gap="medium")
    with ti1:
        st.markdown(
            '<div style="font-size:13px;font-weight:600;color:#cdd8eb;font-family:DM Sans,sans-serif;margin-bottom:10px">🇮🇳 CERT-In Advisory Feed <span style="background:#0d2640;border:1px solid #00a8ff44;padding:1px 6px;border-radius:3px;color:#00a8ff;font-size:9px;font-family:Space Mono,monospace">INDIA SPECIFIC</span></div>',
            unsafe_allow_html=True,
        )
        with st.spinner("Loading CERT-In advisories..."):
            advisories = fetch_certin_advisories(max_items=8)
            cs = get_certin_summary()
        st.markdown(
            f"""<div style="display:flex;gap:10px;margin-bottom:12px">
          <div style="background:#0e1420;border:1px solid #1e2d45;border-radius:5px;padding:10px;flex:1;text-align:center">
            <div style="font-size:22px;font-weight:700;color:#00a8ff;font-family:Space Mono,monospace">{cs["total"]}</div>
            <div style="font-size:10px;color:#4a6080;font-family:Space Mono,monospace">TOTAL</div></div>
          <div style="background:#0e1420;border:1px solid #ff3d5755;border-radius:5px;padding:10px;flex:1;text-align:center">
            <div style="font-size:22px;font-weight:700;color:#ff3d57;font-family:Space Mono,monospace">{cs["critical"]}</div>
            <div style="font-size:10px;color:#4a6080;font-family:Space Mono,monospace">CRITICAL</div></div>
          <div style="background:#0e1420;border:1px solid #ff6b3555;border-radius:5px;padding:10px;flex:1;text-align:center">
            <div style="font-size:22px;font-weight:700;color:#ff6b35;font-family:Space Mono,monospace">{cs["high"]}</div>
            <div style="font-size:10px;color:#4a6080;font-family:Space Mono,monospace">HIGH</div></div>
        </div>""",
            unsafe_allow_html=True,
        )
        for adv in advisories:
            sev2 = adv.get("severity", "HIGH")
            sc4 = {
                "CRITICAL": "#ff3d57",
                "HIGH": "#ff6b35",
                "MEDIUM": "#ffd60a",
                "LOW": "#00e676",
            }.get(sev2, "#4a6080")
            ss = f"CVSS {adv.get('cvss_score', 'N/A')}" if adv.get("cvss_score") else ""
            st.markdown(
                f"""<div style="background:#0e1420;border:1px solid #1e2d45;border-left:3px solid {sc4};
                        border-radius:5px;padding:10px 14px;margin-bottom:8px">
              <div style="display:flex;justify-content:space-between;align-items:center">
                <div style="font-size:11px;font-weight:700;color:{sc4};font-family:Space Mono,monospace">{adv.get("advisory_id", "")}</div>
                <div style="display:flex;gap:6px">
                  <span style="background:{sc4}22;color:{sc4};border:1px solid {sc4}44;padding:1px 6px;border-radius:3px;font-size:9px;font-family:Space Mono,monospace">{sev2}</span>
                  <span style="font-size:9px;color:#4a6080;font-family:Space Mono,monospace">{ss}</span>
                </div>
              </div>
              <div style="font-size:11px;color:#cdd8eb;margin-top:4px">{adv.get("title", "")[:70]}</div>
              <div style="font-size:10px;color:#8899b0;margin-top:4px;line-height:1.4">{adv.get("description", "")[:140]}...</div>
              <div style="font-size:9px;color:#4a6080;font-family:Space Mono,monospace;margin-top:4px">{adv.get("source", "")} · {adv.get("published", "")}
                {"&nbsp; <a href='" + adv.get("link", "") + "' target='_blank' style='color:#00a8ff'>↗</a>" if adv.get("link") else ""}</div>
            </div>""",
                unsafe_allow_html=True,
            )

    with ti2:
        st.markdown(
            '<div style="font-size:13px;font-weight:600;color:#cdd8eb;font-family:DM Sans,sans-serif;margin-bottom:10px">🎯 IP Threat Leaderboard</div>',
            unsafe_allow_html=True,
        )
        profs2 = ts_eng.get_top_threats(8)
        if not profs2:
            st.markdown(
                '<div style="font-size:11px;color:#4a6080;font-family:Space Mono,monospace">No IP profiles yet. Simulate attacks to build threat intelligence.</div>',
                unsafe_allow_html=True,
            )
        else:
            for i2, p2 in enumerate(profs2):
                st.markdown(threat_score_row(p2, i2), unsafe_allow_html=True)
            if profs2:
                tp = profs2[0]
                tsc = tp["threat_score"]
                tc3 = (
                    "#ff3d57"
                    if tsc >= 80
                    else "#ff6b35"
                    if tsc >= 60
                    else "#ffd60a"
                    if tsc >= 40
                    else "#00a8ff"
                )
                lb3 = (
                    "CRITICAL"
                    if tsc >= 80
                    else "HIGH"
                    if tsc >= 60
                    else "MEDIUM"
                    if tsc >= 40
                    else "LOW"
                    if tsc >= 20
                    else "CLEAN"
                )
                st.markdown(
                    f"""<div style="background:#0e1420;border:1px solid {tc3}55;border-radius:6px;padding:14px;text-align:center;margin-top:10px">
                  <div style="font-size:10px;color:#4a6080;font-family:Space Mono,monospace;margin-bottom:5px">TOP THREAT GAUGE</div>
                  <div style="font-size:36px;font-weight:700;color:{tc3};font-family:Space Mono,monospace;line-height:1">{tsc}</div>
                  <div style="font-size:9px;color:{tc3};font-family:Space Mono,monospace;margin:3px 0 8px">{lb3}</div>
                  <div style="background:#131b2a;border-radius:2px;height:5px">
                    <div style="background:{tc3};height:100%;width:{tsc}%;border-radius:2px;transition:width .5s"></div></div>
                  <div style="font-size:10px;color:#4a6080;font-family:Space Mono,monospace;margin-top:5px">{tp["ip"]} · {"/".join(tp["attack_types"])}</div>
                </div>""",
                    unsafe_allow_html=True,
                )


# ════════════ TAB 6 — GLOBAL ATTACK MAP ═════════════════════════════
with tabs[5]:
    m1, m2 = st.columns([3, 1], gap="medium")
    with m1:
        st.markdown(
            '<div style="font-size:13px;font-weight:600;color:#cdd8eb;font-family:DM Sans,sans-serif;margin-bottom:10px">🌐 Global Threat Map <span style="background:#003330;border:1px solid #00d4b844;padding:1px 6px;border-radius:3px;color:#00d4b8;font-size:9px;font-family:Space Mono,monospace">REAL-TIME GEOIP</span></div>',
            unsafe_allow_html=True,
        )
        if log:
            try:
                mhtml = _cached_map_html(log)
                if mhtml:
                    st.components.v1.html(mhtml, height=480, scrolling=False)
                else:
                    st.markdown(
                        '<div style="background:#0e1420;border:1px dashed #1e2d45;border-radius:6px;padding:60px;text-align:center;color:#4a6080;font-family:Space Mono,monospace;font-size:11px">Map cache is empty. Generate events to build map.</div>',
                        unsafe_allow_html=True,
                    )
            except Exception as ex:
                st.markdown(
                    f'<div style="background:#0e1420;border:1px solid #1e2d45;border-radius:6px;padding:20px;color:#4a6080;font-family:Space Mono,monospace;font-size:11px">Map error: {ex}</div>',
                    unsafe_allow_html=True,
                )
        else:
            st.markdown(
                '<div style="background:#0e1420;border:1px dashed #1e2d45;border-radius:6px;padding:60px;text-align:center;color:#4a6080;font-family:Space Mono,monospace;font-size:11px">🌐 NO ATTACK DATA YET — Simulate attacks to see global threat map</div>',
                unsafe_allow_html=True,
            )

    with m2:
        st.markdown(
            '<div style="font-size:13px;font-weight:600;color:#cdd8eb;font-family:DM Sans,sans-serif;margin-bottom:10px">📍 Geo Intelligence</div>',
            unsafe_allow_html=True,
        )
        if log:
            gs = get_geo_stats(log)
            st.markdown(
                f"""<div style="background:#0e1420;border:1px solid #1e2d45;border-radius:5px;padding:12px;margin-bottom:12px">
              <div style="display:flex;justify-content:space-between;margin-bottom:6px">
                <span style="font-size:11px;color:#4a6080;font-family:Space Mono,monospace">Unique IPs</span>
                <span style="font-size:14px;font-weight:700;color:#00a8ff;font-family:Space Mono,monospace">{gs["unique_ips"]}</span></div>
              <div style="display:flex;justify-content:space-between">
                <span style="font-size:11px;color:#4a6080;font-family:Space Mono,monospace">Total Events</span>
                <span style="font-size:14px;font-weight:700;color:#cdd8eb;font-family:Space Mono,monospace">{gs["total_attacks"]}</span></div>
            </div>""",
                unsafe_allow_html=True,
            )
            st.markdown(
                '<div style="font-size:10px;color:#4a6080;font-family:Space Mono,monospace;margin-bottom:6px">TOP ORIGIN COUNTRIES</div>',
                unsafe_allow_html=True,
            )
            pal = ["#ff3d57", "#ff6b35", "#ffd60a", "#00a8ff", "#b84dff"]
            for i3, (country, cnt) in enumerate(gs["top_countries"]):
                c5 = pal[i3 % len(pal)]
                p5 = int(cnt / max(gs["total_attacks"], 1) * 100)
                st.markdown(
                    f"""<div style="margin-bottom:7px">
                  <div style="display:flex;justify-content:space-between;margin-bottom:3px">
                    <span style="font-size:11px;color:#cdd8eb">{country}</span>
                    <span style="font-size:11px;color:{c5};font-family:Space Mono,monospace">{cnt}</span></div>
                  <div style="background:#131b2a;border-radius:2px;height:3px">
                    <div style="background:{c5};height:100%;width:{p5}%;border-radius:2px"></div></div>
                </div>""",
                    unsafe_allow_html=True,
                )

            st.markdown(
                '<div style="font-size:10px;color:#4a6080;font-family:Space Mono,monospace;margin-top:10px;margin-bottom:6px">ATTACKER DETAILS</div>',
                unsafe_allow_html=True,
            )
            for ev3 in log[-5:]:
                ip3 = ev3.get("src_ip", "")
                g3 = geolocate_ip(ip3)
                tc4 = {
                    "SQLi": "#ff3d57",
                    "XSS": "#ffd60a",
                    "LFI": "#b84dff",
                    "CMDi": "#ff6b35",
                }.get(ev3.get("attack_type", ""), "#cdd8eb")
                st.markdown(
                    f"""<div style="background:#0e1420;border:1px solid #1e2d45;border-radius:4px;padding:7px 10px;margin-bottom:5px">
                  <div style="font-size:10px;color:#cdd8eb;font-family:Space Mono,monospace">{ip3}</div>
                  <div style="font-size:9px;color:#4a6080;margin-top:2px">{g3.get("city", "?")}, {g3.get("country", "?")}</div>
                  <div style="font-size:9px;color:{tc4};font-family:Space Mono,monospace">{ev3.get("attack_type")}</div>
                </div>""",
                    unsafe_allow_html=True,
                )
        else:
            st.markdown(
                '<div style="font-size:11px;color:#4a6080;font-family:Space Mono,monospace">No geo data yet.</div>',
                unsafe_allow_html=True,
            )


# ════════════ TAB 7 — THREAT ANALYTICS ══════════════════════════════
with tabs[6]:
    a1, a2 = st.columns([1, 1], gap="medium")
    with a1:
        st.markdown(
            '<div style="font-size:13px;font-weight:600;color:#cdd8eb;font-family:DM Sans,sans-serif;margin-bottom:10px">📊 Attack Distribution</div>',
            unsafe_allow_html=True,
        )
        type_colors = {
            "SQLi": "#ff3d57",
            "XSS": "#ffd60a",
            "LFI": "#b84dff",
            "CMDi": "#ff6b35",
        }
        for at2, cnt2 in [("SQLi", sqli), ("XSS", xss), ("LFI", lfi), ("CMDi", cmdi)]:
            pct2 = int(cnt2 / max(total, 1) * 100)
            c6 = type_colors[at2]
            st.markdown(
                f"""<div style="margin-bottom:12px">
              <div style="display:flex;justify-content:space-between;margin-bottom:5px">
                <span style="font-size:12px;font-weight:600;color:{c6}">{at2}</span>
                <span style="font-size:12px;color:#cdd8eb;font-family:Space Mono,monospace">{cnt2} <span style="color:#4a6080;font-size:10px">({pct2}%)</span></span></div>
              <div style="background:#131b2a;border-radius:3px;height:8px;overflow:hidden">
                <div style="background:{c6};height:100%;width:{pct2}%;border-radius:3px;transition:width .5s"></div></div>
            </div>""",
                unsafe_allow_html=True,
            )

        st.markdown(
            '<div style="font-size:13px;font-weight:600;color:#cdd8eb;font-family:DM Sans,sans-serif;margin:14px 0 10px">⚡ Severity Breakdown</div>',
            unsafe_allow_html=True,
        )
        sevc = Counter(e.get("severity", "?") for e in log)
        for sv, sc5 in [
            ("CRITICAL", "#ff3d57"),
            ("HIGH", "#ff6b35"),
            ("MEDIUM", "#ffd60a"),
            ("LOW", "#00e676"),
        ]:
            cnt3 = sevc.get(sv, 0)
            p3 = int(cnt3 / max(total, 1) * 100)
            st.markdown(
                f"""<div style="display:flex;align-items:center;gap:10px;margin-bottom:8px">
              <div style="width:70px;font-size:10px;color:{sc5};font-family:Space Mono,monospace;text-align:right">{sv}</div>
              <div style="flex:1;background:#131b2a;border-radius:2px;height:5px;overflow:hidden">
                <div style="background:{sc5};height:100%;width:{p3}%;border-radius:2px"></div></div>
              <div style="width:28px;font-size:11px;color:#cdd8eb;font-family:Space Mono,monospace">{cnt3}</div>
            </div>""",
                unsafe_allow_html=True,
            )

    with a2:
        st.markdown(
            '<div style="font-size:13px;font-weight:600;color:#cdd8eb;font-family:DM Sans,sans-serif;margin-bottom:10px">🎯 Detection Confidence</div>',
            unsafe_allow_html=True,
        )
        if log:
            bkts = {
                "HIGH (75-100)": 0,
                "MED (50-74)": 0,
                "LOW (25-49)": 0,
                "MIN (0-24)": 0,
            }
            for e4 in log:
                cv = e4.get("confidence", 0)
                if cv >= 75:
                    bkts["HIGH (75-100)"] += 1
                elif cv >= 50:
                    bkts["MED (50-74)"] += 1
                elif cv >= 25:
                    bkts["LOW (25-49)"] += 1
                else:
                    bkts["MIN (0-24)"] += 1
            for (lbl2, cnt4), c7 in zip(
                bkts.items(), ["#00e676", "#00a8ff", "#ffd60a", "#4a6080"]
            ):
                p4 = int(cnt4 / max(total, 1) * 100)
                st.markdown(
                    f"""<div style="margin-bottom:10px">
                  <div style="display:flex;justify-content:space-between;margin-bottom:4px">
                    <span style="font-size:10px;color:{c7};font-family:Space Mono,monospace">{lbl2}</span>
                    <span style="font-size:11px;color:#cdd8eb;font-family:Space Mono,monospace">{cnt4} ({p4}%)</span></div>
                  <div style="background:#131b2a;border-radius:2px;height:6px;overflow:hidden">
                    <div style="background:{c7};height:100%;width:{p4}%;border-radius:2px"></div></div>
                </div>""",
                    unsafe_allow_html=True,
                )

        st.markdown(
            '<div style="font-size:13px;font-weight:600;color:#cdd8eb;font-family:DM Sans,sans-serif;margin:14px 0 10px">🛡 Auto-Defense Actions</div>',
            unsafe_allow_html=True,
        )
        actc = Counter(e.get("action", "?") for e in log)
        for act2, c8 in [
            ("BLOCKED", "#00e676"),
            ("RATE_MONITORED", "#ffd60a"),
            ("PENDING", "#4a6080"),
        ]:
            cnt5 = actc.get(act2, 0)
            p5b = int(cnt5 / max(total, 1) * 100)
            st.markdown(
                f"""<div style="display:flex;align-items:center;gap:10px;margin-bottom:8px">
              <div style="width:120px;font-size:10px;color:{c8};font-family:Space Mono,monospace">{act2}</div>
              <div style="flex:1;background:#131b2a;border-radius:2px;height:5px">
                <div style="background:{c8};height:100%;width:{p5b}%"></div></div>
              <div style="font-size:11px;color:#cdd8eb;font-family:Space Mono,monospace">{cnt5}</div>
            </div>""",
                unsafe_allow_html=True,
            )

        if st.session_state.last:
            st.markdown(
                '<div style="font-size:13px;font-weight:600;color:#cdd8eb;font-family:DM Sans,sans-serif;margin:14px 0 10px">🇮🇳 CERT-In Matches</div>',
                unsafe_allow_html=True,
            )
            last2 = st.session_state.last
            mts = match_attack_to_certin(
                last2.get("attack_type", "SQLi"), last2.get("payload_snip", "")
            )
            for m2 in mts[:3]:
                sc6 = {
                    "CRITICAL": "#ff3d57",
                    "HIGH": "#ff6b35",
                    "MEDIUM": "#ffd60a",
                }.get(m2.get("severity", "HIGH"), "#4a6080")
                st.markdown(
                    f"""<div style="background:#0e1420;border:1px solid {sc6}33;border-left:2px solid {sc6};
                            border-radius:4px;padding:8px 10px;margin-bottom:6px">
                  <div style="font-size:10px;font-weight:700;color:{sc6};font-family:Space Mono,monospace">{m2.get("advisory_id", "")}</div>
                  <div style="font-size:10px;color:#8899b0;margin-top:3px">{m2.get("description", "")[:100]}...</div>
                </div>""",
                    unsafe_allow_html=True,
                )


# ════════════ TAB 8 — RESPONSE & REPORTS ════════════════════════════
with tabs[7]:
    rr1, rr2 = st.columns([1, 1], gap="medium")
    with rr1:
        st.markdown(
            '<div style="font-size:13px;font-weight:600;color:#cdd8eb;font-family:DM Sans,sans-serif;margin-bottom:12px">📄 Incident Report Generator</div>',
            unsafe_allow_html=True,
        )
        org = st.text_input("Organization Name", value="Target Organization", key="org")
        if REPORTLAB_OK:
            if st.button(
                "🖨 Generate PDF Report", type="primary", use_container_width=True
            ):
                if not log:
                    st.warning("No attack data.")
                else:
                    with st.spinner("Generating..."):
                        try:
                            rpath = generate_report(
                                log, bips, "/tmp/autoshield_report.pdf", org
                            )
                            with open(rpath, "rb") as f2:
                                b64r = base64.b64encode(f2.read()).decode()
                            st.markdown(
                                f"""<div style="background:#002a14;border:1px solid #00e67655;border-radius:6px;padding:12px 16px;margin-top:8px">
                              <div style="font-size:12px;font-weight:600;color:#00e676;margin-bottom:8px">✅ Report Generated</div>
                              <a href="data:application/pdf;base64,{b64r}" download="autoshield_report.pdf"
                                 style="background:#00e67622;color:#00e676;border:1px solid #00e67655;padding:6px 16px;border-radius:4px;
                                        text-decoration:none;font-size:11px;font-family:Space Mono,monospace;display:inline-block">⬇ Download Report PDF</a>
                            </div>""",
                                unsafe_allow_html=True,
                            )
                        except Exception as ex2:
                            st.error(f"Failed: {ex2}")
        else:
            st.markdown(
                '<div style="background:#1a0d00;border:1px solid #ff6b3544;border-radius:5px;padding:10px 12px"><div style="font-size:11px;color:#ff6b35">pip install reportlab</div></div>',
                unsafe_allow_html=True,
            )

        st.markdown(
            """<div style="background:#0e1420;border:1px solid #1e2d45;border-radius:5px;padding:12px 14px;margin-top:12px">
          <div style="font-size:11px;font-weight:600;color:#cdd8eb;margin-bottom:8px">Report Includes</div>
          <div style="font-size:10px;color:#8899b0;font-family:Space Mono,monospace;line-height:1.8">
            ✓ Executive summary + stats<br/>✓ Full attack log (last 50)<br/>
            ✓ Blocked IP table<br/>✓ SQLi/XSS/LFI/CMDi recommendations<br/>✓ CONFIDENTIAL classification
          </div>
        </div>""",
            unsafe_allow_html=True,
        )

    with rr2:
        st.markdown(
            '<div style="font-size:13px;font-weight:600;color:#cdd8eb;font-family:DM Sans,sans-serif;margin-bottom:12px">🚨 Alert Configuration</div>',
            unsafe_allow_html=True,
        )
        for channel, icon, cname in [
            ("whatsapp", "📱", "WhatsApp / Twilio"),
            ("email", "📧", "Email / SMTP"),
        ]:
            cfg2 = acfg[channel]
            ok2 = cfg2["configured"]
            sc7 = "#00e676" if ok2 else "#4a6080"
            st.markdown(
                f"""<div style="background:#0e1420;border:1px solid {"#00e67644" if ok2 else "#1e2d45"};
                        border-radius:5px;padding:12px 14px;margin-bottom:10px">
              <div style="display:flex;justify-content:space-between;align-items:center">
                <div style="font-size:12px;font-weight:600;color:#cdd8eb">{icon} {cname}</div>
                <span style="background:{"#002a14" if ok2 else "#131b2a"};color:{sc7};border:1px solid {sc7}44;
                             padding:2px 8px;border-radius:3px;font-size:9px;font-family:Space Mono,monospace">{"ACTIVE" if ok2 else "NOT SET"}</span>
              </div>
              <div style="font-size:10px;color:#4a6080;font-family:Space Mono,monospace;margin-top:6px">
                {"To: " + cfg2["to"][:40] if ok2 else "Set env: " + ("TWILIO_SID + ALERT_WA_TO" if channel == "whatsapp" else "SMTP_USER + ALERT_EMAIL_TO")}
              </div>
            </div>""",
                unsafe_allow_html=True,
            )

        st.markdown(
            """<div style="background:#0e1420;border:1px solid #1e2d45;border-radius:5px;padding:10px 12px;margin-bottom:12px">
          <div style="font-size:10px;color:#8899b0;font-family:Space Mono,monospace;line-height:1.8">
            🔴 CRITICAL → immediate alert<br/>🟡 HIGH → alert after 5 events/min<br/>
            ⏱ Cooldown: 120s per IP<br/>📤 WhatsApp + Email (parallel)
          </div>
        </div>""",
            unsafe_allow_html=True,
        )

        if st.button("📨 Send Test Alert", use_container_width=True):
            ev_t = st.session_state.last or {
                "src_ip": "0.0.0.0",
                "attack_type": "SQLi",
                "severity": "CRITICAL",
                "action": "BLOCKED",
                "confidence": 75,
                "cve_hints": ["CVE-2023-23752"],
                "payload_snip": "test",
                "timestamp": datetime.now().isoformat(),
            }
            res = fire_alert(ev_t, force=True)
            wa_r = res.get("channels", {}).get("whatsapp", {}).get("status", "SKIPPED")
            em_r = res.get("channels", {}).get("email", {}).get("status", "SKIPPED")
            st.markdown(
                f"""<div style="background:#0e1420;border:1px solid #1e2d45;border-radius:5px;padding:10px 12px;margin-top:8px">
              <div style="font-size:10px;font-family:Space Mono,monospace;color:#4a6080">
                WhatsApp: <span style="color:{"#00e676" if wa_r == "SENT" else "#ffd60a"}">{wa_r}</span><br/>
                Email: <span style="color:{"#00e676" if em_r == "SENT" else "#ffd60a"}">{em_r}</span>
              </div>
            </div>""",
                unsafe_allow_html=True,
            )

        st.markdown(
            '<div style="font-size:13px;font-weight:600;color:#cdd8eb;font-family:DM Sans,sans-serif;margin:14px 0 8px">🐳 One-Command Deploy</div>',
            unsafe_allow_html=True,
        )
        st.code("docker compose up --build\n# → http://localhost:8501", language="bash")

# ════════════ TAB 9 — WEBSITE PROTECTION PANEL ═══════════════════════
with tabs[8]:
    st.markdown(
        '<div style="font-size:13px;font-weight:600;color:#E7EEF9;font-family:DM Sans,sans-serif;margin-bottom:14px">🛡️ Website Protection Panel</div>',
        unsafe_allow_html=True,
    )

    # Domain management
    wp1, wp2 = st.columns([1.6, 1], gap="medium")
    with wp1:
        st.markdown(
            """<div class='glass-card'>
            <div style='font-size:12px;font-weight:700;color:#E7EEF9;margin-bottom:12px'>Connected Domains</div>""",
            unsafe_allow_html=True,
        )
        # Use monitor target as a managed domain
        domains = [
            {
                "domain": st.session_state.monitor_target.replace("https://", "")
                .replace("http://", "")
                .rstrip("/"),
                "status": "active",
                "ssl": True,
            }
        ]
        if "wp_domains" not in st.session_state:
            st.session_state.wp_domains = domains
        for i_d, d_info in enumerate(st.session_state.wp_domains):
            d_status = d_info.get("status", "active")
            s_col = "#00FF9C" if d_status == "active" else "#FFC857"
            st.markdown(
                f"""<div style="background:rgba(8,11,16,.5);border:1px solid var(--bd);border-radius:10px;
                        padding:14px 16px;margin-bottom:10px;display:flex;justify-content:space-between;align-items:center">
                  <div>
                    <div style="font-size:14px;font-weight:600;color:#E7EEF9;font-family:var(--mono)">{d_info["domain"]}</div>
                    <div style="font-size:10px;color:var(--muted);margin-top:4px;font-family:var(--mono)">
                      SSL: <span style="color:#00FF9C">{"● Active" if d_info.get("ssl") else "○ Inactive"}</span>
                      &nbsp;·&nbsp; DNS: <span style="color:#00C8FF">Routed via AutoShield</span>
                    </div>
                  </div>
                  <div style="display:flex;align-items:center;gap:12px">
                    <span style="background:{"rgba(0,255,156,.08)" if d_status == "active" else "rgba(255,200,87,.08)"};
                                 border:1px solid {s_col}44;color:{s_col};
                                 padding:4px 12px;border-radius:6px;font-size:10px;font-weight:600;font-family:var(--mono)">
                      {"PROTECTED" if d_status == "active" else "PAUSED"}
                    </span>
                  </div>
                </div>""",
                unsafe_allow_html=True,
            )

        # Add new domain
        new_dom = st.text_input(
            "Add domain", placeholder="yoursite.com", key="wp_new_domain"
        )
        dc1, dc2 = st.columns(2)
        with dc1:
            if st.button("➕ Add Domain", use_container_width=True, key="wp_add"):
                if new_dom.strip():
                    st.session_state.wp_domains.append(
                        {
                            "domain": new_dom.strip()
                            .replace("https://", "")
                            .replace("http://", "")
                            .rstrip("/"),
                            "status": "active",
                            "ssl": True,
                        }
                    )
                    st.rerun()
        with dc2:
            wp_protect = st.toggle("Protection enabled", value=True, key="wp_toggle")
        st.markdown("</div>", unsafe_allow_html=True)

        # DNS configuration
        st.markdown(
            """<div class='glass-card' style='margin-top:12px'>
            <div style='font-size:12px;font-weight:700;color:#E7EEF9;margin-bottom:12px'>DNS Configuration</div>
            <div style='background:rgba(8,11,16,.5);border:1px solid var(--bd);border-radius:10px;padding:14px 16px;
                         font-family:var(--mono);font-size:11px;line-height:2'>
              <span style="color:var(--muted)">CNAME</span>&nbsp;&nbsp; <span style="color:#00C8FF">proxy.autoshield.ai</span><br/>
              <span style="color:var(--muted)">A</span>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; <span style="color:#E7EEF9">104.26.8.142</span><br/>
              <span style="color:var(--muted)">AAAA</span>&nbsp;&nbsp;&nbsp; <span style="color:#E7EEF9">2606:4700:3030::681a:892</span><br/>
              <span style="color:var(--muted)">TXT</span>&nbsp;&nbsp;&nbsp;&nbsp; <span style="color:#6A5CFF">autoshield-verify=as_v1_xxx</span>
            </div>
            <div style='font-size:10px;color:var(--muted);margin-top:8px'>
              Point your domain's DNS records to route traffic through AutoShield's edge network.
            </div>
            </div>""",
            unsafe_allow_html=True,
        )

    with wp2:
        # Traffic routing status
        st.markdown(
            f"""<div class='glass-card'>
            <div style='font-size:12px;font-weight:700;color:#E7EEF9;margin-bottom:12px'>Traffic Routing</div>
            <div style='text-align:center;padding:16px 0'>
              <div style='width:72px;height:72px;border-radius:50%;
                          background:{"rgba(0,255,156,.06)" if wp_protect else "rgba(255,200,87,.06)"};
                          border:2px solid {"#00FF9C" if wp_protect else "#FFC857"};
                          display:inline-flex;align-items:center;justify-content:center;
                          font-size:28px;margin-bottom:12px'>
                {"🛡️" if wp_protect else "⚠️"}
              </div>
              <div style='font-size:18px;font-weight:700;color:{"#00FF9C" if wp_protect else "#FFC857"};
                          font-family:var(--mono)'>{"ACTIVE" if wp_protect else "PAUSED"}</div>
              <div style='font-size:10px;color:var(--muted);margin-top:4px;font-family:var(--mono)'>
                {"All traffic routed through WAF" if wp_protect else "Traffic bypassing protection"}
              </div>
            </div>
            <div style='display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-top:8px'>
              <div style='background:rgba(8,11,16,.5);border:1px solid var(--bd);border-radius:8px;padding:10px;text-align:center'>
                <div style='font-size:16px;font-weight:700;color:#00C8FF;font-family:var(--mono)'>{total}</div>
                <div style='font-size:9px;color:var(--muted);font-family:var(--mono);text-transform:uppercase'>Requests</div>
              </div>
              <div style='background:rgba(8,11,16,.5);border:1px solid var(--bd);border-radius:8px;padding:10px;text-align:center'>
                <div style='font-size:16px;font-weight:700;color:#FF4D4D;font-family:var(--mono)'>{blk}</div>
                <div style='font-size:9px;color:var(--muted);font-family:var(--mono);text-transform:uppercase'>Blocked</div>
              </div>
            </div>
            </div>""",
            unsafe_allow_html=True,
        )

        # Quick firewall rules
        st.markdown(
            """<div class='glass-card' style='margin-top:12px'>
            <div style='font-size:12px;font-weight:700;color:#E7EEF9;margin-bottom:12px'>Quick Firewall Rules</div>
            </div>""",
            unsafe_allow_html=True,
        )
        wp_ip = st.text_input("Block IP", value="203.0.113.0", key="wp_block_ip")
        if st.button("🚫 Block IP", use_container_width=True, key="wp_block_btn"):
            blocker.block_ip(
                wp_ip,
                reason="Website Protection Panel",
                severity="HIGH",
                attack_type="Manual",
            )
            _push_notification("INFO", f"Blocked {wp_ip} via protection panel")
            st.rerun()

        wp_rate_th = st.number_input(
            "Rate limit (req/min)", min_value=1, max_value=1000, value=60, key="wp_rate"
        )
        if st.button("➕ Add Rate Rule", use_container_width=True, key="wp_rate_btn"):
            st.session_state.firewall_rate_rules.append(
                {"threshold": int(wp_rate_th), "window": 60}
            )
            _push_notification("INFO", f"Rate limit rule: {wp_rate_th} req/min")
            st.rerun()

        st.markdown(
            """<div class='glass-card' style='margin-top:12px'>
            <div style='font-size:12px;font-weight:700;color:#E7EEF9;margin-bottom:8px'>Geo Blocking</div>
            </div>""",
            unsafe_allow_html=True,
        )
        wp_countries = st.multiselect(
            "Block traffic from",
            [
                "China",
                "Russia",
                "North Korea",
                "Iran",
                "Brazil",
                "India",
                "Netherlands",
                "Germany",
                "United States",
            ],
            default=list(st.session_state.firewall_country_block),
            key="wp_country_block",
        )
        st.session_state.firewall_country_block = set(wp_countries)


# ─── Footer ────────────────────────────────────────────────────────────────────
st.markdown(
    """
<div style="text-align:center;padding:24px 0 12px;color:#4A6080;font-size:10px;
            font-family:Space Mono,monospace;border-top:1px solid #1C2535;margin-top:24px">
  AutoShield AI Fusion Console &nbsp;·&nbsp; Scapy + ML + iptables + NVD + CERT-In + Folium + ReportLab
  &nbsp;·&nbsp; <span style="color:#00FF9C">● SYSTEM ACTIVE</span>
</div>""",
    unsafe_allow_html=True,
)

realtime_active = (
    st.session_state.cli_mode
    or st.session_state.sniff_mode
    or st.session_state.autopilot
)
if realtime_active and not st.session_state.pause_live:
    recently_active = (
        st.session_state.last_stream_seen > 0
        and (time.time() - st.session_state.last_stream_seen) <= 8
    )
    poll_interval = (
        1
        if (
            st.session_state.autopilot or st.session_state.sniff_mode or recently_active
        )
        else 3
    )
    time.sleep(poll_interval)
    st.rerun()
