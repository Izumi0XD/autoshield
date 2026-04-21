"""
AutoShield - Attack Map
Geolocates attacker IPs and renders a live threat map using Folium.
Uses ip-api.com free tier (no key needed, 45 req/min).
"""

import requests
import folium
import json
import time
import logging
import os
from datetime import datetime
from collections import defaultdict

log = logging.getLogger("AutoShield.AttackMap")

IP_API_URL  = "http://ip-api.com/json/{ip}?fields=status,country,regionName,city,lat,lon,isp,org,query"
CACHE_FILE  = "/tmp/autoshield_geo_cache.json"
RATE_LIMIT  = 0.8   # seconds between requests (45/min safe limit)

# ─── Geo cache (persist between runs) ────────────────────────────────────────

def _load_cache() -> dict:
    try:
        with open(CACHE_FILE) as f:
            return json.load(f)
    except Exception:
        return {}

def _save_cache(cache: dict):
    try:
        with open(CACHE_FILE, "w") as f:
            json.dump(cache, f)
    except Exception:
        pass

_geo_cache = _load_cache()

# Known private/local IP ranges → skip API call
_PRIVATE_PREFIXES = ("10.", "192.168.", "172.16.", "172.17.", "127.", "::1", "0.0.0.0")

def _is_private(ip: str) -> bool:
    return any(ip.startswith(p) for p in _PRIVATE_PREFIXES)

# Fake geo for private IPs (demo mode: place them near India)
_DEMO_LOCATIONS = [
    {"country": "India",        "city": "New Delhi",  "lat": 28.6139, "lon": 77.2090, "isp": "Demo ISP"},
    {"country": "China",        "city": "Beijing",    "lat": 39.9042, "lon": 116.4074,"isp": "China Telecom"},
    {"country": "Russia",       "city": "Moscow",     "lat": 55.7558, "lon": 37.6173, "isp": "Rostelecom"},
    {"country": "United States","city": "Ashburn",    "lat": 39.0438, "lon": -77.4874,"isp": "Amazon AWS"},
    {"country": "Germany",      "city": "Frankfurt",  "lat": 50.1109, "lon": 8.6821,  "isp": "Hetzner"},
    {"country": "Brazil",       "city": "São Paulo",  "lat": -23.5505,"lon": -46.6333,"isp": "Claro"},
    {"country": "India",        "city": "Mumbai",     "lat": 19.0760, "lon": 72.8777, "isp": "Reliance Jio"},
    {"country": "Netherlands",  "city": "Amsterdam",  "lat": 52.3676, "lon": 4.9041,  "isp": "Digital Ocean"},
]

_demo_idx = 0

def geolocate_ip(ip: str) -> dict:
    """Return geo dict for an IP. Cached, rate-limited."""
    global _demo_idx

    if ip in _geo_cache:
        return _geo_cache[ip]

    if _is_private(ip):
        # Rotate through demo locations for private IPs
        loc = dict(_DEMO_LOCATIONS[_demo_idx % len(_DEMO_LOCATIONS)])
        loc["query"] = ip
        loc["status"] = "demo"
        _demo_idx += 1
        _geo_cache[ip] = loc
        _save_cache(_geo_cache)
        return loc

    try:
        time.sleep(RATE_LIMIT)
        resp = requests.get(IP_API_URL.format(ip=ip), timeout=5)
        data = resp.json()
        if data.get("status") == "success":
            _geo_cache[ip] = data
            _save_cache(_geo_cache)
            return data
    except Exception as e:
        log.error(f"Geo lookup failed for {ip}: {e}")

    # Fallback
    fallback = {"country": "Unknown", "city": "Unknown", "lat": 20.5937, "lon": 78.9629,
                "isp": "Unknown", "query": ip, "status": "fallback"}
    return fallback


# ─── Map builder ──────────────────────────────────────────────────────────────

SEVERITY_COLORS = {
    "CRITICAL": "#ef4444",
    "HIGH":     "#f97316",
    "MEDIUM":   "#eab308",
    "LOW":      "#22c55e",
}

ATTACK_ICONS = {
    "SQLi": "💉",
    "XSS":  "📝",
    "LFI":  "📂",
    "CMDi": "💻",
}

def build_attack_map(attack_events: list[dict], output_path: str = "/tmp/autoshield_map.html") -> str:
    """
    Build Folium map from attack events list.
    Returns path to generated HTML file.
    """
    # Center on India
    m = folium.Map(
        location=[20.5937, 78.9629],
        zoom_start=3,
        tiles="CartoDB dark_matter",
    )

    # Aggregate attacks per IP
    ip_attacks: dict[str, list] = defaultdict(list)
    for event in attack_events:
        ip_attacks[event.get("src_ip", "0.0.0.0")].append(event)

    for ip, events in ip_attacks.items():
        geo   = geolocate_ip(ip)
        lat   = geo.get("lat", 20.5937)
        lon   = geo.get("lon", 78.9629)
        count = len(events)

        # Use worst severity for color
        sev_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
        severities = [e.get("severity","LOW") for e in events]
        worst_sev  = next((s for s in sev_order if s in severities), "LOW")
        color      = SEVERITY_COLORS.get(worst_sev, "#ef4444")

        # Attack type summary
        types = list({e.get("attack_type","?") for e in events})
        icons = " ".join(ATTACK_ICONS.get(t,"⚠️") for t in types)

        # Popup HTML
        latest  = events[-1]
        popup_html = f"""
        <div style="font-family:monospace;background:#1e1e1e;color:#e6edf3;
                    padding:12px;border-radius:6px;min-width:220px">
          <b style="color:{color}">⚠ {worst_sev} ATTACK</b><br/>
          <hr style="border-color:#444;margin:6px 0"/>
          <b>IP:</b> {ip}<br/>
          <b>Location:</b> {geo.get('city','?')}, {geo.get('country','?')}<br/>
          <b>ISP:</b> {geo.get('isp','?')[:30]}<br/>
          <b>Attacks:</b> {count} ({', '.join(types)})<br/>
          <b>Status:</b> <span style="color:#22c55e">{latest.get('action','DETECTED')}</span><br/>
          <b>Last:</b> {latest.get('timestamp','')[-8:-3]}<br/>
          <b>CVE:</b> {latest.get('cve_hints',['?'])[0]}
        </div>
        """

        # Pulse circle for severity
        radius = min(8 + count * 3, 25)
        folium.CircleMarker(
            location=[lat, lon],
            radius=radius,
            color=color,
            fill=True,
            fill_color=color,
            fill_opacity=0.7,
            popup=folium.Popup(popup_html, max_width=280),
            tooltip=f"{icons} {ip} ({count} attacks)",
        ).add_to(m)

        # Arrow line to Indian server (demo: target = New Delhi)
        if geo.get("country") != "India" or geo.get("status") != "demo":
            folium.PolyLine(
                locations=[[lat, lon], [28.6139, 77.2090]],
                color=color,
                weight=1.5,
                opacity=0.4,
                dash_array="5 5",
            ).add_to(m)

    # Target server marker
    folium.Marker(
        location=[28.6139, 77.2090],
        popup="🛡️ AutoShield Protected Server",
        icon=folium.Icon(color="green", icon="shield", prefix="fa"),
        tooltip="🛡️ Protected Server",
    ).add_to(m)

    # Legend
    legend_html = """
    <div style="position:fixed;bottom:30px;left:30px;background:#1e1e1e;
                border:1px solid #444;padding:12px;border-radius:8px;
                font-family:monospace;color:#e6edf3;font-size:12px;z-index:9999">
      <b>🛡️ AutoShield Threat Map</b><br/><br/>
      <span style="color:#ef4444">●</span> CRITICAL &nbsp;
      <span style="color:#f97316">●</span> HIGH<br/>
      <span style="color:#eab308">●</span> MEDIUM &nbsp;
      <span style="color:#22c55e">●</span> LOW<br/><br/>
      💉 SQLi &nbsp; 📝 XSS<br/>
      📂 LFI &nbsp; 💻 CMDi
    </div>
    """
    m.get_root().html.add_child(folium.Element(legend_html))

    m.save(output_path)
    log.info(f"Attack map saved: {output_path}")
    return output_path


def get_geo_stats(attack_events: list[dict]) -> dict:
    """Summary geo stats for dashboard."""
    countries = defaultdict(int)
    for event in attack_events:
        ip  = event.get("src_ip","0.0.0.0")
        geo = geolocate_ip(ip)
        countries[geo.get("country","Unknown")] += 1

    return {
        "top_countries": sorted(countries.items(), key=lambda x: x[1], reverse=True)[:5],
        "unique_ips":    len({e.get("src_ip") for e in attack_events}),
        "total_attacks": len(attack_events),
    }


# ─── Self-test ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=== Attack Map Self-Test ===\n")

    demo_events = [
        {"src_ip": "192.168.1.1",  "attack_type": "SQLi", "severity": "CRITICAL",
         "action": "BLOCKED", "timestamp": datetime.now().isoformat(),
         "cve_hints": ["CVE-2023-23752"]},
        {"src_ip": "192.168.1.2",  "attack_type": "XSS",  "severity": "HIGH",
         "action": "BLOCKED", "timestamp": datetime.now().isoformat(),
         "cve_hints": ["CVE-2023-32315"]},
        {"src_ip": "192.168.1.3",  "attack_type": "LFI",  "severity": "CRITICAL",
         "action": "BLOCKED", "timestamp": datetime.now().isoformat(),
         "cve_hints": ["CVE-2023-29489"]},
        {"src_ip": "10.0.0.14",    "attack_type": "CMDi", "severity": "CRITICAL",
         "action": "BLOCKED", "timestamp": datetime.now().isoformat(),
         "cve_hints": ["CVE-2023-46604"]},
    ]

    path = build_attack_map(demo_events, "/tmp/test_map.html")
    print(f"Map generated: {path}")

    stats = get_geo_stats(demo_events)
    print(f"\nGeo stats: {json.dumps(stats, indent=2)}")

    print("\nGeo samples:")
    for ip in ["192.168.1.1", "10.0.0.14"]:
        geo = geolocate_ip(ip)
        print(f"  {ip} → {geo.get('city')}, {geo.get('country')}")
