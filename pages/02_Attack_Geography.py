import streamlit as st

from auth import current_user, logout, require_auth
from ui_shell import inject_shell_styles, render_sidebar, render_top_nav

require_auth()

st.set_page_config(page_title="Attack Geography — AutoShield AI", page_icon="🌐", layout="wide")
inject_shell_styles()
render_sidebar("attack_geo")
search = render_top_nav("attack_geo")

st.markdown(
    """<div style="margin-bottom:16px">
      <div style="font-size:24px;font-weight:800;color:#E7EEF9;letter-spacing:-.02em">🌐 Attack Geography</div>
      <div style="font-size:13px;color:#8B949E;margin-top:4px">Geospatial threat visualization and origin analysis</div>
    </div>""",
    unsafe_allow_html=True,
)

if search:
    st.info(f"Search query active: {search}")

log = st.session_state.get("log", [])

if log:
    try:
        from attack_map import build_attack_map, get_geo_stats, geolocate_ip
        import os

        m1, m2 = st.columns([2.5, 1], gap="medium")
        with m1:
            st.markdown(
                '<div class="glass"><div style="font-size:12px;font-weight:700;color:#E7EEF9;margin-bottom:10px">Global Threat Map</div>',
                unsafe_allow_html=True,
            )
            try:
                map_path = build_attack_map(log, "/tmp/geo_page_map.html")
                with open(map_path, encoding="utf-8") as f:
                    map_html = f.read()
                st.components.v1.html(map_html, height=440, scrolling=False)
            except Exception as ex:
                st.markdown(
                    f'<div style="padding:40px;text-align:center;color:#4A6080;font-family:Space Mono,monospace;font-size:11px">Map error: {ex}</div>',
                    unsafe_allow_html=True,
                )
            st.markdown("</div>", unsafe_allow_html=True)

        with m2:
            gs = get_geo_stats(log)
            st.markdown(
                f"""<div class='glass'>
                <div style='font-size:12px;font-weight:700;color:#E7EEF9;margin-bottom:12px'>Geo Intelligence</div>
                <div style="background:rgba(8,11,16,.5);border:1px solid #1C2535;border-radius:10px;padding:14px;margin-bottom:12px">
                  <div style="display:flex;justify-content:space-between;margin-bottom:8px">
                    <span style="font-size:11px;color:#4A6080;font-family:Space Mono,monospace">Unique IPs</span>
                    <span style="font-size:16px;font-weight:700;color:#00C8FF;font-family:Space Mono,monospace">{gs["unique_ips"]}</span>
                  </div>
                  <div style="display:flex;justify-content:space-between">
                    <span style="font-size:11px;color:#4A6080;font-family:Space Mono,monospace">Total Events</span>
                    <span style="font-size:16px;font-weight:700;color:#E7EEF9;font-family:Space Mono,monospace">{gs["total_attacks"]}</span>
                  </div>
                </div>""",
                unsafe_allow_html=True,
            )

            st.markdown(
                '<div style="font-size:10px;color:#4A6080;font-family:Space Mono,monospace;margin-bottom:8px">TOP ORIGIN COUNTRIES</div>',
                unsafe_allow_html=True,
            )
            pal = ["#FF4D4D", "#FF8B5B", "#FFC857", "#00C8FF", "#6A5CFF"]
            for i, (country, cnt) in enumerate(gs["top_countries"]):
                c = pal[i % len(pal)]
                p = int(cnt / max(gs["total_attacks"], 1) * 100)
                st.markdown(
                    f"""<div style="margin-bottom:8px">
                      <div style="display:flex;justify-content:space-between;margin-bottom:3px">
                        <span style="font-size:11px;color:#CDD8EB">{country}</span>
                        <span style="font-size:11px;color:{c};font-family:Space Mono,monospace">{cnt}</span>
                      </div>
                      <div style="background:#0B0F14;border-radius:2px;height:4px">
                        <div style="background:{c};height:100%;width:{p}%;border-radius:2px"></div>
                      </div>
                    </div>""",
                    unsafe_allow_html=True,
                )

            # Attacker details
            st.markdown(
                '<div style="font-size:10px;color:#4A6080;font-family:Space Mono,monospace;margin:12px 0 8px">RECENT ATTACKERS</div>',
                unsafe_allow_html=True,
            )
            for ev in log[-5:]:
                ip = ev.get("src_ip", "")
                geo = geolocate_ip(ip)
                at_col = {"SQLi": "#FF4D4D", "XSS": "#FFC857", "LFI": "#6A5CFF", "CMDi": "#FF8B5B"}.get(
                    ev.get("attack_type", ""), "#8B949E"
                )
                st.markdown(
                    f"""<div style="background:rgba(8,11,16,.5);border:1px solid #1C2535;border-radius:8px;padding:8px 10px;margin-bottom:6px">
                      <div style="font-size:11px;color:#E7EEF9;font-family:Space Mono,monospace">{ip}</div>
                      <div style="font-size:9px;color:#4A6080;margin-top:2px">{geo.get("city", "?")}, {geo.get("country", "?")}</div>
                      <div style="font-size:9px;color:{at_col};font-family:Space Mono,monospace">{ev.get("attack_type")}</div>
                    </div>""",
                    unsafe_allow_html=True,
                )
            st.markdown("</div>", unsafe_allow_html=True)

    except Exception as ex:
        st.error(f"Geo module error: {ex}")
else:
    st.markdown(
        """<div class='glass' style='text-align:center;padding:60px'>
          <div style='font-size:40px;margin-bottom:16px;opacity:.3'>🌐</div>
          <div style='font-size:14px;color:#4A6080;font-family:Space Mono,monospace'>No attack data available</div>
          <div style='font-size:12px;color:#4A6080;margin-top:6px'>Simulate attacks from the Fusion Dashboard to see the global threat map.</div>
        </div>""",
        unsafe_allow_html=True,
    )

# ─── Footer ────────────────────────────────────────────────────────────────────
u = current_user()
st.caption(f"Signed in as: {u.get('name', 'Unknown')} ({u.get('provider', 'local')})")
c1, c2 = st.columns(2)
with c1:
    if st.button("Logout", use_container_width=True, key="geo_logout"):
        logout()
        st.switch_page("pages/00_Login.py")
with c2:
    if st.button("Open Fusion Dashboard", use_container_width=True, key="geo_dash"):
        st.switch_page("dashboard.py")
